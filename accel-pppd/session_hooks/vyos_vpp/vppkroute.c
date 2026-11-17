/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Kernel copy of VPP PPPoE session routes ([vpp-route-export] section).
 *
 * [vpp-route-export]
 * interface=pppoe-export   dummy interface owned by accel (restart to change)
 * proto=250                rtm_protocol of the kernel routes (restart to change)
 * network=100.64.0.0/22    one line per network, IPv4 or IPv6
 * network=2001:db8::/32
 *
 * A session route (peer /32, Framed-Route, IPv6 interface prefix, peer /128,
 * DHCPv6-PD) is copied to the kernel when its prefix is inside one of the
 * networks. The copy is a plain unicast route "dst dev <dummy>" in the main
 * table. The dummy has no linux-cp pair, so linux-cp finds no path for these
 * routes and installs nothing in VPP (with "lcp param route-no-paths" off, the
 * VPP default). FRR sees them as kernel routes: "redistribute kernel" with a
 * route-map matching the interface exports them.
 *
 * The dummy is recreated on start, which also drops copies left by a previous
 * run; with no network configured, a dummy of that name left by a previous
 * run is deleted instead. The networks are re-read on "reload" and every
 * session is resynced right after it, from the module context.
 */

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "triton.h"
#include "events.h"
#include "ap_session.h"
#include "libnetlink.h"
#include "log.h"
#include "memdebug.h"

#include "vppiputils.h"
#include "vppkroute.h"

#define KR_SECTION "vpp-route-export"
#define KR_DEF_IFNAME "pppoe-export"
#define KR_DEF_PROTO 250
#define KR_LINK_BUF 32768

struct kr_net {
	struct list_head entry;
	int af;
	int len;
	union {
		struct in_addr ip4;
		struct in6_addr ip6;
	} addr;
};

static LIST_HEAD(kr_nets);
static pthread_rwlock_t kr_nets_lock = PTHREAD_RWLOCK_INITIALIZER;

/* Fixed at start: changing them needs a restart. */
static char kr_ifname[IFNAMSIZ];
static int kr_proto;
static int kr_configured;

/* Dummy ifindex, 0 while the feature is off or the link could not be made. */
static int kr_ifindex;

static struct rtnl_handle kr_rth;
static int kr_rth_open;
static pthread_mutex_t kr_rth_lock = PTHREAD_MUTEX_INITIALIZER;

static int kr_get_ifindex(void)
{
	return __atomic_load_n(&kr_ifindex, __ATOMIC_ACQUIRE);
}

static void kr_set_ifindex(int ifindex)
{
	__atomic_store_n(&kr_ifindex, ifindex, __ATOMIC_RELEASE);
}

/*
 * Own netlink socket in the default namespace. The libnetlink helpers
 * (iproute_add & co) go through the thread-local "net" and, with HAVE_VRF,
 * look the VRF up with a handle that is never returned to the pool.
 */
static int kr_talk(struct nlmsghdr *n, struct nlmsghdr *answer)
{
	int r;

	pthread_mutex_lock(&kr_rth_lock);

	if (!kr_rth_open) {
		if (rtnl_open(&kr_rth, 0)) {
			pthread_mutex_unlock(&kr_rth_lock);
			errno = EIO;
			return -1;
		}
		kr_rth_open = 1;
	}

	r = rtnl_talk(&kr_rth, n, 0, 0, answer, NULL, NULL, 0);
	if (r < 0 && (errno == EBADF || errno == ENOTSOCK || errno == ECONNREFUSED)) {
		rtnl_close(&kr_rth);
		kr_rth_open = 0;
	}

	pthread_mutex_unlock(&kr_rth_lock);

	return r;
}

static int kr_route(int is_add, int ifindex, int af, const void *dst, int len)
{
	struct {
		struct nlmsghdr n;
		struct rtmsg r;
		char buf[256];
	} req;
	int alen = af == AF_INET ? 4 : 16;

	memset(&req, 0, sizeof(req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
	/* No NLM_F_REPLACE: never overwrite a route someone else owns. */
	req.n.nlmsg_flags = NLM_F_REQUEST | (is_add ? NLM_F_CREATE : 0);
	req.n.nlmsg_type = is_add ? RTM_NEWROUTE : RTM_DELROUTE;
	req.r.rtm_family = af;
	req.r.rtm_table = RT_TABLE_MAIN;
	req.r.rtm_protocol = kr_proto;
	req.r.rtm_scope = af == AF_INET ? RT_SCOPE_LINK : RT_SCOPE_UNIVERSE;
	req.r.rtm_type = RTN_UNICAST;
	req.r.rtm_dst_len = len;

	addattr_l(&req.n, sizeof(req), RTA_DST, dst, alen);
	addattr32(&req.n, sizeof(req), RTA_OIF, ifindex);

	if (kr_talk(&req.n, NULL) == 0)
		return 0;

	/* The same route is there already (session route added twice). */
	if (is_add && errno == EEXIST)
		return 0;

	/* Gone already: the dummy was deleted, or the route never made it. */
	if (!is_add && (errno == ESRCH || errno == ENODEV || errno == ENOENT))
		return 0;

	return -1;
}

static const char *kr_fmt(int af, const void *dst, int len, char *buf, size_t size)
{
	char ip[INET6_ADDRSTRLEN];

	if (!inet_ntop(af, dst, ip, sizeof(ip)))
		strcpy(ip, "?");
	snprintf(buf, size, "%s/%d", ip, len);

	return buf;
}

/*
 * Kernel copies in use, one entry per route and dummy, counted by holder.
 * Two sessions can hold the same prefix for a while (a subscriber with a
 * fixed address reconnects before its old session is gone, the same
 * Framed-Route or delegated prefix on both): the kernel has a single route
 * for them, so only the last holder to leave may delete it. Without the
 * count the old session took the route of the new one when it ended.
 *
 * kr_copies_lock is held across the netlink call: an add and a delete of the
 * same route from two session threads reach the kernel in the order of the
 * count. Lock order: kr_copies_lock, then kr_rth_lock (kr_talk).
 */
#define KR_COPY_BUCKETS 16384

struct kr_copy {
	struct kr_copy *next;
	int ifindex;
	int af;
	int len;
	unsigned int holders;
	uint8_t dst[16];
};

static struct kr_copy *kr_copies[KR_COPY_BUCKETS];
static pthread_mutex_t kr_copies_lock = PTHREAD_MUTEX_INITIALIZER;

static struct kr_copy **kr_copy_find(int ifindex, int af, const void *dst, int len)
{
	const uint8_t *p = dst;
	int alen = af == AF_INET ? 4 : 16;
	uint32_t h = 2166136261u;
	struct kr_copy **pc;
	int i;

	/* FNV-1a over the address and the prefix length */
	for (i = 0; i < alen; i++)
		h = (h ^ p[i]) * 16777619u;
	h = (h ^ (uint32_t)len) * 16777619u;

	for (pc = &kr_copies[h % KR_COPY_BUCKETS]; *pc; pc = &(*pc)->next) {
		struct kr_copy *c = *pc;

		if (c->ifindex == ifindex && c->af == af && c->len == len &&
		    !memcmp(c->dst, dst, alen))
			break;
	}

	/* The entry, or the end of the chain where a new one goes. */
	return pc;
}

int vpp_kroute_add(int ifindex, int af, const void *dst, int len)
{
	char buf[INET6_ADDRSTRLEN + 5];
	struct kr_copy **pc, *c;
	int err;

	pthread_mutex_lock(&kr_copies_lock);

	pc = kr_copy_find(ifindex, af, dst, len);
	if (*pc) {
		(*pc)->holders++;
		pthread_mutex_unlock(&kr_copies_lock);
		return 0;
	}

	c = _malloc(sizeof(*c));
	if (!c) {
		err = ENOMEM;
		goto err;
	}

	if (kr_route(1, ifindex, af, dst, len)) {
		err = errno;
		_free(c);
		goto err;
	}

	memset(c, 0, sizeof(*c));
	c->ifindex = ifindex;
	c->af = af;
	c->len = len;
	c->holders = 1;
	memcpy(c->dst, dst, af == AF_INET ? 4 : 16);
	*pc = c;

	pthread_mutex_unlock(&kr_copies_lock);
	return 0;

err:
	pthread_mutex_unlock(&kr_copies_lock);
	log_error("vpp-route-export: failed to add %s dev %s: %s\n",
		  kr_fmt(af, dst, len, buf, sizeof(buf)), kr_ifname, strerror(err));
	return -1;
}

int vpp_kroute_del(int ifindex, int af, const void *dst, int len)
{
	char buf[INET6_ADDRSTRLEN + 5];
	struct kr_copy **pc, *c;
	int r, err;

	pthread_mutex_lock(&kr_copies_lock);

	pc = kr_copy_find(ifindex, af, dst, len);
	c = *pc;
	/* Nothing held (the add failed), or another session still holds it. */
	if (!c || --c->holders) {
		pthread_mutex_unlock(&kr_copies_lock);
		return 0;
	}

	*pc = c->next;
	_free(c);

	r = kr_route(0, ifindex, af, dst, len);
	err = errno;

	pthread_mutex_unlock(&kr_copies_lock);

	if (r == 0)
		return 0;

	log_error("vpp-route-export: failed to delete %s dev %s: %s\n",
		  kr_fmt(af, dst, len, buf, sizeof(buf)), kr_ifname, strerror(err));
	return -1;
}

static int kr_prefix_match(const uint8_t *net, const uint8_t *dst, int len)
{
	int bytes = len / 8;
	int bits = len % 8;

	if (memcmp(net, dst, bytes))
		return 0;

	if (bits) {
		uint8_t mask = 0xff << (8 - bits);

		if ((net[bytes] & mask) != (dst[bytes] & mask))
			return 0;
	}

	return 1;
}

int vpp_kroute_lookup(int af, const void *dst, int len)
{
	struct kr_net *n;
	int ifindex = kr_get_ifindex();
	int found = 0;

	if (!ifindex)
		return 0;

	pthread_rwlock_rdlock(&kr_nets_lock);
	list_for_each_entry(n, &kr_nets, entry) {
		if (n->af != af || len < n->len)
			continue;
		if (kr_prefix_match((const uint8_t *)&n->addr, dst, n->len)) {
			found = 1;
			break;
		}
	}
	pthread_rwlock_unlock(&kr_nets_lock);

	return found ? ifindex : 0;
}

/* "a.b.c.d/len", "x::y/len" or a bare address (host route). */
static struct kr_net *kr_parse_net(const char *val)
{
	struct kr_net *n;
	char buf[INET6_ADDRSTRLEN + 5];
	char *slash, *end;
	int max;
	long len;
	uint8_t *a;
	int i;

	if (strlen(val) >= sizeof(buf))
		return NULL;
	strcpy(buf, val);

	n = _malloc(sizeof(*n));
	if (!n)
		return NULL;
	memset(n, 0, sizeof(*n));

	slash = strchr(buf, '/');
	if (slash)
		*slash = 0;

	if (inet_pton(AF_INET, buf, &n->addr.ip4) == 1) {
		n->af = AF_INET;
		max = 32;
	} else if (inet_pton(AF_INET6, buf, &n->addr.ip6) == 1) {
		n->af = AF_INET6;
		max = 128;
	} else
		goto err;

	if (slash) {
		len = strtol(slash + 1, &end, 10);
		if (slash[1] == 0 || *end || len < 0 || len > max)
			goto err;
		n->len = len;
	} else
		n->len = max;

	/* Clear host bits so the match only looks at the network part. */
	a = (uint8_t *)&n->addr;
	for (i = 0; i < max / 8; i++) {
		int bit = i * 8;

		if (bit >= n->len)
			a[i] = 0;
		else if (bit + 8 > n->len)
			a[i] &= 0xff << (8 - (n->len - bit));
	}

	return n;

err:
	_free(n);
	return NULL;
}

static void kr_free_nets(struct list_head *list)
{
	struct kr_net *n;

	while (!list_empty(list)) {
		n = list_entry(list->next, typeof(*n), entry);
		list_del(&n->entry);
		_free(n);
	}
}

/* Kind of link ifname: 1 = dummy, 0 = other kind, -1 = no such link. */
static int kr_link_is_dummy(const char *ifname, int *ifindex)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[256];
	} req;
	struct nlmsghdr *ans;
	struct ifinfomsg *ifi;
	struct rtattr *tb[IFLA_MAX + 1];
	struct rtattr *li[IFLA_INFO_MAX + 1];
	int len, r = -1;

	ans = _malloc(KR_LINK_BUF);
	if (!ans)
		return -1;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_GETLINK;
	req.i.ifi_family = AF_UNSPEC;
	addattr_l(&req.n, sizeof(req), IFLA_IFNAME, ifname, strlen(ifname) + 1);

	if (kr_talk(&req.n, ans) < 0 || ans->nlmsg_type != RTM_NEWLINK)
		goto out;

	ifi = NLMSG_DATA(ans);
	len = ans->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
	if (len < 0)
		goto out;

	*ifindex = ifi->ifi_index;
	r = 0;

	parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), len);
	if (!tb[IFLA_LINKINFO])
		goto out;

	parse_rtattr_nested(li, IFLA_INFO_MAX, tb[IFLA_LINKINFO]);
	if (li[IFLA_INFO_KIND] && !strcmp(RTA_DATA(li[IFLA_INFO_KIND]), "dummy"))
		r = 1;

out:
	_free(ans);
	return r;
}

static int kr_link_del(int ifindex)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
	} req;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = RTM_DELLINK;
	req.i.ifi_family = AF_UNSPEC;
	req.i.ifi_index = ifindex;

	return kr_talk(&req.n, NULL);
}

static int kr_link_add(const char *ifname)
{
	struct {
		struct nlmsghdr n;
		struct ifinfomsg i;
		char buf[256];
	} req;
	struct rtattr *linkinfo;

	memset(&req, 0, sizeof(req));
	req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
	req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL;
	req.n.nlmsg_type = RTM_NEWLINK;
	req.i.ifi_family = AF_UNSPEC;
	/* Up from the start: IPv4 routes need the device up, and zebra only
	 * redistributes routes whose interface is up. */
	req.i.ifi_flags = IFF_UP;
	req.i.ifi_change = IFF_UP;

	addattr_l(&req.n, sizeof(req), IFLA_IFNAME, ifname, strlen(ifname) + 1);
	linkinfo = addattr_nest(&req.n, sizeof(req), IFLA_LINKINFO);
	addattr_l(&req.n, sizeof(req), IFLA_INFO_KIND, "dummy", strlen("dummy"));
	addattr_nest_end(&req.n, linkinfo);

	return kr_talk(&req.n, NULL);
}

/*
 * Make sure the dummy exists and is up. With fresh set (start), an existing
 * dummy is deleted first so that no route of a previous run survives.
 * A link of another kind with the same name is never touched.
 */
static int kr_link_setup(int fresh)
{
	int ifindex = 0;
	int st = kr_link_is_dummy(kr_ifname, &ifindex);

	if (st == 0) {
		log_error("vpp-route-export: interface %s exists and is not a dummy, feature disabled\n",
			  kr_ifname);
		return -1;
	}

	if (st == 1 && !fresh)
		return ifindex;

	if (st == 1 && kr_link_del(ifindex)) {
		log_error("vpp-route-export: failed to delete stale %s: %s\n", kr_ifname, strerror(errno));
		return -1;
	}

	if (kr_link_add(kr_ifname)) {
		log_error("vpp-route-export: failed to create dummy %s: %s\n", kr_ifname, strerror(errno));
		return -1;
	}

	ifindex = 0;
	if (kr_link_is_dummy(kr_ifname, &ifindex) != 1 || !ifindex) {
		log_error("vpp-route-export: dummy %s not found after create\n", kr_ifname);
		return -1;
	}

	log_info1("vpp-route-export: dummy %s ready (ifindex %d)\n", kr_ifname, ifindex);

	return ifindex;
}

/*
 * Start with the feature off: delete the dummy a previous run left behind.
 * A run that died without its teardown (SIGKILL, crash) leaves its copies on
 * the dummy, and with no network configured nothing else removes them: FRR
 * would keep announcing the routes of sessions that are gone. Same rule as
 * with the feature on: only a link that is a dummy is touched.
 */
static void kr_link_cleanup(const char *ifname)
{
	int ifindex = 0;

	if (kr_link_is_dummy(ifname, &ifindex) != 1)
		return;

	if (kr_link_del(ifindex)) {
		log_error("vpp-route-export: failed to delete stale %s: %s\n", ifname, strerror(errno));
		return;
	}

	log_info1("vpp-route-export: no network configured, deleted dummy %s left by a previous run\n",
		  ifname);
}

/* Protocols zebra handles as its own, or as something else than "kernel". */
static int kr_proto_valid(long proto)
{
	if (proto < 5 || proto > 255)
		return 0; /* unspec, redirect, kernel, boot, static */
	if (proto == 11 || proto == 42)
		return 0; /* zebra, babel */
	if (proto >= 186 && proto <= 199)
		return 0; /* bgp ... srte and the rest of zebra's range */
	return 1;
}

/*
 * Module context: a reload only queues one call here, and this call queues
 * the per-session sync after the reload is done. Queuing one call per session
 * from the reload handler woke every session context while the reload ran.
 *
 * The context needs a close: on shutdown triton_terminate() asks every
 * context to close and only lets the threads exit once all of them are
 * unregistered. Without it accel hung on stop until systemd sent SIGKILL.
 */
static void kr_ctx_close(struct triton_context_t *ctx);
static struct triton_context_t kr_ctx = {
	.close = kr_ctx_close,
};
static int kr_sync_pending;
static int kr_ctx_closed;

static void kr_ctx_close(struct triton_context_t *ctx)
{
	/* After the unregister kr_ctx.tpd is NULL: a reload must not queue on it. */
	__atomic_store_n(&kr_ctx_closed, 1, __ATOMIC_SEQ_CST);
	triton_context_unregister(ctx);
}

static void kr_sync_sessions(void *unused)
{
	struct ap_session *ses;

	/* A reload from now on queues a new pass with its own config. */
	__atomic_store_n(&kr_sync_pending, 0, __ATOMIC_SEQ_CST);

	pthread_rwlock_rdlock(&ses_lock);
	list_for_each_entry(ses, &ses_list, entry) {
		if (ses->ctrl->type != CTRL_TYPE_PPPOE || !ses->ctrl->ctx)
			continue;
		triton_context_call(ses->ctrl->ctx, (triton_event_func)vpp_iproute_kernel_sync, ses);
	}
	pthread_rwlock_unlock(&ses_lock);
}

static void kr_load_config(int start)
{
	struct conf_sect_t *s = conf_get_section(KR_SECTION);
	struct conf_option_t *opt;
	LIST_HEAD(nets);
	LIST_HEAD(old);
	const char *ifname = KR_DEF_IFNAME;
	long proto = KR_DEF_PROTO;
	int n_nets = 0;
	int fresh = start;
	int ifindex;

	if (s) {
		list_for_each_entry(opt, &s->items, entry) {
			if (!strcmp(opt->name, "interface") && opt->val) {
				ifname = opt->val;
			} else if (!strcmp(opt->name, "proto") && opt->val) {
				char *end;

				proto = strtol(opt->val, &end, 10);
				if (*end || !kr_proto_valid(proto)) {
					log_error("vpp-route-export: invalid proto '%s' (5-255, not a zebra protocol), using %d\n",
						  opt->val, KR_DEF_PROTO);
					proto = KR_DEF_PROTO;
				}
			} else if (!strcmp(opt->name, "network") && opt->val) {
				struct kr_net *n = kr_parse_net(opt->val);

				if (!n) {
					log_error("vpp-route-export: invalid network '%s', ignored\n", opt->val);
					continue;
				}
				list_add_tail(&n->entry, &nets);
				n_nets++;
			} else {
				log_warn("vpp-route-export: unknown option '%s'\n", opt->name);
			}
		}
	}

	if (strlen(ifname) >= IFNAMSIZ) {
		log_error("vpp-route-export: interface name '%s' too long, feature disabled\n", ifname);
		kr_free_nets(&nets);
		n_nets = 0;
	}

	if (!kr_configured) {
		/* First time on (start or reload): take name/proto, start clean. */
		if (n_nets) {
			strcpy(kr_ifname, ifname);
			kr_proto = proto;
			kr_configured = 1;
			fresh = 1;
		}
	} else if (strcmp(ifname, kr_ifname) || proto != kr_proto) {
		log_warn("vpp-route-export: interface/proto change needs a restart, keeping %s proto %d\n",
			 kr_ifname, kr_proto);
	}

	pthread_rwlock_wrlock(&kr_nets_lock);
	list_splice_init(&kr_nets, &old);
	list_splice_init(&nets, &kr_nets);
	pthread_rwlock_unlock(&kr_nets_lock);
	kr_free_nets(&old);

	if (n_nets) {
		/* Afterwards, recreate the dummy only if it went missing. */
		ifindex = kr_link_setup(fresh);
		kr_set_ifindex(ifindex > 0 ? ifindex : 0);
	} else {
		/* No network: sessions drop their copies; the dummy stays. */
		kr_set_ifindex(0);

		/* At start no session holds a copy: nothing on it is ours to keep. */
		if (start && strlen(ifname) < IFNAMSIZ)
			kr_link_cleanup(ifname);
	}

	/* Several reloads in a row are served by a single pending pass.
	 * After the close (shutdown) the context is gone: nothing to sync. */
	if (!start && !__atomic_load_n(&kr_ctx_closed, __ATOMIC_SEQ_CST) &&
	    !__atomic_exchange_n(&kr_sync_pending, 1, __ATOMIC_SEQ_CST))
		triton_context_call(&kr_ctx, kr_sync_sessions, NULL);
}

static void kr_reload(void)
{
	kr_load_config(0);
}

static void vppkroute_init(void)
{
	triton_context_register(&kr_ctx, NULL);
	triton_context_wakeup(&kr_ctx);

	kr_load_config(1);

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)kr_reload);
}

DEFINE_INIT(21, vppkroute_init);
