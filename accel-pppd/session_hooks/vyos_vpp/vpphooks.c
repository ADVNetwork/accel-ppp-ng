/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

/*
 * Session hooks of the VPP dataplane.
 *
 * What a session has in VPP (the pppoeN interface, its routes, its policers)
 * belongs to one VPP process. The rules this file keeps:
 *
 *  - The session records the VPP process that made its interface (generation
 *    and pid, vpputils.h). Every later call for that session checks, under
 *    vpp_lock, that the VPP that answers is still that process. After a VPP
 *    restart the same sw_if_index is nothing, or the interface of another
 *    subscriber; before this check, the teardown of an old session removed
 *    the policer of the new session with the same index and plan, and the
 *    route watchdog put the route of an old session on the interface of a
 *    new one.
 *  - When a connection reaches a new VPP process, the sessions made in the
 *    previous one are terminated at once: they have nothing in the dataplane
 *    and never will.
 *  - A teardown tries every step, whatever the result of the previous one.
 *    What VPP did not confirm (the connection was lost, VPP did not answer)
 *    goes to a list that the module timer retries. Until the delete of the
 *    session is confirmed, or VPP restarts, the PPPoE session id is not
 *    given to another subscriber: the VPP fast path finds the session by the
 *    id alone.
 *  - A session is terminated only from its own context.
 */

#include <linux/if_ether.h> /* ETH_P_ALL */
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>
#include <errno.h>
#include <sys/syscall.h>

#include "triton.h"
#include "events.h"
#include "ap_session_hooks.h"

#include "ap_session.h"
#include "ppp.h"
#include "ipdb.h"
#include "memdebug.h"
#include "log.h"

#include "vpputils.h"
#include "vppiputils.h"
#include "vpppolicer.h"
#include "vpppoe.h"
#include "vppstats.h"

#include "vpphooks.h"

extern struct list_head ses_list;
extern pthread_rwlock_t ses_lock;

#define VPP_ROUTE_WATCHDOG_PERIOD_MS 60000
#define VPP_ROUTE_WATCHDOG_BOOT_SKIP_SEC 120
#define VPP_ROUTE_WATCHDOG_MIN_SESSION_AGE_SEC 60

/* Module timer: connection check, deferred cleanup, sweep after a VPP restart. */
#define VPP_TICK_MS 2000
/* Deferred cleanups tried per tick, and tries of one before it is given up. */
#define VPP_DEFERRED_PER_TICK 512
#define VPP_DEFERRED_MAX_TRIES 30

static time_t vpp_route_watchdog_boot;

/* [vpp] session-mtu=0 leaves the pppoeN with the VPP default MTU */
static int conf_session_mtu = 1;

/* NOTE: functions from ctrl/pppoe plugin! */
void pppoe_get_session_mac_and_sid(struct ap_session *ses, uint8_t **mac, uint16_t *sid);
void pppoe_sid_release(uint16_t sid);

struct ap_session_hooks_t vpp_hooks;

static void *pd_key;

struct vpphook_private_data_t *vpphook_get_pd(struct ap_session *ses)
{
	struct ap_private *pd;

	list_for_each_entry(pd, &ses->pd_list, entry) {
		if (pd->key == &pd_key)
			return container_of(pd, struct vpphook_private_data_t, pd);
	}

	return NULL;
}

struct vpphook_private_data_t *vpphook_live(struct ap_session *ses, uint32_t *sw_if_index,
					    uint32_t *gen)
{
	struct vpphook_private_data_t *pd;
	uint32_t idx, g;

	if (!ses)
		return NULL;

	pd = vpphook_get_pd(ses);
	if (!pd)
		return NULL;

	idx = __atomic_load_n(&pd->vpp_sw_if_index, __ATOMIC_ACQUIRE);
	g = __atomic_load_n(&pd->vpp_gen, __ATOMIC_ACQUIRE);
	if (idx == ~0U || g != vpp_generation())
		return NULL;

	*sw_if_index = idx;
	*gen = g;
	return pd;
}

int vpphook_session_hook_init(struct ap_session *ses)
{
	struct vpphook_private_data_t *pd = _malloc(sizeof(struct vpphook_private_data_t));
	if (pd == NULL)
		return -1;

	memset(pd, 0, sizeof(struct vpphook_private_data_t));
	pd->pd.key = &pd_key;
	pd->vpp_sw_if_index = ~0U;

	INIT_LIST_HEAD(&pd->vpp_routes);
	pthread_mutex_init(&pd->vpp_routes_lock, NULL);

	list_add_tail(&pd->pd.entry, &ses->pd_list);

	return 0; /* return 0 is ok */
}

void vpphook_session_hook_deinit(struct ap_session *ses)
{
	struct vpphook_private_data_t *pd = vpphook_get_pd(ses);
	if (pd == NULL)
		return;

	/* Normally empty already (pppoe_terminate flushes the routes). */
	vpp_iproute_forget(ses);

	/*
	 * The session left ses_list under the write lock before this point, and
	 * the watchdog only works on a session with the read lock held: nobody
	 * else has the lock now.
	 */
	list_del(&pd->pd.entry);
	pthread_mutex_destroy(&pd->vpp_routes_lock);
	_free(pd);
}

/* ---- Cleanup that VPP did not confirm ----------------------------------- */

/*
 * What is left in VPP of a session that ended while VPP could not be told:
 * routes through its interface, policers by name, and the PPPoE session
 * itself, with its id held.
 */
struct vpp_deferred {
	struct list_head entry;
	uint32_t gen;
	uint32_t ifindex;
	int tries;
	int del_session;
	uint16_t sid;
	uint8_t mac[ETH_ALEN];
	in_addr_t peer_addr;
	int n_policers;
	char policers[2][POLICER_NAME_MAX_LEN];
	int n_routes;
	struct vpp_route_key *routes;
};

static LIST_HEAD(vpp_deferred_list);
static pthread_mutex_t vpp_deferred_lock = PTHREAD_MUTEX_INITIALIZER;
static unsigned int vpp_deferred_count;
/*
 * Held for a whole pass of vpphook_deferred_run(), which works on the entries
 * outside the list. Lock order: vpp_deferred_run_lock, then vpp_deferred_lock
 * or vpp_lock; never taken with vpp_lock held.
 */
static pthread_mutex_t vpp_deferred_run_lock = PTHREAD_MUTEX_INITIALIZER;

/*
 * The call got no answer from the VPP of generation gen, and that VPP may
 * still be there. An answer of the API, even an error, is an answer; so is a
 * VPP that restarted, which has nothing left to remove.
 */
static int vpphook_unconfirmed(int ret, uint32_t gen)
{
	return (ret > 0 || ret == -1) && vpp_generation() == gen;
}

/* routes is malloc'ed and becomes of the list (or is freed here) */
static void vpphook_defer(uint32_t gen, uint32_t ifindex, int del_session, const uint8_t *mac,
			  uint16_t sid, in_addr_t peer_addr,
			  char policers[2][POLICER_NAME_MAX_LEN], int n_policers,
			  struct vpp_route_key *routes, int n_routes)
{
	struct vpp_deferred *d = malloc(sizeof(*d));
	int i;

	if (!d) {
		log_error("vpp: out of memory, the cleanup of pppoe sid=%u is not retried\n", sid);
		if (del_session)
			pppoe_sid_release(sid);
		free(routes);
		return;
	}

	memset(d, 0, sizeof(*d));
	d->gen = gen;
	d->ifindex = ifindex;
	d->del_session = del_session;
	d->sid = sid;
	memcpy(d->mac, mac, ETH_ALEN);
	d->peer_addr = peer_addr;
	for (i = 0; i < n_policers && i < 2; i++)
		memcpy(d->policers[d->n_policers++], policers[i], POLICER_NAME_MAX_LEN);
	d->routes = routes;
	d->n_routes = n_routes;

	pthread_mutex_lock(&vpp_deferred_lock);
	list_add_tail(&d->entry, &vpp_deferred_list);
	vpp_deferred_count++;
	pthread_mutex_unlock(&vpp_deferred_lock);
}

/*
 * A session is about to make a policer with this name: it is not a leftover
 * any more, and the retry must not delete it under that session. A pass in
 * progress is waited for: what it deletes, it deletes before the session
 * makes its own.
 */
void vpphook_deferred_forget_policer(uint32_t gen, const char *name)
{
	struct vpp_deferred *d;
	int i;

	if (!__atomic_load_n(&vpp_deferred_count, __ATOMIC_RELAXED))
		return;

	pthread_mutex_lock(&vpp_deferred_run_lock);
	pthread_mutex_lock(&vpp_deferred_lock);
	list_for_each_entry(d, &vpp_deferred_list, entry) {
		if (d->gen != gen)
			continue;
		for (i = 0; i < d->n_policers; i++) {
			if (strcmp(d->policers[i], name))
				continue;
			if (i + 1 < d->n_policers)
				memcpy(d->policers[i], d->policers[d->n_policers - 1], POLICER_NAME_MAX_LEN);
			d->n_policers--;
			i--;
		}
	}
	pthread_mutex_unlock(&vpp_deferred_lock);
	pthread_mutex_unlock(&vpp_deferred_run_lock);
}

/*
 * One entry of the list. Returns 0 when nothing of it is left in VPP, 1 when
 * VPP gave no answer (try again later), 2 when the VPP it belonged to is
 * gone, and all that was left in it too.
 */
static int vpphook_deferred_one(struct vpp_deferred *d, int *done_ses, int *done_pol, int *done_rt)
{
	int r;

	if (vpp_generation() != d->gen)
		return 2;

	/* the routes while the interface is still there, then the rest */
	while (d->n_routes) {
		r = vpp_route_del(d->gen, d->ifindex, &d->routes[d->n_routes - 1]);
		if (vpp_generation() != d->gen)
			return 2;
		if (vpphook_unconfirmed(r, d->gen))
			return 1;
		if (r && r != VPP_API_ERR_NO_SUCH_ENTRY)
			log_error("vpp: leftover route of pppoe sid=%u del failed ret=%d\n", d->sid, r);
		d->n_routes--;
		(*done_rt)++;
	}

	while (d->n_policers) {
		r = vpppolicer_del_name(d->gen, d->policers[d->n_policers - 1]);
		if (vpp_generation() != d->gen)
			return 2;
		if (vpphook_unconfirmed(r, d->gen))
			return 1;
		if (r)
			log_error("vpp: leftover policer %s del failed ret=%d\n",
				  d->policers[d->n_policers - 1], r);
		d->n_policers--;
		(*done_pol)++;
	}

	if (d->del_session) {
		r = vpppoe_sync_del_pppoe_interface(d->gen, d->mac, d->sid, d->peer_addr);
		if (vpp_generation() != d->gen)
			return 2;
		if (vpphook_unconfirmed(r, d->gen))
			return 1;
		if (r)
			log_error("vpp: leftover pppoe session sid=%u del failed ret=%d\n", d->sid, r);
		d->del_session = 0;
		pppoe_sid_release(d->sid);
		(*done_ses)++;
	}

	return 0;
}

/* Module context. Entries with nothing left to do are freed here. */
static void vpphook_deferred_run(void)
{
	struct vpp_deferred *d;
	LIST_HEAD(work);
	LIST_HEAD(keep);
	int budget = VPP_DEFERRED_PER_TICK;
	int stop = 0, r;
	int done_ses = 0, done_pol = 0, done_rt = 0, gone = 0;

	pthread_mutex_lock(&vpp_deferred_run_lock);

	pthread_mutex_lock(&vpp_deferred_lock);
	list_splice_init(&vpp_deferred_list, &work);
	pthread_mutex_unlock(&vpp_deferred_lock);

	while (!list_empty(&work)) {
		d = list_entry(work.next, typeof(*d), entry);
		list_del(&d->entry);

		/* dropping what a VPP that is gone left costs nothing: no budget */
		if (vpp_generation() != d->gen) {
			r = 2;
		} else if (stop || budget <= 0) {
			list_add_tail(&d->entry, &keep);
			continue;
		} else {
			budget--;
			r = vpphook_deferred_one(d, &done_ses, &done_pol, &done_rt);
		}

		if (r == 1) {
			if (++d->tries < VPP_DEFERRED_MAX_TRIES) {
				/* VPP does not answer: the others wait for the next tick too */
				stop = 1;
				list_add_tail(&d->entry, &keep);
				continue;
			}
			log_error("vpp: giving up the cleanup of pppoe sid=%u after %d tries%s\n",
				  d->sid, d->tries, d->del_session ? " (its session may still be in VPP)" : "");
		} else if (r == 2) {
			gone++;
		}

		/* a session id still held goes back: its session is gone, or given up */
		if (d->del_session)
			pppoe_sid_release(d->sid);
		pthread_mutex_lock(&vpp_deferred_lock);
		vpp_deferred_count--;
		pthread_mutex_unlock(&vpp_deferred_lock);
		free(d->routes);
		free(d);
	}

	if (!list_empty(&keep)) {
		pthread_mutex_lock(&vpp_deferred_lock);
		list_splice(&keep, &vpp_deferred_list);
		pthread_mutex_unlock(&vpp_deferred_lock);
	}

	pthread_mutex_unlock(&vpp_deferred_run_lock);

	if (done_ses || done_pol || done_rt)
		log_warn("vpp: cleanup that VPP had not confirmed: removed now %d pppoe session(s), "
			 "%d policer(s) and %d route(s); %u session(s) still waiting\n",
			 done_ses, done_pol, done_rt,
			 __atomic_load_n(&vpp_deferred_count, __ATOMIC_RELAXED));
	if (gone)
		log_warn("vpp: cleanup of %d session(s) dropped: the VPP they were in restarted\n", gone);
}

/* ---- Session interface --------------------------------------------------- */

static void vpphook_set_index(struct vpphook_private_data_t *pd, uint32_t ifindex, uint32_t gen,
			      uint32_t pid)
{
	/* the index last: whoever sees it sees the VPP it belongs to */
	__atomic_store_n(&pd->vpp_gen, gen, __ATOMIC_RELEASE);
	__atomic_store_n(&pd->vpp_pid, pid, __ATOMIC_RELEASE);
	__atomic_store_n(&pd->vpp_sw_if_index, ifindex, __ATOMIC_RELEASE);
}

/*
 * Remove from VPP everything the session has there. Every step is tried.
 * Returns 1 when the delete of the PPPoE session was not confirmed: its
 * session id stays held until the deferred cleanup gets an answer.
 */
static int vpphook_teardown(struct ap_session *ses, struct vpphook_private_data_t *pd)
{
	char policers[2][POLICER_NAME_MAX_LEN];
	char ipbuf[INET_ADDRSTRLEN] = "0.0.0.0";
	struct vpp_route_key *routes = NULL;
	uint32_t ifindex, gen;
	uint8_t *mac = NULL;
	uint16_t sid;
	in_addr_t peer_addr = 0;
	int ret, n_policers, n_routes, hold = 0;

	pppoe_get_session_mac_and_sid(ses, &mac, &sid);
	if (ses->ipv4 && ses->ipv4->peer_addr) {
		peer_addr = ses->ipv4->peer_addr;
		inet_ntop(AF_INET, &peer_addr, ipbuf, sizeof(ipbuf));
	}

	if (!vpphook_live(ses, &ifindex, &gen)) {
		/*
		 * No interface, or one of a VPP that restarted: VPP has nothing
		 * of this session. The saved routes still have kernel copies.
		 */
		__atomic_store_n(&pd->vpp_sw_if_index, ~0U, __ATOMIC_RELEASE);
		vpp_iproute_flush(ses, 0, 0, ~0U, NULL);
		vpppolicer_remove_limiter(ses);

		/*
		 * An add that got no answer may have made the session in VPP
		 * all the same. The delete says so; "no such session" is fine.
		 */
		gen = pd->vpp_add_gen;
		pd->vpp_add_gen = 0;
		if (gen && gen == vpp_generation()) {
			ret = vpppoe_sync_del_pppoe_interface(gen, mac, sid, peer_addr);
			if (vpphook_unconfirmed(ret, gen)) {
				vpphook_defer(gen, ~0U, 1, mac, sid, peer_addr, NULL, 0, NULL, 0);
				hold = 1;
			}
		}

		return hold;
	}

	/*
	 * No answer from VPP is not worth a line per session (thousands end
	 * together when VPP goes away; the tick says how many are waiting):
	 * the error lines are for what VPP refused.
	 */
	ret = vpppolicer_remove_limiter(ses);
	if (ret && !vpphook_unconfirmed(ret, gen))
		log_ppp_error("vpp: pppoe terminate policer_remove failed sid=%u peer=%s ret=%d\n",
			      sid, ipbuf, ret);
	else if (ret)
		log_ppp_info2("vpp: no answer from VPP removing the policers, sid=%u peer=%s\n", sid, ipbuf);
	n_policers = vpppolicer_leftover(ses, ifindex, policers);

	/*
	 * From here on the session has no interface for anyone else: the
	 * route watchdog of another thread cannot put a route back on it
	 * while, or after, the routes are removed below.
	 */
	__atomic_store_n(&pd->vpp_sw_if_index, ~0U, __ATOMIC_RELEASE);

	n_routes = vpp_iproute_flush(ses, 1, gen, ifindex, &routes);

	ret = vpppoe_sync_del_pppoe_interface(gen, mac, sid, peer_addr);
	hold = vpphook_unconfirmed(ret, gen);
	if (ret && !hold)
		log_ppp_error("vpp: pppoe session del failed sid=%u peer=%s ret=%d\n", sid, ipbuf, ret);
	else if (ret)
		log_ppp_info2("vpp: no answer from VPP deleting the session, sid=%u peer=%s\n", sid, ipbuf);

	if (hold || n_policers || n_routes)
		vpphook_defer(gen, ifindex, hold, mac, sid, peer_addr, policers, n_policers,
			      routes, n_routes);
	else
		free(routes);

	return hold;
}

int vpphook_pppoe_create_vpp_session_interface(struct ap_session *ses)
{
	struct vpphook_private_data_t *pd = vpphook_get_pd(ses);
	uint32_t ifindex = ~0U, gen = 0, pid = 0;
	int ret = 0, r;
	uint8_t *mac = NULL;
	uint16_t sid;
	in_addr_t peer_addr = 0;
	char ipbuf[INET_ADDRSTRLEN] = "0.0.0.0";

	if (!pd)
		return -1;

	pppoe_get_session_mac_and_sid(ses, &mac, &sid);

	if (ses->ipv4) {
		peer_addr = ses->ipv4->peer_addr;
		if (!peer_addr) {
			log_ppp_error("vpp: pppoe create sid=%u with zero peer_addr, aborting\n", sid);
			return -1;
		}
		inet_ntop(AF_INET, &peer_addr, ipbuf, sizeof(ipbuf));
	}

	ret = vpppoe_sync_add_pppoe_interface(mac, sid, peer_addr, &ifindex, &gen, &pid);
	if (ret == VPP_API_ERR_TUNNEL_EXIST) {
		/*
		 * VPP has a session with this MAC and session id, and accel
		 * has none (the id was free): one whose add or delete got
		 * lost. It is ours to remove; then the add once more.
		 */
		log_ppp_warn("vpp: pppoe session sid=%u already in VPP, removing it and adding again\n", sid);
		r = vpppoe_sync_del_pppoe_interface(gen, mac, sid, peer_addr);
		if (r == 0)
			ret = vpppoe_sync_add_pppoe_interface(mac, sid, peer_addr, &ifindex, &gen, &pid);
	}
	if (ret) {
		/* no answer: VPP may have made the session, the teardown asks */
		if (ret > 0)
			pd->vpp_add_gen = gen;
		log_ppp_error("vpp: pppoe session add failed sid=%u peer=%s ret=%d\n", sid, ipbuf, ret);
		return ret;
	}

	/* From here on the session owns an interface: a failure removes it. */
	pd->vpp_add_gen = 0;
	vpphook_set_index(pd, ifindex, gen, pid);

	ret = vpppoe_dump_interface_name(gen, ifindex, ses->ifname, AP_IFNAME_LEN);
	if (ret) {
		log_ppp_error("vpp: no name for the new interface sw_if_index=%u sid=%u ret=%d\n",
			      ifindex, sid, ret);
		goto undo;
	}

	/*
	 * The MTU the peer asked for in LCP, before any route goes through
	 * the interface. A failure is not worth the session: the interface
	 * keeps the MTU it had (the VPP default if it is new).
	 */
	if (conf_session_mtu && ses->ctrl->ppp) {
		struct ppp_t *ppp = container_of(ses, typeof(*ppp), ses);

		if (ppp->mtu >= 68 && ppp->mtu <= 65535) {
			r = vpppoe_set_mtu(gen, ifindex, ppp->mtu);
			if (r)
				log_ppp_warn("vpp: mtu %d not applied to %s, ret=%d\n",
					     ppp->mtu, ses->ifname, r);
		}
	}

	if (ses->ipv4) {
		r = vpppoe_set_feature(gen, ifindex, 0, "ip4-not-enabled", "ip4-unicast");
		if (r)
			log_ppp_warn("vpp: ip4 not enabled on %s, ret=%d\n", ses->ifname, r);

		ret = vpp_iproute_add_del(ses, 1, peer_addr, 32);
		if (ret) {
			log_ppp_error("vpp: pppoe route add failed sid=%u peer=%s ret=%d\n",
				      sid, ipbuf, ret);
			goto undo;
		}
	}

	if (ses->ipv6) {
		r = vpppoe_set_feature(gen, ifindex, 0, "ip6-not-enabled", "ip6-unicast");
		if (r)
			log_ppp_warn("vpp: ip6 not enabled on %s, ret=%d\n", ses->ifname, r);
	}

	return 0;

undo:
	/* a held session id is given back by the deferred cleanup */
	vpphook_teardown(ses, pd);
	return ret;
}

int vpphook_pppoe_terminate(struct ap_session *ses, int hard)
{
	struct vpphook_private_data_t *pd = vpphook_get_pd(ses);

	if (!pd)
		return 0;

	return vpphook_teardown(ses, pd);
}

/* ---- Sessions of a VPP that restarted ------------------------------------ */

static struct triton_context_t vpp_ctx;
static int vpp_ctx_closed;
static struct triton_timer_t vpp_tick_timer;
static struct triton_timer_t vpp_route_watchdog_timer;
static int vpp_sweep_pending;

/* session context */
static void vpphook_stale_terminate(struct ap_session *ses)
{
	log_ppp_warn("vpp: VPP restarted, session is not in the dataplane any more\n");
	ap_session_terminate(ses, TERM_NAS_REBOOT, 1);
}

/*
 * Module context. Ask every session whose interface was made in a previous
 * VPP process to end, each in its own context. A session with no interface
 * yet is left alone: it will get one in the VPP that runs now.
 */
static void vpphook_sweep(void)
{
	struct vpphook_private_data_t *pd;
	struct ap_session *ses;
	uint32_t cur = vpp_generation();
	int n = 0;

	pthread_rwlock_rdlock(&ses_lock);
	list_for_each_entry(ses, &ses_list, entry) {
		if (ses->hooks != &vpp_hooks || !ses->ctrl->ctx)
			continue;

		pd = vpphook_get_pd(ses);
		if (!pd)
			continue;

		if (__atomic_load_n(&pd->vpp_sw_if_index, __ATOMIC_ACQUIRE) == ~0U ||
		    __atomic_load_n(&pd->vpp_gen, __ATOMIC_ACQUIRE) == cur)
			continue;

		if (__atomic_exchange_n(&pd->stale_kill, 1, __ATOMIC_SEQ_CST))
			continue;

		triton_context_call(ses->ctrl->ctx, (triton_event_func)vpphook_stale_terminate, ses);
		n++;
	}
	pthread_rwlock_unlock(&ses_lock);

	if (n)
		log_warn("vpp: terminating %d session(s) made in a VPP process that is gone\n", n);
}

/* ---- Watch on the VPP process -------------------------------------------- */

/*
 * A pidfd of the VPP process the API is connected to: readable when that
 * process exits, however it dies. What is done then cannot wait for the next
 * tick: the stat segment of the dead VPP has to be unmapped before the VPP
 * that systemd starts next asks for its hugepages (vppstats.c).
 */
static struct triton_md_handler_t vpp_pidfd_hnd = { .fd = -1 };
static uint32_t vpp_pidfd_pid;
/* pid already seen to be gone: no second look until the API finds another VPP */
static uint32_t vpp_gone_pid;

static void vpphook_unwatch(void)
{
	if (vpp_pidfd_hnd.tpd)
		triton_md_unregister_handler(&vpp_pidfd_hnd, 1);
	else if (vpp_pidfd_hnd.fd >= 0)
		close(vpp_pidfd_hnd.fd);
	vpp_pidfd_hnd.fd = -1;
	vpp_pidfd_pid = 0;
}

static void vpphook_vpp_gone(uint32_t pid)
{
	vpp_gone_pid = pid;
	log_warn("vpp: the VPP process (pid %u) exited\n", pid);
	vpp_stats_drop();
	vpp_connection_lost();
}

static int vpphook_pidfd_read(struct triton_md_handler_t *h)
{
	uint32_t pid = vpp_pidfd_pid;

	vpphook_unwatch();
	vpphook_vpp_gone(pid);

	/* the handler is unregistered: nothing to arm again */
	return 1;
}

/* Module context: keep the watch on the VPP process of the current connection. */
static void vpphook_watch(void)
{
	uint32_t pid = vpp_instance_pid();
	int fd;

	if (!pid || pid == vpp_pidfd_pid || pid == vpp_gone_pid)
		return;

	vpphook_unwatch();

	fd = syscall(SYS_pidfd_open, pid, 0);
	if (fd < 0) {
		/* gone already (the tick will reconnect), or no pidfd in this kernel */
		if (errno == ESRCH)
			vpphook_vpp_gone(pid);
		return;
	}

	vpp_pidfd_pid = pid;
	vpp_pidfd_hnd.fd = fd;
	vpp_pidfd_hnd.read = vpphook_pidfd_read;
	triton_md_register_handler(&vpp_ctx, &vpp_pidfd_hnd);
	triton_md_enable_handler(&vpp_pidfd_hnd, MD_MODE_READ);
}

void vpphook_vpp_restarted(void)
{
	/* the tick does the sweep: this runs with vpp_lock held, in any context */
	__atomic_store_n(&vpp_sweep_pending, 1, __ATOMIC_SEQ_CST);
}

static void vpphook_tick(struct triton_timer_t *t)
{
	static unsigned int vpp_deferred_logged;
	int up = vpp_keepalive();
	unsigned int n;

	if (up)
		vpphook_watch();

	if (__atomic_exchange_n(&vpp_sweep_pending, 0, __ATOMIC_SEQ_CST))
		vpphook_sweep();

	/*
	 * With no connection there is nobody to ask, and whether the VPP that
	 * comes back is the same one is not known yet: the list waits.
	 */
	n = __atomic_load_n(&vpp_deferred_count, __ATOMIC_RELAXED);
	if (n && n != vpp_deferred_logged)
		log_warn("vpp: %u session(s) ended with no answer from VPP: what they left there is "
			 "removed when VPP answers, or goes away with it\n", n);
	vpp_deferred_logged = n;

	if (up && n)
		vpphook_deferred_run();
}

/* ---- Route watchdog ------------------------------------------------------ */

/* session context */
static void vpphook_watchdog_terminate(struct ap_session *ses)
{
	ap_session_terminate(ses, TERM_NAS_ERROR, 0);
}

/* Reinstall dataplane routes before terminating the PPPoE session. */
static int vpphook_watchdog_reinstall_v4(struct ap_session *ses, uint32_t gen)
{
	int ret;

	ret = vpp_iproute_add_del(ses, 1, ses->ipv4->peer_addr, 32);
	if (ret)
		return ret;

	return vpp_ip4_host_route_present(gen, ses->ipv4->peer_addr) == 1 ? 0 : -1;
}

static int vpphook_watchdog_reinstall_pd(struct ap_session *ses, uint32_t gen,
					 const struct ipv6db_addr_t *pfx)
{
	int ret;

	ret = vpp_ip6route_add_del(ses, 1, &pfx->addr, pfx->prefix_len);
	if (ret)
		return ret;

	return vpp_ip6_prefix_route_present(gen, &pfx->addr, pfx->prefix_len) == 1 ?
	       0 : -1;
}

static void vpphook_route_watchdog(struct triton_timer_t *t)
{
	struct ap_session *ses;
	struct ipv6db_addr_t *v6p;
	char ipbuf[INET_ADDRSTRLEN];
	char ip6buf[INET6_ADDRSTRLEN];
	time_t now = time(NULL);
	int route_st;

	/* Skip bring-up storm: mass create holds vpp_lock for seconds per batch. */
	if (now - vpp_route_watchdog_boot < VPP_ROUTE_WATCHDOG_BOOT_SKIP_SEC)
		return;

	/* Sessions still activating or mass teardown in progress — VPP may lag. */
	if (ap_session_stat.starting > 0 || ap_session_stat.finishing > 50)
		return;

	pthread_rwlock_rdlock(&ses_lock);
	list_for_each_entry(ses, &ses_list, entry) {
		uint32_t ifindex, gen;

		if (ses->ctrl->type != CTRL_TYPE_PPPOE || !ses->ctrl->ctx)
			continue;
		if (ses->state != AP_STATE_ACTIVE || ses->terminated)
			continue;
		if (!ses->ipv4 || !ses->ipv4->peer_addr)
			continue;
		if (now - ses->start_time < VPP_ROUTE_WATCHDOG_MIN_SESSION_AGE_SEC)
			continue;

		/* only sessions of the VPP that runs now: the sweep ends the others */
		if (!vpphook_live(ses, &ifindex, &gen))
			continue;

		route_st = vpp_ip4_host_route_present(gen, ses->ipv4->peer_addr);
		if (route_st != 0)
			continue;

		inet_ntop(AF_INET, &ses->ipv4->peer_addr, ipbuf, sizeof(ipbuf));
		if (vpphook_watchdog_reinstall_v4(ses, gen) == 0) {
			log_info2("vpp: reinstalled missing /32 route for %s on %s (sw_if_index %u)\n",
				 ipbuf, ses->ifname, ifindex);
			continue;
		}

		/* VPP restarted meanwhile: not a missing route */
		if (gen != vpp_generation())
			continue;

		log_info2("vpp: terminating pppoe session %s: missing /32 route for %s on sw_if_index %u (reinstall failed)\n",
			  ses->ifname, ipbuf, ifindex);
		triton_context_call(ses->ctrl->ctx, (triton_event_func)vpphook_watchdog_terminate, ses);
		continue;
	}

	list_for_each_entry(ses, &ses_list, entry) {
		uint32_t ifindex, gen;

		if (ses->ctrl->type != CTRL_TYPE_PPPOE || !ses->ctrl->ctx)
			continue;
		if (ses->state != AP_STATE_ACTIVE || ses->terminated)
			continue;
		if (!ses->ipv6_dp || list_empty(&ses->ipv6_dp->prefix_list))
			continue;
		if (now - ses->start_time < VPP_ROUTE_WATCHDOG_MIN_SESSION_AGE_SEC)
			continue;

		if (!vpphook_live(ses, &ifindex, &gen))
			continue;

		list_for_each_entry(v6p, &ses->ipv6_dp->prefix_list, entry) {
			route_st = vpp_ip6_prefix_route_present(gen, &v6p->addr,
								v6p->prefix_len);
			if (route_st < 0)
				continue;
			if (route_st != 0)
				continue;

			inet_ntop(AF_INET6, &v6p->addr, ip6buf, sizeof(ip6buf));
			if (vpphook_watchdog_reinstall_pd(ses, gen, v6p) == 0) {
				log_info2("vpp: reinstalled missing PD route %s/%i on %s (sw_if_index %u)\n",
					 ip6buf, v6p->prefix_len, ses->ifname, ifindex);
				continue;
			}

			if (gen != vpp_generation())
				break;

			log_info2("vpp: terminating pppoe session %s: missing PD route %s/%i on sw_if_index %u (reinstall failed)\n",
				  ses->ifname, ip6buf, v6p->prefix_len, ifindex);
			triton_context_call(ses->ctrl->ctx, (triton_event_func)vpphook_watchdog_terminate, ses);
			break;
		}
	}
	pthread_rwlock_unlock(&ses_lock);
}

/* ---- Address and route hooks --------------------------------------------- */

int vpphook_ipaddr_add(struct ap_session *ses, int ifindex, in_addr_t addr, int mask)
{
	/* setup route instead */
	return vpp_iproute_add_del(ses, 1, addr, mask);
}

int vpphook_ipaddr_add_peer(struct ap_session *ses, int ifindex, in_addr_t addr, in_addr_t peer_addr)
{
	/* setup route instead */
	return vpp_iproute_add_del(ses, 1, peer_addr, 32);
}

int vpphook_ipaddr_del(struct ap_session *ses, int ifindex, in_addr_t addr, int mask)
{
	/* remove route instead */
	return vpp_iproute_add_del(ses, 0, addr, mask);
}

int vpphook_ipaddr_del_peer(struct ap_session *ses, int ifindex, in_addr_t addr, in_addr_t peer)
{
	/* remove route instead */
	return vpp_iproute_add_del(ses, 0, peer, 32);
}

int vpphook_iproute_add(struct ap_session *ses, int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name)
{
	return vpp_iproute_add_del(ses, 1, dst, mask);
}

int vpphook_iproute_del(struct ap_session *ses, int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name)
{
	return vpp_iproute_add_del(ses, 0, dst, mask);
}

int vpphook_ip6route_add(struct ap_session *ses, int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name)
{
	return vpp_ip6route_add_del(ses, 1, dst, pref_len);
}

int vpphook_ip6route_del(struct ap_session *ses, int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name)
{
	return vpp_ip6route_add_del(ses, 0, dst, pref_len);
}

int vpphook_ip6addr_add(struct ap_session *ses, int ifindex, struct in6_addr *addr, int prefix_len)
{
	/* setup route instead */
	return vpp_ip6route_add_del(ses, 1, addr, prefix_len);
}

int vpphook_ip6addr_add_peer(struct ap_session *ses, int ifindex, struct in6_addr *addr, struct in6_addr *peer_addr)
{
	/* setup route instead */
	return vpp_ip6route_add_del(ses, 1, peer_addr, 128);
}

int vpphook_ip6addr_del(struct ap_session *ses, int ifindex, struct in6_addr *addr, int prefix_len)
{
	/* remove route instead */
	return vpp_ip6route_add_del(ses, 0, addr, prefix_len);
}

struct ap_session_hooks_t vpp_hooks = {
	.hooks_name = "vpp",

	.get = vpp_get,
	.put = vpp_put,

	.session_hook_init = vpphook_session_hook_init,
	.session_hook_deinit = vpphook_session_hook_deinit,

	.pppoe_create_session_interface = vpphook_pppoe_create_vpp_session_interface,
	.pppoe_terminate = vpphook_pppoe_terminate,
	.read_stats = vpphook_read_stats,

	.ipaddr_add = vpphook_ipaddr_add,
	.ipaddr_add_peer = vpphook_ipaddr_add_peer,
	.ipaddr_del = vpphook_ipaddr_del,
	.ipaddr_del_peer = vpphook_ipaddr_del_peer,
	.iproute_add = vpphook_iproute_add,
	.iproute_del = vpphook_iproute_del,
	.ip6route_add = vpphook_ip6route_add,
	.ip6route_del = vpphook_ip6route_del,
	.ip6addr_add = vpphook_ip6addr_add,
	.ip6addr_add_peer = vpphook_ip6addr_add_peer,
	.ip6addr_del = vpphook_ip6addr_del,

	.install_limiter = vpppolicer_install_limiter,
	.remove_limiter = vpppolicer_remove_limiter,

	.is_non_dev_ppp = 1,
	.is_non_socket_dhcpv6_nd = 1
};

/* ---- Module -------------------------------------------------------------- */

/*
 * The context needs a close: on shutdown triton asks every context to close
 * and only lets the threads exit once all of them are unregistered.
 */
static void vpp_ctx_close(struct triton_context_t *ctx)
{
	__atomic_store_n(&vpp_ctx_closed, 1, __ATOMIC_SEQ_CST);

	if (vpp_tick_timer.tpd)
		triton_timer_del(&vpp_tick_timer);
	if (vpp_route_watchdog_timer.tpd)
		triton_timer_del(&vpp_route_watchdog_timer);
	vpphook_unwatch();

	triton_context_unregister(ctx);
}

static void vpphooks_load_config(void)
{
	char *opt = conf_get_opt("vpp", "session-mtu");

	conf_session_mtu = opt ? atoi(opt) != 0 : 1;
}

static void vpphooks_init()
{
	ap_session_hooks_register(&vpp_hooks);

	vpphooks_load_config();
	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)vpphooks_load_config);

	vpp_ctx.close = vpp_ctx_close;
	triton_context_register(&vpp_ctx, NULL);

	vpp_tick_timer.expire = vpphook_tick;
	vpp_tick_timer.period = VPP_TICK_MS;
	triton_timer_add(&vpp_ctx, &vpp_tick_timer, 0);

	vpp_route_watchdog_boot = time(NULL);
	vpp_route_watchdog_timer.expire = vpphook_route_watchdog;
	vpp_route_watchdog_timer.period = VPP_ROUTE_WATCHDOG_PERIOD_MS;
	triton_timer_add(&vpp_ctx, &vpp_route_watchdog_timer, 0);

	triton_context_wakeup(&vpp_ctx);
}

DEFINE_INIT(20, vpphooks_init);
