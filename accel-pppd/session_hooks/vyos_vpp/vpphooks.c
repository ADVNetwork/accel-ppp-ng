/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#include <linux/if_ether.h> /* ETH_P_ALL */
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <time.h>

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

static time_t vpp_route_watchdog_boot;

/* NOTE: function from ctrl/pppoe plugin! */
void pppoe_get_session_mac_and_sid(struct ap_session *ses, uint8_t **mac, uint16_t *sid);

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

int vpphook_get_sw_if_index(struct ap_session *ses, uint32_t *sw_if_index)
{
	struct vpphook_private_data_t *pd;

	if (!ses || !sw_if_index)
		return -1;

	pd = vpphook_get_pd(ses);
	if (!pd)
		return -1;

	*sw_if_index = pd->vpp_sw_if_index;
	return 0;
}

int vpphook_session_hook_init(struct ap_session *ses)
{
	struct vpphook_private_data_t *pd = _malloc(sizeof(struct vpphook_private_data_t));
	if (pd == NULL)
		return -1;

	memset(pd, 0, sizeof(struct vpphook_private_data_t));
	pd->pd.key = &pd_key;

	INIT_LIST_HEAD(&pd->vpp_routes);

	list_add_tail(&pd->pd.entry, &ses->pd_list);

	return 0; /* return 0 is ok */
}

void vpphook_session_hook_deinit(struct ap_session *ses)
{
	struct vpphook_private_data_t *pd = vpphook_get_pd(ses);
	if (pd == NULL)
		return;

	list_del(&pd->pd.entry);
	_free(pd);
}

static struct triton_timer_t vpp_route_watchdog_timer;

/* Reinstall dataplane routes before terminating the PPPoE session. */
static int vpphook_watchdog_reinstall_v4(struct ap_session *ses, uint32_t sw_if_index)
{
	int ret;

	ret = vpp_iproute_add_del(ses, 1, sw_if_index, 0, ses->ipv4->peer_addr, 0, 0, 32, 0);
	if (ret)
		return ret;

	return vpp_ip4_host_route_present(sw_if_index, ses->ipv4->peer_addr) == 1 ? 0 : -1;
}

static int vpphook_watchdog_reinstall_pd(struct ap_session *ses, uint32_t sw_if_index,
					 const struct ipv6db_addr_t *pfx)
{
	int ret;

	ret = vpp_ip6route_add_del(ses, 1, sw_if_index, &pfx->addr, pfx->prefix_len, NULL, 0, 0);
	if (ret)
		return ret;

	return vpp_ip6_prefix_route_present(sw_if_index, &pfx->addr, pfx->prefix_len) == 1 ?
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
		uint32_t ifindex;
		struct vpphook_private_data_t *pd;

		if (ses->ctrl->type != CTRL_TYPE_PPPOE)
			continue;
		if (ses->state != AP_STATE_ACTIVE || ses->terminated)
			continue;
		if (!ses->ipv4 || !ses->ipv4->peer_addr)
			continue;
		if (now - ses->start_time < VPP_ROUTE_WATCHDOG_MIN_SESSION_AGE_SEC)
			continue;

		pd = vpphook_get_pd(ses);
		if (!pd || !pd->vpp_sw_if_index)
			continue;

		ifindex = pd->vpp_sw_if_index;
		route_st = vpp_ip4_host_route_present(ifindex, ses->ipv4->peer_addr);
		if (route_st != 0)
			continue;

		inet_ntop(AF_INET, &ses->ipv4->peer_addr, ipbuf, sizeof(ipbuf));
		if (vpphook_watchdog_reinstall_v4(ses, ifindex) == 0) {
			log_info2("vpp: reinstalled missing /32 route for %s on %s (sw_if_index %u)\n",
				 ipbuf, ses->ifname, ifindex);
			continue;
		}

		log_info2("vpp: terminating pppoe session %s: missing /32 route for %s on sw_if_index %u (reinstall failed)\n",
			  ses->ifname, ipbuf, ifindex);
		ap_session_terminate(ses, TERM_NAS_ERROR, 0);
		continue;
	}

	list_for_each_entry(ses, &ses_list, entry) {
		uint32_t ifindex;
		struct vpphook_private_data_t *pd;

		if (ses->ctrl->type != CTRL_TYPE_PPPOE)
			continue;
		if (ses->state != AP_STATE_ACTIVE || ses->terminated)
			continue;
		if (!ses->ipv6_dp || list_empty(&ses->ipv6_dp->prefix_list))
			continue;
		if (now - ses->start_time < VPP_ROUTE_WATCHDOG_MIN_SESSION_AGE_SEC)
			continue;

		pd = vpphook_get_pd(ses);
		if (!pd || !pd->vpp_sw_if_index)
			continue;

		ifindex = pd->vpp_sw_if_index;
		list_for_each_entry(v6p, &ses->ipv6_dp->prefix_list, entry) {
			route_st = vpp_ip6_prefix_route_present(ifindex, &v6p->addr,
								v6p->prefix_len);
			if (route_st < 0)
				continue;
			if (route_st != 0)
				continue;

			inet_ntop(AF_INET6, &v6p->addr, ip6buf, sizeof(ip6buf));
			if (vpphook_watchdog_reinstall_pd(ses, ifindex, v6p) == 0) {
				log_info2("vpp: reinstalled missing PD route %s/%i on %s (sw_if_index %u)\n",
					 ip6buf, v6p->prefix_len, ses->ifname, ifindex);
				continue;
			}

			log_info2("vpp: terminating pppoe session %s: missing PD route %s/%i on sw_if_index %u (reinstall failed)\n",
				  ses->ifname, ip6buf, v6p->prefix_len, ifindex);
			ap_session_terminate(ses, TERM_NAS_ERROR, 0);
			break;
		}
	}
	pthread_rwlock_unlock(&ses_lock);
}

int vpphook_pppoe_create_vpp_session_interface(struct ap_session *ses)
{
	uint32_t ifindex = -1;
	int ret = 0;
	uint8_t *mac = NULL;
	uint16_t sid;
	in_addr_t peer_addr = 0;
	char ipbuf[INET_ADDRSTRLEN];

	pppoe_get_session_mac_and_sid(ses, &mac, &sid);

	if (ses->ipv4)
		peer_addr = ses->ipv4->peer_addr;

	ret = vpppoe_sync_add_pppoe_interface(mac, sid, peer_addr, &ifindex);
	if (ret) {
		if (peer_addr) {
			inet_ntop(AF_INET, &peer_addr, ipbuf, sizeof(ipbuf));
			log_error("vpp: pppoe session add failed sid=%u peer=%s ret=%d\n",
				  sid, ipbuf, ret);
		}
		return ret;
	}

	vpphook_get_pd(ses)->vpp_sw_if_index = ifindex;
	vpppoe_dump_interface_name(ifindex, ses->ifname, AP_IFNAME_LEN);

	if (ses->ipv4) {
		vpppoe_set_feature(ifindex, 0, "ip4-not-enabled", "ip4-unicast");

		if (!peer_addr) {
			log_error("vpp: pppoe create sid=%u with zero peer_addr, aborting\n", sid);
			vpppoe_sync_del_pppoe_interface(mac, sid, peer_addr);
			return -1;
		}

		ret = vpp_iproute_add_del(ses, 1, ifindex, 0, peer_addr, 0, 0, 32, 0);
		if (ret) {
			inet_ntop(AF_INET, &peer_addr, ipbuf, sizeof(ipbuf));
			log_error("vpp: pppoe route add failed sid=%u peer=%s ret=%d\n",
				  sid, ipbuf, ret);
			vpppoe_sync_del_pppoe_interface(mac, sid, peer_addr);
			return ret;
		}
	}

	if (ses->ipv6)
		vpppoe_set_feature(ifindex, 0, "ip6-not-enabled", "ip6-unicast");

	return 0;
}

int vpphook_pppoe_terminate(struct ap_session *ses, int hard)
{
	uint8_t *mac = NULL;
	uint16_t sid;
	in_addr_t peer_addr = 0;
	int ret = 0;
	char ipbuf[INET_ADDRSTRLEN];

	pppoe_get_session_mac_and_sid(ses, &mac, &sid);
	if (ses->ipv4)
		peer_addr = ses->ipv4->peer_addr;

	ret = vpp_iproute_flush(ses);
	if (ret)
		goto exit;
	ret = vpppolicer_remove_limiter(ses);
	if (ret) {
		if (peer_addr)
			inet_ntop(AF_INET, &peer_addr, ipbuf, sizeof(ipbuf));
		log_error("vpp: pppoe terminate policer_remove failed sid=%u peer=%s ret=%d\n",
			  sid, peer_addr ? ipbuf : "0.0.0.0", ret);
		goto exit;
	}
	ret = vpppoe_sync_del_pppoe_interface(mac, sid, peer_addr);
	if (ret) {
		if (peer_addr)
			inet_ntop(AF_INET, &peer_addr, ipbuf, sizeof(ipbuf));
		log_error("vpp: pppoe session del failed sid=%u peer=%s ret=%d\n",
			  sid, peer_addr ? ipbuf : "0.0.0.0", ret);
	}

exit:
	return ret;
}

int vpphook_ipaddr_add(struct ap_session *ses, int ifindex, in_addr_t addr, int mask)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	/* setup route instead */
	return vpp_iproute_add_del(ses, 1, sw_ifindex, 0, addr, 0, 0, mask, 0);
}

int vpphook_ipaddr_add_peer(struct ap_session *ses, int ifindex, in_addr_t addr, in_addr_t peer_addr)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	/* setup route instead */
	return vpp_iproute_add_del(ses, 1, sw_ifindex, 0, peer_addr, 0, 0, 32, 0);
}

int vpphook_ipaddr_del(struct ap_session *ses, int ifindex, in_addr_t addr, int mask)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	/* remove route instead */
	return vpp_iproute_add_del(ses, 0, sw_ifindex, 0, addr, 0, 0, mask, 0);
}

int vpphook_ipaddr_del_peer(struct ap_session *ses, int ifindex, in_addr_t addr, in_addr_t peer)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	/* remove route instead */
	return vpp_iproute_add_del(ses, 0, sw_ifindex, 0, peer, 0, 0, 32, 0);
}

int vpphook_iproute_add(struct ap_session *ses, int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	return vpp_iproute_add_del(ses, 1, sw_ifindex, src, dst, gw, proto, mask, prio);
}

int vpphook_iproute_del(struct ap_session *ses, int ifindex, in_addr_t src, in_addr_t dst, in_addr_t gw, int proto, int mask, uint32_t prio, const char *vrf_name)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	return vpp_iproute_add_del(ses, 0, sw_ifindex, src, dst, gw, proto, mask, prio);
}

int vpphook_ip6route_add(struct ap_session *ses, int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	return vpp_ip6route_add_del(ses, 1, sw_ifindex, dst, pref_len, gw, proto, prio);
}

int vpphook_ip6route_del(struct ap_session *ses, int ifindex, const struct in6_addr *dst, int pref_len, const struct in6_addr *gw, int proto, uint32_t prio, const char *vrf_name)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	return vpp_ip6route_add_del(ses, 0, sw_ifindex, dst, pref_len, gw, proto, prio);
}

int vpphook_ip6addr_add(struct ap_session *ses, int ifindex, struct in6_addr *addr, int prefix_len)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	/* setup route instead */
	return vpp_ip6route_add_del(ses, 1, sw_ifindex, addr, prefix_len, NULL, 0, 0);
}

int vpphook_ip6addr_add_peer(struct ap_session *ses, int ifindex, struct in6_addr *addr, struct in6_addr *peer_addr)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	/* setup route instead */
	return vpp_ip6route_add_del(ses, 1, sw_ifindex, peer_addr, 128, NULL, 0, 0);
}

int vpphook_ip6addr_del(struct ap_session *ses, int ifindex, struct in6_addr *addr, int prefix_len)
{
	uint32_t sw_ifindex = vpphook_get_pd(ses)->vpp_sw_if_index;
	/* remove route instead */
	return vpp_ip6route_add_del(ses, 0, sw_ifindex, addr, prefix_len, NULL, 0, 0);
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
	.stats_batch_set_filter = vpphook_stats_batch_set_filter,
	.stats_batch_begin = vpphook_stats_batch_begin,
	.stats_batch_end = vpphook_stats_batch_end,
	.get_sw_if_index = vpphook_get_sw_if_index,

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


static void vpphooks_init()
{
	ap_session_hooks_register(&vpp_hooks);

	vpp_route_watchdog_boot = time(NULL);
	vpp_route_watchdog_timer.expire = vpphook_route_watchdog;
	vpp_route_watchdog_timer.period = VPP_ROUTE_WATCHDOG_PERIOD_MS;
	triton_timer_add(triton_context_self(), &vpp_route_watchdog_timer, 0);
}

DEFINE_INIT(20, vpphooks_init);