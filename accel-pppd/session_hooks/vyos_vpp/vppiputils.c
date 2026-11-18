/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
*/

#include <vapi/ip.api.vapi.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "ap_session.h"
#include "triton.h"
#include "vpputils.h"
#include "vpphooks.h"

#include "vppiputils.h"
#include "vppkroute.h"

DEFINE_VAPI_MSG_IDS_IP_API_JSON

struct vpp_route_t {
	struct list_head entry;

	int af;

	union {
		struct {
			in_addr_t dst;
			int mask;
		} ip4;

		struct {
			struct in6_addr dst;
			int preffix;
		} ip6;
	} un;

	/* Dummy ifindex holding the kernel copy ([vpp-route-export]), 0 = none. */
	int kifindex;
};

static const void *vpp_route_dst(const struct vpp_route_t *r)
{
	return r->af == AF_INET ? (const void *)&r->un.ip4.dst : (const void *)&r->un.ip6.dst;
}

static int vpp_route_len(const struct vpp_route_t *r)
{
	return r->af == AF_INET ? r->un.ip4.mask : r->un.ip6.preffix;
}

static int vpp_route_match(const struct vpp_route_t *r, int af, const void *dst, int len)
{
	if (r->af != af || vpp_route_len(r) != len)
		return 0;

	return !memcmp(vpp_route_dst(r), dst, af == AF_INET ? 4 : 16);
}

/* Bring the kernel copy of the route in line with [vpp-route-export]. */
static void vpp_route_kernel_sync(struct vpp_route_t *r)
{
	int want = vpp_kroute_lookup(r->af, vpp_route_dst(r), vpp_route_len(r));

	if (r->kifindex == want)
		return;

	/* Not covered any more, or the dummy was recreated with a new ifindex. */
	if (r->kifindex) {
		vpp_kroute_del(r->kifindex, r->af, vpp_route_dst(r), vpp_route_len(r));
		r->kifindex = 0;
	}

	if (want && vpp_kroute_add(want, r->af, vpp_route_dst(r), vpp_route_len(r)) == 0)
		r->kifindex = want;
}

static void vpp_route_kernel_del(struct vpp_route_t *r)
{
	if (!r->kifindex)
		return;

	vpp_kroute_del(r->kifindex, r->af, vpp_route_dst(r), vpp_route_len(r));
	r->kifindex = 0;
}

/*
 * Remember a route added to VPP for this session. The same route added again
 * (watchdog reinstall, address and peer hooks) keeps a single entry.
 *
 * The watchdog reinstall comes from the watchdog timer context, not from the
 * session: the list and its entries are only touched with vpp_routes_lock
 * held, here and in every function below.
 */
static void vpp_route_save(struct ap_session *ses, int af, const void *dst, int len)
{
	struct vpphook_private_data_t *vpphook_data = vpphook_get_pd(ses);
	struct vpp_route_t *saved_route;

	if (!vpphook_data)
		return;

	pthread_mutex_lock(&vpphook_data->vpp_routes_lock);

	list_for_each_entry(saved_route, &vpphook_data->vpp_routes, entry) {
		if (vpp_route_match(saved_route, af, dst, len)) {
			vpp_route_kernel_sync(saved_route);
			goto out;
		}
	}

	saved_route = (struct vpp_route_t *)malloc(sizeof(*saved_route));
	if (!saved_route)
		goto out;

	memset(saved_route, 0, sizeof(*saved_route));
	saved_route->af = af;
	if (af == AF_INET) {
		memcpy(&saved_route->un.ip4.dst, dst, 4);
		saved_route->un.ip4.mask = len;
	} else {
		memcpy(&saved_route->un.ip6.dst, dst, 16);
		saved_route->un.ip6.preffix = len;
	}
	list_add_tail(&saved_route->entry, &vpphook_data->vpp_routes);

	vpp_route_kernel_sync(saved_route);

out:
	pthread_mutex_unlock(&vpphook_data->vpp_routes_lock);
}

static void vpp_route_del_saved(struct ap_session *ses, int af, const void *dst, int len)
{
	struct list_head *pos, *n;
	struct vpphook_private_data_t *vpphook_data = vpphook_get_pd(ses);

	if (!vpphook_data)
		return;

	pthread_mutex_lock(&vpphook_data->vpp_routes_lock);

	list_for_each_safe(pos, n, &vpphook_data->vpp_routes) {
		struct vpp_route_t *saved_route = list_entry(pos, typeof(*saved_route), entry);

		if (vpp_route_match(saved_route, af, dst, len)) {
			vpp_route_kernel_del(saved_route);
			list_del(&saved_route->entry);
			free(saved_route);
		}
	}

	pthread_mutex_unlock(&vpphook_data->vpp_routes_lock);
}

static void vpp_iproute_save(struct ap_session *ses, in_addr_t dst, int mask)
{
	vpp_route_save(ses, AF_INET, &dst, mask);
}

static void vpp_iproute_del_saved(struct ap_session *ses, in_addr_t dst, int mask)
{
	vpp_route_del_saved(ses, AF_INET, &dst, mask);
}

static void vpp_ip6route_save(struct ap_session *ses, const struct in6_addr *dst, int pref_len)
{
	vpp_route_save(ses, AF_INET6, dst, pref_len);
}

static void vpp_ip6route_del_saved(struct ap_session *ses, const struct in6_addr *dst, int pref_len)
{
	vpp_route_del_saved(ses, AF_INET6, dst, pref_len);
}

void vpp_iproute_kernel_sync(struct ap_session *ses)
{
	struct vpphook_private_data_t *vpphook_data = vpphook_get_pd(ses);
	struct vpp_route_t *saved_route;

	if (!vpphook_data)
		return;

	pthread_mutex_lock(&vpphook_data->vpp_routes_lock);
	list_for_each_entry(saved_route, &vpphook_data->vpp_routes, entry)
		vpp_route_kernel_sync(saved_route);
	pthread_mutex_unlock(&vpphook_data->vpp_routes_lock);
}

typedef struct vpp_ip_route_lookup_ctx_t {
	int32_t api_retval;
	int found;
} vpp_ip_route_lookup_ctx_t;

static vapi_error_e vpp_ip_route_lookup_cb(struct vapi_ctx_s *ctx,
					 void *callback_ctx,
					 vapi_error_e rv,
					 bool is_last,
					 vapi_payload_ip_route_lookup_reply *reply)
{
	vpp_ip_route_lookup_ctx_t *lookup_ctx = callback_ctx;

	if (rv != VAPI_OK || !reply || !lookup_ctx)
		return rv;

	lookup_ctx->api_retval = reply->retval;
	if (lookup_ctx->api_retval != 0 || reply->route.n_paths == 0)
		return rv;

	/* Route present: exact /32 lookup succeeded with at least one path.
	 * Do not index reply->route.paths[] — VAPI flex-array layout is unreliable. */
	lookup_ctx->found = 1;

	return rv;
}

int vpp_ip4_host_route_present(uint32_t gen, in_addr_t dst)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;
	vpp_ip_route_lookup_ctx_t lookup_ctx = {
		.api_retval = -1,
		.found = 0,
	};

	vpp_lock();

	ctx = vpp_get_vapi_gen(gen);
	if (ctx == NULL)
		goto exit;

	vapi_msg_ip_route_lookup *req = vapi_alloc_ip_route_lookup(ctx);
	if (req == NULL)
		goto exit;

	req->payload.table_id = 0;
	req->payload.exact = 1;
	req->payload.prefix.address.af = ADDRESS_IP4;
	memcpy(req->payload.prefix.address.un.ip4, &dst, sizeof(dst));
	req->payload.prefix.len = 32;

	err = vapi_ip_route_lookup(ctx, req, vpp_ip_route_lookup_cb, &lookup_ctx);
	err = vpp_vapi_complete(err);

exit:
	vpp_unlock();

	if (err != VAPI_OK)
		return -1;

	/* Missing exact route: VPP often returns api_retval != 0 (e.g. NO_SUCH_ENTRY)
	 * with found still 0 — must be 0 (absent), not -1, or the route watchdog skips. */
	return lookup_ctx.found ? 1 : 0;
}

int vpp_ip6_prefix_route_present(uint32_t gen, const struct in6_addr *dst,
				 int prefix_len)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;
	vpp_ip_route_lookup_ctx_t lookup_ctx = {
		.api_retval = -1,
		.found = 0,
	};

	if (!dst || prefix_len <= 0 || prefix_len > 128)
		return -1;

	vpp_lock();

	ctx = vpp_get_vapi_gen(gen);
	if (ctx == NULL)
		goto exit;

	vapi_msg_ip_route_lookup *req = vapi_alloc_ip_route_lookup(ctx);
	if (req == NULL)
		goto exit;

	req->payload.table_id = 0;
	req->payload.exact = 1;
	req->payload.prefix.address.af = ADDRESS_IP6;
	memcpy(req->payload.prefix.address.un.ip6, dst, sizeof(*dst));
	req->payload.prefix.len = prefix_len;

	err = vapi_ip_route_lookup(ctx, req, vpp_ip_route_lookup_cb, &lookup_ctx);
	err = vpp_vapi_complete(err);

exit:
	vpp_unlock();

	if (err != VAPI_OK)
		return -1;

	return lookup_ctx.found ? 1 : 0;
}

static vapi_error_e vpp_ip_ro_cb(struct vapi_ctx_s *ctx,
				 void *callback_ctx,
				 vapi_error_e rv,
				 bool is_last,
				 vapi_payload_ip_route_add_del_reply *reply)
{
	struct vpp_vapi_reply_ctx *reply_ctx = callback_ctx;

	if (rv == VAPI_OK && reply_ctx && reply)
		reply_ctx->api_retval = reply->retval;

	return rv;
}

static int vpp_iproute(uint32_t gen, int is_add, uint32_t ifindex, in_addr_t dst, int mask)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;
	struct vpp_vapi_reply_ctx reply_ctx = { 0, NULL };
	int attempt;

	vpp_lock();

	for (attempt = 0; attempt < 3; attempt++) {
		/*
		 * A failed attempt may have dropped the connection, and the
		 * VPP behind the next one may be another process.
		 */
		ctx = vpp_get_vapi_gen(gen);
		if (ctx == NULL) {
			err = -1;
			goto exit;
		}

		vapi_msg_ip_route_add_del *req = vapi_alloc_ip_route_add_del(ctx, 1);
		if (req == NULL) {
			err = -1;
			goto exit;
		}

		reply_ctx.api_retval = 0;
		req->payload.is_add = is_add;
		/*
		 * Add replaces the paths of the prefix: the session that comes
		 * last gets the traffic. Delete removes only the path through
		 * this session (is_multipath). A delete by prefix removed the
		 * whole entry, so an old session that ended took the route of a
		 * newer one holding the same prefix (the same Framed-Route, a
		 * fixed address reconnecting). With the path already replaced
		 * by the newer session, the delete finds nothing and VPP
		 * answers 0.
		 */
		req->payload.is_multipath = !is_add;
		req->payload.route.prefix.address.af = ADDRESS_IP4;
		memcpy(req->payload.route.prefix.address.un.ip4, &dst, sizeof(dst));
		req->payload.route.prefix.len = mask;
		req->payload.route.paths[0].sw_if_index = ifindex;

		err = vapi_ip_route_add_del(ctx, req, vpp_ip_ro_cb, &reply_ctx);
		err = vpp_vapi_complete(err);
		err = vpp_vapi_errno(err, &reply_ctx);
		if (err == 0 || !is_add)
			break;

		usleep(2000 * (attempt + 1));
	}

exit:
	vpp_unlock();
	return err;
}

int vpp_iproute_add_del(struct ap_session *ses, int is_add, in_addr_t dst, int mask)
{
	uint32_t ifindex, gen;
	int ret;

	if (!vpphook_live(ses, &ifindex, &gen)) {
		if (is_add)
			return -1;
		vpp_iproute_del_saved(ses, dst, mask);
		return 0;
	}

	ret = vpp_iproute(gen, is_add, ifindex, dst, mask);

	if (is_add) {
		if (ret == 0)
			vpp_iproute_save(ses, dst, mask);
	} else if (ret == 0) {
		vpp_iproute_del_saved(ses, dst, mask);
	}

	return ret;
}

static vapi_error_e vpp_ip6_ro_cb(struct vapi_ctx_s *ctx,
				  void *callback_ctx,
				  vapi_error_e rv,
				  bool is_last,
				  vapi_payload_ip_route_add_del_reply *reply)
{
	struct vpp_vapi_reply_ctx *reply_ctx = callback_ctx;

	if (rv == VAPI_OK && reply_ctx && reply)
		reply_ctx->api_retval = reply->retval;

	return rv;
}

static int vpp_ip6route(uint32_t gen, int is_add, uint32_t ifindex, const struct in6_addr *dst,
			int pref_len)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;
	struct vpp_vapi_reply_ctx reply_ctx = { 0, NULL };
	int attempt;

	vpp_lock();

	for (attempt = 0; attempt < 3; attempt++) {
		/* see vpp_iproute() */
		ctx = vpp_get_vapi_gen(gen);
		if (ctx == NULL) {
			err = -1;
			goto exit;
		}

		vapi_msg_ip_route_add_del *req = vapi_alloc_ip_route_add_del(ctx, 1);
		if (req == NULL) {
			err = -1;
			goto exit;
		}

		reply_ctx.api_retval = 0;
		req->payload.is_add = is_add;
		/* delete only the path through this session, see vpp_iproute() */
		req->payload.is_multipath = !is_add;
		req->payload.route.prefix.address.af = ADDRESS_IP6;
		memcpy(req->payload.route.prefix.address.un.ip6, dst, sizeof(*dst));
		req->payload.route.prefix.len = pref_len;
		req->payload.route.paths[0].sw_if_index = ifindex;

		err = vapi_ip_route_add_del(ctx, req, vpp_ip6_ro_cb, &reply_ctx);
		err = vpp_vapi_complete(err);
		err = vpp_vapi_errno(err, &reply_ctx);
		if (err == 0 || !is_add)
			break;

		usleep(2000 * (attempt + 1));
	}

exit:
	vpp_unlock();
	return err;
}

int vpp_ip6route_add_del(struct ap_session *ses, int is_add, const struct in6_addr *dst, int pref_len)
{
	uint32_t ifindex, gen;
	int ret;

	if (!vpphook_live(ses, &ifindex, &gen)) {
		if (is_add)
			return -1;
		vpp_ip6route_del_saved(ses, dst, pref_len);
		return 0;
	}

	ret = vpp_ip6route(gen, is_add, ifindex, dst, pref_len);

	if (is_add && ret != 0 &&
	    vpp_ip6_prefix_route_present(gen, dst, pref_len) == 1)
		ret = 0;

	if (is_add) {
		if (ret == 0)
			vpp_ip6route_save(ses, dst, pref_len);
	} else if (ret == 0) {
		vpp_ip6route_del_saved(ses, dst, pref_len);
	}

	return ret;
}

void vpp_iproute_forget(struct ap_session *ses)
{
	struct list_head *pos, *n;
	struct vpphook_private_data_t *vpphook_data = vpphook_get_pd(ses);

	if (!vpphook_data)
		return;

	pthread_mutex_lock(&vpphook_data->vpp_routes_lock);

	list_for_each_safe(pos, n, &vpphook_data->vpp_routes) {
		struct vpp_route_t *saved_route = list_entry(pos, typeof(*saved_route), entry);

		vpp_route_kernel_del(saved_route);
		list_del(&saved_route->entry);
		free(saved_route);
	}

	pthread_mutex_unlock(&vpphook_data->vpp_routes_lock);
}

int vpp_route_del(uint32_t gen, uint32_t ifindex, const struct vpp_route_key *key)
{
	if (key->af == AF_INET) {
		in_addr_t dst;

		memcpy(&dst, key->dst, sizeof(dst));
		return vpp_iproute(gen, 0, ifindex, dst, key->len);
	}

	return vpp_ip6route(gen, 0, ifindex, (const struct in6_addr *)key->dst, key->len);
}

int vpp_iproute_flush(struct ap_session *ses, int live, uint32_t gen, uint32_t ifindex,
		      struct vpp_route_key **left)
{
	struct list_head *pos, *n;
	struct vpphook_private_data_t *vpphook_data = vpphook_get_pd(ses);
	struct vpp_route_key *keys = NULL, *nk;
	int n_left = 0, ret;
	LIST_HEAD(routes);

	if (left)
		*left = NULL;

	if (!vpphook_data)
		return 0;

	/*
	 * Take the routes off the session first: the deletes in VPP below wait
	 * on vpp_lock, and the list lock is not held across them. An entry the
	 * watchdog saves after this point, and its kernel copy, are dropped by
	 * vpp_iproute_forget() when the session is freed.
	 */
	pthread_mutex_lock(&vpphook_data->vpp_routes_lock);
	list_splice_init(&vpphook_data->vpp_routes, &routes);
	pthread_mutex_unlock(&vpphook_data->vpp_routes_lock);

	list_for_each_safe(pos, n, &routes) {
		struct vpp_route_t *saved_route = list_entry(pos, typeof(*saved_route), entry);

		vpp_route_kernel_del(saved_route);

		ret = 0;
		if (!live)
			;
		else if (saved_route->af == AF_INET)
			ret = vpp_iproute(gen, 0, ifindex, saved_route->un.ip4.dst, saved_route->un.ip4.mask);
		else if (saved_route->af == AF_INET6)
			ret = vpp_ip6route(gen, 0, ifindex, &saved_route->un.ip6.dst, saved_route->un.ip6.preffix);

		/*
		 * No answer, and the VPP may still be the same: the route may
		 * still be there. An answer of the API, even an error, or a
		 * VPP that restarted, leaves nothing to try again.
		 */
		if (left && (ret > 0 || ret == -1) && vpp_generation() == gen) {
			nk = realloc(keys, (n_left + 1) * sizeof(*keys));
			if (nk) {
				keys = nk;
				memset(&keys[n_left], 0, sizeof(keys[n_left]));
				keys[n_left].af = saved_route->af;
				keys[n_left].len = vpp_route_len(saved_route);
				memcpy(keys[n_left].dst, vpp_route_dst(saved_route),
				       saved_route->af == AF_INET ? 4 : 16);
				n_left++;
			}
		}

		list_del(&saved_route->entry);
		free(saved_route);
	}

	if (left)
		*left = keys;

	return n_left;
}
