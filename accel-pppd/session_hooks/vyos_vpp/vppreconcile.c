/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Startup reconciliation of the VPP dataplane.
 *
 * The accel-ppp process that owns a VPP is the only one that creates PPPoE
 * sessions, routes through pppoeN and "vyos_*" policers in it. When the
 * process dies without its teardown (SIGKILL, SIGSEGV + __core_restart), all
 * of that stays in VPP, and the new process knows nothing about it:
 *
 *  - orphan PPPoE sessions keep their session_id in the fast-path hash, which
 *    is indexed by session_id only; a new session with the same id would
 *    take its traffic (adv-vpp AGENTS.md, "session_id unico");
 *  - API routes through the orphan pppoeN stay in FIB 0. VPP reuses the
 *    sw_if_index of a deleted session for the next one, so the route ends up
 *    on another subscriber's session;
 *  - shaper policers stay applied to the interface that will be reused.
 *
 * Adopting the orphans is not possible: the PPP state (LCP, auth, IPCP,
 * RADIUS accounting, pool leases) died with the process, and the CPE
 * reconnects anyway. So on the first successful connection of the process,
 * before any session of its own exists in VPP, this deletes every PPPoE
 * session, every API route in table 0 whose path goes through a PPPoE
 * interface, visible or hidden, and every policer named by vpppolicer.c.
 *
 * Only PPPoE interfaces: an API route of another client (the manager) whose
 * interface is hidden or gone is not ours and is left alone. sw_interface_dump
 * does not list a hidden pppoeN, so the names of the hidden interfaces come
 * from the stat segment (/if/names, vppstats.c). Without the stat segment only
 * the visible pppoeN are known: a route through a hidden one stays, and VPP
 * keeps that pppoeN out of reuse until the route leaves.
 *
 * The route dump makes VPP walk the whole FIB of table 0 with the workers
 * stopped (ip_route_v2_dump is not mp-safe, and the table holds the BGP
 * routes). No VAPI context is handed out before the reconciliation succeeds
 * and the previous process is gone, so nobody adds a route or a policer
 * between two attempts: a pass that removed everything is not repeated, and a
 * later attempt only looks at the sessions. With no pppoeN at all in VPP the
 * route dump is skipped.
 *
 * pppoe_session_dump answers with a wrong message id in adv-vpp builds
 * before the fix in pppoe_api.c (msg_id_base missing since the original
 * plugin): the client gets garbage or nothing. So the pppoeN interfaces are
 * also taken from sw_interface_dump, and at the end no visible pppoeN may be
 * left. Each deleted session leaves its pppoeN hidden, kept by VPP for reuse.
 *
 * Runs with vpp_lock held, from vpppoe_connect_to_vpp().
 */

#include <vapi/vapi.h>
#include <vapi/vpe.api.vapi.h>
#include <vapi/pppoe.api.vapi.h>
#include <vapi/interface.api.vapi.h>
#include <vapi/ip.api.vapi.h>
#include <vapi/policer.api.vapi.h>
#include <vapi/fib.api.vapi.h>

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"

#include "vpputils.h"
#include "vppstats.h"
#include "vppreconcile.h"

DEFINE_VAPI_MSG_IDS_FIB_API_JSON

/*
 * Id of the FIB source "API" ("show fib source"). Asked to VPP by name
 * (fib_source_dump); this value (vnet/fib/fib_source.h in VPP 25.10) is only
 * used when VPP does not answer.
 */
#define VPP_FIB_SOURCE_API_DEFAULT 8
#define VPP_FIB_SOURCE_API_NAME "API"

/* Seconds between two progress lines while deleting. */
#define REC_PROGRESS_SEC 5

/* State kept between attempts of this process (vpp_lock held). */
static int rec_api_src = -1;	/* FIB source id, -1 = not asked yet */
static int rec_routes_done;	/* a pass removed every orphan route */
static int rec_policers_done;	/* a pass removed every policer of ours */

struct rec_session {
	uint32_t sw_if_index;
	uint16_t session_id;
	uint8_t client_mac[6];
	vapi_type_address client_ip;
	uint32_t decap_vrf_id;
};

struct rec_route {
	int is_ip6;
	vapi_type_prefix prefix;
	uint8_t n_paths;	/* paths of the route */
	uint8_t n_orphan;	/* paths through an orphan interface */
	vapi_type_fib_path orphan[4];
};

struct rec_state {
	int failed;

	struct rec_session *ses;
	size_t n_ses, cap_ses;

	/* visible[i] != 0: sw_if_index i is listed by sw_interface_dump */
	uint8_t *visible;
	size_t n_visible;

	/* pppoe[i] != 0: sw_if_index i is a visible pppoeN */
	uint8_t *pppoe;
	size_t n_pppoe;
	size_t n_pppoe_if;

	/* named[i] != 0: the stat segment names sw_if_index i pppoeN (hidden
	 * ones included); have_names = 0: the stat segment was not read */
	uint8_t *named;
	size_t n_named;
	size_t n_named_if;
	int have_names;

	/* paths of API routes through an interface VPP does not list and that
	 * is not a pppoeN (or cannot be checked): left alone */
	size_t n_paths_left;

	struct rec_route *routes;
	size_t n_routes, cap_routes;

	char (*policers)[64];
	size_t n_policers, cap_policers;
};

static int rec_grow(void **v, size_t *cap, size_t n, size_t elt)
{
	size_t ncap;
	void *nv;

	if (n < *cap)
		return 0;

	ncap = *cap ? *cap * 2 : 64;
	nv = realloc(*v, ncap * elt);
	if (!nv)
		return -1;

	*v = nv;
	*cap = ncap;
	return 0;
}

static int rec_mark(uint8_t **map, size_t *len, uint32_t idx)
{
	size_t nlen;
	uint8_t *nm;

	if (idx == ~0U)
		return 0;

	if (idx >= *len) {
		nlen = (size_t)idx + 1024;
		nm = realloc(*map, nlen);
		if (!nm)
			return -1;
		memset(nm + *len, 0, nlen - *len);
		*map = nm;
		*len = nlen;
	}

	(*map)[idx] = 1;
	return 0;
}

static int rec_test(const uint8_t *map, size_t len, uint32_t idx)
{
	return idx < len && map[idx];
}

static void rec_free(struct rec_state *st)
{
	free(st->ses);
	free(st->visible);
	free(st->pppoe);
	free(st->named);
	free(st->routes);
	free(st->policers);
	memset(st, 0, sizeof(*st));
}

/* A request left the connection down: stop, the caller retries later. */
static struct vapi_ctx_s *rec_ctx(void)
{
	return vpp_peek_vapi();
}

/* ---- PPPoE sessions ---------------------------------------------------- */

static vapi_error_e rec_pppoe_dump_cb(struct vapi_ctx_s *ctx, void *cb_ctx,
				      vapi_error_e rv, bool is_last,
				      vapi_payload_pppoe_session_details *d)
{
	struct rec_state *st = cb_ctx;
	struct rec_session *s;

	if (rv != VAPI_OK || !d || !st)
		return rv;

	/*
	 * Garbage from a VPP with the message id bug should not pass this;
	 * session_id 0 is discovery only. Whatever slips through is caught by
	 * the final check of vpp_reconcile_orphans().
	 */
	if (!rec_test(st->pppoe, st->n_pppoe, d->sw_if_index) || !d->session_id) {
		log_warn("vpp: reconcile: ignoring pppoe session dump entry sw_if_index=%u sid=%u\n",
			 d->sw_if_index, d->session_id);
		return rv;
	}

	if (rec_grow((void **)&st->ses, &st->cap_ses, st->n_ses, sizeof(*st->ses))) {
		st->failed = 1;
		return rv;
	}

	s = &st->ses[st->n_ses++];
	s->sw_if_index = d->sw_if_index;
	s->session_id = d->session_id;
	memcpy(s->client_mac, d->client_mac, sizeof(s->client_mac));
	s->client_ip = d->client_ip;
	s->decap_vrf_id = d->decap_vrf_id;

	return rv;
}

static int rec_dump_pppoe(struct rec_state *st)
{
	struct vapi_ctx_s *ctx = rec_ctx();
	vapi_msg_pppoe_session_dump *req;
	vapi_error_e err;

	if (!ctx)
		return -1;

	req = vapi_alloc_pppoe_session_dump(ctx);
	if (!req)
		return -1;

	req->payload.sw_if_index = ~0;

	err = vapi_pppoe_session_dump(ctx, req, rec_pppoe_dump_cb, st);
	err = vpp_vapi_complete(err);

	return (err != VAPI_OK || st->failed) ? -1 : 0;
}

static vapi_error_e rec_pppoe_del_cb(struct vapi_ctx_s *ctx, void *cb_ctx,
				     vapi_error_e rv, bool is_last,
				     vapi_payload_pppoe_add_del_session_reply *reply)
{
	struct vpp_vapi_reply_ctx *reply_ctx = cb_ctx;

	if (rv == VAPI_OK && reply_ctx && reply)
		reply_ctx->api_retval = reply->retval;

	return rv;
}

static int rec_del_pppoe(const struct rec_session *s)
{
	struct vapi_ctx_s *ctx = rec_ctx();
	struct vpp_vapi_reply_ctx reply_ctx = { 0, NULL };
	vapi_msg_pppoe_add_del_session *req;
	vapi_error_e err;
	int ret;

	if (!ctx)
		return -1;

	req = vapi_alloc_pppoe_add_del_session(ctx);
	if (!req)
		return -1;

	req->payload.is_add = 0;
	req->payload.session_id = s->session_id;
	req->payload.client_ip = s->client_ip;
	req->payload.decap_vrf_id = s->decap_vrf_id;
	memcpy(req->payload.client_mac, s->client_mac, sizeof(s->client_mac));
	req->payload.disable_fib = 1;

	err = vapi_pppoe_add_del_session(ctx, req, rec_pppoe_del_cb, &reply_ctx);
	err = vpp_vapi_complete(err);
	ret = vpp_vapi_errno(err, &reply_ctx);

	if (ret == VPP_API_ERR_NO_SUCH_ENTRY)
		ret = 0;

	return ret;
}

/* ---- Interfaces -------------------------------------------------------- */

/* format_pppoe_name() in the adv-vpp pppoe plugin: "pppoe%d" */
static int rec_is_pppoe_name(const uint8_t *name)
{
	return !strncmp((const char *)name, "pppoe", 5) && name[5] >= '0' && name[5] <= '9';
}

static vapi_error_e rec_if_dump_cb(struct vapi_ctx_s *ctx, void *cb_ctx,
				   vapi_error_e rv, bool is_last,
				   vapi_payload_sw_interface_details *d)
{
	struct rec_state *st = cb_ctx;

	if (rv != VAPI_OK || !d || !st)
		return rv;

	if (rec_mark(&st->visible, &st->n_visible, d->sw_if_index))
		st->failed = 1;

	if (rec_is_pppoe_name(d->interface_name)) {
		if (rec_mark(&st->pppoe, &st->n_pppoe, d->sw_if_index))
			st->failed = 1;
		st->n_pppoe_if++;
	}

	return rv;
}

static int rec_dump_interfaces(struct rec_state *st)
{
	struct vapi_ctx_s *ctx = rec_ctx();
	vapi_msg_sw_interface_dump *req;
	vapi_error_e err;

	if (!ctx)
		return -1;

	req = vapi_alloc_sw_interface_dump(ctx, 0);
	if (!req)
		return -1;

	req->payload.sw_if_index = ~0;
	req->payload.name_filter_valid = 0;

	err = vapi_sw_interface_dump(ctx, req, rec_if_dump_cb, st);
	err = vpp_vapi_complete(err);

	return (err != VAPI_OK || st->failed) ? -1 : 0;
}

/* The pppoeN that the stat segment names: the hidden ones are only here. */
static void rec_name_cb(uint32_t sw_if_index, const char *name, void *arg)
{
	struct rec_state *st = arg;

	if (!rec_is_pppoe_name((const uint8_t *)name))
		return;

	if (rec_mark(&st->named, &st->n_named, sw_if_index))
		st->failed = 1;
	st->n_named_if++;
}

static void rec_collect_names(struct rec_state *st)
{
	st->have_names = vpphook_stats_if_names(rec_name_cb, st) == 0;
	if (!st->have_names)
		log_warn("vpp: reconcile: stat segment not available, hidden pppoe interfaces are not known: "
			 "API routes through them are not checked\n");
}

/* ---- FIB source -------------------------------------------------------- */

static vapi_error_e rec_fib_source_cb(struct vapi_ctx_s *ctx, void *cb_ctx,
				      vapi_error_e rv, bool is_last,
				      vapi_payload_fib_source_details *d)
{
	int *id = cb_ctx;
	char name[sizeof(d->src.name) + 1];

	if (rv != VAPI_OK || !d || !id)
		return rv;

	memcpy(name, d->src.name, sizeof(d->src.name));
	name[sizeof(d->src.name)] = 0;
	if (!strcmp(name, VPP_FIB_SOURCE_API_NAME))
		*id = d->src.id;

	return rv;
}

/* Once per process: the id does not change while VPP runs. */
static int rec_api_source(void)
{
	struct vapi_ctx_s *ctx = rec_ctx();
	vapi_msg_fib_source_dump *req;
	vapi_error_e err;
	int id = -1;

	if (rec_api_src >= 0)
		return 0;
	if (!ctx)
		return -1;

	if (vapi_is_msg_available(ctx, vapi_msg_id_fib_source_dump)) {
		req = vapi_alloc_fib_source_dump(ctx);
		if (!req)
			return -1;

		err = vapi_fib_source_dump(ctx, req, rec_fib_source_cb, &id);
		err = vpp_vapi_complete(err);
		if (err != VAPI_OK)
			return -1;
	}

	if (id < 0) {
		log_warn("vpp: reconcile: VPP did not name the FIB source \"%s\", using id %d\n",
			 VPP_FIB_SOURCE_API_NAME, VPP_FIB_SOURCE_API_DEFAULT);
		id = VPP_FIB_SOURCE_API_DEFAULT;
	}

	rec_api_src = id;
	return 0;
}

/* ---- Progress ---------------------------------------------------------- */

/* The deletes are one call each; with thousands of orphans say it is alive. */
static void rec_progress(time_t *last, const char *what, size_t done, size_t total)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (!*last) {
		*last = now.tv_sec;
		return;
	}
	if (now.tv_sec - *last < REC_PROGRESS_SEC)
		return;

	*last = now.tv_sec;
	log_warn("vpp: reconcile: %zu of %zu %s removed\n", done, total, what);
}

/* ---- Routes ------------------------------------------------------------ */

/*
 * A path is orphan when it goes out through a PPPoE interface: at startup
 * every PPPoE session in VPP is an orphan, and so is a route left on a pppoeN
 * that VPP hid for reuse after the session delete. A hidden interface is not
 * in the interface dump, so it only counts when the stat segment names it
 * pppoeN. Any other interface that VPP does not list (hidden or deleted) is
 * not ours: the route belongs to another API client. Recursive paths
 * (sw_if_index ~0) are left alone.
 *
 * Returns 1 = orphan, 0 = not ours, -1 = not listed and not a pppoeN (or not
 * checked, without the stat segment): left alone and counted.
 */
static int rec_path_orphan(const struct rec_state *st, uint32_t sw_if_index)
{
	if (sw_if_index == ~0U)
		return 0;

	if (rec_test(st->pppoe, st->n_pppoe, sw_if_index))
		return 1;

	if (rec_test(st->visible, st->n_visible, sw_if_index))
		return 0;

	if (st->have_names && rec_test(st->named, st->n_named, sw_if_index))
		return 1;

	return -1;
}

struct rec_route_dump_ctx {
	struct rec_state *st;
	int is_ip6;
};

static vapi_error_e rec_route_dump_cb(struct vapi_ctx_s *ctx, void *cb_ctx,
				      vapi_error_e rv, bool is_last,
				      vapi_payload_ip_route_v2_details *d)
{
	struct rec_route_dump_ctx *dctx = cb_ctx;
	struct rec_state *st;
	struct rec_route r;
	unsigned i;

	if (rv != VAPI_OK || !d || !dctx)
		return rv;

	st = dctx->st;

	/* walk_w_src lists entries sourced by API, paths are of the best source */
	if (d->route.src != rec_api_src)
		return rv;

	memset(&r, 0, sizeof(r));
	r.is_ip6 = dctx->is_ip6;
	r.prefix = d->route.prefix;
	r.n_paths = d->route.n_paths;

	for (i = 0; i < d->route.n_paths; i++) {
		int orphan = rec_path_orphan(st, d->route.paths[i].sw_if_index);

		if (orphan < 0)
			st->n_paths_left++;
		if (orphan <= 0)
			continue;
		if (r.n_orphan < sizeof(r.orphan) / sizeof(r.orphan[0]))
			r.orphan[r.n_orphan] = d->route.paths[i];
		r.n_orphan++;
	}

	if (!r.n_orphan)
		return rv;

	if (rec_grow((void **)&st->routes, &st->cap_routes, st->n_routes,
		     sizeof(*st->routes))) {
		st->failed = 1;
		return rv;
	}

	st->routes[st->n_routes++] = r;

	return rv;
}

static int rec_dump_routes(struct rec_state *st, int is_ip6)
{
	struct vapi_ctx_s *ctx = rec_ctx();
	struct rec_route_dump_ctx dctx = { st, is_ip6 };
	vapi_msg_ip_route_v2_dump *req;
	vapi_error_e err;

	if (!ctx)
		return -1;

	req = vapi_alloc_ip_route_v2_dump(ctx);
	if (!req)
		return -1;

	/* Only API routes: FIB 0 also holds the full BGP table (linux-cp). */
	req->payload.src = rec_api_src;
	req->payload.table.table_id = 0;
	req->payload.table.is_ip6 = is_ip6;

	err = vapi_ip_route_v2_dump(ctx, req, rec_route_dump_cb, &dctx);
	err = vpp_vapi_complete(err);

	return (err != VAPI_OK || st->failed) ? -1 : 0;
}

static vapi_error_e rec_route_del_cb(struct vapi_ctx_s *ctx, void *cb_ctx,
				     vapi_error_e rv, bool is_last,
				     vapi_payload_ip_route_add_del_reply *reply)
{
	struct vpp_vapi_reply_ctx *reply_ctx = cb_ctx;

	if (rv == VAPI_OK && reply_ctx && reply)
		reply_ctx->api_retval = reply->retval;

	return rv;
}

/*
 * Every path orphan: delete the API entry of the prefix, without paths. The
 * path decode of ip_route_add_del refuses a sw_if_index that no longer
 * exists, and that is the case after the interface is deleted. Otherwise
 * remove only the orphan paths, one by one (these still exist, hidden).
 */
static int rec_del_route(const struct rec_route *r)
{
	struct vapi_ctx_s *ctx;
	struct vpp_vapi_reply_ctx reply_ctx;
	vapi_msg_ip_route_add_del *req;
	vapi_error_e err;
	unsigned i, n;
	int ret = 0;

	if (r->n_orphan >= r->n_paths) {
		ctx = rec_ctx();
		if (!ctx)
			return -1;

		req = vapi_alloc_ip_route_add_del(ctx, 0);
		if (!req)
			return -1;

		memset(&reply_ctx, 0, sizeof(reply_ctx));
		req->payload.is_add = 0;
		req->payload.is_multipath = 0;
		req->payload.route.table_id = 0;
		req->payload.route.prefix = r->prefix;
		req->payload.route.n_paths = 0;

		err = vapi_ip_route_add_del(ctx, req, rec_route_del_cb, &reply_ctx);
		err = vpp_vapi_complete(err);
		return vpp_vapi_errno(err, &reply_ctx);
	}

	n = r->n_orphan;
	if (n > sizeof(r->orphan) / sizeof(r->orphan[0]))
		n = sizeof(r->orphan) / sizeof(r->orphan[0]);

	for (i = 0; i < n; i++) {
		ctx = rec_ctx();
		if (!ctx)
			return -1;

		req = vapi_alloc_ip_route_add_del(ctx, 1);
		if (!req)
			return -1;

		memset(&reply_ctx, 0, sizeof(reply_ctx));
		req->payload.is_add = 0;
		req->payload.is_multipath = 1;
		req->payload.route.table_id = 0;
		req->payload.route.prefix = r->prefix;
		req->payload.route.n_paths = 1;
		req->payload.route.paths[0] = r->orphan[i];

		err = vapi_ip_route_add_del(ctx, req, rec_route_del_cb, &reply_ctx);
		err = vpp_vapi_complete(err);
		err = vpp_vapi_errno(err, &reply_ctx);
		if (err && !ret)
			ret = err;
	}

	return ret;
}

static void rec_format_prefix(const struct rec_route *r, char *buf, size_t size)
{
	char ip[INET6_ADDRSTRLEN];

	inet_ntop(r->is_ip6 ? AF_INET6 : AF_INET, r->is_ip6 ?
		  (const void *)r->prefix.address.un.ip6 :
		  (const void *)r->prefix.address.un.ip4, ip, sizeof(ip));
	snprintf(buf, size, "%s/%u", ip, r->prefix.len);
}

/* ---- Policers ---------------------------------------------------------- */

/* Name made by vpppolicer_generate_name(): vyos_<sw_if_index>_<rate>_<burst>_<up|down> */
static int rec_policer_ours(const char *name)
{
	unsigned sw_if_index, rate;
	unsigned long burst;
	char dir[8];
	int n = 0;

	if (sscanf(name, "vyos_%u_%u_%lu_%7[a-z]%n", &sw_if_index, &rate, &burst,
		   dir, &n) != 4)
		return 0;

	return name[n] == 0 && (!strcmp(dir, "up") || !strcmp(dir, "down"));
}

static vapi_error_e rec_policer_dump_cb(struct vapi_ctx_s *ctx, void *cb_ctx,
					vapi_error_e rv, bool is_last,
					vapi_payload_policer_details *d)
{
	struct rec_state *st = cb_ctx;
	char name[64];

	if (rv != VAPI_OK || !d || !st)
		return rv;

	memcpy(name, d->name, sizeof(name));
	name[sizeof(name) - 1] = 0;

	if (!rec_policer_ours(name))
		return rv;

	if (rec_grow((void **)&st->policers, &st->cap_policers, st->n_policers,
		     sizeof(*st->policers))) {
		st->failed = 1;
		return rv;
	}

	memcpy(st->policers[st->n_policers++], name, sizeof(name));

	return rv;
}

static int rec_dump_policers(struct rec_state *st)
{
	struct vapi_ctx_s *ctx = rec_ctx();
	vapi_msg_policer_dump *req;
	vapi_error_e err;

	if (!ctx)
		return -1;

	req = vapi_alloc_policer_dump(ctx);
	if (!req)
		return -1;

	req->payload.match_name_valid = 0;

	err = vapi_policer_dump(ctx, req, rec_policer_dump_cb, st);
	err = vpp_vapi_complete(err);

	return (err != VAPI_OK || st->failed) ? -1 : 0;
}

static vapi_error_e rec_policer_del_cb(struct vapi_ctx_s *ctx, void *cb_ctx,
				       vapi_error_e rv, bool is_last,
				       vapi_payload_policer_add_del_reply *reply)
{
	struct vpp_vapi_reply_ctx *reply_ctx = cb_ctx;

	if (rv == VAPI_OK && reply_ctx && reply)
		reply_ctx->api_retval = reply->retval;

	return rv;
}

/* policer_del in adv-vpp also unapplies the policer from its interfaces. */
static int rec_del_policer(const char *name)
{
	struct vapi_ctx_s *ctx = rec_ctx();
	struct vpp_vapi_reply_ctx reply_ctx = { 0, NULL };
	vapi_msg_policer_add_del *req;
	vapi_error_e err;
	int ret;

	if (!ctx)
		return -1;

	req = vapi_alloc_policer_add_del(ctx);
	if (!req)
		return -1;

	req->payload.is_add = 0;
	strncpy((char *)req->payload.name, name, sizeof(req->payload.name) - 1);
	req->payload.name[sizeof(req->payload.name) - 1] = 0;

	err = vapi_policer_add_del(ctx, req, rec_policer_del_cb, &reply_ctx);
	err = vpp_vapi_complete(err);
	ret = vpp_vapi_errno(err, &reply_ctx);

	if (ret == VPP_API_ERR_NO_SUCH_ENTRY)
		ret = 0;

	return ret;
}

/* ---- Entry point ------------------------------------------------------- */

static int rec_collect(struct rec_state *st)
{
	/* Interfaces first: the session dump is checked against them. */
	if (rec_dump_interfaces(st)) {
		log_error("vpp: reconcile: sw_interface_dump failed\n");
		return -1;
	}
	if (rec_dump_pppoe(st)) {
		log_error("vpp: reconcile: pppoe_session_dump failed\n");
		return -1;
	}

	/* Routes and policers only until a pass removed all of them. */
	if (!rec_routes_done) {
		rec_collect_names(st);
		if (st->failed)
			return -1;

		if (st->have_names && !st->n_named_if && !st->n_pppoe_if) {
			/*
			 * VPP never had a pppoeN, visible or hidden: no route
			 * of ours can be in the FIB, and the walk of the whole
			 * table is not worth it.
			 */
			rec_routes_done = 1;
		} else {
			if (rec_api_source()) {
				log_error("vpp: reconcile: fib_source_dump failed\n");
				return -1;
			}
			if (rec_dump_routes(st, 0) || rec_dump_routes(st, 1)) {
				log_error("vpp: reconcile: ip_route_v2_dump failed\n");
				return -1;
			}
		}
	}
	if (!rec_policers_done && rec_dump_policers(st)) {
		log_error("vpp: reconcile: policer_dump failed\n");
		return -1;
	}

	return 0;
}

int vpp_reconcile_orphans(void)
{
	struct rec_state st;
	size_t i, n_v4 = 0, n_v6 = 0;
	size_t err_routes = 0, err_policers = 0, err_sessions = 0;
	char pfx[INET6_ADDRSTRLEN + 8];
	char ip[INET_ADDRSTRLEN];
	time_t progress = 0;
	int ret;

	memset(&st, 0, sizeof(st));

	if (rec_collect(&st)) {
		rec_free(&st);
		return -1;
	}

	if (st.n_paths_left)
		log_warn("vpp: reconcile: %zu path(s) of API routes through interfaces that VPP does not "
			 "list left alone (%s)\n", st.n_paths_left,
			 st.have_names ? "not pppoe interfaces" : "hidden pppoe interfaces not known");

	if (!st.n_pppoe_if && !st.n_ses && !st.n_routes && !st.n_policers) {
		log_info1("vpp: reconcile: no orphan pppoe session, route or policer in VPP\n");
		rec_free(&st);
		return 0;
	}

	log_warn("vpp: reconcile: VPP holds %zu pppoe interface(s), %zu pppoe session(s), "
		 "%zu route(s) and %zu policer(s) from a previous accel-ppp process; removing\n",
		 st.n_pppoe_if, st.n_ses, st.n_routes, st.n_policers);

	/* Routes first: none may point at a pppoeN that VPP hands out again. */
	for (i = 0; i < st.n_routes; i++) {
		ret = rec_del_route(&st.routes[i]);
		if (!rec_ctx())
			goto lost;
		if (ret) {
			rec_format_prefix(&st.routes[i], pfx, sizeof(pfx));
			log_error("vpp: reconcile: route %s del failed ret=%d\n", pfx, ret);
			err_routes++;
			continue;
		}
		if (st.routes[i].is_ip6)
			n_v6++;
		else
			n_v4++;
		rec_progress(&progress, "route(s)", i + 1, st.n_routes);
	}
	/* Every orphan route is gone: a later attempt does not walk the FIB. */
	if (!err_routes)
		rec_routes_done = 1;

	for (i = 0; i < st.n_policers; i++) {
		ret = rec_del_policer(st.policers[i]);
		if (!rec_ctx())
			goto lost;
		if (ret) {
			log_error("vpp: reconcile: policer %s del failed ret=%d\n",
				  st.policers[i], ret);
			err_policers++;
		}
		rec_progress(&progress, "policer(s)", i + 1, st.n_policers);
	}
	if (!err_policers)
		rec_policers_done = 1;

	for (i = 0; i < st.n_ses; i++) {
		ret = rec_del_pppoe(&st.ses[i]);
		if (!rec_ctx())
			goto lost;
		if (ret) {
			inet_ntop(AF_INET, st.ses[i].client_ip.un.ip4, ip, sizeof(ip));
			log_error("vpp: reconcile: pppoe session sid=%u peer=%s sw_if_index=%u del failed ret=%d\n",
				  st.ses[i].session_id, ip, st.ses[i].sw_if_index, ret);
			err_sessions++;
		}
		rec_progress(&progress, "pppoe session(s)", i + 1, st.n_ses);
	}

	log_warn("vpp: reconcile: removed %zu pppoe session(s), %zu ipv4 and %zu ipv6 route(s), "
		 "%zu policer(s); failed %zu, %zu, %zu\n",
		 st.n_ses - err_sessions, n_v4, n_v6, st.n_policers - err_policers,
		 err_sessions, err_routes, err_policers);

	rec_free(&st);

	/*
	 * A session left behind keeps its session_id in the fast-path hash:
	 * do not hand the connection out (sessions fail to come up) until a
	 * later attempt clears it. A route or policer left behind is logged.
	 * Count what is left from a fresh interface dump, which does not
	 * depend on pppoe_session_dump.
	 */
	memset(&st, 0, sizeof(st));
	ret = rec_dump_interfaces(&st);
	if (!rec_ctx())
		goto lost;
	if (ret) {
		log_error("vpp: reconcile: sw_interface_dump failed\n");
		rec_free(&st);
		return -1;
	}
	if (st.n_pppoe_if) {
		log_error("vpp: reconcile: %zu pppoe interface(s) still up in VPP. If the VPP lists no "
			  "pppoe session through the API (adv-vpp without the pppoe_session_dump fix), "
			  "remove them with 'vppctl delete pppoe sessions'\n", st.n_pppoe_if);
		rec_free(&st);
		return -1;
	}
	rec_free(&st);

	return err_sessions ? -1 : 0;

lost:
	log_error("vpp: reconcile: connection to VPP lost, will retry\n");
	rec_free(&st);
	return -1;
}
