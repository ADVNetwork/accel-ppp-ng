/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
*/

#include <vapi/vapi.h>
#include <vapi/vpe.api.vapi.h>
#include <vapi/memclnt.api.vapi.h>

#include <pthread.h>
#include <time.h>

#include "triton.h"
#include "events.h"
#include "log.h"

#include "vpputils.h"
#include "vpphooks.h"
#include "vppstats.h"
#include "vppreconcile.h"

/*
 * How long a thread waits for a VPP reply before dropping the connection.
 * VAPI gives up after 1 second on the socket transport, which is too short
 * for a busy VPP. The caller holds vpp_lock during the wait.
 */
#define VPP_REPLY_TIMEOUT_SEC 10

/*
 * Wait between failed startup reconciliations (vppreconcile.c): 5 s after the
 * first failure, doubled after each one up to 60 s. A failure that does not
 * go away by itself (a session VPP refuses to delete, a VPP that does not
 * list its sessions) is not hammered with dumps every 5 s.
 */
#define VPP_RECONCILE_RETRY_MIN_SEC 5
#define VPP_RECONCILE_RETRY_MAX_SEC 60

/*
 * Wait after a connection attempt that failed. With VPP down, every session
 * that ends asks for the connection several times, and thousands end
 * together: without the wait each of those calls was a new attempt.
 */
#define VPP_CONNECT_RETRY_MS 200

int sc_vpp_queue_size = 1024;

/*
 * Set once the startup reconciliation succeeded. Until then this process has
 * created nothing in VPP, so everything PPPoE found there is an orphan.
 */
static int vpp_reconciled;
static time_t vpp_reconcile_failed_at;
static int vpp_reconcile_retry_sec = VPP_RECONCILE_RETRY_MIN_SEC;

/* Monotonic time of the last failed connection attempt (vpp_lock held). */
static struct timespec vpp_connect_failed_at;
static int vpp_connect_failed;

/*
 * The VPP process of the current connection, or of the last one (vpputils.h).
 * Written with vpp_lock held; read from any thread.
 */
static uint32_t vpp_gen;
static uint32_t vpp_pid;

struct vpp_connect_t
{
	vapi_ctx_t vapi;
	int rfcounter;
	pthread_mutex_t lock_vpp;

	struct list_head vpp_handlers;
} vpp_connect;

const char vpp_app_name[] = "accel-vpp";

void vpppoe_disconnect_from_vpp();

uint32_t vpp_generation(void)
{
	return __atomic_load_n(&vpp_gen, __ATOMIC_ACQUIRE);
}

uint32_t vpp_instance_pid(void)
{
	return __atomic_load_n(&vpp_pid, __ATOMIC_ACQUIRE);
}

void vpp_instance(uint32_t *gen, uint32_t *pid)
{
	*gen = vpp_gen;
	*pid = vpp_pid;
}

static vapi_error_e vpp_ping_cb(struct vapi_ctx_s *ctx, void *callback_ctx, vapi_error_e rv,
				bool is_last, vapi_payload_control_ping_reply *reply)
{
	uint32_t *pid = callback_ctx;

	if (rv == VAPI_OK && reply && pid && reply->retval == 0)
		*pid = reply->vpe_pid;

	return rv;
}

/*
 * vpp_lock held. The pid of the VPP process, or 0 when it did not answer; the
 * connection is then dropped, unless the request could not even be made.
 */
static uint32_t vpp_ping(void)
{
	vapi_ctx_t ctx = vpp_connect.vapi;
	vapi_msg_control_ping *req;
	vapi_error_e err;
	uint32_t pid = 0;

	if (ctx == NULL)
		return 0;

	req = vapi_alloc_control_ping(ctx);
	if (req == NULL)
		return 0;

	err = vapi_control_ping(ctx, req, vpp_ping_cb, &pid);
	err = vpp_vapi_complete(err);

	return err == VAPI_OK ? pid : 0;
}

static void vpppoe_connect_to_vpp()
{
	struct timespec now;
	uint32_t pid;

	vpp_connect.vapi = NULL;

	clock_gettime(CLOCK_MONOTONIC, &now);
	if (!vpp_reconciled && vpp_reconcile_failed_at &&
	    now.tv_sec - vpp_reconcile_failed_at < vpp_reconcile_retry_sec)
		return;

	if (vpp_connect_failed &&
	    (now.tv_sec - vpp_connect_failed_at.tv_sec) * 1000 +
	    (now.tv_nsec - vpp_connect_failed_at.tv_nsec) / 1000000 < VPP_CONNECT_RETRY_MS)
		return;

	vapi_error_e verr = vapi_ctx_alloc(&vpp_connect.vapi);

	if (verr != VAPI_OK || vpp_connect.vapi == NULL) {
		vpp_connect.vapi = NULL;
		goto failed;
	}

	verr = vapi_connect_ex(vpp_connect.vapi, vpp_app_name, NULL, sc_vpp_queue_size, sc_vpp_queue_size, VAPI_MODE_BLOCKING, true, true);
	if (verr != VAPI_OK) {
		vapi_ctx_free(vpp_connect.vapi);
		vpp_connect.vapi = NULL;
		goto failed;
	}

	/*
	 * Which VPP is this? Nobody gets the context before the answer: what
	 * the sessions keep of VPP is only good for the process that made it.
	 */
	pid = vpp_ping();
	if (!pid) {
		log_error("vpp: connected, but VPP did not answer the control ping\n");
		vpppoe_disconnect_from_vpp();
		goto failed;
	}

	if (vpp_connect_failed) {
		vpp_connect_failed = 0;
		log_warn("vpp: connected to VPP again\n");
	}

	if (pid != vpp_pid) {
		int restarted = vpp_pid != 0;

		if (restarted)
			log_warn("vpp: VPP restarted (pid %u, was %u): the sessions made in the previous "
				 "process are gone from the dataplane and will be terminated\n", pid, vpp_pid);

		__atomic_store_n(&vpp_pid, pid, __ATOMIC_RELEASE);
		__atomic_store_n(&vpp_gen, vpp_gen + 1, __ATOMIC_RELEASE);

		if (restarted)
			vpphook_vpp_restarted();
	}

	if (vpp_reconciled)
		return;

	/*
	 * First connection of the process: clear what a previous accel-ppp left
	 * in VPP before anyone gets the context. On failure no context is
	 * handed out, so no session is created next to an orphan one with the
	 * same session_id.
	 */
	if (vpp_reconcile_orphans() == 0) {
		vpp_reconciled = 1;
		return;
	}

	/* the wait before the next attempt: the one of the previous failure, doubled */
	if (vpp_reconcile_failed_at) {
		vpp_reconcile_retry_sec *= 2;
		if (vpp_reconcile_retry_sec > VPP_RECONCILE_RETRY_MAX_SEC)
			vpp_reconcile_retry_sec = VPP_RECONCILE_RETRY_MAX_SEC;
	}

	clock_gettime(CLOCK_MONOTONIC, &now);
	vpp_reconcile_failed_at = now.tv_sec ? now.tv_sec : 1;
	log_error("vpp: startup reconciliation failed, no session will be created until it succeeds "
		  "(retry in %d s)\n", vpp_reconcile_retry_sec);
	vpppoe_disconnect_from_vpp();
	return;

failed:
	if (!vpp_connect_failed)
		log_warn("vpp: no connection to VPP (not running, or not answering)\n");
	vpp_connect_failed = 1;
	clock_gettime(CLOCK_MONOTONIC, &vpp_connect_failed_at);
}

void vpppoe_disconnect_from_vpp()
{
	if (vpp_connect.vapi != NULL) {
		vapi_disconnect(vpp_connect.vapi);
		vapi_ctx_free(vpp_connect.vapi);
		vpp_connect.vapi = NULL;
	}

	/* VPP may be gone: nothing of it stays mapped (vppstats.c) */
	vpp_stats_drop();
}

void vpp_connection_lost(void)
{
	/* a thread in the middle of a call finds out by itself */
	if (pthread_mutex_trylock(&vpp_connect.lock_vpp))
		return;

	vpppoe_disconnect_from_vpp();
	pthread_mutex_unlock(&vpp_connect.lock_vpp);
}

struct vapi_ctx_s *vpp_peek_vapi(void)
{
	return vpp_connect.vapi;
}

struct vapi_ctx_s * vpp_get_vapi() {
	if (vpp_connect.vapi == NULL && __atomic_load_n(&vpp_connect.rfcounter, __ATOMIC_SEQ_CST)) {
		vpppoe_connect_to_vpp();
	}
	return vpp_connect.vapi;
}

struct vapi_ctx_s *vpp_get_vapi_gen(uint32_t gen)
{
	struct vapi_ctx_s *ctx = vpp_get_vapi();

	return (ctx && vpp_gen == gen) ? ctx : NULL;
}

int vpp_keepalive(void)
{
	int up;

	/* someone is talking to VPP right now: that call finds out by itself */
	if (pthread_mutex_trylock(&vpp_connect.lock_vpp))
		return 1;

	if (__atomic_load_n(&vpp_connect.rfcounter, __ATOMIC_SEQ_CST)) {
		if (vpp_connect.vapi == NULL)
			vpppoe_connect_to_vpp();
		else
			vpp_ping();
	}

	up = vpp_connect.vapi != NULL;
	pthread_mutex_unlock(&vpp_connect.lock_vpp);

	return up;
}

void vpp_lock() {
	pthread_mutex_lock(&vpp_connect.lock_vpp);
}

void vpp_unlock() {
	pthread_mutex_unlock(&vpp_connect.lock_vpp);
}

int vpp_get()
{
	vpp_lock();
	int rfc = __sync_fetch_and_add(&vpp_connect.rfcounter, 1);
	if (!rfc)
		vpppoe_connect_to_vpp();
	vpp_unlock();

	return 0;
}

void vpp_put()
{
	vpp_lock();
	int rfc = __sync_sub_and_fetch(&vpp_connect.rfcounter, 1);
	if (!rfc)
		vpppoe_disconnect_from_vpp();
	vpp_unlock();
}

static long vpp_elapsed_ms(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - start->tv_sec) * 1000 + (now.tv_nsec - start->tv_nsec) / 1000000;
}

vapi_error_e vpp_vapi_complete(vapi_error_e err)
{
	vapi_ctx_t ctx = vpp_connect.vapi;
	struct timespec start;

	if (ctx == NULL)
		return err;

	if (err == VAPI_EAGAIN && !vapi_requests_empty(ctx)) {
		clock_gettime(CLOCK_MONOTONIC, &start);
		do {
			if (vpp_elapsed_ms(&start) >= VPP_REPLY_TIMEOUT_SEC * 1000) {
				err = VAPI_ENORESP;
				break;
			}
			err = vapi_dispatch(ctx);
		} while (err == VAPI_EAGAIN);

		if (err == VAPI_OK)
			log_warn("vpp: slow reply, %ld ms beyond the VAPI timeout\n",
				 vpp_elapsed_ms(&start));
	}

	/*
	 * A request still queued holds a callback context on the stack of a
	 * caller about to return. Dropping the connection discards the request,
	 * so its late reply can never reach that context.
	 */
	if (err >= VAPI_ECON_FAIL || !vapi_requests_empty(ctx)) {
		log_error("vpp: dropping connection, api call failed err=%d\n", (int)err);
		vpppoe_disconnect_from_vpp();
	}

	return err;
}

int vpp_vapi_errno(vapi_error_e err, const struct vpp_vapi_reply_ctx *ctx)
{
	if (err != VAPI_OK)
		return (int) err;
	if (ctx && ctx->api_retval != 0)
		return (int) ctx->api_retval;
	return 0;
}

static void vpppoe_load_config(void)
{
	char *opt;

	opt = conf_get_opt("vpp", "queue-size");
	if (opt)
		sc_vpp_queue_size = atoi(opt);
}

static void vpppoe_init()
{
	memset(&vpp_connect, 0, sizeof(vpp_connect));
	pthread_mutex_init(&vpp_connect.lock_vpp, NULL);
	INIT_LIST_HEAD(&vpp_connect.vpp_handlers);

	vpppoe_load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)vpppoe_load_config);
}

DEFINE_INIT(20, vpppoe_init);