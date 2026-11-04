/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
*/

#include <vapi/vapi.h>
#include <vapi/vpe.api.vapi.h>

#include <pthread.h>
#include <time.h>

#include "triton.h"
#include "events.h"
#include "log.h"

#include "vpputils.h"

/*
 * How long a thread waits for a VPP reply before dropping the connection.
 * VAPI gives up after 1 second on the socket transport, which is too short
 * for a busy VPP. The caller holds vpp_lock during the wait.
 */
#define VPP_REPLY_TIMEOUT_SEC 10

int sc_vpp_queue_size = 1024;

struct vpp_connect_t
{
	vapi_ctx_t vapi;
	int rfcounter;
	pthread_mutex_t lock_vpp;

	struct list_head vpp_handlers;
} vpp_connect;

const char vpp_app_name[] = "accel-vpp";

static void vpppoe_connect_to_vpp()
{
	vpp_connect.vapi = NULL;
	vapi_error_e verr = vapi_ctx_alloc(&vpp_connect.vapi);

	if (verr != VAPI_OK || vpp_connect.vapi == NULL) {
		vpp_connect.vapi = NULL;
		return;
	}

	verr = vapi_connect_ex(vpp_connect.vapi, vpp_app_name, NULL, sc_vpp_queue_size, sc_vpp_queue_size, VAPI_MODE_BLOCKING, true, true);
	if (verr != VAPI_OK) {
		vapi_ctx_free(vpp_connect.vapi);
		vpp_connect.vapi = NULL;
		return;
	}
}

void vpppoe_disconnect_from_vpp()
{
	if (vpp_connect.vapi != NULL) {
		vapi_disconnect(vpp_connect.vapi);
		vapi_ctx_free(vpp_connect.vapi);
		vpp_connect.vapi = NULL;
	}
}

struct vapi_ctx_s * vpp_get_vapi() {
	if (vpp_connect.vapi == NULL && __atomic_load_n(&vpp_connect.rfcounter, __ATOMIC_SEQ_CST)) {
		vpppoe_connect_to_vpp();
	}
	return vpp_connect.vapi;
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