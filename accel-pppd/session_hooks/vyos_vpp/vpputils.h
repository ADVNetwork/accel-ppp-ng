/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
*/

#ifndef VPPUTILS_H
#define VPPUTILS_H

#include <stdint.h>
#include <vapi/vapi.h>

struct vapi_ctx_s;
struct vapi_ctx_s * vpp_get_vapi();
/* Current context, without connecting. Call with vpp_lock held. */
struct vapi_ctx_s *vpp_peek_vapi(void);

/*
 * The VPP process behind the connection. Every connection asks VPP for its
 * pid (control_ping): when it is not the pid of the previous connection, VPP
 * restarted, and the generation goes up. An interface index, a route or a
 * policer made in one generation means nothing in the next: the same
 * sw_if_index names the interface of another subscriber there. So whoever
 * keeps something of VPP keeps the generation with it and goes through
 * vpp_get_vapi_gen().
 *
 * The generation only changes inside vpp_lock.
 */
uint32_t vpp_generation(void);
/* pid of the VPP process of the current generation, 0 before the first connection */
uint32_t vpp_instance_pid(void);
/* generation and pid together; call with vpp_lock held */
void vpp_instance(uint32_t *gen, uint32_t *pid);

/*
 * As vpp_get_vapi(), but NULL when the VPP that answers is not the one of
 * generation gen. Call with vpp_lock held.
 */
struct vapi_ctx_s *vpp_get_vapi_gen(uint32_t gen);

/*
 * Check the connection with a control_ping, connecting if there is none.
 * Called from the module timer (vpphooks.c), so a VPP that went away or came
 * back is noticed without waiting for a session to need the API. Does
 * nothing when another thread is using the connection. Returns 0 when there
 * is no connection to VPP.
 */
int vpp_keepalive(void);

/*
 * The VPP process is known to be gone (vpphooks.c watches it): drop the
 * connection now, unless a thread is using it.
 */
void vpp_connection_lost(void);

void vpp_lock();
void vpp_unlock();

/* export symbols */
int vpp_get();
void vpp_put();

struct vpp_vapi_reply_ctx {
	int32_t api_retval;
	uint32_t *sw_if_index;
};

/*
 * Call with vpp_lock held, right after every VAPI request. Waits for a late
 * reply and returns the final result. On return the request is finished, or
 * the connection was dropped: fetch the context again with vpp_get_vapi().
 */
vapi_error_e vpp_vapi_complete(vapi_error_e err);

int vpp_vapi_errno(vapi_error_e err, const struct vpp_vapi_reply_ctx *ctx);

/* vnet/error.h: VNET_API_ERROR_* */
#define VPP_API_ERR_INVALID_SW_IF_INDEX (-2)
#define VPP_API_ERR_NO_SUCH_ENTRY (-6)
#define VPP_API_ERR_INVALID_VALUE (-7)
#define VPP_API_ERR_TUNNEL_EXIST (-75)
#define VPP_API_ERR_VALUE_EXIST (-81)

#endif /* VPPUTILS_H */
