/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#include <vapi/vapi.h>
#include <vapi/vpe.api.vapi.h>
#include <vapi/pppoe.api.vapi.h>
#include <vapi/feature.api.vapi.h>
#include <vapi/interface.api.vapi.h>

#include <linux/if_ether.h>
#include <netinet/in.h>

#include <memory.h>
#include <stdio.h>

#include "triton.h"
#include "vpputils.h"
#include "vpppoe.h"

DEFINE_VAPI_MSG_IDS_VPE_API_JSON
DEFINE_VAPI_MSG_IDS_PPPOE_API_JSON
DEFINE_VAPI_MSG_IDS_FEATURE_API_JSON
DEFINE_VAPI_MSG_IDS_INTERFACE_API_JSON

static void vpppoe_set_client_ip(vapi_msg_pppoe_add_del_session *req, in_addr_t client_ip)
{
	req->payload.client_ip.af = ADDRESS_IP4;
	memcpy(req->payload.client_ip.un.ip4, &client_ip, sizeof(client_ip));
}

static vapi_error_e vpppoe_s_session_add_reply_callback(struct vapi_ctx_s *ctx,
							void *callback_ctx,
							vapi_error_e rv,
							bool is_last,
							vapi_payload_pppoe_add_del_session_reply *reply)
{
	struct vpp_vapi_reply_ctx *reply_ctx = callback_ctx;

	if (rv == VAPI_OK && reply_ctx && reply) {
		reply_ctx->api_retval = reply->retval;
		if (reply_ctx->api_retval == 0 && reply_ctx->sw_if_index)
			*reply_ctx->sw_if_index = reply->sw_if_index;
	}

	return rv;
}

int vpppoe_sync_add_pppoe_interface(uint8_t *client_mac, uint16_t session_id,
				    in_addr_t client_ip, uint32_t *sw_ifindex,
				    uint32_t *gen, uint32_t *pid)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;
	struct vpp_vapi_reply_ctx reply_ctx = { 0, sw_ifindex };

	vpp_lock();

	ctx = vpp_get_vapi();
	if (ctx == NULL) {
		goto exit;
	}

	/* the VPP process this request goes to: fixed while vpp_lock is held */
	vpp_instance(gen, pid);

	vapi_msg_pppoe_add_del_session *req = vapi_alloc_pppoe_add_del_session(ctx);
	if (req == NULL) {
		goto exit;
	}

	vpppoe_set_client_ip(req, client_ip);
	memcpy(req->payload.client_mac, client_mac, ETH_ALEN);

	req->payload.is_add = 1;
	req->payload.session_id = session_id;
	/* Route installed explicitly via ip_route_add_del; keep VPP session lean. */
	req->payload.disable_fib = 1;

	err = vapi_pppoe_add_del_session(ctx, req, vpppoe_s_session_add_reply_callback, &reply_ctx);
	err = vpp_vapi_complete(err);
	err = vpp_vapi_errno(err, &reply_ctx);

exit:
	vpp_unlock();
	return err;
}

static vapi_error_e vpppoe_s_session_del_reply_callback(struct vapi_ctx_s *ctx,
							void *callback_ctx,
							vapi_error_e rv,
							bool is_last,
							vapi_payload_pppoe_add_del_session_reply *reply)
{
	struct vpp_vapi_reply_ctx *reply_ctx = callback_ctx;

	if (rv == VAPI_OK && reply_ctx && reply)
		reply_ctx->api_retval = reply->retval;

	return rv;
}

int vpppoe_sync_del_pppoe_interface(uint32_t gen, uint8_t *client_mac, uint16_t session_id,
				    in_addr_t client_ip)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;
	struct vpp_vapi_reply_ctx reply_ctx = { 0, NULL };

	vpp_lock();

	ctx = vpp_get_vapi_gen(gen);
	if (ctx == NULL) {
		goto exit;
	}

	vapi_msg_pppoe_add_del_session *req = vapi_alloc_pppoe_add_del_session(ctx);
	if (req == NULL) {
		goto exit;
	}

	vpppoe_set_client_ip(req, client_ip);
	memcpy(req->payload.client_mac, client_mac, ETH_ALEN);

	req->payload.is_add = 0;
	req->payload.session_id = session_id;
	req->payload.disable_fib = 1;

	err = vapi_pppoe_add_del_session(ctx, req, vpppoe_s_session_del_reply_callback, &reply_ctx);
	err = vpp_vapi_complete(err);
	err = vpp_vapi_errno(err, &reply_ctx);
	if (err == VPP_API_ERR_NO_SUCH_ENTRY)
		err = 0;

exit:
	vpp_unlock();
	return err;
}

static vapi_error_e vpppoe_set_feature_callback(struct vapi_ctx_s *ctx,
						void *callback_ctx,
						vapi_error_e rv,
						bool is_last,
						vapi_payload_feature_enable_disable_reply *reply)
{
	struct vpp_vapi_reply_ctx *reply_ctx = callback_ctx;

	if (rv == VAPI_OK && reply_ctx && reply)
		reply_ctx->api_retval = reply->retval;

	return rv;
}

int vpppoe_set_feature(uint32_t gen, uint32_t ifindex, int is_enabled, const char *feature,
		       const char *arc)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;
	struct vpp_vapi_reply_ctx reply_ctx = { 0, NULL };

	vpp_lock();

	ctx = vpp_get_vapi_gen(gen);
	if (ctx == NULL) {
		goto exit;
	}

	vapi_msg_feature_enable_disable *req = vapi_alloc_feature_enable_disable(ctx);
	if (req == NULL) {
		goto exit;
	}

	strncpy((char *)req->payload.feature_name, feature, 63);
	req->payload.feature_name[63] = 0;
	strncpy((char *)req->payload.arc_name, arc, 63);
	req->payload.arc_name[63] = 0;

	req->payload.sw_if_index = ifindex;
	req->payload.enable = is_enabled;

	err = vapi_feature_enable_disable(ctx, req, vpppoe_set_feature_callback, &reply_ctx);
	err = vpp_vapi_complete(err);
	err = vpp_vapi_errno(err, &reply_ctx);

exit:
	vpp_unlock();
	return err;
}

typedef struct vpppoe_dump_interface_name_ctx_t
{
	char *name;
	size_t size;
	uint32_t ifindex;
	int found;
} vpppoe_dump_interface_name_ctx_t;

static vapi_error_e vpppoe_dump_interface_name_callback(struct vapi_ctx_s *ctx,
							void *callback_ctx,
							vapi_error_e rv,
							bool is_last,
							vapi_payload_sw_interface_details *reply)
{
	vpppoe_dump_interface_name_ctx_t *dump_ctx = callback_ctx;
	size_t n;

	if (dump_ctx == NULL || reply == NULL || rv != VAPI_OK)
		return rv;

	if (reply->sw_if_index != dump_ctx->ifindex)
		return rv;

	n = dump_ctx->size > sizeof(reply->interface_name) ? sizeof(reply->interface_name) : dump_ctx->size;
	memcpy(dump_ctx->name, reply->interface_name, n);
	dump_ctx->name[n - 1] = 0;
	dump_ctx->found = dump_ctx->name[0] != 0;

	return rv;
}

int vpppoe_dump_interface_name(uint32_t gen, uint32_t ifindex, char *name, size_t size)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;
	/* On the stack: the request is finished, or dropped, before the return. */
	vpppoe_dump_interface_name_ctx_t dump_ctx = { name, size, ifindex, 0 };

	if (name == NULL || !size) {
		return -1;
	}

	vpp_lock();

	ctx = vpp_get_vapi_gen(gen);
	if (ctx == NULL) {
		goto exit;
	}

	vapi_msg_sw_interface_dump *req = vapi_alloc_sw_interface_dump(ctx, 0);
	if (req == NULL) {
		goto exit;
	}

	req->payload.sw_if_index = ifindex;

	err = vapi_sw_interface_dump(ctx, req, vpppoe_dump_interface_name_callback, &dump_ctx);
	err = vpp_vapi_complete(err);

exit:
	vpp_unlock();

	if (err != VAPI_OK)
		return err;

	return dump_ctx.found ? 0 : -1;
}

static vapi_error_e vpppoe_set_mtu_callback(struct vapi_ctx_s *ctx,
					    void *callback_ctx,
					    vapi_error_e rv,
					    bool is_last,
					    vapi_payload_sw_interface_set_mtu_reply *reply)
{
	struct vpp_vapi_reply_ctx *reply_ctx = callback_ctx;

	if (rv == VAPI_OK && reply_ctx && reply)
		reply_ctx->api_retval = reply->retval;

	return rv;
}

/*
 * The interface MTU that VPP checks before the PPPoE header goes on
 * (ip4-midchain). A pppoeN is made with MTU 0, which VPP reads as 9000: a
 * packet larger than what the CPE asked for in LCP went out whole, and a
 * strict CPE dropped it.
 *
 * Only the L3 MTU is set. VPP rewrites the four values (L3, IP4, IP6, MPLS)
 * on every call, and a per-protocol value of 0 follows the L3 one.
 */
int vpppoe_set_mtu(uint32_t gen, uint32_t ifindex, uint32_t mtu)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;
	struct vpp_vapi_reply_ctx reply_ctx = { 0, NULL };

	vpp_lock();

	ctx = vpp_get_vapi_gen(gen);
	if (ctx == NULL) {
		goto exit;
	}

	vapi_msg_sw_interface_set_mtu *req = vapi_alloc_sw_interface_set_mtu(ctx);
	if (req == NULL) {
		goto exit;
	}

	req->payload.sw_if_index = ifindex;
	memset(req->payload.mtu, 0, sizeof(req->payload.mtu));
	req->payload.mtu[0] = mtu;

	err = vapi_sw_interface_set_mtu(ctx, req, vpppoe_set_mtu_callback, &reply_ctx);
	err = vpp_vapi_complete(err);
	err = vpp_vapi_errno(err, &reply_ctx);

exit:
	vpp_unlock();
	return err;
}
