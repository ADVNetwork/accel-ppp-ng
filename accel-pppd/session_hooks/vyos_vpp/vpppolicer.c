/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#include <vapi/vapi.h>
#include <vapi/vpe.api.vapi.h>
#include <vapi/policer.api.vapi.h>

#include <stdio.h>

#include "ap_session.h"
#include "ppp.h"
#include "log.h"
#include "triton.h"
#include "events.h"
#include "vpputils.h"
#include "vpppoe.h"
#include "vpphooks.h"

#include "vpppolicer.h"

DEFINE_VAPI_MSG_IDS_POLICER_API_JSON

static uint32_t s_vpp_policer_type = SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_2698;
static double s_cir_factor = 0.8;
static double s_cb_factor = 1;
static double s_eir_factor = 1;
static double s_eb_factor = 0.2;
static uint32_t s_conform_action = SSE2_QOS_ACTION_API_TRANSMIT;
static uint32_t s_exceed_action = SSE2_QOS_ACTION_API_TRANSMIT;
static uint32_t s_violate_action = SSE2_QOS_ACTION_API_DROP;

static vapi_error_e vpppolicer_set_input_callback(struct vapi_ctx_s *ctx,
						  void *callback_ctx,
						  vapi_error_e rv,
						  bool is_last,
						  vapi_payload_policer_input_reply *reply)
{
	struct vpp_vapi_reply_ctx *reply_ctx = callback_ctx;

	if (rv == VAPI_OK && reply_ctx && reply)
		reply_ctx->api_retval = reply->retval;

	return rv;
}

static int vpppolicer_set_input(uint32_t gen, int is_add, uint32_t ifindex, const char *policer_name)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;
	struct vpp_vapi_reply_ctx reply_ctx = { 0, NULL };

	vpp_lock();

	ctx = vpp_get_vapi_gen(gen);
	if (ctx == NULL) {
		goto exit;
	}

	vapi_msg_policer_input *req = vapi_alloc_policer_input(ctx);
	if (req == NULL) {
		goto exit;
	}

	req->payload.apply = is_add;
	strncpy((char *)req->payload.name, policer_name, sizeof(req->payload.name) - 1);
	req->payload.name[sizeof(req->payload.name) - 1] = 0;
	req->payload.sw_if_index = ifindex;

	err = vapi_policer_input(ctx, req, vpppolicer_set_input_callback, &reply_ctx);
	err = vpp_vapi_complete(err);
	err = vpp_vapi_errno(err, &reply_ctx);

exit:
	vpp_unlock();
	return err;
}

static vapi_error_e vpppolicer_set_output_callback(struct vapi_ctx_s *ctx,
						   void *callback_ctx,
						   vapi_error_e rv,
						   bool is_last,
						   vapi_payload_policer_output_reply *reply)
{
	struct vpp_vapi_reply_ctx *reply_ctx = callback_ctx;

	if (rv == VAPI_OK && reply_ctx && reply)
		reply_ctx->api_retval = reply->retval;

	return rv;
}

static int vpppolicer_set_output(uint32_t gen, int is_add, uint32_t ifindex, const char *policer_name)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;
	struct vpp_vapi_reply_ctx reply_ctx = { 0, NULL };

	vpp_lock();

	ctx = vpp_get_vapi_gen(gen);
	if (ctx == NULL) {
		goto exit;
	}

	vapi_msg_policer_output *req = vapi_alloc_policer_output(ctx);
	if (req == NULL) {
		goto exit;
	}

	req->payload.apply = is_add;
	strncpy((char *)req->payload.name, policer_name, sizeof(req->payload.name) - 1);
	req->payload.name[sizeof(req->payload.name) - 1] = 0;
	req->payload.sw_if_index = ifindex;

	err = vapi_policer_output(ctx, req, vpppolicer_set_output_callback, &reply_ctx);
	err = vpp_vapi_complete(err);
	err = vpp_vapi_errno(err, &reply_ctx);

exit:
	vpp_unlock();
	return err;
}

static vapi_error_e vpppolicer_add_del_callback(struct vapi_ctx_s *ctx,
						void *callback_ctx,
						vapi_error_e rv,
						bool is_last,
						vapi_payload_policer_add_del_reply *reply)
{
	struct vpp_vapi_reply_ctx *reply_ctx = callback_ctx;

	if (rv == VAPI_OK && reply_ctx && reply)
		reply_ctx->api_retval = reply->retval;

	return rv;
}

static int vpppolicer_add_del(uint32_t gen, int is_add, const char *policer_name, uint32_t cir_kbits, uint64_t cb_bits)
{
	vapi_error_e err = -1;
	struct vapi_ctx_s *ctx;
	struct vpp_vapi_reply_ctx reply_ctx = { 0, NULL };

	vpp_lock();

	ctx = vpp_get_vapi_gen(gen);
	if (ctx == NULL) {
		goto exit;
	}

	vapi_msg_policer_add_del *req = vapi_alloc_policer_add_del(ctx);
	if (req == NULL) {
		goto exit;
	}

	req->payload.is_add = is_add;
	strncpy((char *)req->payload.name, policer_name, sizeof(req->payload.name) - 1);
	req->payload.name[sizeof(req->payload.name) - 1] = 0;

	req->payload.cir = cir_kbits * s_cir_factor;
	req->payload.cb = cb_bits * s_cb_factor;
	req->payload.eir = cir_kbits * s_eir_factor;
	req->payload.eb = cb_bits * s_eb_factor;

	req->payload.rate_type = SSE2_QOS_RATE_API_KBPS;
	req->payload.round_type = SSE2_QOS_ROUND_API_TO_CLOSEST;
	req->payload.type = s_vpp_policer_type;

	req->payload.conform_action.type = s_conform_action;
	req->payload.exceed_action.type = s_exceed_action;
	req->payload.violate_action.type = s_violate_action;

	req->payload.color_aware = 0;

	err = vapi_policer_add_del(ctx, req, vpppolicer_add_del_callback, &reply_ctx);
	err = vpp_vapi_complete(err);
	err = vpp_vapi_errno(err, &reply_ctx);

exit:
	vpp_unlock();
	return err;
}

/*
 * Delete a policer by name. policer_del in adv-vpp also takes the policer
 * off the interfaces it is applied to. 0 also when VPP has no such policer.
 */
int vpppolicer_del_name(uint32_t gen, const char *policer_name)
{
	int ret = vpppolicer_add_del(gen, 0, policer_name, 0, 0);

	return ret == VPP_API_ERR_NO_SUCH_ENTRY ? 0 : ret;
}

void vpppolicer_format_name(char *name, size_t size, uint32_t sw_if_index, uint32_t rate, uint64_t burst, int is_up)
{
	/* vppreconcile.c (rec_policer_ours) recognises this format */
	snprintf(name, size, "vyos_%u_%u_%lu_%s", sw_if_index, rate, (unsigned long)burst, is_up ? "up" : "down");
}

/*
 * Make the policer and apply it to the interface. Any answer of VPP other
 * than success leaves nothing behind and fails: before, the answers were not
 * read, and a session whose policer VPP refused ran without any limit.
 */
static int vpppolicer_apply(uint32_t gen, uint32_t ifindex, const char *name, uint32_t rate, uint64_t burst, int is_up)
{
	int ret;

	/* from now on the name is of this session, not a leftover to delete */
	vpphook_deferred_forget_policer(gen, name);

	ret = vpppolicer_add_del(gen, 1, name, rate, burst);
	if (ret == VPP_API_ERR_VALUE_EXIST) {
		/*
		 * Left by a session that had this interface before and could
		 * not remove it. Same rate and burst, but the type and the
		 * factors may be others: make it again.
		 */
		vpppolicer_del_name(gen, name);
		ret = vpppolicer_add_del(gen, 1, name, rate, burst);
	}
	if (ret)
		return ret;

	ret = is_up ? vpppolicer_set_input(gen, 1, ifindex, name) :
		      vpppolicer_set_output(gen, 1, ifindex, name);
	if (ret) {
		vpppolicer_del_name(gen, name);
		return ret;
	}

	return 0;
}

int vpppolicer_install_limiter(struct ap_session *ses, int down_speed, int down_burst, int up_speed, int up_burst)
{
	int ret = 0;
	char policer_input[POLICER_NAME_MAX_LEN] = {};
	char policer_output[POLICER_NAME_MAX_LEN] = {};
	struct vpphook_private_data_t *vpphook_data;
	uint32_t ifindex, gen;

	vpphook_data = vpphook_live(ses, &ifindex, &gen);
	if (!vpphook_data)
		return -1;

	/* convert rate to kbits/s and burst to bits */
	down_speed = down_speed * 8 / 1000;
	down_burst = down_burst * 8;
	up_speed = up_speed * 8 / 1000;
	up_burst = up_burst * 8;

	/* Remove previously installed limiter, if exists */
	vpppolicer_remove_limiter(ses);

	if (down_speed) {
		vpppolicer_format_name(policer_output, sizeof(policer_output), ifindex, down_speed, down_burst, 0);
		ret = vpppolicer_apply(gen, ifindex, policer_output, down_speed, down_burst, 0);
		if (ret) {
			log_ppp_error("vpp: download policer %s refused by VPP, ret=%d\n", policer_output, ret);
			goto exit;
		}

		vpphook_data->vpppolicer_down = down_speed;
		vpphook_data->vpppolicer_down_burst = down_burst;
	}

	if (up_speed) {
		vpppolicer_format_name(policer_input, sizeof(policer_input), ifindex, up_speed, up_burst, 1);
		ret = vpppolicer_apply(gen, ifindex, policer_input, up_speed, up_burst, 1);
		if (ret) {
			log_ppp_error("vpp: upload policer %s refused by VPP, ret=%d\n", policer_input, ret);
			/* no half limiter: the caller is told the install failed */
			vpppolicer_remove_limiter(ses);
			goto exit;
		}

		vpphook_data->vpppolicer_up = up_speed;
		vpphook_data->vpppolicer_up_burst = up_burst;

		/*
		 * VPP's policer_input() API (src/vnet/policer/policer.c) already
		 * enables policer-input on device-input + ip4-unicast + ip6-unicast.
		 * Only the multicast arcs are not covered by the API and must be
		 * enabled manually here. Without this split, ip4/ip6-unicast end up
		 * with the feature twice (API + manual), policing every packet twice
		 * against the same token bucket and dropping ~all conformed traffic.
		 */
		if (vpppoe_set_feature(gen, ifindex, 1, "policer-input", "ip4-multicast") ||
		    vpppoe_set_feature(gen, ifindex, 1, "policer-input", "ip6-multicast"))
			log_ppp_warn("vpp: upload policer %s not applied to multicast\n", policer_input);
	}

exit:
	return ret;
}

/*
 * Take the limiter off the session interface. Both directions are always
 * tried; the first error is returned. A direction that could not be removed
 * stays recorded in the session, for vpppolicer_leftover().
 */
int vpppolicer_remove_limiter(struct ap_session *ses)
{
	int ret = 0, r;
	char policer_input[POLICER_NAME_MAX_LEN] = {};
	char policer_output[POLICER_NAME_MAX_LEN] = {};
	struct vpphook_private_data_t *vpphook_data = vpphook_get_pd(ses);
	uint32_t ifindex, gen;

	if (!vpphook_data)
		return 0;

	if (!vpphook_live(ses, &ifindex, &gen)) {
		/* the policers of a VPP that restarted went away with it */
		vpphook_data->vpppolicer_down = 0;
		vpphook_data->vpppolicer_down_burst = 0;
		vpphook_data->vpppolicer_up = 0;
		vpphook_data->vpppolicer_up_burst = 0;
		return 0;
	}

	if (vpphook_data->vpppolicer_down) {
		vpppolicer_format_name(policer_output, sizeof(policer_output), ifindex, vpphook_data->vpppolicer_down, vpphook_data->vpppolicer_down_burst, 0);
		/* the unapply answers 0 also when the policer is not applied */
		vpppolicer_set_output(gen, 0, ifindex, policer_output);
		r = vpppolicer_del_name(gen, policer_output);
		if (r == 0) {
			vpphook_data->vpppolicer_down = 0;
			vpphook_data->vpppolicer_down_burst = 0;
		} else {
			ret = r;
		}
	}

	if (vpphook_data->vpppolicer_up) {
		vpppolicer_format_name(policer_input, sizeof(policer_input), ifindex, vpphook_data->vpppolicer_up, vpphook_data->vpppolicer_up_burst, 1);

		/*
		 * Disable all feature arcs BEFORE clearing the policer index and
		 * deleting the policer object.
		 *
		 * Bug: the previous order was:
		 *   1. set_input(0)  -> sets policer_index_by_sw_if_index[RX][sw_if] = ~0
		 *                       + disables policer-input on device-input arc
		 *   2. add_del(0)    -> frees the policer from the VPP pool  <-- too early
		 *   3. set_feature(0, "ip4-unicast") ... etc.                <-- too late
		 *
		 * Between steps 2 and 3, packets traversing the ip4/ip6-unicast/multicast
		 * arcs still hit the policer-input node. That node reads
		 * policer_index_by_sw_if_index[RX][sw_if] = ~0 and passes ~0 directly to
		 * vnet_policer_police(), which does &pm->policers[~0] -- an out-of-bounds
		 * pool access that crashes the VPP worker thread.
		 *
		 * Correct order: disable every arc first, then clear the index, then free.
		 *
		 * VPP's policer_input() API disables device-input + ip4-unicast +
		 * ip6-unicast (matching the enable path), so only the multicast arcs
		 * need to be disabled manually here.
		 */
		vpppoe_set_feature(gen, ifindex, 0, "policer-input", "ip4-multicast");
		vpppoe_set_feature(gen, ifindex, 0, "policer-input", "ip6-multicast");

		vpppolicer_set_input(gen, 0, ifindex, policer_input);
		r = vpppolicer_del_name(gen, policer_input);
		if (r == 0) {
			vpphook_data->vpppolicer_up = 0;
			vpphook_data->vpppolicer_up_burst = 0;
		} else if (!ret) {
			ret = r;
		}
	}

	return ret;
}

/*
 * Names of the policers that vpppolicer_remove_limiter() could not remove,
 * for the deferred cleanup (vpphooks.c); the session forgets them. Returns
 * how many names were written (0 to 2).
 */
int vpppolicer_leftover(struct ap_session *ses, uint32_t ifindex, char names[2][POLICER_NAME_MAX_LEN])
{
	struct vpphook_private_data_t *vpphook_data = vpphook_get_pd(ses);
	int n = 0;

	if (!vpphook_data)
		return 0;

	if (vpphook_data->vpppolicer_down) {
		vpppolicer_format_name(names[n++], POLICER_NAME_MAX_LEN, ifindex, vpphook_data->vpppolicer_down, vpphook_data->vpppolicer_down_burst, 0);
		vpphook_data->vpppolicer_down = 0;
		vpphook_data->vpppolicer_down_burst = 0;
	}

	if (vpphook_data->vpppolicer_up) {
		vpppolicer_format_name(names[n++], POLICER_NAME_MAX_LEN, ifindex, vpphook_data->vpppolicer_up, vpphook_data->vpppolicer_up_burst, 1);
		vpphook_data->vpppolicer_up = 0;
		vpphook_data->vpppolicer_up_burst = 0;
	}

	return n;
}

static uint32_t vpppolicer_parse_action(const char *opt)
{
	uint32_t ret = SSE2_QOS_ACTION_API_DROP;

	if (!strncmp(opt, "transmit", sizeof("transmit") - 1)) {
		ret = SSE2_QOS_ACTION_API_TRANSMIT;
	} /* TODO: add transmit and mark? */

	return ret;
}

static void vpppolicer_load_config(void)
{
	char *opt;

	opt = conf_get_opt("shaper", "vpp-policer-type");
	if (opt) {
		s_conform_action = SSE2_QOS_ACTION_API_TRANSMIT;
		s_exceed_action = SSE2_QOS_ACTION_API_DROP;
		s_violate_action = SSE2_QOS_ACTION_API_DROP;

		s_cir_factor = 1;
		s_cb_factor = 1;
		s_eir_factor = 0;
		s_eb_factor = 0;

		if (!strncmp(opt, "1r2c", sizeof("1r2c") - 1)) {
			s_vpp_policer_type = SSE2_QOS_POLICER_TYPE_API_1R2C;
		} else if (!strncmp(opt, "1r3c", sizeof("1r3c") - 1)) {
			s_vpp_policer_type = SSE2_QOS_POLICER_TYPE_API_1R3C_RFC_2697;
			s_cb_factor = 0.8;
			s_eb_factor = 0.2;
		} else if (!strncmp(opt, "2r3c", sizeof("2r3c") - 1)) {
			s_vpp_policer_type = SSE2_QOS_POLICER_TYPE_API_2R3C_RFC_2698;
			s_cir_factor = 0.8;
			s_eir_factor = 1;
			s_eb_factor = 0.2;
			s_exceed_action = SSE2_QOS_ACTION_API_TRANSMIT;
		}
	}

	opt = conf_get_opt("shaper", "vpp-cir-factor");
	if (opt)
		s_cir_factor = atof(opt);

	opt = conf_get_opt("shaper", "vpp-cb-factor");
	if (opt)
		s_cb_factor = atof(opt);

	opt = conf_get_opt("shaper", "vpp-eir-factor");
	if (opt)
		s_eir_factor = atof(opt);

	opt = conf_get_opt("shaper", "vpp-eb-factor");
	if (opt)
		s_eb_factor = atof(opt);

	opt = conf_get_opt("shaper", "vpp-conform-action");
	if (opt)
		s_conform_action = vpppolicer_parse_action(opt);

	opt = conf_get_opt("shaper", "vpp-exceed-action");
	if (opt)
		s_exceed_action = vpppolicer_parse_action(opt);

	opt = conf_get_opt("shaper", "vpp-violate-action");
	if (opt)
		s_violate_action = vpppolicer_parse_action(opt);

	/* Per-type constraints override generic factor opts (1R2C rejects EIR/EB). */
	switch (s_vpp_policer_type) {
	case SSE2_QOS_POLICER_TYPE_API_1R2C:
		s_eir_factor = 0;
		s_eb_factor = 0;
		break;
	case SSE2_QOS_POLICER_TYPE_API_1R3C_RFC_2697:
		s_eir_factor = 0;
		break;
	default:
		break;
	}
}

static void vpppolicer_init()
{
	vpppolicer_load_config();

	triton_event_register_handler(EV_CONFIG_RELOAD, (triton_event_func)vpppolicer_load_config);
}

DEFINE_INIT(50, vpppolicer_init);
