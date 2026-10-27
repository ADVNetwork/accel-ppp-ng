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

void vpp_lock();
void vpp_unlock();

/* export symbols */
int vpp_get();
void vpp_put();

struct vpp_vapi_reply_ctx {
	int32_t api_retval;
	uint32_t *sw_if_index;
};

int vpp_vapi_errno(vapi_error_e err, const struct vpp_vapi_reply_ctx *ctx);

/* vnet/error.h: VNET_API_ERROR_NO_SUCH_ENTRY */
#define VPP_API_ERR_NO_SUCH_ENTRY (-6)

#endif /* VPPUTILS_H */
