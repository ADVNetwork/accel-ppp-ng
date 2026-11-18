/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
*/

#ifndef VPPPOE_H
#define VPPPOE_H

#include <stdint.h>
#include <netinet/in.h>

/*
 * Session-scoped calls take the generation of the VPP process that made the
 * session interface (vpputils.h) and fail, without touching VPP, when the
 * VPP that answers is another one. The add returns the generation and the
 * pid of the VPP that made the interface.
 */
int vpppoe_sync_add_pppoe_interface(uint8_t *client_mac, uint16_t session_id,
				    in_addr_t client_ip, uint32_t *sw_ifindex,
				    uint32_t *gen, uint32_t *pid);
int vpppoe_sync_del_pppoe_interface(uint32_t gen, uint8_t *client_mac, uint16_t session_id,
				    in_addr_t client_ip);
int vpppoe_set_feature(uint32_t gen, uint32_t ifindex, int is_enabled, const char *feature,
		       const char *arc);
/* 0 = name holds the name VPP gives to ifindex */
int vpppoe_dump_interface_name(uint32_t gen, uint32_t ifindex, char *name, size_t size);
/* L3 MTU of the interface; the per-protocol MTUs follow it */
int vpppoe_set_mtu(uint32_t gen, uint32_t ifindex, uint32_t mtu);

#endif /* VPPPOE_H */