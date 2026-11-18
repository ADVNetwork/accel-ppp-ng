/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
*/

#ifndef VPPIPUTILS_H
#define VPPIPUTILS_H

#include <stdint.h>
#include <netinet/in.h>

struct ap_session;

/*
 * Add or delete a route through the session interface. An add fails when the
 * session has no interface in the VPP that runs now; a delete then only
 * drops the saved entry and its kernel copy, VPP has nothing to remove.
 */
int vpp_iproute_add_del(struct ap_session *ses, int is_add, in_addr_t dst, int mask);
int vpp_ip6route_add_del(struct ap_session *ses, int is_add, const struct in6_addr *dst, int pref_len);

/* ip_route_lookup for dst/32 in fib0, in the VPP of generation gen.
 * Returns 1 if route present, 0 if lookup ok and route absent,
 * -1 if VAPI/lookup failed or VPP is of another generation (inconclusive —
 * do not treat as missing). */
int vpp_ip4_host_route_present(uint32_t gen, in_addr_t dst);

/* ip_route_lookup for dst/prefix_len in fib0. Same return convention as v4. */
int vpp_ip6_prefix_route_present(uint32_t gen, const struct in6_addr *dst, int prefix_len);

/* A route through a session interface, by its address family and prefix. */
struct vpp_route_key {
	int af;
	int len;
	uint8_t dst[16];
};

/* Remove the routes of the session from VPP, through ifindex of the VPP of
 * generation gen, and forget them. With live == 0 (no interface, or one of a
 * VPP that restarted) VPP is not touched: only the saved entries and their
 * kernel copies go.
 *
 * Returns how many deletes got no answer from VPP; those routes are handed
 * to the caller in *left (malloc, caller frees), to be tried again with
 * vpp_route_del(). */
int vpp_iproute_flush(struct ap_session *ses, int live, uint32_t gen, uint32_t ifindex,
		      struct vpp_route_key **left);

/* Delete the path of a route through ifindex in the VPP of generation gen. */
int vpp_route_del(uint32_t gen, uint32_t ifindex, const struct vpp_route_key *key);

/* add/remove the kernel copies of the session routes per [vpp-route-export];
 * runs in the session context */
void vpp_iproute_kernel_sync(struct ap_session *ses);

/* drop the saved routes (and their kernel copies) without touching VPP;
 * for a session freed without pppoe_terminate */
void vpp_iproute_forget(struct ap_session *ses);

#endif /* VPPIPUTILS_H */