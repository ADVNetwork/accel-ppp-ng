/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Kernel copy of VPP PPPoE session routes ([vpp-route-export] section).
 *
 * Session routes only exist in the VPP FIB. So that FRR can advertise them
 * (redistribute kernel), accel installs a copy of every session route covered
 * by the configured networks on a Linux dummy interface that has no linux-cp
 * pair, so nothing of it is synced back into VPP.
 */

#ifndef VPPKROUTE_H
#define VPPKROUTE_H

#include <netinet/in.h>

/*
 * Returns the dummy ifindex if af/dst/len is covered by a configured network,
 * or 0 if the route must not go to the kernel (feature off or not covered).
 */
int vpp_kroute_lookup(int af, const void *dst, int len);

/*
 * Take/release the kernel copy of the route on dummy ifindex. 0 = ok.
 * Counted by holder: the first add installs the kernel route, the last del
 * removes it, so sessions that hold the same prefix share one route. Call
 * del once for every add that returned 0, with the same ifindex.
 */
int vpp_kroute_add(int ifindex, int af, const void *dst, int len);
int vpp_kroute_del(int ifindex, int af, const void *dst, int len);

#endif /* VPPKROUTE_H */
