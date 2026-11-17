/* SPDX-License-Identifier: GPL-2.0-or-later */

#ifndef VPPRECONCILE_H
#define VPPRECONCILE_H

/*
 * Delete from VPP the PPPoE sessions, their API routes in table 0 and the
 * shaper policers left by a previous accel-ppp process. Call with vpp_lock
 * held, on the first connection of the process, before any session of its
 * own exists in VPP.
 *
 * Returns 0 when no PPPoE session is left in VPP, -1 otherwise (dump or
 * delete failed, or the connection was lost).
 */
int vpp_reconcile_orphans(void);

#endif /* VPPRECONCILE_H */
