/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 */

#ifndef VPPSTATS_H
#define VPPSTATS_H

#include <stdint.h>
#include <stddef.h>

struct ap_session;
struct rtnl_link_stats64;

/* Counters of the session interface; -1 when they cannot be read now. */
int vpphook_read_stats(struct ap_session *ses, struct rtnl_link_stats64 *stats);

/*
 * Counters of sw_if_index in the VPP process vpp_pid. -1 when the stat
 * segment of that process is not available or could not be read.
 */
int vpp_stats_read_if(uint32_t vpp_pid, uint32_t sw_if_index, struct rtnl_link_stats64 *stats);

/*
 * Names of every interface of the VPP the API is connected to, hidden ones
 * included (stat segment /if/names); -1 if the stat segment could not be
 * read. cb runs after the read is over, with no lock held.
 */
int vpphook_stats_if_names(void (*cb)(uint32_t sw_if_index, const char *name, void *arg), void *arg);

/*
 * Unmap the stat segment now. Called when the VPP process exits and when the
 * API connection is lost: the segment of a VPP that is gone keeps its
 * hugepages taken while it is mapped. The next read maps it again.
 */
void vpp_stats_drop(void);

#endif /* VPPSTATS_H */
