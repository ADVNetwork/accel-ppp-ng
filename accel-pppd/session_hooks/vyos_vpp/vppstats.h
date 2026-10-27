/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 */

#ifndef VPPSTATS_H
#define VPPSTATS_H

struct ap_session;
struct rtnl_link_stats64;

int vpphook_read_stats(struct ap_session *ses, struct rtnl_link_stats64 *stats);
int vpphook_stats_batch_set_filter(const uint32_t *if_indices, size_t count);
int vpphook_stats_batch_begin(void);
void vpphook_stats_batch_end(void);

#endif /* VPPSTATS_H */
