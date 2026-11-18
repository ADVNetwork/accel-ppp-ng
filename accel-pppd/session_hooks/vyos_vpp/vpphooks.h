/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#ifndef VPPHOOKS_H
#define VPPHOOKS_H

#include <stdint.h>
#include <pthread.h>

#include "ap_session.h"

#include "list.h"

struct vpphook_private_data_t {
	struct ap_private pd;
	/*
	 * Interface of the session in VPP: ~0 while the session has none.
	 * vpp_gen and vpp_pid name the VPP process that made it (vpputils.h).
	 * Once VPP restarts, the index is nothing in the new process, or the
	 * interface of another subscriber: every use of it goes through
	 * vpphook_live(), and through vpp_get_vapi_gen() under vpp_lock.
	 *
	 * Written by the session context only; the CLI, the watchdog and the
	 * stats readers of other threads read them (atomic loads).
	 */
	uint32_t vpp_sw_if_index;
	uint32_t vpp_gen;
	uint32_t vpp_pid;
	/*
	 * Generation of the VPP that was sent an add of this session and did
	 * not answer (0 = none): it may have made the session all the same.
	 */
	uint32_t vpp_add_gen;
	/* the sweep of a VPP restart already asked this session to end */
	int stale_kill;
	/*
	 * Routes of the session in VPP (vppiputils.c). The session context is
	 * not the only one that touches the list: the route watchdog timer
	 * (vpphooks.c) reinstalls a missing route from its own context. Every
	 * access to the list and to its entries holds vpp_routes_lock.
	 */
	struct list_head vpp_routes;
	pthread_mutex_t vpp_routes_lock;
	uint32_t vpppolicer_down;
	uint64_t vpppolicer_down_burst;
	uint32_t vpppolicer_up;
	uint64_t vpppolicer_up_burst;
};

struct vpphook_private_data_t *vpphook_get_pd(struct ap_session *ses);

/*
 * The interface of the session and the generation it belongs to, when the
 * session has an interface in the VPP process that runs now. NULL when it
 * has none, or when the one it had was made in a VPP that restarted since.
 */
struct vpphook_private_data_t *vpphook_live(struct ap_session *ses, uint32_t *sw_if_index,
					    uint32_t *gen);

/* vpputils.c found a new VPP process behind the API (vpp_lock held). */
void vpphook_vpp_restarted(void);

/*
 * A session is making a policer with this name in the VPP of generation
 * gen: the deferred cleanup must not take it for a leftover.
 */
void vpphook_deferred_forget_policer(uint32_t gen, const char *name);

#endif /* VPPHOOKS_H */