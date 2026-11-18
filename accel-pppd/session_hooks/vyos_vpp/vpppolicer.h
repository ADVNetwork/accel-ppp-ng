/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 * Andrii Melnychenko a.melnychenko@vyos.io
 */

#ifndef VPPPOLICER_H
#define VPPPOLICER_H

#include <stdint.h>
#include <stddef.h>

struct ap_session;

#define POLICER_NAME_MAX_LEN 64

int vpppolicer_install_limiter(struct ap_session *ses, int down_speed, int down_burst, int up_speed, int up_burst);
int vpppolicer_remove_limiter(struct ap_session *ses);

/* names of the policers the last remove left in VPP; the session forgets them */
int vpppolicer_leftover(struct ap_session *ses, uint32_t ifindex, char names[2][POLICER_NAME_MAX_LEN]);
/* delete a policer by name in the VPP of generation gen; 0 also when it is not there */
int vpppolicer_del_name(uint32_t gen, const char *policer_name);

#endif /* VPPPOLICER_H */
