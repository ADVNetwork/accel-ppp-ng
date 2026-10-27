/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright (c) 2025 by VyOS Networks
 */

#include <linux/if_link.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/inotify.h>
#include <poll.h>
#include <fcntl.h>

#include <vpp-api/client/stat_client.h>
#include <vppinfra/types.h>
#include <vppinfra/vec.h>

#include "triton.h"
#include "vpphooks.h"
#include "vppstats.h"
#include "log.h"
#include "memdebug.h"

/* Maximum cache size: 1M entries = ~32MB max memory usage */
#define MAX_VPP_STATS_CACHE_SIZE (1024 * 1024)
/*
 * Sanity limit for sw_if_index to prevent excessive memory allocation.
 * VPP typically uses sequential interface indices, so if we see indices
 * above this threshold, something is likely wrong or the VPP instance
 * has been running for a very long time without recycling IDs.
 * At 100K indices, we'd allocate ~3.2MB for the cache array.
 */
#define MAX_SANE_SW_IF_INDEX (100 * 1000)

static pthread_mutex_t vpp_stats_lock = PTHREAD_MUTEX_INITIALIZER;
static int vpp_stats_connected;
static pthread_rwlock_t vpp_stats_cache_lock = PTHREAD_RWLOCK_INITIALIZER;
static int vpp_stats_batch_active;  /* Changed from __thread to global - protected by vpp_stats_cache_lock */
static uint32_t *vpp_stats_filter;
static size_t vpp_stats_filter_len;
/* Serializes the batch begin/end pair: prevents two concurrent CLI commands
 * from corrupting each other's cache snapshot. Held from stats_batch_begin
 * until stats_batch_end. */
static pthread_mutex_t vpp_stats_batch_mutex = PTHREAD_MUTEX_INITIALIZER;

/*
 * Cached result of stat_segment_ls() for the four standard interface counters.
 * Protected by vpp_stats_lock. Populated once per VPP connection; cleared on
 * disconnect. Eliminates per-session regex (regexec via stat_segment_ls_r) from
 * the hot disconnect path: with N sessions terminating, this reduces the cost
 * from N×stat_segment_ls() to a single call.
 */
static u32 *vpp_stats_if_dir = NULL;

/*
 * Short-lived cache of the last stat_segment_dump() result.
 * Protected by vpp_stats_lock.
 *
 * During mass disconnect (e.g. 4000 sessions terminating within milliseconds),
 * every session calls vpp_stats_read_interface() individually. Without caching,
 * this causes N×stat_segment_dump() calls, each of which requires VPP worker
 * threads to synchronize hardware counters — the source of the 14% CPU shown
 * by vlib_worker_thread_fn in perf top.
 *
 * A 200ms TTL is safe because: (a) the stats are used for final RADIUS
 * accounting, where sub-second accuracy is sufficient; (b) the session is
 * already in the terminating state, so no new traffic is expected.
 */
static stat_segment_data_t *vpp_stats_dump_res = NULL;
static struct timespec vpp_stats_dump_res_ts;
#define VPP_STATS_DUMP_TTL_MS 200

struct vpp_stats_cache_entry {
	uint64_t rx_packets;
	uint64_t tx_packets;
	uint64_t rx_bytes;
	uint64_t tx_bytes;
};

static struct vpp_stats_cache_entry *vpp_stats_cache;
static size_t vpp_stats_cache_len;
static int vpp_stats_cache_valid;

/* inotify for detecting VPP restart (socket file deletion) */
static int vpp_stats_inotify_fd = -1;
static int vpp_stats_inotify_wd = -1;
static struct triton_context_t vpp_stats_inotify_ctx;
static struct triton_md_handler_t vpp_stats_inotify_hnd;
static struct triton_timer_t vpp_stats_health_timer;
static char vpp_stats_sock_basename[256] = "stats.sock";  /* fallback */
#define VPP_STATS_HEALTH_CHECK_INTERVAL 30  /* seconds */

static void vpp_stats_inotify_watch(void);
static void vpp_stats_health_check(struct triton_timer_t *t);
static int  vpp_stats_ensure_if_dir(void);

/*
 * Connect to VPP statistics segment socket.
 *
 * THREAD-SAFETY NOTE:
 * This function is called under vpp_stats_lock protection (via vpp_stats_connect).
 * We rely on the VPP stat_segment_connect() internal timeout mechanisms instead
 * of using alarm()/signals, which are NOT safe in multi-threaded environments.
 *
 * The previous implementation used alarm() + siglongjmp(), which is dangerous
 * in a multi-threaded daemon because:
 * 1. SIGALRM is delivered to the entire process, not just the calling thread
 * 2. Any thread could intercept the signal, causing undefined behavior
 * 3. siglongjmp can bypass mutex unlocks, causing deadlocks
 *
 * If VPP socket connection hangs, it's better to let the VPP client library
 * handle it (it may have internal timeouts) or rely on system socket timeouts
 * rather than introducing unsafe signal handling.
 */
static int vpp_stats_connect_locked(void)
{
	if (vpp_stats_connected)
		return 0;

	/*
	 * Attempt connection to VPP statistics segment.
	 * This call should be non-blocking or have reasonable internal timeouts.
	 * If it blocks indefinitely, that's a VPP API issue that should be
	 * fixed in libvppapiclient, not worked around with unsafe signals.
	 */
	if (stat_segment_connect(STAT_SEGMENT_SOCKET_FILE) != 0) {
		log_error("vpp_stats: failed to connect to VPP stat segment socket %s\n",
		          STAT_SEGMENT_SOCKET_FILE);
		return -1;
	}

	vpp_stats_connected = 1;
	log_debug("vpp_stats: connected to VPP stat segment\n");
	vpp_stats_inotify_watch();
	return 0;
}

static int vpp_stats_connect(void)
{
	int ret;

	pthread_mutex_lock(&vpp_stats_lock);
	ret = vpp_stats_connect_locked();
	pthread_mutex_unlock(&vpp_stats_lock);

	return ret;
}

/*
 * Note: We keep the connection open permanently for better performance.
 * This function is kept for compatibility and potential future use.
 */
static void vpp_stats_disconnect(void)
{
	pthread_mutex_lock(&vpp_stats_lock);
	if (vpp_stats_connected) {
		stat_segment_disconnect();
		vpp_stats_connected = 0;
		log_debug("vpp_stats: disconnected from VPP stat segment\n");
		pthread_rwlock_wrlock(&vpp_stats_cache_lock);
		vpp_stats_cache_valid = 0;
		pthread_rwlock_unlock(&vpp_stats_cache_lock);
	}
	/* Invalidate per-session caches — the shared memory mapping is gone */
	if (vpp_stats_if_dir) {
		vec_free(vpp_stats_if_dir);
		vpp_stats_if_dir = NULL;
	}
	if (vpp_stats_dump_res) {
		stat_segment_data_free(vpp_stats_dump_res);
		vpp_stats_dump_res = NULL;
	}
	pthread_mutex_unlock(&vpp_stats_lock);
}

static int vpp_stats_inotify_read(struct triton_md_handler_t *hnd)
{
	char buf[sizeof(struct inotify_event) + 256];
	ssize_t n;
	struct inotify_event *ev;
	char *p;

	n = read(vpp_stats_inotify_fd, buf, sizeof(buf));
	if (n < (ssize_t)sizeof(struct inotify_event)) {
		if (n < 0 && errno != EAGAIN)
			log_warn("vpp_stats: inotify read error: %s\n", strerror(errno));
		return 0;
	}

	for (p = buf; p < buf + n; p += sizeof(struct inotify_event) + ev->len) {
		ev = (struct inotify_event *)p;
		if (ev->mask & IN_Q_OVERFLOW) {
			log_warn("vpp_stats: inotify queue overflow, disconnecting (may have missed VPP restart)\n");
			vpp_stats_disconnect();
			break;
		}
		if ((ev->mask & IN_DELETE) && ev->len > 0 &&
		    strcmp(ev->name, vpp_stats_sock_basename) == 0) {
			log_debug("vpp_stats: socket removed (VPP restart detected)\n");
			vpp_stats_disconnect();
			break;
		}
	}
	return 0;
}

static void vpp_stats_inotify_watch(void)
{
	char path[256];
	char *last_slash;
	const char *dir;
	int wd;

	if (vpp_stats_inotify_fd < 0 || vpp_stats_inotify_wd >= 0)
		return;

	strncpy(path, STAT_SEGMENT_SOCKET_FILE, sizeof(path) - 1);
	path[sizeof(path) - 1] = '\0';
	last_slash = strrchr(path, '/');
	if (last_slash && last_slash > path) {
		*last_slash = '\0';
		dir = path;
		strncpy(vpp_stats_sock_basename, last_slash + 1, sizeof(vpp_stats_sock_basename) - 1);
		vpp_stats_sock_basename[sizeof(vpp_stats_sock_basename) - 1] = '\0';
	} else {
		dir = ".";
		strncpy(vpp_stats_sock_basename, path, sizeof(vpp_stats_sock_basename) - 1);
		vpp_stats_sock_basename[sizeof(vpp_stats_sock_basename) - 1] = '\0';
	}

	wd = inotify_add_watch(vpp_stats_inotify_fd, dir, IN_DELETE);
	if (wd >= 0) {
		vpp_stats_inotify_wd = wd;
		log_debug("vpp_stats: watching %s for VPP restart\n", path);
	}
}

/*
 * Periodic health check: detect VPP crash without clean socket deletion.
 * If VPP dies (SIGKILL, OOM, etc.) the socket file may remain; inotify
 * won't fire IN_DELETE. A lightweight stat_segment_ls verifies connectivity.
 */
static void vpp_stats_health_check(struct triton_timer_t *t)
{
	u8 **patterns = 0;
	u32 *dir = NULL;

	pthread_mutex_lock(&vpp_stats_lock);
	if (!vpp_stats_connected) {
		pthread_mutex_unlock(&vpp_stats_lock);
		goto reschedule;
	}

	vec_add1(patterns, (u8 *)"/");
	dir = stat_segment_ls(patterns);
	vec_free(patterns);
	pthread_mutex_unlock(&vpp_stats_lock);

	if (!dir) {
		log_warn("vpp_stats: health check failed - VPP may have crashed (socket not removed)\n");
		vpp_stats_disconnect();
		goto reschedule;
	}
	vec_free(dir);

reschedule:
	vpp_stats_health_timer.expire = vpp_stats_health_check;
	vpp_stats_health_timer.expire_tv.tv_sec = VPP_STATS_HEALTH_CHECK_INTERVAL;
	triton_timer_mod(&vpp_stats_health_timer, 0);
}

static void vpp_stats_inotify_close(struct triton_context_t *ctx)
{
	triton_timer_del(&vpp_stats_health_timer);
	triton_md_disable_handler(&vpp_stats_inotify_hnd, MD_MODE_READ);
	triton_md_unregister_handler(&vpp_stats_inotify_hnd, 1);
	if (vpp_stats_inotify_fd >= 0) {
		close(vpp_stats_inotify_fd);
		vpp_stats_inotify_fd = -1;
		vpp_stats_inotify_wd = -1;
	}
	triton_context_unregister(ctx);
}

static void vpp_stats_sum_simple(const stat_segment_data_t *data,
				 uint32_t sw_if_index,
				 uint64_t *value)
{
	u32 thread;

	if (!data || data->type != STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE)
		return;

	for (thread = 0; thread < vec_len(data->simple_counter_vec); thread++) {
		if (sw_if_index >= vec_len(data->simple_counter_vec[thread]))
			continue;
		*value += data->simple_counter_vec[thread][sw_if_index];
	}
}

static void vpp_stats_sum_combined(const stat_segment_data_t *data,
				   uint32_t sw_if_index,
				   uint64_t *packets,
				   uint64_t *bytes)
{
	u32 thread;

	if (!data || data->type != STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED)
		return;

	for (thread = 0; thread < vec_len(data->combined_counter_vec); thread++) {
		if (sw_if_index >= vec_len(data->combined_counter_vec[thread]))
			continue;
		*packets += data->combined_counter_vec[thread][sw_if_index].packets;
		*bytes += data->combined_counter_vec[thread][sw_if_index].bytes;
	}
}

static size_t vpp_stats_max_index_simple(const stat_segment_data_t *data)
{
	u32 thread;
	size_t max_len = 0;

	if (!data || data->type != STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE)
		return 0;

	for (thread = 0; thread < vec_len(data->simple_counter_vec); thread++) {
		if (vec_len(data->simple_counter_vec[thread]) > max_len)
			max_len = vec_len(data->simple_counter_vec[thread]);
	}

	return max_len;
}

static size_t vpp_stats_max_index_combined(const stat_segment_data_t *data)
{
	u32 thread;
	size_t max_len = 0;

	if (!data || data->type != STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED)
		return 0;

	for (thread = 0; thread < vec_len(data->combined_counter_vec); thread++) {
		if (vec_len(data->combined_counter_vec[thread]) > max_len)
			max_len = vec_len(data->combined_counter_vec[thread]);
	}

	return max_len;
}

/*
 * Refresh the global statistics cache by querying VPP for all interface counters.
 * This function is called at the start of batch statistics collection.
 *
 * LOCKING STRATEGY:
 * - Acquires vpp_stats_cache_lock (read) to copy filter configuration
 * - Releases lock during VPP API calls (which may take 10-100ms)
 * - Acquires vpp_stats_cache_lock (write) to update the global cache
 *
 * ERROR HANDLING:
 * The filter_locked variable tracks whether we're holding the read lock,
 * ensuring it's always released before returning on error paths.
 *
 * MEMORY ALLOCATION:
 * Allocates a new cache array based on the highest sw_if_index seen.
 * The old cache is freed only after the new one is successfully populated.
 */
static int vpp_stats_cache_refresh(void)
{
	u32 *dir = NULL;
	stat_segment_data_t *res = NULL;
	struct vpp_stats_cache_entry *cache = NULL;
	size_t cache_len = 0;
	uint32_t *filter = NULL;
	size_t filter_len = 0;
	int filter_locked = 0;
	int have_rx_packets = 0;
	int have_tx_packets = 0;
	int have_rx_bytes = 0;
	int have_tx_bytes = 0;
	u32 i;
	struct timespec ts_start, ts_end;
	long long elapsed_ms;

	clock_gettime(CLOCK_MONOTONIC, &ts_start);

	/*
	 * Hold vpp_stats_lock for the entire duration of stat_segment_* usage.
	 * Prevents SIGSEGV: inotify/health_check can call stat_segment_disconnect()
	 * (munmap) while we iterate over res[]. Without this lock, we'd read
	 * unmapped memory and crash.
	 */
	pthread_mutex_lock(&vpp_stats_lock);
	if (!vpp_stats_connected) {
		pthread_mutex_unlock(&vpp_stats_lock);
		return -1;
	}

	/*
	 * Reuse the cached interface directory to avoid another stat_segment_ls()
	 * regex scan. If not yet cached, populate it now (once per connection).
	 */
	if (vpp_stats_ensure_if_dir()) {
		pthread_mutex_unlock(&vpp_stats_lock);
		log_error("vpp_stats: stat_segment_ls failed - VPP may be down or restarting\n");
		vpp_stats_disconnect();
		return -1;
	}
	dir = vpp_stats_if_dir;

	/*
	 * For the batch refresh we always want a fresh dump — do not use the
	 * short-lived per-session dump cache here, since batch mode collects stats
	 * for ALL sessions and accuracy matters more than latency savings.
	 */
	res = stat_segment_dump(dir);
	if (!res) {
		/* dir may be stale; invalidate so next call re-runs stat_segment_ls */
		vec_free(vpp_stats_if_dir);
		vpp_stats_if_dir = NULL;
		pthread_mutex_unlock(&vpp_stats_lock);
		log_error("vpp_stats: stat_segment_dump failed - VPP may be down or restarting\n");
		vpp_stats_disconnect();
		return -1;
	}

	/*
	 * Acquire read lock to safely copy the filter configuration.
	 * We release immediately if no filter is set, or keep it locked
	 * if we need to use the filter during cache population.
	 */
	pthread_rwlock_rdlock(&vpp_stats_cache_lock);
	filter = vpp_stats_filter;
	filter_len = vpp_stats_filter_len;
	if (!filter_len) {
		pthread_rwlock_unlock(&vpp_stats_cache_lock);
		filter_locked = 0;
	} else {
		filter_locked = 1;
	}

	for (i = 0; i < vec_len(res); i++) {
		size_t max_len = 0;

		if (!res[i].name)
			continue;

		if (!strcmp(res[i].name, "/if/rx") || !strcmp(res[i].name, "/if/tx")) {
			max_len = vpp_stats_max_index_combined(&res[i]);
			if (!max_len)
				max_len = vpp_stats_max_index_simple(&res[i]);
		} else if (!strcmp(res[i].name, "/if/rx-bytes") || !strcmp(res[i].name, "/if/tx-bytes")) {
			max_len = vpp_stats_max_index_simple(&res[i]);
		}

		if (max_len > cache_len)
			cache_len = max_len;
	}

	if (!cache_len) {
		if (filter_locked)
			pthread_rwlock_unlock(&vpp_stats_cache_lock);
		stat_segment_data_free(res);
		pthread_mutex_unlock(&vpp_stats_lock);
		return -1;
	}

	if (filter_len) {
		size_t idx;
		cache_len = 0;
		for (idx = 0; idx < filter_len; idx++) {
			if (filter[idx] + 1 > cache_len)
				cache_len = filter[idx] + 1;
		}
	}

	/*
	 * SANITY CHECK: Prevent excessive memory allocation for sparse interface indices.
	 * If VPP generates very high sw_if_index values (e.g., due to not recycling IDs
	 * after many interface create/delete cycles), we could attempt to allocate
	 * hundreds of megabytes of memory for mostly empty cache entries.
	 *
	 * Typical deployments use sequential indices (0, 1, 2, ..., N) where N < 100K.
	 * If we encounter indices beyond this threshold, log a warning and fall back
	 * to non-batch mode for safety.
	 */
	if (cache_len > MAX_SANE_SW_IF_INDEX) {
		log_warn("vpp_stats: refusing to allocate cache for %zu interfaces "
		         "(max_index=%zu, threshold=%d). VPP may not be recycling interface IDs. "
		         "Falling back to non-batch stats collection.\n",
		         cache_len, cache_len - 1, MAX_SANE_SW_IF_INDEX);
		if (filter_locked)
			pthread_rwlock_unlock(&vpp_stats_cache_lock);
		stat_segment_data_free(res);
		pthread_mutex_unlock(&vpp_stats_lock);
		return -1;
	}

	cache = _malloc(cache_len * sizeof(*cache));
	if (!cache) {
		if (filter_locked)
			pthread_rwlock_unlock(&vpp_stats_cache_lock);
		stat_segment_data_free(res);
		pthread_mutex_unlock(&vpp_stats_lock);
		return -1;
	}
	memset(cache, 0, cache_len * sizeof(*cache));

	for (i = 0; i < vec_len(res); i++) {
		if (!res[i].name)
			continue;

		if (!strcmp(res[i].name, "/if/rx")) {
			if (filter_len) {
				size_t idx;
				have_rx_packets = 1;
				if (res[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED)
					have_rx_bytes = 1;
				for (idx = 0; idx < filter_len; idx++) {
					u32 thread;
					u32 sw_if_index = filter[idx];
					if (res[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED) {
						for (thread = 0; thread < vec_len(res[i].combined_counter_vec); thread++) {
							if (sw_if_index >= vec_len(res[i].combined_counter_vec[thread]))
								continue;
							cache[sw_if_index].rx_packets += res[i].combined_counter_vec[thread][sw_if_index].packets;
							cache[sw_if_index].rx_bytes += res[i].combined_counter_vec[thread][sw_if_index].bytes;
						}
					} else if (res[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE) {
						for (thread = 0; thread < vec_len(res[i].simple_counter_vec); thread++) {
							if (sw_if_index >= vec_len(res[i].simple_counter_vec[thread]))
								continue;
							cache[sw_if_index].rx_packets += res[i].simple_counter_vec[thread][sw_if_index];
						}
					}
				}
			} else if (res[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED) {
				u32 thread;
				have_rx_packets = 1;
				have_rx_bytes = 1;
				for (thread = 0; thread < vec_len(res[i].combined_counter_vec); thread++) {
					u32 j;
					for (j = 0; j < vec_len(res[i].combined_counter_vec[thread]); j++) {
						cache[j].rx_packets += res[i].combined_counter_vec[thread][j].packets;
						cache[j].rx_bytes += res[i].combined_counter_vec[thread][j].bytes;
					}
				}
			} else if (res[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE) {
				u32 thread;
				have_rx_packets = 1;
				for (thread = 0; thread < vec_len(res[i].simple_counter_vec); thread++) {
					u32 j;
					for (j = 0; j < vec_len(res[i].simple_counter_vec[thread]); j++)
						cache[j].rx_packets += res[i].simple_counter_vec[thread][j];
				}
			}
			continue;
		}

		if (!strcmp(res[i].name, "/if/tx")) {
			if (filter_len) {
				size_t idx;
				have_tx_packets = 1;
				if (res[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED)
					have_tx_bytes = 1;
				for (idx = 0; idx < filter_len; idx++) {
					u32 thread;
					u32 sw_if_index = filter[idx];
					if (res[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED) {
						for (thread = 0; thread < vec_len(res[i].combined_counter_vec); thread++) {
							if (sw_if_index >= vec_len(res[i].combined_counter_vec[thread]))
								continue;
							cache[sw_if_index].tx_packets += res[i].combined_counter_vec[thread][sw_if_index].packets;
							cache[sw_if_index].tx_bytes += res[i].combined_counter_vec[thread][sw_if_index].bytes;
						}
					} else if (res[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE) {
						for (thread = 0; thread < vec_len(res[i].simple_counter_vec); thread++) {
							if (sw_if_index >= vec_len(res[i].simple_counter_vec[thread]))
								continue;
							cache[sw_if_index].tx_packets += res[i].simple_counter_vec[thread][sw_if_index];
						}
					}
				}
			} else if (res[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED) {
				u32 thread;
				have_tx_packets = 1;
				have_tx_bytes = 1;
				for (thread = 0; thread < vec_len(res[i].combined_counter_vec); thread++) {
					u32 j;
					for (j = 0; j < vec_len(res[i].combined_counter_vec[thread]); j++) {
						cache[j].tx_packets += res[i].combined_counter_vec[thread][j].packets;
						cache[j].tx_bytes += res[i].combined_counter_vec[thread][j].bytes;
					}
				}
			} else if (res[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE) {
				u32 thread;
				have_tx_packets = 1;
				for (thread = 0; thread < vec_len(res[i].simple_counter_vec); thread++) {
					u32 j;
					for (j = 0; j < vec_len(res[i].simple_counter_vec[thread]); j++)
						cache[j].tx_packets += res[i].simple_counter_vec[thread][j];
				}
			}
			continue;
		}

		if (!strcmp(res[i].name, "/if/rx-bytes")) {
			u32 thread;
			have_rx_bytes = 1;
			if (filter_len) {
				size_t idx;
				for (idx = 0; idx < filter_len; idx++) {
					u32 sw_if_index = filter[idx];
					for (thread = 0; thread < vec_len(res[i].simple_counter_vec); thread++) {
						if (sw_if_index >= vec_len(res[i].simple_counter_vec[thread]))
							continue;
						cache[sw_if_index].rx_bytes += res[i].simple_counter_vec[thread][sw_if_index];
					}
				}
			} else {
				for (thread = 0; thread < vec_len(res[i].simple_counter_vec); thread++) {
					u32 j;
					for (j = 0; j < vec_len(res[i].simple_counter_vec[thread]); j++)
						cache[j].rx_bytes += res[i].simple_counter_vec[thread][j];
				}
			}
			continue;
		}

		if (!strcmp(res[i].name, "/if/tx-bytes")) {
			u32 thread;
			have_tx_bytes = 1;
			if (filter_len) {
				size_t idx;
				for (idx = 0; idx < filter_len; idx++) {
					u32 sw_if_index = filter[idx];
					for (thread = 0; thread < vec_len(res[i].simple_counter_vec); thread++) {
						if (sw_if_index >= vec_len(res[i].simple_counter_vec[thread]))
							continue;
						cache[sw_if_index].tx_bytes += res[i].simple_counter_vec[thread][sw_if_index];
					}
				}
			} else {
				for (thread = 0; thread < vec_len(res[i].simple_counter_vec); thread++) {
					u32 j;
					for (j = 0; j < vec_len(res[i].simple_counter_vec[thread]); j++)
						cache[j].tx_bytes += res[i].simple_counter_vec[thread][j];
				}
			}
			continue;
		}
	}

	/*
	 * Release filter lock if we were holding it.
	 * We're done reading filter values during cache population.
	 */
	if (filter_locked) {
		pthread_rwlock_unlock(&vpp_stats_cache_lock);
		filter_locked = 0;
	}

	stat_segment_data_free(res);
	pthread_mutex_unlock(&vpp_stats_lock);

	/*
	 * Verify we got all required counter types from VPP.
	 * If any are missing, VPP may be in an inconsistent state.
	 */
	if (!have_rx_packets || !have_tx_packets || !have_rx_bytes || !have_tx_bytes) {
		log_error("vpp_stats: incomplete statistics from VPP (rx_pkt=%d tx_pkt=%d rx_bytes=%d tx_bytes=%d)\n",
		          have_rx_packets, have_tx_packets, have_rx_bytes, have_tx_bytes);
		_free(cache);
		return -1;
	}

	/*
	 * Atomically swap the old cache with the new one.
	 * This ensures readers using vpp_stats_cache_get() always see
	 * either fully valid old data or fully valid new data.
	 */
	pthread_rwlock_wrlock(&vpp_stats_cache_lock);
	if (vpp_stats_cache)
		_free(vpp_stats_cache);
	vpp_stats_cache = cache;
	vpp_stats_cache_len = cache_len;
	vpp_stats_cache_valid = 1;
	pthread_rwlock_unlock(&vpp_stats_cache_lock);

	clock_gettime(CLOCK_MONOTONIC, &ts_end);
	elapsed_ms = (ts_end.tv_sec - ts_start.tv_sec) * 1000LL;
	elapsed_ms += (ts_end.tv_nsec - ts_start.tv_nsec) / 1000000LL;

	log_debug("vpp_stats: cache refresh completed in %lld ms (cache_len=%zu, filter_len=%zu)\n",
	          elapsed_ms, cache_len, filter_len);

	return 0;
}

static int vpp_stats_cache_get(uint32_t sw_if_index, struct rtnl_link_stats64 *stats)
{
	int ret = -1;

	pthread_rwlock_rdlock(&vpp_stats_cache_lock);
	if (vpp_stats_cache_valid && sw_if_index < vpp_stats_cache_len) {
		memset(stats, 0, sizeof(*stats));
		stats->rx_packets = vpp_stats_cache[sw_if_index].rx_packets;
		stats->tx_packets = vpp_stats_cache[sw_if_index].tx_packets;
		stats->rx_bytes = vpp_stats_cache[sw_if_index].rx_bytes;
		stats->tx_bytes = vpp_stats_cache[sw_if_index].tx_bytes;
		ret = 0;
	}
	pthread_rwlock_unlock(&vpp_stats_cache_lock);

	return ret;
}

/*
 * Populate vpp_stats_if_dir if not already cached.
 * Must be called under vpp_stats_lock.
 * Returns 0 on success, -1 on failure.
 */
static int vpp_stats_ensure_if_dir(void)
{
	u8 **patterns = 0;
	u32 *dir;

	if (vpp_stats_if_dir)
		return 0;

	vec_add1(patterns, (u8 *)"/if/rx");
	vec_add1(patterns, (u8 *)"/if/tx");
	vec_add1(patterns, (u8 *)"/if/rx-bytes");
	vec_add1(patterns, (u8 *)"/if/tx-bytes");
	dir = stat_segment_ls(patterns);
	vec_free(patterns);

	if (!dir)
		return -1;

	vpp_stats_if_dir = dir;
	return 0;
}

static int vpp_stats_read_interface(uint32_t sw_if_index, struct rtnl_link_stats64 *stats)
{
	stat_segment_data_t *res = NULL;
	uint64_t rx_packets = 0;
	uint64_t tx_packets = 0;
	uint64_t rx_bytes = 0;
	uint64_t tx_bytes = 0;
	int have_rx_packets = 0;
	int have_tx_packets = 0;
	int have_rx_bytes = 0;
	int have_tx_bytes = 0;
	u32 i;

	pthread_mutex_lock(&vpp_stats_lock);
	if (!vpp_stats_connected) {
		pthread_mutex_unlock(&vpp_stats_lock);
		return -1;
	}

	/*
	 * Get cached directory (avoids per-session regex via stat_segment_ls_r).
	 * vpp_stats_if_dir is populated once per VPP connection and reused for
	 * every subsequent call, eliminating the dominant regexec overhead.
	 */
	if (vpp_stats_ensure_if_dir()) {
		pthread_mutex_unlock(&vpp_stats_lock);
		vpp_stats_disconnect();
		return -1;
	}

	/*
	 * Reuse a recent dump if it's within the TTL window.
	 * During mass disconnect all sessions terminate within milliseconds of
	 * each other; sharing one dump result reduces N×dump() to ~1 call and
	 * eliminates the VPP worker-thread synchronization bottleneck.
	 */
	if (vpp_stats_dump_res) {
		struct timespec now;
		long long age_ms;

		clock_gettime(CLOCK_MONOTONIC, &now);
		age_ms = (now.tv_sec - vpp_stats_dump_res_ts.tv_sec) * 1000LL +
		         (now.tv_nsec - vpp_stats_dump_res_ts.tv_nsec) / 1000000LL;
		if (age_ms >= VPP_STATS_DUMP_TTL_MS) {
			stat_segment_data_free(vpp_stats_dump_res);
			vpp_stats_dump_res = NULL;
		}
	}

	if (!vpp_stats_dump_res) {
		vpp_stats_dump_res = stat_segment_dump(vpp_stats_if_dir);
		if (!vpp_stats_dump_res) {
			/*
			 * Dump failed; the cached dir may be stale (e.g. VPP
			 * restarted without a clean socket deletion). Invalidate
			 * the dir so the next call rebuilds it via stat_segment_ls.
			 */
			vec_free(vpp_stats_if_dir);
			vpp_stats_if_dir = NULL;
			pthread_mutex_unlock(&vpp_stats_lock);
			vpp_stats_disconnect();
			return -1;
		}
		clock_gettime(CLOCK_MONOTONIC, &vpp_stats_dump_res_ts);
	}
	res = vpp_stats_dump_res;

	for (i = 0; i < vec_len(res); i++) {
		if (!res[i].name)
			continue;

		if (!strcmp(res[i].name, "/if/rx")) {
			if (res[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED) {
				vpp_stats_sum_combined(&res[i], sw_if_index, &rx_packets, &rx_bytes);
				have_rx_packets = 1;
				have_rx_bytes = 1;
			} else if (res[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE) {
				vpp_stats_sum_simple(&res[i], sw_if_index, &rx_packets);
				have_rx_packets = 1;
			}
			continue;
		}

		if (!strcmp(res[i].name, "/if/tx")) {
			if (res[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED) {
				vpp_stats_sum_combined(&res[i], sw_if_index, &tx_packets, &tx_bytes);
				have_tx_packets = 1;
				have_tx_bytes = 1;
			} else if (res[i].type == STAT_DIR_TYPE_COUNTER_VECTOR_SIMPLE) {
				vpp_stats_sum_simple(&res[i], sw_if_index, &tx_packets);
				have_tx_packets = 1;
			}
			continue;
		}

		if (!strcmp(res[i].name, "/if/rx-bytes")) {
			vpp_stats_sum_simple(&res[i], sw_if_index, &rx_bytes);
			have_rx_bytes = 1;
			continue;
		}

		if (!strcmp(res[i].name, "/if/tx-bytes")) {
			vpp_stats_sum_simple(&res[i], sw_if_index, &tx_bytes);
			have_tx_bytes = 1;
			continue;
		}
	}

	/* Do NOT free res here — it is owned by vpp_stats_dump_res cache */
	pthread_mutex_unlock(&vpp_stats_lock);

	if (!have_rx_packets || !have_tx_packets || !have_rx_bytes || !have_tx_bytes)
		return -1;

	memset(stats, 0, sizeof(*stats));
	stats->rx_packets = rx_packets;
	stats->tx_packets = tx_packets;
	stats->rx_bytes = rx_bytes;
	stats->tx_bytes = tx_bytes;

	return 0;
}

int vpphook_read_stats(struct ap_session *ses, struct rtnl_link_stats64 *stats)
{
	struct vpphook_private_data_t *pd;
	int batch_active;

	if (!ses || !stats)
		return -1;

	pd = vpphook_get_pd(ses);
	if (!pd)
		return -1;

	/* Check if batch mode is active (thread-safe read) */
	pthread_rwlock_rdlock(&vpp_stats_cache_lock);
	batch_active = vpp_stats_batch_active;
	pthread_rwlock_unlock(&vpp_stats_cache_lock);

	if (batch_active) {
		if (!vpp_stats_cache_get(pd->vpp_sw_if_index, stats))
			return 0;
		/* Session's sw_if_index outside cache (e.g. new clients after batch start).
		 * Return zeros instead of blocking with per-session IPC - avoids holding
		 * ses_lock for seconds during "show sessions" and freezing the BNG. */
		memset(stats, 0, sizeof(*stats));
		return 0;
	}

	/*
	 * Connect once and keep the connection open for all subsequent queries.
	 * This eliminates reconnection overhead when querying stats for multiple
	 * sessions. The connection is maintained indefinitely since stats queries
	 * are frequent (CLI commands, radius accounting, etc).
	 *
	 * Performance impact:
	 * - Before: 30 sessions × (connect + dump + disconnect) = ~5-15 seconds
	 * - After:  1 connect + 30 dumps = ~50-200ms
	 */
	if (vpp_stats_connect())
		return -1;

	return vpp_stats_read_interface(pd->vpp_sw_if_index, stats);
}

int vpphook_stats_batch_set_filter(const uint32_t *if_indices, size_t count)
{
	uint32_t *copy = NULL;

	if (count) {
		copy = _malloc(count * sizeof(*copy));
		if (!copy)
			return -1;
		memcpy(copy, if_indices, count * sizeof(*copy));
	}

	pthread_rwlock_wrlock(&vpp_stats_cache_lock);
	if (vpp_stats_filter)
		_free(vpp_stats_filter);
	vpp_stats_filter = copy;
	vpp_stats_filter_len = count;
	pthread_rwlock_unlock(&vpp_stats_cache_lock);

	return 0;
}

int vpphook_stats_batch_begin(void)
{
	int ret;

	/* Acquire batch mutex before any state changes.
	 * Released by vpphook_stats_batch_end() or on error paths below. */
	pthread_mutex_lock(&vpp_stats_batch_mutex);

	if (vpp_stats_connect()) {
		pthread_mutex_unlock(&vpp_stats_batch_mutex);
		return -1;
	}

	/*
	 * Invalidate cache and reset batch mode flag BEFORE attempting refresh.
	 * This ensures we never serve stale data if refresh fails.
	 */
	pthread_rwlock_wrlock(&vpp_stats_cache_lock);
	vpp_stats_cache_valid = 0;
	vpp_stats_batch_active = 0;
	pthread_rwlock_unlock(&vpp_stats_cache_lock);

	/*
	 * Attempt to refresh the cache with current VPP statistics.
	 * If this fails (e.g., due to VPP being down, excessive indices, or
	 * memory allocation failure), we remain in non-batch mode.
	 */
	ret = vpp_stats_cache_refresh();
	if (ret != 0) {
		log_error("vpp_stats: batch mode initialization failed, "
		          "falling back to per-session stats collection\n");
		pthread_mutex_unlock(&vpp_stats_batch_mutex);
		return -1;
	}

	/*
	 * Cache refresh succeeded - activate batch mode.
	 * All subsequent vpphook_read_stats() calls will use the cached data
	 * until vpphook_stats_batch_end() is called.
	 */
	pthread_rwlock_wrlock(&vpp_stats_cache_lock);
	vpp_stats_batch_active = 1;
	pthread_rwlock_unlock(&vpp_stats_cache_lock);

	return 0;
}

void vpphook_stats_batch_end(void)
{
	/*
	 * Deactivate batch mode. Subsequent stats queries will fall back to
	 * individual per-session collection via vpp_stats_read_interface().
	 * The cache remains allocated but marked invalid until the next batch begin.
	 */
	pthread_rwlock_wrlock(&vpp_stats_cache_lock);
	vpp_stats_batch_active = 0;
	vpp_stats_cache_valid = 0;  /* Mark cache invalid for safety */
	pthread_rwlock_unlock(&vpp_stats_cache_lock);
	/* Release the batch mutex acquired in vpphook_stats_batch_begin,
	 * allowing the next CLI command to start a new batch. */
	pthread_mutex_unlock(&vpp_stats_batch_mutex);
}

static void vpp_stats_inotify_init(void)
{
	vpp_stats_inotify_fd = inotify_init1(IN_NONBLOCK | IN_CLOEXEC);
	if (vpp_stats_inotify_fd < 0) {
		log_warn("vpp_stats: inotify_init failed, VPP restart detection disabled\n");
		return;
	}

	memset(&vpp_stats_inotify_ctx, 0, sizeof(vpp_stats_inotify_ctx));
	memset(&vpp_stats_inotify_hnd, 0, sizeof(vpp_stats_inotify_hnd));
	memset(&vpp_stats_health_timer, 0, sizeof(vpp_stats_health_timer));
	vpp_stats_inotify_ctx.close = vpp_stats_inotify_close;
	triton_context_register(&vpp_stats_inotify_ctx, NULL);
	vpp_stats_inotify_hnd.fd = vpp_stats_inotify_fd;
	vpp_stats_inotify_hnd.read = vpp_stats_inotify_read;
	triton_md_register_handler(&vpp_stats_inotify_ctx, &vpp_stats_inotify_hnd);
	triton_md_enable_handler(&vpp_stats_inotify_hnd, MD_MODE_READ);
	vpp_stats_health_timer.expire = vpp_stats_health_check;
	vpp_stats_health_timer.expire_tv.tv_sec = VPP_STATS_HEALTH_CHECK_INTERVAL;
	triton_timer_add(&vpp_stats_inotify_ctx, &vpp_stats_health_timer, 0);
	triton_context_wakeup(&vpp_stats_inotify_ctx);
}

DEFINE_INIT(19, vpp_stats_inotify_init);
