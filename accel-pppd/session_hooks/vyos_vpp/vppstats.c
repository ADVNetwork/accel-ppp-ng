/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Interface counters and names from the VPP stat segment.
 *
 * VPP publishes its counters in a shared memory segment that clients map
 * read-only. A writer in VPP sets in_progress, changes the segment, bumps the
 * epoch and clears in_progress; a reader takes no lock, reads, and at the end
 * checks that the epoch did not move. Until that check, everything the reader
 * saw may be half-written or already freed: the directory vector and the
 * counter vectors are moved by VPP whenever they grow (a new interface, a new
 * graph node, a new thread).
 *
 * The VPP client library (stat_client.c) walks those vectors trusting the
 * lengths and pointers it finds, and only then checks the epoch. A vector
 * moved under it leaves a garbage length, and the walk runs off the end of
 * the mapping: accel-pppd died like that in stat_segment_ls_r() while
 * thousands of sessions came up on a freshly started VPP, every one of them
 * a new interface. This file does not use that library. It maps the segment
 * itself and:
 *
 *  - never follows a pointer or a length read from the segment without
 *    checking that the whole object is inside the mapping. A torn read gives
 *    a wrong number at worst, and the epoch check throws it away;
 *  - reads only what it needs: two counters per thread for one interface,
 *    instead of a copy of the counters of every interface;
 *  - finds /if/rx, /if/tx and /if/names by name once per mapping, without
 *    regular expressions, and then checks the name on every use;
 *  - bounds every wait: on the stat socket, for a VPP writer, and the number
 *    of retries.
 *
 * A mapping belongs to one VPP process, known by its pid (SO_PEERCRED on the
 * stat socket). Callers say which VPP process they want the counters of (the
 * one that created the interface, vpputils.c), so a session created in a VPP
 * that restarted since is never answered with the counters that another
 * interface has under the same sw_if_index in the new VPP.
 *
 * The mapping of a VPP that is gone must not be kept: the segment lives in
 * hugepages, and they stay taken for as long as anyone maps it. A VPP that
 * restarts needs every hugepage of the old one (the pool is sized for one
 * VPP): with a few of them held here, its DPDK could not start the NIC and
 * VPP came up with no interface (lab, 2026-11-18). So the mapping is dropped
 * the moment the VPP process exits or the API connection is lost
 * (vpp_stats_drop()), and made again by the next read.
 *
 * There is no cache and no batch mode: reading one interface costs a few
 * dozen memory loads, so "show sessions" reads each session like every other
 * caller does.
 */

#include <linux/if_link.h>
#include <pthread.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include <vppinfra/types.h>
#include <vppinfra/vec.h>
#include <vlib/stats/shared.h>
#include <vlib/counter_types.h>

#include "triton.h"
#include "ap_session.h"
#include "log.h"

#include "vpphooks.h"
#include "vpputils.h"
#include "vppstats.h"

#define VS_SOCKET_FILE "/run/vpp/stats.sock"
/* STAT_SEGMENT_VERSION (vlib/stats/stats.h) of the layout read here */
#define VS_SEGMENT_VERSION 2

/* A vppinfra vector keeps its length in a u32, 8 bytes before the data. */
#define VS_VEC_HDR 8
_Static_assert(sizeof(vec_header_t) == VS_VEC_HDR && offsetof(vec_header_t, len) == 0,
	       "vppinfra vector header changed: review vppstats.c");

/* Wait on the stat socket (connect and the answer with the segment). */
#define VS_SOCKET_TIMEOUT_MS 1000
/* Seconds between two attempts to map the segment. */
#define VS_CONNECT_RETRY_SEC 1
/* Total time of one read (waiting for a VPP writer and trying), and its tries. */
#define VS_WRITER_WAIT_MS 200
#define VS_MAX_ATTEMPTS 32
/*
 * Reads of an unchanged segment that fail in a row before its layout is
 * taken as unknown, and seconds without reading it after that.
 */
#define VS_STABLE_FAILS 3
#define VS_UNREADABLE_RETRY_SEC 2
/* Seconds between two log lines about a segment that cannot be read. */
#define VS_LOG_INTERVAL_SEC 60
/* Sanity limits for what the segment says. */
#define VS_MAX_THREADS 1024
#define VS_MAX_INTERFACES (1U << 20)
#define VS_IF_NAME_LEN 64

enum {
	VS_IF_RX,
	VS_IF_TX,
	VS_IF_NAMES,
	VS_N_ENTRIES,
};

static const char *const vs_entry_name[VS_N_ENTRIES] = {
	[VS_IF_RX] = "/if/rx",
	[VS_IF_TX] = "/if/tx",
	[VS_IF_NAMES] = "/if/names",
};

struct vs_map {
	const uint8_t *mem;	/* NULL = no mapping */
	size_t size;
	uint64_t vbase;		/* address of the segment inside VPP */
	uint32_t pid;		/* VPP process the segment belongs to */
	/* directory index of each entry, ~0 = not found yet (atomic) */
	uint32_t idx[VS_N_ENTRIES];
	/*
	 * Monotonic second of a read that failed on a segment that was not
	 * changing: it is not the layout this file knows (atomic, 0 = none).
	 * Reads fail at once for VS_UNREADABLE_RETRY_SEC after it, instead
	 * of walking the whole directory again for every session.
	 */
	uint32_t unreadable_at;
};

/*
 * vs_lock: readers of the mapping hold it for reading, the one that replaces
 * the mapping for writing. vs_connect_lock: one thread at a time talks to the
 * stat socket, without vs_lock, so a VPP that does not answer never holds the
 * readers of a mapping that is still there.
 */
static struct vs_map vs;
static pthread_rwlock_t vs_lock = PTHREAD_RWLOCK_INITIALIZER;
static pthread_mutex_t vs_connect_lock = PTHREAD_MUTEX_INITIALIZER;
static time_t vs_next_connect;		/* vs_connect_lock */
static uint32_t vs_log_at;		/* atomic */

static time_t vs_now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec;
}

static long vs_elapsed_ms(const struct timespec *start)
{
	struct timespec now;

	clock_gettime(CLOCK_MONOTONIC, &now);
	return (now.tv_sec - start->tv_sec) * 1000 + (now.tv_nsec - start->tv_nsec) / 1000000;
}

/* One line per VS_LOG_INTERVAL_SEC for a failure every reader would repeat. */
static int vs_log_due(void)
{
	uint32_t now = (uint32_t)vs_now();
	uint32_t last = __atomic_load_n(&vs_log_at, __ATOMIC_RELAXED);

	if (last && now - last < VS_LOG_INTERVAL_SEC)
		return 0;

	return __atomic_compare_exchange_n(&vs_log_at, &last, now ? now : 1, 0,
					   __ATOMIC_RELAXED, __ATOMIC_RELAXED);
}

/* ---- Bounded access to the segment -------------------------------------- */

/* A value read once: the compiler has no second look at the shared memory. */
static inline uint64_t vs_ld64(const void *p)
{
	uint64_t v;

	__builtin_memcpy(&v, p, sizeof(v));
	return v;
}

static inline uint32_t vs_ld32(const void *p)
{
	uint32_t v;

	__builtin_memcpy(&v, p, sizeof(v));
	return v;
}

/*
 * Address inside VPP -> address in this mapping, or NULL when [vaddr,
 * vaddr + need) is not wholly inside the segment, past the shared header.
 */
static const uint8_t *vs_ptr(const struct vs_map *m, uint64_t vaddr, size_t need)
{
	uint64_t off = vaddr - m->vbase;

	if (off < sizeof(vlib_stats_shared_header_t) || off > m->size || need > m->size - off)
		return NULL;

	return m->mem + off;
}

/*
 * A vppinfra vector of elements of elt bytes at vaddr: its data and its
 * length, or NULL when the header or the data are not inside the segment.
 */
static const uint8_t *vs_vec(const struct vs_map *m, uint64_t vaddr, size_t elt, uint32_t *len)
{
	const uint8_t *hdr, *data;
	uint32_t n;

	if (vaddr < VS_VEC_HDR)
		return NULL;

	hdr = vs_ptr(m, vaddr - VS_VEC_HDR, VS_VEC_HDR);
	if (!hdr)
		return NULL;

	n = vs_ld32(hdr);
	data = hdr + VS_VEC_HDR;
	if (n > (m->size - (size_t)(data - m->mem)) / elt)
		return NULL;

	*len = n;
	return data;
}

/*
 * Start of a read: wait for the VPP writer, for at most what is left of
 * VS_WRITER_WAIT_MS since *start, and take the epoch. -1 = the writer did
 * not leave in time.
 */
static int vs_read_begin(const struct vs_map *m, const struct timespec *start, uint64_t *epoch)
{
	const vlib_stats_shared_header_t *h = (const void *)m->mem;
	const struct timespec nap = { 0, 100000 };
	int spin = 0;

	while (__atomic_load_n(&h->in_progress, __ATOMIC_SEQ_CST)) {
		if (++spin < 200)
			continue;
		if (vs_elapsed_ms(start) >= VS_WRITER_WAIT_MS)
			return -1;
		nanosleep(&nap, NULL);
	}

	*epoch = __atomic_load_n(&h->epoch, __ATOMIC_SEQ_CST);
	return 0;
}

/*
 * End of a read: nothing changed since vs_read_begin().
 *
 * The order of the two loads matters. The writer ends with "epoch++" and
 * then "in_progress = 0", one right after the other. Looking at the epoch
 * first (as stat_segment_access_end() of the VPP client does) accepts a read
 * made in the middle of a write whenever those two stores land between the
 * two loads: old epoch, flag already clear. Seen about once every two seconds
 * against a VPP creating interfaces. With in_progress first, a writer that
 * was active during the read is either still active here, or has already
 * bumped the epoch that is read next.
 */
static int vs_read_ok(const struct vs_map *m, uint64_t epoch)
{
	const vlib_stats_shared_header_t *h = (const void *)m->mem;

	if (__atomic_load_n(&h->in_progress, __ATOMIC_SEQ_CST))
		return 0;

	return __atomic_load_n(&h->epoch, __ATOMIC_SEQ_CST) == epoch;
}

static const uint8_t *vs_dir(const struct vs_map *m, uint32_t *n)
{
	const vlib_stats_shared_header_t *h = (const void *)m->mem;
	uint64_t vaddr = (uint64_t)(uintptr_t)__atomic_load_n(&h->directory_vector, __ATOMIC_ACQUIRE);

	return vs_vec(m, vaddr, sizeof(vlib_stats_entry_t), n);
}

static int vs_entry_is(const vlib_stats_entry_t *e, const char *name)
{
	return e->type != STAT_DIR_TYPE_EMPTY && e->type != STAT_DIR_TYPE_ILLEGAL &&
	       !strncmp(e->name, name, sizeof(e->name));
}

/*
 * Copy of the directory entry "which". The index is kept from one read to
 * the next (an entry never moves while its VPP runs) and the name is checked
 * on the copy every time; a walk of the directory happens once per mapping.
 */
static int vs_entry(struct vs_map *m, const uint8_t *dir, uint32_t n, int which,
		    vlib_stats_entry_t *e)
{
	const char *name = vs_entry_name[which];
	uint32_t i = __atomic_load_n(&m->idx[which], __ATOMIC_RELAXED);
	size_t name_len;

	if (i < n) {
		memcpy(e, dir + (size_t)i * sizeof(*e), sizeof(*e));
		if (vs_entry_is(e, name))
			return 0;
	}

	/*
	 * These entries are made when VPP starts, after its error counters:
	 * a few thousand entries in. Only the name is looked at in place; an
	 * entry that seems to be the one is copied and checked on the copy.
	 */
	name_len = strlen(name) + 1;
	for (i = 0; i < n; i++) {
		const uint8_t *d = dir + (size_t)i * sizeof(*e);

		if (memcmp(d + offsetof(vlib_stats_entry_t, name), name, name_len))
			continue;
		memcpy(e, d, sizeof(*e));
		if (!vs_entry_is(e, name))
			continue;
		__atomic_store_n(&m->idx[which], i, __ATOMIC_RELAXED);
		return 0;
	}

	return -1;
}

/* The segment is one this file cannot read: do not insist for a while. */
static int vs_unreadable(const struct vs_map *m)
{
	uint32_t at = __atomic_load_n(&m->unreadable_at, __ATOMIC_RELAXED);

	return at && (uint32_t)vs_now() - at < VS_UNREADABLE_RETRY_SEC;
}

static void vs_set_unreadable(struct vs_map *m)
{
	uint32_t now = (uint32_t)vs_now();

	__atomic_store_n(&m->unreadable_at, now ? now : 1, __ATOMIC_RELAXED);
}

/* Sum over the threads of the combined counter of one interface. */
static int vs_combined(const struct vs_map *m, const vlib_stats_entry_t *e,
		       uint32_t sw_if_index, uint64_t *packets, uint64_t *bytes)
{
	const uint8_t *threads, *c;
	uint32_t n_threads, len, t;
	uint64_t vaddr;

	if (e->type != STAT_DIR_TYPE_COUNTER_VECTOR_COMBINED)
		return -1;

	threads = vs_vec(m, (uint64_t)(uintptr_t)e->data, sizeof(uint64_t), &n_threads);
	if (!threads || !n_threads || n_threads > VS_MAX_THREADS)
		return -1;

	for (t = 0; t < n_threads; t++) {
		vaddr = vs_ld64(threads + (size_t)t * sizeof(uint64_t));
		c = vs_vec(m, vaddr, sizeof(vlib_counter_t), &len);
		if (!c)
			return -1;
		/* a thread that never saw the interface has a shorter vector */
		if (sw_if_index >= len)
			continue;
		c += (size_t)sw_if_index * sizeof(vlib_counter_t);
		*packets += vs_ld64(c + offsetof(vlib_counter_t, packets));
		*bytes += vs_ld64(c + offsetof(vlib_counter_t, bytes));
	}

	return 0;
}

/* vs_lock held for reading. 0 = out[] holds rx packets, rx bytes, tx packets, tx bytes. */
static int vs_read_if(struct vs_map *m, uint32_t sw_if_index, uint64_t out[4])
{
	vlib_stats_entry_t rx, tx;
	struct timespec start;
	const uint8_t *dir;
	uint64_t epoch;
	uint32_t n;
	int attempt, stable_fail = 0;

	if (vs_unreadable(m))
		return -1;

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (attempt = 0; attempt < VS_MAX_ATTEMPTS; attempt++) {
		/* also bounds the tries of a segment that never stays still */
		if (vs_read_begin(m, &start, &epoch) ||
		    (attempt && vs_elapsed_ms(&start) >= VS_WRITER_WAIT_MS))
			break;

		memset(out, 0, 4 * sizeof(out[0]));

		dir = vs_dir(m, &n);
		if (dir &&
		    !vs_entry(m, dir, n, VS_IF_RX, &rx) &&
		    !vs_entry(m, dir, n, VS_IF_TX, &tx) &&
		    !vs_combined(m, &rx, sw_if_index, &out[0], &out[1]) &&
		    !vs_combined(m, &tx, sw_if_index, &out[2], &out[3]) &&
		    vs_read_ok(m, epoch))
			return 0;

		/*
		 * The segment did not change and still could not be read,
		 * three times in a row: it is not the layout this file knows,
		 * and one more try reads the same thing.
		 */
		if (!vs_read_ok(m, epoch)) {
			stable_fail = 0;
		} else if (++stable_fail >= VS_STABLE_FAILS) {
			vs_set_unreadable(m);
			if (vs_log_due())
				log_error("vpp_stats: interface counters not found in the VPP stat segment\n");
			return -1;
		}
	}

	if (vs_log_due())
		log_warn("vpp_stats: VPP kept changing the stat segment for %ld ms, read given up\n",
			 vs_elapsed_ms(&start));

	return -1;
}

/* ---- Mapping ------------------------------------------------------------ */

static int vs_recv_fd(int sock)
{
	struct msghdr msg;
	char iobuf[1];
	struct iovec io = { .iov_base = iobuf, .iov_len = sizeof(iobuf) };
	union {
		char buf[CMSG_SPACE(sizeof(int))];
		struct cmsghdr align;
	} u;
	struct cmsghdr *cmsg;
	int fd = -1;

	memset(&msg, 0, sizeof(msg));
	msg.msg_iov = &io;
	msg.msg_iovlen = 1;
	msg.msg_control = u.buf;
	msg.msg_controllen = sizeof(u.buf);

	if (recvmsg(sock, &msg, MSG_CMSG_CLOEXEC) < 0)
		return -1;

	for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
		if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS &&
		    cmsg->cmsg_len >= CMSG_LEN(sizeof(int)))
			memcpy(&fd, CMSG_DATA(cmsg), sizeof(fd));
	}

	return fd;
}

/*
 * Ask VPP for the segment and map it. No lock of this file is needed: m is
 * private to the caller until it installs it.
 */
static int vs_open(struct vs_map *m)
{
	const struct timeval tv = {
		.tv_sec = VS_SOCKET_TIMEOUT_MS / 1000,
		.tv_usec = (VS_SOCKET_TIMEOUT_MS % 1000) * 1000,
	};
	const vlib_stats_shared_header_t *h;
	struct sockaddr_un un;
	struct ucred cred;
	socklen_t len;
	struct stat st;
	void *mem;
	int sock, fd, i;

	memset(m, 0, sizeof(*m));

	sock = socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0);
	if (sock < 0)
		return -1;

	/* connect() waits on the send timeout when the listen queue is full */
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	memset(&un, 0, sizeof(un));
	un.sun_family = AF_UNIX;
	strncpy(un.sun_path, VS_SOCKET_FILE, sizeof(un.sun_path) - 1);
	if (connect(sock, (struct sockaddr *)&un, sizeof(un)) < 0) {
		close(sock);
		return -1;
	}

	len = sizeof(cred);
	if (getsockopt(sock, SOL_SOCKET, SO_PEERCRED, &cred, &len) == 0 && cred.pid > 0)
		m->pid = cred.pid;

	fd = vs_recv_fd(sock);
	close(sock);
	if (fd < 0)
		return -1;

	if (fstat(fd, &st) < 0 || st.st_size < (off_t)(sizeof(*h) + VS_VEC_HDR)) {
		close(fd);
		return -1;
	}

	mem = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);
	if (mem == MAP_FAILED)
		return -1;

	h = mem;
	if (h->version != VS_SEGMENT_VERSION || !h->base) {
		if (vs_log_due())
			log_error("vpp_stats: VPP stat segment version %llu is not the one this module reads (%d)\n",
				  (unsigned long long)h->version, VS_SEGMENT_VERSION);
		munmap(mem, st.st_size);
		return -1;
	}

	m->mem = mem;
	m->size = st.st_size;
	m->vbase = (uint64_t)(uintptr_t)h->base;
	for (i = 0; i < VS_N_ENTRIES; i++)
		m->idx[i] = ~0U;

	return 0;
}

/*
 * Replace the mapping by the segment of the VPP that answers on the stat
 * socket now. Returns 0 when a mapping of the VPP process "pid" is in place.
 */
static int vs_remap(uint32_t pid)
{
	struct vs_map nm, old;
	time_t now;

	if (pthread_mutex_trylock(&vs_connect_lock))
		return -1;

	now = vs_now();
	if (now < vs_next_connect)
		goto fail;
	vs_next_connect = now + VS_CONNECT_RETRY_SEC;

	if (vs_open(&nm))
		goto fail;

	if (!nm.pid) {
		/* no SO_PEERCRED: the socket is taken on trust */
		nm.pid = pid;
	} else if (nm.pid != pid) {
		/*
		 * The stat socket is of another VPP process than the one the
		 * API talks to: VPP restarted and the API has not caught up,
		 * or the caller asks for a VPP that is gone. Not this one.
		 * (A VPP in another pid namespace would always end here: its
		 * counters are not read.)
		 */
		if (vs_log_due())
			log_warn("vpp_stats: the stat socket belongs to VPP pid %u, the counters asked for are of pid %u\n",
				 nm.pid, pid);
		munmap((void *)nm.mem, nm.size);
		goto fail;
	}

	pthread_rwlock_wrlock(&vs_lock);
	old = vs;
	vs = nm;
	pthread_rwlock_unlock(&vs_lock);

	if (old.mem)
		munmap((void *)old.mem, old.size);

	log_debug("vpp_stats: mapped the stat segment of VPP pid %u (%zu MB)\n", nm.pid, nm.size >> 20);

	pthread_mutex_unlock(&vs_connect_lock);
	return 0;

fail:
	pthread_mutex_unlock(&vs_connect_lock);
	return -1;
}

/*
 * Run fn on the mapping of the VPP process pid, with vs_lock held for
 * reading. The mapping is replaced when it is of another process, but only
 * on behalf of the VPP the API is connected to now: a caller that asks for a
 * VPP that is gone never takes the mapping away from the others.
 */
static int vs_with_map(uint32_t pid, int (*fn)(struct vs_map *m, void *arg), void *arg)
{
	int tries, r;

	if (!pid)
		return -1;

	for (tries = 0; tries < 2; tries++) {
		pthread_rwlock_rdlock(&vs_lock);
		if (vs.mem && vs.pid == pid) {
			r = fn(&vs, arg);
			pthread_rwlock_unlock(&vs_lock);
			return r;
		}
		pthread_rwlock_unlock(&vs_lock);

		if (pid != vpp_instance_pid() || vs_remap(pid))
			return -1;
	}

	return -1;
}

void vpp_stats_drop(void)
{
	struct vs_map old;

	pthread_rwlock_wrlock(&vs_lock);
	old = vs;
	memset(&vs, 0, sizeof(vs));
	pthread_rwlock_unlock(&vs_lock);

	if (old.mem) {
		munmap((void *)old.mem, old.size);
		log_debug("vpp_stats: dropped the stat segment of VPP pid %u\n", old.pid);
	}
}

/* ---- Interface counters -------------------------------------------------- */

struct vs_if_arg {
	uint32_t sw_if_index;
	uint64_t out[4];
};

static int vs_if_fn(struct vs_map *m, void *arg)
{
	struct vs_if_arg *a = arg;

	return vs_read_if(m, a->sw_if_index, a->out);
}

int vpp_stats_read_if(uint32_t vpp_pid, uint32_t sw_if_index, struct rtnl_link_stats64 *stats)
{
	struct vs_if_arg a = { .sw_if_index = sw_if_index };

	if (sw_if_index == ~0U || vs_with_map(vpp_pid, vs_if_fn, &a))
		return -1;

	memset(stats, 0, sizeof(*stats));
	stats->rx_packets = a.out[0];
	stats->rx_bytes = a.out[1];
	stats->tx_packets = a.out[2];
	stats->tx_bytes = a.out[3];

	return 0;
}

int vpphook_read_stats(struct ap_session *ses, struct rtnl_link_stats64 *stats)
{
	struct vpphook_private_data_t *pd;

	if (!ses || !stats)
		return -1;

	pd = vpphook_get_pd(ses);
	if (!pd)
		return -1;

	/*
	 * The counters of the VPP process that made the interface, whatever
	 * VPP runs now: after a VPP restart the session reads the last values
	 * of the old segment while it is still mapped, and nothing after.
	 */
	return vpp_stats_read_if(__atomic_load_n(&pd->vpp_pid, __ATOMIC_RELAXED),
				 __atomic_load_n(&pd->vpp_sw_if_index, __ATOMIC_RELAXED), stats);
}

/* ---- Interface names ----------------------------------------------------- */

struct vs_names_arg {
	char (*names)[VS_IF_NAME_LEN];
	uint32_t n;
};

/* vs_lock held for reading. Fills a->names with a copy of /if/names. */
static int vs_names_fn(struct vs_map *m, void *arg)
{
	struct vs_names_arg *a = arg;
	vlib_stats_entry_t e;
	struct timespec start;
	const uint8_t *dir, *vec, *s;
	uint64_t epoch;
	uint32_t n, n_if, len, i;
	int attempt, stable_fail = 0;

	if (vs_unreadable(m))
		return -1;

	clock_gettime(CLOCK_MONOTONIC, &start);

	for (attempt = 0; attempt < VS_MAX_ATTEMPTS; attempt++) {
		if (vs_read_begin(m, &start, &epoch) ||
		    (attempt && vs_elapsed_ms(&start) >= VS_WRITER_WAIT_MS))
			break;

		free(a->names);
		a->names = NULL;
		a->n = 0;

		dir = vs_dir(m, &n);
		if (!dir || vs_entry(m, dir, n, VS_IF_NAMES, &e) ||
		    e.type != STAT_DIR_TYPE_NAME_VECTOR)
			goto again;

		vec = vs_vec(m, (uint64_t)(uintptr_t)e.data, sizeof(uint64_t), &n_if);
		if (!vec || n_if > VS_MAX_INTERFACES)
			goto again;

		a->names = calloc(n_if ? n_if : 1, sizeof(*a->names));
		if (!a->names)
			return -1;

		for (i = 0; i < n_if; i++) {
			uint64_t vaddr = vs_ld64(vec + (size_t)i * sizeof(uint64_t));

			/* no name: the index was never used, or the name was freed */
			if (!vaddr)
				continue;
			s = vs_vec(m, vaddr, 1, &len);
			if (!s)
				goto again;
			if (len > VS_IF_NAME_LEN - 1)
				len = VS_IF_NAME_LEN - 1;
			memcpy(a->names[i], s, len);
			a->names[i][len] = 0;
		}

		if (vs_read_ok(m, epoch)) {
			a->n = n_if;
			return 0;
		}
		continue;
again:
		if (!vs_read_ok(m, epoch)) {
			stable_fail = 0;
		} else if (++stable_fail >= VS_STABLE_FAILS) {
			vs_set_unreadable(m);
			break;
		}
	}

	free(a->names);
	a->names = NULL;
	a->n = 0;
	return -1;
}

int vpphook_stats_if_names(void (*cb)(uint32_t sw_if_index, const char *name, void *arg), void *arg)
{
	struct vs_names_arg a = { NULL, 0 };
	uint32_t i;

	if (vs_with_map(vpp_instance_pid(), vs_names_fn, &a))
		return -1;

	for (i = 0; i < a.n; i++) {
		if (a.names[i][0])
			cb(i, a.names[i], arg);
	}

	free(a.names);
	return 0;
}
