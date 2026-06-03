/* SPDX-License-Identifier: GPL-2.0 */
/*
 * focus-sched loader: detects CPU topology, loads focus.bpf.c, and serves a
 * line-based control socket that focusd uses to update focus/distract marks
 * and tunables. See README.md for the protocol.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <time.h>
#include <libgen.h>
#include <getopt.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <bpf/bpf.h>
#include <scx/common.h>
#include "focus.h"
#include "focus.bpf.skel.h"

#define MAX_CLIENTS	8
#define CLIENT_BUF	(256 * 1024)
#define MAX_IDS		16384

const char help_fmt[] =
"focus-sched: a focus-aware sched_ext scheduler.\n"
"\n"
"Usage: %s [options]\n"
"\n"
"  -c PCT        Cap distract tasks at PCT%% of total CPU time (default 30, 100 = off)\n"
"  -b MS         Wake-chain boost duration in ms (default 30)\n"
"  -H US         Demote focus/boost tasks averaging >= US per run (default 2500)\n"
"  -e CPULIST    Treat CPULIST as efficiency CPUs (overrides detection)\n"
"  -E            Energy mode: never run distract work on perf CPUs unless starving\n"
"  -S            Disable SMT isolation\n"
"  -A            Disable audio rescue for distract tasks\n"
"  -s PATH       Control socket path (default /run/focus-sched.sock)\n"
"  -u UID[:GID]  Owner of the control socket (lets focusd run unprivileged)\n"
"  -i SEC        Print stats every SEC seconds (default 1, 0 = quiet)\n"
"  -v            Print libbpf debug messages\n"
"  -h            Display this help and exit\n";

static bool verbose;
static volatile int exit_req;
static int nr_possible;

static const char *stat_names[FS_NR_STATS] = {
	"disp_focus", "disp_boost", "disp_normal", "disp_distract",
	"rt_focus", "rt_boost", "rt_normal", "rt_distract",
	"direct_idle", "preempt_kick", "tick_preempt", "smt_kick",
	"boost_down", "boost_up", "hog_demote", "audio_rescue",
	"cap_throttle", "starve_rescue", "place_perf", "place_eff",
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sigint_handler(int sig)
{
	exit_req = 1;
}

/* ---- topology ---------------------------------------------------------- */

static int read_str(const char *path, char *buf, size_t size)
{
	FILE *f = fopen(path, "r");
	size_t n;

	if (!f)
		return -errno;
	n = fread(buf, 1, size - 1, f);
	fclose(f);
	buf[n] = '\0';
	while (n && (buf[n - 1] == '\n' || buf[n - 1] == ' '))
		buf[--n] = '\0';
	return 0;
}

static long read_long(const char *path, long dfl)
{
	char buf[64];

	if (read_str(path, buf, sizeof(buf)))
		return dfl;
	return strtol(buf, NULL, 0);
}

/* Parse "0-3,8,10-11" into @out. Returns the number of CPUs set. */
static int parse_cpulist(const char *s, bool *out, int max)
{
	int cnt = 0;

	while (*s) {
		char *end;
		long a = strtol(s, &end, 10), b = a;

		if (end == s)
			return -EINVAL;
		if (*end == '-')
			b = strtol(end + 1, &end, 10);
		for (long i = a; i <= b && i < max; i++) {
			if (i >= 0 && !out[i]) {
				out[i] = true;
				cnt++;
			}
		}
		s = *end == ',' ? end + 1 : end;
		if (*end && *end != ',')
			break;
	}
	return cnt;
}

static void detect_topology(struct focus_bpf *skel, const char *eff_override)
{
	static bool eff[MAX_CPUS], online[MAX_CPUS];
	char path[256], buf[4096];
	long max_cap = 0;
	int nr_eff = 0, nr_online = 0;
	const char *eff_src = "none";

	if (!read_str("/sys/devices/system/cpu/online", buf, sizeof(buf)))
		nr_online = parse_cpulist(buf, online, nr_possible);
	if (nr_online <= 0) {
		for (int i = 0; i < nr_possible; i++)
			online[i] = true;
		nr_online = nr_possible;
	}

	if (eff_override) {
		nr_eff = parse_cpulist(eff_override, eff, nr_possible);
		SCX_BUG_ON(nr_eff < 0, "invalid --eff-cpus list '%s'", eff_override);
		eff_src = "user";
	} else if (!read_str("/sys/devices/cpu_atom/cpus", buf, sizeof(buf)) && buf[0]) {
		/* Intel hybrid: E-cores are listed under the cpu_atom PMU */
		nr_eff = parse_cpulist(buf, eff, nr_possible);
		eff_src = "intel-hybrid";
	} else {
		/* ARM big.LITTLE: anything well below the max capacity is LITTLE */
		for (int i = 0; i < nr_possible; i++) {
			snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpu_capacity", i);
			long cap = read_long(path, 0);
			if (cap > max_cap)
				max_cap = cap;
		}
		for (int i = 0; max_cap && i < nr_possible; i++) {
			snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cpu_capacity", i);
			if (read_long(path, max_cap) * 10 < max_cap * 8) {
				eff[i] = true;
				nr_eff++;
			}
		}
		if (nr_eff)
			eff_src = "cpu_capacity";
	}

	for (int i = 0; i < nr_possible; i++) {
		bool sib[MAX_CPUS] = {};
		int sibling = -1;

		snprintf(path, sizeof(path),
			 "/sys/devices/system/cpu/cpu%d/topology/thread_siblings_list", i);
		if (!read_str(path, buf, sizeof(buf)) && parse_cpulist(buf, sib, nr_possible) > 1) {
			for (int j = 0; j < nr_possible; j++) {
				if (sib[j] && j != i) {
					sibling = j;
					break;
				}
			}
		}

		snprintf(path, sizeof(path), "/sys/devices/system/cpu/cpu%d/cache/index3/id", i);
		skel->rodata->cpu_llc[i] = read_long(path, 0);
		skel->rodata->cpu_sibling[i] = sibling;
		skel->rodata->cpu_eff[i] = eff[i];
	}

	skel->rodata->nr_cpus = nr_possible;
	skel->rodata->nr_online_cpus = nr_online;
	skel->rodata->have_eff = nr_eff > 0 && nr_eff < nr_possible;

	printf("topology: %d possible, %d online, %d efficiency CPUs (%s)\n",
	       nr_possible, nr_online, nr_eff, eff_src);
}

/* ---- mark maps --------------------------------------------------------- */

static int cmp_u64(const void *a, const void *b)
{
	__u64 x = *(const __u64 *)a, y = *(const __u64 *)b;

	return x < y ? -1 : x > y;
}

/*
 * Make the set of keys carrying @mark in @fd equal to @ids. Keys of other
 * marks are left alone unless they appear in @ids, in which case they are
 * overwritten.
 */
static int sync_marks(int fd, bool wide_key, __u8 mark, __u64 *ids, int nr)
{
	static __u64 stale[MAX_IDS];
	int nr_stale = 0;
	__u64 key = 0, next = 0;
	void *prev = NULL;

	qsort(ids, nr, sizeof(*ids), cmp_u64);

	while (!bpf_map_get_next_key(fd, prev, &next)) {
		__u64 id = wide_key ? next : *(__u32 *)&next;
		__u8 val;

		if (!bpf_map_lookup_elem(fd, &next, &val) && val == mark &&
		    !bsearch(&id, ids, nr, sizeof(*ids), cmp_u64) && nr_stale < MAX_IDS)
			stale[nr_stale++] = next;
		key = next;
		prev = &key;
	}

	for (int i = 0; i < nr_stale; i++)
		bpf_map_delete_elem(fd, &stale[i]);

	for (int i = 0; i < nr; i++) {
		__u64 k = ids[i];
		__u32 k32 = ids[i];
		int ret = bpf_map_update_elem(fd, wide_key ? (void *)&k : (void *)&k32,
					      &mark, BPF_ANY);
		if (ret)
			return ret;
	}
	return 0;
}

/* ---- stats ------------------------------------------------------------- */

static void read_stats(struct focus_bpf *skel, __u64 *out)
{
	__u64 cnts[nr_possible];

	memset(out, 0, sizeof(__u64) * FS_NR_STATS);
	for (__u32 idx = 0; idx < FS_NR_STATS; idx++) {
		if (bpf_map_lookup_elem(bpf_map__fd(skel->maps.stats), &idx, cnts))
			continue;
		for (int cpu = 0; cpu < nr_possible; cpu++)
			out[idx] += cnts[cpu];
	}
}

static void print_stats(__u64 *cur, __u64 *prev)
{
	__u64 d[FS_NR_STATS], rt_total = 0;

	for (int i = 0; i < FS_NR_STATS; i++)
		d[i] = cur[i] - prev[i];
	for (int i = 0; i < FS_NR_CLASSES; i++)
		rt_total += d[ST_RT_FOCUS + i];
	if (!rt_total)
		rt_total = 1;

	printf("cpu%% focus=%4.1f boost=%4.1f normal=%4.1f distract=%4.1f | "
	       "preempt=%llu tick=%llu smt=%llu boost=%llu/%llu hog=%llu audio=%llu "
	       "cap=%llu starve=%llu perf=%llu eff=%llu\n",
	       100.0 * d[ST_RT_FOCUS] / rt_total, 100.0 * d[ST_RT_BOOST] / rt_total,
	       100.0 * d[ST_RT_NORMAL] / rt_total, 100.0 * d[ST_RT_DISTRACT] / rt_total,
	       d[ST_PREEMPT_KICK], d[ST_TICK_PREEMPT], d[ST_SMT_KICK],
	       d[ST_BOOST_DOWN], d[ST_BOOST_UP], d[ST_HOG_DEMOTE], d[ST_AUDIO_RESCUE],
	       d[ST_CAP_THROTTLE], d[ST_STARVE_RESCUE], d[ST_PLACE_PERF], d[ST_PLACE_EFF]);
	fflush(stdout);
}

/* ---- control socket ---------------------------------------------------- */

struct client {
	int fd;
	size_t len;
	char *buf;
};

static struct client clients[MAX_CLIENTS];

static int reply(int fd, const char *fmt, ...)
{
	char buf[4096];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	va_end(ap);
	if (n < 0)
		return n;
	if (n > (int)sizeof(buf) - 2)
		n = sizeof(buf) - 2;
	buf[n++] = '\n';
	return write(fd, buf, n) == n ? 0 : -EIO;
}

static int cmd_set(struct focus_bpf *skel, int fd, char *args)
{
	static __u64 ids[MAX_IDS];
	char *what = strtok(args, " \t"), *tok;
	bool cgroup;
	__u8 mark;
	int nr = 0, ret, map_fd;

	if (!what)
		return reply(fd, "err usage: set <focus|distract>_<tgid|cgroup> [id...]");
	if (!strcmp(what, "focus_tgid"))
		mark = MARK_FOCUS, cgroup = false;
	else if (!strcmp(what, "focus_cgroup"))
		mark = MARK_FOCUS, cgroup = true;
	else if (!strcmp(what, "distract_tgid"))
		mark = MARK_DISTRACT, cgroup = false;
	else if (!strcmp(what, "distract_cgroup"))
		mark = MARK_DISTRACT, cgroup = true;
	else
		return reply(fd, "err unknown set '%s'", what);

	while ((tok = strtok(NULL, " \t")) && nr < MAX_IDS) {
		char *end;
		__u64 id = strtoull(tok, &end, 10);

		if (*end || !id)
			return reply(fd, "err bad id '%s'", tok);
		ids[nr++] = id;
	}

	map_fd = bpf_map__fd(cgroup ? skel->maps.cgroup_marks : skel->maps.tgid_marks);
	ret = sync_marks(map_fd, cgroup, mark, ids, nr);
	__atomic_add_fetch(&skel->data->cfg_gen, 1, __ATOMIC_RELAXED);
	if (ret)
		return reply(fd, "err map update failed (%d)", ret);
	return reply(fd, "ok %d", nr);
}

static int cmd_tune(struct focus_bpf *skel, int fd, char *args)
{
	char *key = strtok(args, " \t"), *val = strtok(NULL, " \t"), *end;
	long v;

	if (!key || !val)
		return reply(fd, "err usage: tune <key> <value>");
	v = strtol(val, &end, 10);
	if (*end || v < 0)
		return reply(fd, "err bad value '%s'", val);

	if (!strcmp(key, "cap_pct"))
		skel->data->cap_pct = v > 100 ? 100 : v;
	else if (!strcmp(key, "boost_ms"))
		skel->data->boost_ns = v * 1000000ULL;
	else if (!strcmp(key, "hog_us"))
		skel->data->hog_ns = v * 1000ULL;
	else if (!strcmp(key, "smt_isolation"))
		skel->data->smt_isolation = !!v;
	else if (!strcmp(key, "audio_rescue"))
		skel->data->audio_rescue = !!v;
	else if (!strcmp(key, "energy_mode"))
		skel->bss->energy_mode = !!v;
	else
		return reply(fd, "err unknown tunable '%s'", key);
	return reply(fd, "ok");
}

static int cmd_get(struct focus_bpf *skel, int fd)
{
	return reply(fd, "ok cap_pct=%u boost_ms=%llu hog_us=%llu smt_isolation=%d "
		     "audio_rescue=%d energy_mode=%d have_eff=%d",
		     skel->data->cap_pct, skel->data->boost_ns / 1000000,
		     skel->data->hog_ns / 1000, skel->data->smt_isolation,
		     skel->data->audio_rescue, skel->bss->energy_mode,
		     skel->rodata->have_eff);
}

static int cmd_stats(struct focus_bpf *skel, int fd)
{
	__u64 st[FS_NR_STATS];
	char buf[2048];
	int off = 0;

	read_stats(skel, st);
	for (int i = 0; i < FS_NR_STATS; i++)
		off += snprintf(buf + off, sizeof(buf) - off, " %s=%llu", stat_names[i], st[i]);
	return reply(fd, "ok%s", buf);
}

static int handle_line(struct focus_bpf *skel, int fd, char *line)
{
	char *cmd = line, *args;

	while (*cmd == ' ' || *cmd == '\t')
		cmd++;
	args = strpbrk(cmd, " \t");
	if (args)
		*args++ = '\0';
	else
		args = cmd + strlen(cmd);

	if (!*cmd)
		return 0;
	if (!strcmp(cmd, "ping"))
		return reply(fd, "ok pong");
	if (!strcmp(cmd, "set"))
		return cmd_set(skel, fd, args);
	if (!strcmp(cmd, "tune"))
		return cmd_tune(skel, fd, args);
	if (!strcmp(cmd, "get"))
		return cmd_get(skel, fd);
	if (!strcmp(cmd, "stats"))
		return cmd_stats(skel, fd);
	return reply(fd, "err unknown command '%s'", cmd);
}

static void drop_client(struct client *c)
{
	close(c->fd);
	free(c->buf);
	c->fd = -1;
	c->buf = NULL;
	c->len = 0;
}

static void serve_client(struct focus_bpf *skel, struct client *c)
{
	ssize_t n = read(c->fd, c->buf + c->len, CLIENT_BUF - 1 - c->len);
	char *line, *nl;

	if (n <= 0) {
		drop_client(c);
		return;
	}
	c->len += n;
	c->buf[c->len] = '\0';

	line = c->buf;
	while ((nl = strchr(line, '\n'))) {
		*nl = '\0';
		if (handle_line(skel, c->fd, line)) {
			drop_client(c);
			return;
		}
		line = nl + 1;
	}
	c->len -= line - c->buf;
	memmove(c->buf, line, c->len);
	if (c->len == CLIENT_BUF - 1) {
		reply(c->fd, "err line too long");
		drop_client(c);
	}
}

static int open_socket(const char *path, const char *owner)
{
	struct sockaddr_un addr = { .sun_family = AF_UNIX };
	int fd;

	SCX_BUG_ON(strlen(path) >= sizeof(addr.sun_path), "socket path too long");
	strcpy(addr.sun_path, path);
	unlink(path);

	fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
	SCX_BUG_ON(fd < 0, "socket");
	SCX_BUG_ON(bind(fd, (struct sockaddr *)&addr, sizeof(addr)), "bind %s", path);
	SCX_BUG_ON(listen(fd, MAX_CLIENTS), "listen");

	if (owner) {
		uid_t uid = strtoul(owner, NULL, 10);
		const char *colon = strchr(owner, ':');
		gid_t gid = colon ? strtoul(colon + 1, NULL, 10) : (gid_t)-1;

		SCX_BUG_ON(chown(path, uid, gid), "chown %s", path);
		chmod(path, 0660);
	} else {
		chmod(path, 0600);
	}
	return fd;
}

static void poll_loop(struct focus_bpf *skel, int lfd, int interval)
{
	__u64 prev[FS_NR_STATS], cur[FS_NR_STATS];
	struct timespec last, now;

	read_stats(skel, prev);
	clock_gettime(CLOCK_MONOTONIC, &last);

	while (!exit_req && !UEI_EXITED(skel, uei)) {
		struct pollfd pfds[MAX_CLIENTS + 1];
		int map[MAX_CLIENTS + 1], n = 0;

		pfds[n++] = (struct pollfd){ .fd = lfd, .events = POLLIN };
		for (int i = 0; i < MAX_CLIENTS; i++) {
			if (clients[i].fd >= 0) {
				map[n] = i;
				pfds[n++] = (struct pollfd){ .fd = clients[i].fd, .events = POLLIN };
			}
		}

		if (poll(pfds, n, 250) > 0) {
			if (pfds[0].revents & POLLIN) {
				int cfd = accept4(lfd, NULL, NULL, SOCK_CLOEXEC);
				int slot = -1;

				for (int i = 0; cfd >= 0 && i < MAX_CLIENTS; i++) {
					if (clients[i].fd < 0) {
						slot = i;
						break;
					}
				}
				if (slot >= 0) {
					clients[slot].fd = cfd;
					clients[slot].buf = malloc(CLIENT_BUF);
					clients[slot].len = 0;
					if (!clients[slot].buf)
						drop_client(&clients[slot]);
				} else if (cfd >= 0) {
					reply(cfd, "err too many clients");
					close(cfd);
				}
			}
			for (int i = 1; i < n; i++) {
				if (pfds[i].revents & (POLLIN | POLLHUP | POLLERR))
					serve_client(skel, &clients[map[i]]);
			}
		}

		clock_gettime(CLOCK_MONOTONIC, &now);
		if (interval && now.tv_sec - last.tv_sec >= interval) {
			read_stats(skel, cur);
			print_stats(cur, prev);
			memcpy(prev, cur, sizeof(prev));
			last = now;
		}
	}
}

int main(int argc, char **argv)
{
	const char *sock_path = "/run/focus-sched.sock", *owner = NULL, *eff_cpus = NULL;
	long cap = 30, boost_ms = 30, hog_us = 2500, interval = 1;
	bool energy = false, smt = true, audio = true;
	struct focus_bpf *skel;
	struct bpf_link *link;
	int opt, lfd;
	__u64 ecode;

	libbpf_set_print(libbpf_print_fn);
	signal(SIGINT, sigint_handler);
	signal(SIGTERM, sigint_handler);
	signal(SIGPIPE, SIG_IGN);

	while ((opt = getopt(argc, argv, "c:b:H:e:ESAs:u:i:vh")) != -1) {
		switch (opt) {
		case 'c': cap = strtol(optarg, NULL, 10); break;
		case 'b': boost_ms = strtol(optarg, NULL, 10); break;
		case 'H': hog_us = strtol(optarg, NULL, 10); break;
		case 'e': eff_cpus = optarg; break;
		case 'E': energy = true; break;
		case 'S': smt = false; break;
		case 'A': audio = false; break;
		case 's': sock_path = optarg; break;
		case 'u': owner = optarg; break;
		case 'i': interval = strtol(optarg, NULL, 10); break;
		case 'v': verbose = true; break;
		default:
			fprintf(stderr, help_fmt, basename(argv[0]));
			return opt != 'h';
		}
	}

	nr_possible = libbpf_num_possible_cpus();
	SCX_BUG_ON(nr_possible <= 0, "can't determine number of CPUs");
	SCX_BUG_ON(nr_possible > MAX_CPUS, "%d CPUs exceeds MAX_CPUS (%d)", nr_possible, MAX_CPUS);

	for (int i = 0; i < MAX_CLIENTS; i++)
		clients[i].fd = -1;
	lfd = open_socket(sock_path, owner);

restart:
	skel = SCX_OPS_OPEN(focus_ops, focus_bpf);

	detect_topology(skel, eff_cpus);
	skel->data->cap_pct = cap < 0 ? 0 : cap > 100 ? 100 : cap;
	skel->data->boost_ns = boost_ms * 1000000ULL;
	skel->data->hog_ns = hog_us * 1000ULL;
	skel->data->smt_isolation = smt;
	skel->data->audio_rescue = audio;
	skel->bss->energy_mode = energy;

	SCX_OPS_LOAD(skel, focus_ops, focus_bpf, uei);
	link = SCX_OPS_ATTACH(skel, focus_ops, focus_bpf);
	printf("focus-sched attached, control socket %s\n", sock_path);
	fflush(stdout);

	poll_loop(skel, lfd, interval);

	bpf_link__destroy(link);
	ecode = UEI_REPORT(skel, uei);
	focus_bpf__destroy(skel);

	if (!exit_req && UEI_ECODE_RESTART(ecode))
		goto restart;

	close(lfd);
	unlink(sock_path);
	return 0;
}
