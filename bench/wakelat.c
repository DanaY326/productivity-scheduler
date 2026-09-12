/* SPDX-License-Identifier: GPL-2.0 */
/*
 * wakelat: periodic-wakeup latency, a stand-in for an interactive app.
 *
 * Each thread sleeps until an absolute deadline every PERIOD us and records
 * how late it actually woke. Prints p50/p99/p99.9/max after DURATION seconds,
 * discarding the first WARMUP seconds (time for focusd/bench to mark us).
 *
 *   wakelat [-t threads] [-p period_us] [-d duration_s] [-w warmup_s] [-r run_us]
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define NR_BUCKETS 100000	/* 1us buckets, last one is overflow (>= 100ms) */

static int period_us = 1000, duration_s = 10, warmup_s = 1, run_us = 50;
static atomic_ulong hist[NR_BUCKETS];

static long long ts_ns(const struct timespec *t)
{
	return t->tv_sec * 1000000000LL + t->tv_nsec;
}

static void *worker(void *arg)
{
	struct timespec next, now;
	long long start, end, warm;

	clock_gettime(CLOCK_MONOTONIC, &next);
	start = ts_ns(&next);
	warm = start + warmup_s * 1000000000LL;
	end = warm + duration_s * 1000000000LL;

	for (;;) {
		long long target, lat;

		next.tv_nsec += period_us * 1000L;
		while (next.tv_nsec >= 1000000000L) {
			next.tv_nsec -= 1000000000L;
			next.tv_sec++;
		}
		clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &next, NULL);
		clock_gettime(CLOCK_MONOTONIC, &now);

		target = ts_ns(&next);
		lat = (ts_ns(&now) - target) / 1000;
		if (target >= warm)
			atomic_fetch_add(&hist[lat < NR_BUCKETS - 1 ? lat : NR_BUCKETS - 1], 1);
		if (target >= end)
			break;

		/* simulate a little work per frame/event */
		do
			clock_gettime(CLOCK_MONOTONIC, &now);
		while (ts_ns(&now) - target < (long long)run_us * 1000 + lat * 1000);
	}
	return NULL;
}

static long pct(unsigned long total, double p)
{
	unsigned long want = (unsigned long)(total * p), seen = 0;

	for (long i = 0; i < NR_BUCKETS; i++) {
		seen += hist[i];
		if (seen > want)
			return i;
	}
	return NR_BUCKETS - 1;
}

int main(int argc, char **argv)
{
	int nr_threads = 4, opt;
	unsigned long total = 0;
	long max = 0;

	while ((opt = getopt(argc, argv, "t:p:d:w:r:")) != -1) {
		switch (opt) {
		case 't': nr_threads = atoi(optarg); break;
		case 'p': period_us = atoi(optarg); break;
		case 'd': duration_s = atoi(optarg); break;
		case 'w': warmup_s = atoi(optarg); break;
		case 'r': run_us = atoi(optarg); break;
		default:
			fprintf(stderr, "usage: %s [-t threads] [-p period_us] [-d duration_s] "
				"[-w warmup_s] [-r run_us]\n", argv[0]);
			return 1;
		}
	}

	fprintf(stderr, "wakelat pid %d: %d threads, period %dus, run %dus, %ds (+%ds warmup)\n",
		getpid(), nr_threads, period_us, run_us, duration_s, warmup_s);

	pthread_t th[nr_threads];
	for (int i = 0; i < nr_threads; i++)
		pthread_create(&th[i], NULL, worker, NULL);
	for (int i = 0; i < nr_threads; i++)
		pthread_join(th[i], NULL);

	for (long i = 0; i < NR_BUCKETS; i++) {
		total += hist[i];
		if (hist[i])
			max = i;
	}
	printf("wakeups=%lu p50=%ldus p99=%ldus p99.9=%ldus max=%ldus%s\n",
	       total, pct(total, 0.5), pct(total, 0.99), pct(total, 0.999), max,
	       max == NR_BUCKETS - 1 ? "+" : "");
	return 0;
}
