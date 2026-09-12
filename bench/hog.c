/* SPDX-License-Identifier: GPL-2.0 */
/*
 * hog: CPU-bound background load that reports its own throughput, a stand-in
 * for a distraction (video decode, game, Electron spinning).
 *
 *   hog [-t threads] [-d duration_s]
 */
#define _GNU_SOURCE
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

static atomic_ulong iters;
static atomic_int stop;

static void *spin(void *arg)
{
	unsigned long n = 0;
	volatile unsigned long x = 1;

	while (!atomic_load_explicit(&stop, memory_order_relaxed)) {
		for (int i = 0; i < 100000; i++)
			x = x * 2654435761u + i;
		n++;
	}
	atomic_fetch_add(&iters, n);
	return NULL;
}

int main(int argc, char **argv)
{
	int nr_threads = sysconf(_SC_NPROCESSORS_ONLN), duration_s = 10, opt;

	while ((opt = getopt(argc, argv, "t:d:")) != -1) {
		switch (opt) {
		case 't': nr_threads = atoi(optarg); break;
		case 'd': duration_s = atoi(optarg); break;
		default:
			fprintf(stderr, "usage: %s [-t threads] [-d duration_s]\n", argv[0]);
			return 1;
		}
	}

	fprintf(stderr, "hog pid %d: %d threads for %ds\n", getpid(), nr_threads, duration_s);

	pthread_t th[nr_threads];
	for (int i = 0; i < nr_threads; i++)
		pthread_create(&th[i], NULL, spin, NULL);
	sleep(duration_s);
	atomic_store(&stop, 1);
	for (int i = 0; i < nr_threads; i++)
		pthread_join(th[i], NULL);

	printf("hog_iters_per_sec=%.1f\n", (double)iters / duration_s);
	return 0;
}
