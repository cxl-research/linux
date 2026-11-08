// SPDX-License-Identifier: GPL-2.0
/*
 * ftier_hot: synthetic hot/cold workload for FTier tests.
 *
 * Allocates a THP-backed anonymous buffer bound to a set of nodes, then
 * repeatedly touches a hot sub-range and periodically reports which share
 * of the hot and cold ranges resides on the "fast" nodes.
 *
 * Copyright (c) 2025-2026 Alan Nair <alannair1000@gmail.com>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define MPOL_DEFAULT	0
#define MPOL_BIND	2
#define PAGE_SZ		4096UL
#define MB		(1UL << 20)

static unsigned long size_mb = 1024, hot_mb = 128, hot_off_mb;
static unsigned long bind_mask = 0xc, fast_mask = 0x3;
static int seconds = 30, nr_threads = 1, report_ms = 1000, stride = 64;
static int no_thp;
static volatile int stop;
static char *buf;
static volatile unsigned long touches;

static double now(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec + ts.tv_nsec / 1e9;
}

static void *toucher(void *arg)
{
	unsigned long tid = (unsigned long)arg, n = 0;
	char *start = buf + hot_off_mb * MB;
	unsigned long len = hot_mb * MB, off;

	while (!stop) {
		for (off = tid * PAGE_SZ; off < len; off += nr_threads * PAGE_SZ) {
			start[off + (n & (PAGE_SZ / stride - 1)) * stride]++;
			n++;
		}
		__atomic_fetch_add(&touches, len / PAGE_SZ / nr_threads,
				   __ATOMIC_RELAXED);
	}
	return NULL;
}

/* Fraction of sampled pages in [off, off + len) that live on fast nodes. */
static double fast_share(unsigned long off, unsigned long len)
{
	unsigned long step = 16 * PAGE_SZ, n = len / step, i, fast = 0, ok = 0;
	void **pages = calloc(n, sizeof(*pages));
	int *status = calloc(n, sizeof(*status));
	double ret = -1;

	if (!pages || !status || !n)
		goto out;
	for (i = 0; i < n; i++)
		pages[i] = buf + off + i * step;
	if (syscall(SYS_move_pages, 0, n, pages, NULL, status, 0))
		goto out;
	for (i = 0; i < n; i++) {
		if (status[i] < 0)
			continue;
		ok++;
		if (fast_mask & (1UL << status[i]))
			fast++;
	}
	if (ok)
		ret = 100.0 * fast / ok;
out:
	free(pages);
	free(status);
	return ret;
}

static void usage(const char *p)
{
	fprintf(stderr,
		"usage: %s [-s size_mb] [-H hot_mb] [-o hot_off_mb] [-t seconds]\n"
		"          [-b bind_mask] [-f fast_mask] [-T threads] [-r report_ms] [-n]\n"
		"  -n: use base pages (MADV_NOHUGEPAGE)\n",
		p);
	exit(2);
}

int main(int argc, char **argv)
{
	unsigned long cold_len, hot_end, last = 0, cur;
	pthread_t th[64];
	double t0, t, tl;
	int opt, i;

	while ((opt = getopt(argc, argv, "s:H:o:t:b:f:T:r:n")) != -1) {
		switch (opt) {
		case 's': size_mb = strtoul(optarg, NULL, 0); break;
		case 'H': hot_mb = strtoul(optarg, NULL, 0); break;
		case 'o': hot_off_mb = strtoul(optarg, NULL, 0); break;
		case 't': seconds = atoi(optarg); break;
		case 'b': bind_mask = strtoul(optarg, NULL, 0); break;
		case 'f': fast_mask = strtoul(optarg, NULL, 0); break;
		case 'T': nr_threads = atoi(optarg); break;
		case 'r': report_ms = atoi(optarg); break;
		case 'n': no_thp = 1; break;
		default: usage(argv[0]);
		}
	}
	if (hot_off_mb + hot_mb > size_mb || nr_threads < 1 || nr_threads > 64)
		usage(argv[0]);

	buf = mmap(NULL, size_mb * MB, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	madvise(buf, size_mb * MB, no_thp ? MADV_NOHUGEPAGE : MADV_HUGEPAGE);
	if (bind_mask &&
	    syscall(SYS_set_mempolicy, MPOL_BIND, &bind_mask, 64)) {
		perror("set_mempolicy");
		return 1;
	}
	memset(buf, 1, size_mb * MB);
	if (syscall(SYS_set_mempolicy, MPOL_DEFAULT, NULL, 0)) {
		perror("set_mempolicy default");
		return 1;
	}

	printf("ftier_hot pid=%d size_mb=%lu hot_mb=%lu off_mb=%lu\n",
	       getpid(), size_mb, hot_mb, hot_off_mb);
	fflush(stdout);

	for (i = 0; i < nr_threads; i++)
		pthread_create(&th[i], NULL, toucher, (void *)(unsigned long)i);

	hot_end = (hot_off_mb + hot_mb) * MB;
	cold_len = size_mb * MB - hot_end;
	t0 = tl = now();
	while ((t = now()) - t0 < seconds) {
		usleep(report_ms * 1000);
		t = now();
		cur = touches;
		printf("t=%.1f hot_fast=%.1f cold_fast=%.1f mtouch_s=%.2f\n",
		       t - t0, fast_share(hot_off_mb * MB, hot_mb * MB),
		       cold_len ? fast_share(hot_end, cold_len) : -1.0,
		       (cur - last) / (t - tl) / 1e6);
		fflush(stdout);
		last = cur;
		tl = t;
	}
	stop = 1;
	for (i = 0; i < nr_threads; i++)
		pthread_join(th[i], NULL);
	return 0;
}
