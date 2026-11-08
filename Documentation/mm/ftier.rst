.. SPDX-License-Identifier: GPL-2.0

===============
FTier internals
===============

:Author: Alan Nair <alannair1000@gmail.com>

This document describes the implementation of FTier in ``mm/ftier``. For
the interface and tuning, see Documentation/admin-guide/mm/ftier.rst.

Files
=====

============== ===========================================================
core.c         targets, tracked address spaces, PUD-level scan, main thread
afs.c          Adaptive Frequency Scanning of PMD pages, scanner threads
hotlist.c      the Hotlist
tiering.c      candidate selection, adaptive hotness level, migration
hint.c         hint-fault filter and migration credit
sysfs.c        ``/sys/kernel/mm/ftier``
cha.c          ``ftier_cha`` latency monitor module
internal.h     shared data structures
============== ===========================================================

Outside ``mm/ftier``: ``include/linux/ftier.h`` (the interface for
monitors and core mm), ``include/trace/events/ftier.h``, the hint-fault
hook in ``numa_migrate_check()`` (``mm/memory.c``) and the tier
membership checks in ``mm/memory-tiers.c``.

Threads and locking
===================

- The **main thread** (``ftier``) runs every ``tick_ms``. It reconciles
  the tracked address spaces with the target, runs the PUD-level scan
  every ``fscan_period_ms``, collects AFS counts into the Hotlist every
  ``interval_ms``, cools the Hotlist every ``cool_ms`` and, when tiering,
  runs the tiering tick with the time left in 90% of the tick.
- A pool of ``nr_scanners`` **scanner threads** (``ftier_afs/N``) scans
  PMD pages.
- **Hint faults** run in the faulting task with the page table lock held.

Locks, outermost first:

``ftier_state_lock`` (mutex)
    Serialises state changes from sysfs: start and stop, target changes,
    and the tier node lists.
``ftier_lock`` (mutex)
    Protects the target, the tracked spaces, their PUDs and the Hotlist.
    The main thread holds it while it works and drops it while sleeping.
    Scanners never take it.
scanner ``lock`` (spinlock, per scanner)
    Protects the scanner's timerqueue and the scan state of the PUDs it
    owns.
``ftier_tier.lock`` (spinlock, irqsave)
    The latest monitor sample. Monitors may report from any context.

The hint-fault path takes no lock: it uses atomics and reads the target
set through an RCU-protected hash of target mms.

Address spaces are pinned with ``mmgrab()`` while tracked. They are only
walked after ``mmget_not_zero()`` and under ``mmap_read_trylock()``, so
the exit of a target or the reuse of its pid never leaves dangling
pointers, and FTier never queues behind a writer of the target's mmap
lock (``nr_lock_miss`` counts skipped scans). Targets are held by
``struct pid`` and ``struct cgroup`` references.

Data structures
===============

``struct ftier_space``
    A tracked mm and its list of tracked PMD pages.
``struct ftier_pud``
    One active PUD entry, i.e. one page of 512 PMD entries (1 GB). It
    holds the AFS state of that page (16-bit counters, scan period,
    interval budget) and the lookup table of its Hotlist entries
    (``hot[512]``, 4 KB).
``struct ftier_hot`` (32 bytes)
    A Hotlist entry for one PMD entry (2 MB): bucket link, stored
    hotness and the epoch at which it was stored, its index in the PUD,
    and residency flags.
``struct ftier_hotlist``
    ``FTIER_HOT_LEVELS`` (32) buckets, their sizes and the current epoch.

AFS
===

PUD level
    Every ``fscan_period_ms`` the main thread walks the PUD entries of
    each tracked mm, test-and-clears their accessed bits and starts
    tracking the PMD pages of accessed entries. A PMD page whose PUD entry
    stays idle for more than ``pud_idle_scans`` consecutive scans is
    dropped, and so are pages whose PUD entry disappears.

PMD level
    Each PMD page is owned by one scanner, which keeps its pages in a
    timerqueue ordered by deadline and sleeps on an hrtimer in between,
    so short periods do not busy-wait. A scan test-and-clears the
    accessed bit of the 512 PMD entries and increments the counters of
    the accessed ones (saturating at 65535). With ``track_thp``, entries
    mapping THPs are counted too; with ``notify_secondary``, the secondary
    MMUs (KVM) are queried through the mmu notifiers.

    After each scan the period adapts: fewer than ``low_wm`` accessed
    entries doubles it, more than ``high_wm_pct`` percent of the mapped
    entries halves it, within [``min_period_us``, ``max_period_us``].
    The period is also kept at least twice the duration of the last
    scan, so a scanner spends at most half its time on one page. A page
    starts at ``init_period_us`` (20 Hz).

    A page is scanned at most ``scans_per_interval`` (S) times per
    interval. When it runs out early, scanning pauses until the next
    interval, and the counts are scaled by interval / observed time
    (bounded) when they are collected, assuming a stationary access
    rate.

TLB
    x86 does not flush the TLB when clearing accessed bits. A PMD entry
    that maps a page of PTEs is still marked accessed by page walks
    after TLB misses on its leaves, but a PMD leaf (THP) is only marked
    on a miss of its own 2 MB translation. ``flush_tlb`` optionally
    flushes the range of a scan with ``flush_tlb_mm_range()``.

Hotlist
=======

An entry with effective hotness H is in the bucket of level
``ilog2(H)``. Positions in the bucket array are relative to the epoch:
the bucket of level L is at ``(L + epoch) % 32``. Cooling increments the
epoch, which halves every entry's effective hotness without touching it
(``hotness >> (epoch - entry epoch)``). Only the entries of the bucket
that would become level -1 are discarded, so cooling costs O(that bucket)
regardless of the Hotlist size.

When AFS reports a count for an entry, the count is added to its
effective hotness and the entry moves to the tail of its new bucket. An
entry whose bucket does not change keeps its place. AFS looks entries up
through ``ftier_pud::hot``, in O(1).

Because of the relative positions, entries change bucket at every
cooling even when their level stays the same, and they are relinked in
the order AFS reports them (address order). The selection below must
not rely on bucket order across cooling periods.

Candidate selection and migration
=================================

Each tiering tick:

1. **Signal.** Read ``promote_mb`` and the latest monitor sample. With
   ``monitor_timeout_ms`` set and no report within it, the rate is 0. The
   rate is capped by ``max_migrate_mbps``; its sign gives the direction,
   and the source and destination node masks follow.
2. **Hotness level.** Once per ``level_period_ms``, ``adapt_level()``
   updates ``level_off`` from the change of the latency gap and the
   volume moved in the period (see the admin guide).
3. **Candidates.** ``collect_candidates()`` walks the buckets from the
   hottest non-empty level minus ``level_off`` downwards and collects up
   to ``FTIER_MAX_CANDIDATES`` (1024) entries, skipping entries whose
   residency flags say they have nothing to move in this direction.
4. **Regions.** Each candidate is handled in turn (``tier_region()``)
   until ``max_candidates`` regions with pages to move have been
   handled, the page budget is met or the time budget runs out. Handled
   entries rotate to the tail of their bucket.

``demand_migrate``
    The tick's budget is a credit that accrues at the target rate (up to
    one second's worth). The pages of a region on source nodes are
    isolated (``folio_isolate_lru()``; shared folios are skipped, as with
    ``mbind(MPOL_MF_MOVE)``) and migrated with ``migrate_pages()`` in
    ``migrate_batch`` batches, round-robin over the destination nodes.
    Allocation never enters direct reclaim (``GFP_NOWAIT``-like flags
    plus ``__GFP_KSWAPD_RECLAIM``), so a full destination fails fast.

``hint_fault``
    Migration proceeds in rounds. At the start of each interval, the
    target volume for the interval is set from the rate. When the
    previous round has ended and the volume is not met, a new round
    protects pages of the selected regions up to the remaining volume:
    PTEs of source-node pages are made ``PROT_NONE`` (under the PTE lock,
    with mmu notifier invalidation and batched TLB flushes through
    ``mmu_gather``) and their folios are stamped with the current time.
    PMD-mapped THPs are protected with ``change_huge_pmd()``, which only
    protects non-top-tier memory. The round's threshold is computed from
    the hotness of the regions that had pages to protect, and the round
    lasts that long (at least one tick); rounds that protected nothing
    end at once.

    The next access to a protected page raises a NUMA hint fault, and
    ``numa_migrate_check()`` calls ``ftier_hint_fault()`` for target
    mms. It checks that the page is on a source node, computes the hint
    fault latency from the folio's access time, compares it with the
    threshold, and takes one credit per page from a counter refilled by
    the tiering loop at the target rate. If all pass, it returns the
    destination node (the local node if it is a destination, otherwise
    round-robin) and the core NUMA code migrates the folio. Any other
    outcome returns ``NUMA_NO_NODE`` and the fault only restores the PTE.

Threshold
    In steady state, an entry's hotness averages about 1.5x the accesses
    AFS counts per cooling period, so a region of hotness H is accessed
    about h = H / (1.5 x ``cool_ms``) times per millisecond. A page
    accessed at that rate is expected to fault within 1/h ms. The median
    over the round's regions is used, clamped to [``hint_min_ms``,
    ``hint_max_ms``].

Residency flags
    When a region is found to have no pages on the source tier (or all of
    them moved), it is flagged as such, stamped with the epoch, and
    skipped for ``residency_epochs`` cooling periods. FTier's own
    migrations update the flags, so they only go stale when pages move or
    are allocated outside FTier.

Monitor interface
=================

``ftier_report_tier_state()`` stores a ``struct ftier_tier_sample``
(latencies, bandwidths and the requested rate) with its time, sets
``sysctl_promote_mb`` and emits ``ftier_tier``. It can be called from
any context. ``ftier_dram_nodes`` and ``ftier_cxl_nodes`` are exported
for monitors that need the tier layout.

``ftier_cha`` programs, in every group of 8 CHAs of the monitored socket,
CHA i to count the TOR occupancy of one request class (demand read,
RFO, and their prefetches; to DRAM or CXL), and CHAs 2k and 2k + 1 to
count the DRAM and CXL inserts of class k. Occupancy over inserts gives
the latency of each tier (Little's law), with the CXL counts subtracted
from the DRAM ones because the DRAM filters also match CXL. Counters are
read with ``rdmsrq_safe_on_cpu()`` on a CPU of the socket; if that CPU
goes offline, the monitor moves to another one and reprograms the CHAs.

Testing
=======

``tools/testing/selftests/mm/ftier``:

``ftier_hot.c``
    A workload with a hot and a cold part of configurable size, binding
    and page size, reporting the share of each on the fast tier.
``ftier_vmtest.sh``
    The tests: interface and input validation, tracking, promotion and
    demotion in each mode and threshold mode, fewer candidates than hot
    regions, multi-node tiers, level adaptation, monitor staleness, the
    CHA monitor, cgroup targets, target exit, every tracepoint, a
    randomised churn of state and tunable changes while targets are
    killed, and a final scan of the kernel log for warnings, lockdep,
    KASAN and RCU reports.
``run_vm.sh``
    Runs the tests in a QEMU VM with HMAT-described tiers, meant for
    kernels with KASAN, lockdep and ``DEBUG_VM``.
