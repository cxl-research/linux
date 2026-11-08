.. SPDX-License-Identifier: GPL-2.0

=====================================
FTier: memory tiering for bandwidth
=====================================

:Author: Alan Nair <alannair1000@gmail.com>

FTier moves application memory between a DRAM tier and a CXL-attached
memory tier so that both tiers serve load at the same latency, which
maximises the memory bandwidth available to the application. Unlike
tiering for capacity, it migrates hot data in both directions: when DRAM
is congested, hot regions are demoted to CXL.

FTier has three parts:

- **Adaptive Frequency Scanning (AFS)** estimates the access frequency of
  every 2 MB region (PMD entry) of the target from the accessed bits of
  the page tables, at a cost independent of the page size.
- The **Hotlist** keeps those estimates in logarithmic hotness buckets
  and cools them over time.
- The **tiering loop** picks regions from the Hotlist and migrates their
  pages, at the rate and in the direction requested by a **tier latency
  monitor**, either directly or after filtering out cold pages with NUMA
  hint faults.

The internals are described in Documentation/mm/ftier.rst.

Requirements
============

``CONFIG_FTIER`` (x86-64; needs ``NUMA_BALANCING``, ``MIGRATION``,
``TRANSPARENT_HUGEPAGE`` and ``CGROUPS``). ``CONFIG_FTIER_CHA_MONITOR``
builds the ``ftier_cha`` latency monitor module for Intel Sapphire Rapids
and Emerald Rapids.

FTier needs at least one DRAM node and one CXL node with memory. It does
not use automatic NUMA balancing; boot with ``numa_balancing=disable`` or
leave it off so that the two do not fight over the same pages.

Quick start
===========

Track and tier the processes of cgroup ``/sys/fs/cgroup/app``, with the
in-tree monitor setting the migration rate::

    cd /sys/kernel/mm/ftier
    echo tiering > ftier_status
    echo hint_fault > ftier_tiering_mode
    echo app > target_cgroup
    modprobe ftier_cha

Stop::

    rmmod ftier_cha
    echo off > ftier_status

``ftier_status`` must be ``tracking`` or ``tiering`` before a target can
be set. Setting ``ftier_status`` to ``off`` releases all state.

Tiers
=====

``dram_nodes`` and ``cxl_nodes`` are node lists (``0-1``, ``2,3``).
Promotion moves pages from ``cxl_nodes`` to ``dram_nodes``, demotion the
other way; with several destination nodes, migrations are spread
round-robin, preferring the faulting CPU's node in hint-fault mode.
Nodes in neither list are left alone.

At boot, FTier keeps the layout of its evaluation server if it applies
(node 1 is DRAM with CPUs, CPU-less memory nodes above 1 are CXL);
otherwise the nodes in the top memory tier are DRAM and the remaining
memory nodes are CXL. The choice is logged (``ftier: DRAM nodes 1, CXL
nodes 2-3``).

Both lists must be non-empty, contain only nodes with memory and be
disjoint. They can be changed at any time.

Tier latency monitors
=====================

FTier does not decide on its own how much to migrate. A monitor measures
the tiers and sets the target rate, ``promote_mb``, in MB/s: positive to
promote, negative to demote, zero to stop. FTier caps it at
``max_migrate_mbps``. Monitors can report:

``ftier_cha`` (in tree)
    Measures the load latency of DRAM and CXL with the CHA TOR counters
    of one socket and applies the Colloid rule: bisect the share of
    requests served by DRAM until both tiers see the same latency. It
    polls every 100 ms and reports latencies, bandwidths and the rate
    through ``ftier_report_tier_state()``. It is not loaded
    automatically. Module parameters:

    ================== ======= ==========================================
    poll_ms            100     polling period
    max_mb             512     rate at full imbalance, MB/s
    delta_pc           2       latency difference ignored, % of DRAM
    eps                100     bisection resolution (1/10000 of the
                               DRAM share); 0 makes the rate
                               proportional to the latency gap instead
    dram_latency_offset 0      cycles added to the DRAM latency
    min_inserts        1000    requests per poll below which the tiers
                               count as idle
    node               auto    node whose socket is monitored; default
                               the first DRAM node with CPUs
    nr_cha             auto    CHAs per socket, a multiple of 8;
                               default the cores per package
    force              0       load on other CPU models
    verbose            0       log every sample
    ================== ======= ==========================================

    The module programs the CHA counters directly: do not use perf
    ``uncore_cha`` events, or another CHA-based monitor, while it is
    loaded. Unloading it clears the counters and sets ``promote_mb`` to 0.

User space
    Write ``promote_mb`` directly, or write a full sample to
    ``tier_report``::

        # dram_lat cxl_lat dram_mbps cxl_mbps promote_mb
        echo "310 520 41000 9000 128" > tier_report

    Latencies are in any common unit. A sample also feeds the adaptive
    hotness level (see below) with the latency gap.

Kernel modules
    Call ``ftier_report_tier_state()`` from ``<linux/ftier.h>``, or write
    ``sysctl_promote_mb`` (MB/s) as older monitors do.

Set ``monitor_timeout_ms`` to stop migrating when the monitor has not
reported for that long, so that a crashed monitor cannot leave a stale
rate in place (``nr_monitor_stale`` counts the affected ticks). Writes to
``promote_mb`` do not count as reports.

Tiering modes
=============

``demand_migrate``
    Pages of selected regions that sit on the source tier are migrated at
    once. Every page of a hot 2 MB region moves, cold or not.

``hint_fault``
    Pages of selected regions are protected, and a page only migrates
    when it is accessed again within the hint-fault latency threshold,
    which filters cold pages out of hot regions. Migration proceeds in
    rounds; each round protects up to the volume still due in the
    current interval and lasts the threshold of the round. Faults that
    would exceed the migration-rate cap are not migrated.

    ``hint_mode`` selects the threshold:

    ``median`` (default)
        1/h, for the median access frequency h of the regions selected
        in the round, clamped to [``hint_min_ms``, ``hint_max_ms``].
    ``fixed``
        ``hint_max_ms``.
    ``histogram``
        The filter of the original FTier code: the threshold passes the
        ``hint_pass_bp`` (basis points) fraction of recent faults with the
        lowest latency on each tier.

    PMD-mapped THPs on the CXL tier are protected and promoted whole.
    Demotion in hint-fault mode only applies to base pages, because the
    core THP code does not protect top-tier huge pages.

The adaptive hotness level
==========================

The hottest regions are not always the right ones to move: moving a very
hot region can swing the latency gap past balance, and the monitor then
moves it back. Once per ``level_period_ms``, FTier compares the latency
gap with the previous period. It selects colder regions
(``level_off`` + 1) if the gap changed sign (``overshoot``) or changed by
more than ``level_jump_pct`` percent while less than ``level_small_pct``
percent of the permitted volume moved (``sensitive``). It selects hotter
regions (``level_off`` - 1) if at least ``level_full_pct`` percent of the
permitted volume moved but the gap shrank by less than
``level_progress_pct`` percent (``slow``). Gaps within
``level_deadband_pm`` per mille count as balanced.

The gap is the reported (cxl_lat - dram_lat) / dram_lat when a sample
arrived within the last two periods, and otherwise the requested rate
relative to ``max_migrate_mbps``. ``level_adapt=0`` always uses the
hottest regions. The ``flevel`` tracepoint logs every decision.

The level-adaptation thresholds are not given by the FTier design and
their defaults have not been tuned on a wide range of workloads.

sysfs reference
===============

All files are in ``/sys/kernel/mm/ftier``. Values are validated: invalid
writes fail with ``EINVAL`` and leave the setting unchanged. Settings
take effect immediately, except ``nr_scanners``, which can only change
while ``ftier_status`` is ``off``.

State and targets
-----------------

==================== =========== ============================================
ftier_status         off         ``off``, ``tracking`` (AFS only) or
                                 ``tiering``
ftier_tiering_mode   demand      ``demand_migrate`` or ``hint_fault``
target_pid           0           track one process (its address space)
target_cgroup        (none)      track the processes of a cgroup v2, by path
                                 relative to the cgroup root; ``none``
                                 clears it
promote_mb           0           target migration rate, MB/s, signed
tier_report          (write)     monitor sample, see above
dram_nodes           auto        DRAM tier node list
cxl_nodes            auto        CXL tier node list
==================== =========== ============================================

AFS
---

==================== ======= ===================================================
interval_ms          1000    measurement interval; counts are reported to the
                             Hotlist once per interval (100-60000)
scans_per_interval   1000    S: scans of a PMD page per interval
init_period_us       50000   initial scan period of a PMD page (20 Hz)
min_period_us        50      fastest scan period
max_period_us        500000  slowest scan period
low_wm               3       fewer accessed entries per scan: slow down
high_wm_pct          60      more than this % of mapped entries accessed:
                             speed up
fscan_period_ms      10000   period of the PUD-level scan that finds active
                             PMD pages
pud_idle_scans       1       idle PUD scans after which a PMD page is dropped
nr_scanners          4       AFS scanner threads (1-64; not live)
slack_us             20      hrtimer slack of the scanners
track_thp            1       also count PMD-mapped THPs
notify_secondary     1       also query secondary MMUs (KVM) for accesses
flush_tlb            0       see below
min_pmds_per_fscan   -       alias of ``low_wm``
max_fhot_pc          -       alias of ``high_wm_pct``
fspin_ms             5000    unused; kept for compatibility
==================== ======= ===================================================

``flush_tlb``: x86 clears accessed bits without a TLB flush, and the CPU
sets the accessed bit of a PMD entry mapping a THP only on a TLB miss. A
hot THP whose translation stays in the TLB therefore looks idle. ``0``
never flushes (the design); ``1`` flushes the scanned range after
clearing the accessed bit of a THP mapping; ``2`` flushes after clearing
any accessed bit. Flushes send IPIs to the CPUs running the target, and
``nr_tlb_flush`` counts them. Use ``1`` for THP-backed targets whose hot
set is small enough to stay in the TLB.

Hotlist and tiering
-------------------

==================== ======= ===================================================
tick_ms              100     tiering loop period (10-1000, at most interval_ms)
cool_ms              2000    Hotlist cooling period: hotness halves
max_migrate_mbps     1024    global migration-rate cap, MB/s
migrate_batch        512     folios per migrate_pages() call
max_candidates       256     regions with pages to move per tick
residency_epochs     8       cooling periods for which a region found to have
                             nothing to move is skipped
hint_mode            median  ``median``, ``fixed`` or ``histogram``
hint_min_ms          1       lower bound of the hint-fault threshold
hint_max_ms          1000    upper bound; the threshold in ``fixed`` mode
hint_pass_bp         10000   ``histogram`` mode pass ratio, basis points
hint_thresh_ms       (read)  current threshold
level_adapt          1       adaptive hotness level
level_period_ms      1000    adaptation period
level_small_pct      25      "little" volume, % of the permitted volume
level_full_pct       90      "near the cap", % of the permitted volume
level_jump_pct       50      "large" gap change, % of the previous gap
level_progress_pct   10      sufficient gap reduction, %
level_deadband_pm    20      balanced gap, per mille
level_off            (read)  current level offset below the hottest level
monitor_timeout_ms   0       stale monitor timeout; 0 disables
hint_fault_latency_threshold_ms - alias of ``hint_max_ms``
hf_pass_ratio_bp     -       alias of ``hint_pass_bp``
==================== ======= ===================================================

Observability
=============

``stats``
    Counters since FTier was last started, one ``name value`` pair per
    line:

    - tracked state: ``nr_spaces``, ``nr_puds`` (PMD pages under AFS),
      ``nr_hot_entries``;
    - AFS cost: ``nr_fscans``/``fscan_us`` (PUD scans),
      ``nr_pmd_scans``/``pmd_scan_us`` (PMD-page scans and their CPU
      time), ``nr_tlb_flush``, ``nr_intervals``/``collect_us``,
      ``nr_throttled`` (PMD-page intervals that used up S),
      ``nr_lock_miss`` (scans skipped on mmap lock contention);
    - churn: ``nr_pud_added``, ``nr_pud_removed``, ``nr_space_added``,
      ``nr_space_removed``, ``nr_cool``;
    - tiering: ``nr_tier_ticks``/``tier_us`` (loop CPU time),
      ``nr_promoted``, ``nr_demoted`` (demand mode), ``nr_migrate_fail``,
      ``nr_protected`` (hint mode), ``nr_overrun`` (loop iterations
      longer than ``tick_ms``),
      ``nr_rounds``, ``nr_level_colder``, ``nr_level_hotter``,
      ``nr_monitor_stale``;
    - hint faults: ``nr_hint_faults``, ``nr_hint_migrate``, and the
      rejections ``nr_hint_reject_tier`` (not from a source node),
      ``nr_hint_reject_lat`` (too slow) and ``nr_hint_reject_rate``
      (over the rate cap).

``hotlist``
    ``epoch E entries N discarded D``, then one ``level entries MB`` line
    per non-empty hotness level, hottest first.

Tracepoints (``events/ftier``)
    ========= =========================================================
    fscan     a PUD-level scan of a target: PMD pages found, duration
    fspin     one interval of a PMD page: scans, final period, scale
    fhist     at each cooling: MB tracked per hotness level
    fhotlist  Hotlist size after each interval
    fmigrate  every tiering tick: regions, pages, budget, level
    fregion   every region handled: source/destination pages, moved
    fround    every hint-fault round: regions, pages, median, threshold
    flevel    every hotness-level decision and its reason
    ftier_tier every monitor report
    fhint     hint-fault latency histogram, ``histogram`` mode
    ========= =========================================================

Overheads
=========

- AFS: about 20 us of CPU time per PMD-page scan on a Xeon Gold 5418Y
  (measured). The worst case is (memory / 1 GB) x S scans per interval;
  lower ``scans_per_interval`` or raise ``min_period_us`` to bound it.
  ``pmd_scan_us`` reports the actual cost.
- Memory: 32 bytes per tracked 2 MB region plus 4 KB per tracked GB for
  the lookup table.
- Tiering: at most 90% of ``tick_ms`` per tick (``tier_us``); migration
  bandwidth is bounded by ``max_migrate_mbps``.
- Hint-fault mode adds one minor fault per protected page.

Testing
=======

``tools/testing/selftests/mm/ftier`` contains a functional and robustness
suite. ``run_vm.sh <bzImage> <log>`` runs it in a QEMU VM with two DRAM
and two CXL-like nodes (described by HMAT); on a host with FTier,
``ftier_vmtest.sh`` runs it directly (see the variables at its top).
