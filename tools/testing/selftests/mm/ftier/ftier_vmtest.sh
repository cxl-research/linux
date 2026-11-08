#!/bin/sh
# SPDX-License-Identifier: GPL-2.0
#
# FTier functional and robustness tests. Runs inside a VM (or on a test
# host) with nodes 0-1 as the fast tier and nodes 2-3 as the slow tier.
#
# Copyright (c) 2025-2026 Alan Nair <alannair1000@gmail.com>

F=/sys/kernel/mm/ftier
T=/sys/kernel/tracing
[ -d $T/events/ftier ] || T=/sys/kernel/debug/tracing
HOT=${HOT:-./ftier_hot}
SIZE=${SIZE:-1024}
HOTMB=${HOTMB:-128}
# The FTier tiers are currently fixed: node 1 is DRAM, nodes 2-3 are CXL.
FAST=0x2
SLOW=0xc
PG=${PG--n}		# ftier_hot page-size flag: -n for base pages, "" for THP
nr_pass=0
nr_fail=0

pass() { nr_pass=$((nr_pass + 1)); echo "TEST $1 PASS ${2:-}"; }
fail() {
	nr_fail=$((nr_fail + 1))
	echo "TEST $1 FAIL ${2:-}"
	echo "--- vmstat"
	grep -E "^(numa_|pgmigrate|thp_migration|pgpromote|pgdemote|thp_split)" /proc/vmstat | tr '\n' ' '
	echo
	echo "--- trace head (HPID=$HPID)"
	head -40 $T/trace
	echo "--- trace tail"
	grep -v ' 0, done=0' $T/trace | tail -30
}
check() { if [ "$2" -eq 1 ]; then pass "$1" "$3"; else fail "$1" "$3"; fi; }
stat() { awk -v k="$1" '$1 == k { print $2 }' $F/stats; }
w() { echo "$2" > "$F/$1" 2>/dev/null; }

# Last reported hot/cold fast-tier share from an ftier_hot log.
last_share() { awk -F'[ =]' '/^t=/ { h = $4; c = $6 } END { print int(h) " " int(c) }' "$1"; }

reset() {
	echo 0 > $T/events/ftier/enable
	echo > $T/trace
	echo 1 > $T/events/ftier/fmigrate/enable
	echo 1 > $T/events/ftier/fregion/enable
	w ftier_status off
	w promote_mb 0
	w target_pid 0
	w target_cgroup ""
	w ftier_tiering_mode demand_migrate
	w fscan_period_ms 1000
	w cool_ms 1000
	w max_migrate_mbps 1024
	w flush_tlb ${FLUSH:-0}
}

start_hot_pg() { l=$1; shift; start_hot "$l" $PG -f $FAST "$@"; }

start_hot() {	# $1 = log, rest = ftier_hot args
	log=$1; shift
	$HOT "$@" > "$log" 2>&1 &
	HPID=$!
	i=0
	while ! grep -q '^t=' "$log" 2>/dev/null && [ $i -lt 60 ]; do
		sleep 1; i=$((i + 1))
	done
}

t_sysfs() {
	ok=1
	for a in ftier_status ftier_tiering_mode target_pid target_cgroup \
		 promote_mb migrate_batch hint_fault_latency_threshold_ms \
		 scans_per_interval interval_ms tick_ms stats hotlist \
		 min_pmds_per_fscan max_fhot_pc fspin_ms; do
		[ -r $F/$a ] || { ok=0; echo "missing $a"; }
	done
	check sysfs_present $ok
	check sysfs_default_off "$(grep -c '^off$' $F/ftier_status)" \
		"$(cat $F/ftier_status)"
}

t_invalid() {
	ok=1
	for kv in "ftier_status bogus" "ftier_tiering_mode bogus" \
		  "promote_mb abc" "promote_mb 999999999" "tick_ms 0" \
		  "interval_ms 1" "high_wm_pct 0" "high_wm_pct 101" \
		  "target_pid -1" "migrate_batch 0" "migrate_batch 100000"; do
		set -- $kv
		if echo "$2" > $F/$1 2>/dev/null; then
			ok=0; echo "accepted: $kv"
		fi
	done
	w min_period_us 50
	w max_period_us 500000
	echo 40 > $F/max_period_us 2>/dev/null && { ok=0; echo "max<min accepted"; }
	echo 1000000 > $F/min_period_us 2>/dev/null && { ok=0; echo "min>max accepted"; }
	echo 2000 > $F/tick_ms 2>/dev/null && { ok=0; echo "tick>interval accepted"; }
	echo $$ > $F/target_pid 2>/dev/null && { ok=0; echo "target_pid accepted while off"; }
	w ftier_status tracking
	long=$(head -c 5000 /dev/zero | tr '\0' a)
	echo "$long" > $F/target_cgroup 2>/dev/null && { ok=0; echo "long cgroup accepted"; }
	echo nonexistent > $F/target_cgroup 2>/dev/null && { ok=0; echo "bad cgroup accepted"; }
	echo 999999 > $F/target_pid 2>/dev/null && { ok=0; echo "dead pid accepted"; }
	echo 8 > $F/nr_scanners 2>/dev/null && { ok=0; echo "nr_scanners changed while on"; }
	w ftier_status off
	check invalid_input_rejected $ok
}

t_tracking() {
	reset
	start_hot_pg /tmp/track.log -s $SIZE -H $HOTMB -t 25 -b $SLOW
	w ftier_status tracking
	w target_pid $HPID
	sleep 15
	cat $F/stats; cat $F/hotlist
	check tracking_hotlist "$([ "$(stat nr_hot_entries)" -gt 0 ] && echo 1 || echo 0)" \
		"entries=$(stat nr_hot_entries)"
	check tracking_scans "$([ "$(stat nr_pmd_scans)" -gt 0 ] && echo 1 || echo 0)" \
		"scans=$(stat nr_pmd_scans)"
	check tracking_no_migration "$([ "$(stat nr_promoted)" -eq 0 ] && echo 1 || echo 0)"
	w ftier_status off
	kill $HPID 2>/dev/null; wait $HPID 2>/dev/null
}

t_promote() {	# $1 = mode
	reset
	w ftier_tiering_mode $1
	w hint_fault_latency_threshold_ms 1000
	start_hot_pg /tmp/prom-$1.log -s $SIZE -H $HOTMB -o 256 -t 40 -b $SLOW
	set -- $1 $(last_share /tmp/prom-$1.log)
	before=$2
	w promote_mb 64
	w ftier_status tiering
	w target_pid $HPID
	sleep 30
	set -- $1 $(last_share /tmp/prom-$1.log)
	cat $F/stats; tail -3 /tmp/prom-$1.log
	check promote_$1 "$([ "$2" -ge 80 ] && echo 1 || echo 0)" \
		"hot_fast ${before}->$2 cold_fast=$3"
	check promote_$1_cold_left "$([ "$3" -le 50 ] && echo 1 || echo 0)" \
		"cold_fast=$3"
	w ftier_status off
	kill $HPID 2>/dev/null; wait $HPID 2>/dev/null
}

t_demote() {
	reset
	start_hot_pg /tmp/demote.log -s $SIZE -H $HOTMB -t 35 -b $FAST
	w promote_mb -64
	w ftier_status tiering
	w target_pid $HPID
	sleep 25
	set -- $(last_share /tmp/demote.log)
	cat $F/stats
	check demote_demand "$([ "$1" -le 20 ] && echo 1 || echo 0)" \
		"hot_fast=$1 demoted=$(stat nr_demoted)"
	w ftier_status off
	kill $HPID 2>/dev/null; wait $HPID 2>/dev/null
}

t_cgroup() {
	reset
	mkdir -p /sys/fs/cgroup/ftier
	start_hot_pg /tmp/cg1.log -s 512 -H 64 -t 35 -b $SLOW
	p1=$HPID
	start_hot_pg /tmp/cg2.log -s 512 -H 64 -t 35 -b $SLOW
	p2=$HPID
	echo $p1 > /sys/fs/cgroup/ftier/cgroup.procs
	echo $p2 > /sys/fs/cgroup/ftier/cgroup.procs
	w promote_mb 64
	w ftier_status tiering
	w target_cgroup ftier
	sleep 25
	set -- $(last_share /tmp/cg1.log) $(last_share /tmp/cg2.log)
	check cgroup_spaces "$([ "$(stat nr_spaces)" -eq 2 ] && echo 1 || echo 0)" \
		"spaces=$(stat nr_spaces)"
	check cgroup_promote "$([ "$1" -ge 80 ] && [ "$3" -ge 80 ] && echo 1 || echo 0)" \
		"hot_fast p1=$1 p2=$3"
	w ftier_status off
	kill $p1 $p2 2>/dev/null; wait $p1 $p2 2>/dev/null
}

t_exit() {
	reset
	start_hot_pg /tmp/exit.log -s 512 -H 64 -t 5 -b $SLOW
	w promote_mb 64
	w ftier_status tiering
	w target_pid $HPID
	wait $HPID 2>/dev/null
	sleep 5
	check exit_space_released "$([ "$(stat nr_spaces)" -eq 0 ] && echo 1 || echo 0)" \
		"spaces=$(stat nr_spaces) puds=$(stat nr_puds) hot=$(stat nr_hot_entries)"
	check exit_hotlist_empty "$([ "$(stat nr_hot_entries)" -eq 0 ] && echo 1 || echo 0)"
	w ftier_status off
}

t_trace() {
	reset
	echo > $T/trace
	for e in fhist fmigrate fscan fspin fhotlist fregion; do
		echo 1 > $T/events/ftier/$e/enable
	done
	start_hot_pg /tmp/trace.log -s 512 -H 64 -t 12 -b $SLOW
	w promote_mb 64
	w ftier_status tiering
	w target_pid $HPID
	sleep 8
	w ftier_status off
	echo 0 > $T/events/ftier/enable
	for e in fhist fmigrate fscan fspin fhotlist fregion; do
		n=$(grep -c " $e:" $T/trace)
		check trace_$e "$([ "$n" -gt 0 ] && echo 1 || echo 0)" "n=$n"
	done
	kill $HPID 2>/dev/null; wait $HPID 2>/dev/null
}

t_churn() {	# $1 = iterations
	iters=$1
	reset
	mkdir -p /sys/fs/cgroup/ftier
	w interval_ms 200
	w tick_ms 20
	w fscan_period_ms 1000
	pids=""
	for i in 1 2 3 4; do
		$HOT $PG -s 256 -H 32 -t 600 -b $SLOW -r 100000 > /dev/null 2>&1 &
		pids="$pids $!"
	done
	set -- $pids
	n=0
	while [ $n -lt $iters ]; do
		n=$((n + 1))
		r=$(awk -v s=$n 'BEGIN { srand(s); print int(rand() * 12) }')
		case $r in
		0) w ftier_status off ;;
		1) w ftier_status tracking ;;
		2|3) w ftier_status tiering ;;
		4) w target_pid "$(echo $pids | awk -v s=$n '{ srand(s); print $(int(rand() * NF) + 1) }')" ;;
		5) for p in $pids; do echo $p > /sys/fs/cgroup/ftier/cgroup.procs 2>/dev/null; done
		   w target_cgroup ftier ;;
		6) w promote_mb $(( (n % 7 - 3) * 32 )) ;;
		7) w ftier_tiering_mode hint_fault ;;
		8) w ftier_tiering_mode demand_migrate ;;
		9) w ftier_status off; w nr_scanners $((n % 6 + 1)) ;;
		10) # Kill and replace one workload while it may be scanned.
		    victim=$(echo $pids | awk '{ print $1 }')
		    kill -9 $victim 2>/dev/null; wait $victim 2>/dev/null
		    $HOT $PG -s 256 -H 32 -t 600 -b $SLOW -r 100000 > /dev/null 2>&1 &
		    pids="$(echo $pids | cut -d' ' -f2-) $!" ;;
		11) w scans_per_interval $((n * 37 % 2000 + 1)); w init_period_us $((n * 101 % 100000 + 50)) ;;
		esac
		cat $F/stats $F/hotlist > /dev/null
		sleep 0.$((n % 3))
	done
	w ftier_status off
	for p in $pids; do kill -9 $p 2>/dev/null; done
	wait 2>/dev/null
	w interval_ms 1000
	w tick_ms 100
	w nr_scanners 4
	pass churn "iterations=$iters"
}

t_dmesg() {
	if dmesg | grep -E 'BUG:|WARNING:|possible circular|inconsistent lock|INFO: task|INFO: rcu|sleeping function|list_(add|del) corruption|Oops|general protection|stack-protector|refcount_t:|ODEBUG|kmemleak:.*new suspected|soft lockup|hard LOCKUP' > /tmp/dmesg.bad; then
		fail dmesg_clean "$(head -c 2000 /tmp/dmesg.bad)"
		dmesg | tail -200
	else
		pass dmesg_clean
	fi
}

TESTS=${TESTS:-"sysfs invalid tracking promote_demand promote_hint demote cgroup exit trace churn dmesg"}
for t in $TESTS; do
	echo "=== $t"
	case $t in
	promote_demand) t_promote demand_migrate ;;
	promote_hint) t_promote hint_fault ;;
	churn) t_churn ${CHURN:-300} ;;
	*) t_$t ;;
	esac
done
reset
echo "RESULT pass=$nr_pass fail=$nr_fail"
[ $nr_fail -eq 0 ]
