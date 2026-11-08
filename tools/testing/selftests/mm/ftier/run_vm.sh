#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
#
# Boot a kernel in QEMU with an emulated two-tier NUMA topology and run
# ftier_vmtest.sh inside it.
#
#   [FTIER_CHA_KO=ftier_cha.ko] run_vm.sh <bzImage> <logfile> [VAR=value...]
#
# Nodes 0-1 have CPUs and low HMAT latency; nodes 2-3 are CPU-less with
# higher latency so the kernel places them in a lower memory tier.
#
# Copyright (c) 2025-2026 Alan Nair <alannair1000@gmail.com>

set -euo pipefail

KERNEL=$1
LOG=$2
shift 2
DIR=$(cd "$(dirname "$0")" && pwd)
WORK=$(mktemp -d /tmp/ftier-vm.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

gcc -O2 -static -pthread -o "$WORK/ftier_hot" "$DIR/ftier_hot.c"

mkdir -p "$WORK"/root/{bin,sbin,proc,sys,dev,tmp,etc}
cp "$(command -v busybox)" "$WORK/root/bin/busybox"
for app in $("$WORK/root/bin/busybox" --list); do
	[ "$app" = busybox ] || ln -sf busybox "$WORK/root/bin/$app"
done
cp "$WORK/ftier_hot" "$DIR/ftier_vmtest.sh" "$WORK/root/"
# The CHA monitor module, tested for clean refusal (no CHA MSRs in a VM).
if [ -n "${FTIER_CHA_KO:-}" ]; then
	cp "$FTIER_CHA_KO" "$WORK/root/ftier_cha.ko"
	set -- "$@" CHA=fail CHA_KO=/ftier_cha.ko
else
	set -- "$@" CHA=skip
fi

envs=""
for kv in "$@"; do
	envs="$envs export $(printf '%q' "$kv");"
done

cat > "$WORK/root/init" <<EOF
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /tmp
mount -t cgroup2 cgroup2 /sys/fs/cgroup
mount -t debugfs debugfs /sys/kernel/debug
mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null
echo "+memory +cpuset" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
cd /
echo "--- memory tiers"
for f in /sys/devices/virtual/memory_tiering/memory_tier*/nodelist; do
	echo "\$f: \$(cat \$f)"
done
cat /sys/kernel/mm/transparent_hugepage/enabled
$envs
HOT=/ftier_hot sh /ftier_vmtest.sh
echo "VMTEST_EXIT=\$?"
sync
poweroff -f
EOF
chmod +x "$WORK/root/init"
(cd "$WORK/root" && find . | cpio -o -H newc --quiet | gzip -1) > "$WORK/initrd.gz"

numa=(-object memory-backend-ram,id=m0,size=3G
      -object memory-backend-ram,id=m1,size=3G
      -object memory-backend-ram,id=m2,size=2G
      -object memory-backend-ram,id=m3,size=2G
      -numa node,nodeid=0,cpus=0-3,memdev=m0,initiator=0
      -numa node,nodeid=1,cpus=4-7,memdev=m1,initiator=1
      -numa node,nodeid=2,memdev=m2,initiator=0
      -numa node,nodeid=3,memdev=m3,initiator=1)
for i in 0 1; do
	for t in 0 1 2 3; do
		if [ "$t" -eq "$i" ]; then lat=80; bw=40G
		elif [ "$t" -lt 2 ]; then lat=140; bw=20G
		else lat=300; bw=10G; fi
		numa+=(-numa "hmat-lb,initiator=$i,target=$t,hierarchy=memory,data-type=access-latency,latency=$lat"
		       -numa "hmat-lb,initiator=$i,target=$t,hierarchy=memory,data-type=access-bandwidth,bandwidth=$bw")
	done
done

timeout ${VM_TIMEOUT:-1800} qemu-system-x86_64 \
	-machine q35,hmat=on -enable-kvm -cpu host -smp 8 -m 10G \
	"${numa[@]}" \
	-kernel "$KERNEL" -initrd "$WORK/initrd.gz" \
	-append "console=ttyS0 panic=-1 oops=panic panic_on_warn=0 transparent_hugepage=always numa_balancing=disable kasan.fault=report softlockup_panic=0 loglevel=6" \
	-nographic -no-reboot -serial mon:stdio 2>&1 | tee "$LOG" | grep -E --line-buffered '^(TEST|RESULT|===|VMTEST)|Kernel panic|BUG:|KASAN'
grep -q 'VMTEST_EXIT=0' "$LOG"
