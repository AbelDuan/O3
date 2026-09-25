#!/usr/bin/env bash
# One-shot evidence grab after the run2 crash. Run as soon as adb is authorized.
set -u
S=${1:-<LAN-IP>:5555}
export ADB_LOCAL_TRANSPORT_MAX_PORT=5553
export HOME=/tmp/adbstd
OUT=/root/projects/cve-hunt/evidence-run2
mkdir -p "$OUT"
say(){ printf '\n=== %s ===\n' "$*"; }

say "0. device state (compare boot_id to baseline 21acd92f-6455-4fca-9564-367ca91a64fa)"
adb -s $S shell "cat /proc/sys/kernel/random/boot_id; uptime; cat /sys/fs/selinux/enforce; echo" 2>&1 | tee "$OUT/post-baseline.txt"

say "1. app log — owner/mtime tell us if it is the NEW run"
adb -s $S shell "stat -c '%y %U %s' /sdcard/Android/data/o3.ennea.pocv1/files/last-64560.log" 2>&1 | tee -a "$OUT/post-baseline.txt"
adb -s $S shell "cat /sdcard/Android/data/o3.ennea.pocv1/files/last-64560.log" > "$OUT/last-64560-run2.log" 2>&1
echo "lines: $(wc -l < "$OUT/last-64560-run2.log")"

say "2. did PIPE_COUNT take effect? (expect pairs=10000 fragments=30000)"
grep -oE "pairs=[0-9]+ fragments=[0-9]+" "$OUT/last-64560-run2.log" | sort -u
say "3. reclaim gate result (the decisive line)"
grep -oE "ORDER1_RECLAIM_GATE .*" "$OUT/last-64560-run2.log" || echo "(none)"
say "4. hit-slot lines (expected 0 if still missing)"
grep -c "DIRECT_CRED_HIT_SLOT" "$OUT/last-64560-run2.log" || true
say "5. reaper / reap lines (stage-1 had exactly 1)"
grep -nE "REAPER|VICTIM_REAP|WATCHER_REAP" "$OUT/last-64560-run2.log" || echo "(none)"
say "6. tail"
tail -15 "$OUT/last-64560-run2.log"

say "7. bugreportz for the new pstore"
adb -s $S shell bugreportz 2>&1 | tail -2
