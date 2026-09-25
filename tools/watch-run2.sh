#!/usr/bin/env bash
# Watch an Ennea run and capture the crash point. Distinguishes NEW log from stale.
# Usage: bash watch-run2.sh [seconds]
set -u
S=<LAN-IP>:5555
export ADB_LOCAL_TRANSPORT_MAX_PORT=5553
export HOME=/tmp/adbstd
DUR=${1:-300}
OUT=/root/projects/cve-hunt/evidence-run2
mkdir -p "$OUT"
LOG=/sdcard/Android/data/o3.ennea.pocv1/files/last-64560.log

echo "=== watch start $(date -u +%H:%M:%S) ==="
BASE_EPOCH=$(date +%s)
prev_size=0
end=$(( BASE_EPOCH + DUR ))

while [ "$(date +%s)" -lt "$end" ]; do
  if ! adb -s $S get-state >/dev/null 2>&1; then
    echo "[$(date -u +%H:%M:%S)] !! DEVICE UNREACHABLE — likely panic/black screen"
    break
  fi
  # size + mtime + owner: detects a NEW run (fresh log) vs the stale 02:38 file
  info=$(adb -s $S shell "stat -c '%s %Y %U' $LOG 2>/dev/null" 2>/dev/null | tr -d '\r')
  if [ -n "$info" ]; then
    sz=$(echo "$info" | awk '{print $1}')
    mt=$(echo "$info" | awk '{print $2}')
    ow=$(echo "$info" | awk '{print $3}')
    if [ "$sz" != "$prev_size" ]; then
      echo "[$(date -u +%H:%M:%S)] log size=$sz mtime=$mt owner=$ow"
      prev_size=$sz
    fi
  fi
  sleep 4
done

echo "=== final capture $(date -u +%H:%M:%S) ==="
adb -s $S shell "cat $LOG" > "$OUT/last-64560-run2.log" 2>/dev/null
echo "lines: $(wc -l < "$OUT/last-64560-run2.log" 2>/dev/null || echo 0)"
echo "owner/mtime: $(adb -s $S shell "stat -c '%y %U' $LOG" 2>/dev/null | tr -d '\r')"
echo "--- tail ---"
tail -15 "$OUT/last-64560-run2.log" 2>/dev/null
