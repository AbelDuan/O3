#!/usr/bin/env bash
# Pair using ONLY the code: auto-detect the pairing port from mDNS, then pair+connect.
# Usage: bash pair-by-code.sh <code> [host]
set -u
export ADB_LOCAL_TRANSPORT_MAX_PORT=5553
export HOME=/root/projects/.adb-wifi/stdhome
mkdir -p "$HOME/.android"

CODE=${1:?need 6-digit code}
HOST=${2:-}

detect() {
  timeout 25 python3 - "$1" <<'PY' 2>/dev/null | tail -1
import sys, time
from zeroconf import Zeroconf, ServiceBrowser
want = sys.argv[1]
out = {}
class L:
    def add_service(self, zc, t, n):
        i = zc.get_service_info(t, n)
        if i:
            ip = ".".join(map(str, i.addresses[0])) if i.addresses else ""
            out.setdefault(t, []).append((i.port, ip))
    def update_service(self, *a, **k): pass
    def remove_service(self, *a, **k): pass
zc = Zeroconf()
for t in ("_adb-tls-pairing._tcp.local.", "_adb-tls-connect._tcp.local."):
    ServiceBrowser(zc, t, L())
time.sleep(10)
zc.close()
p = out.get("_adb-tls-pairing._tcp.local.", [])
c = out.get("_adb-tls-connect._tcp.local.", [])
pair = f"{p[0][1]}:{p[0][0]}" if p else ""
conn = f"{c[0][1]}:{c[0][0]}" if c else ""
print(f"{pair}|{conn}")
PY
}

INFO=$(detect "$CODE")
PAIR_T=${INFO%%|*}
CONN_T=${INFO##*|}
echo "detected: pair='$PAIR_T' connect='$CONN_T'"
if [ -z "$PAIR_T" ]; then
  echo "NO_PAIR_PORT: 配对弹窗没开（或已关闭）"
  exit 1
fi
[ -n "$HOST" ] && PAIR_T="$HOST:${PAIR_T##*:}"

if [ ! -f "$HOME/.android/adbkey" ]; then
  adb keygen "$HOME/.android/adbkey" 2>&1 | tail -1
fi
adb kill-server 2>/dev/null; sleep 1; adb start-server 2>&1 | tail -1; sleep 1

echo "=== pair $PAIR_T ==="
timeout 60 adb pair "$PAIR_T" "$CODE" 2>&1 | tail -2
echo "=== connect ==="
[ -n "$CONN_T" ] && timeout 40 adb connect "$CONN_T" 2>&1 | tail -1
timeout 30 adb connect "${PAIR_T%%:*}:5555" 2>&1 | tail -1
sleep 2
adb devices -l 2>&1
for t in $(adb devices | awk 'NR>1 && $2=="device"{print $1}'); do
  echo "--- $t ---"; timeout 25 adb -s "$t" shell "id; cat /sys/fs/selinux/enforce; echo; cat /proc/sys/kernel/random/boot_id" 2>&1 | head -5
done
