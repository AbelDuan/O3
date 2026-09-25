#!/usr/bin/env bash
# Canonical wireless-debugging pair + connect, using the STANDARD adb client only.
# One window, one key, no key switching.
#
# Usage: bash pair-connect.sh <pair_host:port> <code> [connect_host:port]
set -u
export ADB_LOCAL_TRANSPORT_MAX_PORT=5553
export HOME=/root/projects/.adb-wifi/stdhome
mkdir -p "$HOME"

PAIR_TARGET=${1:?need pair host:port}
CODE=${2:?need 6-digit code}
CONNECT_TARGET=${3:-}

echo "=== 0. one dedicated key for this flow ==="
if [ ! -f "$HOME/.android/adbkey" ]; then
  mkdir -p "$HOME/.android"
  adb keygen "$HOME/.android/adbkey" 2>&1 | tail -1
fi
chmod 600 "$HOME/.android/adbkey" 2>/dev/null || true
python3 - "$HOME/.android/adbkey.pub" <<'PY'
import base64,hashlib,sys
raw=base64.b64decode(open(sys.argv[1]).read().split()[0])
print("  key sha256:", hashlib.sha256(raw).hexdigest().upper()[:32])
PY

echo "=== 1. clean server ==="
adb kill-server 2>/dev/null; sleep 1
adb start-server 2>&1 | tail -1; sleep 1

echo "=== 2. pair $PAIR_TARGET with code $CODE ==="
timeout 60 adb pair "$PAIR_TARGET" "$CODE" 2>&1 | tail -3

echo "=== 3. connect ==="
if [ -n "$CONNECT_TARGET" ]; then
  timeout 40 adb connect "$CONNECT_TARGET" 2>&1 | tail -1
fi
# also try the host from the pair target on 5555
PAIR_HOST=${PAIR_TARGET%%:*}
timeout 30 adb connect "$PAIR_HOST:5555" 2>&1 | tail -1

sleep 2
echo "=== 4. state ==="
adb devices -l 2>&1
echo "=== 5. prove it works ==="
for t in $(adb devices | awk 'NR>1 && $2=="device"{print $1}'); do
  echo "--- $t ---"
  timeout 25 adb -s "$t" shell "id; cat /sys/fs/selinux/enforce; echo; cat /proc/sys/kernel/random/boot_id" 2>&1 | head -5
done
