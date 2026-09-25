#!/usr/bin/env bash
# Restart the auth holder cleanly (avoids pkill self-match by living in a file).
set -u
cd /root/projects/cve-hunt
for p in $(pgrep -f 'hold-auth\.py' 2>/dev/null); do
  [ "$p" != "$$" ] && kill "$p" 2>/dev/null
done
sleep 1
export ADBKEYDIR=/root/projects/.adb-wifi/stdhome/.android
nohup python3 hold-auth.py "${1:-<LAN-IP>}" "${2:-5555}" "${3:-600}" > /tmp/holdauth2.log 2>&1 &
echo "holder pid=$!"
sleep 6
head -6 /tmp/holdauth2.log
