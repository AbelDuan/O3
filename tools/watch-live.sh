#!/usr/bin/env bash
# 实时流式取证：把设备上的 app 日志与 logcat 边产生边落到容器里。
# 与 watch-run2.sh 的区别：不是最后才 cat，而是持续流 —— 黑屏/panic 后 App 被卸载、
# /sdcard/Android/data 被清，也已经留下完整记录在容器。
# Usage: bash watch-live.sh [seconds]
set -u
S=${ADB_SERIAL:-<LAN-IP>:38079}
export ADB_LOCAL_TRANSPORT_MAX_PORT=5553
export HOME=/tmp/adbstd2
DUR=${1:-900}
OUT=/root/projects/cve-hunt/evidence-live
mkdir -p "$OUT"
APP=/sdcard/Android/data/o3.ennea.pocv1/files/last-64560.log
STAMP=$(date -u +%Y%m%d-%H%M%S)
APPLOG="$OUT/app-$STAMP.log"
LOGCAT="$OUT/logcat-$STAMP.log"
LIFE=$(( DUR + 15 ))          # 流进程比主循环多活 15s，确保最后几行也落盘

echo "=== live capture start $(date -u +%H:%M:%S) serial=$S dur=${DUR}s ==="
echo "app log  -> $APPLOG"
echo "logcat   -> $LOGCAT"

# timeout 包住 adb，保证脚本结束时流一定停（adb 不随父 shell 的 kill 退出）
timeout "$LIFE" adb -s "$S" logcat -b all -v threadtime -T 200 2>&1 \
  | sed -u 's/\r$//' >> "$LOGCAT" &
timeout "$LIFE" adb -s "$S" shell "tail -F $APP" 2>&1 \
  | sed -u 's/\r$//' >> "$APPLOG" &

end=$(( $(date +%s) + DUR ))
while [ "$(date +%s)" -lt "$end" ]; do
  sleep 5
  if ! adb -s "$S" get-state >/dev/null 2>&1; then
    echo "[$(date -u +%H:%M:%S)] !! 设备失联 —— 极可能已黑屏/panic"
    sleep 25
    if adb -s "$S" get-state >/dev/null 2>&1; then
      echo "[$(date -u +%H:%M:%S)] 设备已回来"
      { echo "=== post-reboot state $(date -u +%H:%M:%S) ==="
        adb -s "$S" shell 'uptime; cat /proc/sys/kernel/random/boot_id; getprop sys.boot.reason' 2>&1
      } >> "$OUT/postreboot-$STAMP.txt"
    fi
    break
  fi
done

echo "=== capture end $(date -u +%H:%M:%S) ==="
for f in "$APPLOG" "$LOGCAT"; do
  printf '%-52s %8s bytes  %6s lines\n' "$(basename "$f")" \
    "$(stat -c%s "$f" 2>/dev/null || echo 0)" "$(wc -l < "$f" 2>/dev/null || echo 0)"
done
echo "--- app 日志尾部 ---"
tail -15 "$APPLOG" 2>/dev/null
