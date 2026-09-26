#!/usr/bin/env bash
# 越狱跑完后立刻抓验证快照（趁 SELinux 副作用还没扩散）。
# 用法: bash post-run-verify.sh [最长等待秒数]
set -u
S=${ADB_SERIAL:-<LAN-IP>:36963}
export ADB_LOCAL_TRANSPORT_MAX_PORT=5553
export HOME=/tmp/adbstd2
WAIT=${1:-900}
OUT=/root/projects/cve-hunt/evidence-live
APP=/sdcard/Android/data/o3.ennea.pocv1/files/last-64560.log
SNAP="$OUT/verify-$(date -u +%Y%m%d-%H%M%S).txt"

echo "=== 守望开始 $(date -u +%H:%M:%S)，等待越狱运行 ==="
start=$(date +%s)
seen=0
while [ $(( $(date +%s) - start )) -lt "$WAIT" ]; do
  if ! adb -s "$S" get-state >/dev/null 2>&1; then
    echo "[$(date -u +%H:%M:%S)] 设备失联（可能黑屏/重启），等它回来…"
    sleep 25
    continue
  fi
  # 检测本轮是否已产生新日志（出现 SUCCESS/FAIL 或文件更新）
  info=$(adb -s "$S" shell "stat -c '%s %Y' $APP 2>/dev/null" 2>/dev/null | tr -d '\r')
  if [ -n "$info" ]; then
    sz=$(echo "$info" | awk '{print $1}')
    if [ "$sz" -gt 1000 ] 2>/dev/null; then
      tail_txt=$(adb -s "$S" shell "tail -3 $APP 2>/dev/null" 2>/dev/null | tr -d '\r')
      if echo "$tail_txt" | grep -qE 'SUCCESS|FAIL|ROOT_UID_PASS|MAGICA_STAGE1'; then
        echo "[$(date -u +%H:%M:%S)] 检测到本轮已出结果，开始抓快照"
        seen=1
        break
      fi
    fi
  fi
  sleep 6
done

{
  echo "=== 越狱后验证快照 $(date -u +%Y-%m-%dT%H:%M:%SZ) ==="
  echo "--- 1) App 日志尾部 ---"
  adb -s "$S" shell "tail -12 $APP 2>/dev/null" 2>&1 | tr -d '\r'
  echo
  echo "--- 2) root 是否到手 ---"
  adb -s "$S" shell 'which su; su -c "id -u" 2>&1' 2>&1 | tr -d '\r'
  echo
  echo "--- 3) ★ SELinux 是否被写坏（核心验证）---"
  echo -n "unknown_sid_count="; adb -s "$S" shell 'dmesg 2>/dev/null | grep -c "before initial load_policy"' 2>&1 | tr -d '\r'
  adb -s "$S" shell 'getenforce; cat /sys/fs/selinux/policyvers; echo; ps -Z -A 2>/dev/null | sed -n 2p' 2>&1 | tr -d '\r'
  echo
  echo "--- 4) App 能否启动（设置 / KernelSU）---"
  adb -s "$S" shell 'am start -a android.settings.SETTINGS >/dev/null 2>&1; sleep 3; dumpsys activity activities 2>/dev/null | grep -m1 topResumedActivity' 2>&1 | tr -d '\r' | cut -c30-100
  adb -s "$S" shell 'am start -n me.weishu.kernelsu/.ui.MainActivity >/dev/null 2>&1; sleep 4; ps -A -o NAME 2>/dev/null | grep -c kernelsu' 2>&1 | tr -d '\r'
} | tee "$SNAP"

echo "=== 快照已存: $SNAP ==="
[ "$seen" = 1 ] || echo "(注意：未检测到明确结果行，可能超时)"
