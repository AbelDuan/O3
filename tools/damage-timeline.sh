#!/usr/bin/env bash
# 定性实验：SELinux 的 initialized 到底是被【exploit 的 permissive 写入】还是
# 被【KernelSU 的 Magica late-load】清掉的？
# 做法：秒级同时采样 dmesg 计数 + app 日志最后一行，记下「第一次出现损坏」时
#       App 正处在哪个阶段。
# 用法: bash damage-timeline.sh [最长等待秒数]
set -u
export ADB_LOCAL_TRANSPORT_MAX_PORT=5553
export HOME=/tmp/adbstd2
WAIT=${1:-1500}
OUT=/root/projects/cve-hunt/evidence-live
TL="$OUT/damage-timeline-$(date -u +%Y%m%d-%H%M%S).log"
APP=/sdcard/Android/data/o3.ennea.pocv1/files/last-64560.log

S=""
find_port() {   # 端口每次 ctl.restart adbd 后都会变，自动重发现
  local p
  p=$(timeout 15 python3 /tmp/finddev.py <LAN-IP> 2>/dev/null | awk '{print $2}')
  if [ -n "$p" ]; then
    timeout 20 adb connect <LAN-IP>:$p >/dev/null 2>&1
    sleep 1
    S="<LAN-IP>:$p"; echo "[$(date -u +%H:%M:%S)] 设备端口 -> $p" | tee -a "$TL"
    return 0
  fi
  return 1
}

echo "=== 时间线实验开始 $(date -u +%H:%M:%S) ===" | tee -a "$TL"
find_port || echo "(先没找到，边跑边找)" | tee -a "$TL"

start=$(date +%s); first=0; last_line=""; last_cnt=-1
while [ $(( $(date +%s) - start )) -lt "$WAIT" ]; do
  if [ -z "$S" ] || ! adb -s "$S" get-state >/dev/null 2>&1; then
    S=""; find_port || { sleep 3; continue; }
  fi
  cnt=$(adb -s "$S" shell 'dmesg 2>/dev/null | grep -c "before initial load_policy"' 2>/dev/null | tr -d '\r')
  [ -z "$cnt" ] && cnt=-1
  line=$(adb -s "$S" shell "tail -1 $APP 2>/dev/null" 2>/dev/null | tr -d '\r' | cut -c1-110)

  if [ "$cnt" != "$last_cnt" ] && [ "$cnt" -ge 0 ] 2>/dev/null; then
    echo "[$(date -u +%H:%M:%S)] unknown_sid=$cnt  | app: ${line:-<无>}" | tee -a "$TL"
    last_cnt=$cnt
  fi
  # 第一次从 0 变正 —— 关键判据
  if [ "$first" = 0 ] && [ "$cnt" -gt 0 ] 2>/dev/null; then
    first=1
    {
      echo "  **************************************************************"
      echo "  ★ 损坏首次出现: $(date -u +%H:%M:%S)  计数=$cnt"
      echo "  ★ 此刻 App 日志最后一行: ${line:-<无>}"
      echo "  **************************************************************"
    } | tee -a "$TL"
  fi
  # 拿到 root 也记一笔（对照）
  u=$(adb -s "$S" shell 'su -c "id -u" 2>/dev/null' 2>/dev/null | tr -d '\r')
  if [ "$u" = "0" ]; then
    echo "[$(date -u +%H:%M:%S)] (root 已可用) unknown_sid=$cnt | app: ${line:-<无>}" | tee -a "$TL"
    u=""
  fi
  sleep 2
done
echo "=== 实验结束 $(date -u +%H:%M:%S)，时间线: $TL ==="
