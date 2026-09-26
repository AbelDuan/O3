#!/usr/bin/env bash
# 抢在 SELinux 副作用扩散前：一检测到 root 就立刻做 KernelSU 持久化。
# 用法: bash grab-root-and-patch.sh [最长等待秒数]
set -u
S=${ADB_SERIAL:-<LAN-IP>:38541}
export ADB_LOCAL_TRANSPORT_MAX_PORT=5553
export HOME=/tmp/adbstd2
WAIT=${1:-1200}
OUT=/root/projects/cve-hunt/evidence-live
LOG="$OUT/persist-$(date -u +%Y%m%d-%H%M%S).log"

say() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

say "守望开始 serial=$S，等待 root 出现（请点完整越狱）"
start=$(date +%s); got=0
while [ $(( $(date +%s) - start )) -lt "$WAIT" ]; do
  if adb -s "$S" get-state >/dev/null 2>&1; then
    U=$(adb -s "$S" shell 'su -c "id -u" 2>/dev/null' 2>/dev/null | tr -d '\r')
    if [ "$U" = "0" ]; then got=1; say "★ root 到手（su -c id -u = 0）"; break; fi
  else
    say "设备暂不可达，继续等…"
  fi
  sleep 4
done

if [ "$got" != 1 ]; then say "超时未拿到 root，退出"; exit 1; fi

say "--- 立刻做 KernelSU 持久化 ---"
K=/data/adb/ksud
say "[A] 先备份两个分区（若还没备份）"
adb -s "$S" shell "su -c 'ls /data/adb/ksu/*.img 2>/dev/null | head -3'" 2>&1 | tee -a "$LOG"

say "[B] 尝试 -o 指向【目录】（怀疑之前 ENOENT 是把 -o 当目录）"
adb -s "$S" shell "su -c 'mkdir -p /data/adb/ksu/patchout && $K boot-patch -o /data/adb/ksu/patchout 2>&1 | tail -6'" 2>&1 | tee -a "$LOG"
say "    产物:"; adb -s "$S" shell "su -c 'ls -la /data/adb/ksu/patchout/ 2>&1'" 2>&1 | tee -a "$LOG"

say "[C] 若上面没产物，再试 -o 指向【文件】+ 以备份镜像为输入"
adb -s "$S" shell "su -c 'B=\$(ls /data/adb/ksu/ksu_backup_* 2>/dev/null | head -1); echo backup=\$B; $K boot-patch -b \$B -o /data/adb/ksu/patched.img 2>&1 | tail -4; ls -la /data/adb/ksu/patched.img 2>&1'" 2>&1 | tee -a "$LOG"

say "[D] 当前 SELinux 状况（对照）"
adb -s "$S" shell 'dmesg 2>/dev/null | grep -c "before initial load_policy"' 2>&1 | tee -a "$LOG"

say "守望结束，日志: $LOG"
