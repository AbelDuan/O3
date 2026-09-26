#!/usr/bin/env bash
# 等设备上线（无线调试被打开）后，自动推 v5 APK 到 /sdcard 并调起安装界面。
set -u
export ADB_LOCAL_TRANSPORT_MAX_PORT=5553
export HOME=/tmp/adbstd2
APK=/root/projects/ennea-repack/work/ennea-o3v1-18sel-sel5.apk
DEST=/sdcard/ennea-sel5.apk
WAIT=${1:-2400}
LOG=/root/projects/cve-hunt/evidence-live/push-sel5.log

say() { echo "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }

say "守望开始：等 <LAN-IP> 上线，上线后自动推送 $APK"
start=$(date +%s); S=""
while [ $(( $(date +%s) - start )) -lt "$WAIT" ]; do
  if [ -z "$S" ] || ! adb -s "$S" get-state >/dev/null 2>&1; then
    S=""
    P=$(timeout 15 python3 /tmp/finddev.py <LAN-IP> 2>/dev/null | awk '{print $2}')
    if [ -n "$P" ]; then
      timeout 20 adb connect <LAN-IP>:$P >/dev/null 2>&1; sleep 2
      if timeout 12 adb -s <LAN-IP>:$P shell 'echo ok' 2>/dev/null | grep -q ok; then
        S="<LAN-IP>:$P"; say "★ 设备上线: $S"; echo "$S" > /tmp/target
      fi
    fi
    [ -z "$S" ] && { sleep 6; continue; }
  fi
  # 检查目标文件是否已在且哈希一致
  want=$(sha256sum "$APK" | cut -c1-32)
  have=$(timeout 30 adb -s "$S" shell "sha256sum $DEST 2>/dev/null" 2>/dev/null | tr -d '\r' | cut -c1-32)
  if [ "$want" = "$have" ]; then
    say "文件已在设备上且哈希一致（$want），跳过推送"
  else
    say "推送 APK..."
    timeout 180 adb -s "$S" push "$APK" "$DEST" 2>&1 | tail -1 | tee -a "$LOG"
    timeout 30 adb -s "$S" shell "chmod 666 $DEST" 2>/dev/null
    timeout 30 adb -s "$S" shell "am broadcast -a android.intent.action.MEDIA_SCANNER_SCAN_FILE -d file://$DEST >/dev/null 2>&1"
    have=$(timeout 30 adb -s "$S" shell "sha256sum $DEST 2>/dev/null" 2>/dev/null | tr -d '\r' | cut -c1-32)
    say "设备端哈希 = ${have:-<空>}  期望 = $want  $([ "$want" = "$have" ] && echo ✓ || echo ✗)"
  fi
  # 调起安装界面（可能因系统损坏而起不来，失败不重试太多次）
  for i in 1 2 3; do
    timeout 30 adb -s "$S" shell "am start -a android.intent.action.VIEW -d file://$DEST -t application/vnd.android.package-archive >/dev/null 2>&1"
    sleep 4
    top=$(timeout 20 adb -s "$S" shell 'dumpsys activity activities 2>/dev/null | grep -m1 topResumedActivity' 2>/dev/null | tr -d '\r')
    if echo "$top" | grep -q packageinstaller; then say "★ 安装界面已弹出，请点「安装」"; break; fi
    say "安装界面未出现（第 $i 次），$(echo "$top" | cut -c30-80)"
    sleep 6
  done
  say "本轮完成，退出守望"
  exit 0
done
say "超时未见设备上线"
