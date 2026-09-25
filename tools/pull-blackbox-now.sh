#!/usr/bin/env bash
# 一次性黑屏取证：adb 一恢复就把它跑完，产出可离线分析的证据包。
# 用法: bash /root/projects/cve-hunt/pull-blackbox-now.sh
set -u
OUT=/root/projects/cve-hunt/evidence-$(date -u +%Y%m%d-%H%M%S)
mkdir -p "$OUT"
say() { printf '\n=== %s ===\n' "$*"; }

say "0. 设备与基线"
adb devices
adb shell "getprop ro.build.fingerprint; getprop ro.build.version.security_patch; \
  echo -n 'enforce='; cat /sys/fs/selinux/enforce; echo; \
  cat /proc/sys/kernel/random/boot_id; uptime; \
  cat /proc/sys/kernel/pid_max" 2>&1 | tee "$OUT/baseline.txt"

say "1. 装机态校验（是否补丁版：REPEATS=12 / 官方 ksud）"
PKG=$(adb shell pm path o3.ennea.pocv1 | head -1 | tr -d '\r' | cut -d: -f2)
echo "path=$PKG" | tee -a "$OUT/baseline.txt"
if [ -n "$PKG" ]; then
  adb pull "$PKG" "$OUT/base.apk" >/dev/null 2>&1 && \
    sha256sum "$OUT/base.apk" | tee -a "$OUT/baseline.txt"
  python3 - "$OUT/base.apk" <<'PY' 2>&1 | tee -a "$OUT/baseline.txt"
import sys, zipfile, hashlib
apk = sys.argv[1]
z = zipfile.ZipFile(apk)
k = z.read('lib/arm64-v8a/libenneaksud.so')
print('ksud size', len(k), 'sha256', hashlib.sha256(k).hexdigest()[:32])
print('ksud CI-mark gdfadc083:', b'gdfadc083' in k)
print('ksud official-mark:', b'3.3.0 (uapi' in k)
PY
fi

say "2. App 侧日志（last-64560.log，含 stage-1/stage-2 全部输出）"
adb shell "cat /sdcard/Android/data/o3.ennea.pocv1/files/last-64560.log" \
  > "$OUT/last-64560.log" 2>&1 || adb shell "run-as o3.ennea.pocv1 cat files/last-64560.log" \
  > "$OUT/last-64560.log" 2>&1
wc -l "$OUT/last-64560.log"; tail -25 "$OUT/last-64560.log"

say "3. 进程/僵尸快照（钉 wait4 者与孤儿 cohort）"
adb shell "ps -A -o PID,PPID,PGID,USER,STAT,NAME | grep -Ei 'exe|ennea|kernelsu|ksud|networkstack' " | tee "$OUT/ps.txt"

say "4. AVC / init / 崩溃日志窗（本轮 boot）"
adb shell "logcat -d -b all -t 20000 2>/dev/null | grep -iE 'avc:|init:|exe|ennea|kernelsu|ksud|panic|Oops|watchdog|FATAL' | tail -400" | tee "$OUT/logcat-window.txt"

say "5. bugreportz（拿 blackbox: pstore/mdr/minidump）"
adb shell bugreportz 2>&1 | tee "$OUT/bugreportz.txt"
BRPATH=$(grep -oE '/data/user/[^ ]+bugreport[^ ]+\.zip' "$OUT/bugreportz.txt" | head -1)
if [ -n "${BRPATH:-}" ]; then
  adb pull "$BRPATH" "$OUT/bugreport.zip" && echo "pulled $BRPATH"
  ( cd "$OUT" && unzip -o -q bugreport.zip -d bugreport-extract 2>/dev/null
    find bugreport-extract -name 'blackbox.tar.gz' -exec tar xzf {} -C bugreport-extract \; 2>/dev/null
    ls bugreport-extract/xring_logs/ 2>/dev/null | tail -20 )
else
  echo "bugreportz 未返回路径（可能被占用/失败）"
fi

say "6. xring_logs 目录（若可直接读）"
adb shell "ls -lat /data/vendor/xring_logs/ 2>&1 | head -20" | tee "$OUT/xring-dirs.txt"

printf '\n证据包: %s\n' "$OUT"
