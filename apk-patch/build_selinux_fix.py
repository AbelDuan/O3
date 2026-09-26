#!/usr/bin/env python3
"""修复越狱 APK 的 SELinux 副作用（v3）。

根因（本会话指令级定位）：
  cred 阶段有一处「重新置为 permissive」的写入，目标地址写成 selinux_state + 1。
  本机内核 BTF 证实：enforcing 在 +0x0、**initialized 在 +0x1**（上游布局才是
  disabled@0 / enforcing@1）。于是它把 initialized 清成 0 —— SELinux 变成
  「未初始化」，security_sid_to_context_core() 直接返回 -EINVAL，
  导致 selinux_android_setcontext() 失败 → zygote/USAP 池 abort → 任何 App 都起不来
  （表现：KernelSU 白屏闪退、系统不稳、偶发「存储损坏」提示）。

修法：把两处 `add x3, x8, #0x1` 改成 `add x3, x8, #0x0`，让它按本机布局写 enforcing。
  同长原地改（4 字节），不动其它逻辑。
    0x13b58  add x3, x8, #0x1   编码 0x91000503  ->  0x91000103  (file 0xfb58)
    0x13be8  add x3, x8, #0x1   编码 0x91000503  ->  0x91000103  (file 0xfbe8)
  .text 映射：file_off = vaddr - 0x4000
"""
import os
import shutil
import struct
import subprocess
import sys
import zipfile

WORK = "/root/projects/ennea-repack/work"
SRC = os.path.join(WORK, "ennea-o3v1-18sel.apk")
OUT_UNSIGNED = os.path.join(WORK, "unsigned-selinuxfix.apk")
OUT_SIGNED = os.path.join(WORK, "ennea-o3v1-18sel-selinuxfix.apk")
SO_ENTRY = "lib/arm64-v8a/libennea64560.so"
TEXT_DELTA = 0x4000
KS = "/tmp/ennea-ks.p12"
APKSIGNER = "/usr/share/java/apksigner.jar"
JAVA_BIN = "/opt/jre/usr/lib/jvm/java-21-openjdk-arm64/bin/java"

# (vaddr, 旧编码, 新编码, 说明)
PATCHES = [
    (0x13B58, 0x91000503, 0x91000103, "cred 阶段 permissive 写：+1 -> +0"),
    (0x13BE8, 0x91000503, 0x91000103, "cred 阶段 permissive 写（第二处）：+1 -> +0"),
]


def main():
    with zipfile.ZipFile(SRC) as z:
        so = bytearray(z.read(SO_ENTRY))

    for va, old, new, why in PATCHES:
        off = va - TEXT_DELTA
        cur = struct.unpack_from("<I", so, off)[0]
        if cur != old:
            print(f"ABORT: {va:#x} (file {off:#x}) 期望 {old:#010x}，实际 {cur:#010x}")
            return 1
        struct.pack_into("<I", so, off, new)
        print(f"  {why:38s} {va:#x} -> file {off:#x}: {old:#010x} => {new:#010x}")

    so_path = os.path.join(WORK, "libennea64560.selinuxfix.so")
    open(so_path, "wb").write(bytes(so))
    print("  已写出:", so_path)

    sys.path.insert(0, WORK)
    import repack as R
    R.SRC, R.OUT = SRC, OUT_UNSIGNED
    R.REPL = {SO_ENTRY: bytes(so)}
    print("  重打包...")
    R.main()

    shutil.copy(OUT_UNSIGNED, OUT_SIGNED)
    cmd = [JAVA_BIN, "-jar", APKSIGNER, "sign",
           "--ks", KS, "--ks-type", "PKCS12",
           "--ks-pass", "pass:android", "--key-pass", "pass:android", OUT_SIGNED]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("ABORT: apksigner:", r.stdout[-400:], r.stderr[-400:])
        return 1
    v = subprocess.run([JAVA_BIN, "-jar", APKSIGNER, "verify", "--print-certs", OUT_SIGNED],
                       capture_output=True, text=True)
    print("  verify rc =", v.returncode, "| size:", os.path.getsize(OUT_SIGNED))
    return 0


if __name__ == "__main__":
    sys.exit(main())
