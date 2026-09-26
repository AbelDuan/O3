#!/usr/bin/env python3
"""修复越狱 APK 的 SELinux 副作用（v5 —— 目标地址前移 31 字节）。

根因（本会话定位到指令级）：
  permissive 阶段用 crosscache 机制让内核往 selinux_state 写 4 个分块（chunks=4），
  落在 +0..+3 四个连续字节上。本机 BTF 证实 enforcing 在 +0x0、**initialized 在 +0x1**，
  于是 enforcing（想要的 permissive）和 initialized（不想要的）一起被清 0。
  initialized=0 → security_sid_to_context_core() 直接 -EINVAL →
  selinux_android_setcontext() 失败 → zygote/USAP 池 abort → 任何 App 起不来
  （KernelSU 白屏闪退、系统不稳、黑屏、重启后「储存损坏」提示）。

修法：把零写目标从 selinux_state+0 前移到 selinux_state-3，
      写入窗口变成 [selinux_state-3, selinux_state+0]，只清 enforcing，保住 initialized。
  两处必须同改，否则 native 侧「目标类型识别」比对失败会走错分支：
    1) classes.dex  0x431170 的 const-wide v2 立即数：0xffffffc082959630 -> ...962d
    2) libennea64560.so 0xe0ec movn x9,#0x69cf（~0x69cf=0x9630）-> #0x69d2（~0x69d2=0x962d）
  dex 改了必须重算 header 的 adler32 校验和与 SHA-1 签名，否则 ART 拒绝加载。
"""
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import zipfile
import zlib

WORK = "/root/projects/ennea-repack/work"
SRC = os.path.join(WORK, "ennea-o3v1-18sel.apk")
OUT_UNSIGNED = os.path.join(WORK, "unsigned-sel5.apk")
OUT_SIGNED = os.path.join(WORK, "ennea-o3v1-18sel-sel5.apk")
SO_ENTRY = "lib/arm64-v8a/libennea64560.so"
KS = "/tmp/ennea-ks.p12"
APKSIGNER = "/usr/share/java/apksigner.jar"
JAVA_BIN = "/opt/jre/usr/lib/jvm/java-21-openjdk-arm64/bin/java"

DEX_CONST_OFF = 0x431172          # const-wide v2 立即数的第 1 个字节
DEX_OLD, DEX_NEW = b"\x30", b"\x11"   # 0x...9630 -> 0x...9611（前移 31）
SO_OFF = 0xE0EC - 0x4000          # .text 映射 vaddr = fileoff + 0x4000
SO_OLD, SO_NEW = 0x928D39E9, 0x928D3DC9   # movn x9,#0x69cf -> #0x69ee（前移 31）


def fix_dex_checksums(dex: bytearray) -> None:
    """重算 dex header 的 signature(sha1, 自 offset 32 起) 与 checksum(adler32, 自 offset 12 起)。

    顺序不能反：checksum 覆盖 [12:]，而 signature 正好落在 [12:32] 内 ——
    必须先写 signature，再算 checksum，否则算出来的 checksum 立刻失效。
    """
    dex[12:32] = hashlib.sha1(bytes(dex[32:])).digest()
    struct.pack_into("<I", dex, 8, zlib.adler32(bytes(dex[12:])) & 0xFFFFFFFF)


def main():
    with zipfile.ZipFile(SRC) as z:
        dex = bytearray(z.read("classes.dex"))
        so = bytearray(z.read(SO_ENTRY))

    # --- 1) dex 常量 ---
    if bytes(dex[DEX_CONST_OFF:DEX_CONST_OFF + 1]) != DEX_OLD:
        print("ABORT: dex %#x 期望 %s，实际 %s" % (DEX_CONST_OFF, DEX_OLD.hex(), dex[DEX_CONST_OFF:DEX_CONST_OFF+1].hex()))
        return 1
    # 校验整条 const-wide
    op, reg = dex[DEX_CONST_OFF - 2], dex[DEX_CONST_OFF - 1]
    imm = struct.unpack_from("<Q", dex, DEX_CONST_OFF)[0]
    if op != 0x18:
        print("ABORT: %#x 不是 const-wide（op=%#x）" % (DEX_CONST_OFF - 2, op))
        return 1
    print("  dex  const-wide v%d = %#018x  ->  %#018x" % (
        reg, imm, imm - 31))
    dex[DEX_CONST_OFF] = DEX_NEW[0]
    fix_dex_checksums(dex)
    print("  dex  校验和/签名已重算")

    # --- 2) .so 常量 ---
    cur = struct.unpack_from("<I", so, SO_OFF)[0]
    if cur != SO_OLD:
        print("ABORT: so %#x 期望 %#010x，实际 %#010x" % (SO_OFF, SO_OLD, cur))
        return 1
    struct.pack_into("<I", so, SO_OFF, SO_NEW)
    print("  so   movn x9,#0x69cf -> #0x69ee  (file %#x)" % SO_OFF)

    so_path = os.path.join(WORK, "libennea64560.sel5.so")
    open(so_path, "wb").write(bytes(so))

    # --- 3) 重打包 + 签名 ---
    sys.path.insert(0, WORK)
    import repack as R
    R.SRC, R.OUT = SRC, OUT_UNSIGNED
    R.REPL = {"classes.dex": bytes(dex), SO_ENTRY: bytes(so)}
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
