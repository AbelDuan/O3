#!/usr/bin/env python3
"""构建「安全化变体」：把 MAX_ATTEMPTS / CONTROLLED_ATTEMPTS 上钳制改成 1。

只改 .so 两个同长字（不动 dex），复用 work/repack.py 的重打包逻辑：
未替换条目原样拷贝压缩字节、stored 条目 4 字节对齐、丢弃 v1 签名后交给 apksigner。

输入：work/ennea-o3v1-18sel.apk（PIPE_COUNT=10000 版）
输出：work/ennea-o3v1-18sel-attempt1.apk（未签名 → 再签）
"""
import os
import shutil
import struct
import subprocess
import sys
import zipfile

WORK = "/root/projects/ennea-repack/work"
SRC = os.path.join(WORK, "ennea-o3v1-18sel.apk")
OUT_UNSIGNED = os.path.join(WORK, "unsigned-attempt1.apk")
OUT_SIGNED = os.path.join(WORK, "ennea-o3v1-18sel-attempt1.apk")
SO_ENTRY = "lib/arm64-v8a/libennea64560.so"

TEXT_OFF, TEXT_VA = 0x9710, 0xD710
# (vaddr, 旧 imm16, 新 imm16)
PATCHES = [(0xE3E4, 0x100, 0x1), (0xE404, 0x24, 0x1)]


def voff(va):
    return TEXT_OFF + (va - TEXT_VA)


def main():
    with zipfile.ZipFile(SRC) as z:
        so = bytearray(z.read(SO_ENTRY))
        dex = z.read("classes.dex")

    for va, old, new in PATCHES:
        off = voff(va)
        w = struct.unpack_from("<I", so, off)[0]
        cur = (w >> 5) & 0xFFFF
        if cur != old:
            print(f"ABORT: {va:#x} imm16={cur:#x}，期望旧值 {old:#x}（补丁已打过或结构变了）")
            return 1
        neww = 0x52800003 | (new << 5)
        struct.pack_into("<I", so, off, neww)
        print(f"  patched {va:#x} (fileoff {off:#x}): imm16 {old:#x} -> {new:#x}")

    # stage replacement inputs where repack.py expects them
    so_path = os.path.join(WORK, "libennea64560.attempt1.so")
    dex_path = os.path.join(WORK, "classes.attempt1.dex")
    open(so_path, "wb").write(bytes(so))
    open(dex_path, "wb").write(dex)

    # reuse repack.py by overriding its module constants
    sys.path.insert(0, WORK)
    import repack as R
    R.SRC, R.OUT = SRC, OUT_UNSIGNED
    R.REPL = {
        "classes.dex": dex,
        SO_ENTRY: bytes(so),
    }
    print("  repacking (verbatim copy of untouched entries, 4-byte align)...")
    R.main()

    # sign
    ks = "/tmp/ennea-ks.p12"
    if not os.path.exists(ks):
        print(f"ABORT: keystore {ks} missing")
        return 1
    shutil.copy(OUT_UNSIGNED, OUT_SIGNED)
    cmd = ["java", "-jar", "/usr/share/java/apksigner.jar", "sign",
           "--ks", ks, "--ks-type", "PKCS12",
           "--ks-pass", "pass:android", "--key-pass", "pass:android", OUT_SIGNED]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("ABORT: apksigner failed:", r.stdout[-400:], r.stderr[-400:])
        return 1
    print(f"  signed -> {OUT_SIGNED}")

    # verify
    v = subprocess.run(["java", "-jar", "/usr/share/java/apksigner.jar", "verify",
                        "--print-certs", OUT_SIGNED], capture_output=True, text=True)
    print("  verify rc =", v.returncode)
    print("  size:", os.path.getsize(OUT_SIGNED))
    return 0


if __name__ == "__main__":
    sys.exit(main())
