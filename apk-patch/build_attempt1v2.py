#!/usr/bin/env python3
"""安全化变体 v2：正确地把尝试数强制为 1。

v1 失败原因（实机日志）：`.so` 对 tuning env 是**校验**而非钳制 ——
  TUNING_ENV_GATE_FAIL name=YINGTIAN_MAX_ATTEMPTS value=12 range=1-1
Java 侧把 MAX_ATTEMPTS/CONTROLLED_ATTEMPTS 都设成 "12"，只把 range 改成 [1,1]
会让校验直接失败并**中止**（好处：是干净失败，不 panic）。

正确做法 = 让 Java 的值**读不到** + 把默认值设为 1：
  1) 改 env 名字串末位（同长），getenv 落空 → 用默认值
     YINGTIAN_MAX_ATTEMPTS(0x2911)          -> ...ATTEMPTQ
     YINGTIAN_CONTROLLED_ATTEMPTS(0x2ac8)   -> ...ATTEMPTQ
  2) 把两个默认值初始化改成 1
     0xdd78  mov w8,#0x20 (32) -> #1
     0xdd84  mov w8,#0x24 (36) -> #1
  3) range 上界仍设 1（v1 已做），保证默认值 1 落在 [1,1] 内
     0xe3e4  mov w3,#0x100 -> #1
     0xe404  mov w3,#0x24  -> #1

全部为同长原地改；.text 映射 vaddr = fileoff + 0x4000。
"""
import os
import shutil
import struct
import subprocess
import sys
import zipfile

WORK = "/root/projects/ennea-repack/work"
SRC = os.path.join(WORK, "ennea-o3v1-18sel.apk")          # PIPE_COUNT=10000 基线
OUT_UNSIGNED = os.path.join(WORK, "unsigned-attempt1v2.apk")
OUT_SIGNED = os.path.join(WORK, "ennea-o3v1-18sel-attempt1v2.apk")
SO_ENTRY = "lib/arm64-v8a/libennea64560.so"
TEXT_OFF, TEXT_VA = 0x9710, 0xD710

# (vaddr, 寄存器号, 旧 imm16, 新 imm16, 说明)
WORD_PATCHES = [
    (0xDD78, 8, 0x20, 0x1, "默认 MAX_ATTEMPTS"),
    (0xDD84, 8, 0x24, 0x1, "默认 CONTROLLED_ATTEMPTS"),
    (0xE3E4, 3, 0x100, 0x1, "range 上界 MAX_ATTEMPTS"),
    (0xE404, 3, 0x24, 0x1, "range 上界 CONTROLLED_ATTEMPTS"),
]
# (文件偏移, 旧字节, 新字节, 说明)  —— 改 env 名末位，让 Java 的 setenv 落空
STR_PATCHES = [
    (0x2911 + 20, b"S", b"Q", "YINGTIAN_MAX_ATTEMPTS -> ...ATTEMPTQ"),
    (0x2AC8 + 27, b"S", b"Q", "YINGTIAN_CONTROLLED_ATTEMPTS -> ...ATTEMPTQ"),
]


def voff(va):
    return TEXT_OFF + (va - TEXT_VA)


def main():
    with zipfile.ZipFile(SRC) as z:
        so = bytearray(z.read(SO_ENTRY))
        dex = z.read("classes.dex")

    for va, rd, old, new, why in WORD_PATCHES:
        off = voff(va)
        w = struct.unpack_from("<I", so, off)[0]
        base = 0x52800000 | rd          # MOVZ w<rd>, #imm16
        if (w & 0xFFE0001F) != base:
            print(f"ABORT: {va:#x} 不是 movz w{rd} (word={w:#010x})"); return 1
        cur = (w >> 5) & 0xFFFF
        if cur != old:
            print(f"ABORT: {va:#x} imm16={cur:#x}，期望 {old:#x}"); return 1
        struct.pack_into("<I", so, off, base | (new << 5))
        print(f"  {why:32s} {va:#x} (file {off:#x}): {old:#x} -> {new:#x}")

    for off, old, new, why in STR_PATCHES:
        if so[off:off + len(old)] != old:
            print(f"ABORT: {off:#x} 期望 {old!r}，实际 {so[off:off+len(old)]!r}"); return 1
        so[off:off + len(new)] = new
        print(f"  {why:32s} file {off:#x}: {old.decode()} -> {new.decode()}")

    so_path = os.path.join(WORK, "libennea64560.attempt1v2.so")
    open(so_path, "wb").write(bytes(so))

    sys.path.insert(0, WORK)
    import repack as R
    R.SRC, R.OUT = SRC, OUT_UNSIGNED
    R.REPL = {"classes.dex": dex, SO_ENTRY: bytes(so)}
    print("  repacking...")
    R.main()

    shutil.copy(OUT_UNSIGNED, OUT_SIGNED)
    cmd = ["java", "-jar", "/usr/share/java/apksigner.jar", "sign",
           "--ks", "/tmp/ennea-ks.p12", "--ks-type", "PKCS12",
           "--ks-pass", "pass:android", "--key-pass", "pass:android", OUT_SIGNED]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print("ABORT: apksigner:", r.stdout[-300:], r.stderr[-300:]); return 1
    v = subprocess.run(["java", "-jar", "/usr/share/java/apksigner.jar", "verify",
                        "--print-certs", OUT_SIGNED], capture_output=True, text=True)
    print("  verify rc =", v.returncode, "| size:", os.path.getsize(OUT_SIGNED))
    return 0


if __name__ == "__main__":
    sys.exit(main())
