#!/usr/bin/env python3
"""RED/GREEN: 把 MAX_ATTEMPTS / CONTROLLED_ATTEMPTS 的上钳制到 1（安全化变体）。

动机（Round 13 结论）：stage-2 判 MISS 时**不收尸**，每轮尝试都留下一个
cpu-timer 链表已损坏的 victim；实测第 4 轮的 victim(9531) 退出时 panic。
把尝试数压到 1，最多只留 1 个坏进程，显著降低「迟早炸」的概率，
让用户能在不强制重启的前提下反复试跑、并测量单轮命中率。

做法：不改 dex，改 .so 的 **clamp 上界**（同长原地改）——
Java 侧 `makeExploitBuilder` 把 YINGTIAN_MAX_ATTEMPTS / CONTROLLED_ATTEMPTS 都设成 "12"，
但 .so 读 env 时会按 [min,max] 钳制；把 max 改成 1 即可强制生效值为 1。

  vaddr 0xe3e4 (fileoff 0xa3e4): mov w3,#0x100 (256)  -> mov w3,#1
  vaddr 0xe404 (fileoff 0xa404): mov w3,#0x24  (36)   -> mov w3,#1

.text 映射：vaddr = fileoff + 0x4000
"""
import struct
import sys
import zipfile

APK = sys.argv[1] if len(sys.argv) > 1 else \
    "/root/projects/ennea-repack/work/ennea-o3v1-18sel.apk"
SO_ENTRY = "lib/arm64-v8a/libennea64560.so"
TEXT_OFF, TEXT_VA = 0x9710, 0xD710

# (vaddr, 期望 imm16)
SITES = [(0xE3E4, 0x1), (0xE404, 0x1)]


def voff(va: int) -> int:
    return TEXT_OFF + (va - TEXT_VA)


def movz_w3_imm(so: bytes, va: int):
    w = struct.unpack_from("<I", so, voff(va))[0]
    # MOVZ 32-bit, Rd=w3:  sf=0 opc=10 100101 hw=00 imm16 Rd=00011
    if (w & 0xFFE0001F) != 0x52800003:
        return None
    return (w >> 5) & 0xFFFF


def main():
    with zipfile.ZipFile(APK) as z:
        so = z.read(SO_ENTRY)

    bad = []
    for va, want in SITES:
        got = movz_w3_imm(so, va)
        if got is None:
            print(f"RED: {va:#x} 不是 movz w3（.so 结构变了）")
            bad.append(va)
        elif got != want:
            print(f"RED: {va:#x} imm16={got:#x}（{got}），期望 {want:#x}")
            bad.append(va)
        else:
            print(f"  ok  {va:#x} imm16={got:#x}（{got}）")

    if bad:
        print(f"RED: {len(bad)} 处未达期望 —— 尝试数仍 >1，安全化未生效")
        return 1
    print("GREEN: MAX_ATTEMPTS / CONTROLLED_ATTEMPTS 上钳制均为 1")
    return 0


if __name__ == "__main__":
    sys.exit(main())
