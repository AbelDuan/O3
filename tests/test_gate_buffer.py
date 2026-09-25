#!/usr/bin/env python3
"""ORDER1_RECLAIM_GATE (0x18b6c) 的结构不变量检查 —— 守护反汇编结论，防止补丁改错地方。

Round 12 反汇编结论（.text 映射 vaddr = fileoff + 0x4000）：
   0x18b94  mov  w0, #0x6000        ; malloc(0x6000)
   0x18bc8  mov  w26, #0x6000       ; recvfrom 的长度基准
   0x18bb0  ldr  w24, [x23,#0x3e0]  ; 外层循环 = PIPE_COUNT（运行期全局）
   0x18c08  cmp  x28, x24 / b.ge done
   0x18c28  ldr  w0, [x21,#4]!      ; fd = fd_array[i]
   0x18c2c  bl   recvfrom(GOT 0x24248)

⚠️ 关键概念区分（本测试的核心）：
  * PIPE_COUNT 是 **recvfrom 的循环次数**（fd 个数）；
  * 0x6000 是 **每次 recvfrom 的缓冲字节数**。
  二者量纲不同，**不应相等** —— 早先「把 0x6000 也改成 0x2710」的想法是错的
  （那会把 24KB 缓冲缩成 10KB，反而更差）。

所以本测试不强制某个具体数值，而是断言：
  1. 两处缓冲常量存在且为 movz；
  2. 它们的值 **>= 0x6000**（不得被调小）；
  3. PIPE_COUNT 的生效初始化点（0xdda4）等于期望值。
这样既能守护「补丁没改坏缓冲」，又不会把量纲搞混。
"""
import struct
import sys
import zipfile

APK = "/root/projects/ennea-repack/work/ennea-o3v1-18sel.apk"
SO_ENTRY = "lib/arm64-v8a/libennea64560.so"
TEXT_OFF, TEXT_VA = 0x9710, 0xD710

BUF_SITES_VA = (0x18B94, 0x18BC8)   # recvfrom/malloc 缓冲常量
BUF_MIN = 0x6000                    # 不得低于原始值
PIPE_INIT_VA = 0xDDA4               # PIPE_COUNT 生效初始化点
PIPE_EXPECT = 0x2710                # 10000


def va_to_off(va: int) -> int:
    return TEXT_OFF + (va - TEXT_VA)


def movz_imm(so: bytes, va: int):
    w = struct.unpack_from("<I", so, va_to_off(va))[0]
    if (w & 0xFF800000) != 0x52800000:   # MOVZ 32-bit
        return None
    return (w >> 5) & 0xFFFF


def main():
    with zipfile.ZipFile(APK) as z:
        so = z.read(SO_ENTRY)

    rc = 0
    for va in BUF_SITES_VA:
        imm = movz_imm(so, va)
        if imm is None:
            print(f"RED: {va:#x} 不是 movz（.so 结构变了）")
            rc = 1
        elif imm < BUF_MIN:
            print(f"RED: {va:#x} 缓冲常量 {imm:#x} < {BUF_MIN:#x}（被调小了，错方向）")
            rc = 1
        else:
            print(f"  ok  {va:#x} 缓冲常量 = {imm:#x} ({imm})")

    p = movz_imm(so, PIPE_INIT_VA)
    if p != PIPE_EXPECT:
        print(f"RED: PIPE_COUNT 初始化点 {PIPE_INIT_VA:#x} = "
              f"{'?' if p is None else hex(p)}，期望 {PIPE_EXPECT:#x}")
        rc = 1
    else:
        print(f"  ok  {PIPE_INIT_VA:#x} PIPE_COUNT = {p:#x} ({p})")

    if rc == 0:
        print("GREEN: gate 结构不变量成立（缓冲未缩小 + PIPE_COUNT=10000）")
    return rc


if __name__ == "__main__":
    sys.exit(main())
