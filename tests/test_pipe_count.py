#!/usr/bin/env python3
"""RED/GREEN: APK 内 libennea64560.so 的 PIPE_COUNT 默认值必须是 10000（原 6000）。

依据（Round 9）：设备端崩溃的故障地址是 cred 形状的 uid/gid，说明被释放的
cpu-timer slab 页在 walk 之前已经被 cred 抢走 —— 也就是我们的 spray 没抢到该页。
PIPE_COUNT 决定 spray 覆盖页数（6000 pairs → 18000 fragments），
在 .so 钳制允许的上限内提到 10000（+67% 覆盖）能显著提高「我们占住该页」的概率，
即使 attempt 仍判 MISS，页面内容也是我们的 fake node（walk 安全）。

.so 里两处初始化同一全局 [x,#0x3e0]：
  0xdda4: mov w8, #0x1770 (6000)   ← 生效值（日志 pairs=6000 印证）
  0xdc54: mov w8, #0xbb8  (3000)   ← 另一条 profile 路径
本测试只认「后面紧跟 str w8,[x?,#0x3e0] 的那个 mov」，并要求其 imm16 == 0x2710。
"""
import struct
import sys
import zipfile

APK = "/root/projects/ennea-repack/work/ennea-o3v1-18sel.apk"
SO_ENTRY = "lib/arm64-v8a/libennea64560.so"
TEXT_OFF, TEXT_VA = 0x9710, 0xD710
EXPECT_IMM = 0x2710  # 10000


def find_pipe_count_defaults(so: bytes):
    """return list of (file_offset, imm16) for `mov w8,#imm` immediately
    followed by `str w8,[x?,#0x3e0]`"""
    sites = []
    for o in range(TEXT_OFF, TEXT_OFF + 0x12440 - 8, 4):
        w = struct.unpack_from("<I", so, o)[0]
        if (w & 0xFFE0001F) != 0x52800008:      # movz w8, #imm16
            continue
        imm = (w >> 5) & 0xFFFF
        w2 = struct.unpack_from("<I", so, o + 4)[0]
        # adrp x?, ... then str w8,[x?,#0x3e0]
        if (w2 & 0x9F000000) != 0x90000000:
            continue
        w3 = struct.unpack_from("<I", so, o + 8)[0]
        # STR (imm, unsigned offset): 0xB9000000 | imm12<<10 | Rn<<5 | Rt
        if ((w3 & 0xFFC00000) == 0xB9000000
                and ((w3 >> 10) & 0xFFF) == (0x3E0 >> 2)
                and (w3 & 0x1F) == 8):
            sites.append((o, imm))
    return sites


def main():
    with zipfile.ZipFile(APK) as z:
        so = z.read(SO_ENTRY)
    sites = find_pipe_count_defaults(so)
    print("PIPE_COUNT default sites:", [(hex(o), hex(i), i) for o, i in sites])
    eff = [i for _, i in sites]
    if not sites:
        print("RED: 找不到 PIPE_COUNT 默认值站点（.so 结构可能已变）")
        return 1
    if EXPECT_IMM not in eff:
        print(f"RED: 期望默认值 {EXPECT_IMM}（10000），实际 {eff}")
        return 1
    print("GREEN: PIPE_COUNT 默认值 = 10000")
    return 0


if __name__ == "__main__":
    sys.exit(main())
