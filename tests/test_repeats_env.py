#!/usr/bin/env python3
"""RED/GREEN: Ennea makeExploitBuilder 注入的 YINGTIAN_REPEATS 必须是 '12'。

背景（Goal Round 1-2 根因）: stage-2 竞态期间，释放的 cpu-timer slab 页被
cred 对象跨缓存回收，迟到的 wait4 遍历 posix_cputimers 时把 cred 的
uid/gid 当 rb 指针解引用 → kernel panic → 黑屏。
REPEATS 决定 exec 风暴规模 = cred 分配压力的主要来源之一，
24 → 12 直接把跨缓存碰撞概率减半。

断言: APK classes.dex 中 YINGTIAN_REPEATS 环境变量紧跟的 const-string 值为 '12'。
"""
import struct
import sys
import zipfile

APK = "/root/projects/ennea-repack/work/ennea-o3v1-18sel.apk"


def uleb(d, o):
    v = s = 0
    while True:
        b = d[o]
        o += 1
        v |= (b & 0x7F) << s
        if not b & 0x80:
            return v, o
        s += 7


def string_at(dex, idx):
    str_off = struct.unpack_from("<I", dex, 0x3C)[0]
    off = struct.unpack_from("<I", dex, str_off + 4 * idx)[0]
    _, o = uleb(dex, off)
    end = dex.index(b"\x00", o)
    return dex[o:end].decode("utf-8", "replace")


def string_idx(dex, target):
    n = struct.unpack_from("<I", dex, 0x38)[0]
    out = []
    for i in range(n):
        if string_at(dex, i) == target:
            out.append(i)
    return out


def const_string_xrefs(dex, idx):
    """find 0x1a (const-string vAA, BBBB) instructions referencing idx"""
    hits = []
    for off in range(0x40, len(dex) - 3):
        if dex[off] == 0x1A and struct.unpack_from("<H", dex, off + 2)[0] == idx:
            hits.append(off)
        # also wide form 0x1b const-string/jumbo only if needed — skip
    return hits


def repeats_value(dex):
    """locate YINGTIAN_REPEATS string, its xref, then the NEXT const-string
    in the same method (the value put)."""
    key = string_idx(dex, "YINGTIAN_REPEATS")
    assert len(key) == 1, f"YINGTIAN_REPEATS idx ambiguous: {key}"
    xrefs = const_string_xrefs(dex, key[0])
    assert len(xrefs) == 1, f"YINGTIAN_REPEATS xrefs: {xrefs}"
    # scan forward for the next const-string opcode (0x1a) = the value
    p = xrefs[0] + 4
    limit = p + 64
    while p < limit:
        if dex[p] == 0x1A:
            vidx = struct.unpack_from("<H", dex, p + 2)[0]
            return string_at(dex, vidx)
        p += 1
    raise AssertionError("no value const-string after YINGTIAN_REPEATS")


def main():
    with zipfile.ZipFile(APK) as z:
        dex = z.read("classes.dex")
    val = repeats_value(dex)
    print(f"YINGTIAN_REPEATS = {val!r}")
    assert val == "12", (
        f"RED: expected YINGTIAN_REPEATS='12' (halve exec/cred storm to "
        f"cut cross-cache collision), got {val!r}"
    )
    print("GREEN: REPEATS=12")


if __name__ == "__main__":
    sys.exit(main())
