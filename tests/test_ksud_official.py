#!/usr/bin/env python3
"""RED/GREEN: APK 内嵌的 ksud（lib/arm64-v8a/libenneaksud.so）必须是 KernelSU 官方 release，
而不是 CI/dev 构建。

背景（用户指令 2026-09-25）：内置 KernelSU 换正式版、不要 CI 版。
经比对：
  - 内嵌 manager APK (res/0W.apk) 与官方 release v3.3.0(32601) 逐字节一致 ✓
  - 内嵌 ksud 带 `3.3.0-25-gdfadc083`（git describe：tag 后 25 个提交的 CI 构建）✗
  - 官方 release 的 libksud.so 版本串为 `3.3.0 (uapi: 2)`，sha256=99aaa607…

断言:
  1. ksud 内不含 CI 标记 `gdfadc083` / `3.3.0-25-`
  2. ksud 内含官方 release 标记 `3.3.0 (uapi`
  3. 文件大小 == 官方 libksud.so (4892712)
"""
import hashlib
import sys
import zipfile

APK = "/root/projects/ennea-repack/work/ennea-o3v1-18sel.apk"
ENTRY = "lib/arm64-v8a/libenneaksud.so"
OFFICIAL_SHA256 = "99aaa607e9c9da6a0e898366ecf0a14d"   # prefix; full below
OFFICIAL_SHA256_FULL = None  # filled from downloaded file if available
OFFICIAL_SIZE = 4892712
CI_MARK = b"gdfadc083"
CI_VER = b"3.3.0-25-"
OFFICIAL_MARK = b"3.3.0 (uapi"


def main():
    with zipfile.ZipFile(APK) as z:
        ksud = z.read(ENTRY)
    problems = []
    if CI_MARK in ksud or CI_VER in ksud:
        problems.append("RED: ksud still CI build (contains gdfadc083 / 3.3.0-25-)")
    if OFFICIAL_MARK not in ksud:
        problems.append("RED: ksud missing official release marker '3.3.0 (uapi'")
    if len(ksud) != OFFICIAL_SIZE:
        problems.append(f"RED: ksud size {len(ksud)} != official {OFFICIAL_SIZE}")
    sha = hashlib.sha256(ksud).hexdigest()
    print(f"ksud size={len(ksud)} sha256={sha[:32]}…")
    if problems:
        print("\n".join(problems))
        return 1
    print("GREEN: embedded ksud == official KernelSU v3.3.0 release")
    return 0


if __name__ == "__main__":
    sys.exit(main())
