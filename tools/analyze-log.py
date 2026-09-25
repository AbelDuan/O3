#!/usr/bin/env python3
"""分析 Ennea `last-64560.log`（或其后 128KB 截断片段），判定崩溃停在哪个阶段，
并给出下一手补丁方向（对照 CVE-18.0-report.md 第十一节的分流表）。

用法:
    python3 analyze-log.py <log 文件>            # 或 - 读 stdin
    python3 analyze-log.py - --json

判定优先级（取**最后**出现的那一批标记）:
  MAGICA_WRAPPER_READY 之后的 stage-2 序列:
    DELETE_ROLE_GATE → DELETE_JOIN → PRIME_JOIN → EXEC_REPEAT → HEAD_PAD_FREE
    → LANE_DONE → RCU_FORCE → SLAB_DRAIN → SPRAY_DONE → ORDER1_RECLAIM_GATE
    → [REAPER_*_PASS | ATTEMPT_MISS] → MISC_BRIDGE_*
"""
import json
import re
import sys

# 判定表：(正则, 结论, 下一手)
RULES = [
    (r"MISC_BRIDGE_(READ|RESULT)_PASS|MISC_BRIDGE_STAGE_BEGIN",
     "已过收尸阶段，进入/完成 bridge 读取", "转向 bridge/跨缓存校验路径"),
    (r"REAPER_(FINITE|DETACHED)_PASS",
     "收尸遍历已走完（说明该次 walk 页面内容安全）", "若仍崩，崩溃在收尸之后"),
    (r"ATTEMPT_MISS",
     "MISS 路径收尸（changed_nodes=0 ⇒ 页面不属于我们）—— 本报告认定的高危点",
     "PIPE_COUNT 提升最对症；可再降 REPEATS"),
    (r"ORDER1_RECLAIM_GATE",
     "已到 reclaim 统计，尚未见收尸结论", "看 changed_nodes 是否 0"),
    (r"SPRAY_DONE",
     "已 spray 完但未见收尸结论 → 收尸/遍历中崩", "PIPE_COUNT 提升最对症"),
    (r"SLAB_DRAIN",
     "在跨缓存排水阶段", "检查 drain 是否成功/超时"),
    (r"RCU_FORCE",
     "在 RCU 强制回调阶段", "检查 rcu_wait"),
    (r"LANE_DONE",
     "车道跑完（race 已发生），崩在其后", "看后续 drain/spray/reap"),
    (r"DELETE_ROLE_GATE|DELETE_JOIN_STAGE",
     "竞态车道内的 delete 阶段崩（race 刚发生）", "提 PIPE_COUNT + 降 REPEATS 继续压"),
    (r"PRIME_JOIN_STAGE|EXEC_REPEAT_GATE",
     "竞态车道内的 exec 重复阶段崩", "降 REPEATS；看 exec 重叠度"),
    (r"HEAD_PAD_ALLOC",
     "车道起步（head pad 分配）", "异常：崩得太早"),
    (r"ATTEMPT_BEGIN",
     "attempt 刚开始", "异常：崩得太早"),
    (r"MAGICA_WRAPPER_READY",
     "停在 ksud/Magica 拉起处（车道开始前）", "转向时序隔离，非 PIPE_COUNT 补丁"),
    (r"CRED_TARGET_READY|CRED_CAPTURE_PASS",
     "停在 cred 捕获阶段（stage-2 极早期）", "检查 cred 目标/uid 前置条件"),
]

CRITICAL = re.compile(r"panic|Oops|BUG:|kernel BUG|Unable to handle|Call trace|Watchdog", re.I)


def analyze(text: str):
    lines = [l for l in text.splitlines() if l.strip()]
    # 只看最后一次运行：从最后一个明显的“开始”标记切起
    start_idx = 0
    for i, l in enumerate(lines):
        if re.search(r"PERMISSIVE_PROCESS_EXIT|CRED_TARGET_READY|STAGE1_|BEGIN", l):
            start_idx = i
    run = lines[start_idx:]

    verdict, nxt, last_marker = "未识别（日志里没有任何已知阶段标记）", "先确认拷出来的是越狱运行的日志", None
    for pat, v, n in RULES:
        hit = None
        for l in run:
            if re.search(pat, l):
                hit = l.strip()
        if hit:
            verdict, nxt, last_marker = v, n, hit
            break

    marks = {}
    for pat, _v, _n in RULES:
        key = pat.split("|")[0].strip("^(")
        marks[key] = sum(1 for l in run if re.search(pat, l))

    reclaim = [l for l in run if "ORDER1_RECLAIM_GATE" in l]
    spray = [l for l in run if "SPRAY_DONE" in l]
    lane = [l for l in run if "LANE_DONE" in l]
    reaper = [l for l in run if re.search(r"REAPER_\w+_PASS", l)]
    misses = [l for l in run if "ATTEMPT_MISS" in l]
    panics = [l for l in run if CRITICAL.search(l)]

    return {
        "lines": len(run),
        "last_marker": last_marker,
        "verdict": verdict,
        "next_action": nxt,
        "counts": {
            "LANE_DONE": len(lane),
            "SPRAY_DONE": len(spray),
            "ORDER1_RECLAIM_GATE": len(reclaim),
            "REAPER_PASS": len(reaper),
            "ATTEMPT_MISS": len(misses),
            "ATTEMPT_HIT": sum(1 for l in run if "ATTEMPT_HIT" in l),
            "panic_lines": len(panics),
        },
        "last_reclaim": reclaim[-1].strip() if reclaim else None,
        "last_spray": spray[-1].strip() if spray else None,
        "last_lane": lane[-1].strip()[:160] if lane else None,
        "tail": [l.strip()[:160] for l in run[-6:]],
    }


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    src = sys.argv[1]
    text = sys.stdin.read() if src == "-" else open(src, encoding="utf-8", errors="replace").read()
    r = analyze(text)
    if "--json" in sys.argv:
        print(json.dumps(r, ensure_ascii=False, indent=2))
        return 0
    print(f"日志行数(本次运行): {r['lines']}")
    print(f"最后命中标记    : {r['last_marker']}")
    print(f"判定            : {r['verdict']}")
    print(f"下一手          : {r['next_action']}")
    c = r["counts"]
    print(f"计数            : LANE_DONE={c['LANE_DONE']} SPRAY_DONE={c['SPRAY_DONE']} "
          f"RECLAIM={c['ORDER1_RECLAIM_GATE']} REAPER={c['REAPER_PASS']} "
          f"MISS={c['ATTEMPT_MISS']} HIT={c['ATTEMPT_HIT']} panic行={c['panic_lines']}")
    for k in ("last_lane", "last_spray", "last_reclaim"):
        if r[k]:
            print(f"{k:15s}: {r[k]}")
    print("尾部:")
    for l in r["tail"]:
        print("   ", l)
    return 0


if __name__ == "__main__":
    sys.exit(main())
