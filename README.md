# O3 — Xring O3 (lhasa) 越狱 / LPE 研究记录

设备：Xiaomi `2608BPX34C`（代号 **lhasa**，小米 18 Fold），Android 17 / HyperOS **OS4.0.18.0.XPNCNXM**，
内核 `6.18.21-android17-5-g284297031c53`，SPL 2026-08-01。

目标：在无特权 App 上下文下取得 **UID 0**，并让 KernelSU 以 late-load 方式接管；全程不得黑屏 / panic。

> 本仓库只收录**分析文档与工具**。设备取证转储（bugreport / pstore / 日志）与 APK 二进制**不在此仓库**——
> 它们体积以 GB 计，且含大量个人设备数据。仓库内所有局域网地址已脱敏为 `<LAN-IP>`。

---

## 1. 漏洞链

| 环节 | 内容 |
|---|---|
| 权限提升 | **CVE-2026-64560** — `posix-cpu-timers` UAF：`sys_timer_delete` 与 `de_thread`（exec）竞态 |
| 框架侧 | **CVE-2026-49881** — 用于把 SELinux 切到 permissive |
| 落地 | permissive → 直接 cred 零写（UID 0）→ KernelSU Magica late-load |

本机加固现状：`kasan=off`、`init_on_alloc=1`、`SLAB_FREELIST_RANDOM/HARDENED=y`、`CFI=y`、
`VMAP_STACK=y`、`HARDENED_USERCOPY=y`。

## 2. 两段式路线

```
stage-1  DIRECT_ZERO_PERMISSIVE_PASS  → selinux_state.enforcing = 0   ✅ 已稳定复现
stage-2  DIRECT_CRED_PHASE_BEGIN      → cred+4 八字节零写 → UID 0     ❌ 崩溃点
         （随后 MAGICA_WRAPPER_READY → KernelSU late-load）
```

`TARGET_PROFILE_GATE_PASS` 确认 profile 匹配 `lhasa-OS4.0.18.0.XPNCNXM`。

## 3. 黑屏根因（已用 pstore 闭环）

stage-2 崩溃时 panic 原文：

```
list_add double add: new=ffffff821d084e90, prev=ffffff821d084e90, next=ffffffc0d3eb3b40
kernel BUG at lib/list_debug.c:37!
CPU: 7 UID: 1073 PID: 9531 Comm: exe
  __list_add_valid_or_report → __list_add → collect_timerqueue
  → check_process_timers → handle_posix_cpu_timers → posix_cpu_timers_work
  → task_work_run → do_exit
Kernel panic - not syncing: Oops - BUG: Fatal exception
```

- 崩溃 PID **9531** 正是 App 日志中第 4 轮选中的 `victim=9531` —— **victim 自己退出时**内核走到
  已被竞态破坏的 cpu-timer 链表，`BUG_ON` 触发。
- 所有帧偏移均已用 `systemmap18.txt` 逐条校验（见 `docs/`）。
- `/proc/cmdline` 无 `panic=`，故 panic 即**永久黑屏**，只能强制重启。

### 关键结构性发现
- stage-1 走 `REAPER_FINITE_PASS`（victim 被立刻收尸）→ 安全；
- stage-2 判 `ORDER1_RECLAIM_GATE changed_nodes=0` 后直接 `ATTEMPT_MISS`，
  **4 个 victim 全程未被收尸**，坏链表进程累积 → 迟早有一个退出时炸。
- 全日志仅 **1** 条 `REAPER_*`（属 stage-1），stage-2 一条都没有。
- gate 的三趟 slot 扫描在日志里 `DIRECT_CRED_HIT_SLOT` 出现 **0 次**，与 `changed_nodes=0` 互证。

## 4. 目录

| 路径 | 内容 |
|---|---|
| `docs/CVE-18.0-report.md` | 主报告（取证时间线、反汇编分析、补丁台账、逐轮结论） |
| `tools/` | 分析与取证工具（日志分析、NVD 扫描、adb 无线配对/取证、运行监控） |
| `tests/` | TDD 校验（PIPE_COUNT / REPEATS / 内嵌 ksud / gate 结构不变量） |
| `exploit-src/` | 上游 PoC 源码（dada）与 lhasa 18.0 kernel profile |

## 5. 复现要点

```bash
# 校验某个 APK 是否含目标补丁（PIPE_COUNT=10000 / REPEATS=12 / 官方 ksud）
python3 tests/test_pipe_count.py   <apk>
python3 tests/test_repeats_env.py  <apk>
python3 tests/test_ksud_official.py <apk>
python3 tests/test_gate_buffer.py   <apk>   # gate 结构不变量守护
```

`.so` 内 `.text` 的映射关系为 **`vaddr = fileoff + 0x4000`**（反汇编时务必用这个换算）。

## 6. 已知的补丁点位（lhasa 18.0）

| 位置 | 含义 | 值 |
|---|---|---|
| `libennea64560.so` vaddr `0xdda4` | PIPE_COUNT 生效初始化点（`movz w8,#imm`） | `0x1770`(6000) → `0x2710`(10000) |
| `libennea64560.so` vaddr `0xdc54` | 另一条 profile 路径 | `0xbb8`(3000) |
| `libennea64560.so` vaddr `0x18b94`/`0x18bc8` | gate 的 `recvfrom` 缓冲（**非** PIPE_COUNT，勿改成 10000） | `0x6000` |
| dex `0x431CE4` | `YINGTIAN_REPEATS` 常量字符串 | `"24"` → `"12"` |

## 7. 环境备注

- adb 走 loopback（容器与手机同机），端口取 `persist.adb.tcp.port=5555`。
- **绝不要**执行 `setprop ctl.restart adbd` —— 实测会让 adbd 停止且不自动恢复。
- 设备重启会清空 adb 授权；无线调试的 `_adb-tls-connect` 端口在 TLS 层会拒绝未配对证书。
