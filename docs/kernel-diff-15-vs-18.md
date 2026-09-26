# 内核对比：OS4.0.15.0 vs OS4.0.18.0（lhasa / Xiaomi 18 Fold）

> 数据来源：两次 boot 镜像解出的 kallsyms（`systemmap15.txt` / `systemmap18.txt`）与镜像本体。

## 1. 构建标识

| | OS4.0.15.0 | OS4.0.18.0 |
|---|---|---|
| 版本串 | `6.18.21-android17-5-g1d099fcb35e0-abogki538445360-4k` | `6.18.21-android17-5-g284297031c53-abogki553682993-4k` |
| 镜像大小 | 42,936,832 | 42,940,928（+4096 = 正好 1 页） |
| 符号数 | 138904 | 138921 |
| 共有符号 | — | 138371 |
| 独占符号 | 533 | 550 |

## 2. 代码布局：不是平移，是重排

按 4KB 页比较，**97.5% 的页内容不同**（10218/10482）。符号漂移量**高度不一致**：

| 符号 | 15.0 | 18.0 | 漂移 |
|---|---|---|---|
| `posix_cpu_timer_del` | `0xffffffc0800be930` | `0xffffffc0800c464c` | +0x5d1c |
| `collect_timerqueue` | `0xffffffc080097530` | `0xffffffc08009fa18` | +0x84e8 |
| `check_process_timers` | `0xffffffc0800976d8` | `0xffffffc08009fe00` | +0x8728 |
| `__list_add_valid_or_report` | `0xffffffc080057740` | `0xffffffc08005e5c4` | +0x6e84 |
| `avc_has_perm_noaudit` | `0xffffffc0801acc48` | `0xffffffc0801bcd24` | +0x100dc |
| `handle_posix_cpu_timers` | `0xffffffc080439174` | `0xffffffc080442d84` | +0x9c10 |
| `selinux_state` | `0xffffffc0829586a0` | `0xffffffc082959630` | +0xf90 |
| `selinux_avc` | `0xffffffc082958628` | `0xffffffc082957e10` | -0x818 |
| `init_task` | `0xffffffc0826c04c0` | `0xffffffc0826bf240` | -0x1280 |
| `init_cred` | `0xffffffc0826d2b08` | `0xffffffc0826d2a50` | -0xb8 |

漂移从 **−0x818**（`selinux_avc`，反向移动）到 **+0x100dc**（`avc_has_perm_noaudit`）不等
⇒ **15.0 上的任何硬编码内核地址/偏移，在 18.0 上必然失效。**

最常见的漂移量：

| 漂移 | 符号数 |
|---|---|
| +0x400 | 5743 |
| -0x10 | 5485 |
| +0x14b1 | 5315 |
| +0x13cc | 5314 |
| -0x8 | 3782 |
| -0x20 | 2993 |
| +0xff8 | 2696 |
| +0x38 | 2195 |

## 3. 移植踩过的坑（均已实证）

| 硬编码项 | 15.0 语义 | 18.0 语义 | 后果 |
|---|---|---|---|
| `.so` 的 `0x2958629` | `selinux_avc + 1`（`avc_cache_threshold` 第 2 字节） | `selinux_avc + 0x819` → **AVC 512 桶哈希表内部** | 写 0 = 踩坏 AVC 哈希链 → 任一次权限检查遍历该桶即 oops |
| 竞态探针 `posix_cpu_timer_del + 72` | 落在尾声代码 | **正好是 `ret`**（该函数 18.0 仅 0x48 字节） | 探针失效 |
| `.rodata` 的 `0xffffffc0807ff9c0` / `…7fff74` | `t_start/t_stop`、`cmdline_proc_show` | `dquot_*` 系列 | 语义完全不同，属 15 代遗留 |

## 4. BTF 结构核对（决定 SELinux 写入偏移的关键）

从 `kernel_Image18_raw` 内嵌 BTF（170,540 类型）解出：

```c
struct selinux_state {   // size = 112
    u8 enforcing;        // +0x0   <- 本机布局：enforcing 在最前
    u8 initialized;      // +0x1   <- 被误清即导致系统级损坏
    u8 policycap[];      // +0x2
    void *status_page;   // +0x10
    struct mutex status_lock; // +0x18
    struct selinux_policy *policy; // +0x40
    struct mutex policy_mutex;     // +0x48
};
```

⚠️ 上游内核布局是 `disabled@0 / enforcing@1`；**本机把 `enforcing` 放在 +0**。
移植件若沿用上游偏移，就会写到 `initialized` —— 这正是黑屏/闪退/文件标签污染的根因。

