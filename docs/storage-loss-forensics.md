# /sdcard 文件"丢失"与"储存损坏"提示 —— 只读取证结论（2026-09-26 09:32–09:45，设备在线）

设备：`<LAN-IP>:46811`（lhasa / 2608BPX34C），Android 17，`su` 不存在（无 root），
dmesg 不可读（`klogctl: Permission denied`）。当前 boot 于 09:28:14（uptime 252s），
`sys.boot.reason=reboot,ap_s_coldboot,na` = **正常重启，非 panic**。

## 结论速览

| # | 问题 | 结论 |
|---|---|---|
| 1 | 文件丢没丢 | **没丢**。文件仍在 `/data/media/0`（有 inode），但 SELinux 标签是 `unlabeled`，被拒访问 → 看不见。 |
| 2 | 重启是否删文件 | **未观察到任何删除**。重启前的文件全部存活；"消失"的文件物理存在。 |
| 3 | "储存损坏"来源 | `com.xiaomi.finddevice` 在 BOOT_COMPLETED 时自报，**不是文件系统损坏**（fsck 干净）。 |
| 4 | 与 SELinux 损坏的关系 | **是同一根因的下游**：`initialized` 清零 → 新建 inode 落 `unlabeled` → 文件不可见 + finddevice 自检失败。 |

## Q1 文件没丢，是被 SELinux 拒绝访问（已证实）

```
$ adb shell 'ls -la /sdcard/ennea-sel5.apk'          → Permission denied   (EACCES)
$ adb shell 'ls -la /sdcard/zzz-no-such-file-xyz.apk' → No such file or directory (ENOENT)  ← 对照
$ adb shell 'test -e /sdcard/ennea-sel5.apk'          → false
```
EACCES 而非 ENOENT ⇒ 路径**存在但不可访问**。决定性证据（MediaProvider 自己的 AVC 拒绝）：
```
avc: denied { getattr } for path="/storage/emulated/0/ennea-sel5.apk" dev="dm-76" ino=40627
  scontext=u:r:mediaprovider_app:s0 tcontext=u:object_r:unlabeled:s0 tclass=file permissive=0
```
**有 inode（40627）即文件存在**；MediaProvider 自己 stat 不了它 ⇒ readdir 不列、lookup 返 EACCES、
MediaStore 无行（`content query ... LIKE '%sel5.apk%'` → `No result found`）。
PackageInstaller 同样打不开：`Failed to open APK '/sdcard/ennea-sel5.apk': I/O error`。

标签差异是确证：可见文件 `u:object_r:fuse:s0`（`ls -laZ /sdcard/ennea-sel4.apk`），
幽灵文件 `unlabeled`。对照实验：`ennea-sel4.APK`（大小写变体）→ exit 0（FUSE 大小写不敏感，
证明 lookup 能命中真文件）；`ennea-sel5.APK` → EACCES；`ennea-sel5x.apk` → ENOENT。

**索引一致性**：当前 `/sdcard`、`Download`、`Documents`、`Pictures`、`DCIM` 下磁盘文件与
MediaStore 行**完全一致**（8 个文件全在索引里，无磁盘有/索引无的项）。所以本案**不是**
"只是没被索引"——`ennea-sel5.apk` 连 MediaProvider 都 stat 不到，**永远无法被索引**。
（历史 §二十 的"僵死文件"是同一机制；`am broadcast MEDIA_SCANNER_SCAN_FILE` 对
`unlabeled` 文件**无效**，因为它同样走 MediaProvider。）

## Q2 重启不删文件（已证实，但未目击重启本身）

当前 boot（09:28:14）之后仍在的、早于该时刻创建的文件：
```
ennea-fix.apk 01:47 | ennea-sel4.apk 09:16 | ksu_now.png 00:22
Download/ennea-selinuxfix.apk 01:38 | Download/ennea-o3v1-18sel.apk 09-25 04:17
```
用户报"重启后消失"的文件，实测**全部仍存在且不可访问**（AVC 中带 inode）：
```
/storage/emulated/0/ennea-sel5.apk                  ino=40627   (62 次拒绝)
/storage/emulated/0/stock_init_boot_b.img           ino=32194   (22 次)
/storage/emulated/0/ksu_patched_init_boot_b.img     ino=32266   (20 次)
```
即"重启后丢失"= 重启后这些 `unlabeled` 文件依然被拒 → 表现得像丢了。
**未目击重启过程**（我 09:32 接入时已重启完），重启前后对比系由 mtime/inode 推断。

## Q3 "储存损坏"来自 finddevice 自检，不是文件系统损坏（已证实）

```
09-26 09:29:18.079 ActivityManager: ... callingPackage: com.xiaomi.finddevice;
  intent: { act=miui.cloud.finddevice.notification.STORAGE_CORRUPTED };
  tempAllowListReason:<... android.intent.action.BOOT_COMPLETED ...>
```
即该提示由 `com.xiaomi.finddevice` 在 **BOOT_COMPLETED** 时发出（仅 09:29:18–09:29:22，
全 boot 仅此一次；09:36/09:39 的 grep 命中是 adbd 回显我自己的命令行，已排除）。
**文件系统是干净的**：
```
vold: [libfs_mgr] Running /system/bin/fsck.f2fs -a -c 10000 /dev/block/mapper/userdata
vold: [libfs_mgr] fsck on /data took 99ms          ← 无错误
vold: [libfs_mgr] __mount(...type=f2fs)=0,during time: 115 ms: Success
```
全量 logcat 中无 F2FS-/EXT4-fs 损坏、无 I/O error（`Invalid ext4 superblock` 是 fs_mgr
对 f2fs 设备的常规探测噪声）。另：`ro.boot.verifiedbootstate=green`、
`ro.boot.vbmeta.device_state=locked` ⇒ 与 bootloader/AVB 无关。
→ 排除 (a) 真损坏；**不是**非正常关机触发（本次是正常重启），而是**持久状态**触发：
finddevice 读不到自己的数据文件。

## Q4 根因链：SELinux 损坏 → `unlabeled` → 文件不可见 + finddevice 报损坏

历史证据（`evidence-live/dmesg-2320.txt` / `dmesg-2333.txt`）：
```
SELinux: security_sid_to_context_core: called before initial load_policy on unknown SID 2249
  → dmesg-2320.txt 命中 262 次；dmesg-2333.txt 命中 685 次
init: Unable to set property 'sys.usb.ffs.ready': getpeercon() failed: Invalid argument
```
`damage-timeline-20260926-011647.log`：`unknown_sid` 由 0 → 9 **与 exploit 的
`MISC_BRIDGE_READ_PASS attempt=1 ... target=0` 同刻（01:17:36）**。
**当前 SELinux 已恢复健康**：`getenforce`=Enforcing、`ps -Z` → `init` = `u:r:init:s0`
（非空 ⇒ sid→context 正常）、`ls -laZ` 可读标签。

但损坏留下了**落盘的疤**：全 logcat 有 **1226 条** `tcontext=u:object_r:unlabeled:s0` 拒绝，
覆盖 `/data/tombstones/*`、各 App 的 `shared_prefs/*.xml`（`launcher_sharedpreference.xml`、
`one_track_pref.xml`、`NfcServicePrefs.xml`…）。其中与本案直接相关的：
```
09:29:18.173 avc: denied { read } for comm="SharedPreferenc" name="mipush_extra.xml"
  scontext=u:r:platform_app_36:s0:c512,c768 tcontext=u:object_r:unlabeled:s0
```
`ps -Z | grep finddevice` → `u:r:platform_app_36:s0:c512,c768`，**scontext 完全吻合** ⇒
**finddevice 读不了自己的 `mipush_extra.xml`（unlabeled）**，紧接着就发出 STORAGE_CORRUPTED。
同一秒还有 `FindDeviceStatusManagerInternal.updateDeviceCredential(...)`。

**所以：「储存损坏」是这套 SELinux 损坏的下游表现，不是真的存储坏了。**
"黑屏/卡死"与损坏同时发生（§二十四/§二十五：损坏后 zygote/USAP 池 abort）也与本案一致。

## 已证实 / 推测 / 待确认

- **已证实**：三个"丢失"文件有活 inode 且标签为 `unlabeled`；MediaProvider 自身被拒 getattr；
  可见文件标签为 `fuse:s0`；MediaStore 与文件系统当前一致；fsck 干净；提示来自 finddevice
  且由 BOOT_COMPLETED 触发；历史 262/685 次 `before initial load_policy`；当前 SELinux 健康。
- **推测（证据强但非直读）**：`unlabeled` 是损坏窗口内创建文件所致（内核
  `selinux_initialized()==0` 时 `isec->sid = SECINITSID_UNLABELED`）；MIUI 文件管理器走
  MediaStore 所以看不见（未直接抓 `com.android.fileexplorer` 的查询）。
- **需条件才能确认**：当前 boot 的 `before initial load_policy` 计数（无 root，dmesg 不可读，
  `logcat -b kernel` 为空）；重启前后完整清单对比（未目击重启）。
- **修复方向（未执行，只读调查）**：`restorecon -R /data/media/0` 或对上述 inode 重打标签，
  即可让文件重新可见——**不是数据丢失，是标签问题**。
