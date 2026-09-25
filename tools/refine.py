#!/usr/bin/env python3
"""在已抓取的候选里按「本机可达性」收窄。"""
import json, re, sys
raw = json.load(open('candidates.json'))
REACH = ('net/', 'kernel/', 'fs/', 'mm/', 'ipc/', 'security/', 'io_uring/', 'block/',
         'drivers/android/', 'lib/', 'crypto/')
NOISE = ('ocfs2','adfs','ntfs','ksmbd','cifs','smb/','exfat','erofs','jffs2','gfs2','reiserfs',
         'hfs','fat/','nfs','ceph','f2fs','ubifs','xfs','btrfs','nilfs','orangefs','9p',
         'drivers/gpu','drivers/net/wireless','drivers/crypto','drivers/mtd','drivers/spi',
         'drivers/md','drivers/of','drivers/pmdomain','drivers/bluetooth','drivers/scsi',
         'drivers/usb','drivers/infiniband','drivers/vfio','drivers/block','drivers/dma',
         'arch/','tools/','samples/','selftests','test_')
CORE = ('binder','ashmem','io_uring','futex','epoll','pipe','skbuff','af_unix','af_packet',
        'net/core','net/ipv4','net/ipv6','net/socket','net/netlink','key','cred','task',
        'mm/','signal','timer','sched','file_table','fs/read_write','fs/ioctl','fs/eventpoll')
rows=[]
for c in raw:
    f=' '.join(c['files'])
    if any(n in f for n in NOISE): continue
    if not (any(f.startswith(p) or ('/'+p) in f or p in f for p in REACH)): continue
    hit=any(k in f for k in CORE)
    rows.append((c['pub'], c['id'], c['fix'], c['score'], hit, f, c['desc']))
rows.sort(reverse=True)
print(f'{"pub":10s} {"id":16s} {"fix":8s} {"cvss":5s} core files')
for pub,cid,fix,score,hit,f,desc in rows:
    print(f'{pub:10s} {cid:16s} 6.18.{fix.split(".")[2]:<5s} {str(score):5s} {"*" if hit else " "} {f}')
print(f'-- {len(rows)} 条（已排除驱动/需挂载文件系统）')
