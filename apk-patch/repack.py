#!/usr/bin/env python3
"""重打包 EnneaO3V1 APK：只替换 classes.dex 与 libennea64560.so。
未替换的条目**原样拷贝压缩字节**（不重新压缩），stored 条目按 4 字节对齐；
丢弃原 v1 签名文件，签名交给 apksigner。"""
import struct, zipfile, zlib

SRC, OUT = 'orig.apk', 'unsigned.apk'
REPL = {
    'classes.dex': open('classes.patched.dex', 'rb').read(),
    'lib/arm64-v8a/libennea64560.so': open('libennea64560.patched.so', 'rb').read(),
}
SKIP_EXT = ('SF', 'RSA', 'DSA')
ALIGN = 4


def deflate_raw(data, level=9):
    c = zlib.compressobj(level, zlib.DEFLATED, -15)
    return c.compress(data) + c.flush()


def dos_time(dt):
    return ((dt[3] << 11) | (dt[4] << 5) | (dt[5] // 2),
            ((dt[0] - 1980) << 9) | (dt[1] << 5) | dt[2])


def raw_bytes(fh, info):
    """源包里该条目的原始压缩字节。"""
    fh.seek(info.header_offset)
    h = fh.read(30)
    nl, el = struct.unpack_from('<HH', h, 26)
    fh.seek(info.header_offset + 30 + nl + el)
    return fh.read(info.compress_size)


def main():
    zin = zipfile.ZipFile(SRC)
    src = open(SRC, 'rb')
    out = open(OUT, 'wb')
    central, n, replaced = [], 0, []
    for info in zin.infolist():
        name = info.filename
        if name == 'META-INF/MANIFEST.MF' or (name.startswith('META-INF/')
                                              and name.rsplit('.', 1)[-1] in SKIP_EXT):
            continue
        method = info.compress_type
        if name in REPL:
            raw = REPL[name]
            crc, usize = zlib.crc32(raw) & 0xffffffff, len(raw)
            data = deflate_raw(raw) if method == 8 else raw
            replaced.append(f"{name} ({len(raw)}B)")
        else:
            data = raw_bytes(src, info)
            crc, usize = info.CRC, info.file_size
            assert len(data) == info.compress_size
        name_b = name.encode()
        off = out.tell()
        extra = b''
        if method == 0:
            padlen = (-(off + 30 + len(name_b) + 4)) % ALIGN
            extra = struct.pack('<HH', 0xD935, padlen) + b'\x00' * padlen
        out.write(struct.pack('<IHHHHHIIIHH', 0x04034B50, 20, 0, method,
                              *dos_time(info.date_time), crc, len(data), usize,
                              len(name_b), len(extra)))
        out.write(name_b)
        out.write(extra)
        out.write(data)
        central.append(struct.pack('<IHHHHHHIIIHHHHHII', 0x02014B50, 20, 20, 0, method,
                                   *dos_time(info.date_time), crc, len(data), usize,
                                   len(name_b), len(extra), 0, 0, 0, 0, off)
                       + name_b + extra)
        n += 1
    cd_off = out.tell()
    cd = b''.join(central)
    out.write(cd)
    out.write(struct.pack('<IHHHHIIH', 0x06054B50, 0, 0, n, n, len(cd), cd_off, 0))
    size = out.tell()
    out.close()
    src.close()
    print(f"条目 {n} 个，替换：{replaced}")
    print(f"输出 {OUT} {size} 字节")


if __name__ == '__main__':
    main()
