"""Windows Prefetch (.pf) parser for the Day-26 metadata lane 'Before You Go' (prefetch.<field>).
Pure Python: MAM-compressed Win10/11 files (`MAM\\x04` / `MAM\\x84` header = LZXPRESS Huffman, MS-XCA 2.2.4) are decompressed
here, then the SCCA header + file information (v17 XP, v23 Vista/7, v26 8.1, v30 10/11) + volumes + filename strings are read.
usage: prefetch.py <file.pf> [field ...]"""
import sys, struct, datetime

FIELDS = ("executable_name", "prefetch_hash", "prefetch_hash_hex", "format_version", "file_size", "run_count",
          "last_run_time", "last_run_times", "volume_count", "volume_device_path", "volume_serial_number",
          "volume_creation_time", "file_metrics_count", "filenames", "executable_path", "compressed", "signature_valid")


# ----------------------------------------------------------------------------------------------- LZXPRESS Huffman (MS-XCA)
def lzxpress_huffman_decompress(data, out_size, ext_first=True):
    out = bytearray()
    pos = 0
    n = len(data)
    while len(out) < out_size:
        if pos + 256 > n:
            break
        lengths = [0] * 512
        for i in range(256):
            b = data[pos + i]
            lengths[2 * i] = b & 0xF
            lengths[2 * i + 1] = b >> 4
        pos += 256
        syms = sorted((l, s) for s, l in enumerate(lengths) if l)
        table = [None] * (1 << 15)
        code = 0
        prev = syms[0][0] if syms else 0
        for idx, (l, s) in enumerate(syms):
            if idx:
                code = (code + 1) << (l - prev)
            prev = l
            lo = code << (15 - l)
            hi = (code + 1) << (15 - l)
            for k in range(lo, min(hi, 1 << 15)):
                table[k] = (s, l)
        chunk_end = min(len(out) + 65536, out_size)
        if pos + 4 > n:
            break
        bits = ((data[pos] | data[pos + 1] << 8) << 16) | (data[pos + 2] | data[pos + 3] << 8)
        pos += 4
        extra = 16

        def take(k, bits, extra, pos):
            v = (bits >> (32 - k)) & ((1 << k) - 1) if k else 0
            bits = (bits << k) & 0xFFFFFFFF
            extra -= k
            if extra < 0:
                if pos + 2 <= n:
                    bits |= (data[pos] | data[pos + 1] << 8) << (-extra)
                pos += 2
                extra += 16
            return v, bits, extra, pos

        while len(out) < chunk_end:
            e = table[(bits >> 17) & 0x7FFF]
            if e is None:
                raise ValueError("bad huffman code")
            s, l = e
            _, bits, extra, pos = take(l, bits, extra, pos)
            if s < 256:
                out.append(s)
                continue
            if s == 256 and pos >= n:
                break
            s -= 256
            length = s & 0xF
            obits = s >> 4

            def ext(length, pos):
                if length == 15:
                    b = data[pos]; pos += 1
                    if b == 255:
                        L = data[pos] | data[pos + 1] << 8; pos += 2
                        if L == 0:
                            L = struct.unpack_from("<I", data, pos)[0]; pos += 4
                        length = L - 15
                    else:
                        length = b
                    length += 15
                return length + 3, pos

            if ext_first:
                length, pos = ext(length, pos)
                off, bits, extra, pos = take(obits, bits, extra, pos)
            else:
                off, bits, extra, pos = take(obits, bits, extra, pos)
                length, pos = ext(length, pos)
            offset = off + (1 << obits)
            if offset > len(out):
                raise ValueError("bad match offset")
            for _ in range(length):
                out.append(out[-offset])
        if len(out) >= chunk_end and chunk_end < out_size:
            continue
        if len(out) >= out_size:
            break
    return bytes(out[:out_size])


def decompress_mam(b):
    """MAM\\x04 (Win10 prefetch) -> decompressed bytes; non-MAM input is returned unchanged. (MAM\\x84 carries a CRC32.)"""
    if b[:3] != b"MAM":
        return b, False
    flags = b[3]
    size = struct.unpack_from("<I", b, 4)[0]
    body = b[12:] if flags & 0x80 else b[8:]
    try:
        d = lzxpress_huffman_decompress(body, size)
        if d[4:8] == b"SCCA" or len(d) == size:
            return d, True
    except Exception:
        pass
    return lzxpress_huffman_decompress(body, size, ext_first=False), True


# ----------------------------------------------------------------------------------------------- prefetch structures
def filetime(v):
    if not v:
        return None
    try:
        return (datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) +
                datetime.timedelta(microseconds=v // 10)).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    except Exception:
        return None


def parse(b):
    d, comp = decompress_mam(b)
    r = {"compressed": comp}
    if len(d) < 84:
        return r
    ver, sig, _u, size = struct.unpack_from("<I4sII", d, 0)
    r["format_version"] = ver
    r["signature_valid"] = sig == b"SCCA"
    r["file_size"] = size
    name = d[16:76].decode("utf-16-le", "replace")
    r["executable_name"] = name.split("\x00", 1)[0]
    h = struct.unpack_from("<I", d, 76)[0]
    r["prefetch_hash"] = h
    r["prefetch_hash_hex"] = "%08X" % h
    fi = 84
    u32 = lambda o: struct.unpack_from("<I", d, o)[0]
    u64 = lambda o: struct.unpack_from("<Q", d, o)[0]
    r["file_metrics_offset"] = u32(fi); r["file_metrics_count"] = u32(fi + 4)
    r["trace_chains_offset"] = u32(fi + 8); r["trace_chains_count"] = u32(fi + 12)
    r["filename_strings_offset"] = u32(fi + 16); r["filename_strings_size"] = u32(fi + 20)
    r["volumes_info_offset"] = u32(fi + 24); r["volume_count"] = u32(fi + 28); r["volumes_info_size"] = u32(fi + 32)
    times = []
    if ver == 17:
        times = [u64(fi + 36)]; rc_off = fi + 60
    elif ver == 23:
        times = [u64(fi + 44)]; rc_off = fi + 68
    elif ver == 26:
        times = [u64(fi + 44 + 8 * i) for i in range(8)]; rc_off = fi + 124
    else:  # 30 / 31
        times = [u64(fi + 44 + 8 * i) for i in range(8)]
        rc_off = fi + 124 if r["file_metrics_offset"] >= 308 else fi + 116
    r["run_count"] = u32(rc_off) if rc_off + 4 <= len(d) else None
    times = [t for t in times if t]
    r["last_run_times"] = [filetime(t) for t in times]
    r["last_run_time"] = filetime(times[0]) if times else None
    # filename strings
    fo, fs = r["filename_strings_offset"], r["filename_strings_size"]
    names = []
    if 0 < fo < len(d) and fs:
        blob = d[fo:fo + fs]
        try:
            names = [x for x in blob.decode("utf-16-le", "replace").split("\x00") if x]
        except Exception:
            names = []
    r["filenames"] = names
    r["filename_count"] = len(names)
    exe = r["executable_name"].upper()
    r["executable_path"] = next((x for x in names if x.upper().endswith("\\" + exe)), None) if exe else None
    # volumes
    vols = []
    vo, vc = r["volumes_info_offset"], r["volume_count"]
    esize = {17: 40, 23: 104, 26: 104}.get(ver, 96)
    for i in range(min(vc, 16)):
        e = vo + i * esize
        if e + 20 > len(d):
            break
        dp_off, dp_len, vct, serial = struct.unpack_from("<IIQI", d, e)
        path = ""
        if 0 < vo + dp_off < len(d):
            path = d[vo + dp_off: vo + dp_off + 2 * dp_len].decode("utf-16-le", "replace").rstrip("\x00")
        vols.append({"device_path": path, "creation_time": filetime(vct), "serial_number": "%08X" % serial,
                     "serial_number_u32": serial})
    r["volumes"] = vols
    if vols:
        r["volume_device_path"] = vols[0]["device_path"]
        r["volume_serial_number"] = vols[0]["serial_number"]
        r["volume_creation_time"] = vols[0]["creation_time"]
        r["volume_device_paths"] = [v["device_path"] for v in vols]
        r["volume_serial_numbers"] = [v["serial_number"] for v in vols]
    return r


ALIASES = {"name": "executable_name", "exe_name": "executable_name", "executable": "executable_name",
           "hash": "prefetch_hash_hex", "hash_hex": "prefetch_hash_hex", "version": "format_version",
           "run_counter": "run_count", "last_run": "last_run_time", "last_execution_time": "last_run_time",
           "volume_serial": "volume_serial_number", "volume_serial_hex": "volume_serial_number",
           "device_path": "volume_device_path", "volume_path": "volume_device_path",
           "number_of_files": "filename_count", "file_count": "filename_count", "files": "filenames",
           "metrics_count": "file_metrics_count", "size": "file_size", "path": "executable_path",
           "uncompressed_size": "file_size", "is_compressed": "compressed"}


def field(b, fld):
    r = parse(b)
    f = ALIASES.get(fld, fld)
    if f in r:
        return r[f]
    f2 = f.replace("-", "_")
    if f2 in r:
        return r[f2]
    raise KeyError(fld)


if __name__ == "__main__":
    b = open(sys.argv[1], "rb").read()
    r = parse(b)
    keys = sys.argv[2:] or [k for k in r if k != "filenames"] + ["filenames"]
    for k in keys:
        print(k, "=", r.get(k))
