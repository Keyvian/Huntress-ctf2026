"""Pure-Python raw disk image parser (MBR + EBR chain + GPT primary/backup with CRC validation), Day-28 'Where It All Began'.
parse(b) -> dict with scheme, sector_size, partitions[...] (table order), errors[...];  field(b, name) -> value for `disk.<name>`.
usage: disk.py <img> [field ...]        (no field: prints the full parse as JSON)"""
import sys, json, struct, zlib, uuid

EXTENDED = {0x05, 0x0F, 0x85}


def guid(b):
    return str(uuid.UUID(bytes_le=bytes(b)))


def _mbr_entries(sec):
    out = []
    for i in range(4):
        e = sec[446 + 16 * i: 462 + 16 * i]
        boot, ptype = e[0], e[4]
        start, count = struct.unpack_from("<II", e, 8)
        out.append({"slot": i, "boot": boot, "type": ptype, "start": start, "count": count})
    return out


def _gpt_header(b, off, ss):
    h = b[off: off + 512]
    if len(h) < 92 or h[:8] != b"EFI PART":
        return None
    rev, hsz, hcrc = struct.unpack_from("<III", h, 8)
    cur, alt, first, last = struct.unpack_from("<QQQQ", h, 24)
    dguid = guid(h[56:72])
    pelba, npe, pesz, pecrc = struct.unpack_from("<QIII", h, 72)
    hh = bytearray(h[:hsz]); hh[16:20] = b"\0\0\0\0"
    hdr_ok = (zlib.crc32(bytes(hh)) & 0xffffffff) == hcrc
    arr = b[pelba * ss: pelba * ss + npe * pesz]
    arr_ok = len(arr) == npe * pesz and (zlib.crc32(arr) & 0xffffffff) == pecrc
    ents = []
    for i in range(npe):
        e = arr[i * pesz:(i + 1) * pesz]
        if len(e) < 128:
            break
        if e[:16] == b"\0" * 16:
            continue
        s, en, attr = struct.unpack_from("<QQQ", e, 32)
        name = e[56:128].decode("utf-16-le", "replace").split("\0")[0]
        ents.append({"index": i, "type_guid": guid(e[:16]), "unique_guid": guid(e[16:32]), "start": s, "end": en,
                     "count": en - s + 1, "attributes": attr, "name": name})
    return {"offset": off, "revision": "%d.%d" % (rev >> 16, rev & 0xffff), "header_size": hsz, "header_crc_ok": hdr_ok,
            "current_lba": cur, "alternate_lba": alt, "first_usable": first, "last_usable": last, "disk_guid": dguid,
            "entries_lba": pelba, "num_entries": npe, "entry_size": pesz, "entries_crc_ok": arr_ok, "entries": ents}


def parse(b):
    r = {"size": len(b), "errors": [], "partitions": []}
    sec = b[:512]
    r["mbr_signature_ok"] = len(sec) == 512 and sec[510:512] == b"\x55\xaa"
    if not r["mbr_signature_ok"]:
        r["errors"].append("no 55aa")
    mbr = _mbr_entries(sec) if len(sec) == 512 else []
    r["mbr"] = mbr
    r["disk_signature"] = "0x%08x" % struct.unpack_from("<I", sec, 440)[0] if len(sec) >= 444 else None
    gpt = None
    if any(e["type"] == 0xEE for e in mbr) or b[512:520] == b"EFI PART" or b[4096:4104] == b"EFI PART":
        for ss in (512, 4096):
            p = _gpt_header(b, ss, ss)
            nsec = len(b) // ss
            bk = _gpt_header(b, (p["alternate_lba"] if p and p["alternate_lba"] < nsec else nsec - 1) * ss, ss)
            if bk is None and nsec:
                bk = _gpt_header(b, (nsec - 1) * ss, ss)
            if p or bk:
                gpt = {"sector_size": ss, "primary": p, "backup": bk}
                break
    if gpt:
        r["scheme"] = "gpt"; r["sector_size"] = gpt["sector_size"]
        p, bk = gpt["primary"], gpt["backup"]
        good = lambda h: h and h["header_crc_ok"] and h["entries_crc_ok"]
        use = p if good(p) else (bk if good(bk) else (p or bk))
        r["gpt_used"] = "primary" if use is p else "backup"
        r["gpt_primary_valid"] = bool(good(p)); r["gpt_backup_valid"] = bool(good(bk))
        if not good(p):
            r["errors"].append("primary GPT invalid")
        if not good(bk):
            r["errors"].append("backup GPT invalid")
        if p and bk and good(p) and good(bk) and [(e["start"], e["end"], e["type_guid"]) for e in p["entries"]] != \
                [(e["start"], e["end"], e["type_guid"]) for e in bk["entries"]]:
            r["errors"].append("primary/backup entry mismatch")
        r["gpt"] = {k: (v if k not in ("primary", "backup") else
                        ({kk: vv for kk, vv in v.items() if kk != "entries"} if v else None)) for k, v in gpt.items()}
        r["disk_guid"] = use["disk_guid"]
        for e in use["entries"]:
            r["partitions"].append(dict(e, kind="gpt"))
    else:
        r["scheme"] = "mbr"; r["sector_size"] = 512
        for e in mbr:
            if e["type"] == 0 and e["count"] == 0 and e["start"] == 0:
                continue
            if e["type"] == 0:
                continue
            r["partitions"].append({"index": e["slot"], "kind": "primary" if e["type"] not in EXTENDED else "extended",
                                    "type": "0x%02x" % e["type"], "start": e["start"], "count": e["count"],
                                    "end": e["start"] + e["count"] - 1, "bootable": e["boot"] == 0x80})
            if e["type"] in EXTENDED:
                base = e["start"]; cur = base; seen = set(); n = 4
                while cur and cur not in seen and (cur + 1) * 512 <= len(b):
                    seen.add(cur)
                    es = b[cur * 512:(cur + 1) * 512]
                    if es[510:512] != b"\x55\xaa":
                        r["errors"].append("EBR at %d no 55aa" % cur); break
                    ee = _mbr_entries(es)
                    if ee[0]["type"]:
                        r["partitions"].append({"index": n, "kind": "logical", "type": "0x%02x" % ee[0]["type"],
                                                "start": cur + ee[0]["start"], "count": ee[0]["count"],
                                                "end": cur + ee[0]["start"] + ee[0]["count"] - 1,
                                                "bootable": ee[0]["boot"] == 0x80, "ebr_lba": cur})
                        n += 1
                    if ee[1]["type"] in EXTENDED and ee[1]["start"]:
                        cur = base + ee[1]["start"]
                    else:
                        break
    ss = r["sector_size"]
    for p in r["partitions"]:
        if (p["end"] + 1) * ss > len(b):
            r["errors"].append("partition %s beyond image" % p["index"])
    return r


def field(b, name):
    r = parse(b)
    parts = r["partitions"]
    data = [p for p in parts if p["kind"] != "extended"]
    n = name.lower()
    if n in ("partition_start_lba_sequence", "partition_start_lbas", "start_lba_sequence"):
        return [p["start"] for p in data]
    if n in ("partition_end_lba_sequence",):
        return [p["end"] for p in data]
    if n in ("partition_sector_count_sequence", "partition_size_sectors_sequence"):
        return [p["count"] for p in data]
    if n in ("partition_count",):
        return len(data)
    if n in ("partition_scheme", "scheme", "partition_table_type"):
        return r["scheme"]
    if n in ("sector_size", "sector_size_bytes", "logical_sector_size_bytes"):
        return r["sector_size"]
    if n in ("partition_name_sequence", "partition_names"):
        return [p.get("name") for p in data]
    if n in ("partition_type_guid_sequence",):
        return [p.get("type_guid") for p in data]
    if n in ("partition_type_sequence", "mbr_partition_type_sequence"):
        return [p.get("type") for p in data]
    if n in ("disk_guid",):
        return r.get("disk_guid")
    if n in ("disk_signature", "mbr_disk_signature"):
        return r.get("disk_signature")
    if n in ("valid",):
        return not r["errors"]
    raise KeyError("unknown disk field " + name)


if __name__ == "__main__":
    b = open(sys.argv[1], "rb").read()
    if len(sys.argv) > 2:
        for f in sys.argv[2:]:
            print(f, json.dumps(field(b, f)))
    else:
        print(json.dumps(parse(b), indent=1))
