"""Day-24 metadata 'Event Horizon' — Windows EVTX (ElfFile) field family, pure struct parsing (nothing executed).
File header (4096 B): magic 'ElfFile\\0', first/last chunk number, next_record_id, header_size 128, minor/major, block size 4096,
chunk count, file flags, CRC32 (first 120 bytes).  Chunks (65536 B each, from 4096): 'ElfChnk\\0', first/last record number,
first/last record id, header_size 128, last_record_data_offset, free_space_offset, records CRC (512..free_off), header CRC
(0..120 + 128..512).  Records: '**\\0\\0', size u32, record id u64, FILETIME u64, binxml..., size u32 (trailer copy).
record_count = number of COMPLETE, well-formed records actually present (walked record by record through every chunk,
stopping at a bad magic / impossible size / mismatching size trailer) — "count records accurately" after duplication/truncation,
rather than trusting next_record_id - 1 or the chunk headers' first/last numbers (both are reported too, for diagnostics).
usage: evtx.py <file.evtx>"""
import struct, zlib, datetime

MAGIC = b"ElfFile\0"
CHUNK_MAGIC = b"ElfChnk\0"
REC_MAGIC = b"**\0\0"


def _filetime(ft):
    try:
        return (datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc) + datetime.timedelta(microseconds=ft // 10)).isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def info(b):
    i = {"file_size_bytes": len(b), "magic_valid": b[:8] == MAGIC}
    h = b[:128]
    if len(h) < 128:
        i["truncated_header"] = True
        return i
    i["first_chunk_number"], i["last_chunk_number"], i["next_record_id"] = struct.unpack_from("<QQQ", h, 8)
    i["header_size"] = struct.unpack_from("<I", h, 32)[0]
    i["minor_version"], i["major_version"], i["header_block_size"], i["header_chunk_count"] = struct.unpack_from("<HHHH", h, 36)
    i["file_flags"], i["header_crc32"] = struct.unpack_from("<II", h, 120)
    i["header_crc32_valid"] = zlib.crc32(h[:120]) == i["header_crc32"]
    i["version"] = "%d.%d" % (i["major_version"], i["minor_version"])
    i["flags_dirty"] = bool(i["file_flags"] & 1)
    i["flags_full"] = bool(i["file_flags"] & 2)
    i["claimed_record_count"] = max(i["next_record_id"] - 1, 0)
    expected = 4096 + i["header_chunk_count"] * 65536
    i["expected_size_bytes"] = expected
    i["truncated"] = len(b) < expected
    i["trailing_bytes"] = max(len(b) - expected, 0)
    chunks = []
    recs = []
    off = 4096
    chunk_claimed = 0
    while off < len(b):
        c = b[off:off + 65536]
        ch = {"offset": off, "length": len(c), "magic_valid": c[:8] == CHUNK_MAGIC, "complete": len(c) == 65536}
        if ch["magic_valid"] and len(c) >= 128:
            f = struct.unpack_from("<QQQQIIII", c, 8)
            ch.update(first_record_number=f[0], last_record_number=f[1], first_record_id=f[2], last_record_id=f[3], header_size=f[4],
                      last_record_data_offset=f[5], free_space_offset=f[6], records_crc32=f[7])
            ch["header_crc32"] = struct.unpack_from("<I", c, 124)[0]
            ch["header_crc32_valid"] = len(c) >= 512 and zlib.crc32(c[:120] + c[128:512]) == ch["header_crc32"]
            ch["records_crc32_valid"] = 512 <= f[6] <= len(c) and zlib.crc32(c[512:f[6]]) == f[7]
            ch["claimed_record_count"] = f[1] - f[0] + 1 if f[1] >= f[0] else 0
            chunk_claimed += ch["claimed_record_count"]
            p, n = 512, 0
            ids = []
            while p + 28 <= len(c) and c[p:p + 4] == REC_MAGIC:
                sz = struct.unpack_from("<I", c, p + 4)[0]
                if sz < 28 or p + sz > len(c):
                    ch["partial_record"] = True
                    break
                sz2 = struct.unpack_from("<I", c, p + sz - 4)[0]
                if sz2 != sz:
                    ch["partial_record"] = True
                    break
                rid, ft = struct.unpack_from("<QQ", c, p + 8)
                recs.append({"chunk": len(chunks), "offset": off + p, "size": sz, "record_id": rid, "filetime": ft})
                ids.append(rid)
                n += 1
                p += sz
            ch["record_count"] = n
            ch["records_end_offset"] = p
            ch["record_ids"] = ids
        chunks.append(ch)
        off += 65536
    i["chunk_count"] = len(chunks)
    i["valid_chunk_count"] = sum(1 for c in chunks if c["magic_valid"])
    i["complete_chunk_count"] = sum(1 for c in chunks if c["magic_valid"] and c["complete"])
    i["chunk_claimed_record_count"] = chunk_claimed
    i["record_count"] = len(recs)
    ids = [r["record_id"] for r in recs]
    i["unique_record_id_count"] = len(set(ids))
    i["duplicate_record_count"] = len(ids) - len(set(ids))
    i["record_ids"] = ids
    i["first_record_id"] = min(ids) if ids else None
    i["last_record_id"] = max(ids) if ids else None
    fts = [r["filetime"] for r in recs]
    i["first_record_filetime"] = min(fts) if fts else None
    i["last_record_filetime"] = max(fts) if fts else None
    i["first_record_time_utc"] = _filetime(min(fts)) if fts else None
    i["last_record_time_utc"] = _filetime(max(fts)) if fts else None
    i["any_partial_record"] = any(c.get("partial_record") for c in chunks)
    i["records_crc32_all_valid"] = all(c.get("records_crc32_valid", False) for c in chunks if c["magic_valid"])
    i["chunks_crc32_all_valid"] = all(c.get("header_crc32_valid", False) for c in chunks if c["magic_valid"])
    i["count_matches_header"] = i["record_count"] == i["claimed_record_count"]
    i["count_matches_chunks"] = i["record_count"] == chunk_claimed
    i["chunks"] = chunks
    return i


ALIASES = {
    "records": "record_count", "event_record_count": "record_count", "total_records": "record_count", "num_records": "record_count",
    "chunks": "chunk_count", "number_of_chunks": "header_chunk_count", "chunk_count_header": "header_chunk_count",
    "next_record_identifier": "next_record_id", "next_event_record_id": "next_record_id",
    "is_truncated": "truncated", "is_dirty": "flags_dirty", "is_full": "flags_full", "dirty": "flags_dirty", "full": "flags_full",
    "header_crc_valid": "header_crc32_valid", "crc32_valid": "header_crc32_valid", "major": "major_version", "minor": "minor_version",
    "size_bytes": "file_size_bytes", "unique_record_count": "unique_record_id_count",
    "first_record_number": "first_record_id", "last_record_number": "last_record_id",
    "first_event_record_id": "first_record_id", "last_event_record_id": "last_record_id",
}


def field(b, name):
    i = info(b)
    n = ALIASES.get(name, name)
    if n in i:
        return i[n]
    if n.endswith("_hex") and n[:-4] in i and isinstance(i[n[:-4]], int):
        return "0x%08x" % i[n[:-4]]
    raise KeyError("unknown evtx field %s" % name)


if __name__ == "__main__":
    import sys, json
    i = info(open(sys.argv[1], "rb").read())
    ch = i.pop("chunks")
    i.pop("record_ids")
    print(json.dumps(i, indent=1, default=str))
    for c in ch:
        c.pop("record_ids", None)
        print(" chunk", json.dumps(c, default=str))
