"""Day-23 metadata 'Page Me Maybe': pure-Python SQLite 3 database identity parser -> `sqlite.<field>` resolver.
Header (100 bytes, big-endian, https://www.sqlite.org/fileformat.html) is parsed from the real bytes; the database may be
EMBEDDED (header at a non-zero offset: we locate `SQLite format 3\\0`), TRUNCATED (file shorter than header page count x page
size), COPIED (header page count stale vs. file size) or MISLABELED (.sqlite extension but no SQLite magic -> most fields are
`none`). Schema / tables come from reading the bytes with the stdlib sqlite3 module on a temp copy (read-only; falls back
gracefully when the file is damaged). Nothing is executed.
usage: sqlite.py <file.sqlite> [field ...]"""
import os, re, io, json, struct, hashlib, sqlite3, tempfile

MAGIC = b"SQLite format 3\x00"
ENCODINGS = {1: "UTF-8", 2: "UTF-16le", 3: "UTF-16be"}


def locate(b):
    """offset of the SQLite header inside b (0 for a plain database), or None when absent."""
    if b[:16] == MAGIC:
        return 0
    i = b.find(MAGIC)
    return i if i >= 0 else None


def header(h):
    """dict of the 100-byte header fields (h = 100+ bytes starting at the magic)."""
    ps = struct.unpack(">H", h[16:18])[0]
    page_size = 65536 if ps == 1 else ps
    d = {
        "magic_valid": h[:16] == MAGIC,
        "page_size_raw": ps,
        "page_size_bytes": page_size,
        "write_version": h[18],
        "read_version": h[19],
        "reserved_bytes_per_page": h[20],
        "max_embedded_payload_fraction": h[21],
        "min_embedded_payload_fraction": h[22],
        "leaf_payload_fraction": h[23],
        "file_change_counter": struct.unpack(">I", h[24:28])[0],
        "header_page_count": struct.unpack(">I", h[28:32])[0],
        "freelist_trunk_page": struct.unpack(">I", h[32:36])[0],
        "freelist_page_count": struct.unpack(">I", h[36:40])[0],
        "schema_cookie": struct.unpack(">I", h[40:44])[0],
        "schema_format_number": struct.unpack(">I", h[44:48])[0],
        "default_page_cache_size": struct.unpack(">i", h[48:52])[0],
        "largest_root_btree_page": struct.unpack(">I", h[52:56])[0],
        "text_encoding_code": struct.unpack(">I", h[56:60])[0],
        "user_version": struct.unpack(">i", h[60:64])[0],
        "incremental_vacuum": struct.unpack(">I", h[64:68])[0],
        "application_id": struct.unpack(">i", h[68:72])[0],
        "application_id_u32": struct.unpack(">I", h[68:72])[0],
        "version_valid_for": struct.unpack(">I", h[92:96])[0],
        "sqlite_version_number": struct.unpack(">I", h[96:100])[0],
    }
    d["text_encoding"] = ENCODINGS.get(d["text_encoding_code"], "none")
    d["application_id_hex"] = "0x%08x" % d["application_id_u32"]
    aid = h[68:72]
    d["application_id_ascii"] = aid.decode("ascii") if aid.isalpha() or (aid.isalnum() and aid != b"\x00" * 4) else "none"
    v = d["sqlite_version_number"]
    d["sqlite_version"] = "%d.%d.%d" % (v // 1000000, (v // 1000) % 1000, v % 1000) if v else "none"
    wv, rv = d["write_version"], d["read_version"]
    d["journal_mode"] = "wal" if (wv == 2 or rv == 2) else ("delete" if wv == 1 else "none")
    d["header_sha256"] = hashlib.sha256(h[:100]).hexdigest()
    return d


def _schema(dbbytes):
    """sqlite_master rows via the stdlib module on a temp copy (read-only); [] when unreadable."""
    fd, p = tempfile.mkstemp(suffix=".sqlite")
    try:
        os.write(fd, dbbytes); os.close(fd)
        c = sqlite3.connect("file:%s?mode=ro&immutable=1" % p, uri=True)
        try:
            rows = c.execute("select type,name,tbl_name,rootpage,sql from sqlite_master order by rowid").fetchall()
            counts = {}
            for t, n, _tn, _rp, _sql in rows:
                if t == "table":
                    try:
                        counts[n] = c.execute('select count(*) from "%s"' % n.replace('"', '""')).fetchone()[0]
                    except Exception:
                        counts[n] = None
            try:
                pragma = {k: c.execute("pragma %s" % k).fetchone()[0] for k in
                          ("page_size", "page_count", "freelist_count", "application_id", "user_version", "encoding",
                           "schema_version", "auto_vacuum")}
            except Exception:
                pragma = {}
            return rows, counts, pragma
        finally:
            c.close()
    except Exception:
        return [], {}, {}
    finally:
        try: os.unlink(p)
        except Exception: pass


def info(b):
    off = locate(b)
    d = {"file_size_bytes": len(b), "is_sqlite": off is not None, "header_offset": off, "embedded": bool(off),
         "sha256": hashlib.sha256(b).hexdigest(), "md5": hashlib.md5(b).hexdigest()}
    if off is None:
        d["format"] = sniff(b)
        return d
    db = b[off:]
    d.update(header(db[:100].ljust(100, b"\x00")))
    ps = d["page_size_bytes"]
    hp = d["header_page_count"]
    d["embedded_size_bytes"] = len(db)
    d["available_bytes"] = len(db)
    d["file_page_count"] = len(db) // ps if ps else 0           # whole pages actually present
    d["file_page_count_ceil"] = -(-len(db) // ps) if ps else 0
    d["expected_size_bytes"] = hp * ps                            # what the header claims
    d["header_claim_size_bytes"] = hp * ps
    # header page count is only trusted when version_valid_for == file_change_counter (sqlite rule); else derived from size
    valid_hdr = hp > 0 and d["version_valid_for"] == d["file_change_counter"]
    d["header_page_count_valid"] = valid_hdr
    d["page_count"] = hp if valid_hdr else d["file_page_count"]
    d["truncated"] = len(db) < hp * ps
    d["is_truncated"] = d["truncated"]
    d["missing_bytes"] = max(0, hp * ps - len(db))
    d["missing_page_count"] = max(0, hp - d["file_page_count"])
    d["trailing_bytes"] = len(db) - d["file_page_count"] * ps if ps else len(db)
    d["size_is_page_multiple"] = ps > 0 and len(db) % ps == 0
    d["page_geometry_valid"] = ps in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536) and len(db) % ps == 0 and len(db) >= hp * ps
    d["page_size_valid"] = ps in (512, 1024, 2048, 4096, 8192, 16384, 32768, 65536)
    d["oversized_claim"] = hp * ps > len(db)
    d["impossible_claim"] = d["oversized_claim"] or (not d["page_size_valid"]) or (d["freelist_page_count"] > hp) or \
        (d["largest_root_btree_page"] > hp and valid_hdr)
    rows, counts, pragma = _schema(db)
    d["schema_rows"] = rows
    d["table_names"] = [n for t, n, *_ in rows if t == "table"]
    d["index_names"] = [n for t, n, *_ in rows if t == "index"]
    d["view_names"] = [n for t, n, *_ in rows if t == "view"]
    d["trigger_names"] = [n for t, n, *_ in rows if t == "trigger"]
    d["table_count"] = len(d["table_names"])
    d["index_count"] = len(d["index_names"])
    d["object_count"] = len(rows)
    d["row_counts"] = counts
    d["total_row_count"] = sum(v for v in counts.values() if isinstance(v, int))
    d["pragma"] = pragma
    d["schema_sql"] = [r[4] for r in rows if r[4]]
    d["root_pages"] = {n: rp for _t, n, _tn, rp, _s in rows}
    d["max_root_page"] = max([rp for *_a, rp, _s in [(r[0], r[1], r[2], r[3], r[4]) for r in rows]] or [0])
    return d


def sniff(b):
    if b[:2] == b"PK": return "zip"
    if b[:4] == b"\x7fELF": return "elf"
    if b[:2] == b"MZ": return "pe"
    if b[:8] == b"\x89PNG\r\n\x1a\n": return "png"
    if b[:3] == b"\xff\xd8\xff": return "jpeg"
    if b[:5] == b"%PDF-": return "pdf"
    if b[:4] == b"\xd0\xcf\x11\xe0": return "ole"
    if b[:2] == b"\x1f\x8b": return "gzip"
    if b[:4] in (b"RIFF",): return "riff"
    if b[4:8] == b"ftyp": return "mp4"
    try:
        b.decode("utf-8"); return "text"
    except Exception:
        return "unknown"


_ALIASES = {
    "page_size": "page_size_bytes", "pagesize": "page_size_bytes", "page_size_in_bytes": "page_size_bytes",
    "page_count_header": "header_page_count", "declared_page_count": "header_page_count", "in_header_page_count": "header_page_count",
    "header_database_size_pages": "header_page_count", "database_size_in_pages": "header_page_count", "claimed_page_count": "header_page_count",
    "actual_page_count": "file_page_count", "computed_page_count": "file_page_count", "physical_page_count": "file_page_count",
    "pages_present": "file_page_count", "page_count_from_size": "file_page_count",
    "size_bytes": "file_size_bytes", "file_size": "file_size_bytes",
    "encoding": "text_encoding", "text_encoding_name": "text_encoding",
    "appid": "application_id", "app_id": "application_id", "application_id_int": "application_id", "application_id_decimal": "application_id",
    "change_counter": "file_change_counter", "schema_format": "schema_format_number", "schema_version": "schema_cookie",
    "freelist_count": "freelist_page_count", "freelist_pages": "freelist_page_count",
    "tables": "table_names", "table_list": "table_names", "indexes": "index_names", "index_list": "index_names",
    "truncated_claim": "truncated", "header_claims_more_pages_than_file": "oversized_claim",
    "library_version": "sqlite_version", "sqlite_version_string": "sqlite_version", "version": "sqlite_version",
    "header_offset_bytes": "header_offset", "embedded_offset": "header_offset", "offset": "header_offset",
    "is_embedded": "embedded", "valid_magic": "magic_valid", "magic_present": "magic_valid", "header_valid": "magic_valid",
    "is_valid_sqlite": "is_sqlite", "valid": "is_sqlite",
    "row_count": "total_row_count", "total_rows": "total_row_count",
}


def field(b, snake):
    """value of sqlite.<snake> for the given bytes (strings / ints / lists; 'none' when absent)."""
    i = info(b)
    s = snake.lower()
    s = _ALIASES.get(s, s)
    if s in i:
        v = i[s]
        if isinstance(v, bool):
            return "true" if v else "false"
        if v is None:
            return "none"
        return v
    m = re.fullmatch(r"(?:table|rows?)_count_(\w+)", s)
    if m and m.group(1) in i.get("row_counts", {}):
        return i["row_counts"][m.group(1)]
    m = re.fullmatch(r"(\w+)_row_count", s)
    if m and m.group(1) in i.get("row_counts", {}):
        return i["row_counts"][m.group(1)]
    if s in ("mislabeled", "is_mislabeled", "label_mismatch"):
        return "false" if i["is_sqlite"] else "true"
    if s in ("detected_format", "actual_format", "true_format"):
        return "sqlite" if i["is_sqlite"] else i.get("format", "unknown")
    return "none"


if __name__ == "__main__":
    import sys
    b = open(sys.argv[1], "rb").read()
    i = info(b)
    i.pop("schema_rows", None)
    print(json.dumps(i, indent=1, default=str))
    for f in sys.argv[2:]:
        print(f, "=", field(b, f))
