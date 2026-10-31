"""Day-25 metadata 'Hive Mind': pure-Python Windows registry hive (regf) parser -> `registry.<field>` resolver.
Base block (4096 bytes, https://github.com/msuhanov/regf/blob/master/Windows%20registry%20file%20format%20specification.md)
+ hive bins (`hbin`) + cells (nk / vk / sk / lf-lh-li-ri lists / db) are parsed from the real bytes. Nothing is executed.
hive_root_name = key name of the ROOT nk cell (header root_cell_offset, relative to the first hbin at file offset 0x1000);
the header's embedded file name (offset 48, 64 bytes UTF-16LE, last 31 chars of the on-disk path) is kept separately as
header_file_name because the prompt says the hives were RENAMED (the on-disk name is not the true root).
usage: reghive.py <file.hiv> [field ...]"""
import struct, json, hashlib, datetime, re

MAGIC = b"regf"
HBIN = b"hbin"
EPOCH = datetime.datetime(1601, 1, 1, tzinfo=datetime.timezone.utc)
REG_TYPES = {0: "REG_NONE", 1: "REG_SZ", 2: "REG_EXPAND_SZ", 3: "REG_BINARY", 4: "REG_DWORD", 5: "REG_DWORD_BIG_ENDIAN",
             6: "REG_LINK", 7: "REG_MULTI_SZ", 8: "REG_RESOURCE_LIST", 9: "REG_FULL_RESOURCE_DESCRIPTOR",
             10: "REG_RESOURCE_REQUIREMENTS_LIST", 11: "REG_QWORD"}
NK_FLAGS = {0x0001: "KEY_VOLATILE", 0x0002: "KEY_HIVE_EXIT", 0x0004: "KEY_HIVE_ENTRY", 0x0008: "KEY_NO_DELETE",
            0x0010: "KEY_SYM_LINK", 0x0020: "KEY_COMP_NAME", 0x0040: "KEY_PREDEF_HANDLE", 0x0080: "KEY_VIRTUAL_SOURCE",
            0x0100: "KEY_VIRTUAL_TARGET", 0x0200: "KEY_VIRTUAL_STORE"}


def filetime(v):
    if not v:
        return "none"
    try:
        return (EPOCH + datetime.timedelta(microseconds=v // 10)).strftime("%Y-%m-%dT%H:%M:%S.") + "%07dZ" % (v % 10000000)
    except Exception:
        return "none"


def guid(b):
    if len(b) < 16:
        return "none"
    d1, d2, d3 = struct.unpack("<IHH", b[:8])
    return "%08x-%04x-%04x-%s-%s" % (d1, d2, d3, b[8:10].hex(), b[10:16].hex())


def utf16z(b):
    s = b.decode("utf-16-le", "replace")
    return s.split("\x00", 1)[0]


def key_name(b, flags):
    return b.decode("latin-1") if flags & 0x20 else b.decode("utf-16-le", "replace")


def header(h):
    d = {"magic_valid": h[:4] == MAGIC}
    (d["primary_sequence_number"], d["secondary_sequence_number"]) = struct.unpack("<II", h[4:12])
    d["sequence_numbers_match"] = d["primary_sequence_number"] == d["secondary_sequence_number"]
    d["last_written_filetime"] = struct.unpack("<Q", h[12:20])[0]
    d["last_written_utc"] = filetime(d["last_written_filetime"])
    (d["major_version"], d["minor_version"], d["file_type"], d["file_format"], d["root_cell_offset"],
     d["hive_bins_data_size"], d["clustering_factor"]) = struct.unpack("<7I", h[20:48])
    d["version"] = "%d.%d" % (d["major_version"], d["minor_version"])
    d["root_cell_offset_hex"] = "0x%x" % d["root_cell_offset"]
    d["root_cell_file_offset"] = 0x1000 + d["root_cell_offset"]
    d["file_type_name"] = {0: "primary", 1: "transaction_log", 2: "transaction_log", 6: "transaction_log"}.get(d["file_type"], "unknown")
    d["file_format_name"] = {1: "direct_memory_load"}.get(d["file_format"], "unknown")
    d["header_file_name"] = utf16z(h[48:112])
    d["rm_id_guid"] = guid(h[112:128])
    d["log_id_guid"] = guid(h[128:144])
    d["flags"] = struct.unpack("<I", h[144:148])[0]
    d["tm_id_guid"] = guid(h[148:164])
    d["guid_signature"] = h[164:168].decode("latin-1")
    d["last_reorganized_filetime"] = struct.unpack("<Q", h[168:176])[0]
    d["last_reorganized_utc"] = filetime(d["last_reorganized_filetime"])
    d["checksum_stored"] = struct.unpack("<I", h[508:512])[0]
    x = 0
    for i in range(0, 508, 4):
        x ^= struct.unpack("<I", h[i:i + 4])[0]
    if x == 0xFFFFFFFF:
        x = 0xFFFFFFFE
    if x == 0:
        x = 1
    d["checksum_computed"] = x
    d["checksum_valid"] = x == d["checksum_stored"]
    d["checksum_hex"] = "0x%08x" % d["checksum_stored"]
    d["boot_type"] = struct.unpack("<I", h[4088:4092])[0] if len(h) >= 4092 else 0
    d["boot_recover"] = struct.unpack("<I", h[4092:4096])[0] if len(h) >= 4096 else 0
    d["header_sha256"] = hashlib.sha256(h[:4096]).hexdigest()
    return d


class Hive:
    def __init__(self, b):
        self.b = b
        self.h = header(b[:4096].ljust(4096, b"\x00"))
        self.bins = []
        off = 0x1000
        while off + 32 <= len(b) and b[off:off + 4] == HBIN:
            rel, size = struct.unpack("<II", b[off + 4:off + 12])
            ts = struct.unpack("<Q", b[off + 20:off + 28])[0]
            self.bins.append({"file_offset": off, "offset": rel, "size": size, "timestamp_utc": filetime(ts)})
            if size == 0:
                break
            off += size
        self.bins_end = off
        self.cells = {}  # rel offset -> (size, payload)
        for hb in self.bins:
            o = hb["file_offset"] + 32
            end = hb["file_offset"] + hb["size"]
            while o + 4 <= end:
                sz = struct.unpack("<i", b[o:o + 4])[0]
                if sz == 0:
                    break
                asz = abs(sz)
                if asz < 4 or o + asz > end:
                    break
                self.cells[o - 0x1000] = (sz, b[o + 4:o + asz])
                o += asz
        self.keys = {}
        self.root = self.nk(self.h["root_cell_offset"])
        self.all_keys = []
        self.all_values = []
        if self.root:
            self.walk(self.root, "")

    def cell(self, rel):
        c = self.cells.get(rel)
        if c is None:
            o = 0x1000 + rel
            if 0 <= o + 4 <= len(self.b):
                sz = struct.unpack("<i", self.b[o:o + 4])[0]
                if sz and abs(sz) >= 4 and o + abs(sz) <= len(self.b):
                    return (sz, self.b[o + 4:o + abs(sz)])
            return None
        return c

    def nk(self, rel):
        c = self.cell(rel)
        if not c or c[1][:2] != b"nk":
            return None
        p = c[1]
        k = {"offset": rel, "allocated": c[0] < 0}
        k["flags"] = struct.unpack("<H", p[2:4])[0]
        k["flag_names"] = [n for f, n in sorted(NK_FLAGS.items()) if k["flags"] & f]
        k["last_written_filetime"] = struct.unpack("<Q", p[4:12])[0]
        k["last_written_utc"] = filetime(k["last_written_filetime"])
        (k["access_bits"], k["parent_offset"], k["subkey_count"], k["volatile_subkey_count"], k["subkey_list_offset"],
         k["volatile_subkey_list_offset"], k["value_count"], k["value_list_offset"], k["security_offset"],
         k["class_name_offset"]) = struct.unpack("<10I", p[12:52])
        (k["largest_subkey_name_length"], k["largest_subkey_class_length"], k["largest_value_name_length"],
         k["largest_value_data_size"], k["workvar"]) = struct.unpack("<5I", p[52:72])
        nl, cl = struct.unpack("<HH", p[72:76])
        k["name_length"] = nl
        k["name"] = key_name(p[76:76 + nl], k["flags"])
        k["class_name"] = "none"
        if k["class_name_offset"] != 0xFFFFFFFF and cl:
            cc = self.cell(k["class_name_offset"])
            if cc:
                k["class_name"] = cc[1][:cl].decode("utf-16-le", "replace")
        k["is_root"] = bool(k["flags"] & 0x04)
        return k

    def subkey_offsets(self, rel, depth=0):
        if rel == 0xFFFFFFFF or depth > 8:
            return []
        c = self.cell(rel)
        if not c:
            return []
        p = c[1]
        sig = p[:2]
        n = struct.unpack("<H", p[2:4])[0]
        out = []
        if sig in (b"lf", b"lh"):
            for i in range(n):
                out.append(struct.unpack("<I", p[4 + 8 * i:8 + 8 * i])[0])
        elif sig == b"li":
            for i in range(n):
                out.append(struct.unpack("<I", p[4 + 4 * i:8 + 4 * i])[0])
        elif sig == b"ri":
            for i in range(n):
                out += self.subkey_offsets(struct.unpack("<I", p[4 + 4 * i:8 + 4 * i])[0], depth + 1)
        return out

    def values(self, k):
        out = []
        if k["value_count"] == 0 or k["value_list_offset"] == 0xFFFFFFFF:
            return out
        c = self.cell(k["value_list_offset"])
        if not c:
            return out
        p = c[1]
        for i in range(k["value_count"]):
            if 4 * i + 4 > len(p):
                break
            vo = struct.unpack("<I", p[4 * i:4 * i + 4])[0]
            vc = self.cell(vo)
            if not vc or vc[1][:2] != b"vk":
                continue
            q = vc[1]
            nl, dl, do, ty, fl = struct.unpack("<HIIIH", q[2:18])
            v = {"offset": vo, "name_length": nl, "data_length_raw": dl, "data_offset": do, "type": ty,
                 "type_name": REG_TYPES.get(ty, "0x%x" % ty), "flags": fl}
            v["name"] = q[20:20 + nl].decode("latin-1") if fl & 1 else q[20:20 + nl].decode("utf-16-le", "replace")
            if nl == 0:
                v["name"] = "(Default)"
            inline = bool(dl & 0x80000000)
            size = dl & 0x7FFFFFFF
            if inline:
                data = q[8:12][:size]
            else:
                dc = self.cell(do)
                data = dc[1][:size] if dc else b""
                if dc and dc[1][:2] == b"db" and size > 16344:  # big data
                    nseg = struct.unpack("<H", dc[1][2:4])[0]
                    lst = self.cell(struct.unpack("<I", dc[1][4:8])[0])
                    data = b""
                    for s in range(nseg):
                        so = struct.unpack("<I", lst[1][4 * s:4 * s + 4])[0]
                        sc = self.cell(so)
                        data += sc[1][:16344] if sc else b""
                    data = data[:size]
            v["data_size"] = size
            v["data_inline"] = inline
            v["data_hex"] = data.hex()
            v["data_sha256"] = hashlib.sha256(data).hexdigest()
            v["data_md5"] = hashlib.md5(data).hexdigest()
            v["value"] = decode_data(ty, data)
            out.append(v)
        return out

    def walk(self, k, path, depth=0):
        k["path"] = (path + "\\" + k["name"]) if path else k["name"]
        k["depth"] = depth
        k["values"] = self.values(k)
        self.all_keys.append(k)
        self.all_values += [(k, v) for v in k["values"]]
        k["subkeys"] = []
        if depth > 64:
            return
        for so in self.subkey_offsets(k["subkey_list_offset"]):
            sk = self.nk(so)
            if sk:
                k["subkeys"].append(sk)
                self.walk(sk, k["path"], depth + 1)


def decode_data(ty, data):
    try:
        if ty in (1, 2, 6):
            return utf16z(data)
        if ty == 7:
            s = data.decode("utf-16-le", "replace")
            return [x for x in s.split("\x00") if x]
        if ty == 4 and len(data) >= 4:
            return struct.unpack("<I", data[:4])[0]
        if ty == 5 and len(data) >= 4:
            return struct.unpack(">I", data[:4])[0]
        if ty == 11 and len(data) >= 8:
            return struct.unpack("<Q", data[:8])[0]
    except Exception:
        pass
    return data.hex()


def info(b):
    hv = Hive(b)
    d = dict(hv.h)
    d["file_size"] = len(b)
    d["sha256"] = hashlib.sha256(b).hexdigest()
    d["md5"] = hashlib.md5(b).hexdigest()
    d["sha1"] = hashlib.sha1(b).hexdigest()
    d["hbin_count"] = len(hv.bins)
    d["hbin_total_size"] = sum(x["size"] for x in hv.bins)
    d["hive_bins_data_size_matches"] = d["hbin_total_size"] == d["hive_bins_data_size"]
    d["cell_count"] = len(hv.cells)
    d["allocated_cell_count"] = sum(1 for s, _ in hv.cells.values() if s < 0)
    d["free_cell_count"] = sum(1 for s, _ in hv.cells.values() if s > 0)
    d["nk_cell_count"] = sum(1 for s, p in hv.cells.values() if p[:2] == b"nk")
    d["vk_cell_count"] = sum(1 for s, p in hv.cells.values() if p[:2] == b"vk")
    d["sk_cell_count"] = sum(1 for s, p in hv.cells.values() if p[:2] == b"sk")
    d["header_file_name_stem"] = re.sub(r"\.[^.]*$", "", d["header_file_name"].split("\\")[-1])
    r = hv.root
    if r:
        d["hive_root_name"] = r["name"]
        d["root_key_name"] = r["name"]
        d["root_name_length"] = r["name_length"]
        d["root_is_hive_entry"] = r["is_root"]
        d["root_flags"] = r["flags"]
        d["root_flags_hex"] = "0x%04x" % r["flags"]
        d["root_flag_names"] = r["flag_names"]
        d["root_last_written_utc"] = r["last_written_utc"]
        d["root_last_written_filetime"] = r["last_written_filetime"]
        d["root_subkey_count"] = r["subkey_count"]
        d["root_value_count"] = r["value_count"]
        d["root_class_name"] = r["class_name"]
        d["root_parent_offset"] = r["parent_offset"]
        d["root_security_offset"] = r["security_offset"]
        d["root_value_names"] = [v["name"] for v in r["values"]]
        d["root_values"] = {v["name"]: v["value"] for v in r["values"]}
        d["root_value_types"] = {v["name"]: v["type_name"] for v in r["values"]}
        for v in r["values"]:
            d["root_value_" + re.sub(r"\W+", "_", v["name"]).lower()] = v["value"]
            d["value_" + re.sub(r"\W+", "_", v["name"]).lower()] = v["value"]
        d["key_count"] = len(hv.all_keys)
        d["subkey_count_total"] = len(hv.all_keys) - 1
        d["value_count_total"] = len(hv.all_values)
        d["key_paths"] = [k["path"] for k in hv.all_keys]
        d["value_names"] = [v["name"] for _, v in hv.all_values]
        d["max_depth"] = max(k["depth"] for k in hv.all_keys)
        d["last_written_key_utc"] = max(k["last_written_utc"] for k in hv.all_keys)
    else:
        for k in ("hive_root_name", "root_key_name", "root_last_written_utc", "root_class_name"):
            d[k] = "none"
        d["root_subkey_count"] = d["root_value_count"] = d["key_count"] = d["value_count_total"] = 0
        d["root_value_names"] = []
    d["root_cell_valid"] = r is not None
    return d


ALIASES = {
    "root_name": "hive_root_name", "root": "hive_root_name", "root_key": "hive_root_name", "hive_root": "hive_root_name",
    "root_key_name": "hive_root_name", "true_root": "hive_root_name", "true_root_name": "hive_root_name",
    "file_name": "header_file_name", "filename": "header_file_name", "hive_file_name": "header_file_name",
    "embedded_file_name": "header_file_name", "embedded_filename": "header_file_name", "header_filename": "header_file_name",
    "hive_name": "header_file_name", "name": "header_file_name", "path": "header_file_name", "file_path": "header_file_name",
    "host_label": "header_file_name_stem", "host": "header_file_name_stem", "system": "header_file_name_stem",
    "last_written": "last_written_utc", "last_written_timestamp": "last_written_utc", "timestamp_utc": "last_written_utc",
    "timestamp": "last_written_utc", "modified_utc": "last_written_utc", "last_modified_utc": "last_written_utc",
    "root_last_written": "root_last_written_utc", "root_timestamp_utc": "root_last_written_utc",
    "primary_sequence": "primary_sequence_number", "secondary_sequence": "secondary_sequence_number",
    "sequence_match": "sequence_numbers_match", "sequences_match": "sequence_numbers_match", "dirty": "sequence_numbers_match",
    "major": "major_version", "minor": "minor_version", "format_version": "version", "hive_version": "version",
    "root_offset": "root_cell_offset", "root_cell_offset_dec": "root_cell_offset",
    "bins_size": "hive_bins_data_size", "hbins_size": "hive_bins_data_size", "data_size": "hive_bins_data_size",
    "checksum": "checksum_hex", "header_checksum": "checksum_hex", "checksum_ok": "checksum_valid", "header_checksum_valid": "checksum_valid",
    "subkey_count": "root_subkey_count", "value_count": "root_value_count", "values": "root_value_names",
    "value_names_json": "root_value_names", "key_count_total": "key_count", "total_keys": "key_count", "total_values": "value_count_total",
    "marker": "value_marker", "marker_value": "value_marker", "ordinal": "value_ordinal", "ordinal_value": "value_ordinal",
    "class_name": "root_class_name", "hbins": "hbin_count", "bin_count": "hbin_count", "type": "file_type_name",
    "file_type_name_str": "file_type_name", "format": "file_format_name", "size_bytes": "file_size",
}


def field(b, name):
    d = info(b)
    n = name.lower()
    if n in d:
        return d[n]
    if n in ALIASES and ALIASES[n] in d:
        return d[ALIASES[n]]
    # root_value_<name> / value_<name> dynamic lookups
    for pfx in ("root_value_", "value_"):
        if n.startswith(pfx) and n in d:
            return d[n]
    if n.endswith("_hex") and n[:-4] in d and isinstance(d[n[:-4]], int):
        return "0x%x" % d[n[:-4]]
    if n.endswith("_dec") and n[:-4] in d and isinstance(d[n[:-4]], int):
        return d[n[:-4]]
    raise KeyError("registry field %s not known; have %s" % (name, sorted(k for k in d if not k.startswith("key_paths"))))


if __name__ == "__main__":
    import sys
    b = open(sys.argv[1], "rb").read()
    d = info(b)
    if len(sys.argv) > 2:
        for f in sys.argv[2:]:
            print(f, "=", json.dumps(field(b, f), default=str))
    else:
        for k, v in d.items():
            print("%-36s %s" % (k, json.dumps(v, default=str)[:200]))
