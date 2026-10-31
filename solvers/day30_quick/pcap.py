"""Pure-Python packet-capture parser (classic libpcap LE/BE, usec/nsec, + pcapng SHB/IDB/EPB/SPB/OPB) with strict validity checks.
Day 27 'Packet Loss Prevention' metadata lane: pcap.<field> (packet_count, ...).
usage: pcap.py <file> [field ...]"""
import sys, struct, hashlib, datetime

LINKTYPES = {0: "null", 1: "ethernet", 101: "raw", 105: "ieee802_11", 113: "linux_sll", 127: "ieee802_11_radiotap",
             147: "user0", 148: "user1", 149: "user2", 150: "user3", 228: "ipv4", 229: "ipv6", 276: "linux_sll2"}
MAGICS = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6, "little", "usec"), b"\xa1\xb2\xc3\xd4": (">", 1e-6, "big", "usec"),
          b"\x4d\x3c\xb2\xa1": ("<", 1e-9, "little", "nsec"), b"\xa1\xb2\x3c\x4d": (">", 1e-9, "big", "nsec")}


def _iso(t):
    try:
        return datetime.datetime.fromtimestamp(int(t), datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def parse_classic(b, r):
    e, res, endian, unit = MAGICS[b[:4]]
    r.update(format="pcap", endianness=endian, timestamp_resolution=unit)
    if len(b) < 24:
        r["errors"].append("truncated_global_header"); return
    vmaj, vmin, tz, sig, snap, lt = struct.unpack(e + "HHiIII", b[4:24])
    r.update(version_major=vmaj, version_minor=vmin, version="%d.%d" % (vmaj, vmin), thiszone=tz, sigfigs=sig,
             snaplen=snap, linktype=lt & 0xFFFF, linktype_raw=lt, linktype_name=LINKTYPES.get(lt & 0xFFFF, str(lt & 0xFFFF)))
    if (vmaj, vmin) != (2, 4):
        r["errors"].append("bad_version")
    off = 24
    pk = []
    while off < len(b):
        if len(b) - off < 16:
            r["errors"].append("truncated_record_header@%d" % off); break
        ts, tf, incl, orig = struct.unpack(e + "IIII", b[off:off + 16])
        if off + 16 + incl > len(b):
            r["errors"].append("truncated_record_data@%d" % off); break
        bad = []
        if snap and incl > snap:
            bad.append("incl_gt_snaplen")
        if incl > orig:
            bad.append("incl_gt_orig")
        if tf >= (1000000 if unit == "usec" else 1000000000):
            bad.append("frac_overflow")
        if bad:
            r["errors"].append("%s@%d" % ("+".join(bad), off))
        pk.append(dict(offset=off, ts_sec=ts, ts_frac=tf, ts=ts + tf * res, incl_len=incl, orig_len=orig,
                       data=b[off + 16:off + 16 + incl], bad=bad))
        off += 16 + incl
    r["packets"] = pk
    r["parsed_bytes"] = off


def parse_ng(b, r):
    r.update(format="pcapng")
    off = 0
    e = "<"
    pk = []
    ifs = []
    while off < len(b):
        if len(b) - off < 12:
            r["errors"].append("truncated_block@%d" % off); break
        bt = struct.unpack(e + "I", b[off:off + 4])[0]
        if bt == 0x0A0D0D0A:
            bom = b[off + 8:off + 12]
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">" if bom == b"\x1a\x2b\x3c\x4d" else e
            if bom not in (b"\x4d\x3c\x2b\x1a", b"\x1a\x2b\x3c\x4d"):
                r["errors"].append("bad_bom@%d" % off)
            r.setdefault("endianness", "little" if e == "<" else "big")
            vmaj, vmin = struct.unpack(e + "HH", b[off + 12:off + 16])
            r.setdefault("version", "%d.%d" % (vmaj, vmin))
            r.setdefault("version_major", vmaj); r.setdefault("version_minor", vmin)
            r["section_count"] = r.get("section_count", 0) + 1
        bl = struct.unpack(e + "I", b[off + 4:off + 8])[0]
        if bl < 12 or bl % 4 or off + bl > len(b):
            r["errors"].append("bad_block_len@%d" % off); break
        if struct.unpack(e + "I", b[off + bl - 4:off + bl])[0] != bl:
            r["errors"].append("trailer_mismatch@%d" % off)
        body = b[off + 8:off + bl - 4]
        if bt == 1:
            lt, _, snap = struct.unpack(e + "HHI", body[:8])
            ifs.append(dict(linktype=lt, snaplen=snap))
            r.setdefault("linktype", lt); r.setdefault("snaplen", snap)
            r.setdefault("linktype_name", LINKTYPES.get(lt, str(lt)))
        elif bt == 6:
            iid, th, tl, incl, orig = struct.unpack(e + "IIIII", body[:20])
            pk.append(dict(offset=off, ts=((th << 32) | tl) * 1e-6, ts_sec=((th << 32) | tl) // 1000000, incl_len=incl,
                           orig_len=orig, data=body[20:20 + incl], iface=iid, bad=[]))
        elif bt == 3:
            orig = struct.unpack(e + "I", body[:4])[0]
            pk.append(dict(offset=off, ts=None, ts_sec=None, incl_len=len(body) - 4, orig_len=orig, data=body[4:], bad=[]))
        elif bt == 2:
            iid, drops, th, tl, incl, orig = struct.unpack(e + "HHIIII", body[:20])
            pk.append(dict(offset=off, ts=((th << 32) | tl) * 1e-6, ts_sec=((th << 32) | tl) // 1000000, incl_len=incl,
                           orig_len=orig, data=body[20:20 + incl], iface=iid, bad=[]))
        off += bl
    r["interfaces"] = ifs
    r["interface_count"] = len(ifs)
    r["packets"] = pk
    r["parsed_bytes"] = off


def parse(b):
    r = {"file_size": len(b), "errors": [], "magic_hex": b[:4].hex()}
    if b[:4] in MAGICS:
        parse_classic(b, r)
    elif b[:4] == b"\x0a\x0d\x0d\x0a":
        parse_ng(b, r)
    else:
        r["format"] = "unknown"
        r["errors"].append("bad_magic")
        r["packets"] = []
    pk = r["packets"]
    r["packet_count"] = len(pk)
    r["valid"] = not r["errors"]
    r["malformed"] = bool(r["errors"])
    r["error"] = r["errors"][0] if r["errors"] else "none"
    r["captured_bytes"] = sum(p["incl_len"] for p in pk)
    r["original_bytes"] = sum(p["orig_len"] for p in pk)
    r["truncated_packet_count"] = sum(1 for p in pk if p["incl_len"] < p["orig_len"])
    r["max_packet_length"] = max((p["incl_len"] for p in pk), default=0)
    r["max_original_length"] = max((p["orig_len"] for p in pk), default=0)
    ts = [p["ts"] for p in pk if p.get("ts") is not None]
    if ts:
        r["first_timestamp"] = int(min(ts)); r["last_timestamp"] = int(max(ts))
        r["first_timestamp_iso"] = _iso(min(ts)); r["last_timestamp_iso"] = _iso(max(ts))
        r["duration_seconds"] = round(max(ts) - min(ts), 6)
    r["trailing_bytes"] = len(b) - r.get("parsed_bytes", len(b))
    r["payloads"] = [p["data"] for p in pk]
    r["payload_strings"] = [p["data"].decode("latin-1") for p in pk]
    r["sha256"] = hashlib.sha256(b).hexdigest()
    return r


ALIASES = {"packets_count": "packet_count", "count": "packet_count", "num_packets": "packet_count",
           "frame_count": "packet_count", "packet_total": "packet_count", "link_type": "linktype",
           "snapshot_length": "snaplen", "snap_len": "snaplen", "byte_order": "endianness", "is_valid": "valid",
           "is_malformed": "malformed"}


def field(b, fld):
    r = parse(b)
    f = ALIASES.get(fld, fld)
    if f in r and f not in ("packets", "payloads"):
        return r[f]
    f2 = f.replace("-", "_")
    if f2 in r:
        return r[f2]
    raise KeyError(fld)


if __name__ == "__main__":
    b = open(sys.argv[1], "rb").read()
    r = parse(b)
    keys = sys.argv[2:] or [k for k in r if k not in ("packets", "payloads")]
    for k in keys:
        print(k, "=", r.get(k))
    for p in r["packets"][:50]:
        print("  pkt @%d ts=%s incl=%d orig=%d bad=%s data=%r" % (p["offset"], p.get("ts"), p["incl_len"], p["orig_len"],
                                                                 p["bad"], p["data"][:64]))
