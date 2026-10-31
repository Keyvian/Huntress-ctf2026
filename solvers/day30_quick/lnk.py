"""Pure-Python Windows shell link (.lnk, MS-SHLLINK) parser for the day-14 'Shortcut Home' metadata lane.
LNK(b).info -> flat dict of snake_case fields; LNK(b).target_candidates() -> where the link points, per structure.
usage: lnk.py <file.lnk>...   (dumps every field as JSON)"""
import sys, struct, uuid, datetime, json

FLAG_NAMES = ["HasLinkTargetIDList", "HasLinkInfo", "HasName", "HasRelativePath", "HasWorkingDir", "HasArguments",
              "HasIconLocation", "IsUnicode", "ForceNoLinkInfo", "HasExpString", "RunInSeparateProcess", "Unused1",
              "HasDarwinID", "RunAsUser", "HasExpIcon", "NoPidlAlias", "Unused2", "RunWithShimLayer",
              "ForceNoLinkTrack", "EnableTargetMetadata", "DisableLinkPathTracking", "DisableKnownFolderTracking",
              "DisableKnownFolderAlias", "AllowLinkToLink", "UnaliasOnSave", "PreferEnvironmentPath",
              "KeepLocalIDListForUNCTarget"]
ATTR_NAMES = ["READONLY", "HIDDEN", "SYSTEM", "Reserved1", "DIRECTORY", "ARCHIVE", "Reserved2", "NORMAL",
              "TEMPORARY", "SPARSE_FILE", "REPARSE_POINT", "COMPRESSED", "OFFLINE", "NOT_CONTENT_INDEXED", "ENCRYPTED"]
SHOW = {1: "SW_SHOWNORMAL", 3: "SW_SHOWMAXIMIZED", 7: "SW_SHOWMINNOACTIVE"}
DRIVE_TYPES = {0: "DRIVE_UNKNOWN", 1: "DRIVE_NO_ROOT_DIR", 2: "DRIVE_REMOVABLE", 3: "DRIVE_FIXED", 4: "DRIVE_REMOTE",
               5: "DRIVE_CDROM", 6: "DRIVE_RAMDISK"}
KNOWN_ROOTS = {"20d04fe0-3aea-1069-a2d8-08002b30309d": "My Computer", "450d8fba-ad25-11d0-98a8-0800361b1103": "My Documents",
               "208d2c60-3aea-1069-a2d7-08002b30309d": "My Network Places", "59031a47-3f72-44a7-89c5-5595fe6b30ee": "Users Files",
               "871c5380-42a0-1069-a2ea-08002b30309d": "Internet Explorer", "645ff040-5081-101b-9f08-00aa002f954e": "Recycle Bin",
               "21ec2020-3aea-1069-a2dd-08002b30309d": "Control Panel", "26ee0668-a00a-44d7-9371-beb064c98683": "Control Panel"}
SIGS = {0xA0000001: "environment_variables", 0xA0000002: "console", 0xA0000003: "tracker", 0xA0000004: "console_fe",
        0xA0000005: "special_folder", 0xA0000006: "darwin", 0xA0000007: "icon_environment", 0xA0000008: "shim",
        0xA0000009: "property_store", 0xA000000B: "known_folder", 0xA000000C: "vista_and_above_idlist"}


def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]
def u64(b, o): return struct.unpack_from("<Q", b, o)[0]


def cstr(b, o, enc="cp1252"):
    e = b.index(b"\x00", o)
    return b[o:e].decode(enc, "replace")


def wstr(b, o):
    e = o
    while e + 1 < len(b) and b[e:e + 2] != b"\x00\x00":
        e += 2
    return b[o:e].decode("utf-16-le", "replace")


def fixed_ansi(b):
    return b.split(b"\x00", 1)[0].decode("cp1252", "replace")


def fixed_wide(b):
    s = b.decode("utf-16-le", "replace")
    return s.split("\x00", 1)[0]


def guid(b, o=0):
    return str(uuid.UUID(bytes_le=bytes(b[o:o + 16])))


def filetime(v):
    if not v:
        return None
    try:
        return (datetime.datetime(1601, 1, 1) + datetime.timedelta(microseconds=v // 10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    except OverflowError:
        return None


def dosdt(v):
    if not v:
        return None
    d, t = v & 0xffff, v >> 16
    try:
        return datetime.datetime(1980 + (d >> 9), (d >> 5) & 15, d & 31, t >> 11, (t >> 5) & 63, (t & 31) * 2).strftime("%Y-%m-%dT%H:%M:%S")
    except ValueError:
        return None


def parse_item(it):
    """one shell item (without its size field) -> dict(kind, name)."""
    t = it[0] if it else 0
    if t == 0x1F:
        g = guid(it, 2) if len(it) >= 18 else ""
        return dict(kind="root", guid=g, name=KNOWN_ROOTS.get(g, "{%s}" % g))
    if 0x20 <= t <= 0x2F:
        return dict(kind="volume", name=cstr(it, 1) if len(it) > 1 else "")
    if 0x30 <= t <= 0x3F:
        short = cstr(it, 12)
        o = 12 + len(short.encode("cp1252", "replace")) + 1
        if o % 2:
            o += 1
        if t & 0x04:  # unicode short name
            short = wstr(it, 12); o = 12 + 2 * len(short) + 2
        long = None
        while o + 8 <= len(it):
            sz = u16(it, o)
            if sz < 8 or o + sz > len(it) + 2:
                break
            ver, sig = u16(it, o + 2), u32(it, o + 4)
            if sig == 0xBEEF0004:
                p = o + 8 + 4 + 4 + 2  # ctime, atime, identifier
                if ver >= 7: p += 2 + 8 + 8
                if ver >= 3: p += 2
                if ver >= 9: p += 4
                if ver >= 8: p += 4
                if p < o + sz:
                    long = wstr(it, p)
            o += sz
        return dict(kind="file" if not (t & 1) else "dir", name=long or short, short=short,
                    size=u32(it, 2) if len(it) >= 6 else None, mtime=dosdt(u32(it, 6)) if len(it) >= 10 else None,
                    attrs=u16(it, 10) if len(it) >= 12 else None)
    if 0x40 <= t <= 0x4F:
        return dict(kind="network", name=cstr(it, 4) if len(it) > 4 else "")
    if t == 0x61:
        return dict(kind="uri", name=wstr(it, 1))
    return dict(kind="unknown_%02x" % t, name=None)


def parse_idlist(b, o, end):
    items = []
    while o + 2 <= end:
        sz = u16(b, o)
        if sz == 0:
            break
        items.append(parse_item(b[o + 2:o + sz]))
        o += sz
    return items


def idlist_path(items):
    parts, root = [], None
    for it in items:
        k = it["kind"]
        if k == "root":
            root = it["name"]; continue
        if k == "volume":
            parts = [it["name"].rstrip("\\") + "\\"]; continue
        if k in ("file", "dir", "network", "uri") and it["name"] is not None:
            if parts and not parts[-1].endswith("\\"):
                parts.append("\\")
            parts.append(it["name"])
    p = "".join(parts)
    return p or None, root


class LNK:
    def __init__(self, b):
        self.b = b
        self.info = {}
        self.items = []
        self.parse()

    def parse(self):
        b, i = self.b, self.info
        i["header_size"] = u32(b, 0)
        i["link_clsid"] = guid(b, 4)
        fl = u32(b, 20)
        i["link_flags_u32"] = fl
        i["link_flags_hex"] = "0x%08x" % fl
        i["link_flags"] = [n for k, n in enumerate(FLAG_NAMES) if fl >> k & 1]
        at = u32(b, 24)
        i["file_attributes_u32"] = at
        i["file_attributes_hex"] = "0x%08x" % at
        i["file_attributes"] = [n for k, n in enumerate(ATTR_NAMES) if at >> k & 1]
        for nm, off in (("creation_time", 28), ("access_time", 36), ("write_time", 44)):
            i[nm + "_filetime"] = u64(b, off)
            i[nm] = filetime(u64(b, off))
        i["file_size"] = u32(b, 52)
        i["icon_index"] = struct.unpack_from("<i", b, 56)[0]
        i["show_command"] = u32(b, 60)
        i["show_command_name"] = SHOW.get(u32(b, 60), "SW_SHOWNORMAL")
        hk = u16(b, 64)
        i["hotkey_u16"] = hk
        i["hotkey_hex"] = "0x%04x" % hk
        o = i["header_size"]
        uni = bool(fl & 0x80)
        if fl & 1:
            sz = u16(b, o)
            self.items = parse_idlist(b, o + 2, o + 2 + sz)
            i["idlist_size"] = sz
            i["idlist_path"], i["idlist_root"] = idlist_path(self.items)
            i["idlist_item_count"] = len(self.items)
            o += 2 + sz
        if fl & 2 and not fl & 0x100:
            self._linkinfo(o)
            o += u32(b, o)
        elif fl & 2:
            o += u32(b, o)
        for bit, nm in ((2, "name_string"), (3, "relative_path"), (4, "working_dir"), (5, "command_line_arguments"),
                        (6, "icon_location")):
            if fl >> bit & 1:
                n = u16(b, o); o += 2
                if uni:
                    i[nm] = b[o:o + 2 * n].decode("utf-16-le", "replace"); o += 2 * n
                else:
                    i[nm] = b[o:o + n].decode("cp1252", "replace"); o += n
        i["extra_blocks"] = []
        while o + 4 <= len(b):
            sz = u32(b, o)
            if sz < 4 or o + sz > len(b):
                break
            sig = u32(b, o + 4)
            blk = b[o:o + sz]
            nm = SIGS.get(sig, "0x%08x" % sig)
            i["extra_blocks"].append(nm)
            self._extra(nm, blk)
            o += sz
        i["trailing_bytes"] = len(b) - o

    def _linkinfo(self, o):
        b, i = self.b, self.info
        li = b[o:o + u32(b, o)]
        hs = u32(li, 4)
        lf = u32(li, 8)
        i["link_info_flags"] = lf
        vo, lbo, cno, cso = u32(li, 12), u32(li, 16), u32(li, 20), u32(li, 24)
        lbu = u32(li, 28) if hs >= 0x24 else 0
        csu = u32(li, 32) if hs >= 0x24 else 0
        if lf & 1 and vo:
            v = li[vo:]
            i["drive_type_u32"] = u32(v, 4)
            i["drive_type"] = DRIVE_TYPES.get(u32(v, 4), str(u32(v, 4)))
            i["drive_serial_number_u32"] = u32(v, 8)
            i["drive_serial_number_hex"] = "0x%08x" % u32(v, 8)
            lo = u32(v, 12)
            i["volume_label"] = wstr(v, u32(v, 16)) if lo == 0x14 else cstr(v, lo)
        if lf & 1 and lbo:
            i["local_base_path"] = cstr(li, lbo)
        if lbu:
            i["local_base_path_unicode"] = wstr(li, lbu)
        if lf & 2 and cno:
            c = li[cno:]
            cf = u32(c, 4)
            nno, dno = u32(c, 8), u32(c, 12)
            i["network_provider_type_u32"] = u32(c, 16)
            i["net_name"] = cstr(c, nno) if nno else None
            if cf & 1 and dno:
                i["device_name"] = cstr(c, dno)
            if nno > 0x14:
                nu, du = u32(c, 20), u32(c, 24)
                if nu: i["net_name_unicode"] = wstr(c, nu)
                if du: i["device_name_unicode"] = wstr(c, du)
        if cso:
            i["common_path_suffix"] = cstr(li, cso)
        if csu:
            i["common_path_suffix_unicode"] = wstr(li, csu)

    def _extra(self, nm, blk):
        i = self.info
        if nm in ("environment_variables", "darwin", "icon_environment"):
            i[nm + "_ansi"] = fixed_ansi(blk[8:268])
            i[nm + "_unicode"] = fixed_wide(blk[268:788]) if len(blk) >= 788 else None
        elif nm == "tracker":
            i["tracker_machine_id"] = fixed_ansi(blk[16:32])
            i["tracker_droid_volume"] = guid(blk, 32)
            i["tracker_droid_file"] = guid(blk, 48)
            i["tracker_birth_droid_volume"] = guid(blk, 64)
            i["tracker_birth_droid_file"] = guid(blk, 80)
            u = uuid.UUID(i["tracker_droid_file"])
            if u.version == 1:
                i["tracker_mac_address"] = ":".join("%02x" % (u.node >> (8 * k) & 0xff) for k in range(5, -1, -1))
        elif nm == "special_folder":
            i["special_folder_id"] = u32(blk, 8); i["special_folder_offset"] = u32(blk, 12)
        elif nm == "known_folder":
            i["known_folder_id"] = guid(blk, 8); i["known_folder_offset"] = u32(blk, 24)
        elif nm == "console_fe":
            i["console_code_page"] = u32(blk, 8)
        elif nm == "shim":
            i["shim_layer_name"] = fixed_wide(blk[8:])
        elif nm == "vista_and_above_idlist":
            items = parse_idlist(blk, 8, len(blk))
            i["vista_idlist_path"] = idlist_path(items)[0]

    def target_candidates(self):
        i = self.info
        c = {}
        if i.get("local_base_path_unicode") or i.get("local_base_path"):
            c["linkinfo_local"] = (i.get("local_base_path_unicode") or i.get("local_base_path")) + \
                                  (i.get("common_path_suffix_unicode") or i.get("common_path_suffix") or "")
        if i.get("net_name"):
            nn = i.get("net_name_unicode") or i["net_name"]
            suf = i.get("common_path_suffix_unicode") or i.get("common_path_suffix") or ""
            c["linkinfo_network"] = nn + ("\\" + suf if suf and not nn.endswith("\\") else suf)
        if i.get("idlist_path"):
            c["idlist"] = i["idlist_path"]
        if i.get("vista_idlist_path"):
            c["vista_idlist"] = i["vista_idlist_path"]
        if i.get("environment_variables_unicode") or i.get("environment_variables_ansi"):
            c["environment"] = i.get("environment_variables_unicode") or i.get("environment_variables_ansi")
        if i.get("relative_path"):
            c["relative_path"] = i["relative_path"]
        return c


if __name__ == "__main__":
    for f in sys.argv[1:]:
        L = LNK(open(f, "rb").read())
        print("=====", f)
        print(json.dumps(L.info, indent=1, default=str))
        print("items", json.dumps(L.items, default=str))
        print("targets", json.dumps(L.target_candidates(), indent=1))
