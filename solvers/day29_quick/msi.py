"""Minimal pure-Python MSI (Windows Installer database) reader on top of olefile.
Decodes MSI stream names, the string pool, _Columns schema and any table -> list of row dicts.
usage (debug): msi.py <file.msi>   -> dumps summary info + every table"""
import io, struct, sys
import olefile

_MIME = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz._"


def decode_name(nm):
    out = []
    for ch in nm:
        c = ord(ch)
        if 0x3800 <= c < 0x4800:
            c -= 0x3800
            out.append(_MIME[c & 0x3F]); out.append(_MIME[(c >> 6) & 0x3F])
        elif 0x4800 <= c < 0x4840:
            out.append(_MIME[c - 0x4800])
        elif c == 0x4840:
            out.append("!")
        else:
            out.append(ch)
    return "".join(out)


class MSI:
    def __init__(self, data):
        self.ole = olefile.OleFileIO(io.BytesIO(data))
        self.streams = {}
        for e in self.ole.listdir(streams=True, storages=False):
            raw = "/".join(e)
            self.streams[decode_name(raw)] = raw
        self._strings()
        self._schema()

    def stream(self, name):
        return self.ole.openstream(self.streams[name]).read()

    def _strings(self):
        pool = self.stream("!_StringPool")
        data = self.stream("!_StringData")
        w = struct.unpack("<%dH" % (len(pool) // 2), pool)
        self.codepage = w[0] | ((w[1] & 0x7FFF) << 16)
        self.sref = 3 if (w[1] & 0x8000) else 2
        enc = {65001: "utf-8", 1252: "cp1252", 0: "cp1252"}.get(self.codepage, "cp%d" % self.codepage)
        self.strs = [""]
        i, off, cnt = 1, 0, len(w) // 2
        while i < cnt:
            ln, refs = w[2 * i], w[2 * i + 1]
            if ln == 0 and refs == 0:
                self.strs.append(""); i += 1; continue
            if ln == 0:  # >64k string: high word in refs, real length in next entry
                ln = (refs << 16) + w[2 * i + 2]
                i += 2
            else:
                i += 1
            try:
                s = data[off:off + ln].decode(enc)
            except Exception:
                s = data[off:off + ln].decode("latin1")
            self.strs.append(s); off += ln

    def _read(self, raw, cols):
        """cols: [(name, type)] -> rows (column-major storage)."""
        widths = []
        for _, t in cols:
            if t & 0x0800 or (t & 0xFF) == 0 and t & 0x0100 and t & 0x0800:
                widths.append(self.sref)
            elif (t & 0xFF) <= 2:
                widths.append(2)
            else:
                widths.append(4)
        rs = sum(widths)
        n = len(raw) // rs if rs else 0
        rows = [dict() for _ in range(n)]
        off = 0
        for (name, t), wd in zip(cols, widths):
            for r in range(n):
                b = raw[off:off + wd]; off += wd
                v = int.from_bytes(b, "little")
                if t & 0x0800:
                    rows[r][name] = self.strs[v] if 0 < v < len(self.strs) else None
                elif wd == 2:
                    rows[r][name] = None if v == 0 else v - 0x8000
                else:
                    rows[r][name] = None if v == 0 else v - 0x80000000
        return rows

    def _schema(self):
        raw = self.stream("!_Columns")
        rows = self._read(raw, [("Table", 0x0D00 | 0x0800), ("Number", 0x2502), ("Name", 0x0D00 | 0x0800), ("Type", 0x0502)])
        self.schema = {}
        for r in rows:
            self.schema.setdefault(r["Table"], []).append((r["Number"], r["Name"], r["Type"]))
        for t in self.schema:
            self.schema[t] = [(nm, ty) for _, nm, ty in sorted(self.schema[t])]

    def table(self, name):
        cols = self.schema.get(name)
        if not cols or ("!" + name) not in self.streams:
            return []
        return self._read(self.stream("!" + name), cols)

    def properties(self):
        return {r.get("Property"): r.get("Value") for r in self.table("Property")}

    def summary(self):
        si = self.ole.get_metadata()
        out = {}
        for k in si.SUMMARY_ATTRIBS:
            v = getattr(si, k, None)
            if isinstance(v, bytes):
                v = v.decode("utf-8", "replace")
            out[k] = v
        return out


if __name__ == "__main__":
    m = MSI(open(sys.argv[1], "rb").read())
    print("codepage", m.codepage, "sref", m.sref, "nstr", len(m.strs))
    print("streams", sorted(m.streams))
    for k, v in m.summary().items():
        if v not in (None, 0, ""):
            print("SUMMARY", k, repr(v))
    for t in sorted(m.schema):
        rows = m.table(t)
        print("TABLE", t, m.schema[t], "rows", len(rows))
        for r in rows[:40]:
            print("   ", r)
