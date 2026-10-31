"""Day-31 peek: dump every case member's metadata: PNG chunks, SQLite schema + rows, zips, email attachments.
usage: peek31b.py <evidence.zip>"""
import sys, io, json, base64, zlib, struct, sqlite3, tempfile, os, hashlib, email
import pyzipper


def zmembers(b):
    z = pyzipper.AESZipFile(io.BytesIO(b))
    z.setpassword(b"infected")
    return z, [i for i in z.infolist() if not i.filename.endswith("/")]


def png(d):
    p = 8
    out = []
    while p + 8 <= len(d):
        n, t = struct.unpack(">I4s", d[p:p + 8])
        c = d[p + 8:p + 8 + n]
        crc = struct.unpack(">I", d[p + 8 + n:p + 12 + n])[0] if p + 12 + n <= len(d) else None
        ok = crc == (zlib.crc32(t + c) & 0xffffffff)
        if t == b"IHDR":
            out.append(("IHDR", struct.unpack(">IIBBBBB", c)))
        elif t == b"IDAT":
            out.append(("IDAT", n, "crc", ok))
        elif t == b"IEND":
            out.append(("IEND", "crc", ok))
        else:
            out.append((t.decode("latin1"), c[:300], "crc", ok))
        p += 12 + n
    tail = d[p:]
    if tail:
        out.append(("TRAILER", len(tail), tail[:300]))
    return out


def sq(d):
    fd, fn = tempfile.mkstemp(suffix=".db")
    os.write(fd, d)
    os.close(fd)
    out = []
    try:
        c = sqlite3.connect("file:%s?mode=ro&immutable=1" % fn, uri=True)
        for typ, name, sql in c.execute("select type,name,sql from sqlite_master"):
            out.append((typ, name, sql))
            if typ == "table":
                for r in c.execute('select rowid,* from "%s"' % name):
                    out.append(("ROW", name, r))
        c.close()
    except Exception as ex:
        out.append(("ERR", repr(ex)))
    os.unlink(fn)
    return out


def main():
    z, ms = zmembers(open(sys.argv[1], "rb").read())
    for zi in ms:
        d = z.read(zi.filename)
        print("##", zi.filename, len(d))
        if d[:4] != b"PK\x03\x04":
            print(d[:200])
            continue
        zz, mm = zmembers(d)
        print(" zip date", zi.date_time, "members", len(mm), "comment", zz.comment[:100])
        for i in mm:
            b = zz.read(i.filename)
            print("=== %s %d sha %s date %s comment %r extra %r" % (i.filename, len(b), hashlib.sha256(b).hexdigest()[:12], i.date_time, i.comment[:80], i.extra[:32]))
            if b[:8] == b"\x89PNG\r\n\x1a\n":
                for x in png(b):
                    print("   ", x)
            elif b[:15] == b"SQLite format 3":
                for x in sq(b):
                    print("   ", x)
            elif b[:4] == b"PK\x03\x04":
                y, nn = zmembers(b)
                print("    nested comment", y.comment[:200])
                for j in nn:
                    print("   ", j.filename, j.date_time, repr(j.comment[:80]), y.read(j.filename)[:200])
            elif b[:5] == b"From:":
                m = email.message_from_bytes(b)
                print("    subj", m["Subject"], "mid", m["Message-ID"])
                for p in m.walk():
                    if p.get_content_maintype() != "multipart":
                        print("    part", p.get_content_type(), p.get_filename(), p.get_payload(decode=True)[:200])
            else:
                print("   ", b[:300])


main()
