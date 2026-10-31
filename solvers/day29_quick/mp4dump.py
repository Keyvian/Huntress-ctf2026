"""Dump the box tree + geometry of an ISO-BMFF (MP4/MOV) file: ftyp, mvhd, tkhd (matrix/width/height), hdlr, stsd entries
(visual sample entry width/height, avcC SPS / hvcC / pasp / clap / colr), mdhd timescale/duration, plus any udta/meta strings.
usage: mp4dump.py <file>..."""
import sys, struct

CONTAINERS = {b"moov", b"trak", b"mdia", b"minf", b"stbl", b"edts", b"udta", b"dinf", b"mvex", b"moof", b"traf", b"tref",
              b"meta", b"ilst", b"schi", b"sinf", b"ipro", b"stsd_"}
FULL = {b"meta"}


def rd(b, o, n):
    return b[o:o + n]


def boxes(b, off=0, end=None, depth=0, out=None):
    end = len(b) if end is None else end
    while off + 8 <= end:
        sz, typ = struct.unpack(">I4s", b[off:off + 8])
        hdr = 8
        if sz == 1:
            sz = struct.unpack(">Q", b[off + 8:off + 16])[0]; hdr = 16
        elif sz == 0:
            sz = end - off
        if sz < hdr:
            break
        body = b[off + hdr:off + sz]
        print("  " * depth + "%s size=%d off=%d" % (typ.decode("latin1"), sz, off))
        if typ in CONTAINERS and typ != b"stsd_":
            boxes(b, off + hdr + (4 if typ in FULL else 0), off + sz, depth + 1)
        elif typ == b"stsd":
            n = struct.unpack(">I", body[4:8])[0]
            print("  " * depth + "  entry_count=%d" % n)
            sample_entries(body[8:], depth + 1)
        else:
            detail(typ, body, depth + 1)
        off += sz


def fx16(v):
    return v / 65536.0


def detail(typ, body, depth):
    p = "  " * depth
    try:
        if typ == b"ftyp":
            print(p + "major=%s minor=%d compat=%s" % (body[:4], struct.unpack(">I", body[4:8])[0],
                                                       [body[i:i + 4] for i in range(8, len(body), 4)]))
        elif typ == b"mvhd":
            v = body[0]
            if v == 0:
                ts, dur = struct.unpack(">II", body[12:20])
            else:
                ts, dur = struct.unpack(">IQ", body[20:32])
            print(p + "version=%d timescale=%d duration=%d (%.3fs)" % (v, ts, dur, dur / ts if ts else 0))
        elif typ == b"tkhd":
            v = body[0]
            flags = int.from_bytes(body[1:4], "big")
            if v == 0:
                ct, mt, tid, _, dur = struct.unpack(">IIIII", body[4:24]); o = 24
            else:
                ct, mt, tid, _, dur = struct.unpack(">QQIIQ", body[4:36]); o = 36
            o += 8  # reserved
            layer, alt, vol, _ = struct.unpack(">hhhH", body[o:o + 8]); o += 8
            mat = struct.unpack(">9i", body[o:o + 36]); o += 36
            w, h = struct.unpack(">II", body[o:o + 8])
            print(p + "version=%d flags=0x%x track_id=%d duration=%d layer=%d alt=%d vol=%d" % (v, flags, tid, dur, layer, alt, vol))
            print(p + "matrix=[%s] (a=%.2f b=%.2f c=%.2f d=%.2f tx=%.2f ty=%.2f)" % (
                ",".join(str(x) for x in mat), fx16(mat[0]), fx16(mat[1]), fx16(mat[3]), fx16(mat[4]), fx16(mat[6]), fx16(mat[7])))
            print(p + "width=%.4f height=%.4f (raw 0x%08x 0x%08x)" % (fx16(w), fx16(h), w, h))
        elif typ == b"mdhd":
            v = body[0]
            if v == 0:
                ts, dur = struct.unpack(">II", body[12:20]); lang = struct.unpack(">H", body[20:22])[0]
            else:
                ts, dur = struct.unpack(">IQ", body[20:32]); lang = struct.unpack(">H", body[32:34])[0]
            l = "".join(chr(((lang >> s) & 0x1f) + 0x60) for s in (10, 5, 0))
            print(p + "timescale=%d duration=%d (%.3fs) lang=%s" % (ts, dur, dur / ts if ts else 0, l))
        elif typ == b"hdlr":
            print(p + "handler=%s name=%r" % (body[8:12], body[24:].rstrip(b"\0")))
        elif typ == b"elst":
            v = body[0]
            n = struct.unpack(">I", body[4:8])[0]
            o = 8
            for i in range(n):
                if v == 0:
                    sd, mt, rate = struct.unpack(">IiI", body[o:o + 12]); o += 12
                else:
                    sd, mt, rate = struct.unpack(">QqI", body[o:o + 20]); o += 20
                print(p + "edit[%d] seg_dur=%d media_time=%d rate=%d" % (i, sd, mt, rate))
        elif typ in (b"stts", b"stsz", b"stco", b"stss", b"ctts", b"stsc", b"co64"):
            n = struct.unpack(">I", body[4:8])[0] if typ != b"stsz" else struct.unpack(">I", body[8:12])[0]
            extra = ""
            if typ == b"stsz":
                extra = " sample_size=%d" % struct.unpack(">I", body[4:8])[0]
            if typ == b"stts":
                ents = [struct.unpack(">II", body[8 + 8 * i:16 + 8 * i]) for i in range(min(n, 8))]
                extra = " entries=%s" % ents
            print(p + "count=%d%s" % (n, extra))
        elif typ in (b"\xa9nam", b"\xa9cmt", b"\xa9too", b"\xa9day", b"\xa9ART", b"\xa9alb", b"desc", b"\xa9des", b"name", b"data"):
            print(p + repr(body[:300]))
        elif typ in (b"uuid",):
            print(p + "uuid=%s data=%r" % (body[:16].hex(), body[16:200]))
        elif typ == b"free" or typ == b"skip":
            if body.strip(b"\0"):
                print(p + repr(body[:200]))
        elif typ == b"mdat":
            print(p + "first bytes=%s" % body[:32].hex())
        else:
            if len(body) <= 200:
                print(p + repr(body))
            else:
                print(p + repr(body[:120]) + "...")
    except Exception as e:
        print(p + "ERR", e, repr(body[:80]))


def exp_golomb(bits):
    """returns a reader over a bit list."""
    pass


class BR:
    def __init__(self, b):
        self.b = b; self.pos = 0

    def u(self, n):
        v = 0
        for _ in range(n):
            byte = self.b[self.pos >> 3]
            bit = (byte >> (7 - (self.pos & 7))) & 1
            v = (v << 1) | bit
            self.pos += 1
        return v

    def ue(self):
        z = 0
        while self.u(1) == 0:
            z += 1
            if z > 32:
                raise ValueError("ue")
        return (1 << z) - 1 + self.u(z)

    def se(self):
        k = self.ue()
        return (k + 1) // 2 if k & 1 else -(k // 2)


def unescape(nal):
    out = bytearray(); i = 0
    while i < len(nal):
        if i + 2 < len(nal) and nal[i] == 0 and nal[i + 1] == 0 and nal[i + 2] == 3:
            out += b"\0\0"; i += 3
        else:
            out.append(nal[i]); i += 1
    return bytes(out)


def parse_sps(sps, p):
    r = BR(unescape(sps))
    nal_type = r.u(8) & 0x1f
    profile = r.u(8); constraints = r.u(8); level = r.u(8)
    sps_id = r.ue()
    chroma = 1
    if profile in (100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135):
        chroma = r.ue()
        if chroma == 3:
            r.u(1)
        r.ue(); r.ue(); r.u(1)
        if r.u(1):
            for i in range(8 if chroma != 3 else 12):
                if r.u(1):
                    # scaling list skip
                    size = 16 if i < 6 else 64
                    last, nxt = 8, 8
                    for j in range(size):
                        if nxt:
                            nxt = (last + r.se() + 256) % 256
                        last = last if nxt == 0 else nxt
    log2_max_frame = r.ue() + 4
    poc_type = r.ue()
    if poc_type == 0:
        r.ue()
    elif poc_type == 1:
        r.u(1); r.se(); r.se()
        for _ in range(r.ue()):
            r.se()
    num_ref = r.ue(); r.u(1)
    w_mbs = r.ue() + 1
    h_map = r.ue() + 1
    frame_mbs_only = r.u(1)
    if not frame_mbs_only:
        r.u(1)
    r.u(1)
    crop = r.u(1)
    cl = cr = ct = cb = 0
    if crop:
        cl, cr, ct, cb = r.ue(), r.ue(), r.ue(), r.ue()
    sub_w = 1 if chroma == 0 else (2 if chroma in (1, 2) else 1)
    sub_h = 1 if chroma == 0 else (2 if chroma == 1 else 1)
    unit_y = sub_h * (2 - frame_mbs_only)
    coded_w = w_mbs * 16
    coded_h = (2 - frame_mbs_only) * h_map * 16
    w = coded_w - sub_w * (cl + cr)
    h = coded_h - unit_y * (ct + cb)
    print(p + "SPS profile=%d level=%d chroma=%d mbs=%dx%d coded=%dx%d crop(l,r,t,b)=%s -> %dx%d" % (
        profile, level, chroma, w_mbs, h_map, coded_w, coded_h, (cl, cr, ct, cb), w, h))
    vui = r.u(1)
    if vui:
        if r.u(1):
            ar = r.u(8)
            if ar == 255:
                sw, sh = r.u(16), r.u(16)
                print(p + "VUI aspect_ratio_idc=255 sar=%d:%d" % (sw, sh))
            else:
                print(p + "VUI aspect_ratio_idc=%d" % ar)
    return w, h


def sample_entries(b, depth):
    p = "  " * depth
    off = 0
    while off + 16 <= len(b):
        sz, typ = struct.unpack(">I4s", b[off:off + 8])
        if sz < 16:
            break
        e = b[off + 8:off + sz]
        dref = struct.unpack(">H", e[6:8])[0]
        print(p + "entry %s size=%d dref=%d" % (typ, sz, dref))
        if typ in (b"avc1", b"avc3", b"hvc1", b"hev1", b"mp4v", b"vp09", b"av01", b"encv", b"s263", b"apcn", b"jpeg", b"png ", b"rle ", b"mjpa", b"mjpb", b"dvh1"):
            w, h = struct.unpack(">HH", e[24:28])
            hres, vres = struct.unpack(">II", e[28:36])
            fc = e[40]; cname = e[41:41 + 32]
            depth_, _ = struct.unpack(">HH", e[72:76])
            print(p + "  VISUAL width=%d height=%d hres=%.1f vres=%.1f frame_count=%d compressor=%r depth=%d" % (
                w, h, fx16(hres), fx16(vres), fc, cname.decode("latin1").rstrip("\0"), depth_))
            sub = e[78:]
            so = 0
            while so + 8 <= len(sub):
                ssz, styp = struct.unpack(">I4s", sub[so:so + 8])
                if ssz < 8:
                    break
                sb = sub[so + 8:so + ssz]
                print(p + "  sub %s size=%d" % (styp, ssz))
                if styp == b"avcC":
                    print(p + "    avcC ver=%d profile=%d compat=%d level=%d nal_len=%d" % (sb[0], sb[1], sb[2], sb[3], (sb[4] & 3) + 1))
                    nsps = sb[5] & 0x1f; o = 6
                    for i in range(nsps):
                        l = struct.unpack(">H", sb[o:o + 2])[0]; sps = sb[o + 2:o + 2 + l]; o += 2 + l
                        print(p + "    sps[%d]=%s" % (i, sps.hex()))
                        try:
                            parse_sps(sps, p + "    ")
                        except Exception as ex:
                            print(p + "    SPS parse err", ex)
                    npps = sb[o]; o += 1
                    for i in range(npps):
                        l = struct.unpack(">H", sb[o:o + 2])[0]; pps = sb[o + 2:o + 2 + l]; o += 2 + l
                        print(p + "    pps[%d]=%s" % (i, pps.hex()))
                elif styp == b"pasp":
                    print(p + "    pasp hSpacing=%d vSpacing=%d" % struct.unpack(">II", sb[:8]))
                elif styp == b"clap":
                    v = struct.unpack(">8I", sb[:32])
                    print(p + "    clap w=%d/%d h=%d/%d hoff=%d/%d voff=%d/%d" % v)
                elif styp == b"colr":
                    print(p + "    colr %r" % sb[:20])
                elif styp == b"hvcC":
                    print(p + "    hvcC %s" % sb[:40].hex())
                else:
                    print(p + "    %r" % sb[:80])
                so += ssz
        elif typ in (b"mp4a", b"enca", b"ac-3", b"ec-3", b"opus", b"flac", b"alac", b"samr", b"sawb", b"twos", b"sowt", b"lpcm"):
            ch, bits = struct.unpack(">HH", e[8:12])
            sr = struct.unpack(">I", e[16:20])[0] >> 16
            print(p + "  AUDIO channels=%d bits=%d sr=%d" % (ch, bits, sr))
            print(p + "  rest=%s" % e[20:60].hex())
        else:
            print(p + "  %r" % e[:80])
        off += sz


for f in sys.argv[1:]:
    b = open(f, "rb").read()
    print("=====", f, len(b))
    boxes(b)
