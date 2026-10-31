"""Video stream geometry probe (pure Python; nothing is executed) -> ffprobe-style facts for media.primary_video_* questions
(Day 18 'Frame of Reference'). Containers: MP4/MOV/3GP (tkhd matrix + width/height, stsd visual entry, avcC SPS cropping,
hvcC SPS conformance window, pasp, clap, stts frame rate), Matroska/WebM (PixelWidth/Height, DisplayWidth/Height, crop),
AVI (avih/strf BITMAPINFOHEADER), and a loose fallback. Dimensions follow ffprobe: width/height = decoder output
(SPS-cropped), coded_width/coded_height = uncropped macroblock-aligned frame.
usage: video.py <file>..."""
import struct, re, json
from fractions import Fraction


class BR:
    def __init__(self, b):
        self.b = b; self.pos = 0

    def u(self, n):
        v = 0
        for _ in range(n):
            byte = self.b[self.pos >> 3]
            v = (v << 1) | ((byte >> (7 - (self.pos & 7))) & 1)
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


H264_PROFILES = {66: "Baseline", 77: "Main", 88: "Extended", 100: "High", 110: "High 10", 122: "High 4:2:2", 244: "High 4:4:4 Predictive",
                 44: "CAVLC 4:4:4", 83: "Scalable Baseline", 86: "Scalable High", 118: "Multiview High", 128: "Stereo High"}


def parse_h264_sps(sps):
    r = BR(unescape(sps))
    r.u(8)
    profile = r.u(8); constraints = r.u(8); level = r.u(8)
    r.ue()
    chroma, bit_depth = 1, 8
    if profile in (100, 110, 122, 244, 44, 83, 86, 118, 128, 138, 139, 134, 135):
        chroma = r.ue()
        if chroma == 3:
            r.u(1)
        bit_depth = r.ue() + 8; r.ue(); r.u(1)
        if r.u(1):
            for i in range(8 if chroma != 3 else 12):
                if r.u(1):
                    size = 16 if i < 6 else 64
                    last, nxt = 8, 8
                    for _ in range(size):
                        if nxt:
                            nxt = (last + r.se() + 256) % 256
                        last = last if nxt == 0 else nxt
    r.ue()
    poc = r.ue()
    if poc == 0:
        r.ue()
    elif poc == 1:
        r.u(1); r.se(); r.se()
        for _ in range(r.ue()):
            r.se()
    r.ue(); r.u(1)
    w_mbs = r.ue() + 1
    h_map = r.ue() + 1
    frame_mbs_only = r.u(1)
    if not frame_mbs_only:
        r.u(1)
    r.u(1)
    cl = cr = ct = cb = 0
    if r.u(1):
        cl, cr, ct, cb = r.ue(), r.ue(), r.ue(), r.ue()
    sub_w = 1 if chroma in (0, 3) else 2
    sub_h = 2 if chroma == 1 else 1
    unit_y = sub_h * (2 - frame_mbs_only)
    coded_w = w_mbs * 16
    coded_h = (2 - frame_mbs_only) * h_map * 16
    out = dict(codec_name="h264", profile=H264_PROFILES.get(profile, str(profile)), profile_idc=profile, level=level,
               level_str="%d.%d" % (level // 10, level % 10), chroma_format_idc=chroma, bit_depth=bit_depth,
               coded_width=coded_w, coded_height=coded_h, crop_left=cl * sub_w, crop_right=cr * sub_w, crop_top=ct * unit_y,
               crop_bottom=cb * unit_y, width=coded_w - sub_w * (cl + cr), height=coded_h - unit_y * (ct + cb),
               interlaced=not frame_mbs_only)
    if profile == 100 and constraints & 0x10:
        out["profile"] = "Constrained High" if False else out["profile"]
    if profile == 66 and constraints & 0x40:
        out["profile"] = "Constrained Baseline"
    try:
        if r.u(1):  # vui
            if r.u(1):
                ar = r.u(8)
                table = {1: (1, 1), 2: (12, 11), 3: (10, 11), 4: (16, 11), 5: (40, 33), 6: (24, 11), 7: (20, 11), 8: (32, 11),
                         9: (80, 33), 10: (18, 11), 11: (15, 11), 12: (64, 33), 13: (160, 99), 14: (4, 3), 15: (3, 2), 16: (2, 1)}
                if ar == 255:
                    out["sar"] = (r.u(16), r.u(16))
                else:
                    out["sar"] = table.get(ar, (0, 1))
            if r.u(1):
                r.u(1)
            if r.u(1):  # video_signal_type
                r.u(3); out["full_range"] = r.u(1)
                if r.u(1):
                    out["color_primaries"] = r.u(8); out["transfer"] = r.u(8); out["matrix_coeffs"] = r.u(8)
            if r.u(1):
                r.ue(); r.ue()
            if r.u(1):  # timing
                num_units = r.u(32); time_scale = r.u(32); fixed = r.u(1)
                out["vui_timing"] = (num_units, time_scale, fixed)
    except Exception:
        pass
    pf = {0: "gray", 1: "yuv420p", 2: "yuv422p", 3: "yuv444p"}.get(chroma, "yuv420p")
    if bit_depth > 8:
        pf += "%dle" % bit_depth
    out["pix_fmt"] = pf
    return out


def parse_hevc_sps(sps):
    r = BR(unescape(sps))
    r.u(16)  # nal header
    r.u(4); max_sub = r.u(3); r.u(1)
    # profile_tier_level
    r.u(2); r.u(1); gp = r.u(5); r.u(32); r.u(48); gl = r.u(8)
    sub_prof = [r.u(1) for _ in range(max_sub)]
    sub_lev = [r.u(1) for _ in range(max_sub)]
    if max_sub > 0:
        for _ in range(max_sub, 8):
            r.u(2)
    for i in range(max_sub):
        if sub_prof[i]:
            r.u(88)
        if sub_lev[i]:
            r.u(8)
    r.ue()
    chroma = r.ue()
    if chroma == 3:
        r.u(1)
    w = r.ue(); h = r.ue()
    cl = cr = ct = cb = 0
    if r.u(1):
        cl, cr, ct, cb = r.ue(), r.ue(), r.ue(), r.ue()
    bd = r.ue() + 8; r.ue()
    sub_w = 1 if chroma in (0, 3) else 2
    sub_h = 2 if chroma == 1 else 1
    out = dict(codec_name="hevc", profile={1: "Main", 2: "Main 10", 3: "Main Still Picture"}.get(gp, str(gp)), profile_idc=gp,
               level=gl, level_str="%g" % (gl / 30.0), chroma_format_idc=chroma, bit_depth=bd, coded_width=w, coded_height=h,
               crop_left=cl * sub_w, crop_right=cr * sub_w, crop_top=ct * sub_h, crop_bottom=cb * sub_h,
               width=w - sub_w * (cl + cr), height=h - sub_h * (ct + cb))
    pf = {0: "gray", 1: "yuv420p", 2: "yuv422p", 3: "yuv444p"}.get(chroma, "yuv420p")
    if bd > 8:
        pf += "%dle" % bd
    out["pix_fmt"] = pf
    return out


def fx16(v):
    return v / 65536.0


def atoms(b, start, end):
    p = start
    while p + 8 <= end:
        sz = struct.unpack(">I", b[p:p + 4])[0]
        typ = b[p + 4:p + 8]
        hdr = 8
        if sz == 1:
            sz = struct.unpack(">Q", b[p + 8:p + 16])[0]; hdr = 16
        elif sz == 0:
            sz = end - p
        if sz < hdr:
            break
        yield typ, p + hdr, min(p + sz, end)
        p += sz


def find(b, s, e, path):
    typ, rest = path[0], path[1:]
    out = []
    for t, s2, e2 in atoms(b, s, e):
        if t == typ:
            out += find(b, s2, e2, rest) if rest else [(s2, e2)]
    return out


MP4_VIDEO = {"avc1": "h264", "avc2": "h264", "avc3": "h264", "avc4": "h264", "hvc1": "hevc", "hev1": "hevc", "dvh1": "hevc",
             "dvhe": "hevc", "mp4v": "mpeg4", "vp08": "vp8", "vp09": "vp9", "av01": "av1", "s263": "h263", "jpeg": "mjpeg",
             "mjpa": "mjpeg", "mjpb": "mjpegb", "png ": "png", "rle ": "qtrle", "apcn": "prores", "apch": "prores",
             "apcs": "prores", "apco": "prores", "ap4h": "prores", "ap4x": "prores", "raw ": "rawvideo", "encv": "encv",
             "SVQ3": "svq3", "cvid": "cinepak", "dvc ": "dvvideo", "dvcp": "dvvideo", "xd5a": "mpeg2video", "mx5p": "mpeg2video",
             "m2v1": "mpeg2video", "mp2v": "mpeg2video", "hdv2": "mpeg2video", "ai5p": "h264", "ai1p": "h264", "icod": "aic",
             "vc-1": "vc1", "WMV3": "wmv3", "flv1": "flv1", "theo": "theora", "V210": "v210", "v210": "v210", "2vuy": "rawvideo",
             "yuv2": "rawvideo"}


def rotation_from_matrix(m):
    a, b_, c, d = fx16(m[0]), fx16(m[1]), fx16(m[3]), fx16(m[4])
    import math
    rot = math.degrees(math.atan2(b_, a))
    rot = round(rot) % 360
    return rot, (a, b_, c, d)


def parse_mp4(b):
    inf = dict(container="mp4", streams=[])
    ft = find(b, 0, len(b), [b"ftyp"])
    if ft:
        inf["major_brand"] = b[ft[0][0]:ft[0][0] + 4].decode("latin1")
        inf["minor_version"] = struct.unpack(">I", b[ft[0][0] + 4:ft[0][0] + 8])[0]
        inf["compatible_brands"] = [b[i:i + 4].decode("latin1") for i in range(ft[0][0] + 8, ft[0][1], 4)]
    mvhd = find(b, 0, len(b), [b"moov", b"mvhd"])
    if mvhd:
        s, e = mvhd[0]
        if b[s] == 1:
            ts, dur = struct.unpack(">IQ", b[s + 20:s + 32])
        else:
            ts, dur = struct.unpack(">II", b[s + 12:s + 20])
        inf["timescale"] = ts; inf["duration"] = dur / float(ts) if ts else None
    for s, e in find(b, 0, len(b), [b"moov", b"trak"]):
        st = {}
        hd = find(b, s, e, [b"mdia", b"hdlr"])
        htype = b[hd[0][0] + 8:hd[0][0] + 12].decode("latin1") if hd else "?"
        st["codec_type"] = {"soun": "audio", "vide": "video", "text": "subtitle", "sbtl": "subtitle", "tmcd": "data", "meta": "data"}.get(htype, htype)
        st["handler"] = htype
        tk = find(b, s, e, [b"tkhd"])
        if tk:
            ts_, te = tk[0]
            v = b[ts_]
            st["tkhd_flags"] = int.from_bytes(b[ts_ + 1:ts_ + 4], "big")
            o = ts_ + (36 if v == 1 else 24)
            st["track_id"] = struct.unpack(">I", b[ts_ + (20 if v == 1 else 12):ts_ + (24 if v == 1 else 16)])[0]
            o += 8
            st["layer"], st["alternate_group"], st["volume"] = struct.unpack(">hhh", b[o:o + 6]); o += 8
            mat = struct.unpack(">9i", b[o:o + 36]); o += 36
            w, h = struct.unpack(">II", b[o:o + 8])
            st["matrix"] = list(mat)
            st["rotation"], st["matrix_abcd"] = rotation_from_matrix(mat)
            st["tkhd_width"], st["tkhd_height"] = fx16(w), fx16(h)
            st["display_width"], st["display_height"] = int(round(fx16(w))), int(round(fx16(h)))
        md = find(b, s, e, [b"mdia", b"mdhd"])
        if md:
            ms, me = md[0]
            if b[ms] == 1:
                mts, mdur = struct.unpack(">IQ", b[ms + 20:ms + 32])
            else:
                mts, mdur = struct.unpack(">II", b[ms + 12:ms + 20])
            st["media_timescale"], st["media_duration"] = mts, mdur
            st["duration"] = mdur / float(mts) if mts else None
        stts = find(b, s, e, [b"mdia", b"minf", b"stbl", b"stts"])
        if stts:
            ss, se = stts[0]
            n = struct.unpack(">I", b[ss + 4:ss + 8])[0]
            ents = [struct.unpack(">II", b[ss + 8 + 8 * i:ss + 16 + 8 * i]) for i in range(n)]
            st["stts"] = ents[:16]
            st["nb_frames"] = sum(c for c, d in ents)
            tot = sum(c * d for c, d in ents)
            if tot and st.get("media_timescale"):
                st["avg_frame_rate"] = Fraction(st["nb_frames"] * st["media_timescale"], tot)
                deltas = [d for c, d in ents if d]
                if deltas:
                    st["r_frame_rate"] = Fraction(st["media_timescale"], min(deltas))
        stsz = find(b, s, e, [b"mdia", b"minf", b"stbl", b"stsz"])
        if stsz:
            ss, se = stsz[0]
            st["sample_count"] = struct.unpack(">I", b[ss + 8:ss + 12])[0]
        stsd = find(b, s, e, [b"mdia", b"minf", b"stbl", b"stsd"])
        if stsd:
            ss, se = stsd[0]
            cnt = struct.unpack(">I", b[ss + 4:ss + 8])[0]
            p = ss + 8
            entries = []
            for _ in range(cnt):
                if p + 16 > se:
                    break
                esz = struct.unpack(">I", b[p:p + 4])[0]
                fourcc = b[p + 4:p + 8].decode("latin1")
                ent = dict(fourcc=fourcc)
                if st["codec_type"] == "video" and p + 86 <= se:
                    ent["codec_name"] = MP4_VIDEO.get(fourcc, fourcc.strip().lower())
                    ent["stsd_width"], ent["stsd_height"] = struct.unpack(">HH", b[p + 32:p + 36])
                    ent["hres"], ent["vres"] = [fx16(x) for x in struct.unpack(">II", b[p + 36:p + 44])]
                    ent["frame_count_per_sample"] = struct.unpack(">H", b[p + 48:p + 50])[0]
                    ent["compressor_name"] = b[p + 51:p + 51 + b[p + 50]].decode("latin1", "replace") if b[p + 50] <= 31 else ""
                    ent["depth"] = struct.unpack(">H", b[p + 82:p + 84])[0]
                    for t2, s2, e2 in atoms(b, p + 86, p + esz):
                        sb = b[s2:e2]
                        if t2 == b"avcC" and len(sb) > 6:
                            ent["avcC"] = dict(profile=sb[1], compat=sb[2], level=sb[3], nal_length=(sb[4] & 3) + 1)
                            nsps = sb[5] & 0x1f; o = 6
                            for i in range(nsps):
                                l = struct.unpack(">H", sb[o:o + 2])[0]; sps = sb[o + 2:o + 2 + l]; o += 2 + l
                                if i == 0:
                                    try:
                                        ent["sps"] = parse_h264_sps(sps)
                                    except Exception as ex:
                                        ent["sps_error"] = repr(ex)
                                    ent["sps_hex"] = sps.hex()
                        elif t2 == b"hvcC" and len(sb) > 23:
                            ent["hvcC"] = dict(profile=sb[1] & 0x1f, level=sb[12])
                            na = sb[22]; o = 23
                            for _ in range(na):
                                ntype = sb[o] & 0x3f; nn = struct.unpack(">H", sb[o + 1:o + 3])[0]; o += 3
                                for _ in range(nn):
                                    l = struct.unpack(">H", sb[o:o + 2])[0]; nal = sb[o + 2:o + 2 + l]; o += 2 + l
                                    if ntype == 33 and "sps" not in ent:
                                        try:
                                            ent["sps"] = parse_hevc_sps(nal)
                                        except Exception as ex:
                                            ent["sps_error"] = repr(ex)
                        elif t2 == b"pasp" and len(sb) >= 8:
                            ent["pasp"] = struct.unpack(">II", sb[:8])
                        elif t2 == b"clap" and len(sb) >= 32:
                            v = struct.unpack(">8I", sb[:32])
                            ent["clap"] = dict(w=Fraction(v[0], v[1] or 1), h=Fraction(v[2], v[3] or 1),
                                               hoff=Fraction(struct.unpack(">i", sb[16:20])[0], v[5] or 1),
                                               voff=Fraction(struct.unpack(">i", sb[24:28])[0], v[7] or 1))
                        elif t2 == b"colr":
                            ent["colr"] = sb[:4].decode("latin1") + ":" + sb[4:10].hex()
                        elif t2 == b"fiel" and len(sb) >= 2:
                            ent["fiel"] = (sb[0], sb[1])
                        elif t2 == b"btrt" and len(sb) >= 12:
                            ent["btrt"] = struct.unpack(">III", sb[:12])
                        elif t2 == b"esds":
                            ent["esds"] = True
                        elif t2 in (b"vpcC", b"av1C", b"dvcC", b"dvvC"):
                            ent[t2.decode("latin1")] = sb[:16].hex()
                entries.append(ent)
                p += esz
            st["stsd_entries"] = entries
            if entries:
                e0 = entries[0]
                st["fourcc"] = e0["fourcc"]
                if st["codec_type"] == "video":
                    st["codec_name"] = e0.get("codec_name")
                    st["stsd_width"], st["stsd_height"] = e0.get("stsd_width"), e0.get("stsd_height")
                    sps = e0.get("sps") or {}
                    st["coded_width"] = sps.get("coded_width", e0.get("stsd_width"))
                    st["coded_height"] = sps.get("coded_height", e0.get("stsd_height"))
                    st["width"] = sps.get("width", e0.get("stsd_width"))
                    st["height"] = sps.get("height", e0.get("stsd_height"))
                    for k in ("profile", "level", "level_str", "pix_fmt", "bit_depth", "chroma_format_idc", "crop_left",
                              "crop_right", "crop_top", "crop_bottom", "interlaced", "vui_timing", "full_range"):
                        if k in sps:
                            st[k] = sps[k]
                    sar = sps.get("sar")
                    if e0.get("pasp"):
                        sar = tuple(e0["pasp"])
                    st["sar"] = sar or (1, 1)
                    if e0.get("clap"):
                        st["clap"] = {k: str(v) for k, v in e0["clap"].items()}
                    if st.get("width") and st.get("height"):
                        sw, sh = st["sar"] if st["sar"][1] else (1, 1)
                        f = Fraction(st["width"] * (sw or 1), st["height"] * (sh or 1))
                        st["dar"] = (f.numerator, f.denominator)
                    st["compressor_name"] = e0.get("compressor_name")
        inf["streams"].append(st)
    vids = [s for s in inf["streams"] if s["codec_type"] == "video"]
    inf["video_stream_count"] = len(vids)
    inf["audio_stream_count"] = len([s for s in inf["streams"] if s["codec_type"] == "audio"])
    inf["video"] = vids[0] if vids else None
    # ilst tags
    for s, e in find(b, 0, len(b), [b"moov", b"udta", b"meta"]):
        keys = []
        for t, s2, e2 in atoms(b, s + 4, e):
            if t == b"keys":
                n = struct.unpack(">I", b[s2 + 4:s2 + 8])[0]
                p = s2 + 8
                for _ in range(n):
                    ksz = struct.unpack(">I", b[p:p + 4])[0]
                    keys.append(b[p + 8:p + ksz].decode("utf-8", "replace")); p += ksz
        for t, s2, e2 in atoms(b, s + 4, e):
            if t == b"ilst":
                for t3, s3, e3 in atoms(b, s2, e2):
                    for t4, s4, e4 in atoms(b, s3, e3):
                        if t4 == b"data":
                            idx = struct.unpack(">I", t3)[0]
                            nm = {b"\xa9nam": "title", b"\xa9ART": "artist", b"\xa9alb": "album", b"\xa9cmt": "comment",
                                  b"\xa9day": "date", b"\xa9too": "encoder", b"\xa9xyz": "location", b"\xa9mak": "make",
                                  b"\xa9mod": "model", b"\xa9swr": "software"}.get(t3)
                            if nm is None and 1 <= idx <= len(keys):
                                nm = keys[idx - 1].split(".")[-1]
                            if nm is None:
                                nm = t3.decode("latin1", "replace")
                            inf.setdefault("tags", {})[nm] = b[s4 + 8:e4].decode("utf-8", "replace")
    return inf


# ---------------------------------------------------------------- Matroska / WebM
def ebml_vint(b, p, keep_marker=False):
    first = b[p]
    if first == 0:
        raise ValueError("bad vint")
    n = 1
    while not (first & (0x80 >> (n - 1))):
        n += 1
    v = first if keep_marker else first & (0xFF >> n)
    for i in range(1, n):
        v = (v << 8) | b[p + i]
    return v, n


def ebml_walk(b, s, e):
    p = s
    while p < e:
        try:
            eid, n1 = ebml_vint(b, p, keep_marker=True)
            sz, n2 = ebml_vint(b, p + n1)
        except Exception:
            break
        ds = p + n1 + n2
        if sz == (1 << (7 * n2)) - 1:  # unknown size
            sz = e - ds
        yield eid, ds, min(ds + sz, e)
        p = ds + sz


MASTERS = {0x18538067, 0x1654AE6B, 0xAE, 0xE0, 0xE1, 0x1549A966, 0x54B0 ^ 0}  # Segment, Tracks, TrackEntry, Video, Audio, Info


def parse_mkv(b):
    inf = dict(container="matroska", streams=[])
    if b"webm" in b[:64]:
        inf["container"] = "webm"

    def walk(s, e, depth):
        for eid, ds, de in ebml_walk(b, s, e):
            if eid in (0x18538067, 0x1654AE6B):
                walk(ds, de, depth + 1)
            elif eid == 0x1549A966:
                for cid, cs, ce in ebml_walk(b, ds, de):
                    if cid == 0x2AD7B1:
                        inf["timecode_scale"] = int.from_bytes(b[cs:ce], "big")
                    elif cid == 0x4489:
                        inf["duration_raw"] = struct.unpack(">d" if ce - cs == 8 else ">f", b[cs:ce])[0]
            elif eid == 0xAE:
                st = {}
                for cid, cs, ce in ebml_walk(b, ds, de):
                    if cid == 0x83:
                        st["codec_type"] = {1: "video", 2: "audio", 17: "subtitle"}.get(int.from_bytes(b[cs:ce], "big"), "data")
                    elif cid == 0x86:
                        st["codec_id"] = b[cs:ce].decode("latin1")
                    elif cid == 0xD7:
                        st["track_number"] = int.from_bytes(b[cs:ce], "big")
                    elif cid == 0x23E383:
                        st["default_duration_ns"] = int.from_bytes(b[cs:ce], "big")
                    elif cid == 0x536E:
                        st["name"] = b[cs:ce].decode("utf-8", "replace")
                    elif cid == 0xE0:
                        for vid, vs, ve in ebml_walk(b, cs, ce):
                            val = int.from_bytes(b[vs:ve], "big")
                            nm = {0xB0: "pixel_width", 0xBA: "pixel_height", 0x54B0: "display_width", 0x54BA: "display_height",
                                  0x54B2: "display_unit", 0x54AA: "pixel_crop_bottom", 0x54BB: "pixel_crop_top",
                                  0x54CC: "pixel_crop_left", 0x54DD: "pixel_crop_right", 0x9A: "flag_interlaced",
                                  0x53B8: "stereo_mode"}.get(vid)
                            if nm:
                                st[nm] = val
                    elif cid == 0xE1:
                        for aid, as_, ae in ebml_walk(b, cs, ce):
                            if aid == 0xB5:
                                st["sample_rate"] = struct.unpack(">d" if ae - as_ == 8 else ">f", b[as_:ae])[0]
                            elif aid == 0x9F:
                                st["channels"] = int.from_bytes(b[as_:ae], "big")
                if st.get("codec_type") == "video":
                    cid = st.get("codec_id", "")
                    st["codec_name"] = {"V_MPEG4/ISO/AVC": "h264", "V_MPEGH/ISO/HEVC": "hevc", "V_VP8": "vp8", "V_VP9": "vp9",
                                        "V_AV1": "av1", "V_MPEG4/ISO/ASP": "mpeg4", "V_THEORA": "theora", "V_MPEG2": "mpeg2video",
                                        "V_MJPEG": "mjpeg", "V_MS/VFW/FOURCC": "vfw", "V_PRORES": "prores", "V_FFV1": "ffv1"}.get(cid, cid.lower())
                    pw, ph = st.get("pixel_width"), st.get("pixel_height")
                    cl, cr = st.get("pixel_crop_left", 0), st.get("pixel_crop_right", 0)
                    ct, cb = st.get("pixel_crop_top", 0), st.get("pixel_crop_bottom", 0)
                    st["coded_width"], st["coded_height"] = pw, ph
                    st["width"] = (pw - cl - cr) if pw is not None else None
                    st["height"] = (ph - ct - cb) if ph is not None else None
                    st["crop_left"], st["crop_right"], st["crop_top"], st["crop_bottom"] = cl, cr, ct, cb
                    dw, dh = st.get("display_width", st["width"]), st.get("display_height", st["height"])
                    st["display_width"], st["display_height"] = dw, dh
                    if st["width"] and st["height"] and dw and dh and st.get("display_unit", 0) == 0:
                        sar = Fraction(dw * st["height"], dh * st["width"])
                        st["sar"] = (sar.numerator, sar.denominator)
                        dar = Fraction(dw, dh)
                        st["dar"] = (dar.numerator, dar.denominator)
                    if st.get("default_duration_ns"):
                        fr = Fraction(1000000000, st["default_duration_ns"])
                        st["r_frame_rate"] = fr; st["avg_frame_rate"] = fr
                    st["rotation"] = 0
                inf["streams"].append(st)
    walk(0, len(b), 0)
    vids = [s for s in inf["streams"] if s.get("codec_type") == "video"]
    inf["video_stream_count"] = len(vids)
    inf["audio_stream_count"] = len([s for s in inf["streams"] if s.get("codec_type") == "audio"])
    inf["video"] = vids[0] if vids else None
    if inf.get("duration_raw") is not None:
        inf["duration"] = inf["duration_raw"] * inf.get("timecode_scale", 1000000) / 1e9
    return inf


# ---------------------------------------------------------------- AVI
def parse_avi(b):
    inf = dict(container="avi", streams=[])

    def walk(s, e):
        p = s
        while p + 8 <= e:
            cid = b[p:p + 4]; sz = struct.unpack("<I", b[p + 4:p + 8])[0]
            body_s, body_e = p + 8, min(p + 8 + sz, e)
            if cid in (b"RIFF", b"LIST"):
                ltype = b[body_s:body_s + 4]
                if ltype in (b"AVI ", b"hdrl", b"strl", b"INFO", b"AVIX"):
                    walk(body_s + 4, body_e)
            elif cid == b"avih":
                us, _, _, flags, frames, _, streams, _, w, h = struct.unpack("<10I", b[body_s:body_s + 40])
                inf["avih"] = dict(us_per_frame=us, total_frames=frames, streams=streams, width=w, height=h)
            elif cid == b"strh":
                inf["_cur"] = dict(fcc_type=b[body_s:body_s + 4].decode("latin1"), fcc_handler=b[body_s + 4:body_s + 8].decode("latin1"))
                scale, rate = struct.unpack("<II", b[body_s + 20:body_s + 28])
                length = struct.unpack("<I", b[body_s + 32:body_s + 36])[0]
                inf["_cur"].update(scale=scale, rate=rate, length=length)
                if len(b) >= body_s + 56:
                    l, t, r, bt = struct.unpack("<4h", b[body_s + 48:body_s + 56])
                    inf["_cur"]["rcFrame"] = (l, t, r, bt)
                inf["streams"].append(inf["_cur"])
            elif cid == b"strf" and inf.get("_cur"):
                cur = inf["_cur"]
                if cur["fcc_type"] == "vids" and sz >= 40:
                    bsz, w, h, planes, bpp = struct.unpack("<IiiHH", b[body_s:body_s + 16])
                    comp = b[body_s + 16:body_s + 20]
                    cur.update(codec_type="video", width=abs(w), height=abs(h), coded_width=abs(w), coded_height=abs(h),
                               bit_count=bpp, compression=comp.decode("latin1"), display_width=abs(w), display_height=abs(h))
                    cur["codec_name"] = {b"H264": "h264", b"h264": "h264", b"X264": "h264", b"x264": "h264", b"avc1": "h264", b"HEVC": "hevc",
                                         b"hvc1": "hevc", b"XVID": "mpeg4", b"xvid": "mpeg4", b"DIVX": "mpeg4", b"DX50": "mpeg4", b"FMP4": "mpeg4",
                                         b"MP4V": "mpeg4", b"mp4v": "mpeg4", b"MJPG": "mjpeg", b"mjpg": "mjpeg", b"\0\0\0\0": "rawvideo",
                                         b"DIB ": "rawvideo", b"VP80": "vp8", b"VP90": "vp9", b"MPG2": "mpeg2video", b"MPEG": "mpeg1video",
                                         b"WMV3": "wmv3", b"FFV1": "ffv1", b"cvid": "cinepak", b"dvsd": "dvvideo"}.get(comp, comp.decode("latin1").lower())
                    if cur.get("scale"):
                        fr = Fraction(cur["rate"], cur["scale"])
                        cur["r_frame_rate"] = fr; cur["avg_frame_rate"] = fr
                    cur["nb_frames"] = cur.get("length")
                    cur["sar"] = (1, 1)
                    if cur["width"] and cur["height"]:
                        f = Fraction(cur["width"], cur["height"]); cur["dar"] = (f.numerator, f.denominator)
                    cur["rotation"] = 0
                elif cur["fcc_type"] == "auds":
                    cur["codec_type"] = "audio"
            p += 8 + sz + (sz & 1)
    walk(0, len(b))
    inf.pop("_cur", None)
    vids = [s for s in inf["streams"] if s.get("codec_type") == "video"]
    inf["video_stream_count"] = len(vids)
    inf["audio_stream_count"] = len([s for s in inf["streams"] if s.get("codec_type") == "audio"])
    inf["video"] = vids[0] if vids else None
    return inf


def probe(b):
    try:
        if b[4:8] in (b"ftyp", b"moov", b"mdat", b"wide", b"free", b"skip", b"pnot"):
            return parse_mp4(b)
        if b[:4] == b"\x1aE\xdf\xa3":
            return parse_mkv(b)
        if b[:4] == b"RIFF" and b[8:12] in (b"AVI ", b"AVIX"):
            return parse_avi(b)
    except Exception as ex:
        return dict(container=None, error=repr(ex), streams=[], video=None)
    return dict(container=None, streams=[], video=None)


def frac_str(f):
    if f is None:
        return "none"
    if isinstance(f, Fraction):
        return "%d/%d" % (f.numerator, f.denominator)
    return str(f)


def video_field(b, snake, info=None):
    """media.<snake> for video questions; raises KeyError if the field isn't a video field."""
    inf = info or probe(b)
    s = snake.lower()
    s = re.sub(r"^(primary_|first_|main_)?(video_)?", "", s)
    v = inf.get("video")
    if s in ("video_stream_count", "stream_count_video"):
        return str(inf.get("video_stream_count", 0))
    if v is None:
        if s in ("dimensions", "width", "height", "codec_name", "codec", "coded_dimensions", "rotation", "display_dimensions",
                 "frame_rate", "avg_frame_rate", "r_frame_rate", "nb_frames", "frame_count", "sar", "dar", "pix_fmt", "profile", "level"):
            return "none"
        raise KeyError(snake)
    if s in ("dimensions", "dimensions_pixels", "resolution", "size", "wxh", "frame_size", "frame_dimensions"):
        return "%dx%d" % (v["width"], v["height"])
    if s in ("coded_dimensions", "coded_size", "coded_resolution", "coded_dimensions_pixels"):
        return "%dx%d" % (v["coded_width"], v["coded_height"])
    if s in ("display_dimensions", "display_size", "display_resolution", "track_dimensions", "tkhd_dimensions",
             "presentation_dimensions", "display_dimensions_pixels"):
        return "%dx%d" % (v["display_width"], v["display_height"])
    if s in ("stsd_dimensions", "sample_entry_dimensions", "sample_description_dimensions"):
        return "%dx%d" % (v["stsd_width"], v["stsd_height"])
    if s in ("width",): return str(v["width"])
    if s in ("height",): return str(v["height"])
    if s in ("coded_width",): return str(v["coded_width"])
    if s in ("coded_height",): return str(v["coded_height"])
    if s in ("display_width", "track_width"): return str(v["display_width"])
    if s in ("display_height", "track_height"): return str(v["display_height"])
    if s in ("codec_name", "codec"): return v.get("codec_name") or "none"
    if s in ("codec_tag", "fourcc", "codec_tag_string", "sample_entry_type"): return v.get("fourcc") or "none"
    if s in ("rotation", "rotate", "rotation_degrees"): return str(v.get("rotation", 0))
    if s in ("sar", "sample_aspect_ratio", "pixel_aspect_ratio", "pasp"):
        return "%d:%d" % tuple(v.get("sar", (1, 1)))
    if s in ("dar", "display_aspect_ratio", "aspect_ratio"):
        return "%d:%d" % tuple(v.get("dar", (0, 1)))
    if s in ("frame_rate", "fps", "avg_frame_rate", "average_frame_rate"):
        return frac_str(v.get("avg_frame_rate"))
    if s in ("r_frame_rate", "real_frame_rate", "base_frame_rate"):
        return frac_str(v.get("r_frame_rate"))
    if s in ("frame_rate_fps", "fps_float", "frame_rate_float"):
        f = v.get("avg_frame_rate"); return ("%.3f" % float(f)).rstrip("0").rstrip(".") if f else "none"
    if s in ("nb_frames", "frame_count", "frames", "sample_count"):
        return str(v.get("nb_frames") if v.get("nb_frames") is not None else v.get("sample_count", "none"))
    if s in ("pix_fmt", "pixel_format"): return v.get("pix_fmt") or "none"
    if s in ("profile",): return v.get("profile") or "none"
    if s in ("level",): return str(v.get("level", "none"))
    if s in ("bit_depth", "bits_per_raw_sample"): return str(v.get("bit_depth", "none"))
    if s.startswith("crop"):
        k = {"crop_left": "crop_left", "crop_right": "crop_right", "crop_top": "crop_top", "crop_bottom": "crop_bottom"}.get(s)
        if k: return str(v.get(k, 0))
        return "%d,%d,%d,%d" % (v.get("crop_left", 0), v.get("crop_right", 0), v.get("crop_top", 0), v.get("crop_bottom", 0))
    if s in ("duration", "duration_seconds"):
        d = v.get("duration") or inf.get("duration")
        return ("%.6f" % d).rstrip("0").rstrip(".") if d is not None else "none"
    if s in ("duration_ms", "duration_milliseconds"):
        d = v.get("duration") or inf.get("duration")
        return str(int(round(d * 1000))) if d is not None else "none"
    if s in ("compressor_name", "encoder", "compressorname"): return v.get("compressor_name") or "none"
    if s in ("track_id",): return str(v.get("track_id", "none"))
    if s in ("major_brand", "brand"): return inf.get("major_brand") or "none"
    if s in v:
        x = v[s]
        return json.dumps(x) if isinstance(x, (list, dict)) else str(x)
    raise KeyError(snake)


if __name__ == "__main__":
    import sys
    for f in sys.argv[1:]:
        b = open(f, "rb").read()
        i = probe(b)
        v = i.get("video") or {}
        print(f, json.dumps({k: val for k, val in i.items() if k not in ("streams", "video")}, default=str))
        print("  video:", json.dumps({k: val for k, val in v.items() if k not in ("stsd_entries", "stts", "matrix")}, default=str))
        for k in ("dimensions", "coded_dimensions", "display_dimensions", "stsd_dimensions", "codec_name", "rotation", "sar", "dar",
                  "frame_rate", "r_frame_rate", "nb_frames", "pix_fmt", "profile", "level", "crop"):
            try:
                print("   %-20s %s" % (k, video_field(b, k, i)))
            except Exception as ex:
                print("   %-20s ERR %r" % (k, ex))
