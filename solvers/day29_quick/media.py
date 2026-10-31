"""Audio/media container probe (pure Python; nothing is executed) -> ffprobe-style facts for media.<field> questions (Day 17).
Containers: RIFF/WAVE (+WAVE_FORMAT_EXTENSIBLE), RF64, AIFF/AIFC, MP3 (ID3v2 skipped, MPEG frame header), Ogg (vorbis/opus/
flac/speex), FLAC, MP4/M4A/3GP/MOV (stsd), AMR, AU/SND, Matroska/WebM (CodecID), ASF/WMA (stream properties), CAF, and an .eml
wrapper (first audio attachment). Codec names follow ffprobe codec_name (pcm_s16le, pcm_u8, pcm_alaw, pcm_mulaw, adpcm_ima_wav,
adpcm_ms, mp3, mp2, vorbis, opus, flac, aac, alac, amr_nb, ...). 'none' when no audio stream is found.
usage: media.py <file>..."""
import struct, re, io, json

WAV_TAGS = {
    0x0002: "adpcm_ms", 0x0006: "pcm_alaw", 0x0007: "pcm_mulaw", 0x000A: "wmavoice", 0x0010: "adpcm_ima_oki",
    0x0011: "adpcm_ima_wav", 0x0017: "adpcm_ima_oki", 0x0020: "adpcm_yamaha", 0x0022: "truespeech", 0x0031: "gsm_ms",
    0x0032: "gsm_ms", 0x0038: "amr_nb", 0x0045: "adpcm_g726", 0x0050: "mp2", 0x0055: "mp3", 0x0057: "amr_nb",
    0x0058: "amr_wb", 0x0061: "adpcm_ima_dk4", 0x0062: "adpcm_ima_dk3", 0x0064: "adpcm_g726", 0x0069: "adpcm_ima_wav",
    0x0075: "metasound", 0x00FF: "aac", 0x0111: "g723_1", 0x0130: "sipr", 0x0160: "wmav1", 0x0161: "wmav2",
    0x0162: "wmapro", 0x0163: "wmalossless", 0x0200: "adpcm_ct", 0x0270: "atrac3", 0x028F: "adpcm_g722",
    0x0401: "imc", 0x0402: "iac", 0x1500: "gsm_ms", 0x1600: "aac", 0x1610: "aac", 0x2000: "ac3", 0x2001: "dts",
    0x4143: "aac", 0x566F: "vorbis", 0x5346: "adpcm_swf", 0x594A: "xan_dpcm", 0x6C75: "pcm_mulaw", 0x706D: "aac",
    0xA109: "speex", 0xF1AC: "flac", 0xE923: "atrac3p",
}
MP4_CODECS = {"alac": "alac", "Opus": "opus", "fLaC": "flac", "ac-3": "ac3", "ec-3": "eac3", "samr": "amr_nb",
              "sawb": "amr_wb", "ulaw": "pcm_mulaw", "alaw": "pcm_alaw", "twos": "pcm_s16be", "sowt": "pcm_s16le",
              "raw ": "pcm_u8", "fl32": "pcm_f32be", "fl64": "pcm_f64be", "in24": "pcm_s24be", "in32": "pcm_s32be",
              "ima4": "adpcm_ima_qt", "mp4a": "aac", ".mp3": "mp3", "ms\x00U": "mp3", "dtsc": "dts", "dtsh": "dts",
              "dtsl": "dts", "dtse": "dts", "mlpa": "truehd", "ipcm": "pcm_s16be", "lpcm": "pcm_s16le", "spex": "speex",
              "sevc": "evrc", "sqcp": "qcelp", "Qclp": "qcelp", "QDM2": "qdm2", "QDMC": "qdmc", "WMA ": "wmav2",
              "nmos": "nellymoser", "mp3 ": "mp3", "enca": "aac"}
MKV_CODECS = {"A_OPUS": "opus", "A_VORBIS": "vorbis", "A_FLAC": "flac", "A_AAC": "aac", "A_MPEG/L3": "mp3",
              "A_MPEG/L2": "mp2", "A_MPEG/L1": "mp1", "A_AC3": "ac3", "A_EAC3": "eac3", "A_DTS": "dts", "A_TRUEHD": "truehd",
              "A_MLP": "mlp", "A_ALAC": "alac", "A_TTA1": "tta", "A_WAVPACK4": "wavpack", "A_MS/ACM": "wav",
              "A_PCM/INT/LIT": "pcm_s16le", "A_PCM/INT/BIG": "pcm_s16be", "A_PCM/FLOAT/IEEE": "pcm_f32le",
              "A_REAL/14_4": "ra_144", "A_REAL/28_8": "ra_288", "A_REAL/COOK": "cook", "A_REAL/SIPR": "sipr",
              "A_REAL/ATRC": "atrac3", "A_QUICKTIME": "qdm2", "A_AAC/MPEG4/LC": "aac", "A_AAC/MPEG2/LC": "aac",
              "A_AAC/MPEG4/LC/SBR": "aac", "A_AAC/MPEG4/MAIN": "aac"}
MP3_BITRATES = {  # (version_idx(1=MPEG1,2=MPEG2/2.5), layer) -> table
    (1, 1): [0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448],
    (1, 2): [0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384],
    (1, 3): [0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320],
    (2, 1): [0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256],
    (2, 2): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
    (2, 3): [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
}
MP3_RATES = {3: [44100, 48000, 32000], 2: [22050, 24000, 16000], 0: [11025, 12000, 8000]}


def pcm_name(bps, fmt_float=False, be=False, signed=None):
    e = "be" if be else "le"
    if fmt_float:
        return {32: "pcm_f32" + e, 64: "pcm_f64" + e}.get(bps, "pcm_f32" + e)
    if bps == 8:
        return "pcm_s8" if signed else "pcm_u8"
    return "pcm_s%d%s" % (bps, e)


def _info(**k):
    d = dict(container=None, codec_name=None, sample_rate=None, channels=None, bits_per_sample=None, duration=None,
             bit_rate=None, tags={}, streams=[], audio_stream_count=0, video_stream_count=0)
    d.update(k)
    return d


# ---------------------------------------------------------------- RIFF / WAVE / RF64 / AIFF
def parse_riff(b):
    be = b[:4] == b"RIFX"
    E = ">" if be else "<"
    inf = _info(container="wav" if b[8:12] == b"WAVE" else b[8:12].decode("latin1").strip().lower())
    off, data_size = 12, None
    chunks = []
    while off + 8 <= len(b):
        cid = b[off:off + 4]
        sz = struct.unpack(E + "I", b[off + 4:off + 8])[0]
        body = b[off + 8:off + 8 + sz]
        chunks.append((cid, sz))
        if cid == b"fmt " and len(body) >= 14:
            tag, ch, sr, br, ba = struct.unpack(E + "HHIIH", body[:14])
            bps = struct.unpack(E + "H", body[14:16])[0] if len(body) >= 16 else 0
            inf.update(sample_rate=sr, channels=ch, bits_per_sample=bps or None, bit_rate=br * 8, format_tag=tag)
            if tag == 0xFFFE and len(body) >= 40:
                cb = struct.unpack(E + "H", body[16:18])[0]
                valid, mask = struct.unpack(E + "HI", body[18:24])
                sub = body[24:40]
                tag = struct.unpack("<H", sub[:2])[0]
                inf["subformat_guid"] = sub.hex()
                inf["valid_bits"] = valid
                inf["channel_mask"] = mask
                inf["format_tag_effective"] = tag
            if tag == 1:
                inf["codec_name"] = pcm_name(bps, be=be)
            elif tag == 3:
                inf["codec_name"] = pcm_name(bps, fmt_float=True, be=be)
            else:
                inf["codec_name"] = WAV_TAGS.get(tag, "unknown_0x%04x" % tag)
        elif cid == b"data":
            data_size = sz
            if sz == 0xFFFFFFFF or off + 8 + sz > len(b):
                data_size = len(b) - off - 8
        elif cid == b"ds64" and len(body) >= 24:
            inf["rf64_data_size"] = struct.unpack("<Q", body[8:16])[0]
        elif cid == b"LIST" and body[:4] == b"INFO":
            p = 4
            while p + 8 <= len(body):
                k = body[p:p + 4].decode("latin1")
                n = struct.unpack(E + "I", body[p + 4:p + 8])[0]
                v = body[p + 8:p + 8 + n].split(b"\x00")[0].decode("utf-8", "replace")
                inf["tags"][k] = v
                p += 8 + n + (n & 1)
        elif cid in (b"fact",) and len(body) >= 4:
            inf["fact_samples"] = struct.unpack(E + "I", body[:4])[0]
        off += 8 + sz + (sz & 1)
    inf["chunks"] = [(c.decode("latin1"), s) for c, s in chunks]
    if data_size is not None:
        inf["data_size"] = data_size
        if inf.get("fact_samples") and inf.get("sample_rate"):
            inf["duration"] = inf["fact_samples"] / inf["sample_rate"]
        elif inf.get("bit_rate"):
            inf["duration"] = data_size * 8.0 / inf["bit_rate"]
    if inf.get("codec_name"):
        inf["audio_stream_count"] = 1
        inf["streams"] = [dict(codec_type="audio", codec_name=inf["codec_name"])]
    t = inf["tags"]
    for k, nm in (("INAM", "title"), ("IART", "artist"), ("ICMT", "comment"), ("ICRD", "date"), ("IPRD", "album"),
                  ("ISFT", "encoder"), ("IGNR", "genre"), ("ITRK", "track"), ("ICOP", "copyright")):
        if k in t:
            t.setdefault(nm, t[k])
    return inf


def parse_aiff(b):
    inf = _info(container="aiff")
    aifc = b[8:12] == b"AIFC"
    off = 12
    frames = None
    while off + 8 <= len(b):
        cid = b[off:off + 4]
        sz = struct.unpack(">I", b[off + 4:off + 8])[0]
        body = b[off + 8:off + 8 + sz]
        if cid == b"COMM" and len(body) >= 18:
            ch, frames, bps = struct.unpack(">hIh", body[:8])
            # 80-bit extended sample rate
            exp = struct.unpack(">H", body[8:10])[0]
            mant = struct.unpack(">Q", body[10:18])[0]
            sr = int(round(mant * 2.0 ** ((exp & 0x7FFF) - 16383 - 63))) if mant else 0
            inf.update(channels=ch, bits_per_sample=bps, sample_rate=sr)
            comp = body[18:22].decode("latin1") if aifc and len(body) >= 22 else "NONE"
            inf["compression_type"] = comp
            inf["codec_name"] = {"NONE": pcm_name(bps, be=True, signed=True), "twos": pcm_name(bps, be=True, signed=True),
                                 "sowt": pcm_name(bps, be=False, signed=True), "fl32": "pcm_f32be", "FL32": "pcm_f32be",
                                 "fl64": "pcm_f64be", "ulaw": "pcm_mulaw", "ULAW": "pcm_mulaw", "alaw": "pcm_alaw",
                                 "ALAW": "pcm_alaw", "ima4": "adpcm_ima_qt", "GSM ": "gsm", "MAC3": "mace3",
                                 "MAC6": "mace6", "QDM2": "qdm2", "Qclp": "qcelp", "in24": "pcm_s24be",
                                 "in32": "pcm_s32be", "raw ": "pcm_u8"}.get(comp, comp.strip().lower())
            if frames and sr:
                inf["duration"] = frames / sr
        elif cid == b"NAME":
            inf["tags"]["title"] = body.decode("utf-8", "replace")
        elif cid == b"AUTH":
            inf["tags"]["artist"] = body.decode("utf-8", "replace")
        elif cid == b"ANNO":
            inf["tags"]["comment"] = body.decode("utf-8", "replace")
        off += 8 + sz + (sz & 1)
    if inf.get("codec_name"):
        inf["audio_stream_count"] = 1
    return inf


# ---------------------------------------------------------------- MP3 / ID3
def id3v2_size(b):
    if b[:3] != b"ID3" or len(b) < 10:
        return 0
    sz = ((b[6] & 0x7F) << 21) | ((b[7] & 0x7F) << 14) | ((b[8] & 0x7F) << 7) | (b[9] & 0x7F)
    return 10 + sz + (10 if b[5] & 0x10 else 0)


def id3v2_tags(b):
    tags = {}
    if b[:3] != b"ID3":
        return tags
    ver = b[3]
    end = id3v2_size(b)
    p = 10
    names = {"TIT2": "title", "TT2": "title", "TPE1": "artist", "TP1": "artist", "TALB": "album", "TAL": "album",
             "COMM": "comment", "COM": "comment", "TYER": "date", "TDRC": "date", "TRCK": "track", "TSSE": "encoder",
             "TXXX": "txxx", "TCON": "genre", "TENC": "encoded_by"}
    while p + 10 <= end and p + 10 <= len(b):
        if ver >= 3:
            fid = b[p:p + 4].decode("latin1")
            if ver == 4:
                sz = ((b[p + 4] & 0x7F) << 21) | ((b[p + 5] & 0x7F) << 14) | ((b[p + 6] & 0x7F) << 7) | (b[p + 7] & 0x7F)
            else:
                sz = struct.unpack(">I", b[p + 4:p + 8])[0]
            hdr = 10
        else:
            fid = b[p:p + 3].decode("latin1")
            sz = (b[p + 3] << 16) | (b[p + 4] << 8) | b[p + 5]
            hdr = 6
        if not re.fullmatch(r"[A-Z0-9]{3,4}", fid) or sz <= 0:
            break
        body = b[p + hdr:p + hdr + sz]
        if fid[0] == "T" or fid in ("COMM", "COM"):
            enc = body[0] if body else 0
            raw = body[1:]
            if fid in ("COMM", "COM"):
                raw = raw[3:]
            try:
                if enc == 0:
                    txt = raw.decode("latin1")
                elif enc == 1:
                    txt = raw.decode("utf-16")
                elif enc == 2:
                    txt = raw.decode("utf-16-be")
                else:
                    txt = raw.decode("utf-8")
            except Exception:
                txt = raw.decode("latin1", "replace")
            txt = txt.strip("\x00")
            if fid in ("COMM", "COM") and "\x00" in txt:
                txt = txt.split("\x00", 1)[1]
            if fid == "TXXX" and "\x00" in txt:
                k, v = txt.split("\x00", 1)
                tags[k] = v
            else:
                tags[names.get(fid, fid)] = txt
        p += hdr + sz
    return tags


def mp3_frame(b, p):
    """parse an MPEG audio frame header at p -> dict or None."""
    if p + 4 > len(b) or b[p] != 0xFF or (b[p + 1] & 0xE0) != 0xE0:
        return None
    h = struct.unpack(">I", b[p:p + 4])[0]
    ver = (h >> 19) & 3
    layer = (h >> 17) & 3
    br_idx = (h >> 12) & 15
    sr_idx = (h >> 10) & 3
    pad = (h >> 9) & 1
    mode = (h >> 6) & 3
    if ver == 1 or layer == 0 or br_idx in (0, 15) or sr_idx == 3:
        return None
    L = {3: 1, 2: 2, 1: 3}[layer]
    v = 1 if ver == 3 else 2
    br = MP3_BITRATES[(v, L)][br_idx] * 1000
    sr = MP3_RATES[ver][sr_idx]
    if ver == 0:
        sr //= 2  # MPEG 2.5 uses the MPEG2 table halved
    if L == 1:
        flen = (12 * br // sr + pad) * 4
        spf = 384
    else:
        spf = 1152 if (v == 1 or L == 2) else 576
        flen = spf * br // 8 // sr + pad
    return dict(version=ver, layer=L, bit_rate=br, sample_rate=sr, channels=1 if mode == 3 else 2, frame_len=flen,
                samples=spf, codec_name={1: "mp1", 2: "mp2", 3: "mp3"}[L])


def parse_mp3(b):
    inf = _info(container="mp3")
    inf["tags"] = id3v2_tags(b)
    p = id3v2_size(b)
    f = None
    for q in range(p, min(len(b) - 4, p + 65536)):
        f = mp3_frame(b, q)
        if f:
            n = f["frame_len"]
            f2 = mp3_frame(b, q + n) if q + n + 4 <= len(b) else f
            if f2 and f2["sample_rate"] == f["sample_rate"] and f2["layer"] == f["layer"]:
                p = q
                break
            f = None
    if not f:
        return None
    inf.update(codec_name=f["codec_name"], sample_rate=f["sample_rate"], channels=f["channels"], bit_rate=f["bit_rate"],
               audio_stream_count=1, streams=[dict(codec_type="audio", codec_name=f["codec_name"])])
    # count frames for duration
    frames, q = 0, p
    while q + 4 <= len(b):
        g = mp3_frame(b, q)
        if not g:
            break
        frames += 1
        q += g["frame_len"]
    inf["frame_count"] = frames
    if frames:
        inf["duration"] = frames * f["samples"] / float(f["sample_rate"])
    if b[-128:-125] == b"TAG":
        t = b[-128:]
        inf["tags"].setdefault("title", t[3:33].split(b"\x00")[0].decode("latin1").strip())
        inf["tags"].setdefault("artist", t[33:63].split(b"\x00")[0].decode("latin1").strip())
    return inf


# ---------------------------------------------------------------- Ogg
def ogg_pages(b):
    p = 0
    while p + 27 <= len(b) and b[p:p + 4] == b"OggS":
        nseg = b[p + 26]
        segs = b[p + 27:p + 27 + nseg]
        body_len = sum(segs)
        hdr_type = b[p + 5]
        serial = struct.unpack("<I", b[p + 14:p + 18])[0]
        granule = struct.unpack("<q", b[p + 6:p + 14])[0]
        body = b[p + 27 + nseg:p + 27 + nseg + body_len]
        yield dict(type=hdr_type, serial=serial, granule=granule, body=body)
        p += 27 + nseg + body_len


def vorbis_comments(body):
    tags = {}
    try:
        p = 0
        vl = struct.unpack("<I", body[p:p + 4])[0]; p += 4 + vl
        n = struct.unpack("<I", body[p:p + 4])[0]; p += 4
        for _ in range(n):
            l = struct.unpack("<I", body[p:p + 4])[0]; p += 4
            kv = body[p:p + l].decode("utf-8", "replace"); p += l
            if "=" in kv:
                k, v = kv.split("=", 1)
                tags.setdefault(k.lower(), v)
    except Exception:
        pass
    return tags


def parse_ogg(b):
    inf = _info(container="ogg")
    streams = {}
    last_granule = {}
    for pg in ogg_pages(b):
        s = pg["serial"]
        if pg["type"] & 2:  # BOS
            body = pg["body"]
            st = dict(serial=s, codec_type="audio")
            if body[:7] == b"\x01vorbis":
                st.update(codec_name="vorbis", channels=body[11], sample_rate=struct.unpack("<I", body[12:16])[0],
                          bit_rate=struct.unpack("<i", body[20:24])[0] or None)
            elif body[:8] == b"OpusHead":
                st.update(codec_name="opus", channels=body[9], sample_rate=48000,
                          input_sample_rate=struct.unpack("<I", body[12:16])[0], pre_skip=struct.unpack("<H", body[10:12])[0])
            elif body[:5] == b"\x7fFLAC":
                si = body[17:]
                st.update(codec_name="flac")
                if len(si) >= 34 + 4:
                    x = si[4 + 10:4 + 18]
                    v = int.from_bytes(x, "big")
                    st.update(sample_rate=v >> 44, channels=((v >> 41) & 7) + 1, bits_per_sample=((v >> 36) & 31) + 1,
                              total_samples=v & ((1 << 36) - 1))
            elif body[:8] == b"Speex   ":
                st.update(codec_name="speex", sample_rate=struct.unpack("<I", body[36:40])[0], channels=struct.unpack("<I", body[48:52])[0])
            elif body[:7] == b"\x80theora":
                st.update(codec_type="video", codec_name="theora")
            elif body[:8] == b"OVP80\x01\x01":
                st.update(codec_type="video", codec_name="vp8")
            elif body[:8] == b"\x7fkate\x00\x00\x00":
                st.update(codec_type="subtitle", codec_name="kate")
            else:
                st.update(codec_name="unknown", codec_type="data")
            streams[s] = st
        else:
            if s in streams and streams[s].get("codec_name") in ("vorbis", "opus") and not streams[s].get("tags"):
                body = pg["body"]
                if body[:7] == b"\x03vorbis":
                    streams[s]["tags"] = vorbis_comments(body[7:])
                elif body[:8] == b"OpusTags":
                    streams[s]["tags"] = vorbis_comments(body[8:])
        if pg["granule"] >= 0:
            last_granule[s] = pg["granule"]
    inf["streams"] = list(streams.values())
    aud = [s for s in inf["streams"] if s["codec_type"] == "audio"]
    inf["audio_stream_count"] = len(aud)
    inf["video_stream_count"] = len([s for s in inf["streams"] if s["codec_type"] == "video"])
    if aud:
        a = aud[0]
        inf.update(codec_name=a.get("codec_name"), sample_rate=a.get("sample_rate"), channels=a.get("channels"),
                   bits_per_sample=a.get("bits_per_sample"), bit_rate=a.get("bit_rate"), tags=a.get("tags") or {})
        g = last_granule.get(a["serial"])
        if g is not None:
            if a["codec_name"] == "opus":
                inf["duration"] = (g - a.get("pre_skip", 0)) / 48000.0
            elif a.get("sample_rate"):
                inf["duration"] = g / float(a["sample_rate"])
    return inf


# ---------------------------------------------------------------- FLAC
def parse_flac(b):
    inf = _info(container="flac", codec_name="flac", audio_stream_count=1)
    p = 4
    while p + 4 <= len(b):
        hdr = b[p]
        last, typ = hdr & 0x80, hdr & 0x7F
        n = int.from_bytes(b[p + 1:p + 4], "big")
        body = b[p + 4:p + 4 + n]
        if typ == 0 and len(body) >= 18:
            v = int.from_bytes(body[10:18], "big")
            inf.update(sample_rate=v >> 44, channels=((v >> 41) & 7) + 1, bits_per_sample=((v >> 36) & 31) + 1)
            ts = v & ((1 << 36) - 1)
            inf["total_samples"] = ts
            if ts and inf["sample_rate"]:
                inf["duration"] = ts / float(inf["sample_rate"])
        elif typ == 4:
            inf["tags"] = vorbis_comments(body)
        p += 4 + n
        if last:
            break
    inf["streams"] = [dict(codec_type="audio", codec_name="flac")]
    return inf


# ---------------------------------------------------------------- MP4 / MOV
def mp4_atoms(b, start, end):
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


def mp4_find(b, start, end, path):
    typ, rest = path[0], path[1:]
    out = []
    for t, s, e in mp4_atoms(b, start, end):
        if t == typ:
            if rest:
                out += mp4_find(b, s, e, rest)
            else:
                out.append((s, e))
    return out


def esds_oti(body):
    # descriptor walk: ES_Descriptor(0x03) -> DecoderConfigDescriptor(0x04) objectTypeIndication
    p = 4  # version/flags
    def rd_len(q):
        n, i = 0, 0
        while i < 4:
            c = body[q + i]; n = (n << 7) | (c & 0x7F); i += 1
            if not c & 0x80:
                break
        return n, q + i
    while p < len(body):
        tag = body[p]
        ln, q = rd_len(p + 1)
        if tag == 0x03:
            p = q + 3
            flags = body[q + 2]
            if flags & 0x80: p += 2
            if flags & 0x40: p += 1 + body[p]
            if flags & 0x20: p += 2
            continue
        if tag == 0x04:
            return body[q]
        p = q + ln
    return None


def parse_mp4(b):
    inf = _info(container="mp4")
    ft = mp4_find(b, 0, len(b), [b"ftyp"])
    if ft:
        inf["major_brand"] = b[ft[0][0]:ft[0][0] + 4].decode("latin1")
    traks = mp4_find(b, 0, len(b), [b"moov", b"trak"])
    mvhd = mp4_find(b, 0, len(b), [b"moov", b"mvhd"])
    if mvhd:
        s, e = mvhd[0]
        ver = b[s]
        if ver == 1:
            ts, dur = struct.unpack(">IQ", b[s + 20:s + 32])
        else:
            ts, dur = struct.unpack(">II", b[s + 12:s + 20])
        if ts:
            inf["duration"] = dur / float(ts)
    for s, e in traks:
        hd = mp4_find(b, s, e, [b"mdia", b"hdlr"])
        htype = b[hd[0][0] + 8:hd[0][0] + 12].decode("latin1") if hd else "?"
        st = dict(codec_type={"soun": "audio", "vide": "video", "text": "subtitle", "sbtl": "subtitle"}.get(htype, htype))
        stsd = mp4_find(b, s, e, [b"mdia", b"minf", b"stbl", b"stsd"])
        if stsd:
            ss, se = stsd[0]
            cnt = struct.unpack(">I", b[ss + 4:ss + 8])[0]
            p = ss + 8
            if cnt and p + 8 <= se:
                esz = struct.unpack(">I", b[p:p + 4])[0]
                fourcc = b[p + 4:p + 8].decode("latin1")
                st["fourcc"] = fourcc
                st["codec_name"] = MP4_CODECS.get(fourcc, fourcc.strip().lower())
                if st["codec_type"] == "audio" and p + 36 <= se:
                    ver = struct.unpack(">H", b[p + 16:p + 18])[0]
                    st["channels"] = struct.unpack(">H", b[p + 24:p + 26])[0]
                    st["bits_per_sample"] = struct.unpack(">H", b[p + 26:p + 28])[0]
                    st["sample_rate"] = struct.unpack(">I", b[p + 32:p + 36])[0] >> 16
                    ext = p + 36 + (16 if ver == 1 else 36 if ver == 2 else 0)
                    for t2, s2, e2 in mp4_atoms(b, ext, p + esz):
                        if t2 == b"esds":
                            oti = esds_oti(b[s2:e2])
                            st["object_type"] = oti
                            st["codec_name"] = {0x40: "aac", 0x66: "aac", 0x67: "aac", 0x68: "aac", 0x69: "mp3", 0x6B: "mp3",
                                                0xA5: "ac3", 0xA6: "eac3", 0xA9: "dts", 0xDD: "vorbis", 0xE1: "qcelp"}.get(oti, st["codec_name"])
                        elif t2 == b"wave":
                            for t3, s3, e3 in mp4_atoms(b, s2, e2):
                                if t3 == b"esds":
                                    oti = esds_oti(b[s3:e3])
                                    st["codec_name"] = {0x40: "aac", 0x6B: "mp3", 0x69: "mp3"}.get(oti, st["codec_name"])
        inf["streams"].append(st)
    aud = [s for s in inf["streams"] if s["codec_type"] == "audio"]
    inf["audio_stream_count"] = len(aud)
    inf["video_stream_count"] = len([s for s in inf["streams"] if s["codec_type"] == "video"])
    if aud:
        a = aud[0]
        inf.update(codec_name=a.get("codec_name"), sample_rate=a.get("sample_rate"), channels=a.get("channels"),
                   bits_per_sample=a.get("bits_per_sample"))
    # ilst tags
    for s, e in mp4_find(b, 0, len(b), [b"moov", b"udta", b"meta"]):
        for t, s2, e2 in mp4_atoms(b, s + 4, e):
            if t == b"ilst":
                for t3, s3, e3 in mp4_atoms(b, s2, e2):
                    for t4, s4, e4 in mp4_atoms(b, s3, e3):
                        if t4 == b"data":
                            nm = {b"\xa9nam": "title", b"\xa9ART": "artist", b"\xa9alb": "album", b"\xa9cmt": "comment",
                                  b"\xa9day": "date", b"\xa9too": "encoder"}.get(t3, t3.decode("latin1", "replace"))
                            inf["tags"][nm] = b[s4 + 8:e4].decode("utf-8", "replace")
    return inf


# ---------------------------------------------------------------- misc containers
def parse_amr(b):
    wb = b.startswith(b"#!AMR-WB")
    inf = _info(container="amr", codec_name="amr_wb" if wb else "amr_nb", sample_rate=16000 if wb else 8000, channels=1,
                audio_stream_count=1)
    inf["streams"] = [dict(codec_type="audio", codec_name=inf["codec_name"])]
    return inf


def parse_au(b):
    off, size, enc, sr, ch = struct.unpack(">IIIII", b[4:24])
    name = {1: "pcm_mulaw", 2: "pcm_s8", 3: "pcm_s16be", 4: "pcm_s24be", 5: "pcm_s32be", 6: "pcm_f32be", 7: "pcm_f64be",
            23: "adpcm_g726", 27: "pcm_alaw"}.get(enc, "unknown_%d" % enc)
    bps = {1: 8, 2: 8, 3: 16, 4: 24, 5: 32, 6: 32, 7: 64, 27: 8}.get(enc)
    inf = _info(container="au", codec_name=name, sample_rate=sr, channels=ch, bits_per_sample=bps, audio_stream_count=1)
    if bps and sr and ch:
        inf["duration"] = (len(b) - off) / float(sr * ch * bps / 8)
    inf["streams"] = [dict(codec_type="audio", codec_name=name)]
    return inf


def parse_mkv(b):
    inf = _info(container="matroska")
    # cheap scan: TrackEntry(AE) ... TrackType(83 xx) / CodecID(86 len str)
    ids = [(m.start(), m.group(1).decode("latin1")) for m in re.finditer(rb"\x86[\x80-\xff]([A-Z]_[A-Z0-9/]+(?:/[A-Z0-9]+)*)", b)]
    types = [(m.start(), m.group(1)[0]) for m in re.finditer(rb"\x83\x81([\x01\x02\x03\x10\x11\x12\x20])", b)]
    for off, cid in ids:
        # nearest preceding/following TrackType within 64 bytes
        tt = [t for o, t in types if abs(o - off) < 64]
        ctype = {1: "video", 2: "audio", 17: "subtitle"}.get(tt[0] if tt else (2 if cid.startswith("A_") else 1), "data")
        if cid.startswith("A_"):
            ctype = "audio"
        elif cid.startswith("V_"):
            ctype = "video"
        inf["streams"].append(dict(codec_type=ctype, codec_id=cid, codec_name=MKV_CODECS.get(cid, cid.lower())))
    aud = [s for s in inf["streams"] if s["codec_type"] == "audio"]
    inf["audio_stream_count"] = len(aud)
    inf["video_stream_count"] = len([s for s in inf["streams"] if s["codec_type"] == "video"])
    if aud:
        inf["codec_name"] = aud[0]["codec_name"]
    if b[:4] == b"\x1aE\xdf\xa3" and b"webm" in b[:64]:
        inf["container"] = "webm"
    return inf


def parse_asf(b):
    inf = _info(container="asf")
    # Stream Properties Object GUID B7DC0791-A9B7-11CF-8EE6-00C00C205365; audio media GUID F8699E40-5B4D-11CF-A8FD-00805F5C442B
    SPO = bytes.fromhex("9107dcb7b7a9cf118ee600c00c205365")
    AUD = bytes.fromhex("409e69f84d5bcf11a8fd00805f5c442b")
    p = 0
    while True:
        p = b.find(SPO, p)
        if p < 0:
            break
        q = p + 24
        stype = b[q:q + 16]
        tso = struct.unpack("<I", b[q + 40:q + 44])[0]
        if stype == AUD:
            tag, ch, sr, br, ba, bps = struct.unpack("<HHIIHH", b[q + 54:q + 70])
            name = {1: pcm_name(bps)}.get(tag, WAV_TAGS.get(tag, "unknown_0x%04x" % tag))
            inf["streams"].append(dict(codec_type="audio", codec_name=name, sample_rate=sr, channels=ch, bits_per_sample=bps, bit_rate=br * 8))
        else:
            inf["streams"].append(dict(codec_type="video", codec_name="?"))
        p += 16
    aud = [s for s in inf["streams"] if s["codec_type"] == "audio"]
    inf["audio_stream_count"] = len(aud)
    inf["video_stream_count"] = len(inf["streams"]) - len(aud)
    if aud:
        inf.update(codec_name=aud[0]["codec_name"], sample_rate=aud[0]["sample_rate"], channels=aud[0]["channels"],
                   bits_per_sample=aud[0]["bits_per_sample"], bit_rate=aud[0]["bit_rate"])
    return inf


def parse_caf(b):
    inf = _info(container="caf")
    p = 8
    while p + 12 <= len(b):
        typ = b[p:p + 4]
        sz = struct.unpack(">q", b[p + 4:p + 12])[0]
        body = b[p + 12:p + 12 + sz]
        if typ == b"desc" and len(body) >= 32:
            sr = struct.unpack(">d", body[:8])[0]
            fid = body[8:12].decode("latin1")
            flags, bpp, fpp, cpf, bpc = struct.unpack(">IIIII", body[12:32])
            inf.update(sample_rate=int(sr), channels=cpf, bits_per_sample=bpc or None)
            if fid == "lpcm":
                inf["codec_name"] = pcm_name(bpc, fmt_float=bool(flags & 1), be=not (flags & 2))
            else:
                inf["codec_name"] = {"aac ": "aac", "alac": "alac", ".mp3": "mp3", "ulaw": "pcm_mulaw", "alaw": "pcm_alaw",
                                     "ima4": "adpcm_ima_qt", "opus": "opus", "flac": "flac", "samr": "amr_nb"}.get(fid, fid.strip().lower())
        p += 12 + max(sz, 0)
        if sz < 0:
            break
    inf["audio_stream_count"] = 1 if inf.get("codec_name") else 0
    return inf


# ---------------------------------------------------------------- dispatcher
def is_email(b):
    head = b[:4096]
    return bool(re.match(rb"^(?:[A-Za-z][A-Za-z0-9-]*:\s)", head)) and (b"\nContent-Type:" in head or b"\nFrom:" in head or b"\nMessage-ID:" in head or b"\nSubject:" in head)


def probe(b, depth=0):
    """-> info dict (never raises); codec_name None when no audio stream is recognised."""
    try:
        if b[:4] in (b"RIFF", b"RIFX", b"RF64", b"BW64") and b[8:12] == b"WAVE":
            return parse_riff(b)
        if b[:4] == b"RIFF":
            return parse_riff(b)
        if b[:4] == b"FORM" and b[8:12] in (b"AIFF", b"AIFC"):
            return parse_aiff(b)
        if b[:4] == b"fLaC":
            return parse_flac(b)
        if b[:4] == b"OggS":
            return parse_ogg(b)
        if b[4:8] in (b"ftyp", b"moov", b"mdat", b"wide", b"free", b"skip", b"pnot"):
            return parse_mp4(b)
        if b.startswith(b"#!AMR"):
            return parse_amr(b)
        if b[:4] == b".snd":
            return parse_au(b)
        if b[:4] == b"\x1aE\xdf\xa3":
            return parse_mkv(b)
        if b[:16] == bytes.fromhex("3026b2758e66cf11a6d900aa0062ce6c"):
            return parse_asf(b)
        if b[:4] == b"caff":
            return parse_caf(b)
        if b[:3] == b"ID3" or (len(b) > 4 and b[0] == 0xFF and (b[1] & 0xE0) == 0xE0):
            r = parse_mp3(b)
            if r:
                return r
        if depth == 0 and is_email(b):
            import email, email.policy
            m = email.message_from_bytes(b, policy=email.policy.compat32)
            atts = []
            for part in m.walk():
                if part.is_multipart():
                    continue
                pl = part.get_payload(decode=True) or b""
                r = probe(pl, depth + 1)
                if r.get("codec_name"):
                    r["attachment_filename"] = part.get_filename()
                    r["attachment_content_type"] = part.get_content_type()
                    r["wrapper"] = "eml"
                    return r
            return _info(container="eml")
        r = parse_mp3(b)  # last resort: an MPEG frame sync somewhere near the start (headerless mp3)
        if r and r.get("frame_count", 0) >= 3:
            return r
    except Exception as ex:
        return _info(error=repr(ex))
    return _info(container=None)


def fmt_duration(d, how):
    if d is None:
        return "none"
    if how.endswith("_ms") or how.endswith("milliseconds"):
        return str(int(round(d * 1000)))
    if how.endswith("_us"):
        return str(int(round(d * 1e6)))
    if "rounded" in how or how.endswith("_s_int"):
        return str(int(round(d)))
    s = ("%.6f" % d).rstrip("0").rstrip(".")
    return s


MEDIA_ALIASES = {"codec": "codec_name", "audio_codec": "codec_name", "audio_codec_name": "codec_name",
                 "primary_audio_codec": "codec_name", "primary_audio_codec_name": "codec_name", "primary_codec_name": "codec_name",
                 "first_audio_codec_name": "codec_name", "format": "container", "format_name": "container",
                 "container_format": "container", "container_name": "container", "container": "container",
                 "sample_rate": "sample_rate", "sample_rate_hz": "sample_rate", "audio_sample_rate_hz": "sample_rate",
                 "primary_audio_sample_rate_hz": "sample_rate", "primary_audio_sample_rate": "sample_rate",
                 "channels": "channels", "channel_count": "channels", "audio_channels": "channels",
                 "primary_audio_channels": "channels", "primary_audio_channel_count": "channels",
                 "bits_per_sample": "bits_per_sample", "bit_depth": "bits_per_sample", "primary_audio_bits_per_sample": "bits_per_sample",
                 "bit_rate": "bit_rate", "bitrate": "bit_rate", "bit_rate_bps": "bit_rate",
                 "audio_stream_count": "audio_stream_count", "audio_streams": "audio_stream_count",
                 "video_stream_count": "video_stream_count", "stream_count": "stream_count",
                 "title": "title", "title_tag": "title", "inam": "title", "artist": "artist", "comment": "comment",
                 "format_tag": "format_tag", "wave_format_tag": "format_tag", "format_tag_u16_hex": "format_tag_hex",
                 "wave_format_tag_u16_hex": "format_tag_hex"}


def media_field(b, snake, info=None):
    inf = info or probe(b)
    s = snake.lower()
    if s.startswith("duration"):
        return fmt_duration(inf.get("duration"), s)
    key = MEDIA_ALIASES.get(s)
    if key is None:
        # strip common prefixes/suffixes and retry
        s2 = re.sub(r"^(primary_|first_)?(audio_)?", "", s)
        key = MEDIA_ALIASES.get(s2, s2)
    if key == "codec_name":
        return inf.get("codec_name") or "none"
    if key == "stream_count":
        return str(len(inf.get("streams") or []) or (1 if inf.get("codec_name") else 0))
    if key == "format_tag_hex":
        return "0x%04x" % inf["format_tag"] if inf.get("format_tag") is not None else "none"
    if key in ("title", "artist", "comment", "album", "date", "encoder", "genre"):
        v = (inf.get("tags") or {}).get(key)
        return v if v not in (None, "") else "none"
    if key in inf:
        v = inf[key]
        if isinstance(v, (list, dict)):
            return json.dumps(v, separators=(",", ":"), ensure_ascii=False)
        return "none" if v in (None, "") else str(v)
    t = (inf.get("tags") or {})
    for k, v in t.items():
        if k.replace("_", "").lower() == key.replace("_", "").lower():
            return v
    raise KeyError("no media field %s (have %s, tags %s)" % (snake, sorted(k for k, v in inf.items() if v not in (None, [], {})), sorted(t)))


if __name__ == "__main__":
    import sys
    for f in sys.argv[1:]:
        b = open(f, "rb").read()
        i = probe(b)
        print(f, json.dumps({k: v for k, v in i.items() if k != "chunks"}, default=str)[:1500])
