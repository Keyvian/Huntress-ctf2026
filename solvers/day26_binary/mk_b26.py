"""Build b26.py from b25.py: new module docstring + d26_fields() + the d26 hook in set_answers().
Usage: python -I mk_b26.py <dir containing b25.py>   (writes <dir>/b26.py)"""
import sys, os

d = sys.argv[1]
src = open(os.path.join(d, "b25.py")).read()

HDR = '''"""Day-26 binary 'Crash Course' (crash-triage) solver (d01..d26), any mode.
Day 26 = Day-25 contract (300 q) + 12 fields: d26 = ONE Groovy jar d26--<stem>.jar (member 1 in ZIP central-directory
order) = META-INF/MANIFEST.MF (Main-Class: Day26VariantNNN, "Huntress deterministic Groovy factory"),
<Main>.class (PRIMARY classfile: stageThree/stageTwo/stageOne/main/... + encodedConfig Base64 constant),
<Main>$_main_closure1.class (Groovy closure), crash/trace.json ({"schema":"huntress.synthetic_crash.v1",
"kind":"IllegalStateException","frames":["stageThree","stageTwo","stageOne"]}).
Fields: artifact_sha256_1; format (jar); config_{campaign,domain,mutex,url,crc32_hex} + hcfg_version + xor_key_hex from
the first CRC32-valid HCFG record among the PRIMARY classfile's Base64-alphabet UTF-8 constants (>= 80 chars);
crash_fault_method = frames[0] of crash/trace.json; crash_frames_match_methods = every frame string is in the primary
classfile's method-name set; method_count = the primary classfile's methods_count. Primary classfile = the manifest
Main-Class (fallback: the classfile holding the HCFG record). Built on b25.py:
'''
assert src.startswith('"""Day-25 binary')
src = HDR + src[len('"""'):]

FUNC = '''

def d26_fields(fl, diag):
    """Day-26 'Crash Course' unit: ONE Groovy jar (see module docstring)."""
    A = {}
    for i, (n, b) in enumerate(fl):
        A["d26_artifact_sha256_%d" % (i + 1)] = sha256(b)
    diag["d26_order"] = [n for n, _ in fl]
    jars = [(n, b) for n, b in fl if b[:2] == b"PK"]
    if not jars:
        diag["d26_NO_JAR"] = True
        return A
    n, b = jars[0]
    A["d26_analysis_format"] = fmt_of(b, cli=True)
    jz = zipfile.ZipFile(io.BytesIO(b))
    names = jz.namelist()
    main = None
    try:
        mf = jz.read("META-INF/MANIFEST.MF").decode("latin-1")
        m = re.search(r"Main-Class:\\s*(\\S+)", mf)
        if m:
            main = m.group(1).replace(".", "/") + ".class"
    except KeyError:
        pass
    # primary classfile = manifest Main-Class; fall back to the classfile holding the first CRC32-valid HCFG record
    rec_any = jar_cp_hcfg(b)
    if main not in names:
        diag["d26_MAIN_MISSING"] = main
        main = rec_any["cls"] if rec_any else next((x for x in names if x.endswith(".class") and "$" not in x), None)
    diag["d26_main"] = main
    rec, mnames = None, []
    if main:
        cb = jz.read(main)
        try:
            acc, this, sup, fields, methods = parse_class(cb)
            mnames = [mm[1] for mm in methods]
            A["d26_analysis_method_count"] = str(len(methods))
            diag["d26_methods"] = mnames
        except Exception as ex:
            diag["d26_PARSE_ERR"] = str(ex)
        # HCFG from the primary classfile constant pool (first CRC32-valid Base64>=80 constant)
        for s in class_cp_utf8(cb):
            if len(s) < 80 or not B64_CONST.match(s):
                continue
            try:
                dd = base64.b64decode(s + b"=" * (-len(s) % 4))
            except Exception:
                continue
            if dd[:4] != b"HCFG" or len(dd) < 12:
                continue
            ver, key, ln = dd[4], dd[5], struct.unpack("<H", dd[6:8])[0]
            hdr_crc = struct.unpack("<I", dd[8:12])[0]
            if len(dd) < 12 + ln:
                continue
            plain = bytes(x ^ key for x in dd[12:12 + ln])
            if (zlib.crc32(plain) & 0xffffffff) != hdr_crc:
                continue
            try:
                cfg = json.loads(plain.decode("utf-8"))
            except Exception:
                continue
            if isinstance(cfg, dict):
                rec = dict(ver=ver, key=key, ln=ln, hdr_crc=hdr_crc, plain=plain, cfg=cfg, cls=main)
                break
    if rec is None and rec_any is not None:
        diag["d26_HCFG_FROM_OTHER_CLASS"] = rec_any["cls"]
        rec = rec_any
    if rec:
        c = rec["cfg"]
        for k in ("campaign", "domain", "mutex", "url"):
            A["d26_analysis_config_%s" % k] = str(c.get(k, "none"))
        A["d26_analysis_config_crc32_hex"] = "0x%08x" % rec["hdr_crc"]
        A["d26_analysis_hcfg_version"] = str(rec["ver"])
        A["d26_analysis_xor_key_hex"] = "0x%02x" % rec["key"]
        diag["d26_cfg"] = (rec["cls"], "0x%02x" % rec["key"], "0x%08x" % rec["hdr_crc"], c.get("campaign"))
    else:
        diag["d26_NO_HCFG"] = True
    # crash/trace.json
    tr = next((x for x in names if x.lower().endswith("trace.json")), None)
    diag["d26_trace"] = tr
    if tr:
        try:
            t = json.loads(jz.read(tr).decode("utf-8"))
            frames = t.get("frames") or []
            diag["d26_frames"] = frames; diag["d26_kind"] = t.get("kind")
            if frames:
                A["d26_analysis_crash_fault_method"] = str(frames[0])
            ms = set(mnames)
            missing = [f for f in frames if str(f) not in ms]
            A["d26_analysis_crash_frames_match_methods"] = "true" if frames and not missing else "false"
            if missing:
                diag["d26_frames_missing"] = missing
        except Exception as ex:
            diag["d26_TRACE_ERR"] = str(ex)
    return A

'''
marker = "\n\ndef set_answers(files):"
assert marker in src
src = src.replace(marker, FUNC + marker[1:], 1)

HOOK = '''    if "d25" in by:
        A.update(d25_fields(by["d25"], diag))
'''
assert HOOK in src
src = src.replace(HOOK, HOOK + '''    if "d26" in by:
        A.update(d26_fields(by["d26"], diag))
''', 1)
open(os.path.join(d, "b26.py"), "w").write(src)
print("b26.py written", len(src))
