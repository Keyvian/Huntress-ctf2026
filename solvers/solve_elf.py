#!/usr/bin/env python3
import sys, os, re, json, io, zipfile, subprocess, struct, tempfile, requests
GM = "http://<homebase-ip>/huntress-ctf-proxy"
S = requests.Session(); S.headers.update({"Content-Type": "application/json"})

MACH = {62:"x86-64",3:"i386",40:"arm",183:"aarch64",243:"riscv",2:"sparc",20:"powerpc",21:"powerpc64",8:"mips"}
ETYPE = {1:"ET_REL",2:"ET_EXEC",3:"ET_DYN",4:"ET_CORE"}
CRT = {"_start","main","_init","_fini","_edata","_end","__bss_start","_dl_relocate_static_pie",
 "deregister_tm_clones","register_tm_clones","__do_global_dtors_aux","frame_dummy","__libc_csu_init",
 "__libc_csu_fini","data_start","__data_start","__dso_handle","__TMC_END__","_IO_stdin_used",
 "__gmon_start__","__libc_start_main","completed.0","abort","puts","printf","__cxa_finalize"}


def run(*a):
    return subprocess.run(a, capture_output=True, text=True, errors="replace").stdout


def elf_facts(path):
    with open(path, "rb") as f:
        b = f.read()
    cls, data = b[4], b[5]
    elf_class = "ELF64" if cls == 2 else "ELF32"
    endian = "little" if data == 1 else "big"
    e_type, e_machine = struct.unpack_from("<HH", b, 16)
    e_entry = struct.unpack_from("<Q", b, 24)[0] if cls == 2 else struct.unpack_from("<I", b, 24)[0]
    machine = MACH.get(e_machine, "0x%x" % e_machine)
    elf_type = ETYPE.get(e_type, "0x%x" % e_type)
    rs = run("readelf", "-S", "-W", path)
    has_symtab = "true" if re.search(r"\.symtab\b", rs) else "false"
    marker = "none"
    hx = run("readelf", "-x", ".huntress", path)
    if "Hex dump" in hx:
        raw = bytearray()
        for line in hx.splitlines():
            m = re.match(r"\s*0x[0-9a-fA-F]+\s+((?:[0-9a-fA-F]{2,8}\s){1,4})", line)
            if m:
                for tok in m.group(1).split():
                    for i in range(0, len(tok), 2):
                        raw.append(int(tok[i:i+2], 16))
        marker = bytes(raw).split(b"\x00")[0].decode("utf-8", "replace")
    exported = "none"
    glob_funcs = []
    for line in run("nm", path).splitlines():
        p = line.split()
        if len(p) >= 3 and p[1] == "T" and p[2] not in CRT:
            glob_funcs.append(p[2])
    if glob_funcs:
        exported = glob_funcs[0]
    recover = "none"   # constant returned by the function NAMED recover_code, else none
    dis = run("objdump", "-d", "-M", "intel", path)
    mm = re.search(r"<recover_code>:(.*?)(?:\n\n|\Z)", dis, re.S)
    if mm:
        m2 = re.search(r"mov\s+eax,0x([0-9a-fA-F]+)", mm.group(1))
        if m2:
            recover = str(int(m2.group(1), 16))
    return {"elf_class":elf_class,"endianness":endian,"machine":machine,"elf_type":elf_type,
            "marker":marker,"has_symtab":has_symtab,"exported_symbol":exported,
            "recover_code":recover,"entry_point":"0x%x" % e_entry}


def fetch(cid, delivery=None):
    p = {"op":"artifact","challenge":cid}
    if delivery is not None:
        p["delivery"] = delivery
    return S.get(GM, params=p).content


def rec_extract(blob, prefix, out):
    if blob[:2] != b"PK":
        if blob[:4] == b"\x7fELF":
            out[prefix or "bin"] = blob
        return
    try:
        z = zipfile.ZipFile(io.BytesIO(blob))
    except Exception:
        return
    for info in z.infolist():
        bb = z.read(info.filename)
        if info.filename.lower().endswith(".zip") and bb[:2] == b"PK":
            rec_extract(bb, prefix + info.filename + " -> ", out)
        else:
            out[prefix + info.filename] = bb


def gather(cid, deliveries=False):
    out = {}
    rec_extract(fetch(cid), "", out)
    if deliveries:
        for i in range(0, 8):
            d = fetch(cid, delivery=i)
            if d and not (d[:1] == b"{" and b"error" in d[:60]):
                rec_extract(d, "d%d:" % i, out)
    return {k: v for k, v in out.items() if v[:4] == b"\x7fELF"}


def main():
    import time, hashlib
    cid = sys.argv[1]; t0 = time.time()
    st = S.post(GM, data=json.dumps({"op":"retry" if "retry" in sys.argv[2:] else "start","challenge":cid})).json()
    if st.get("answer_ids") is None or st.get("error"):
        st = S.post(GM, data=json.dumps({"op":"retry","challenge":cid})).json()
    aids = st.get("answer_ids") or []
    print("mode=%s deadline=%s n_answers=%d" % (st.get("mode"), st.get("deadline"), len(aids)))

    def parse(aid):
        s = sl = None; field = aid
        m = re.match(r"set(\d+)\.(.+)$", aid)
        if m: s = int(m.group(1)); field = m.group(2)
        m = re.match(r"slot(\d+)[._](.+)$", field)
        if m: sl = int(m.group(1)); field = m.group(2)
        return s, sl, field

    parsed = [(aid,) + parse(aid) for aid in aids]
    sets = sorted({p[1] for p in parsed if p[1] is not None})

    # PRE-FETCH everything up front (minimize window exposure)
    containers = {}
    if sets:
        for s in sets:
            d = fetch(cid, delivery=s - 1)
            if d[:1] == b"{" and b"error" in d[:60]:
                d = fetch(cid)
            containers[s] = d
    else:
        containers[None] = fetch(cid)
    print("fetched %d containers (t=%.2fs)" % (len(containers), time.time() - t0))

    # extract ELF members per container (positional list)
    def members(data):
        out = {}; rec_extract(data, "", out)
        items = [(k.split(" -> ")[-1].split(":")[-1], v) for k, v in out.items() if v[:4] == b"\x7fELF"]
        return items
    memcache = {k: members(v) for k, v in containers.items()}

    # facts deduped by content hash
    tmpd = tempfile.mkdtemp(); fcache = {}
    def facts_of(data):
        h = hashlib.sha256(data).hexdigest()
        if h in fcache: return fcache[h]
        p = os.path.join(tmpd, h[:12] + ".elf")
        with open(p, "wb") as f: f.write(data)
        fcache[h] = elf_facts(p); return fcache[h]

    def binary_for(s, sl):
        items = memcache.get(s) or memcache.get(None) or []
        if not items: return None
        if sl is not None:
            for cand in ("slot-%d.elf" % sl, "slot%d.elf" % sl, "m-slot-%d.elf" % sl):
                for n, v in items:
                    if n == cand: return v
            return items[sl][1] if sl < len(items) else None
        return items[0][1]

    answers = {}
    for aid, s, sl, field in parsed:
        v = binary_for(s, sl)
        if v is None: continue
        fa = facts_of(v)
        if field in fa: answers[aid] = fa[field]
    print("computed %d/%d answers (t=%.2fs)" % (len(answers), len(aids), time.time() - t0))
    r = S.post(GM, data=json.dumps({"op":"submit","challenge":cid,"answers":answers})).json()
    print("SUBMIT (t=%.2fs):" % (time.time() - t0), json.dumps({k: r.get(k) for k in ("result","flag","remaining","status","error")}))
    if r.get("result") == "CORRECT":
        print("FLAG:", r.get("flag"))


if __name__ == "__main__":
    main()
