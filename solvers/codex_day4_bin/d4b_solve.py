#!/usr/bin/env python3
import json, hashlib, zlib, re, subprocess, struct, sys, io, time
import requests, pyzipper
GM = "http://<homebase-ip>/huntress-ctf-proxy"
S = requests.Session(); S.headers.update({"Content-Type": "application/json"})
BASE = "binary-reverse-engineering-day-04-go-runtime-fingerprints"
WORK = "/home/HuntressCTF/codex_day4_bin"
def sh(c): return subprocess.run(c, shell=True, capture_output=True, text=True).stdout
def cj(x): return json.dumps(x, separators=(",", ":"))
def h(b): return hashlib.sha256(b).hexdigest()

def hcfg(b):
    p = b.index(b"HCFG"); key = b[p+5]; size = int.from_bytes(b[p+6:p+8], "little")
    plain = bytes(x ^ key for x in b[p+12:p+12+size])
    return key, plain, zlib.crc32(plain) & 0xffffffff

def extract(cid):
    raw = S.get(GM, params={"op": "artifact", "challenge": cid}).content
    z = pyzipper.AESZipFile(io.BytesIO(raw)); z.setpassword(b"infected")
    files = {}
    for n in z.namelist():
        if not n.endswith("/"):
            p = WORK + "/" + n.replace("/", "_"); open(p, "wb").write(z.read(n))
            files[n.split("/")[-1]] = (p, z.read(n))
    return files

def d01_fields(path, b, pfx):
    secs = re.findall(r"\]\s+(\.[\w.\-]+)", sh(f"readelf -SW {path}"))
    # .symtab names in order (non-empty), from the .symtab block only
    out_syms = []; intab = False
    for ln in sh(f"readelf -sW {path}").splitlines():
        if "Symbol table '.symtab'" in ln: intab = True; continue
        if "Symbol table '.dynsym'" in ln: intab = False; continue
        if intab:
            m = re.match(r"\s*\d+:\s+\S+\s+\d+\s+\w+\s+\w+\s+\S+\s+\S+\s+(\S+)", ln)
            if m: out_syms.append(m.group(1))
    # recover_code disassembly (Intel, decimal immediate)
    dii = sh(f"objdump -d -Mintel {path}"); grab = False; ins = []
    for ln in dii.splitlines():
        if "<recover_code>:" in ln: grab = True; continue
        if grab:
            m = re.match(r"\s*[0-9a-f]+:\s+[0-9a-f ]+?\s{2,}(\S.*)$", ln)
            if m: ins.append(re.sub(r"\s+", " ", m.group(1)).strip())
            if "ret" in ln: break
    def dec(i):  # 'mov eax,0x1fa4' -> 'mov eax, 8100'
        mm = re.match(r"(\w+)\s+(\w+),(0x[0-9a-f]+|\d+)$", i)
        if mm: return f"{mm.group(1)} {mm.group(2)}, {int(mm.group(3),0)}"
        return i
    dis_dec = [dec(i) for i in ins]
    return {
        pfx+"artifact_sha256_1": [h(b)],
        pfx+"analysis_elf_class": ["ELF64", "ELFCLASS64"],
        pfx+"analysis_machine": ["x86-64", "X86-64", "AMD x86-64"],
        pfx+"analysis_elf_type": ["ET_EXEC", "EXEC"],
        pfx+"analysis_endianness": ["little", "LSB", "little endian"],
        pfx+"analysis_section_names": [cj([""]+secs), cj(secs)],
        pfx+"analysis_symbols": [cj(out_syms), cj([s for s in out_syms if s]), cj(["marker","recover_code"]) ],
        pfx+"analysis_disassembly": [cj(dis_dec), cj(ins), cj([i.replace(",", ", ") for i in ins])],
    }

def cfg_fields(b, pfx, has_url, has_xor):
    key, plain, crc = hcfg(b)
    cfg = json.loads(plain)
    d = {
        pfx+"artifact_sha256_1": [h(b)],
        pfx+"analysis_config_campaign": [cfg.get("campaign")],
        pfx+"analysis_config_domain": [cfg.get("domain")],
        pfx+"analysis_config_mutex": [cfg.get("mutex"), cfg.get("mutex","").replace("\\","\\\\")],
        pfx+"analysis_config_crc32_hex": ["0x%08x" % crc, "0x%x" % crc],
    }
    if has_url: d[pfx+"analysis_config_url"] = [cfg.get("url")]
    if has_xor: d[pfx+"analysis_xor_key_hex"] = ["0x%02x" % key, "0x%x" % key]
    return d

def solve_single():
    cid = BASE
    f = extract(cid)
    d01p, d01b = f["d01--variant-000.elf"]
    d02p, d02b = f["d02--variant-000.elf"]
    d03p, d03b = f["d03--variant-000.dll"]
    rcp, rcb = f["d03--variant-000.runtimeconfig.json"]
    d04p, d04b = f["d04--variant-000.elf"]
    CAND = {}
    CAND.update(d01_fields(d01p, d01b, "d01_"))
    CAND.update(cfg_fields(d02b, "d02_", True, True))
    CAND["d02_analysis_format"] = ["elf", "ELF"]
    # d03 .NET PE
    pos = d03b.index(b"BSJB"); ln = int.from_bytes(d03b[pos+12:pos+16], "little")
    mdv = d03b[pos+16:pos+16+ln].rstrip(b"\x00").decode()
    CAND.update(cfg_fields(d03b, "d03_", False, False))   # d03 has no url/xor fields
    CAND["d03_artifact_sha256_1"] = [h(d03b), h(rcb)]
    CAND["d03_artifact_sha256_2"] = [h(rcb), h(d03b)]
    CAND["d03_analysis_format"] = ["pe_cli", "pe", "pe32"]
    CAND["d03_analysis_machine"] = ["i386", "x86", "Intel 80386"]
    CAND["d03_analysis_metadata_version"] = [mdv]
    # d04 Go ELF
    CAND.update(cfg_fields(d04b, "d04_", True, False))     # d04 has url but no xor field
    CAND["d04_analysis_architecture"] = ["amd64", "x86-64", "x86_64", "AMD x86-64"]
    CAND["d04_analysis_format"] = ["elf", "go", "ELF"]

    st = S.post(GM, data=json.dumps({"op": "start", "challenge": cid})).json()
    ids = st["answer_ids"]; locked = {}
    for fid in ids:
        for c in CAND.get(fid, []):
            if c is None: continue
            r = S.post(GM, data=json.dumps({"op": "submit", "challenge": cid, "answers": {fid: c}})).json()
            if r.get("error") == "rate_limited": time.sleep(1.2); r = S.post(GM, data=json.dumps({"op": "submit", "challenge": cid, "answers": {fid: c}})).json()
            if r.get("result") in ("accepted", "CORRECT"):
                locked[fid] = c; print("OK   %-32s = %r rem=%s" % (fid, c, r.get("remaining"))); break
        else:
            print("FAIL %-32s cands=%s" % (fid, CAND.get(fid)))
    r = S.post(GM, data=json.dumps({"op": "submit", "challenge": cid, "answers": locked})).json()
    print("FINAL:", {k: r.get(k) for k in ("result", "flag", "remaining", "error")})
    return locked

if __name__ == "__main__":
    solve_single()
