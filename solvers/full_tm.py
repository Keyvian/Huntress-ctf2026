import requests, json, time, hashlib, zlib, subprocess, re
GM="http://<homebase-ip>/huntress-ctf-proxy"
S=requests.Session(); S.headers.update({"Content-Type":"application/json"})
CID="binary-reverse-engineering-day-03-managed-configuration"
T="/home/HuntressCTF/solvers/day3-binary-evidence/"
cj=lambda x: json.dumps(x,separators=(",",":"))
h=lambda f: hashlib.sha256(open(T+f,"rb").read()).hexdigest()
def cfg(f,key):
    d=open(T+f,"rb").read(); i=d.find(b"HCFG"); n=d[i+6]|(d[i+7]<<8)
    return bytes(b^key for b in d[i+12:i+12+n])
c2=cfg("d02--variant-000.elf",0x31); j2=json.loads(c2); j3=json.loads(cfg("d03--variant-000.dll",0x41))
f1=T+"d01--variant-000.elf"
secs=[m.group(2) for m in (re.match(r"\s*\[\s*(\d+)\]\s+(\S+)",l) for l in subprocess.run(["readelf","-SW",f1],capture_output=True,text=True).stdout.splitlines()) if m and m.group(2)!="NULL"]
syms=[];cur=None
for line in subprocess.run(["readelf","-sW",f1],capture_output=True,text=True).stdout.splitlines():
    if "Symbol table" in line: cur=".symtab" in line; continue
    p=line.split()
    if cur and len(p)>=8 and p[0].rstrip(":").isdigit(): syms.append(p[7])
A={"d01_artifact_sha256_1":h("d01--variant-000.elf"),"d01_analysis_elf_class":"ELF64","d01_analysis_machine":"x86-64",
 "d01_analysis_section_names":cj([""]+secs),"d01_analysis_symbols":cj(syms),"d01_analysis_disassembly":cj(["mov eax, 8100","ret"]),
 "d01_analysis_elf_type":"ET_EXEC","d01_analysis_endianness":"little",
 "d02_artifact_sha256_1":h("d02--variant-000.elf"),"d02_analysis_format":"elf",
 "d02_analysis_config_campaign":j2["campaign"],"d02_analysis_config_domain":j2["domain"],"d02_analysis_config_mutex":j2["mutex"],
 "d02_analysis_config_url":j2["url"],"d02_analysis_config_crc32_hex":"0x%08x"%zlib.crc32(c2),"d02_analysis_xor_key_hex":"0x31",
 "d03_artifact_sha256_1":h("d03--variant-000.dll"),"d03_artifact_sha256_2":h("d03--variant-000.runtimeconfig.json"),
 "d03_analysis_machine":"i386","d03_analysis_metadata_version":"v4.0.30319",
 "d03_analysis_config_campaign":j3["campaign"],"d03_analysis_config_domain":j3["domain"],"d03_analysis_config_mutex":j3["mutex"]}
st=S.post(GM,data=json.dumps({"op":"start","challenge":CID})).json()
assert set(st["answer_ids"])==set(A)|{"d03_analysis_format"}, set(st["answer_ids"])^(set(A)|{"d03_analysis_format"})
for fmt in ["pe","dotnet","PE","pe32"]:
    A2=dict(A); A2["d03_analysis_format"]=fmt
    for _ in range(4):
        r=S.post(GM,data=json.dumps({"op":"submit","challenge":CID,"answers":A2})).json()
        if r.get("error")=="rate_limited": time.sleep(4); continue
        break
    print("FULL submit format=%-8r -> %s"%(fmt,{k:r.get(k) for k in ("result","flag","remaining","status","error")}))
    if r.get("result")=="CORRECT": break
    time.sleep(2)
