import json, hashlib, zlib, re, subprocess, struct, sys
import requests
GM="http://<homebase-ip>/huntress-ctf-proxy"; S=requests.Session(); S.headers.update({"Content-Type":"application/json"})
CID="binary-reverse-engineering-day-03-managed-configuration"
D="/tmp/d3b/"
def sh(c): return subprocess.run(c,shell=True,capture_output=True,text=True).stdout
def cj(x): return json.dumps(x,separators=(",",":"))

d01=open(D+"d01--variant-000.elf","rb").read()
d02=open(D+"d02--variant-000.elf","rb").read()
d03=open(D+"d03--variant-000.dll","rb").read()
rc =open(D+"d03--variant-000.runtimeconfig.json","rb").read()
h=lambda b:hashlib.sha256(b).hexdigest()

# d01 sections
secs=re.findall(r"\]\s+(\.[\w.\-]+)",sh(f"readelf -SW {D}d01--variant-000.elf"))
# d01 symbols (.symtab) names in order, plus classified
symlines=sh(f"readelf -sW {D}d01--variant-000.elf")
allsyms=[]; globdef=[]; custom=[]
for ln in symlines.splitlines():
    m=re.match(r"\s*\d+:\s+([0-9a-f]+)\s+\d+\s+(\w+)\s+(\w+)\s+\w+\s+(\S+)\s+(\S+)",ln)
    if not m: continue
    val,typ,bind,ndx,name=m.groups()
    if not name or name in ("",): continue
    if ndx!="UND": allsyms.append(name)
    if bind=="GLOBAL" and ndx!="UND": globdef.append(name)
    if name in ("marker","recover_code"): custom.append(name)
# d01 disasm of recover_code
dis=sh(f"objdump -d {D}d01--variant-000.elf")
rc_ins=[]
grab=False
for ln in dis.splitlines():
    if "<recover_code>:" in ln: grab=True; continue
    if grab:
        m=re.match(r"\s*[0-9a-f]+:\s+([0-9a-f ]+?)\s{2,}(\S.*)$",ln)
        if m: rc_ins.append(m.group(2).strip())
        if "ret" in ln: break
rc_att=[re.sub(r"\s+"," ",x).strip() for x in rc_ins]
rc_intel=[]
dii=sh(f"objdump -d -Mintel {D}d01--variant-000.elf"); grab=False
for ln in dii.splitlines():
    if "<recover_code>:" in ln: grab=True; continue
    if grab:
        m=re.match(r"\s*[0-9a-f]+:\s+([0-9a-f ]+?)\s{2,}(\S.*)$",ln)
        if m: rc_intel.append(re.sub(r"\s+"," ",m.group(2)).strip())
        if "ret" in ln: break

# d02 config
sec=d02[0x2180:0x2180+0x17b]
key=None
for k in range(256):
    dec=bytes(b^k for b in sec)
    if b"campaign" in dec and b"{" in dec: key=k; break
dec=bytes(b^key for b in sec); j=dec.find(b"{"); e=dec.rfind(b"}")+1; cfgb=dec[j:e]
cfg=json.loads(cfgb)
crc_json=zlib.crc32(cfgb)&0xffffffff
# d03 machine
elf=struct.unpack_from("<I",d03,0x3c)[0]; mach=struct.unpack_from("<H",d03,elf+4)[0]

CAND={
 "d01_artifact_sha256_1":[h(d01)],
 "d01_analysis_elf_class":["ELF64","ELFCLASS64","64"],
 "d01_analysis_machine":["x86-64","X86-64","EM_X86_64","AMD x86-64","amd64","x86_64","Advanced Micro Devices X86-64"],
 "d01_analysis_elf_type":["ET_EXEC","EXEC","exec"],
 "d01_analysis_endianness":["little","LSB","little endian","lsb"],
 "d01_analysis_section_names":[cj(secs),cj([""]+secs),cj([".huntress"]),cj([s for s in secs if s==".huntress"])],
 "d01_analysis_symbols":[cj(custom),cj(custom[::-1]),cj(["recover_code"]),cj(globdef),cj(allsyms),cj(sorted(custom))],
 "d01_analysis_disassembly":[cj(rc_intel),cj(rc_att),cj(["mov eax, 0x1fa4","ret"]),cj(["mov eax,0x1fa4","ret"]),cj(["mov $0x1fa4,%eax","ret"]),cj(["mov    $0x1fa4,%eax","ret"]),cj(["b8 a4 1f 00 00","c3"]),cj(["b8a41f0000","c3"]),cj([" ".join(rc_att)])],
 "d02_artifact_sha256_1":[h(d02)],
 "d02_analysis_format":["elf","ELF"],
 "d02_analysis_config_campaign":[cfg.get("campaign")],
 "d02_analysis_config_domain":[cfg.get("domain")],
 "d02_analysis_config_mutex":[cfg.get("mutex"), cfg.get("mutex","").replace("\\","\\\\")],
 "d02_analysis_config_url":[cfg.get("url")],
 "d02_analysis_config_crc32_hex":["0x%08x"%crc_json,"0x%x"%crc_json],
 "d02_analysis_xor_key_hex":["0x%02x"%key,"0x%x"%key],
 "d03_artifact_sha256_1":[h(d03),h(rc)],
 "d03_artifact_sha256_2":[h(rc),h(d03)],
 "d03_analysis_format":["pe","PE","pe32"],
 "d03_analysis_machine":["i386","I386","x86","0x14c","0x014c","Intel 80386","IMAGE_FILE_MACHINE_I386","intel i386"],
 "d03_analysis_metadata_version":["v4.0.30319"],
 "d03_analysis_config_campaign":["BR03-000","none","day03","Huntress.Binary.Day03"],
 "d03_analysis_config_domain":["node-000.day03.example.invalid","none"],
 "d03_analysis_config_mutex":["Global\HuntressBR03_000","Global\\HuntressBR03_000","none"],
}
print("d02 cfg:",cfg)
print("d02 crc_json=0x%08x key=0x%02x"%(crc_json,key))
print("d01 secs(%d)=%s"%(len(secs),secs))
print("d01 custom=%s globdef=%s"%(custom,globdef))
print("d01 rc_att=%s rc_intel=%s"%(rc_att,rc_intel))
print("d03 mach=0x%04x"%mach)

st=S.post(GM,data=json.dumps({"op":"start","challenge":CID})).json()
ids=st.get("answer_ids")
locked={}
for fid in ids:
    cands=CAND.get(fid,[])
    done=False
    for c in cands:
        if c is None: continue
        r=S.post(GM,data=json.dumps({"op":"submit","challenge":CID,"answers":{fid:c}})).json()
        res=r.get("result"); rem=r.get("remaining")
        if res in ("accepted","CORRECT"):
            locked[fid]=c; print("OK   %-34s = %r  (remaining=%s)"%(fid,c,rem)); done=True; break
    if not done:
        print("FAIL %-34s  tried %d cands"%(fid,len(cands)))
# final full submit
r=S.post(GM,data=json.dumps({"op":"submit","challenge":CID,"answers":locked})).json()
print("FINAL:",json.dumps({k:r.get(k) for k in ("result","flag","remaining","error")}))
