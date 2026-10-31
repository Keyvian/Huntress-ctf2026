import requests,json,pathlib,hashlib,struct,io,pyzipper,zlib,re,time
U='http://<homebase-ip>/huntress-ctf-proxy'
P=pathlib.Path.home()/'codex_day3'
def gather(b,prefix=''):
 if b[:2]==b'PK':
  z=pyzipper.AESZipFile(io.BytesIO(b));z.setpassword(b'infected');d={}
  for n in z.namelist():
   if not n.endswith('/'): d.update(gather(z.read(n),prefix+n+'/') if n.endswith('.zip') else {prefix+n:z.read(n)})
  return d
 return {prefix or 'artifact':b}
def config(b):
 pos=b.index(b'HCFG'); key=b[pos+5];size=int.from_bytes(b[pos+6:pos+8],'little');plain=bytes(x^key for x in b[pos+12:pos+12+size]);return json.loads(plain),key,zlib.crc32(plain)
def analyze(files):
 out={}
 for n,b in files.items():
  m=re.search(r'd0([123])',n)
  if not m:continue
  d='d0'+m[1]+'_';i='2' if n.endswith('.json') else '1';out[d+'artifact_sha256_'+i]=hashlib.sha256(b).hexdigest()
  if n.endswith('.json'):continue
  if b[:4]==b'\x7fELF':
   out[d+'analysis_elf_class']='ELF64';out[d+'analysis_machine']='x86-64';out[d+'analysis_elf_type']='ET_EXEC';out[d+'analysis_endianness']='little';out[d+'analysis_format']='ELF'
  if b[:2]==b'MZ' and b'BSJB' in b:
   out[d+'analysis_format']='PE32';out[d+'analysis_machine']='x86';pos=b.index(b'BSJB');length=int.from_bytes(b[pos+12:pos+16],'little');out[d+'analysis_metadata_version']=b[pos+16:pos+16+length].rstrip(b'\x00').decode()
  if b'HCFG' in b:
   cfg,key,crc=config(b)
   for k,v in cfg.items():out[d+'analysis_config_'+k]=str(v)
   out[d+'analysis_config_crc32_hex']=f'0x{crc:08x}';out[d+'analysis_xor_key_hex']=f'0x{key:02x}'
 return out
if __name__=='__main__':
 r=json.loads((P/'table_start.json').read_text());a=analyze(gather((P/'table.artifact').read_bytes()));a={k:v for k,v in a.items() if k in r['answer_ids']};(P/'table_answers.json').write_text(json.dumps(a));print(json.dumps(a,indent=2))
 print(requests.post(U,json={'op':'submit','challenge':'binary-reverse-engineering-day-03-managed-configuration','answers':a}).text)
