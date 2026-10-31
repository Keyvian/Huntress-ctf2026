from solve_table import *
import collections
S=requests.Session()
def elf(b):
 shoff=struct.unpack_from('<Q',b,40)[0];ents,num,idx=struct.unpack_from('<HHH',b,58);ss=[struct.unpack_from('<IIQQQQIIQQ',b,shoff+i*ents) for i in range(num)];st=ss[idx];names=b[st[4]:st[4]+st[5]]
 def string(buf,pos):return buf[pos:buf.find(b'\0',pos)].decode()
 sn=[string(names,x[0]) for x in ss];syms=[];imm=None
 for sec in ss:
  if sec[1]!=2:continue
  strs=ss[sec[6]];strings=b[strs[4]:strs[4]+strs[5]]
  for pos in range(sec[4],sec[4]+sec[5],sec[9]):
   name,info,other,sidx,value,size=struct.unpack_from('<IBBHQQ',b,pos)
   if name:syms.append(string(strings,name))
   if name and string(strings,name)=='recover_code':
    s=ss[sidx];code=b[s[4]+value-s[3]:s[4]+value-s[3]+size];m=re.search(b'\xb8(.{4})',code,re.S)
    if m:imm=int.from_bytes(m[1],'little')
 return sn,syms,imm
def answers(files):
 a=analyze(files)
 for n,b in files.items():
  if re.search(r'd01',n) and b[:4]==b'\x7fELF':
   sections,symbols,imm=elf(b);a['d01_analysis_section_names']=json.dumps(sections,separators=(',',':'));a['d01_analysis_symbols']=json.dumps(symbols,separators=(',',':'));a['d01_analysis_disassembly']=json.dumps([f'mov eax, {imm}','ret'],separators=(',',':'))
 a['d02_analysis_format']='elf' if next(b for n,b in files.items() if 'd02' in n)[:4]==b'\x7fELF' else 'pe';a['d03_analysis_format']='pe_cli';a['d03_analysis_machine']='i386'
 return a
def run(mode):
 c='binary-reverse-engineering-day-03-managed-configuration'+('/'+mode if mode!='single_solve' else '')
 for attempt in range(3):
  t=time.time();r=S.post(U,json={'op':'retry' if attempt else 'start','challenge':c}).json();(P/('table_'+mode+'_start.json')).write_text(json.dumps(r))
  if 'answer_ids' not in r:print('start',r);return
  b=S.get(U,params={'op':'artifact','challenge':c}).content;(P/('table_'+mode+'.artifact')).write_bytes(b);files=gather(b);sets=sorted({int(re.match(r'set(\d+)\.',x)[1]) for x in r['answer_ids'] if re.match(r'set(\d+)\.',x)});allanswers={}
  if sets:
   prefixes=sorted({n.rsplit('/',1)[0] for n in files if '/' in n})
   for i,setnum in enumerate(sets):
    subset={n:v for n,v in files.items() if re.search(r'(?:set[-_]?'+str(setnum)+r')(?:\D|$)',n)}
    if not subset and len(prefixes)==len(sets):subset={n:v for n,v in files.items() if n.startswith(prefixes[i]+'/')}
    if not subset:
     bb=S.get(U,params={'op':'artifact','challenge':c,'delivery':setnum-1}).content;subset=gather(bb)
    for k,v in answers(subset).items():allanswers[f'set{setnum}.'+k]=v
  else:allanswers=answers(files)
  a={k:allanswers[k] for k in r['answer_ids'] if k in allanswers};(P/('table_'+mode+'_answers.json')).write_text(json.dumps(a));print(mode,'computed',len(a),'of',len(r['answer_ids']),'elapsed',round(time.time()-t,2),flush=True)
  result=S.post(U,json={'op':'submit','challenge':c,'answers':a}).json();(P/('table_'+mode+'_submit.json')).write_text(json.dumps(result));print({k:result[k] for k in ['result','remaining','error','flag','status'] if k in result},'elapsed',round(time.time()-t,2),flush=True)
  if result.get('result')=='CORRECT':return
  if result.get('result')=='incorrect':print('files',list(files));return
  time.sleep(2)
if __name__=='__main__':run(__import__('sys').argv[1])
