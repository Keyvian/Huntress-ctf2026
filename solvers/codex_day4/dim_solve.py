import sys,json,pathlib,re,time,requests
sys.path.insert(0,'/home/HuntressCTF/codex_day4_script')
import solve_d4 as D
P=pathlib.Path('/home/HuntressCTF/codex_day4');C=D.C;S=requests.Session()
import base64
old_parse=D.parse_ints
def parse(rep,mat):
 if rep.startswith('base64'):return list(base64.b64decode(mat))
 return old_parse(rep,mat)
D.parse_ints=parse
def vbs_plan(s):
 mat=re.search(r'Material_\w+\s*=\s*"([^"]*)"',s)[1]
 rep,xf,param=re.search(r'Codec_\w+\s*=\s*"([^"]*)"',s)[1].split('|')
 if rep.startswith('base64'):arr=list(base64.b64decode(mat))
 elif 'hex' in rep:arr=list(bytes.fromhex(re.sub(r'[:\-\s]','',mat)))
 else:arr=[int(x) for x in re.split(r'[|,\-\s]+',mat) if x]
 if rep.startswith('reversed'):arr=arr[::-1]
 keys=[int(x,16) for x in param.split(',')] if param else []
 if xf=='subtract_modulo_256':arr=[(n+keys[0])%256 for n in arr]
 elif xf=='add_modulo_256':arr=[(n-keys[0])%256 for n in arr]
 elif xf=='single_byte_xor':arr=[n^keys[0] for n in arr]
 elif xf=='repeating_key_xor':arr=[n^keys[i%len(keys)] for i,n in enumerate(arr)]
 elif xf=='rolling_xor':arr=[n^(keys[0] if i==0 else arr[i-1]) for i,n in enumerate(arr)]
 elif xf=='reverse_bytes':arr=arr[::-1]
 elif xf=='reverse_then_xor':arr=[n^keys[0] for n in arr[::-1]]
 elif xf!='identity':raise ValueError(xf)
 text=bytes(arr).decode();assert text.startswith('v=1|'),(rep,xf,text[:30])
 return dict(x.split('=',1) for x in text.split('|') if '=' in x),rep,xf
D.vbs_plan=vbs_plan
def batch(s):
 cfg,exp,ctrl=D.batch_decode_fixed(s)
 region=s.split(':HUNTRESS_INSPECT',2)[-1]
 exp='call_double' if '%%h' in region else 'for_indirect' if re.search(r'for %%\w .*do call set',region,re.I) else 'delayed'
 return cfg,exp,ctrl
D.SE.batch_decode=batch
def analyze(b):
 f=D.gather(b);a,_=D.SE.analyze({k:v for k,v in f.items() if not k.endswith('.vbs')});a.update(D.analyze_vbs(f))
 attacks={'stager':'T1105','downloader':'T1105','uploader':'T1041'}
 for n,b in f.items():
  if not n.endswith('.vbs'):continue
  role=D.NAMES[pathlib.PurePosixPath(n).stem];s=b.decode();r=s[s.index('Function Recover_'):];p='vbscript-'+role+'-'
  a[p+'attack']=attacks.get(role,a[p+'attack'])
  a[p+'control']='select_case' if re.search('Select Case',r,re.I) else 'while_once' if re.search(r'\bWhile\b',r,re.I) else 'do_once' if re.search(r'\bExit Do\b',r,re.I) else 'for_once' if re.search(r'For \w+ = 0 To 0',r,re.I) else 'error_guard' if 'On Error Resume Next' in r else 'direct'
 return a
if __name__=='__main__':
 a=analyze(P.joinpath('dim.zip').read_bytes());ids=json.loads(P.joinpath('dim_start.json').read_text())['answer_ids'];a={k:a[k] for k in ids};P.joinpath('dim_answers.json').write_text(json.dumps(a));held={k:v for k,v in a.items() if k.startswith('vbscript') and k.endswith('control')};base={k:v for k,v in a.items() if k not in held};r=S.post(D.U,json={'op':'submit','challenge':C,'answers':base}).json();print({k:v for k,v in r.items() if k not in ['questions','guidance']});P.joinpath('dim_base_result.json').write_text(json.dumps(r));print('held',held)
