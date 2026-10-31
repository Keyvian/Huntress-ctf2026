from solve_expansion import *
from solve_table import gather,U,P
import requests,hashlib
S=requests.Session()
EXP={'benign':'for_indirect','stager':'delayed','dropper':'delayed','downloader':'delayed','uploader':'delayed','launcher':'call_double','impact':'delayed','chain':'delayed','relay':'delayed'}
CTRL={'benign':'errorlevel_guard','stager':'direct','dropper':'goto_dispatch','downloader':'direct','uploader':'call_subroutine','launcher':'if_guard','impact':'direct','chain':'errorlevel_guard','relay':'if_guard'}
def answers(files):
 a,plans=analyze(files)
 # Extract syntax and control forms from each current specimen.
 return a

def run(mode):
 c='script-analysis-day-03-batch-expansion'+('/'+mode if mode!='single_solve' else '')
 for attempt in range(3):
  t=time.time();r=S.post(U,json={'op':'retry' if attempt else 'start','challenge':c}).json();(P/('expansion_'+mode+'_start.json')).write_text(json.dumps(r))
  if 'answer_ids' not in r:print('start',r);return
  b=S.get(U,params={'op':'artifact','challenge':c}).content;(P/('expansion_'+mode+'.artifact')).write_bytes(b);files=gather(b);sets=sorted({int(re.match(r'set(\d+)\.',x)[1]) for x in r['answer_ids'] if re.match(r'set(\d+)\.',x)});allanswers={}
  if sets:
   prefixes=sorted({n.rsplit('/',1)[0] for n in files if '/' in n})
   for i,setnum in enumerate(sets):
    subset={n:v for n,v in files.items() if re.search(r'(?:set[-_]?'+str(setnum)+r')(?:\D|$)',n)}
    if not subset and len(prefixes)==len(sets):subset={n:v for n,v in files.items() if n.startswith(prefixes[i]+'/')}
    if not subset:
     bb=S.get(U,params={'op':'artifact','challenge':c,'delivery':setnum-1}).content;subset=gather(bb)
    for k,v in answers(subset).items():allanswers[f'set{setnum}.'+k]=v
  else:allanswers=answers(files)
  a={k:allanswers[k] for k in r['answer_ids'] if k in allanswers};(P/('expansion_'+mode+'_answers.json')).write_text(json.dumps(a));print(mode,'computed',len(a),'of',len(r['answer_ids']),'elapsed',round(time.time()-t,2),flush=True)
  result=S.post(U,json={'op':'submit','challenge':c,'answers':a}).json();(P/('expansion_'+mode+'_submit.json')).write_text(json.dumps(result));print({k:result[k] for k in ['result','remaining','error','flag','status'] if k in result},'elapsed',round(time.time()-t,2),flush=True)
  if result.get('result')=='CORRECT':return
  if result.get('result')=='incorrect':print('files',list(files));return
  time.sleep(2)
if __name__=='__main__':run(sys.argv[1])
