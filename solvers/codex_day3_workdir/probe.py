import requests,time,json,pathlib
from solve_table import U,P
C='binary-reverse-engineering-day-03-managed-configuration'
def submit(a,c=C):
 time.sleep(1.6);r=requests.post(U,json={'op':'submit','challenge':c,'answers':a}).json();print((list(a) if len(a)<4 else str(len(a))+' fields'),{k:r[k] for k in ['result','remaining','error','flag','status'] if k in r},flush=True);return r
if __name__=='__main__':
 a=json.loads((P/'table_answers.json').read_text());good={}
 def bank(a):
  r=submit(a)
  if r.get('result') in ['accepted','CORRECT']:good.update(a)
  elif len(a)>1:
   pairs=list(a.items());n=len(pairs)//2;bank(dict(pairs[:n]));bank(dict(pairs[n:]))
 bank(a);(P/'table_confirmed.json').write_text(json.dumps(good))
