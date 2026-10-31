import dim_solve as d,json,time,sys
mode=sys.argv[1];c=d.C+'/'+mode;t=time.monotonic();st=d.S.post(d.D.U,json={'op':'start','challenge':c}).json()
if 'answer_ids' not in st:print(st.get('error'),st.get('result'));quit()
b=d.S.get(d.D.U,params={'op':'artifact','challenge':c}).content
if b[:2]!=b'PK':print('download',b[:80]);quit()
d.P.joinpath('dim_'+mode+'.zip').write_bytes(b);d.P.joinpath('dim_'+mode+'_start.json').write_text(json.dumps(st))
f=d.D.gather(b);sets={}
for k,v in f.items():
 p=k.split('/')[0] if '/' in k else '';sets.setdefault(p,{})[k]=v
if mode=='mastery' and len(sets)<2:
 bb=d.S.get(d.D.U,params={'op':'artifact','challenge':c,'delivery':1}).content
 d.P.joinpath('dim_mastery_delivery1.zip').write_bytes(bb)
 sets={'set1':f,'set2':d.D.gather(bb)}
# Use gather groups only if mastery returns prefixes. Analyze accepts dictionaries via a temporary gather override.
a={};orig=d.D.gather
for index,(group,files) in enumerate(sorted(sets.items()),1):
 d.D.gather=lambda _,files=files:files
 z=d.analyze(b)
 for k,v in z.items():a[(f'set{index}.' if mode=='mastery' else '')+k]=v
# no directories: default keys
if not any(k in a for k in st['answer_ids']):
 d.D.gather=orig;a=d.analyze(b)
d.D.gather=orig
ans={k:a[k] for k in st['answer_ids'] if k in a}
for prefix in ['set1.','set2.']:
 r=d.S.post(d.D.U,json={'op':'submit','challenge':c,'answers':{k:v for k,v in ans.items() if k.startswith(prefix)}}).json();print(prefix,{k:r.get(k) for k in ['result','remaining','error','flag']})
 time.sleep(1.6)
d.P.joinpath('dim_mastery_diag_answers.json').write_text(json.dumps(ans))
