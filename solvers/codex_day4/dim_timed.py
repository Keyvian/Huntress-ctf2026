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
ans={k:a[k] for k in st['answer_ids'] if k in a};r=d.S.post(d.D.U,json={'op':'submit','challenge':c,'answers':ans}).json()
for suffix,obj in [('start',st),('answers',ans),('result',r)]:d.P.joinpath('dim_'+mode+'_'+suffix+'.json').write_text(json.dumps(obj))
d.P.joinpath('dim_'+mode+'.zip').write_bytes(b)
print(len(ans),len(st['answer_ids']),'elapsed',time.monotonic()-t,{k:r.get(k) for k in ['result','remaining','error','flag']})
