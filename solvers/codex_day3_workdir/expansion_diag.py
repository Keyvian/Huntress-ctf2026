from expansion_fast import *
c='script-analysis-day-03-batch-expansion/time_trial'
for group in sys.argv[1:]:
 t=time.time();r=S.post(U,json={'op':'start','challenge':c}).json();b=S.get(U,params={'op':'artifact','challenge':c}).content;f=gather(b);a={k:v for k,v in answers(f).items() if k in r["answer_ids"]}
 if group=='known':a={k:v for k,v in a.items() if not (k.startswith('batch-') and k.endswith(('-control','-expansion')))}
 elif group=='jsplain':a={k:v for k,v in a.items() if k.startswith('jscript-') and not k.endswith('-style')}
 elif group=='batchplain':a={k:v for k,v in a.items() if k.startswith('batch-') and not k.endswith(('-control','-expansion'))}
 elif group=='batch':a={k:v for k,v in a.items() if k.startswith('batch-')}
 else:a={k:v for k,v in a.items() if k.startswith(group)}
 time.sleep(1.6)
 res=S.post(U,json={'op':'submit','challenge':c,'answers':a}).json();print(group,len(a),{k:res.get(k) for k in ['result','remaining','error','flag']},flush=True)
 (P/('diag_'+group+'.json')).write_text(json.dumps({'start':r,'answers':a,'result':res}));(P/('diag_'+group+'.artifact')).write_bytes(b)
 time.sleep(6)
