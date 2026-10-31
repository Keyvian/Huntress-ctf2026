import base64, json, pathlib, re, subprocess, sys, time
import requests
from solve_table import gather, U, P

NAMES = {'host-context':'benign','memory-stage':'stager','embedded-write':'dropper','remote-write':'downloader','outbound-transfer':'uploader','local-dispatch':'launcher','impact-plan':'impact','staged-handoff':'chain','relay-handoff':'relay'}
TECH = {'benign':'none','stager':'T1105','dropper':'T1027','downloader':'T1105','uploader':'T1041','launcher':'T1059.003','impact':'T1486','chain':'T1105','relay':'T1105'}
def js_decode(s):
    # Run only the inert descriptor reconstruction in an isolated Node context.
    m = re.search(r'(?:function\s+(inspect_\w+)\s*\(|var\s+(inspect_\w+)\s*=)',s)
    f = next(x for x in m.groups() if x)
    code = "const vm=require('vm');let c=vm.createContext({});vm.runInContext("+json.dumps(s)+",c,{timeout:500});console.log(JSON.stringify(vm.runInContext('"+f+"()',c,{timeout:500})));"
    return json.loads(subprocess.check_output(['node','-e',code],text=True,timeout=3))
def batch_decode(s):
    vals={}
    for line in s.splitlines():
        m=re.match(r'\s*set\s+"?([A-Za-z_][A-Za-z_0-9]*[0-3])=(.*)',line,re.I)
        if m:
            v=m[2]
            if line.strip().lower().startswith('set "'):v=v.split('"',1)[0]
            vals[m[1].lower()]=v.replace('^|','|')
    assert len(vals)==4, vals
    text=''.join(v for k,v in sorted(vals.items(),key=lambda x:int(x[0][-1])))
    cfg=dict(x.split('=',1) for x in text.split('|'))
    region=s.split(':HUNTRESS_INSPECT',2)[-1]
    if re.search(r'for %%\w .*do call set',region,re.I):exp='for_indirect'
    elif re.search(r'(?m)^call set \"(?:cfg|recovered_configuration|item9|recovered)=[^\n]*%%',region):exp='call_double'
    elif re.search(r'(?im)^.*set .*=[^\n]*!\w+!',region):exp='delayed'
    else:exp='delayed'
    if 'call :HUNTRESS_RECOVER' in region:ctrl='call_subroutine'
    elif 'if defined HUNTRESS_READY' in region:ctrl='if_guard'
    elif 'goto :HUNTRESS_DISPATCH' in region:ctrl='goto_dispatch'
    elif 'if errorlevel' in region:ctrl='errorlevel_guard'
    else:ctrl='direct'
    return cfg,exp,ctrl
def analyze(files):
    a={};plans={}
    for name,b in files.items():
        base=pathlib.PurePosixPath(name).name;stem=base.rsplit('.',1)[0];s=b.decode('utf-8-sig')
        if base.endswith('.ps1'):
            role=stem.split('-')[0];raw=base64.b64decode(re.search(r"FromBase64String\('([^']+)'\)",s)[1])
            # Decode the transformation actually expressed in the specimen.
            if 'bxor' in s:
                km=re.search(r'-bxor\s+(0x[0-9a-fA-F]+|\d+)',s)
                assert km, 'unrecognized PowerShell XOR'
                raw=bytes(v^int(km[1],0) for v in raw)
            if '[Array]::Reverse' in s:raw=raw[::-1]
            d=json.loads(raw);plans[name]=d
            if role=='resource':v={'scenario':'resource_hijacking','attack':'T1496','url':d['b'],'wallet':d['c'],'mutex':d['h']}
            elif role=='collection':v={'scenario':'synthetic_collection','attack':'T1555.003','url':d['b'],'file':d['c'][0],'user-agent':d['f']}
            else:v={'scenario':'synthetic_impact','attack':'T1486','extension':d['b'],'note':d['c'],'url':d['d']}
            a.update({role+'-'+k:str(x) for k,x in v.items()});continue
        role=NAMES.get(stem)
        if not role:continue
        lang='jscript' if base.endswith('.js') else 'batch';prefix=lang+'-'+role+'-'
        if lang=='jscript':
            d=js_decode(s);plans[name]=d;values=d['values'];adapter=d['adapter']
            im=re.search(r'(?:function\s+(inspect_\w+)\s*\(|var\s+(inspect_\w+)\s*=)',s); inspect=s[im.start():]
            if re.match(r'function\s+inspect_',inspect):fun='declaration'
            elif re.search(r'=\s*function\s+\w+\(',inspect):fun='named_expression'
            else:fun='anonymous_expression'
            invoke='apply' if re.search(r'recover_\w+\.apply',inspect) else 'call' if re.search(r'recover_\w+\.call',inspect) else 'direct'
            dot=bool(re.search(r'\w+\.(?:steps|adapter|values|stageCount)',inspect));bracket=bool(re.search(r'\["(?:steps|adapter|values|stageCount)"\]',inspect))
            prop='mixed' if dot and bracket else 'bracket_literal' if bracket else 'dot'
            a.update({prefix+'function-style':fun,prefix+'invocation-style':invoke,prefix+'property-style':prop})
        else:
            d,exp,ctrl=batch_decode(s);plans[name]=d;values=d;adapter=d['adapter']
            a.update({prefix+'expansion':exp,prefix+'control':ctrl,prefix+'graph':d['graph']})
        a[prefix+'role']='benign_utility' if role=='benign' else 'staged_chain' if role=='chain' else 'staged_chain' if role=='relay' else role
        a[prefix+'attack']=('T1140' if role=='dropper' else ('T1059.007' if lang=='jscript' else 'T1059.003') if role in ['launcher','chain','relay'] else TECH[role]);a[prefix+'adapter']=adapter
        for k,v in values.items():
            field={'campaign_id':'campaign','host_id':'host-id' if lang=='batch' else 'host','file_path':'file-path' if lang=='batch' else 'path','note_name':'note-name' if lang=='batch' else 'note'}.get(k,k.replace('_','-'))
            a[prefix+field]=str(v)
    return a,plans
if __name__=='__main__':
    r=json.loads((P/'expansion_start.json').read_text());a,plans=analyze(gather((P/'expansion.artifact').read_bytes()));a={k:v for k,v in a.items() if k in r['answer_ids']}
    (P/'expansion_answers.json').write_text(json.dumps(a));(P/'expansion_plans.json').write_text(json.dumps(plans,indent=2))
    print('computed',len(a),'missing',set(r['answer_ids'])-set(a))
    for n,d in plans.items():print(n,json.dumps(d))
