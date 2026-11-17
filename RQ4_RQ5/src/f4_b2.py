# B-2 finalize: (a) old vs new targets, (b) full categories w/ raw counts, (c) paired common-set vs baseline with family CI
import pickle,re,collections,numpy as np,pandas as pd
R=pickle.load(open('work/R.pkl','rb'))
H=pd.read_csv('../Data/RQ1_and_2/heatmap.csv',index_col=0); ENG=list(H.index)
al={}
for l in open('avclass_data/default.tagging'):
    p=l.rstrip('\n').split('\t')
    if len(p)==2: al[p[0].lower()]=p[1].lower()
def canon(t):
    for _ in range(10):
        if t not in al: break
        t=al[t]
    return t
FAM=set(); GENT=set()
for l in open('avclass_data/default.taxonomy'):
    c,_,v=l.strip().partition(':')
    if c=='FAM': FAM.add(v.split(':')[-1].lower())
    if c=='GEN': GENT.add(v.split(':')[-1].lower())
MYGEN=set('gen generic malicious malware confidence score suspicious unsafe static heur heuristic behaveslike aidetectmalware generickd generickdz genetic genasa highconfidence attribute susgen malwarex mal real protect ml dds classic variant agen eldorado ai'.split())
GEN=GENT|MYGEN
fams=sorted({k[1] for k in R if k[0]=='single'}); FAM|=set(fams)
def toks(l): return [t for t in re.split(r'[^a-z0-9]+',(l or '').lower()) if len(t)>=3]
def cat(rep,e,f,alias=True):
    v=rep['v'].get(e)
    if v not in ('M','U'): return 'missing'
    if v=='U': return 'undetected'
    t=toks(rep['lab'].get(e))
    if alias:
        c=[canon(x) for x in t]
        if f in c: return 'same_family'
        if any(x in FAM for x in c): return 'other_family'
    else:
        if f in t: return 'same_family'
    if any(x in GEN for x in t) or any(canon(x) in GEN for x in t): return 'generic'
    return 'unclassified'
ab={"modify_dos_header":"MDH","extend_dos_stub":"EDS","coff_header":"CH","rich_header":"RH","optional_header":"OH","section_rename":"SRN","section_add":"SAD","section_append":"SAP","content_shifting":"CS","jmp_overlay_back":"JOB","overlay_append":"OAP","instruction_change":"IC","resource_change":"PSC","section_increase":"SIN"}
def nm(op): return ab.get(op,op.replace('RC','PSC').replace('_','+'))
CATS=['same_family','other_family','generic','unclassified','undetected','missing']
# ---- (a)+(b): per-op category counts over targets (og detected & og same_family under alias), split old/new
# Reference = first original-sample scan (RQ1_and_2) for every variant, as in f5_b2paired.py and the paper's RQ5.
cnt=collections.defaultdict(collections.Counter); corr=collections.defaultdict(collections.Counter)
items=[(k,o) for k,o in R.items() if k[0] in('single','multi') and k[3]!='ORIG']
items+=[(('single',k[1],k[2],'BASELINE'),R[('multi',k[1],k[2],'ORIG')]) for k in R if k[0]=='single' and k[3]=='ORIG' and ('multi',k[1],k[2],'ORIG') in R]
for (s,f,seed,op),o in items:
    g=R.get(('single',f,seed,'ORIG'))
    if g is None: continue
    name='(baseline) original rescan' if op=='BASELINE' else nm(op)
    for e in ENG:
        if g['v'].get(e)!='M': continue
        ca=cat(g,e,f,True)
        if ca!='same_family': continue
        old=cat(g,e,f,False)=='same_family'
        a=cat(o,e,f,True); cnt[(name,'old' if old else 'new')][a]+=1
        if old: corr[name][(cat(o,e,f,False),a)]+=1
rows=[]
for (name,grp),c in cnt.items():
    n=sum(c.values()); ret=c['same_family']+c['other_family']+c['generic']+c['unclassified']
    rows.append(dict(variant=name,targets=grp,n=n,**{k:c[k] for k in CATS},lost_among_retained_pct=100*(ret-c['same_family'])/ret if ret else np.nan))
A=pd.DataFrame(rows)
tot=A.groupby('variant')[['n']+CATS].sum().reset_index(); tot['targets']='all'
ret=tot[['same_family','other_family','generic','unclassified']].sum(1); tot['lost_among_retained_pct']=100*(ret-tot.same_family)/ret
A=pd.concat([A,tot]).sort_values(['variant','targets']); A.to_csv('results/B2_categories_counts.csv',index=False)
# correction effect on old targets: lost (no-alias rule) vs lost (alias rule)
crow=[]
for name,c in corr.items():
    ret_old=sum(v for (o,a),v in c.items() if o not in('undetected','missing'))
    lost_noalias=sum(v for (o,a),v in c.items() if o not in('undetected','missing','same_family'))
    lost_alias=sum(v for (o,a),v in c.items() if a not in('undetected','missing','same_family'))
    crow.append(dict(variant=name,old_retained=ret_old,lost_noalias_pct=100*lost_noalias/ret_old,lost_alias_pct=100*lost_alias/ret_old))
C=pd.DataFrame(crow).set_index('variant')
T=A.pivot(index='variant',columns='targets',values='lost_among_retained_pct')
C['new_targets_lost_pct']=T['new']; C['all_targets_alias_pct']=T['all']
C['n_old']=A[A.targets=='old'].set_index('variant').n; C['n_new']=A[A.targets=='new'].set_index('variant').n
C=C.sort_values('all_targets_alias_pct'); C.to_csv('results/B2_old_vs_new.csv'); pd.set_option('display.width',250)
print('=== (a) old vs new targets (lost among retained, %)'); print(C.round(1).to_string())
print('\n=== (b) categories, all targets (raw counts) — selected'); 
sel=['(baseline) original rescan','RH','MDH','PSC','IC','PSC+IC+JOB','PSC+IC+JOB+CS']
print(A[(A.targets=='all')&(A.variant.isin(sel))].set_index('variant').loc[sel,['n']+CATS+['lost_among_retained_pct']].round(1).to_string())
pickle.dump((FAM,GEN,al),open('work/b2_dicts.pkl','wb'))
