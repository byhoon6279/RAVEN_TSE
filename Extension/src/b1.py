import pickle,collections,itertools,pandas as pd,numpy as np
R=pickle.load(open('work/R.pkl','rb'))
Mx=pd.read_csv('../Data/RQ3/rq3_av_perturbation_matrix_equal_eval.csv',index_col=0)
ENG=list(Mx.index)
OPS=['RC','IC','JOB','CS']; sname={'RC':'resource_change','IC':'instruction_change','JOB':'jmp_overlay_back','CS':'content_shifting'}
subsets=[frozenset(c) for r in range(1,5) for c in itertools.combinations(OPS,r)]
def key(S): return '_'.join(o for o in OPS if o in S)
seeds={}
for (s,f,seed,op),o in R.items():
    seeds.setdefault((f,seed),{})[(s,op)]=o
# rows: (fam, seed, engine) with og detected in BOTH scans and all 15 AE verdicts valid
rows=[]; drift=collections.Counter()
for (f,seed),d in seeds.items():
    g1=d.get(('single','ORIG')); g2=d.get(('multi','ORIG'))
    if not g1 or not g2: continue
    srcs={}
    ok=True
    for S in subsets:
        k=('single',sname[next(iter(S))]) if len(S)==1 else ('multi',key(S))
        if k not in d: ok=False;break
        srcs[S]=d[k]
    for e in ENG:
        a,b=g1['v'].get(e),g2['v'].get(e)
        if a in ('M','U') and b in ('M','U'): drift[(a,b)]+=1
        if not ok or a!='M' or b!='M': continue
        vs=[srcs[S]['v'].get(e) for S in subsets]
        if any(v not in ('M','U') for v in vs): continue
        rows.append((f,seed,e)+tuple(int(v=='U') for v in vs))
cols=['fam','seed','e']+[key(S) for S in subsets]
D=pd.DataFrame(rows,columns=cols); pickle.dump(D,open('work/B.pkl','wb'))
print('matched pairs U:',len(D),'seeds',D.seed.nunique(),'families',D.fam.nunique(),'engines',D.e.nunique())
print('original-verdict drift between scans (M/U only):',dict(drift),' M->U rate %.2f%%'%(100*drift[('M','U')]/(drift[('M','M')]+drift[('M','U')])),' U->M rate %.2f%%'%(100*drift[('U','M')]/(drift[('U','U')]+drift[('U','M')])))
