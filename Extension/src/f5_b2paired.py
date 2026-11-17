# Paired: same (seed, engine) set; reference = first-scan original label (same family, alias);
# baseline = rescanned original, variant = AE; both must be detected. family-cluster bootstrap CI of difference.
import pickle,re,numpy as np,pandas as pd
exec(open('src/f4_b2.py').read().split('# ---- (a)+(b)')[0])
fams_l=sorted({k[1] for k in R if k[0]=='single'}); fidx={f:i for i,f in enumerate(fams_l)}
rng=np.random.default_rng(3); B=5000
W=rng.multinomial(len(fams_l),np.ones(len(fams_l))/len(fams_l),size=B).astype(np.float32)
groups={}
for k,o in R.items():
    if k[0] in ('single','multi') and k[3]!='ORIG': groups.setdefault(nm(k[3]),[]).append(k)
rows=[]
for name,keys in groups.items():
    fb=np.zeros(len(fams_l)); fv=np.zeros(len(fams_l)); fn=np.zeros(len(fams_l))
    for (s,f,seed,op) in keys:
        ref=R[('single',f,seed,'ORIG')]; base=R.get(('multi',f,seed,'ORIG'))
        if base is None: continue
        ae=R[(s,f,seed,op)]; i=fidx[f]
        for e in ENG:
            if ref['v'].get(e)!='M' or cat(ref,e,f)!='same_family': continue
            if base['v'].get(e)!='M' or ae['v'].get(e)!='M': continue
            fn[i]+=1; fb[i]+= cat(base,e,f)!='same_family'; fv[i]+= cat(ae,e,f)!='same_family'
    n=fn.sum(); d=(W@(fv-fb))/(W@fn)
    rows.append(dict(variant=name,n_common=int(n),baseline_lost=int(fb.sum()),variant_lost=int(fv.sum()),baseline_pct=100*fb.sum()/n,variant_pct=100*fv.sum()/n,
                     diff_pp=100*(fv.sum()-fb.sum())/n,ci_lo=100*np.percentile(d,2.5),ci_hi=100*np.percentile(d,97.5)))
T=pd.DataFrame(rows).sort_values('diff_pp'); T.to_csv('results/B2_paired_vs_baseline.csv',index=False)
pd.set_option('display.width',250); print(T.round(2).to_string(index=False))
