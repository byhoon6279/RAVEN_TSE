# B-1: one-variant-vs-one-variant transitions S -> S+{op}; raw counts + family-cluster bootstrap CI
import pickle,itertools,numpy as np,pandas as pd
D=pickle.load(open('work/B.pkl','rb'))
OPS=['RC','IC','JOB','CS']; NM={'RC':'PSC'}
def key(S): return '_'.join(o for o in OPS if o in S)
def lab(S): return '+'.join(NM.get(o,o) for o in OPS if o in S)
fams=np.array(sorted(D.fam.unique())); fi=D.fam.map({f:i for i,f in enumerate(fams)}).values
rng=np.random.default_rng(0); B=2000
W=rng.multinomial(len(fams),np.ones(len(fams))/len(fams),size=B)  # bootstrap family weights
def ci(num_f,den_f):
    est=num_f.sum()/den_f.sum(); bs=(W@num_f)/(W@den_f); return est,np.percentile(bs,2.5),np.percentile(bs,97.5)
rows=[]
for r in (1,2,3):
    for S in itertools.combinations(OPS,r):
        for o in OPS:
            if o in S: continue
            S_=frozenset(S); T=S_|{o}
            s=D[key(S_)].values.astype(bool); t=D[key(T)].values.astype(bool)
            n=np.bincount(fi,minlength=len(fams)).astype(float)
            loss=np.bincount(fi,weights=(s&~t),minlength=len(fams)); gain=np.bincount(fi,weights=(~s&t),minlength=len(fams))
            l=ci(loss,n); g=ci(gain,n); nt=ci(gain-loss,n)
            rows.append(dict(S=lab(S_),added=NM.get(o,o),same_month=r>=2,n=int(n.sum()),S_evade=int(s.sum()),T_evade=int(t.sum()),
              loss=int(loss.sum()),gain=int(gain.sum()),loss_pct=100*l[0],gain_pct=100*g[0],net_pct=100*nt[0],net_lo=100*nt[1],net_hi=100*nt[2]))
T=pd.DataFrame(rows); T.to_csv('results/B_paired_transitions.csv',index=False)
pd.set_option('display.width',250); print(T.round(2).to_string(index=False))
print('\nJune-only (S>=2): transitions with net CI entirely <0:',int(((T.same_month)&(T.net_hi<0)).sum()),'of',int(T.same_month.sum()))
print('by added operator (June-only) mean net pp:',T[T.same_month].groupby('added').net_pct.mean().round(2).to_dict())
