# B-2(engine typing): prespecified rule on June-only add-one transitions, per engine, family-cluster bootstrap
import pickle,itertools,numpy as np,pandas as pd
D=pickle.load(open('work/B.pkl','rb'))
OPS=['RC','IC','JOB','CS']; NM={'RC':'PSC'}
def key(S): return '_'.join(o for o in OPS if o in S)
fams=sorted(D.fam.unique()); fidx={f:i for i,f in enumerate(fams)}
rng=np.random.default_rng(1); B=1000
W=rng.multinomial(len(fams),np.ones(len(fams))/len(fams),size=B)
trans=[(frozenset(S),o) for r in (2,3) for S in itertools.combinations(OPS,r) for o in OPS if o not in S]  # 16 June-only
rows=[]
for e,d in D.groupby('e'):
    fi=d.fam.map(fidx).values; n=np.bincount(fi,minlength=len(fams)).astype(float)
    res={}
    for S,o in trans:
        s=d[key(S)].values.astype(bool); t=d[key(S|{o})].values.astype(bool)
        net=np.bincount(fi,weights=t.astype(float)-s,minlength=len(fams))
        est=net.sum()/n.sum(); bs=(W@net)/(W@n); lo,hi=np.percentile(bs,[2.5,97.5])
        res[(S,o)]=(est,lo,hi)
    prim=res[(frozenset(['RC','IC','JOB']),'CS')]
    dec=[k for k,v in res.items() if v[2]<0]
    rows.append(dict(engine=e,n=len(d),primary_net_pp=100*prim[0],primary_lo=100*prim[1],primary_hi=100*prim[2],
        n_sig_decline=len(dec),n_sig_decline_addCS=sum(1 for S,o in dec if o=='CS'),n_sig_increase=sum(1 for v in res.values() if v[1]>0)))
T=pd.DataFrame(rows)
T['type']=np.where(T.n_sig_decline>0,'non-monotone (>=1 significant decline)','no significant decline')
T=T.sort_values('primary_net_pp'); T.to_csv('results/B_engine_types.csv',index=False)
print(T.round(1).to_string(index=False))
print('\nengines:',len(T),'| with >=1 significant decline:',int((T.n_sig_decline>0).sum()),'| of which all declines involve adding CS:',int(((T.n_sig_decline>0)&(T.n_sig_decline==T.n_sig_decline_addCS)).sum()))
print('primary rule (PSC+IC+JOB -> +CS): significant decline',int((T.primary_hi<0).sum()),'| significant increase',int((T.primary_lo>0).sum()),'| neither',int(((T.primary_hi>=0)&(T.primary_lo<=0)).sum()))
