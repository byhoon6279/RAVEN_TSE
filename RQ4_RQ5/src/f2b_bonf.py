import pickle,numpy as np,pandas as pd
D=pickle.load(open('work/B.pkl','rb'))
fams=sorted(D.fam.unique()); fidx={f:i for i,f in enumerate(fams)}
rng=np.random.default_rng(2); B=20000
W=rng.multinomial(len(fams),np.ones(len(fams))/len(fams),size=B).astype(np.float32)
D=D[D.groupby('e').e.transform('size')>=500]
m=D.e.nunique(); a=0.05/m
rows=[]
for e,d in D.groupby('e'):
    fi=d.fam.map(fidx).values; n=np.bincount(fi,minlength=len(fams)).astype(np.float32)
    net=np.bincount(fi,weights=d['RC_IC_JOB_CS'].values-d['RC_IC_JOB'].values,minlength=len(fams)).astype(np.float32)
    bs=(W@net)/(W@n); est=net.sum()/n.sum()
    lo,hi=np.nanpercentile(bs,[100*a/2,100*(1-a/2)])
    rows.append(dict(engine=e,n=len(d),net_pp=100*est,bonf_lo=100*lo,bonf_hi=100*hi))
T=pd.DataFrame(rows).sort_values('net_pp')
T['class']=np.where(T.bonf_hi<0,'decline',np.where(T.bonf_lo>0,'increase','no clear change'))
T.to_csv('results/B_engine_primary_bonf.csv',index=False)
print('engines tested (n>=500):',m,'| Bonferroni two-sided alpha per engine = %.5f'%a)
print(T['class'].value_counts().to_dict())
print(T[T['class']=='decline'].round(1).to_string(index=False))
