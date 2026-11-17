# Label context for PSC+IC+JOB -> PSC+IC+JOB+CS on the RQ4 common set (work/B.pkl, 268,824 pairs).
# loss pairs: PSC+IC+JOB AE undetected, PSC+IC+JOB+CS AE detected.
# both-detected pairs: both AEs detected. Labels are those of the PSC+IC+JOB+CS AE (June scan).
# orig: label of the June original-sample scan over the same common-set pairs.
import pickle,re,collections,pandas as pd
R=pickle.load(open('work/R.pkl','rb')); D=pickle.load(open('work/B.pkl','rb'))
def norm(l): return re.sub(r'[0-9A-F]{6,}|\d+','#',l or '')
ENGS=['Avira','F-Secure','McAfeeD','DeepInstinct']
out=[]
for e in ENGS:
    d=D[D.e==e]
    loss=collections.Counter(); keep=collections.Counter(); origc=collections.Counter(); nloss=nkeep=nog=0
    for f,seed,t,q in zip(d.fam,d.seed,d.RC_IC_JOB,d.RC_IC_JOB_CS):   # 1 = evaded (undetected)
        lab=norm(R[('multi',f,seed,'RC_IC_JOB_CS')]['lab'].get(e))
        nog+=1; origc[norm(R[('multi',f,seed,'ORIG')]['lab'].get(e))]+=1
        if t==1 and q==0: nloss+=1; loss[lab]+=1
        if t==0 and q==0: nkeep+=1; keep[lab]+=1
    for l,_ in loss.most_common(3):
        out.append(dict(engine=e,label=l,loss_pairs=f'{loss[l]}/{nloss}',loss_pct=100*loss[l]/nloss,
          both_detected=f'{keep[l]}/{nkeep}',both_detected_pct=100*keep[l]/max(nkeep,1),
          among_orig=f'{origc[l]}/{nog}',orig_pct=100*origc[l]/nog))
T=pd.DataFrame(out); T.to_csv('results/B_cs_label_evidence.csv',index=False)
pd.set_option('display.width',250); print(T.round(1).to_string(index=False))
