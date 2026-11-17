# Compact extractor: one JSON line per VT report (read-only on source).
import os,sys,json,gzip
from multiprocessing import Pool
CAT={'malicious':'M','suspicious':'S','undetected':'U','harmless':'H','timeout':'T','confirmed-timeout':'C','failure':'F','type-unsupported':'X'}
def job(args):
    tag,fam,path=args
    f=os.path.basename(path)[:-5]
    seed,op=(f.split('|',1)+['ORIG'])[:2] if '|' in f else (f,'ORIG')
    try:
        a=json.load(open(path,'rb'))['data']['attributes']
    except Exception as e:
        return json.dumps({'set':tag,'fam':fam,'seed':seed,'op':op,'err':str(e)[:100]})
    r=a.get('last_analysis_results',{})
    v={e:CAT.get(x.get('category'),'?') for e,x in r.items()}
    lab={e:x.get('result') for e,x in r.items() if x.get('result')}
    ver={e:x.get('engine_update') for e,x in r.items()}
    return json.dumps({'set':tag,'fam':fam,'seed':seed,'op':op,'sha':a.get('sha256'),'date':a.get('last_analysis_date'),
                       'first':a.get('first_submission_date'),'v':v,'lab':lab,'upd':ver},separators=(',',':'))
def tasks(tag,root):
    for fam in sorted(os.listdir(root)):
        fd=os.path.join(root,fam)
        if fam.startswith('.') or not os.path.isdir(fd): continue
        for f in os.listdir(fd):
            if f.endswith('.json') and not f.startswith('.'): yield (tag,fam,os.path.join(fd,f))
def flat(tag,root):
    for f in os.listdir(root):
        if f.endswith('.json') and not f.startswith('.'): yield (tag,'benign',os.path.join(root,f))
if __name__=='__main__':
    D=sys.argv[1]; out=sys.argv[2]
    T=list(tasks('single',D+'/RQ1_and_2/Original_malware_and_AE_report'))+list(tasks('multi',D+'/RQ3/RAVEN_report'))+list(flat('benign',D+'/RQ1_and_2/benign_report'))
    print('reports',len(T),flush=True)
    with gzip.open(out,'wt') as g, Pool(8) as p:
        for i,line in enumerate(p.imap_unordered(job,T,chunksize=64)):
            g.write(line+'\n')
            if i%10000==0: print(i,flush=True)
    print('done',flush=True)
