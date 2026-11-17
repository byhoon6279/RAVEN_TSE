import gzip,json,collections,datetime
def load(path='work/verdicts.jsonl.gz'):
    R={}
    for l in gzip.open(path,'rt'):
        o=json.loads(l); R[(o['set'],o['fam'],o['seed'],o['op'])]=o
    return R
def day(ts): return datetime.datetime.utcfromtimestamp(ts).strftime('%Y-%m-%d') if ts else None
