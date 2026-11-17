# Load the compact verdict table (work/verdicts.jsonl.gz) into a dict keyed by (set, family, seed, op).
import os, sys, pickle
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from load import load
R = load(); pickle.dump(R, open('work/R.pkl', 'wb'))
print('reports', len(R))
