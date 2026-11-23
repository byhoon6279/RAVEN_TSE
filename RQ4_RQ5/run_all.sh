#!/usr/bin/env bash
# Reproduce the TSE extension analyses (RQ4 strategy effects and family-label loss).
# Run from this directory (RQ4_RQ5/). Raw VT reports are read from ../Data (read-only).
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p work results figures
python3 src/extract.py ../Data work/verdicts.jsonl.gz   # 1. compact verdict table (one line per VT report)
python3 src/build_R.py                                  # 2. load table -> work/R.pkl
python3 src/b1.py                                       # 3. common set of seed-engine pairs (15 subsets) -> work/B.pkl
python3 src/f1_paired.py                                # 4. paired gain/loss for 28 one-perturbation transitions
python3 src/f2_engines.py                               # 5. (supplementary) per-engine transitions, uncorrected
python3 src/f2b_bonf.py                                 # 6. per-engine PSC+IC+JOB -> +CS, Bonferroni (70 engines)
python3 src/f3_cslabels.py                              # 7. label context for CS-added losses
python3 src/f4_b2.py                                    # 8. family-label loss (AVClass2 aliases), categories
python3 src/f5_b2paired.py                              # 9. family-label loss, paired vs. original rescan (+ mismatch types)
python3 src/f6_mismatch_types.py                         # 9b. supplementary table: mismatch types in the Table VIII set
python3 src/g1_figs.py work/B.pkl results figures       # 10. figures (vector PDF, TrueType fonts)
