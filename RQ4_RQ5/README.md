# RAVEN TSE RQ4 and RQ5 Analyses

This directory contains the analysis code, result tables, and figures added for the TSE extension of RAVEN.
All analyses reuse the VirusTotal reports already released under `../Data`; no new scans were performed.

- **RQ4 (strategy effects):** paired evasion gains and losses when one perturbation is added to a strategy, and engine-level ASR changes.
- **RQ5 (family-label retention):** whether AEs that remain detected still carry the ground-truth family name in engine labels.

## Requirements

Python 3.10+ with `numpy`, `pandas`, and `matplotlib`.

## Reproduce

```bash
cd RQ4_RQ5
./run_all.sh
```

The script reads `../Data` (read-only), writes intermediate files to `work/` (git-ignored), result tables to `results/`, and figures to `figures/`.
Bootstrap seeds are fixed, so the outputs are deterministic.

## Inputs (from `../Data`)

| Input | Use |
|---|---|
| `RQ1_and_2/Original_malware_and_AE_report/<family>/<seed>.json` | Originals, first scan (Apr–May 2025) |
| `RQ1_and_2/Original_malware_and_AE_report/<family>/<seed>\|<op>.json` | Single-perturbation AEs (PSC = `resource_change`, IC, JOB, CS) |
| `RQ3/RAVEN_report/<family>/<seed>.json` | Originals, rescan (June 2025) |
| `RQ3/RAVEN_report/<family>/<seed>\|RC_IC.json`, … | 11 multi-perturbation AEs (June 2025; `RC` = PSC) |
| `RQ3/rq3_av_perturbation_matrix_equal_eval.csv` | Engine list for RQ4 |
| `RQ1_and_2/heatmap.csv` | Engine list for family-label loss |

The family ground truth is the directory name (100 families).

## Pipeline

| Step | Script | Output |
|---|---|---|
| 1 | `src/extract.py` | `work/verdicts.jsonl.gz`: per-report engine category, label, engine version |
| 2 | `src/build_R.py` (uses `src/load.py`) | `work/R.pkl` |
| 3 | `src/b1.py` | `work/B.pkl`: common set of 268,824 (original, engine) pairs |
| 4 | `src/f1_paired.py` | `results/B_paired_transitions.csv` |
| 5 | `src/f2_engines.py` | `results/B_engine_types.csv` (supplementary, uncorrected) |
| 6 | `src/f2b_bonf.py` | `results/B_engine_primary_bonf.csv` |
| 7 | `src/f3_cslabels.py` | `results/B_cs_label_evidence.csv` |
| 8 | `src/f4_b2.py` | `results/B2_categories_counts.csv`, `results/B2_old_vs_new.csv` |
| 9 | `src/f5_b2paired.py` | `results/B2_paired_vs_baseline.csv` |
| 9b | `src/f6_mismatch_types.py` | `results/B2_mismatch_types.{csv,tex}` |
| 10 | `src/g1_figs.py` | `figures/strategy_transitions.{pdf,csv}`, `figures/engine_strategy_changes.{pdf,csv}` |

## Definitions

**Common set (RQ4).** An (original, engine) pair is kept when the engine labels the original `malicious` in both the first scan and the June rescan, and returns `malicious` or `undetected` for all 15 AEs (every nonempty subset of {PSC, IC, JOB, CS}). This yields 268,824 pairs over 4,816 originals, 100 families, and 71 engines. The same pairs are used in every comparison.

**Gain, loss, ΔASR.** For strategies S and T = S ∪ {p}, a gain is a pair where the S AE is detected and the T AE is not; a loss is the reverse. Gain = n_gain / N × 100, Loss = n_loss / N × 100, ΔASR = Gain − Loss. The AEs of S and T are generated independently. There are 28 such comparisons; the 12 from single perturbations compare April–May scans with June scans, and the other 16 use June scans only.

**Uncertainty.** 95% intervals come from a family-level cluster bootstrap (100 families resampled with replacement, 2,000 resamples, percentile interval), computed directly on ΔASR.

**Engine-level analysis.** For PSC+IC+JOB → PSC+IC+JOB+CS, engines with at least 500 pairs (70 engines) are tested with Bonferroni-adjusted intervals (α = 0.05/70, i.e., 99.93% percentile intervals, 20,000 resamples). An engine is a decrease/increase when its adjusted interval excludes zero.

**Family-label loss.** Labels are lower-cased and split on non-alphanumeric characters (tokens of length ≥ 3); each token is mapped to its canonical name through AVClass2 aliases. Detected labels are classified as same family, other family (AVClass2 FAM or dataset families), generic (AVClass2 GEN plus a small list in `f4_b2.py`), or unclassified. Targets are pairs whose original label contains the ground-truth family. The metric is the share of still-detected AEs whose label no longer contains the ground-truth family; the baseline is the June rescan of the original. Mismatch types (generic, other family, unclassified) in the supplementary table are counted within the same shared set as the paired comparison (the engine detects both the rescanned original and the AE), so they share its denominator.

## AVClass2 data

`avclass_data/` holds copies of the files used:

- Source: [malicialab/avclass](https://github.com/malicialab/avclass), commit `35b0c1548f1f3307286993d5edf959e113f7ea6e` (2024-10-22)
- `default.tagging` SHA-256 `3d02935d1883bd05bf7bff66fc9c55f2cdb47608a64a89f6d29fdc38526a317d`
- `default.taxonomy` SHA-256 `f56aed38b6380527b1f8a49b31e213f3f6f4e5f5ae484ed846772771353e2e16`

## Interpretation limits

- Single-perturbation and multi-perturbation AEs were scanned in different months, so comparisons from single perturbations describe trends within the collected reports rather than exact comparisons.
- Labels describe observed engine outputs only; they do not establish internal detection mechanisms.
