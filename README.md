# RAVEN: Open-Science Artifact (IEEE TSE)

This repository is the open-science artifact for the IEEE Transactions on Software Engineering (TSE) article

> **RAVEN: Measuring Detection Instability in Anti-virus Engines under Semantics-Preserving Perturbations**

which extends our ASE 2026 conference paper of the same name.
It contains the perturbation framework, the VirusTotal (VT) and ClamAV scan reports used in the evaluation, the analysis and figure-generation scripts for every research question (RQ), and the dynamic-trace package used for behavioral sanity checking.

**No malware binaries are distributed.** The released data consist of scan reports, aggregated tables, and execution traces; samples are identified by SHA-256 only. The example inputs in `RAVEN/input/` are benign executables.

## Research Questions and Artifact Map

The TSE article adds two RQs (RQ4 and RQ5) to the conference paper; the conference RQ4 on resilience becomes RQ6.
Directory names `RQ1/`–`RQ4/` follow the conference numbering.

| TSE RQ | Topic | Code | Data | Conference RQ |
|---|---|---|---|---|
| RQ1 | Perturbation impact | `RQ1/` | `Data/RQ1_and_2/` | RQ1 |
| RQ2 | AV specificity (ASR–FPR trade-offs) | `RQ2/` | `Data/RQ1_and_2/` | RQ2 |
| RQ3 | Multi-perturbation strategies and comparison with SOTA frameworks | `RQ3/` | `Data/RQ3/` | RQ3 |
| RQ4 | Strategy effects: paired evasion gains/losses and engine-level changes | `Extension/` | `Data/RQ1_and_2/`, `Data/RQ3/` | new |
| RQ5 | Family-label retention under continued detection | `Extension/` | `Data/RQ1_and_2/`, `Data/RQ3/` | new |
| RQ6 | Resilience: 15-day longitudinal rescans | `RQ4/` | `Data/RQ4/` | RQ4 |
| Validation | Behavioral sanity check of original/AE pairs | `sanity_check/` | `sanity_check/` | supplement |

RQ4 and RQ5 reuse the existing scan reports; no new VT scans were performed for the extension.

## Requirements

The conference analyses were tested on Ubuntu 20.04.6 with Python 3.10; the extension analyses (`Extension/`) were also run on macOS with Python 3.13.

| Purpose | Python packages |
|---|---|
| Perturbation framework (`RAVEN/`) | `lief`, `pefile` |
| Analyses and figures | `pandas`, `numpy`, `matplotlib`, `seaborn` |

```bash
pip install -r requirements.txt
pip install matplotlib seaborn
```

## Data Access

Large data files may not be available directly from this repository. Download the complete artifacts from
[Google Drive](https://drive.google.com/drive/folders/1P4KIVouHTfKtIl6QqFnjtWyBcfVIL-k8?usp=drive_link)
and unzip each archive into the corresponding subdirectory under `Data/`.

| Path | Contents |
|---|---|
| `Data/RQ1_and_2/Original_malware_and_AE_report/<family>/` | VT reports for 5,000 originals (100 families × 50; `<seed>.json`, first scan, Apr–May 2025) and their 14 single-perturbation AEs (`<seed>\|<operator>.json`) |
| `Data/RQ1_and_2/benign_report/` | VT reports for the benign samples used for FPR |
| `Data/RQ1_and_2/Original_malware_and_AE_clam_scan_result.txt` | ClamAV results for originals and single-perturbation AEs |
| `Data/RQ1_and_2/heatmap.csv` | Per-engine, per-operator aggregates for RQ1/RQ2 |
| `Data/RQ3/RAVEN_report/<family>/` | VT reports for the 11 multi-perturbation AEs (`<seed>\|RC_IC.json`, …) and a rescan of the same originals (`<seed>.json`, Jun 2025) |
| `Data/RQ3/SOTA_report/` | VT reports for AEs from Gym-Malware, MAB-Malware, MalwareMakeover, and MalGuise |
| `Data/RQ3/clamav_result/` | ClamAV results for RQ3 |
| `Data/RQ3/rq3_av_perturbation_matrix_equal_eval.csv`, `SOTA_4_heatmap.csv` | Aggregates for RQ3 |
| `Data/RQ4/report/` | Daily VT reports for the longitudinal AEs (TSE RQ6) |
| `Data/RQ4/rq4_latency_with_transitions.csv.gz` | Detection latency and state transitions (TSE RQ6) |

The family of each sample is given by its directory name (AVClass2 labeling).
In report filenames and multi-perturbation strategy names, `RC` (`resource_change`) denotes the PSC operator in the paper.

## Repository Structure

```text
RAVEN_TSE/
├── RAVEN/                         Perturbation framework (see RAVEN/README.md)
│   ├── modifier/                  14 semantics-preserving PE perturbations
│   ├── input/                     Benign example PE binaries
│   ├── RQ1_modifier.py            Generate single-perturbation AEs (RQ1, RQ2)
│   ├── RQ3_modifier.py            Generate multi-perturbation AEs (RQ3)
│   └── RQ4_modifier.py            Generate fixed four-perturbation AEs for the longitudinal study (TSE RQ6)
├── Data/                          Scan reports and aggregates (see Data Access)
├── RQ1/fig5.py                    TSE RQ1 figure
├── RQ2/fig6.py                    TSE RQ2 figure
├── RQ3/fig7.py                    TSE RQ3 figure
├── RQ4/fig8.py                    TSE RQ6 figure
├── Extension/                     TSE RQ4 and RQ5 (see Extension/README.md)
│   ├── run_all.sh                 Reproduce all extension results and figures
│   ├── src/                       Analysis and figure scripts
│   ├── results/                   Result tables (CSV)
│   ├── figures/                   Figures (vector PDF) and their input tables
│   └── avclass_data/              AVClass2 alias and taxonomy files used for RQ5
├── sanity_check/                  Dynamic traces for behavioral validation (see sanity_check/README.md)
├── requirements.txt
└── LICENSE
```

## Reproducing the Results

Run all commands from the repository root after placing the data under `Data/`.

### RQ1–RQ3 and RQ6

| TSE RQ | Command | Output |
|---|---|---|
| RQ1 | `python RQ1/fig5.py` | `RQ1/RQ1_fig_5.pdf` |
| RQ2 | `python RQ2/fig6.py` | `RQ2/RQ2_fig6.pdf` |
| RQ3 | `python RQ3/fig7.py` | `RQ3/RQ3_fig7.pdf` |
| RQ6 | `python RQ4/fig8.py` | `RQ4/RQ4_fig8.pdf` |

Output filenames follow the conference figure numbering.

### RQ4 and RQ5 (TSE extension)

```bash
cd Extension
./run_all.sh
```

The script reads `../Data` without modifying it, writes intermediate files to `Extension/work/` (git-ignored), result tables to `Extension/results/`, and figures to `Extension/figures/`. It runs in about one minute, and bootstrap seeds are fixed, so the outputs are deterministic.

| Output | Paper element |
|---|---|
| `figures/strategy_transitions.pdf`, `results/B_paired_transitions.csv` | RQ4: evasion gains, losses, and ASR changes for the 28 comparisons that add one perturbation |
| `figures/engine_strategy_changes.pdf`, `results/B_engine_primary_bonf.csv` | RQ4: engine-level ASR changes (PSC+IC+JOB → PSC+IC+JOB+CS, Bonferroni-adjusted) |
| `results/B_cs_label_evidence.csv` | RQ4: label context for the engine-level decreases |
| `results/B2_paired_vs_baseline.csv` | RQ5: family-label mismatch rates vs. the original-rescan baseline (table) |
| `results/B2_categories_counts.csv`, `results/B2_old_vs_new.csv` | RQ5: outcome categories and the effect of alias normalization |

Definitions, sample selection, and the AVClass2 version (commit and SHA-256) are documented in [Extension/README.md](Extension/README.md).

## Behavioral Sanity-Check Traces

The `sanity_check/` directory contains the dynamic execution traces used to check whether representative RAVEN-generated AEs preserve the runtime behavior of their originals.

- The manifest contains 62 original/AE pairs, all of which are included.
- The release contains dynamic traces only, not malware binaries.
- Samples are identified by SHA-256 in filenames and in `trace_manifest.csv`.

For one source trace, non-record trailing NUL padding after the final valid event was omitted during export. No execution-event record was removed or modified.

To verify the package:

```bash
cd sanity_check
python3 scripts/summarize_traces.py
```

Expected output:

```text
manifest_rows,62
status,included,62
included_pairs,62
missing_files,0
content_mismatches,0
exact_event_sequence_matches,61
terminal_record_only_differences,1
event_sequence_differences,0
```

See [sanity_check/README.md](sanity_check/README.md) for details.

## Interpretation Notes

- Single-perturbation AEs were scanned in April–May 2025 and multi-perturbation AEs in June 2025. Comparisons that span the two campaigns (TSE RQ4) describe trends within the collected reports rather than exact comparisons.
- VT verdicts and labels reflect engine outputs at scan time and may differ if the same files are rescanned today.
- Engine labels describe outputs only; they do not establish internal detection mechanisms.

## Citation

If you use this artifact, please cite the TSE article and the ASE 2026 conference paper. BibTeX entries will be added upon publication.

## License

This artifact is released under the MIT License. See [LICENSE](LICENSE).
