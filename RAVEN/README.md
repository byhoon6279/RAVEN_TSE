# RAVEN Open Science: Perturbation Generation Scripts (RQ1 / RQ3 / RQ6)

This repository includes Python scripts that generate **semantics-preserving PE perturbations** used in the paper’s measurement pipelines.
Each script batch-processes `.exe` files under an input directory and writes perturbed binaries into an output directory using a deterministic naming convention.

> **Important**: These scripts rely on a local `modifier.py` module that provides the `Modifier` class and individual perturbation methods (e.g., `resource_change()`, `instruction_change()`).
> Make sure `modifier.py` is available on `PYTHONPATH` (e.g., in the same directory as these scripts).

---

## Requirements

- Python 3.x
- `lief` (used by PE modifiers / parsing)
- A local module: `modifier.py` that defines `Modifier(input_exe_path, output_dir)` and perturbation methods.

Example install:
```bash
pip install lief
```

---

## Common Input Layout Assumption

All scripts walk the input tree recursively and process `*.exe`.

Typical structure:
```
<INPUT_DIR>/
  <family_or_group_1>/
    sample1.exe
    sample2.exe
  <family_or_group_2>/
    ...
```

The scripts preserve relative paths under the output directory.

---

# Script 1) `RQ1_modifier.py` (Single-perturbation sweep for RQ1)

## What it does
For each input `.exe`, the script applies a fixed list of **14 single perturbations** one-by-one, and writes each output as a separate file:
- `modify_dos_header`
- `extend_dos_stub`
- `coff_header`
- `rich_header`
- `optional_header`
- `section_rename`
- `section_add`
- `section_append`
- `content_shifting`
- `jmp_overlay_back`
- `overlay_append`
- `resource_change`
- `section_increase`
- `instruction_change`

The script optionally runs in parallel using Python multiprocessing.

## Usage
```bash
python RQ1_modifier.py -i <INPUT_DIR> -o <OUTPUT_DIR>
```

Enable multiprocessing:
```bash
python RQ1_modifier.py -i <INPUT_DIR> -o <OUTPUT_DIR> --multi -j 16
```

## Output naming
For an input file `sample.exe`, outputs are written as:
```
sample|<perturbation_name>.exe
```

Example:
```
sample|resource_change.exe
sample|instruction_change.exe
```

## Output directory structure
The relative path from `<INPUT_DIR>` is preserved:
```
<OUTPUT_DIR>/<relative_path>/sample|resource_change.exe
```

## Notes
- The script contains an internal `target_dir` allowlist (family directory names).  
  If you want to process **all** directories, set `target_dir = []` (or remove the filter).

---

# Script 2) `RQ3_modifier.py` (Combinational perturbations for RQ3)

## What it does
This script generates **perturbation combinations** for a 15-day latency / stability measurement pipeline (RQ3).
It uses four perturbations and their abbreviations:

- `resource_change` → `RC`
- `instruction_change` → `IC`
- `jmp_overlay_back` → `JOB`
- `content_shifting` → `CS`

It enumerates combinations of size **2, 3, and 4**, and for each combination:
1. Applies perturbations in the given order (default combination order),
2. Writes intermediate results into structured directories,
3. If a combination fails, it tries **different permutations** of the same perturbations (`retry_with_permutation`) up to a bounded number of attempts.

It also supports **resume** behavior: it searches for previously generated partial results and reuses them as the starting point.

## Usage
```bash
python RQ3_modifier.py -i <INPUT_DIR> -o <OUTPUT_DIR> -l debug_output.txt
```

Dry-run (no actual modifications; useful to validate traversal and logging):
```bash
python RQ3_modifier.py -i <INPUT_DIR> -o <OUTPUT_DIR> --dry-run
```

Set parallelism:
```bash
python RQ3_modifier.py -i <INPUT_DIR> -o <OUTPUT_DIR> -j 8
```

## Output directory structure
For a combination size `num` and combination key `comb_key`:
```
<OUTPUT_DIR>/
  <num>_perts/
    <comb_key>/
      <relative_path>/
        <base>|<abbrs_joined_by_underscore>.exe
```

- `comb_key` is `"RC+IC"`, `"RC+IC+JOB"`, etc. (joined with `+`)
- Output filename uses `_` between abbreviations:
  - `base|RC_IC.exe`
  - `base|RC_IC_JOB.exe`

Example:
```
<OUTPUT_DIR>/3_perts/RC+IC+JOB/<family>/abcd...|RC_IC_JOB.exe
```

## Temporary directory & cleanup
The script writes intermediate files under:
```
<parent_of_INPUT_DIR>/tmp/perturbation_tmp/tmp_<pid>/...
```

It deletes this temp tree when `--cleanup` is enabled (default behavior in the script).

---

# Script 3) `RQ6_modifier.py` (Fixed 4-perturbation chain for RQ6, longitudinal study)

## What it does
`RQ6_modifier.py` is a specialization of the RQ3 pipeline for RQ6 (the longitudinal study; RQ4 in the conference paper).  
It applies **only the full 4-perturbation chain**:

```
RC + IC + JOB + CS
```

It keeps the same retry logic (permutation fallback) and multiprocessing structure.

## Usage
```bash
python RQ6_modifier.py -i <INPUT_DIR> -o <OUTPUT_DIR> -l debug_output.txt
```

Dry-run:
```bash
python RQ6_modifier.py -i <INPUT_DIR> -o <OUTPUT_DIR> --dry-run
```

## Output directory structure
Same convention as RQ3, but only for `num = 4`:
```
<OUTPUT_DIR>/4_perts/RC+IC+JOB+CS/<relative_path>/<base>|RC_IC_JOB_CS.exe
```

---

## Reproducibility Notes (Open Science)

- These scripts are **binary mutation generators**. Downstream measurement (e.g., VirusTotal report collection, latency analysis) should be documented separately.
- To ensure exact reproducibility:
  - pin Python version and `lief` version,
  - archive the exact `modifier.py` implementation used in the paper,
  - record the command-line invocation and the input dataset snapshot (hash list).

---

## Quick sanity check

1. Pick one `.exe` sample.
2. Run `RQ1_modifier.py` on a small folder.
3. Confirm the output naming pattern: `sample|<pert>.exe`.
4. Run `RQ3_modifier.py --dry-run` and confirm logs and combination keys.

