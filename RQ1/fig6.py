import os
import json
from collections import defaultdict
import pandas as pd
import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.gridspec as gridspec
import matplotlib as mpl

mpl.rcParams["pdf.fonttype"] = 42
mpl.rcParams["ps.fonttype"] = 42

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)

report_dir_candidates = [
    os.path.join(REPO_ROOT, "Data", "RQ1_and_2", "malware"),
    os.path.join(REPO_ROOT, "Data", "RQ1_and_2", "Original_malware_and_AE_report"),
]

report_dir = next((path for path in report_dir_candidates if os.path.isdir(path)), None)
if report_dir is None:
    raise FileNotFoundError(
        "Could not find the RQ1 report directory. Checked: "
        + ", ".join(report_dir_candidates)
    )

perturbation_abbr_map = {
    "modify_dos_header": "MDH",
    "extend_dos_stub": "EDS",
    "coff_header": "CH",
    "rich_header": "RH",
    "optional_header": "OH",
    "section_rename": "SRN",
    "section_add": "SAD",
    "section_append": "SAP",
    "content_shifting": "CS",
    "jmp_overlay_back": "JOB",
    "overlay_append": "OAP",
    "instruction_change": "IC",
    "resource_change": "RC",
    "section_increase": "SIN"
}
abbr_order = list(perturbation_abbr_map.values())

def extract_av_results(path):
    with open(path, "r") as f:
        return json.load(f)["data"]["attributes"]["last_analysis_results"]

# Collect AE–OG pairs: (evaded, evaluated) for each AV × perturbation
temp_stats = defaultdict(lambda: defaultdict(list))  # av → abbr → list of (og_category, ae_category)

for root, _, files in os.walk(report_dir):
    for file in files:
        if not file.endswith(".json") or "|" not in file:
            continue
        try:
            base_name, pert_ext = file.split("|", 1)
            perturbation = pert_ext.replace(".json", "")
            abbr = perturbation_abbr_map.get(perturbation, None)
            if abbr is None:
                continue

            ae_path = os.path.join(root, file)
            og_path = os.path.join(root, base_name + ".json")
            if not os.path.exists(og_path):
                continue

            og_results = extract_av_results(og_path)
            ae_results = extract_av_results(ae_path)

            for av in og_results:
                if av not in ae_results:
                    continue
                ae_category = ae_results[av].get("category")
                if ae_category not in ("malicious", "undetected"):
                    continue
                og_category = og_results[av].get("category")
                temp_stats[av][abbr].append((og_category, ae_category))
        except:
            continue

# Denominator standardization based on the intersection
av_common_abbrs = {av: set(abbrs.keys()) for av, abbrs in temp_stats.items()}
all_avs = sorted(temp_stats.keys())

# Wide-format DataFrame
rows = []
for av in all_avs:
    abbrs = av_common_abbrs[av]
    common_abbrs = abbrs.intersection(set(abbr_order))
    if not common_abbrs:
        continue
    min_eval_count = min(len(temp_stats[av][abbr]) for abbr in common_abbrs)

    row = {"AV Engine": av}
    for abbr in abbr_order:
        samples = temp_stats[av].get(abbr, [])
        if len(samples) < min_eval_count:
            row[abbr] = ""
            continue
        evaded = sum(1 for og_cat, ae_cat in samples[:min_eval_count] if og_cat == "malicious" and ae_cat != "malicious")
        row[abbr] = f"{evaded} / {min_eval_count}"
    rows.append(row)

df_raw = pd.DataFrame(rows)
if df_raw.empty:
    raise RuntimeError(f"No valid AV results were collected from: {report_dir}")

plt.rcParams.update({
    "font.size": 14,
    "xtick.labelsize": 14,
    "ytick.labelsize": 14,
    "axes.labelsize": 16,
    "axes.titlesize": 16,
    "legend.fontsize": 14
})

df_filtered = df_raw[df_raw["AV Engine"] != "FireEye"].copy()

perturbation_order = [
    "MDH", "EDS", "CH", "RH", "OH", "SRN", "SAD",
    "SAP", "CS", "JOB", "OAP", "IC", "RC", "SIN"
]

heatmap_data = []
av_engines = []

for _, row in df_filtered.iterrows():
    av = row["AV Engine"]
    av_engines.append(av)
    rates = []
    for p in perturbation_order:
        cell = row.get(p, "")
        if isinstance(cell, str) and "/" in cell:
            try:
                evaded, total = map(int, cell.split("/"))
                rate = (evaded / total) * 100 if total > 0 else 0
            except:
                rate = 0
        else:
            rate = 0
        rates.append(rate)
    heatmap_data.append(rates)

df_heatmap = pd.DataFrame(heatmap_data, columns=perturbation_order, index=av_engines)
df_heatmap = df_heatmap.rename(columns={"RC": "PSC"})
#df_heatmap.to_csv("heatmap.csv")

cell_height = 0.7
cell_width = 0.4
fig_width = len(av_engines) * cell_width
fig_height = len(perturbation_order) * cell_height

avg_bypass_rate = df_heatmap.mean(axis=1)
df_heatmap = df_heatmap.loc[avg_bypass_rate.sort_values(ascending=False).index]

fig_width = len(df_heatmap.index) * 0.4
fig_height = len(df_heatmap.columns) * 0.4
fig = plt.figure(figsize=(fig_width, fig_height))
gs = gridspec.GridSpec(1, 2, width_ratios=[40, 1], wspace=0.05)

ax = plt.subplot(gs[0])
cbar_ax = plt.subplot(gs[1])

sns.heatmap(
    df_heatmap.T,
    cmap="magma_r",
    linewidths=0.3,
    cbar_ax=cbar_ax,
    ax=ax,
    vmin=0,
    vmax=100,
    square=True
)

ax.set_xlabel("AV Engine", fontsize=16)
ax.set_ylabel("Perturbation", fontsize=16)
ax.set_xticklabels(ax.get_xticklabels(), rotation=90, ha='center')
ax.set_yticklabels(ax.get_yticklabels(), rotation=0)

output_path = os.path.join(SCRIPT_DIR, "RQ1_fig6.pdf")
plt.savefig(output_path, format="pdf", bbox_inches="tight")
print(f"Save: {output_path}")
