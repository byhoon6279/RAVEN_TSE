import os
import pandas as pd
import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import seaborn as sns
import matplotlib.gridspec as gridspec
import matplotlib as mpl

mpl.rcParams["pdf.fonttype"] = 42
mpl.rcParams["ps.fonttype"] = 42

# =========================
# Paths
# =========================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)
rq2_csv_path = os.path.join(REPO_ROOT, "Data", "RQ3", "rq3_av_perturbation_matrix_equal_eval.csv")
sota_path = os.path.join(REPO_ROOT, "Data", "RQ3", "SOTA_4_heatmap.csv")

# =========================
# 0) Desired AV order (fixed)
# =========================
desired_order = ["Lionic", "Alibaba", "Paloalto", "TrendMicro", "Panda", "alibabacloud", "tehtris", "ViRobot", "Yandex", "Zillya", "CAT-QuickHeal", "VirIT", "TACHYON", "TrendMicro-HouseCall", "Gridinsoft", "AhnLab-V3", "Acronis", "SUPERAntiSpyware", "ZoneAlarm", "Xcitium", "K7AntiVirus", "K7GW", "MaxSecure", "VBA32", "Tencent", "Varist", "Webroot", "Symantec", "NANO-Antivirus", "Kaspersky", "Jiangmin", "Kingsoft", "ESET-NOD32", "DrWeb", "F-Secure", "Fortinet", "Avira", "Cylance", "DeepInstinct", "huorong", "Bkav", "CrowdStrike", "AVG", "Avast", "ALYac", "ClamAV", "CTX", "Arcabit", "BitDefender", "VIPRE", "Baidu", "Emsisoft", "MicroWorld-eScan", "Malwarebytes", "McAfeeD", "Zoner", "Antiy-AVL", "Rising", "GData", "Microsoft", "Sangfor", "Skyhigh", "Ikarus", "Sophos", "Cynet", "Trapmine", "SentinelOne", "Google", "APEX", "CMC", "Elastic"]


# =========================
# 1) Load SOTA and rename rows to abbreviations
#    (SOTA csv: rows=AV, cols=SOTA frameworks)
# =========================
df_sota_raw = pd.read_csv(sota_path, index_col=0)

sota_rename_map = {
    "Gym-EMBER": "GE",
    "Gym-MalConv": "GM",
    "MAB-EMBER": "ME",
    "MAB-MalConv": "MM",
    "MalwareMakeover": "MMO",
    "Malguise-MalConv": "MMC",
    "Malguise-MalGraph": "MMG",

    "GE": "GE",
    "GM": "GM",
    "ME": "ME",
    "MM": "MM",
    "MMO": "MMO",
    "MMC": "MMC",
    "MMG": "MMG",
}

# transpose -> rows=SOTA frameworks, cols=AV engines
df_sota = df_sota_raw.T
df_sota.index = [sota_rename_map.get(x, x) for x in df_sota.index]

# =========================
# 2) Load RQ2 and keep ONLY the 4-perturbation combination column -> one row "RM"
# =========================
rq2_df_raw = pd.read_csv(rq2_csv_path)

FOUR_PERT_COMBO_COL = "RC_IC_JOB_CS"  # Raven combination

if FOUR_PERT_COMBO_COL not in rq2_df_raw.columns:
    raise ValueError(
        f"Column '{FOUR_PERT_COMBO_COL}' not found in {rq2_csv_path}. "
        f"Available columns: {list(rq2_df_raw.columns)}"
    )

rm_rates = {}
for _, row in rq2_df_raw.iterrows():
    av = row["AV Engine"]
    cell = row.get(FOUR_PERT_COMBO_COL, "")

    rate = 0.0
    if isinstance(cell, str) and "/" in cell:
        try:
            evaded, total = map(int, cell.split("/"))
            rate = (evaded / total) * 100 if total > 0 else 0.0
        except Exception:
            rate = 0.0

    rm_rates[av] = rate

df_rm = pd.DataFrame([rm_rates], index=["RM"])

# =========================
# 3) Combine rows: SOTA + RM
# =========================
df_combined = pd.concat([df_sota, df_rm], axis=0)

# =========================
# 4) Fix AV engine order to desired_order
#    - keep only columns that exist in df_combined
# =========================
existing_in_order = [av for av in desired_order if av in df_combined.columns]
df_combined = df_combined.reindex(columns=existing_in_order)

# leftovers = [c for c in df_combined.columns if c not in existing_in_order]
# df_combined = df_combined.reindex(columns=existing_in_order + leftovers)

# =========================
# 5) Plot (screenshot-like)
# =========================
plt.rcParams.update({
    "font.size": 12,
    "xtick.labelsize": 10,
    "ytick.labelsize": 12,
    "axes.labelsize": 12,
    "axes.titlesize": 12,
})

fig = plt.figure(figsize=(19, 3.0))
gs = gridspec.GridSpec(1, 2, width_ratios=[50, 1], wspace=0.15)

ax = plt.subplot(gs[0])
cbar_ax = plt.subplot(gs[1])

sns.heatmap(
    df_combined,
    cmap="magma_r",
    vmin=0,
    vmax=100,
    square=False,
    linewidths=0.5,
    linecolor="white",
    ax=ax,
    cbar_ax=cbar_ax,
    cbar_kws={"ticks": [0, 25, 50, 75, 100]}
)

ax.set_xlabel("")
ax.set_ylabel("")
ax.set_xticklabels(ax.get_xticklabels(), rotation=90, ha="center", va="top")
ax.set_yticklabels(ax.get_yticklabels(), rotation=0)
cbar_ax.tick_params(labelsize=10)

plt.subplots_adjust(left=0.05, right=0.97, top=0.98, bottom=0.35)

out_pdf = os.path.join(SCRIPT_DIR, "RQ3_fig9.pdf")
plt.savefig(out_pdf, format="pdf", bbox_inches="tight")
print(f"Save: {out_pdf}")
