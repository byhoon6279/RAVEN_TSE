import os
import pandas as pd
import seaborn as sns
import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt

import matplotlib.gridspec as gridspec
import numpy as np
import matplotlib as mpl

mpl.rcParams["pdf.fonttype"] = 42
mpl.rcParams["ps.fonttype"] = 42

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)

csv_candidates = [
    os.path.join(REPO_ROOT, "Data", "RQ6", "rq4_latency_with_transitions.csv"),
    os.path.join(REPO_ROOT, "Data", "RQ6", "rq4_latency_with_transitions.csv.gz"),
]
csv_path = next((path for path in csv_candidates if os.path.isfile(path)), None)
if csv_path is None:
    raise FileNotFoundError(
        "Could not find rq4_latency_with_transitions data. Checked: "
        + ", ".join(csv_candidates)
    )

# CSV fiel load
df = pd.read_csv(csv_path)

# AV sorting order
desired_order = [
    "Lionic","Alibaba","Paloalto","TrendMicro","Panda","alibabacloud","tehtris","ViRobot","Yandex",
    "Zillya","CAT-QuickHeal","VirIT","TACHYON","TrendMicro-HouseCall","Gridinsoft","AhnLab-V3",
    "Acronis","SUPERAntiSpyware","ZoneAlarm","Xcitium","K7AntiVirus","K7GW","MaxSecure","VBA32",
    "Tencent","Varist","Webroot","Symantec","NANO-Antivirus","Kaspersky","Jiangmin","Kingsoft",
    "ESET-NOD32","DrWeb","F-Secure","Fortinet","Avira","Cylance","DeepInstinct","huorong","Bkav",
    "CrowdStrike","AVG","Avast","ALYac","ClamAV","CTX","Arcabit","BitDefender","VIPRE","Baidu",
    "Emsisoft","MicroWorld-eScan","Malwarebytes","McAfeeD","Zoner","Antiy-AVL","Rising","GData",
    "Microsoft","Sangfor","Skyhigh","Ikarus","Sophos","Cynet","Trapmine","SentinelOne","Google",
    "APEX","CMC","Elastic"
]


# Filter: evasion cases where the OG is detected and the AE is not detected
df_filtered = df[df["og_detected"] == True].copy()
df_filtered = df_filtered[df_filtered["ae_detected"] == False]

# Compute the per-AV daily evasion rate among all detected OG–AE pairs
total_counts = df[df["og_detected"] == True].groupby(["ae_detect_date", "av"]).size()
evasion_counts = df_filtered.groupby(["ae_detect_date", "av"]).size()

evasion_rate = (evasion_counts / total_counts).fillna(0)

df_pivot = evasion_rate.reset_index().pivot(index="ae_detect_date", columns="av", values=0)
df_pivot = df_pivot.fillna(0)

original_dates = df_pivot.index.tolist()
numeric_index = list(range(1, len(original_dates) + 1))

existing_cols = [col for col in desired_order if col in df_pivot.columns]
df_pivot = df_pivot.loc[:, existing_cols]
df_pivot.index = numeric_index

plt.rcParams.update({
    "font.size": 16,
    "xtick.labelsize": 16,
    "ytick.labelsize": 16,
    "axes.labelsize": 16,
    "axes.titlesize": 16,
    "legend.fontsize": 16
})

fig = plt.figure(figsize=(len(df_pivot.columns) * 0.3 + 2, len(df_pivot.index) * 0.35 + 1),)
gs = gridspec.GridSpec(1, 2, width_ratios=[40, 1], wspace=0.05)
ax = plt.subplot(gs[0])
cbar_ax = plt.subplot(gs[1])

sns.heatmap(
    df_pivot,
    cmap="magma_r",
    cbar_ax=cbar_ax,
    linewidths=0.3,
    vmin=0,
    vmax=1,
    ax=ax,
    square=True
)

#ax.set_xlabel("AV Engine", fontsize=16)
ax.set_ylabel("Days", fontsize=18)
ax.set_xlabel("")
ax.set_xticklabels(ax.get_xticklabels(), ha='center')
ax.set_yticklabels(ax.get_yticklabels(), rotation=0, va='center')  # ⬅️ 이 줄 추가

plt.tight_layout()

heatmap_pos = ax.get_position()
cbar_pos = cbar_ax.get_position()

cbar_ax.set_position([
    cbar_pos.x0,       
    heatmap_pos.y0,    
    cbar_pos.width,    
    heatmap_pos.height 
])

plt.savefig(os.path.join(SCRIPT_DIR, "RQ6_fig12.pdf"), format="pdf", bbox_inches="tight")
plt.show()
