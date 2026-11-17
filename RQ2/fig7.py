import os
import json
import pandas as pd
import numpy as np
from glob import glob
from collections import defaultdict, Counter
import matplotlib
matplotlib.use("Agg")

import matplotlib.pyplot as plt
import matplotlib as mpl

mpl.rcParams["pdf.fonttype"] = 42
mpl.rcParams["ps.fonttype"] = 42

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(SCRIPT_DIR)

benign_dir_candidates = [
    os.path.join(REPO_ROOT, "Data", "RQ1_and_2", "benign_report", "vtreport"),
    os.path.join(REPO_ROOT, "Data", "RQ1_and_2", "benign_report"),
]
malware_dir_candidates = [
    os.path.join(REPO_ROOT, "Data", "RQ1_and_2", "malware"),
    os.path.join(REPO_ROOT, "Data", "RQ1_and_2", "Original_malware_and_AE_report"),
]

benign_dir = next((path for path in benign_dir_candidates if os.path.isdir(path)), None)
malware_dir = next((path for path in malware_dir_candidates if os.path.isdir(path)), None)

if benign_dir is None:
    raise FileNotFoundError(
        "Could not find the RQ2 benign report directory. Checked: "
        + ", ".join(benign_dir_candidates)
    )
if malware_dir is None:
    raise FileNotFoundError(
        "Could not find the RQ2 malware report directory. Checked: "
        + ", ".join(malware_dir_candidates)
    )

av_stats = defaultdict(lambda: {"TP": 0, "FP": 0, "TN": 0, "FN": 0})

# 🔹 Benign (GT = 0)
benign_paths = glob(os.path.join(benign_dir, "*.json"))
for path in benign_paths:
    with open(path) as f:
        report = json.load(f)
    results = report.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    for av, res in results.items():
        pred = 1 if res.get("category") == "malicious" else 0
        if pred == 1:
            av_stats[av]["FP"] += 1
        else:
            av_stats[av]["TN"] += 1

# 🔹 Malware OG only (GT = 1)
og_paths = []
for root, _, files in os.walk(malware_dir):
    for f in files:
        if f.endswith(".json") and "|" not in f:
            og_paths.append(os.path.join(root, f))

for path in og_paths:
    with open(path) as f:
        report = json.load(f)
    results = report.get("data", {}).get("attributes", {}).get("last_analysis_results", {})
    for av, res in results.items():
        pred = 1 if res.get("category") == "malicious" else 0
        if pred == 1:
            av_stats[av]["TP"] += 1
        else:
            av_stats[av]["FN"] += 1

rows = []
for av, stats in av_stats.items():
    TP, FP, TN, FN = stats["TP"], stats["FP"], stats["TN"], stats["FN"]
    precision = TP / (TP + FP) if TP + FP > 0 else 0.0
    recall = TP / (TP + FN) if TP + FN > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall > 0 else 0.0
    rows.append({
        "AV": av,
        "TP": TP, "FP": FP, "TN": TN, "FN": FN,
        "Precision": precision, "Recall": recall, "F1": f1
    })

df = pd.DataFrame(rows)
if df.empty:
    raise RuntimeError(
        f"No AV statistics were collected from benign_dir={benign_dir}, malware_dir={malware_dir}"
    )
df.sort_values("F1", ascending=False, inplace=True)
df.to_csv(os.path.join(SCRIPT_DIR, "av_precision_recall_f1.csv"), index=False)

#plot
heatmap_csv_candidates = [
    os.path.join(REPO_ROOT, "Data", "RQ2", "heatmap.csv"),
    os.path.join(REPO_ROOT, "Data", "RQ1_and_2", "heatmap.csv"),
]
heatmap_csv = next((path for path in heatmap_csv_candidates if os.path.isfile(path)), None)
if heatmap_csv is None:
    raise FileNotFoundError(
        "Could not find heatmap.csv. Checked: " + ", ".join(heatmap_csv_candidates)
    )

# ===== Excluded AVs =====
low_participation_avs = [
    'FireEye','MAX','Cybereason','BitDefenderTheta','Cyren','McAfee-GW-Edition','Ad-Aware',
    'Comodo','eGambit','TotalDefense','Qihoo-360','Invincea','F-Prot','Endgame','TheHacker',
    'AVware','WebrootD','Babable','nProtect','WhiteArmor','SymantecMobileInsight',
    'BitDefenderFalx','TrellixENS','WebrootD','Trustlook','Avast-Mobile'
]

# ===== AV order =====
desired_order = [
    "Lionic","Alibaba","Paloalto","TrendMicro","Panda","alibabacloud","tehtris","ViRobot","Yandex",
    "Zillya","CAT-QuickHeal","VirIT","TACHYON","TrendMicro-HouseCall","Gridinsoft","AhnLab-V3",
    "Acronis","SUPERAntiSpyware","ZoneAlarm","Xcitium","K7AntiVirus","K7GW","MaxSecure","VBA32",
    "McAfee","Tencent","Varist","Webroot","Symantec","NANO-Antivirus","Kaspersky","Jiangmin",
    "Kingsoft","ESET-NOD32","DrWeb","F-Secure","Fortinet","Avira","Cylance","DeepInstinct",
    "huorong","Bkav","CrowdStrike","AVG","Avast","ALYac","ClamAV","CTX","Arcabit","BitDefender",
    "VIPRE","Baidu","Emsisoft","MicroWorld-eScan","Malwarebytes","McAfeeD","Zoner","Antiy-AVL",
    "Rising","GData","Microsoft","Sangfor","Skyhigh","Ikarus","Sophos","Cynet","Trapmine",
    "SentinelOne","Google","APEX","CMC","Elastic"
]

# ===== CSV → TPR/FPR =====

df = df[~df["AV"].isin(low_participation_avs)].copy()

df["TPR_pct"] = (df["TP"] / (df["TP"] + df["FN"]).replace(0, np.nan)).fillna(0) * 100
df["FPR_pct"] = (df["FP"] / (df["FP"] + df["TN"]).replace(0, np.nan)).fillna(0) * 100
df_vt = df[["AV","TPR_pct","FPR_pct"]]

# ===== heatmap.csv → ASR(%) =====
df_heatmap = pd.read_csv(heatmap_csv, index_col=0)
df_heatmap = df_heatmap.drop(index=["Average"], errors="ignore")
df_heatmap = df_heatmap.apply(pd.to_numeric, errors="coerce")

df_asr = pd.DataFrame({
    "AV": df_heatmap.index,
    "ASR_pct": df_heatmap.mean(axis=1)
})

df_all = pd.merge(df_vt, df_asr, on="AV", how="inner")
order_used = [av for av in desired_order if av in df_all["AV"].unique()]
df_all = df_all.set_index("AV").loc[order_used].reset_index()
df_all.to_csv(os.path.join(SCRIPT_DIR, "df_all.csv"), index=False)


x = np.arange(len(df_all))
fig, ax = plt.subplots(figsize=(max(18, len(order_used)*0.30), 7.2))  # 높이 살짝↑

ax.plot(x, df_all["TPR_pct"], marker="o", linestyle="-", linewidth=2, color="#2ca02c",
        label="TPR (Malware-I dataset)",markersize=9)
ax.plot(x, df_all["ASR_pct"], marker="^", linestyle="-", linewidth=2, color="#d62728",
        label="ASR (RAVEN-Single dataset, heatmap mean)",markersize=9)
ax.plot(x, df_all["FPR_pct"], marker="s", linestyle="-", linewidth=2, color="#ff7f0e",
        label="FPR (Benign dataset)",markersize=9)

ax.set_xticks(x)
ax.set_xticklabels(df_all["AV"], rotation=90, fontsize=18)
ax.tick_params(axis="x", pad=6)  # 라벨과 축 간격
ax.set_yticks(np.arange(0, 101, 20))
ax.tick_params(axis="y", labelsize=18)
ax.set_ylim(0, 105)
ax.grid(True, axis="both", linestyle="--", alpha=0.6)
ax.margins(x=0.01)

handles, labels = ax.get_legend_handles_labels()
fig.legend(handles, labels,
           loc="upper center", bbox_to_anchor=(0.5, 0.995),
           ncol=3, frameon=False, fontsize=16,
           columnspacing=1.2, handletextpad=0.6, borderaxespad=0.0)

fig.tight_layout(rect=[0, 0, 1, 0.92])
fig.savefig(os.path.join(SCRIPT_DIR, "RQ2_fig7.pdf"), dpi=300, bbox_inches="tight")
plt.show()
