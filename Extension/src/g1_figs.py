# Strategy-effect figures (RQ4_tse): strategy_transitions.pdf, engine_strategy_changes.pdf
# usage (from Extension/): python3 src/g1_figs.py work/B.pkl results figures
import sys, os, pickle, numpy as np, pandas as pd, matplotlib
matplotlib.use('pdf')
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

BPKL, OUT = sys.argv[1], sys.argv[2]
FIG = sys.argv[3] if len(sys.argv) > 3 else os.path.join(OUT, 'figs'); os.makedirs(FIG, exist_ok=True)
plt.rcParams.update({'pdf.fonttype': 42, 'ps.fonttype': 42, 'font.family': 'DejaVu Sans',
                     'font.size': 8, 'axes.labelsize': 9, 'xtick.labelsize': 8, 'ytick.labelsize': 8,
                     'legend.fontsize': 8, 'axes.linewidth': 0.6, 'xtick.major.width': 0.6,
                     'ytick.major.width': 0.6, 'savefig.facecolor': 'white'})
BLUE, ORANGE, GRAY, BLACK = '#0072B2', '#E69F00', '#999999', 'black'
ORDER = ['PSC', 'IC', 'JOB', 'CS']
def lab(ops): return '+'.join(o for o in ORDER if o in ops)

# ---------- (a) tidy data ----------
T = pd.read_csv(os.path.join(OUT, 'B_paired_transitions.csv'))
T = T.copy()  # all 28 one-perturbation-added comparisons (12 single->pair span Apr-May vs Jun scans)
T['src_ops'] = T.S.str.split('+')
T['source'] = T.src_ops.map(lab)
T['target'] = [lab(s + [a]) for s, a in zip(T.src_ops, T.added)]
A = pd.DataFrame(dict(source=T.source, target=T.target, added_perturbation=T.added, n_pairs=T.n,
                      gain_count=T.gain, loss_count=T.loss, gain_pct=T.gain_pct, loss_pct=T.loss_pct,
                      delta_pp=T.net_pct, ci_low=T.net_lo, ci_high=T.net_hi,
                      june_only=T.same_month))
A['k'] = A.source.str.count(r'\+') + 1
A['grp'] = A.added_perturbation.map(ORDER.index)
A['src_rank'] = A.source.map(lambda s: tuple(ORDER.index(o) for o in s.split('+')))
A = A.sort_values(['grp', 'k', 'src_rank']).drop(columns=['k', 'grp', 'src_rank']).reset_index(drop=True)
# checks
assert len(A) == 28 and (A.groupby('added_perturbation').size() == 7).all()
assert np.allclose(A.delta_pp, A.gain_pct - A.loss_pct)
assert np.allclose(A.gain_pct, 100 * A.gain_count / A.n_pairs)
key = A[(A.source == 'PSC+IC+JOB') & (A.added_perturbation == 'CS')].iloc[0]
assert key.gain_count == 12640 and key.loss_count == 10517 and round(key.delta_pp, 2) == 0.79
A.to_csv(os.path.join(FIG, 'strategy_transitions.csv'), index=False)

# ---------- (a) plot ----------
W = 7.16   # (b): figure* at \textwidth
WA = 3.5   # (a): single-column figure at \columnwidth
gap = 0.6
ys, y = [], 0.0
for i in range(len(A)):
    if i and i % 7 == 0: y += gap
    ys.append(y); y += 1
ys = np.array(ys)
fig, ax = plt.subplots(figsize=(WA, 5.2))
h = 0.62
ax.barh(ys, A.gain_pct, height=h, color=BLUE, edgecolor='none', label='Evasion gain', zorder=2)
ax.barh(ys, -A.loss_pct, height=h, color=ORANGE, edgecolor='none', label='Evasion loss', zorder=2)
ax.errorbar(A.delta_pp, ys, xerr=[A.delta_pp - A.ci_low, A.ci_high - A.delta_pp], fmt='D', ms=3.2,
            color=BLACK, mfc=BLACK, ecolor=BLACK, elinewidth=0.9, capsize=1.8, capthick=0.9, zorder=3,
            label=r'$\Delta$ASR (95% CI)')
ax.axvline(0, color=GRAY, lw=0.8, zorder=1)
ax.set_yticks(ys)
ax.set_yticklabels([f'{s} → +{a}' for s, a in zip(A.source, A.added_perturbation)])  # compact: S -> S+{p}
ax.invert_yaxis()
XMAX = 19
ax.set_xlim(-5, XMAX)
ax.set_xticks([-5, 0, 5, 10, 15])
ax.set_xticklabels(['\N{MINUS SIGN}5', '0', '5', '10', '15'])  # loss drawn leftward (display only)
for yy, d in zip(ys, A.delta_pp):
    ax.text(XMAX + 0.4, yy, f'{d:+.1f}', va='center', ha='left', fontsize=7.5, clip_on=False)
ax.text(XMAX + 0.4, ys[0] - 1.1, r'$\Delta$ASR', ha='left', va='center', fontsize=7.5, clip_on=False)
for i, (s, a) in enumerate(zip(A.source, A.added_perturbation)):
    if s == 'PSC+IC+JOB' and a == 'CS':
        ax.get_yticklabels()[i].set_fontweight('bold')
for g in range(1, 4):
    yy = (ys[g * 7 - 1] + ys[g * 7]) / 2
    ax.axhline(yy, color='#DDDDDD', lw=0.6, zorder=0)
ax.set_xlabel('Evasion gain/loss and ASR change\n(percentage points)', linespacing=1.1)
ax.tick_params(axis='y', length=0)
for s in ('top', 'right'): ax.spines[s].set_visible(False)
h_, l_ = ax.get_legend_handles_labels()
fig.legend(h_, ['Gain', 'Loss', r'$\Delta$ASR (95% CI)'], loc='upper center', bbox_to_anchor=(0.5, 1.0),
           ncol=3, frameon=False, handlelength=1.1, columnspacing=0.8, handletextpad=0.35)
fig.subplots_adjust(left=0.375, right=0.89, top=0.935, bottom=0.115)
fig.savefig(os.path.join(FIG, 'strategy_transitions.pdf'))  # fixed W x H, no tight bbox
plt.close(fig)

# ---------- (b) tidy data ----------
E = pd.read_csv(os.path.join(OUT, 'B_engine_primary_bonf.csv'))
D = pickle.load(open(BPKL, 'rb'))
g = D.groupby('e')
asr = pd.DataFrame({'asr_three': 100 * g['RC_IC_JOB'].mean(), 'asr_four': 100 * g['RC_IC_JOB_CS'].mean()})
E = E.merge(asr, left_on='engine', right_index=True)
cls = {'decline': 'decrease', 'increase': 'increase', 'no clear change': 'inconclusive'}
Bn = pd.DataFrame(dict(engine=E.engine, n_pairs=E.n, asr_three=E.asr_three, asr_four=E.asr_four,
                       delta_pp=E.net_pp, adjusted_ci_low=E.bonf_lo, adjusted_ci_high=E.bonf_hi,
                       classification=E['class'].map(cls)))
assert len(Bn) == 70 and (Bn.n_pairs >= 500).all()
assert np.allclose(Bn.delta_pp, Bn.asr_four - Bn.asr_three, atol=1e-6)
assert ((Bn.classification == 'decrease') == (Bn.adjusted_ci_high < 0)).all()
assert ((Bn.classification == 'increase') == (Bn.adjusted_ci_low > 0)).all()
Bn = Bn.sort_values('delta_pp').reset_index(drop=True)
Bn.to_csv(os.path.join(FIG, 'engine_strategy_changes.csv'), index=False)
cnt = Bn.classification.value_counts()

# ---------- (b) plot ----------
STY = {'decrease': (ORANGE, 'v'), 'increase': (BLUE, '^'), 'inconclusive': (GRAY, 'o')}
BOLD = {'Avira', 'McAfeeD', 'F-Secure', 'DeepInstinct'}
fig, axs = plt.subplots(1, 2, figsize=(W, 4.7), sharex=True)
lo, hi = -45, 35
half = 35
for c, ax in enumerate(axs):
    d = Bn.iloc[c * half:(c + 1) * half].reset_index(drop=True)
    yy = np.arange(len(d))
    ax.axvline(0, color=GRAY, lw=0.8, zorder=1)
    for i, r in d.iterrows():
        col, mk = STY[r.classification]
        ax.plot([r.adjusted_ci_low, r.adjusted_ci_high], [i, i], color=col, lw=0.9, zorder=2,
                solid_capstyle='butt')
        ax.plot(r.delta_pp, i, marker=mk, ms=3.4, color=col, mec=col, zorder=3, ls='none')
    ax.set_yticks(yy)
    ax.set_yticklabels(d.engine, fontsize=7.5)
    for t, name in zip(ax.get_yticklabels(), d.engine):
        if name in BOLD: t.set_fontweight('bold')
    ax.set_ylim(len(d) - 0.4, -0.6)
    ax.set_xlim(lo, hi)
    ax.set_xticks([-40, -20, 0, 20])
    ax.tick_params(axis='y', length=0, pad=1.5)
    for s in ('top', 'right'): ax.spines[s].set_visible(False)
    ax.grid(axis='x', color='#EEEEEE', lw=0.5, zorder=0)
handles = [Line2D([], [], color=STY[k][0], marker=STY[k][1], ms=3.6, lw=0.9) for k in
           ('decrease', 'increase', 'inconclusive')]
labels = [f"{cnt.get('decrease', 0)} decreases", f"{cnt.get('increase', 0)} increases",
          f"{cnt.get('inconclusive', 0)} inconclusive"]
fig.legend(handles, labels, loc='upper center', bbox_to_anchor=(0.5, 1.0), ncol=3, frameon=False,
           handlelength=1.6, columnspacing=1.0, handletextpad=0.4)
fig.tight_layout(rect=(0, 0.045, 1, 0.97), w_pad=2.0)
x0, x1 = axs[0].get_position().x0, axs[1].get_position().x1
fig.text((x0 + x1) / 2, axs[0].get_position().y0 - 0.045, 'ASR change (percentage points)',
         ha='center', va='top', fontsize=9)
fig.savefig(os.path.join(FIG, 'engine_strategy_changes.pdf'))  # fixed W x H, no tight bbox
plt.close(fig)
print(cnt.to_dict())
print(A[['source', 'target', 'gain_count', 'loss_count', 'delta_pp', 'ci_low', 'ci_high']].round(2).to_string(index=False))
