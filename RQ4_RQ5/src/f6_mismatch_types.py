# Supplementary table: mismatch types within the Table VIII common set (output of f5_b2paired.py).
# Shares are percentages of mismatched variant labels; all counts come from the same pairs as Table VIII.
import pandas as pd
T=pd.read_csv('results/B2_paired_vs_baseline.csv')
T['k']=T.variant.str.count(r'\+')+1
T=T.sort_values(['k','variant_pct']).reset_index(drop=True)
for c in ('generic','other_family','unclassified'): T[f'{c}_share']=100*T[f'variant_{c}']/T.variant_lost
T[['variant','n_common','variant_lost','variant_pct','variant_generic','variant_other_family','variant_unclassified',
   'generic_share','other_family_share','unclassified_share','baseline_lost','baseline_generic','baseline_other_family','baseline_unclassified']
 ].to_csv('results/B2_mismatch_types.csv',index=False)
f=lambda x:f'{int(x):,}'
L=[r'\begin{table}[t]',r'\centering',
   r'\caption{Family-label mismatch types among variant labels in the paired analysis cohort for each perturbation or strategy. '
   r'Type shares are percentages of mismatched variant labels.}',
   r'\label{tab:supp_mismatch_types}',
   r'\begin{tabular}{@{}lrrrrrr@{}}',r'\toprule',
   r' & & \multicolumn{2}{c}{Mismatches} & \multicolumn{3}{c}{Type share (\%)} \\',
   r'\cmidrule(lr){3-4}\cmidrule(l){5-7}',
   r'Perturbation/strategy & Pairs & $n$ & \% & Generic & Other family & Unclassified \\',r'\midrule']
prev=None
for _,r in T.iterrows():
    if prev is not None and r.k!=prev: L.append(r'\midrule')
    prev=r.k
    L.append(f"{r.variant} & {f(r.n_common)} & {f(r.variant_lost)} & {r.variant_pct:.2f} & {r.generic_share:.1f} & {r.other_family_share:.1f} & {r.unclassified_share:.1f} \\\\")
L+=[r'\bottomrule',r'\end{tabular}',r'\end{table}']
open('results/B2_mismatch_types.tex','w').write('\n'.join(L)+'\n')
print('\n'.join(L))
