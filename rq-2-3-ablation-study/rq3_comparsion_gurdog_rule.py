import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import glob

# 1. Load and concatenate CSVs
csv_files = ["../results/guarddog-temporal/guarddog_large_findings_npm_io.csv" ,"../results/guarddog-temporal/guarddog_large_findings_temporal.csv"]

df = pd.concat([pd.read_csv(f) for f in csv_files], ignore_index=True)

sns.set_theme(style="whitegrid")

# 2. Sirf obfuscation, mangling ya usse related rules ko filter karein
obfuscation_filter = df['rule'].str.contains('obfuscation|mangling|eval|encoded', case=False, na=False)
obf_df = df[obfuscation_filter]

if not obf_df.empty:
    # Benign aur Malicious ke liye relative frequency nikalein
    group_rel_freq = obf_df.groupby('label')['rule'].value_counts(normalize=True).unstack(fill_value=0).T
    
    # 3. Focused Grouped Bar Chart (Comparison ke liye)
    plt.figure(figsize=(10, max(6, len(group_rel_freq) * 0.5)))
    group_rel_freq.plot(kind='barh', figsize=(10, max(6, len(group_rel_freq) * 0.5)), width=0.7, edgecolor='black', colormap='Set2')
    
    plt.xlabel('Relative Frequency', fontsize=12, fontweight='bold')
    plt.ylabel('Obfuscation & Mangling Rules', fontsize=12, fontweight='bold')
    # plt.title('Targeted Comparison: Obfuscation Rules (Benign vs Malicious)', fontsize=14, fontweight='bold')
    plt.gca().invert_yaxis()
    plt.grid(axis='x', linestyle='--', alpha=0.7)
    plt.legend(title='Corpus / Label', loc='upper right')
    plt.tight_layout()
    
    # Vector PDF format mein save karein for LaTeX paper
    plt.savefig('../results/obfuscation_rules_comparison.pdf', format='pdf', bbox_inches='tight')
    plt.show()
    print("Obfuscation rules comparison plot successfully generated and saved!")
else:
    print("Dataset mein is keyword se milte-julte koi rules nahi mile. Rule ka exact naam check karein.")