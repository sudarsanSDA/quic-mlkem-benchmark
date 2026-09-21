import pandas as pd
df = pd.read_csv('benchmark_results.csv')
summary = df.groupby(['Cipher', 'Target_RTT', 'Target_Loss'])['HCT_ms'].agg(
    mean='mean', std='std', median='median',
    p95=lambda x: x.quantile(0.95),
    p99=lambda x: x.quantile(0.99)
).reset_index()
print(summary.to_string(index=False))
