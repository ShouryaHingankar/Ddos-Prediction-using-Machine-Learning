import pandas as pd

# Use the exact path you have
df = pd.read_parquet("data/train/LDAP-training.parquet")
df.columns = [str(c).strip().lower() for c in df.columns]

print("Total rows:", len(df))
print("Columns:", list(df.columns)[:5], "...")

if 'label' in df.columns:
    print("\nLabel counts:")
    print(df['label'].value_counts())
else:
    print("\nERROR: No 'label' column found!")