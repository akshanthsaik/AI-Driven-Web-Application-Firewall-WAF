import pandas as pd

data = pd.read_csv('csic_database.csv', encoding='latin1')

# Print all column names
print("Column Names:", list(data.columns))

# Check unique values in 'classification'
if 'classification' in data.columns:
    print("Unique classification values:", data['classification'].unique())
else:
    print("❌ 'classification' column NOT found!")
