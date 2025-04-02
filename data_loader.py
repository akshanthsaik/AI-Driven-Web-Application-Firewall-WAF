import pandas as pd

# Load dataset, handling extra comma
data = pd.read_csv('csic_database.csv', encoding='latin1')

# Rename first column if needed (check dataset manually)
data.rename(columns={data.columns[0]: "classification"}, inplace=True)

# Debug: Check classification column
print("DataFrame shape:", data.shape)
print("Column names:", data.columns)
print("Classification type:", type(data['classification']))

# Ensure classification is a single column
data['label'] = data['classification'].copy()
 # Convert DataFrame to Series if needed

# Map classification to binary labels
data['label'] = data['classification']

# Feature extraction from 'content' (or relevant columns)
data['payload'] = data['content'].fillna('')

X = pd.DataFrame({
    'length': data['payload'].apply(lambda x: len(str(x))),
    'num_semicolons': data['payload'].apply(lambda x: str(x).count(';')),
    'has_sql_keywords': data['payload'].apply(lambda x: int(any(kw in str(x).upper() for kw in ['SELECT', 'UNION', 'DROP', '1=1'])))
})

y = data['label']

# Save processed data
X.to_csv('processed_features.csv', index=False)
y.to_csv('labels.csv', index=False, header=True)

print("✅ Data successfully processed and saved!")
