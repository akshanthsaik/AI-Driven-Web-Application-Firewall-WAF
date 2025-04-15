import pandas as pd

def load_data():
    # Load dataset
    try:
        df = pd.read_csv('data/raw/csic_database.csv', encoding='latin1')
        print("✅ Dataset loaded successfully")
    except Exception as e:
        print(f"❌ Error loading dataset: {e}")
        exit(1)

    # Debugging information
    print(f"📊 DataFrame shape: {df.shape}")
    print(f"🔍 Column names: {df.columns}")
    print(f"🏷️ Classification values: {df['classification'].unique()}")

    # Handle missing values
    df.fillna({
        "content-type": "UNKNOWN",
        "length": 0,
        "content": "UNKNOWN",
        "Accept": "UNKNOWN"
    }, inplace=True)

    # Convert classification to binary (0 = normal, 1 = attack)
    df['label'] = df['classification'].apply(lambda x: 1 if str(x).strip() != '0' else 0)

    # Combine URL and content for payload analysis
    df['payload'] = df['URL'].fillna('') + df['content'].fillna('')

    # Feature extraction
    X = pd.DataFrame({
        'length': df['payload'].apply(lambda x: len(str(x))),
        'num_semicolons': df['payload'].apply(lambda x: str(x).count(';')),
        'has_sql_keywords': df['payload'].apply(lambda x: int(any(
            kw in str(x).upper() for kw in ['SELECT', 'UNION', 'DROP', '1=1', "' OR '", '" OR "', '--']
        ))),
        'num_special_chars': df['payload'].apply(lambda x: sum(c in "!@#$%^&*()+={}[]|\\:;\"'<>,?/" for c in str(x))),
        'has_http_methods': df['payload'].apply(lambda x: int(any(
            method in str(x).upper() for method in ['GET', 'POST', 'PUT', 'DELETE']
        )))
    })

    y = df['label']

    # Handle missing values
    X.fillna(0, inplace=True)
    y.fillna(0, inplace=True)

    # Save processed data
    X.to_csv('data/processed/processed_features.csv', index=False)
    y.to_csv('data/processed/labels.csv', index=False, header=True)

    print(f"✅ Data successfully processed and saved!")
    print(f"✅ Features shape: {X.shape}, Labels shape: {y.shape}")
    print(f"✅ Positive examples (attacks): {sum(y == 1)}, Negative examples (normal): {sum(y == 0)}")

    return X, y  # Returning for direct use in training

# Run the function if script is executed directly
if __name__ == "__main__":
    load_data()
