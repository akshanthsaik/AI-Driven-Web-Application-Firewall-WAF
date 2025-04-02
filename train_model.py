import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Load processed features and labels
X = pd.read_csv('processed_features.csv')
y = pd.read_csv('labels.csv', header=None).squeeze("columns")  # Ensure labels are read correctly

# Ensure there are no NaN values
X = X.dropna()
y = y.iloc[:len(X)]  # Make sure y matches X in length

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Train RandomForest model
model = RandomForestClassifier(n_estimators=100, max_depth=5, random_state=42)
model.fit(X_train, y_train)

# Evaluate accuracy
print(f"Accuracy: {model.score(X_test, y_test):.2%}")

# Save model
joblib.dump(model, 'waf_model.pkl')
print("✅ Model training complete! Model saved as waf_model.pkl.")
