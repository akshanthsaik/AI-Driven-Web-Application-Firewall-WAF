import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, GridSearchCV
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, accuracy_score
import joblib
import os
from imblearn.over_sampling import SMOTE  # Handle class imbalance
import matplotlib.pyplot as plt

print("🔄 Starting model training...")

# Load processed features and labels
try:
    X = pd.read_csv('data/processed/processed_features.csv')
    y = pd.read_csv('data/processed/labels.csv')['label']  # Ensure correct column name
    print(f"✅ Loaded data: {X.shape[0]} samples with {X.shape[1]} features")
    print(f"✅ Label distribution: {y.value_counts().to_dict()}")
except Exception as e:
    print(f"❌ Error loading data: {e}")
    exit(1)

# Handle class imbalance using SMOTE
print("🔄 Applying SMOTE to handle class imbalance...")
smote = SMOTE(random_state=42)
X_resampled, y_resampled = smote.fit_resample(X, y)
print(f"✅ Resampled dataset: {X_resampled.shape[0]} samples (after SMOTE)")

# Train-test split
print("🔄 Splitting data into training and test sets...")
X_train, X_test, y_train, y_test = train_test_split(
    X_resampled, y_resampled, test_size=0.2, random_state=42, stratify=y_resampled
)
print(f"✅ Training set: {X_train.shape[0]} samples")
print(f"✅ Test set: {X_test.shape[0]} samples")

# Hyperparameter tuning using GridSearchCV
print("🔄 Performing hyperparameter tuning...")
param_grid = {
    'n_estimators': [100, 200, 300],
    'max_depth': [10, 15, 20],
    'min_samples_split': [2, 5],
    'min_samples_leaf': [1, 2],
    'max_features': ['sqrt', 'log2']
}
grid_search = GridSearchCV(
    RandomForestClassifier(random_state=42, class_weight='balanced', n_jobs=-1),
    param_grid,
    cv=3,
    scoring='accuracy',
    verbose=1,
)
grid_search.fit(X_train, y_train)
best_params = grid_search.best_params_
print(f"✅ Best hyperparameters: {best_params}")

# Train Random Forest model with best parameters
print("🔄 Training Random Forest model with optimized hyperparameters...")
model = RandomForestClassifier(
    n_estimators=best_params['n_estimators'],
    max_depth=best_params['max_depth'],
    min_samples_split=best_params['min_samples_split'],
    min_samples_leaf=best_params['min_samples_leaf'],
    max_features=best_params['max_features'],
    random_state=42,
    class_weight='balanced',
    n_jobs=-1
)
model.fit(X_train, y_train)
print("✅ Model training complete")

# Evaluate with cross-validation
cv_scores = cross_val_score(model, X_resampled, y_resampled, cv=5)
print(f"✅ Cross-validation scores: {cv_scores}")
print(f"✅ Mean CV accuracy: {cv_scores.mean():.4f} ± {cv_scores.std():.4f}")

# Evaluate on test set
y_pred = model.predict(X_test)
accuracy = accuracy_score(y_test, y_pred)
roc_auc = roc_auc_score(y_test, model.predict_proba(X_test)[:, 1])
print("\n📊 Test Set Evaluation:")
print(f"Accuracy: {accuracy:.4f}")
print(f"ROC-AUC Score: {roc_auc:.4f}")
print("\n📊 Classification Report:")
print(classification_report(y_test, y_pred))

print("\n📊 Confusion Matrix:")
conf_matrix = confusion_matrix(y_test, y_pred)
print(conf_matrix)

# Feature importance analysis
feature_importances = model.feature_importances_
importance_df = pd.DataFrame({
    'Feature': X.columns,
    'Importance': feature_importances
}).sort_values(by='Importance', ascending=False)

print("\n📊 Feature Importances:")
print(importance_df)

# Plot feature importances
plt.figure(figsize=(10, 6))
plt.barh(importance_df['Feature'], importance_df['Importance'], color='skyblue')
plt.title('Feature Importance')
plt.xlabel('Importance')
plt.ylabel('Features')
plt.gca().invert_yaxis()
plt.tight_layout()
plt.savefig('models/feature_importance.png')
plt.show()

# Save model
os.makedirs('models', exist_ok=True)
model_path = 'models/waf_model.pkl'
joblib.dump(model, model_path)
print(f"✅ Model saved to {os.path.abspath(model_path)}")
print("🔄 Model training process completed.")
