import os
import logging
import json
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.metrics import (classification_report, confusion_matrix, 
                            roc_auc_score, f1_score, accuracy_score, precision_recall_curve)
from skopt import BayesSearchCV
from imblearn.over_sampling import SMOTE
import joblib
import shap
import matplotlib.pyplot as plt

# Configuration
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Paths (hardcoded for consistency)
DATA_DIR = 'data/processed'
MODEL_DIR = 'models'
FEATURES_FILE = os.path.join(DATA_DIR, 'processed_features.csv')
LABELS_FILE = os.path.join(DATA_DIR, 'labels.csv')
MODEL_PATH = os.path.join(MODEL_DIR, 'waf_model.pkl')
FEATURE_IMPORTANCE_PLOT = os.path.join(MODEL_DIR, 'feature_importance.png')
PRECISION_RECALL_PLOT = os.path.join(MODEL_DIR, 'precision_recall_curve.png')

# Ensure directories exist
os.makedirs(MODEL_DIR, exist_ok=True)

# Constants
RANDOM_STATE = 42

def load_data():
    try:
        X = pd.read_csv(FEATURES_FILE)
        y = pd.read_csv(LABELS_FILE)['label']
        
        # Validate data integrity
        assert X.shape[0] == y.shape[0], "Feature/label count mismatch"
        assert not X.isnull().any().any(), "NaN values in features"
        
        logger.info(f"Loaded {X.shape[0]} samples with {X.shape[1]} features")
        logger.info(f"Class distribution:\n{y.value_counts()}")
        
        return X, y
    
    except Exception as e:
        logger.error(f"Data loading failed: {str(e)}")
        raise

def handle_imbalance(X, y):
    class_ratio = y.value_counts().min() / y.value_counts().max()
    if class_ratio < 0.3:
        logger.info("Applying SMOTE for class imbalance...")
        return SMOTE(random_state=RANDOM_STATE).fit_resample(X, y)
    else:
        logger.info("Class distribution acceptable, skipping SMOTE")
        return X, y

def train_model(X_train, y_train):
    param_space = {
        'n_estimators': (100, 500),
        'max_depth': [10, 20, 30, None],
        'min_samples_split': (2, 10),
        'min_samples_leaf': (1, 4),
        'max_features': ['sqrt', 'log2']
    }
    
    model = BayesSearchCV(
        estimator=RandomForestClassifier(
            class_weight='balanced',
            random_state=RANDOM_STATE,
            n_jobs=-1
        ),
        search_spaces=param_space,
        n_iter=50,
        scoring='roc_auc',
        cv=StratifiedKFold(n_splits=3),
        random_state=RANDOM_STATE,
        verbose=2
    )
    
    logger.info(" Starting Bayesian hyperparameter optimization...")
    model.fit(X_train, y_train)
    
    logger.info(f"Best params: {model.best_params_}")
    logger.info(f"Best CV AUC: {model.best_score_:.4f}")
    
    return model.best_estimator_

def evaluate_model(model, X_test, y_test):
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)[:, 1]
    
    metrics = {
        'accuracy': accuracy_score(y_test, y_pred),
        'roc_auc': roc_auc_score(y_test, y_proba),
        'f1': f1_score(y_test, y_pred),
        'confusion_matrix': confusion_matrix(y_test, y_pred).tolist(),
        'classification_report': classification_report(y_test, y_pred)
    }

    precision, recall, _ = precision_recall_curve(y_test, y_proba)
    plt.figure()
    plt.plot(recall, precision, marker='.')
    plt.xlabel('Recall')
    plt.ylabel('Precision')
    plt.title('Precision-Recall Curve')
    plt.savefig(PRECISION_RECALL_PLOT)
    plt.close()
    
    return metrics

def explain_model(model, X_test):
    try:
        explainer = shap.TreeExplainer(model)
        shap_values = explainer.shap_values(X_test)
        
        plt.figure()
        shap.summary_plot(shap_values[1], X_test, show=False)
        plt.savefig(FEATURE_IMPORTANCE_PLOT)
        plt.close()
        
    except Exception as e:
        logger.warning(f" SHAP explanation failed: {str(e)}")

def save_artifacts(model):
    joblib.dump(model, MODEL_PATH)
    logger.info(f" Model saved to {MODEL_PATH}")

def main():
    logger.info(" Starting WAF model training pipeline")
    
    try:
        # Data pipeline
        X, y = load_data()
        X_resampled, y_resampled = handle_imbalance(X, y)
        
        # Train-test split
        X_train, X_test, y_train, y_test = train_test_split(
            X_resampled,
            y_resampled,
            test_size=0.2,
            stratify=y_resampled,
            random_state=RANDOM_STATE
        )
        
        # Model training
        model = train_model(X_train, y_train)
        
        # Evaluation
        metrics = evaluate_model(model, X_test, y_test)
        
        logger.info(f"\n Final Metrics:\n"
                    f"Accuracy: {metrics['accuracy']:.4f}\n"
                    f"ROC-AUC: {metrics['roc_auc']:.4f}\n"
                    f"F1-Score: {metrics['f1']:.4f}")
        
        explain_model(model, X_test)
        save_artifacts(model)
        
        logger.info(" Training pipeline completed successfully")
        
    except Exception as e:
        logger.error(f" Pipeline failed: {str(e)}")
        
if __name__ == "__main__":
    main()
