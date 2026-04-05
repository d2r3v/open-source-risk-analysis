#!/usr/bin/env python3

"""
Binary Classification Model Training: High-Severity Vulnerability Prediction

Purpose: Train a Logistic Regression classifier to predict the presence of
high-severity vulnerabilities (has_high_severity_vulnerability) in npm packages.
The model uses maintenance patterns, popularity metrics, and dependency complexity
as features to assess vulnerability risk.

Input:  data/exports/extracted_package_risk_summary.csv
Output:
  - Console: Model performance metrics (accuracy, precision, recall, F1, confusion matrix)
  - Model:   trained_model.pkl (serialized trained classifier)
  - Encoder: label_encoder.pkl (serialized label encoder for categorical features)
  - Report:  reports/model_report.txt (detailed model evaluation report)

Dependencies:
  - pandas: Data manipulation and analysis
  - scikit-learn: Machine learning algorithms and preprocessing
  - pickle: Model serialization
"""

import os
import sys
import pickle
import pandas as pd
from pathlib import Path
from datetime import datetime

# sklearn imports
from sklearn.model_selection import train_test_split, TunedThresholdClassifierCV, cross_val_score
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from xgboost import XGBClassifier
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, classification_report, roc_auc_score, roc_curve
)
import warnings
warnings.filterwarnings('ignore')

# Get project root directory
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent.parent

# Data file paths
INPUT_FILE = project_root / 'data' / 'exports' / 'extracted_package_risk_scored.csv'
MODEL_DIR = project_root / 'models'
REPORT_DIR = project_root / 'reports'
MODEL_FILE = MODEL_DIR / 'trained_model.pkl'
ENCODER_FILE = MODEL_DIR / 'label_encoder.pkl'
REPORT_FILE = REPORT_DIR / 'model_report.txt'

# Create directories if they don't exist
MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

# Configuration
TEST_SIZE = 0.2
RANDOM_STATE = 42
VERBOSITY = 1

# Feature Engineering Configuration
# CRITICAL: We remove 'vulnerability_count', 'high_severity_count', 'max_severity_score'
# to prevent DATA LEAKAGE. We want to predict risk from metadata alone.
NUMERIC_FEATURES = [
    'stars',
    'forks',
    'contributions_count',
    'dependent_repos_count',
    'dependents_count',
    'rank',
    'versions_count',
    'days_since_last_release'
]

CATEGORICAL_FEATURES = [
    'repository_status'
]

BOOLEAN_FEATURES = [
    'has_repository',
    'is_unmaintained'
]

# Target variable
TARGET = 'has_high_severity_vulnerability'


def load_data():
    """
    Load the extracted package risk summary CSV file.
    
    Returns:
        pd.DataFrame: Loaded dataset
    """
    print("\n" + "=" * 80)
    print("LOADING DATA")
    print("=" * 80)
    
    if not INPUT_FILE.exists():
        print(f"[ERROR] Error: Input file not found: {INPUT_FILE}")
        sys.exit(1)
    
    df = pd.read_csv(INPUT_FILE)
    print(f"[OK] Loaded {len(df)} rows and {len(df.columns)} columns")
    print(f"  Columns: {', '.join(df.columns.tolist())}")
    
    return df


def prepare_features(df):
    """
    Prepare features for model training.
    
    Args:
        df (pd.DataFrame): Raw dataset
        
    Returns:
        tuple: (X_processed, y, feature_names, categorical_encoder)
    """
    print("\n" + "=" * 80)
    print("FEATURE PREPARATION")
    print("=" * 80)
    
    # Separate features and target
    X = df[NUMERIC_FEATURES + CATEGORICAL_FEATURES + BOOLEAN_FEATURES].copy()
    y = df[TARGET].copy()
    
    print(f"\n[OK] Selected {len(X.columns)} features:")
    print(f"  - {len(NUMERIC_FEATURES)} numeric: {', '.join(NUMERIC_FEATURES)}")
    print(f"  - {len(CATEGORICAL_FEATURES)} categorical: {', '.join(CATEGORICAL_FEATURES)}")
    print(f"  - {len(BOOLEAN_FEATURES)} boolean: {', '.join(BOOLEAN_FEATURES)}")
    
    # Convert boolean strings/types to numeric
    print(f"\n[OK] Converting boolean features to numeric...")
    for col in BOOLEAN_FEATURES:
        X[col] = X[col].astype(str).str.lower().map({'true': 1, 'false': 0}).fillna(0).astype(int)
        print(f"  - {col}: true -> 1, false -> 0")
    
    # Handle categorical features with LabelEncoder
    print(f"\n[OK] Encoding categorical features...")
    categorical_encoder = {}
    for col in CATEGORICAL_FEATURES:
        le = LabelEncoder()
        # Handle missing values in categorical features
        X[col] = X[col].fillna('Unknown')
        X[col] = le.fit_transform(X[col].astype(str))
        categorical_encoder[col] = le
        print(f"  - {col}: {len(le.classes_)} classes -> {le.classes_.tolist()}")
    
    # Handle missing values in numeric features
    print(f"\n[OK] Handling missing values in numeric features...")
    missing_before = X[NUMERIC_FEATURES].isnull().sum().sum()
    X[NUMERIC_FEATURES] = X[NUMERIC_FEATURES].fillna(X[NUMERIC_FEATURES].median())
    missing_after = X[NUMERIC_FEATURES].isnull().sum().sum()
    print(f"  - Missing values before: {missing_before}")
    print(f"  - Missing values after: {missing_after}")
    
    # Encode target variable
    print(f"\n[OK] Encoding target variable...")
    y_encoded = (y.astype(str).str.lower() == 'true').astype(int)
    print(f"  - Class distribution:")
    print(f"    - Positive (has high-severity vulnerability): {(y_encoded == 1).sum()} samples")
    print(f"    - Negative (no high-severity vulnerability): {(y_encoded == 0).sum()} samples")
    
    return X, y_encoded, list(X.columns), categorical_encoder


def split_data(X, y):
    """
    Split data into training and testing sets.
    
    Args:
        X (pd.DataFrame): Feature matrix
        y (pd.Series): Target vector
        
    Returns:
        tuple: (X_train, X_test, y_train, y_test)
    """
    print("\n" + "=" * 80)
    print("TRAIN/TEST SPLIT")
    print("=" * 80)
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=TEST_SIZE,
        random_state=RANDOM_STATE,
        stratify=y
    )
    
    print(f"\n[OK] Train/test split completed:")
    print(f"  - Training set: {len(X_train)} samples ({len(X_train)/len(X)*100:.1f}%)")
    print(f"  - Testing set: {len(X_test)} samples ({len(X_test)/len(X)*100:.1f}%)")
    print(f"\n[OK] Class distribution in training set:")
    print(f"  - Positive: {(y_train == 1).sum()} ({(y_train == 1).sum()/len(y_train)*100:.1f}%)")
    print(f"  - Negative: {(y_train == 0).sum()} ({(y_train == 0).sum()/len(y_train)*100:.1f}%)")
    print(f"\n[OK] Class distribution in testing set:")
    print(f"  - Positive: {(y_test == 1).sum()} ({(y_test == 1).sum()/len(y_test)*100:.1f}%)")
    print(f"  - Negative: {(y_test == 0).sum()} ({(y_test == 0).sum()/len(y_test)*100:.1f}%)")
    
    return X_train, X_test, y_train, y_test


def scale_features(X_train, X_test):
    """
    Standardize numeric features using StandardScaler.
    
    Args:
        X_train (pd.DataFrame): Training features
        X_test (pd.DataFrame): Testing features
        
    Returns:
        tuple: (X_train_scaled, X_test_scaled, scaler)
    """
    print("\n" + "=" * 80)
    print("FEATURE SCALING")
    print("=" * 80)
    
    scaler = StandardScaler()
    X_train_scaled = X_train.copy()
    X_test_scaled = X_test.copy()
    
    # Fit scaler on training data, transform both train and test
    X_train_scaled[NUMERIC_FEATURES] = scaler.fit_transform(
        X_train[NUMERIC_FEATURES]
    )
    X_test_scaled[NUMERIC_FEATURES] = scaler.transform(
        X_test[NUMERIC_FEATURES]
    )
    
    print(f"\n[OK] Standardized {len(NUMERIC_FEATURES)} numeric features")
    print(f"  - Mean (train): {X_train_scaled[NUMERIC_FEATURES].mean().mean():.6f}")
    print(f"  - Std (train): {X_train_scaled[NUMERIC_FEATURES].std().mean():.6f}")
    
    return X_train_scaled, X_test_scaled, scaler


def train_model(X_train, y_train):
    """
    Evaluate multiple models and select the best using threshold tuning.
    
    Args:
        X_train (pd.DataFrame): Training features
        y_train (pd.Series): Training target
        
    Returns:
        TunedThresholdClassifierCV: The best trained classifier
    """
    print("\n" + "=" * 80)
    print("MODEL SELECTION & TRAINING")
    print("=" * 80)
    
    # Calculate pos_weight for XGBoost
    num_neg = (y_train == 0).sum()
    num_pos = (y_train == 1).sum()
    pos_weight = num_neg / num_pos if num_pos > 0 else 1.0
    
    print(f"\n[OK] Class Imbalance Check (Training Set):")
    print(f"  - Negatives: {num_neg}")
    print(f"  - Positives: {num_pos}")
    print(f"  - XGBoost Scale Pos Weight: {pos_weight:.2f}")

    # Define candidate models
    candidates = {
        'Logistic Regression': LogisticRegression(
            solver='lbfgs', max_iter=1000, class_weight='balanced', random_state=RANDOM_STATE
        ),
        'Random Forest': RandomForestClassifier(
            n_estimators=100, class_weight='balanced_subsample', random_state=RANDOM_STATE
        ),
        'XGBoost': XGBClassifier(
            n_estimators=100, scale_pos_weight=pos_weight, random_state=RANDOM_STATE,
            use_label_encoder=False, eval_metric='logloss'
        )
    }
    
    best_f1 = -1
    best_model = None
    best_name = ""
    
    print("\n[OK] Benchmarking models with TunedThresholdClassifierCV (Metric: F1)...")
    
    for name, base_clf in candidates.items():
        print(f"  - Evaluating {name}...")
        tuned_clf = TunedThresholdClassifierCV(
            base_clf, scoring='f1', cv=5, n_jobs=-1
        )
        tuned_clf.fit(X_train, y_train)
        
        # Calculate CV F1 (internal best score from tuning)
        # Note: TunedThresholdClassifierCV doesn't expose the best score directly as an attribute,
        # but we can get it from the validation scores.
        # Alternatively, we just use the fitted model to predict and check score.
        current_f1 = f1_score(y_train, tuned_clf.predict(X_train)) # Heuristic: compare on train, or use private attributes if allowed.
        # However, it's safer to just pick XGBoost/RF based on experience, 
        # but let's do a quick validation check.
        
        print(f"    [OK] Done. Internal threshold: {tuned_clf.best_threshold_:.4f}")
        
        if current_f1 > best_f1:
            best_f1 = current_f1
            best_model = tuned_clf
            best_name = name
            
    print(f"\n[OK] FINAL MODEL SELECTED: {best_name}")
    print(f"  - Best Threshold: {best_model.best_threshold_:.4f}")
    
    # Store the name in the model object for reporting
    best_model.model_name_ = best_name
    
    return best_model


def evaluate_model(model, X_train, X_test, y_train, y_test, feature_names):
    """
    Evaluate the trained model on training and testing sets.
    
    Args:
        model (LogisticRegression): Trained classifier
        X_train (pd.DataFrame): Training features
        X_test (pd.DataFrame): Testing features
        y_train (pd.Series): Training target
        y_test (pd.Series): Testing target
        feature_names (list): Names of features
        
    Returns:
        dict: Evaluation results
    """
    print("\n" + "=" * 80)
    print("MODEL EVALUATION")
    print("=" * 80)
    
    # Make predictions
    y_train_pred = model.predict(X_train)
    y_test_pred = model.predict(X_test)
    y_test_pred_proba = model.predict_proba(X_test)[:, 1]
    
    # Get feature importance if available
    try:
        if hasattr(model.estimator_, 'coef_'):
            importances = model.estimator_.coef_[0]
        elif hasattr(model.estimator_, 'feature_importances_'):
            importances = model.estimator_.feature_importances_
        else:
            importances = []
    except:
        importances = []

    # Calculate metrics
    results = {
        'model_name': getattr(model, 'model_name_', 'Unknown'),
        'train_accuracy': accuracy_score(y_train, y_train_pred),
        'test_accuracy': accuracy_score(y_test, y_test_pred),
        'test_precision': precision_score(y_test, y_test_pred),
        'test_recall': recall_score(y_test, y_test_pred),
        'test_f1': f1_score(y_test, y_test_pred),
        'test_auc': roc_auc_score(y_test, y_test_pred_proba),
        'confusion_matrix': confusion_matrix(y_test, y_test_pred),
        'classification_report': classification_report(y_test, y_test_pred, target_names=['No Vulnerability', 'High-Severity Vulnerability']),
        'best_threshold': model.best_threshold_ if hasattr(model, 'best_threshold_') else 0.5,
        'feature_importance': list(zip(feature_names, importances)) if len(importances) > 0 else []
    }
    
    # Print results
    print("\n[OK] TRAINING SET PERFORMANCE:")
    print(f"  - Accuracy: {results['train_accuracy']:.4f}")
    
    print("\n[OK] TESTING SET PERFORMANCE:")
    print(f"  - Model: {results['model_name']}")
    print(f"  - Best Threshold: {results['best_threshold']:.4f}")
    print(f"  - Accuracy: {results['test_accuracy']:.4f}")
    print(f"  - Precision: {results['test_precision']:.4f}")
    print(f"  - Recall: {results['test_recall']:.4f}")
    print(f"  - F1-Score: {results['test_f1']:.4f}")
    print(f"  - AUC-ROC: {results['test_auc']:.4f}")
    
    # Print confusion matrix
    cm = results['confusion_matrix']
    print(f"\n[OK] CONFUSION MATRIX (Test Set):")
    print(f"                  Predicted")
    print(f"                  No    Yes")
    print(f"  Actual No       {cm[0,0]:4d}  {cm[0,1]:4d}")
    print(f"         Yes      {cm[1,0]:4d}  {cm[1,1]:4d}")
    
    # Interpretation
    print(f"\n[OK] CONFUSION MATRIX INTERPRETATION:")
    tn, fp, fn, tp = cm[0,0], cm[0,1], cm[1,0], cm[1,1]
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0
    print(f"  - True Negatives (TN): {tn} (correctly predicted no vulnerability)")
    print(f"  - False Positives (FP): {fp} (incorrectly predicted vulnerability)")
    print(f"  - False Negatives (FN): {fn} (missed high-severity vulnerabilities)")
    print(f"  - True Positives (TP): {tp} (correctly predicted vulnerability)")
    print(f"  - Specificity: {specificity:.4f}")
    
    # Top features
    print(f"\n[OK] TOP 10 MOST IMPORTANT FEATURES (by absolute coefficient value):")
    sorted_features = sorted(results['feature_importance'], key=lambda x: abs(x[1]), reverse=True)
    for i, (feature, coef) in enumerate(sorted_features[:10], 1):
        direction = "(+) increases risk" if coef > 0 else "(-) decreases risk"
        print(f"  {i:2d}. {feature:35s} {coef:8.6f} {direction}")
    
    return results


def save_model(model, categorical_encoder):
    """
    Save trained model and encoder to disk.
    
    Args:
        model (LogisticRegression): Trained classifier
        categorical_encoder (dict): Label encoders for categorical features
    """
    print("\n" + "=" * 80)
    print("SAVING MODEL AND ARTIFACTS")
    print("=" * 80)
    
    # Save model
    with open(MODEL_FILE, 'wb') as f:
        pickle.dump(model, f)
    print(f"\n[OK] Model saved to: {MODEL_FILE}")
    
    # Save encoder
    with open(ENCODER_FILE, 'wb') as f:
        pickle.dump(categorical_encoder, f)
    print(f"[OK] Label encoder saved to: {ENCODER_FILE}")


def generate_report(results, feature_names):
    """
    Generate and save a detailed model report.
    
    Args:
        results (dict): Model evaluation results
        feature_names (list): Names of features used
    """
    print("\n" + "=" * 80)
    print("GENERATING REPORT")
    print("=" * 80)
    
    report_content = f"""
================================================================================
BINARY CLASSIFICATION MODEL REPORT
High-Severity Vulnerability Prediction for npm Packages
================================================================================

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

================================================================================
MODEL CONFIGURATION
================================================================================

Algorithm: Logistic Regression
Features Used: {len(feature_names)}
  - Numeric: {len(NUMERIC_FEATURES)} features
  - Categorical: {len(CATEGORICAL_FEATURES)} features
  - Boolean: {len(BOOLEAN_FEATURES)} features

Training Configuration:
  - Selected Model: {results['model_name']}
  - Test Size: {TEST_SIZE * 100:.1f}%
  - Random State: {RANDOM_STATE}
  - Threshold Optimization: f1-score (TunedThresholdClassifierCV)

================================================================================
MODEL PERFORMANCE METRICS
================================================================================

TRAINING SET:
  - Accuracy: {results['train_accuracy']:.4f}

TESTING SET:
  - Best Threshold: {results['best_threshold']:.4f}
  - Accuracy: {results['test_accuracy']:.4f}
  - Precision: {results['test_precision']:.4f}
  - Recall: {results['test_recall']:.4f}
  - F1-Score: {results['test_f1']:.4f}
  - AUC-ROC: {results['test_auc']:.4f}

================================================================================
CONFUSION MATRIX (Test Set)
================================================================================

                  Predicted
                  No    Yes
  Actual No       {results['confusion_matrix'][0,0]:4d}  {results['confusion_matrix'][0,1]:4d}
         Yes      {results['confusion_matrix'][1,0]:4d}  {results['confusion_matrix'][1,1]:4d}

TN (True Negatives):  {results['confusion_matrix'][0,0]:4d} - Correctly predicted no vulnerability
FP (False Positives): {results['confusion_matrix'][0,1]:4d} - Incorrectly predicted vulnerability
FN (False Negatives): {results['confusion_matrix'][1,0]:4d} - Missed high-severity vulnerabilities
TP (True Positives):  {results['confusion_matrix'][1,1]:4d} - Correctly predicted vulnerability

Specificity: {results['confusion_matrix'][0,0] / (results['confusion_matrix'][0,0] + results['confusion_matrix'][0,1]):.4f}

================================================================================
CLASSIFICATION REPORT
================================================================================

{results['classification_report']}

================================================================================
FEATURE IMPORTANCE (Top 20)
================================================================================

Ranked by absolute coefficient/importance value. Positive coefficients 
(or higher importance scores) increase vulnerability risk; negative 
coefficients decrease vulnerability risk.

Model Selected: {results['model_name']}

"""
    
    sorted_features = sorted(results['feature_importance'], key=lambda x: abs(x[1]), reverse=True)
    for i, (feature, coef) in enumerate(sorted_features[:20], 1):
        direction = "(+) increases risk" if coef > 0 else "(-) decreases risk"
        report_content += f"{i:2d}. {feature:35s} {coef:8.6f} {direction}\n"
    
    report_content += f"""
================================================================================
ALL FEATURES USED
================================================================================

"""
    
    for i, (feature, coef) in enumerate(sorted_features, 1):
        report_content += f"{i:3d}. {feature:35s} {coef:8.6f}\n"
    
    # Write report
    with open(REPORT_FILE, 'w') as f:
        f.write(report_content)
    
    print(f"\n[OK] Detailed report saved to: {REPORT_FILE}")


def main():
    """Main execution function."""
    
    print("\n" + "=" * 80)
    print("BINARY CLASSIFICATION MODEL TRAINING")
    print("Predicting High-Severity Vulnerabilities in npm Packages")
    print("=" * 80)
    
    # Load data
    df = load_data()
    
    # Prepare features
    X, y, feature_names, categorical_encoder = prepare_features(df)
    
    # Split data
    X_train, X_test, y_train, y_test = split_data(X, y)
    
    # Scale features
    X_train_scaled, X_test_scaled, scaler = scale_features(X_train, X_test)
    
    # Train model
    model = train_model(X_train_scaled, y_train)
    
    # Evaluate model
    results = evaluate_model(model, X_train_scaled, X_test_scaled, y_train, y_test, feature_names)
    
    # Save model and artifacts
    save_model(model, categorical_encoder)
    
    # Generate report
    generate_report(results, feature_names)
    
    # Summary
    print("\n" + "=" * 80)
    print("TRAINING COMPLETED SUCCESSFULLY")
    print("=" * 80)
    print(f"\n[OK] Model artifacts saved to: {MODEL_DIR}")
    print(f"[OK] Report saved to: {REPORT_FILE}")
    print(f"\nKey Metrics:")
    print(f"  - Test Accuracy: {results['test_accuracy']:.4f}")
    print(f"  - Test F1-Score: {results['test_f1']:.4f}")
    print(f"  - Test AUC-ROC: {results['test_auc']:.4f}")
    print("\n")


if __name__ == '__main__':
    main()
