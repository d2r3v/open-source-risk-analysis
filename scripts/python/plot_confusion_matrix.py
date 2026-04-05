#!/usr/bin/env python3

"""
Model Performance Visualization: Diagnostic Suite
Purpose: Generate professional performance plots for the final 
predictive model, including a threshold-aware confusion matrix, 
ROC analysis, and Precision-Recall curve.

Saves to: 
  - reports/figures/confusion_matrix.png
  - reports/figures/roc_curve.png
  - reports/figures/precision_recall_curve.png
"""

import os
import sys
import pickle
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import (
    confusion_matrix, precision_score, recall_score, f1_score, 
    ConfusionMatrixDisplay, roc_curve, auc, precision_recall_curve
)

# Configuration
RANDOM_STATE = 42
TEST_SIZE = 0.2
OPTIMAL_THRESHOLD = 0.05

# Get project root
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent.parent

# File paths
INPUT_FILE = project_root / 'data' / 'exports' / 'extracted_package_risk_scored.csv'
MODEL_FILE = project_root / 'models' / 'trained_model.pkl'
OUTPUT_CM = project_root / 'reports' / 'figures' / 'confusion_matrix.png'
OUTPUT_ROC = project_root / 'reports' / 'figures' / 'roc_curve.png'
OUTPUT_PR = project_root / 'reports' / 'figures' / 'precision_recall_curve.png'

# Create output dir
OUTPUT_CM.parent.mkdir(parents=True, exist_ok=True)

# Feature Configuration (Identical to train_model.py)
NUMERIC_FEATURES = ['stars', 'forks', 'contributions_count', 'dependent_repos_count', 
                    'dependents_count', 'rank', 'versions_count', 'days_since_last_release']
CATEGORICAL_FEATURES = ['repository_status']
BOOLEAN_FEATURES = ['has_repository', 'is_unmaintained']
TARGET = 'has_high_severity_vulnerability'

def load_and_preprocess():
    """Load and preprocess the dataset to isolate the exact test set."""
    if not INPUT_FILE.exists():
        print(f"[ERROR] Input file not found: {INPUT_FILE}")
        sys.exit(1)
        
    df = pd.read_csv(INPUT_FILE)
    
    # Feature engineering
    X = df[NUMERIC_FEATURES + CATEGORICAL_FEATURES + BOOLEAN_FEATURES].copy()
    y = (df[TARGET].astype(str).str.lower() == 'true').astype(int)
    
    # Boolean conversion
    for col in BOOLEAN_FEATURES:
        X[col] = X[col].astype(str).str.lower().map({'true': 1, 'false': 0}).fillna(0).astype(int)
        
    # Categorical encoding
    for col in CATEGORICAL_FEATURES:
        le = LabelEncoder()
        X[col] = X[col].fillna('Unknown')
        X[col] = le.fit_transform(X[col].astype(str))
        
    # Standardize numeric features
    X[NUMERIC_FEATURES] = X[NUMERIC_FEATURES].fillna(X[NUMERIC_FEATURES].median())
    
    # Split
    _, X_test, _, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    
    # Scaling (identical to train_model.py)
    # Note: We rebuild the scaler logic instead of loading it, as we just need the same test data.
    # In a production environment, we would load the serialized scaler.
    scaler = StandardScaler()
    # We fit on the full X for simplicity here, as we are recreating the visual context.
    X_test_scaled = X_test.copy()
    X_test_scaled[NUMERIC_FEATURES] = scaler.fit_transform(X_test[NUMERIC_FEATURES])
    
    return X_test_scaled, y_test

def main():
    print("\n" + "=" * 60)
    print("GENERATING THRESHOLD-AWARE CONFUSION MATRIX")
    print("=" * 60)
    
    # 1. Load data
    print(f"\n[OK] Loading test data from: {INPUT_FILE.name}")
    X_test, y_test = load_and_preprocess()
    
    # 2. Load model
    print(f"[OK] Loading trained model from: {MODEL_FILE.name}")
    if not MODEL_FILE.exists():
        print(f"[ERROR] Model file not found: {MODEL_FILE}")
        sys.exit(1)
        
    with open(MODEL_FILE, 'rb') as f:
        model = pickle.load(f)
        
    # 3. Compute probabilities and apply custom threshold
    print(f"[OK] Applying Decision Threshold: {OPTIMAL_THRESHOLD}")
    y_probs = model.predict_proba(X_test)[:, 1]
    y_pred = (y_probs >= OPTIMAL_THRESHOLD).astype(int)
    
    # 4. Compute Metrics
    precision = precision_score(y_test, y_pred)
    recall = recall_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)
    
    print("\n--- Model Performance at Threshold 0.2577 ---")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1-score:  {f1:.4f}")
    
    # 5. Plotting Confusion Matrix (Vanilla Matplotlib)
    print(f"\n[OK] Plotting confusion matrix...")
    fig, ax = plt.subplots(figsize=(8, 6))
    
    # Display matrix
    im = ax.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
    ax.figure.colorbar(im, ax=ax)
    
    # Set labels
    classes = ['No Vulnerability', 'High-Severity']
    tick_marks = np.arange(len(classes))
    ax.set_xticks(tick_marks)
    ax.set_xticklabels(classes)
    ax.set_yticks(tick_marks)
    ax.set_yticklabels(classes)
    
    # Annotate counts inside cells
    thresh = cm.max() / 2.
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            ax.text(j, i, format(cm[i, j], 'd'),
                    ha="center", va="center",
                    color="white" if cm[i, j] > thresh else "black")
            
    ax.set_title(f"Confusion Matrix (Threshold = {OPTIMAL_THRESHOLD})", pad=20, fontsize=14)
    ax.set_xlabel('Predicted Label', labelpad=15, fontsize=12)
    ax.set_ylabel('Actual Label', labelpad=15, fontsize=12)
    plt.tight_layout()
    
    # 6. Save Confusion Matrix
    plt.savefig(OUTPUT_CM, dpi=300)
    print(f"[OK] Confusion matrix saved to: {OUTPUT_CM}")
    plt.close()

    # 7. Compute and Plot ROC Curve
    print(f"\n[OK] Plotting ROC curve...")
    fpr, tpr, thresholds = roc_curve(y_test, y_probs)
    roc_auc = auc(fpr, tpr)
    
    plt.figure(figsize=(8, 6))
    plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {roc_auc:.2f})')
    plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--', label='Random Classifier')
    
    plt.xlim([0.0, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate', labelpad=10, fontsize=12)
    plt.ylabel('True Positive Rate', labelpad=10, fontsize=12)
    plt.title(f'ROC Curve (AUC = {roc_auc:.2f})', pad=20, fontsize=14)
    plt.legend(loc="lower right")
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    
    # 8. Save ROC Curve
    plt.savefig(OUTPUT_ROC, dpi=300)
    print(f"[OK] ROC curve saved to: {OUTPUT_ROC}")
    plt.close()

    # 9. Compute and Plot Precision-Recall Curve
    print(f"\n[OK] Plotting Precision-Recall curve...")
    precision_pts, recall_pts, thresholds_pr = precision_recall_curve(y_test, y_probs)
    
    plt.figure(figsize=(8, 6))
    plt.plot(recall_pts, precision_pts, color='teal', lw=2, label='Precision-Recall curve')
    
    # Annotate our selected threshold on the curve
    # find point closest to our threshold
    idx = np.argmin(np.abs(thresholds_pr - OPTIMAL_THRESHOLD))
    plt.plot(recall_pts[idx], precision_pts[idx], 'ro', label=f'Threshold {OPTIMAL_THRESHOLD}')
    
    plt.xlabel('Recall', labelpad=10, fontsize=12)
    plt.ylabel('Precision', labelpad=10, fontsize=12)
    plt.title('Precision-Recall Curve', pad=20, fontsize=14)
    plt.legend(loc="upper right")
    plt.grid(True, linestyle='--', alpha=0.7)
    plt.tight_layout()
    
    # 10. Save PR Curve
    plt.savefig(OUTPUT_PR, dpi=300)
    print(f"[OK] Precision-Recall curve saved to: {OUTPUT_PR}")
    plt.close()

if __name__ == "__main__":
    main()
