#!/usr/bin/env python3

"""
Example: Using the Trained Model for Predictions

This script demonstrates how to load the trained model and use it to make
predictions on new data.

Note: This is a demonstration/example script. It requires:
1. The training script has been run (models/trained_model.pkl exists)
2. New data in the same format as extracted_package_risk_summary.csv
"""

import pickle
import pandas as pd
import numpy as np
from pathlib import Path

# Project root
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent.parent

# Model files
MODEL_FILE = project_root / 'models' / 'trained_model.pkl'
ENCODER_FILE = project_root / 'models' / 'label_encoder.pkl'

# Feature configuration (must match training script)
NUMERIC_FEATURES = [
    'stars', 'forks', 'contributions_count', 'dependent_repos_count',
    'dependents_count', 'rank', 'versions_count', 'runtime_dependencies_count',
    'score', 'days_since_last_release', 'vulnerability_count',
    'high_severity_count', 'max_severity_score'
]

CATEGORICAL_FEATURES = ['repository_status']
BOOLEAN_FEATURES = ['has_repository', 'is_unmaintained']


def load_model():
    """Load the trained model and encoder."""
    print("Loading trained model...")
    
    if not MODEL_FILE.exists():
        print(f"Error: Model file not found: {MODEL_FILE}")
        print("Please run: python scripts/python/train_model.py")
        return None, None
    
    with open(MODEL_FILE, 'rb') as f:
        model = pickle.load(f)
    
    with open(ENCODER_FILE, 'rb') as f:
        encoders = pickle.load(f)
    
    print(f"✓ Model loaded successfully")
    print(f"  - Features: {len(NUMERIC_FEATURES + CATEGORICAL_FEATURES + BOOLEAN_FEATURES)}")
    print(f"  - Type: {type(model).__name__}")
    
    return model, encoders


def preprocess_features(df, encoders):
    """Preprocess features for prediction (same as training)."""
    
    X = df[NUMERIC_FEATURES + CATEGORICAL_FEATURES + BOOLEAN_FEATURES].copy()
    
    # Convert booleans to numeric
    for col in BOOLEAN_FEATURES:
        X[col] = (X[col] == 'true').astype(int)
    
    # Encode categorical features
    for col in CATEGORICAL_FEATURES:
        X[col] = X[col].fillna('Unknown')
        if col in encoders:
            # Handle unknown categories
            le = encoders[col]
            X[col] = X[col].apply(lambda x: le.transform([x])[0] if x in le.classes_ else 0)
        else:
            print(f"Warning: Encoder for {col} not found")
    
    # Fill missing numeric values with 0 (or use median from training)
    X[NUMERIC_FEATURES] = X[NUMERIC_FEATURES].fillna(0)
    
    return X


def predict_vulnerability(model, encoders, df):
    """Make predictions on new data."""
    
    # Preprocess
    X = preprocess_features(df, encoders)
    
    # Get predictions
    predictions = model.predict(X)
    probabilities = model.predict_proba(X)
    
    # Convert to labels
    results = []
    for idx, row in df.iterrows():
        pred = predictions[idx]
        prob_negative, prob_positive = probabilities[idx]
        
        results.append({
            'package_name': row.get('package_name', 'Unknown'),
            'prediction': 'High-Severity Vulnerability' if pred == 1 else 'No Vulnerability',
            'confidence': max(prob_negative, prob_positive),
            'probability_vulnerable': prob_positive,
            'probability_safe': prob_negative
        })
    
    return pd.DataFrame(results)


# ============================================================================
# EXAMPLE 1: Predict on single package
# ============================================================================

def example_single_package():
    """Example: Predict for a single package."""
    print("\n" + "="*80)
    print("EXAMPLE 1: Single Package Prediction")
    print("="*80)
    
    model, encoders = load_model()
    if model is None:
        return
    
    # Create a sample package data
    sample_data = {
        'package_name': 'example-package',
        'stars': 1000,
        'forks': 100,
        'contributions_count': 500,
        'dependent_repos_count': 250,
        'dependents_count': 5000,
        'rank': 8.5,
        'versions_count': 50,
        'runtime_dependencies_count': 10,
        'score': 8.2,
        'days_since_last_release': 30,
        'vulnerability_count': 2,
        'high_severity_count': 1,
        'max_severity_score': 7.5,
        'repository_status': 'Active',
        'has_repository': 'true',
        'is_unmaintained': 'false'
    }
    
    df = pd.DataFrame([sample_data])
    results = predict_vulnerability(model, encoders, df)
    
    print("\nPrediction Results:")
    print(results.to_string(index=False))


# ============================================================================
# EXAMPLE 2: Predict on multiple packages
# ============================================================================

def example_multiple_packages():
    """Example: Predict for multiple packages."""
    print("\n" + "="*80)
    print("EXAMPLE 2: Multiple Package Predictions")
    print("="*80)
    
    model, encoders = load_model()
    if model is None:
        return
    
    # Create sample data for multiple packages
    samples = [
        {
            'package_name': 'popular-maintained-package',
            'stars': 10000,
            'forks': 2000,
            'contributions_count': 5000,
            'dependent_repos_count': 5000,
            'dependents_count': 50000,
            'rank': 9.5,
            'versions_count': 200,
            'runtime_dependencies_count': 3,
            'score': 9.1,
            'days_since_last_release': 5,
            'vulnerability_count': 0,
            'high_severity_count': 0,
            'max_severity_score': 0.0,
            'repository_status': 'Active',
            'has_repository': 'true',
            'is_unmaintained': 'false'
        },
        {
            'package_name': 'old-unmaintained-package',
            'stars': 100,
            'forks': 10,
            'contributions_count': 50,
            'dependent_repos_count': 10,
            'dependents_count': 100,
            'rank': 2.0,
            'versions_count': 5,
            'runtime_dependencies_count': 20,
            'score': 1.5,
            'days_since_last_release': 730,
            'vulnerability_count': 15,
            'high_severity_count': 5,
            'max_severity_score': 9.2,
            'repository_status': 'Unmaintained',
            'has_repository': 'true',
            'is_unmaintained': 'true'
        },
        {
            'package_name': 'moderately-popular-package',
            'stars': 3000,
            'forks': 500,
            'contributions_count': 1000,
            'dependent_repos_count': 1000,
            'dependents_count': 15000,
            'rank': 6.5,
            'versions_count': 75,
            'runtime_dependencies_count': 8,
            'score': 6.3,
            'days_since_last_release': 90,
            'vulnerability_count': 3,
            'high_severity_count': 1,
            'max_severity_score': 7.1,
            'repository_status': 'Active',
            'has_repository': 'true',
            'is_unmaintained': 'false'
        }
    ]
    
    df = pd.DataFrame(samples)
    results = predict_vulnerability(model, encoders, df)
    
    print("\nPrediction Results:")
    print(results.to_string(index=False))
    
    print("\n\nAnalysis:")
    print("-" * 80)
    for _, row in results.iterrows():
        print(f"\n{row['package_name']}:")
        print(f"  Prediction: {row['prediction']}")
        print(f"  Confidence: {row['confidence']:.2%}")
        print(f"  Vulnerability Risk: {row['probability_vulnerable']:.2%}")


# ============================================================================
# EXAMPLE 3: Predict on real data
# ============================================================================

def example_from_file():
    """Example: Predict on data from CSV file."""
    print("\n" + "="*80)
    print("EXAMPLE 3: Prediction from CSV File")
    print("="*80)
    
    model, encoders = load_model()
    if model is None:
        return
    
    # Load the original data
    input_file = project_root / 'data' / 'exports' / 'extracted_package_risk_summary.csv'
    
    if not input_file.exists():
        print(f"Data file not found: {input_file}")
        return
    
    print(f"Loading data from: {input_file}")
    df = pd.read_csv(input_file)
    
    # Take a sample
    sample_df = df.sample(n=min(5, len(df)), random_state=42)
    
    print(f"Making predictions on {len(sample_df)} packages...")
    results = predict_vulnerability(model, encoders, sample_df)
    
    print("\nSample Predictions:")
    print(results.to_string(index=False))
    
    # Summary statistics
    print("\n\nSummary Statistics:")
    print("-" * 80)
    vulnerable_count = (results['prediction'] == 'High-Severity Vulnerability').sum()
    safe_count = (results['prediction'] == 'No Vulnerability').sum()
    avg_confidence = results['confidence'].mean()
    avg_risk = results['probability_vulnerable'].mean()
    
    print(f"Predicted Vulnerable: {vulnerable_count}/{len(results)} ({vulnerable_count/len(results):.1%})")
    print(f"Predicted Safe: {safe_count}/{len(results)} ({safe_count/len(results):.1%})")
    print(f"Average Confidence: {avg_confidence:.2%}")
    print(f"Average Vulnerability Risk: {avg_risk:.2%}")


# ============================================================================
# EXAMPLE 4: Decision boundary analysis
# ============================================================================

def example_decision_boundary():
    """Example: Analyze decision boundary and probability thresholds."""
    print("\n" + "="*80)
    print("EXAMPLE 4: Decision Boundary Analysis")
    print("="*80)
    
    model, encoders = load_model()
    if model is None:
        return
    
    # Create data points with varying vulnerability counts
    print("\nHow vulnerability count affects predictions:")
    print("-" * 80)
    
    for vuln_count in [0, 1, 3, 5, 10, 15]:
        sample = {
            'package_name': f'package_with_{vuln_count}_vulns',
            'stars': 1000,
            'forks': 100,
            'contributions_count': 500,
            'dependent_repos_count': 250,
            'dependents_count': 5000,
            'rank': 7.0,
            'versions_count': 50,
            'runtime_dependencies_count': 5,
            'score': 7.0,
            'days_since_last_release': 60,
            'vulnerability_count': vuln_count,
            'high_severity_count': vuln_count // 3,  # Roughly 1/3 are high-severity
            'max_severity_score': min(7.0 + vuln_count * 0.3, 10.0),
            'repository_status': 'Active',
            'has_repository': 'true',
            'is_unmaintained': 'false'
        }
        
        df = pd.DataFrame([sample])
        results = predict_vulnerability(model, encoders, df)
        row = results.iloc[0]
        
        print(f"Vulnerabilities: {vuln_count:2d} → Risk: {row['probability_vulnerable']:5.1%} " + 
              f"({row['prediction']})")


# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    print("\n" + "="*80)
    print("TRAINED MODEL USAGE EXAMPLES")
    print("="*80)
    
    # Run examples
    example_single_package()
    example_multiple_packages()
    example_from_file()
    example_decision_boundary()
    
    print("\n" + "="*80)
    print("EXAMPLES COMPLETED")
    print("="*80)
    print("\nTo use the model in your own code:")
    print("""
    import pickle
    import pandas as pd
    
    # Load model and encoder
    with open('models/trained_model.pkl', 'rb') as f:
        model = pickle.load(f)
    with open('models/label_encoder.pkl', 'rb') as f:
        encoders = pickle.load(f)
    
    # Prepare your data (same format as extracted_package_risk_summary.csv)
    # with 16 required features
    df = pd.read_csv('your_data.csv')
    
    # Make predictions
    predictions = model.predict(X)              # 0 or 1
    probabilities = model.predict_proba(X)      # [prob_safe, prob_vulnerable]
    """)
    print("\n")
