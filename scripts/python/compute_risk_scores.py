#!/usr/bin/env python3
import pandas as pd
import numpy as np
import os

"""
Compute Package Risk Scores
Algorithm: risk_score = vulnerability_count * max_severity_score * ln(stars + 1)
Goal: Rank packages by overall risk, weighting popular targets with high-severity vulnerabilities highest.
"""

def compute_risk_scores(input_path, output_path):
    if not os.path.exists(input_path):
        print(f"Error: Input file {input_path} not found.")
        return None

    print(f"Loading data from {input_path}...")
    df = pd.read_csv(input_path)

    # 1. Handle Missing Values
    # We replace NaN with 0 to ensure the formula results in 0 risk rather than NaN
    df['vulnerability_count'] = pd.to_numeric(df['vulnerability_count'], errors='coerce').fillna(0)
    df['max_severity_score'] = pd.to_numeric(df['max_severity_score'], errors='coerce').fillna(0)
    df['stars'] = pd.to_numeric(df['stars'], errors='coerce').fillna(0)

    # 2. Compute Risk Score
    # Log1p(x) is ln(x + 1) - cleaner and mathematically more stable than log(x + 1)
    df['risk_score'] = df['vulnerability_count'] * df['max_severity_score'] * np.log1p(df['stars'])

    # Round to 2 decimal places for cleanliness
    df['risk_score'] = df['risk_score'].round(2)

    # 3. Sort by risk_score (Descending)
    df_sorted = df.sort_values(by='risk_score', ascending=False)

    # 4. Save to CSV
    print(f"Saving scored dataset to {output_path}...")
    df_sorted.to_csv(output_path, index=False)

    return df_sorted

def main():
    # Setup paths
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    input_file = os.path.join(project_root, "data", "exports", "extracted_package_risk_summary.csv")
    output_file = os.path.join(project_root, "data", "exports", "extracted_package_risk_scored.csv")

    scored_df = compute_risk_scores(input_file, output_file)

    if scored_df is not None:
        print("\n" + "="*50)
        print("          TOP 10 PACKAGES BY RISK SCORE")
        print("="*50)
        
        # Display relevant columns for verification
        cols_to_print = ['package_name', 'vulnerability_count', 'max_severity_score', 'stars', 'risk_score']
        print(scored_df[cols_to_print].head(10).to_string(index=False))
        print("="*50)
        print(f"Risk calculation complete. Result: {len(scored_df)} rows processed.")

if __name__ == "__main__":
    main()
