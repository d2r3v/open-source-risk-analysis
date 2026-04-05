#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import os

"""
Advanced Risk Analysis Visualizations & Summary
Goal: Generate refined charts and print a findings summary for the vulnerability project.
Data Source: data/exports/extracted_package_risk_scored.csv
"""

def main():
    # 1. Setup paths
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    # Use the SCORED file if it exists, fallback to summary
    input_file = os.path.join(project_root, "data", "exports", "extracted_package_risk_scored.csv")
    if not os.path.exists(input_file):
        input_file = os.path.join(project_root, "data", "exports", "extracted_package_risk_summary.csv")
        
    output_dir = os.path.join(project_root, "reports", "figures")

    # Ensure output directory exists
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        print(f"Created output directory: {output_dir}")

    # 2. Data Loading and Cleaning
    if not os.path.exists(input_file):
        print(f"Error: No input file found at {input_file}.")
        return

    print(f"Reading from {input_file}...")
    df = pd.read_csv(input_file)

    # Convert numeric columns
    df['max_severity_score'] = pd.to_numeric(df['max_severity_score'], errors='coerce')
    df['stars'] = pd.to_numeric(df['stars'], errors='coerce').fillna(0)
    df['versions_count'] = pd.to_numeric(df['versions_count'], errors='coerce').fillna(0)
    df['days_since_last_release'] = pd.to_numeric(df['days_since_last_release'], errors='coerce')
    df['vulnerability_count'] = pd.to_numeric(df['vulnerability_count'], errors='coerce').fillna(0)

    # Ensure boolean columns
    df['has_high_severity_vulnerability'] = df['has_high_severity_vulnerability'].map({
        'true': True, 'false': False, True: True, False: False, 'True': True, 'False': False
    }).fillna(False)
    
    df['is_unmaintained'] = df['is_unmaintained'].map({
        'true': True, 'false': False, True: True, False: False, 'True': True, 'False': False
    }).fillna(False)

    # Clean repository_status
    df['repository_status'] = df['repository_status'].replace(np.nan, 'Unknown').replace('', 'Unknown')

    # 3. Aesthetics
    sns.set_theme(style="whitegrid")
    print(f"Starting visualization of {len(df)} packages...")

    # =========================================================================
    # Chart 1: Overall Severity Score Distribution (Boxplot)
    # =========================================================================
    vulnerable_df = df[df["vulnerability_count"] > 0].copy()
    if not vulnerable_df.empty:
        plt.figure(figsize=(10, 6))
        sns.boxplot(y="max_severity_score", data=vulnerable_df, color="salmon")
        plt.title("Distribution of Maximum CVSS Severity Scores Across Vulnerable Packages", fontsize=14, pad=15)
        plt.ylabel("CVSS Severity Score")
        plt.ylim(0, 10.5)
        plt.grid(True, axis='y', linestyle='--', alpha=0.6)
        median_val = vulnerable_df["max_severity_score"].median()
        plt.text(0.45, median_val, f'Median: {median_val:.1f}', color='darkred', fontweight='bold')
        plt.tight_layout()
        plt.savefig(os.path.join(output_dir, "severity_distribution_boxplot.png"), dpi=300)
        plt.close()
        print("- Saved: severity_distribution_boxplot.png")

    # =========================================================================
    # Chart 2: Distribution of High Severity Class (Boolean)
    # =========================================================================
    plt.figure(figsize=(10, 6))
    sns.countplot(x='has_high_severity_vulnerability', data=df, palette='viridis', hue='has_high_severity_vulnerability', legend=False)
    plt.title("Count of Packages with High-Severity Vulnerabilities")
    plt.xlabel("Has High-Severity Vulnerability?")
    plt.ylabel("Package Count")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "high_severity_class_distribution.png"), dpi=300)
    plt.close()
    print("- Saved: high_severity_class_distribution.png")

    # =========================================================================
    # Chart 3: Stars by High-Severity Label (Boxplot)
    # =========================================================================
    plt.figure(figsize=(10, 6))
    sns.boxplot(x='has_high_severity_vulnerability', y='stars', data=df, palette='coolwarm', hue='has_high_severity_vulnerability', legend=False)
    plt.yscale('log')
    plt.title("Project Popularity vs. High Severity Status", fontsize=14)
    plt.suptitle("Log-scaled due to skewed distribution", fontsize=10, y=0.92, alpha=0.7)
    plt.xlabel("High Severity Vulnerability (Yes/No)")
    plt.ylabel("GitHub Stars (log scale)")
    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plt.savefig(os.path.join(output_dir, "stars_by_high_severity_boxplot.png"), dpi=300)
    plt.close()
    print("- Saved: stars_by_high_severity_boxplot.png")

    # =========================================================================
    # Chart 4: High Severity Rate by Stars Bucket
    # =========================================================================
    bins = [-1, 99, 999, 9999, 99999, np.inf]
    labels = ['<100', '100-999', '1K-9.9K', '10K-99.9K', '100K+']
    df['stars_bucket'] = pd.cut(df['stars'], bins=bins, labels=labels)
    rate_df = df.groupby('stars_bucket', observed=True)['has_high_severity_vulnerability'].mean().reset_index()
    rate_df['has_high_severity_vulnerability'] *= 100 

    plt.figure(figsize=(10, 6))
    sns.barplot(x='stars_bucket', y='has_high_severity_vulnerability', data=rate_df, palette='magma', hue='stars_bucket', legend=False)
    plt.title("High-Severity Vulnerability Rate (%) by Project Stars")
    plt.xlabel("Stars Bucket")
    plt.ylabel("Percentage of Packages with High Severity (%)")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "high_severity_rate_by_stars_bucket.png"), dpi=300)
    plt.close()
    print("- Saved: high_severity_rate_by_stars_bucket.png")

    # =========================================================================
    # Chart 5: Repository Status Distribution
    # =========================================================================
    plt.figure(figsize=(12, 6))
    sns.countplot(x='repository_status', data=df, palette='tab10', order=df['repository_status'].value_counts().index, hue='repository_status', legend=False)
    plt.title("Repository Status Distribution")
    plt.xlabel("Status")
    plt.ylabel("Count")
    plt.xticks(rotation=45)
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "repository_status_distribution.png"), dpi=300)
    plt.close()
    print("- Saved: repository_status_distribution.png")

    # =========================================================================
    # Chart 6: Top 15 Packages by Vulnerability Count
    # =========================================================================
    top15_vuln = df.nlargest(15, 'vulnerability_count')
    plt.figure(figsize=(12, 8))
    sns.barplot(x='vulnerability_count', y='package_name', data=top15_vuln, palette='flare', hue='package_name', legend=False)
    plt.title("Top 15 Packages by Total OSV Vulnerability Count")
    plt.xlabel("Total Vulnerability Count")
    plt.ylabel("Package Name")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "top_packages_by_vulnerability_count.png"), dpi=300)
    plt.close()
    print("- Saved: top_packages_by_vulnerability_count.png")

    # =========================================================================
    # Chart 7: Vulnerability Count Distribution (Boxplot)
    # =========================================================================
    plt.figure(figsize=(10, 6))
    sns.boxplot(x='is_unmaintained', y='vulnerability_count', data=df, palette='pastel', hue='is_unmaintained', legend=False)
    plt.title("Vulnerability Count Distribution: Maintained vs Unmaintained Packages")
    plt.xlabel("Is Unmaintained?")
    plt.ylabel("Vulnerability Count")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "vulnerability_distribution_by_maintenance.png"), dpi=300)
    plt.close()
    print("- Saved: vulnerability_distribution_by_maintenance.png")

    # =========================================================================
    # Chart 8: Top 10 Packages by RISK SCORE (NEW)
    # =========================================================================
    if 'risk_score' in df.columns:
        top10_risk = df.nlargest(10, 'risk_score')
        plt.figure(figsize=(12, 8))
        sns.barplot(x='risk_score', y='package_name', data=top10_risk, palette='Reds_r', hue='package_name', legend=False)
        plt.title("Top 10 Packages by Weighted Risk Score", fontsize=14)
        plt.suptitle("Composite Risk Score = VulnerabilityCount × MaxSeverity × log(Stars + 1)", fontsize=10, y=0.92, alpha=0.7)
        plt.xlabel("Weighted Risk Score")
        plt.ylabel("Package Name")
        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        plt.savefig(os.path.join(output_dir, "top_packages_by_risk_score.png"), dpi=300)
        plt.close()
        print("- Saved: top_packages_by_risk_score.png")

    # =========================================================================
    # Chart 9: Stars vs Versions Count Scatter Plot
    # =========================================================================
    plt.figure(figsize=(11, 7))
    scatter_df = df[df['stars'] > 0].copy()
    sns.scatterplot(x='stars', y='versions_count', hue='has_high_severity_vulnerability', data=scatter_df, alpha=0.6)
    plt.xscale('log')
    plt.title("Project Popularity (Stars) vs. Maturity (Versions)")
    plt.xlabel("GitHub Stars (Log Scale)")
    plt.ylabel("Versions Count")
    plt.legend(title="Has High Severity Vuln?")
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, "stars_vs_versions_count_scatter.png"), dpi=300)
    plt.close()
    print("- Saved: stars_vs_versions_count_scatter.png")

    # 4. Findings Summary Calculation
    total_packages = len(df)
    vulnerable_packages = len(df[df['vulnerability_count'] > 0])
    high_severity_packages = len(df[df['has_high_severity_vulnerability'] == True])
    
    high_sev_df = df[df['has_high_severity_vulnerability'] == True]
    non_high_sev_df = df[df['has_high_severity_vulnerability'] == False]
    
    avg_stars_high = high_sev_df['stars'].mean()
    avg_stars_low = non_high_sev_df['stars'].mean()
    
    avg_days_high = high_sev_df['days_since_last_release'].mean()
    avg_days_low = non_high_sev_df['days_since_last_release'].mean()

    # Final Report
    print("\n" + "="*40)
    print("        RISK ANALYSIS FINDINGS SUMMARY")
    print("="*40)
    print(f"Total Packages Analyzed:       {total_packages}")
    print(f"Vulnerable Packages (any):     {vulnerable_packages} ({vulnerable_packages/total_packages:.1%})")
    print(f"High-Severity Packages:        {high_severity_packages} ({high_severity_packages/total_packages:.1%})")
    print("-"*40)
    print(f"Average Stars (High Severity): {avg_stars_high:,.1f}")
    print(f"Average Stars (Low/None):      {avg_stars_low:,.1f}")
    
    if 'risk_score' in df.columns:
        print("-"*40)
        top_risk = df.iloc[0]['package_name'] if not df.empty else "N/A"
        top_score = df.iloc[0]['risk_score'] if not df.empty else 0
        print(f"Highest Risk Package:          {top_risk} ({top_score:,.1f})")
        
    print("="*40)
    print("Visualization generation complete. Charts saved to reports/figures/")

if __name__ == "__main__":
    main()
