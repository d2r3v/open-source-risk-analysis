#!/usr/bin/env python3

"""
Exploratory Data Analysis (EDA) for Package Risk Summary

Purpose: Perform comprehensive exploratory data analysis on the extracted
package risk summary dataset including summary statistics, missingness analysis,
and visualization of key patterns.

Input:  data/exports/extracted_package_risk_summary.csv
Output: 
  - Console: Summary statistics and missingness report
  - Figures: 6 plots saved to reports/figures/

Dependencies:
  - pandas: Data manipulation and analysis
  - matplotlib: Plotting library
"""

import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
from pathlib import Path

# Get project root directory
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent.parent

# Data file paths
INPUT_FILE = project_root / 'data' / 'exports' / 'extracted_package_risk_summary.csv'
FIGURES_DIR = project_root / 'reports' / 'figures'

# Create figures directory if it doesn't exist
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

# matplotlib settings
plt.style.use('default')
plt.rcParams['figure.figsize'] = (10, 6)
plt.rcParams['font.size'] = 10


def load_data():
    """
    Load the extracted package risk summary CSV file.
    
    Returns:
        pd.DataFrame: Loaded dataset
    """
    print("Loading data...")
    if not INPUT_FILE.exists():
        print(f"Error: Input file not found: {INPUT_FILE}")
        sys.exit(1)
    
    df = pd.read_csv(INPUT_FILE)
    print(f"✓ Loaded {len(df)} rows and {len(df.columns)} columns\n")
    return df


def print_summary_statistics(df):
    """
    Print summary statistics for numeric columns.
    
    Args:
        df (pd.DataFrame): Dataset to analyze
    """
    print("=" * 80)
    print("SUMMARY STATISTICS")
    print("=" * 80)
    print("\nDataset shape:", df.shape)
    print("\nNumeric columns summary:")
    print(df.describe().to_string())
    print("\n")


def print_missingness_report(df):
    """
    Print a detailed report of missing values.
    
    Args:
        df (pd.DataFrame): Dataset to analyze
    """
    print("=" * 80)
    print("MISSINGNESS ANALYSIS")
    print("=" * 80)
    
    missing_counts = df.isnull().sum()
    missing_percentage = (missing_counts / len(df) * 100).round(2)
    
    # Create missingness dataframe
    missing_df = pd.DataFrame({
        'Column': missing_counts.index,
        'Missing Count': missing_counts.values,
        'Missing %': missing_percentage.values
    })
    
    # Filter to show only columns with missing values
    missing_df = missing_df[missing_df['Missing Count'] > 0].sort_values('Missing Count', ascending=False)
    
    if len(missing_df) == 0:
        print("\nNo missing values found!")
    else:
        print("\nColumns with missing values:")
        print(missing_df.to_string(index=False))
    
    print(f"\nTotal missing cells: {missing_counts.sum()}")
    print(f"Total cells: {df.size}")
    print("\n")


def print_categorical_analysis(df):
    """
    Print analysis of categorical columns.
    
    Args:
        df (pd.DataFrame): Dataset to analyze
    """
    print("=" * 80)
    print("CATEGORICAL COLUMNS ANALYSIS")
    print("=" * 80)
    
    categorical_cols = df.select_dtypes(include=['object']).columns
    
    for col in categorical_cols:
        print(f"\n{col}:")
        value_counts = df[col].value_counts()
        for value, count in value_counts.items():
            pct = (count / len(df) * 100)
            bar = "█" * int(pct / 2)
            print(f"  {str(value):30s} {count:6d} ({pct:5.1f}%) {bar}")


def plot_class_distribution(df):
    """
    Plot 1: Class distribution for has_high_severity_vulnerability
    
    Args:
        df (pd.DataFrame): Dataset to analyze
    """
    print("\n➤ Creating plot 1: Class distribution for has_high_severity_vulnerability...")
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Get value counts
    vulnerability_counts = df['has_high_severity_vulnerability'].value_counts()
    colors = ['#d62728', '#2ca02c']  # Red for true, green for false
    
    # Create bar plot
    bars = ax.bar(
        range(len(vulnerability_counts)),
        vulnerability_counts.values,
        color=colors[:len(vulnerability_counts)],
        edgecolor='black',
        linewidth=1.5,
        alpha=0.7
    )
    
    # Add value labels on bars
    for i, (bar, value) in enumerate(zip(bars, vulnerability_counts.values)):
        height = bar.get_height()
        percentage = (value / len(df) * 100)
        ax.text(
            bar.get_x() + bar.get_width()/2.,
            height,
            f'{int(value)}\n({percentage:.1f}%)',
            ha='center',
            va='bottom',
            fontweight='bold'
        )
    
    ax.set_xlabel('High-Severity Vulnerability Status', fontweight='bold', fontsize=11)
    ax.set_ylabel('Package Count', fontweight='bold', fontsize=11)
    ax.set_title('Class Distribution: High-Severity Vulnerabilities', fontweight='bold', fontsize=13)
    ax.set_xticklabels(['No', 'Yes'] if 'true' in vulnerability_counts.index else ['Yes', 'No'])
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / 'plot_1_class_distribution.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("  ✓ Saved to plot_1_class_distribution.png")


def plot_days_since_last_release(df):
    """
    Plot 2: Histogram of days_since_last_release
    
    Args:
        df (pd.DataFrame): Dataset to analyze
    """
    print("\n➤ Creating plot 2: Histogram of days_since_last_release...")
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Filter out NaN values
    data = df['days_since_last_release'].dropna()
    
    # Create histogram
    ax.hist(
        data,
        bins=50,
        color='#1f77b4',
        edgecolor='black',
        alpha=0.7,
        linewidth=1
    )
    
    # Add statistics lines
    mean_val = data.mean()
    median_val = data.median()
    
    ax.axvline(mean_val, color='red', linestyle='--', linewidth=2, label=f'Mean: {mean_val:.0f} days')
    ax.axvline(median_val, color='green', linestyle='--', linewidth=2, label=f'Median: {median_val:.0f} days')
    
    ax.set_xlabel('Days Since Last Release', fontweight='bold', fontsize=11)
    ax.set_ylabel('Frequency', fontweight='bold', fontsize=11)
    ax.set_title('Distribution of Days Since Last Release', fontweight='bold', fontsize=13)
    ax.legend(fontsize=10)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / 'plot_2_days_since_release.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("  ✓ Saved to plot_2_days_since_release.png")


def plot_stars_by_vulnerability(df):
    """
    Plot 3: Boxplot of stars by vulnerability label
    
    Args:
        df (pd.DataFrame): Dataset to analyze
    """
    print("\n➤ Creating plot 3: Boxplot of stars by vulnerability label...")
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Prepare data for boxplot
    vulnerable_data = df[df['has_high_severity_vulnerability'] == 'true']['stars'].dropna()
    non_vulnerable_data = df[df['has_high_severity_vulnerability'] == 'false']['stars'].dropna()
    
    # Create boxplot
    bp = ax.boxplot(
        [vulnerable_data, non_vulnerable_data],
        labels=['High-Severity Vulnerable', 'Non-Vulnerable'],
        patch_artist=True,
        widths=0.6,
        showmeans=True
    )
    
    # Color the boxes
    colors = ['#d62728', '#2ca02c']
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.6)
    
    ax.set_ylabel('Stars Count', fontweight='bold', fontsize=11)
    ax.set_title('Repository Stars by Vulnerability Status', fontweight='bold', fontsize=13)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Add sample size annotations
    ax.text(1, ax.get_ylim()[1] * 0.95, f'n={len(vulnerable_data)}', 
            ha='center', fontsize=9, bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    ax.text(2, ax.get_ylim()[1] * 0.95, f'n={len(non_vulnerable_data)}', 
            ha='center', fontsize=9, bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / 'plot_3_stars_by_vulnerability.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("  ✓ Saved to plot_3_stars_by_vulnerability.png")


def plot_dependencies_by_vulnerability(df):
    """
    Plot 4: Boxplot of runtime_dependencies_count by vulnerability label
    
    Args:
        df (pd.DataFrame): Dataset to analyze
    """
    print("\n➤ Creating plot 4: Boxplot of runtime_dependencies_count by vulnerability label...")
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    # Prepare data for boxplot
    vulnerable_data = df[df['has_high_severity_vulnerability'] == 'true']['runtime_dependencies_count'].dropna()
    non_vulnerable_data = df[df['has_high_severity_vulnerability'] == 'false']['runtime_dependencies_count'].dropna()
    
    # Create boxplot
    bp = ax.boxplot(
        [vulnerable_data, non_vulnerable_data],
        labels=['High-Severity Vulnerable', 'Non-Vulnerable'],
        patch_artist=True,
        widths=0.6,
        showmeans=True
    )
    
    # Color the boxes
    colors = ['#d62728', '#2ca02c']
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.6)
    
    ax.set_ylabel('Runtime Dependencies Count', fontweight='bold', fontsize=11)
    ax.set_title('Runtime Dependencies by Vulnerability Status', fontweight='bold', fontsize=13)
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    # Add sample size annotations
    ax.text(1, ax.get_ylim()[1] * 0.95, f'n={len(vulnerable_data)}', 
            ha='center', fontsize=9, bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    ax.text(2, ax.get_ylim()[1] * 0.95, f'n={len(non_vulnerable_data)}', 
            ha='center', fontsize=9, bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.5))
    
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / 'plot_4_dependencies_by_vulnerability.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("  ✓ Saved to plot_4_dependencies_by_vulnerability.png")


def plot_repository_status_distribution(df):
    """
    Plot 5: Bar chart of repository_status distribution
    
    Args:
        df (pd.DataFrame): Dataset to analyze
    """
    print("\n➤ Creating plot 5: Bar chart of repository_status distribution...")
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Get value counts
    status_counts = df['repository_status'].value_counts().sort_values(ascending=False)
    
    # Define colors
    colors_map = {
        'Active': '#2ca02c',
        'Unmaintained': '#d62728',
        'Archived': '#ff7f0e',
        'Help Wanted': '#9467bd'
    }
    colors = [colors_map.get(status, '#1f77b4') for status in status_counts.index]
    
    # Create bar plot
    bars = ax.bar(
        range(len(status_counts)),
        status_counts.values,
        color=colors,
        edgecolor='black',
        linewidth=1.5,
        alpha=0.7
    )
    
    # Add value labels on bars
    for bar, value in zip(bars, status_counts.values):
        height = bar.get_height()
        percentage = (value / len(df) * 100)
        ax.text(
            bar.get_x() + bar.get_width()/2.,
            height,
            f'{int(value)}\n({percentage:.1f}%)',
            ha='center',
            va='bottom',
            fontweight='bold',
            fontsize=9
        )
    
    ax.set_xlabel('Repository Status', fontweight='bold', fontsize=11)
    ax.set_ylabel('Package Count', fontweight='bold', fontsize=11)
    ax.set_title('Distribution of Repository Status', fontweight='bold', fontsize=13)
    ax.set_xticklabels(status_counts.index, rotation=45, ha='right')
    ax.grid(axis='y', alpha=0.3, linestyle='--')
    
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / 'plot_5_repository_status.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("  ✓ Saved to plot_5_repository_status.png")


def plot_stars_vs_dependencies(df):
    """
    Plot 6: Scatter plot of stars vs runtime_dependencies_count 
            colored by vulnerability label
    
    Args:
        df (pd.DataFrame): Dataset to analyze
    """
    print("\n➤ Creating plot 6: Scatter plot of stars vs runtime_dependencies_count...")
    
    fig, ax = plt.subplots(figsize=(12, 7))
    
    # Prepare data
    vulnerable_mask = df['has_high_severity_vulnerability'] == 'true'
    
    # Filter out NaN values
    plot_df = df[['stars', 'runtime_dependencies_count', 'has_high_severity_vulnerability']].dropna()
    
    # Create scatter plots for each group
    vulnerable = plot_df[vulnerable_mask]
    non_vulnerable = plot_df[~vulnerable_mask]
    
    ax.scatter(
        non_vulnerable['stars'],
        non_vulnerable['runtime_dependencies_count'],
        color='#2ca02c',
        alpha=0.5,
        s=50,
        label='No High-Severity Vulnerabilities',
        edgecolors='darkgreen',
        linewidth=0.5
    )
    
    ax.scatter(
        vulnerable['stars'],
        vulnerable['runtime_dependencies_count'],
        color='#d62728',
        alpha=0.6,
        s=80,
        label='High-Severity Vulnerable',
        edgecolors='darkred',
        linewidth=0.5,
        marker='^'
    )
    
    ax.set_xlabel('Stars Count', fontweight='bold', fontsize=11)
    ax.set_ylabel('Runtime Dependencies Count', fontweight='bold', fontsize=11)
    ax.set_title('Stars vs Runtime Dependencies by Vulnerability Status', fontweight='bold', fontsize=13)
    ax.legend(fontsize=10, loc='best')
    ax.grid(True, alpha=0.3, linestyle='--')
    
    # Add correlation information
    corr = plot_df['stars'].corr(plot_df['runtime_dependencies_count'])
    ax.text(
        0.98, 0.02,
        f'Correlation: {corr:.3f}\nTotal points: {len(plot_df)}',
        transform=ax.transAxes,
        fontsize=10,
        verticalalignment='bottom',
        horizontalalignment='right',
        bbox=dict(boxstyle='round', facecolor='wheat', alpha=0.8)
    )
    
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / 'plot_6_stars_vs_dependencies.png', dpi=300, bbox_inches='tight')
    plt.close()
    print("  ✓ Saved to plot_6_stars_vs_dependencies.png")


def main():
    """
    Main analysis workflow.
    """
    print("\n" + "=" * 80)
    print("EXPLORATORY DATA ANALYSIS - Package Risk Summary")
    print("=" * 80 + "\n")
    
    # Load data
    df = load_data()
    
    # Print summaries
    print_summary_statistics(df)
    print_missingness_report(df)
    print_categorical_analysis(df)
    
    # Create visualizations
    print("\n" + "=" * 80)
    print("CREATING VISUALIZATIONS")
    print("=" * 80)
    
    plot_class_distribution(df)
    plot_days_since_last_release(df)
    plot_stars_by_vulnerability(df)
    plot_dependencies_by_vulnerability(df)
    plot_repository_status_distribution(df)
    plot_stars_vs_dependencies(df)
    
    # Final summary
    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE")
    print("=" * 80)
    print(f"\n✓ All plots saved to: {FIGURES_DIR}")
    print("\nGenerated files:")
    print("  1. plot_1_class_distribution.png")
    print("  2. plot_2_days_since_release.png")
    print("  3. plot_3_stars_by_vulnerability.png")
    print("  4. plot_4_dependencies_by_vulnerability.png")
    print("  5. plot_5_repository_status.png")
    print("  6. plot_6_stars_vs_dependencies.png")
    print("\n")


if __name__ == '__main__':
    main()
