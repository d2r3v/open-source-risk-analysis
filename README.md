# Open Source Vulnerability Risk Analysis

Analyzing the relationship between package popularity, maintenance activity, and vulnerability exposure using OSV and Libraries.io data.

## Problem Statement
This project investigates whether package metadata (popularity, maintenance activity) can help identify packages that are more likely to contain high-severity vulnerabilities. **Can we identify characteristics of projects that are associated with higher vulnerability risk?**

## Datasets
1. **OSV (Open Source Vulnerabilities)**: Distributed vulnerability database for open-source projects.
   - [OSV API Documentation](https://osv.dev)
2. **Libraries.io**: Metadata on over 5 million open-source packages across 32 ecosystems.
   - [Libraries.io API](https://libraries.io)

## Pipeline Overview
1. **Metadata Extraction**: Fetch project statistics (stars, forks, maintenance status) from Libraries.io.
2. **Vulnerability Fetching**: Query the OSV API for all known vulnerabilities associated with the package list.
3. **Data Enrichment**: Fetch detailed JSON records for each unique OSV ID to extract CVSS scores and malware flags.
4. **Normalization**: Clean and flatten heterogeneous vulnerability data into a structured format.
5. **Aggregation**: Compute package-level risk metrics (vulnerability counts, max severity).
6. **SQL Integration**: Load enriched datasets into a PostgreSQL database for structured querying.
7. **Visualization**: Generate analytical charts using Python (pandas, seaborn).

## Tech Stack
- **JavaScript (Node.js)**: Core data extraction and transformation pipeline.
- **Python (pandas, seaborn, matplotlib)**: Statistical analysis and high-level visualization. *Seaborn is used for advanced statistical plotting (boxplots and distributions) built on top of Matplotlib.*
- **PostgreSQL**: Relational storage and multi-dimensional risk querying.
- **Docker**: Reproducible database environment via Docker Compose.

## Setup & How to Run

### 1. Pre-requisites
- Docker & Docker Compose
- Node.js (v18+)
- Python (v3.10+) with `pandas`, `seaborn`, and `matplotlib` installed.

### 2. Initialize Database
After starting the container, apply the schema and load data to populate the database.

```powershell
# Launch the PostgreSQL container
docker-compose up -d

# Load the database schema (PowerShell)
Get-Content sql/schema.sql | docker exec -i osv-postgres psql -U postgres -d osv_analysis
```

### 3. Execute the Pipeline
```bash
# Fetch and process data (requires LIBRARIES_IO_API_KEY in environment)
node scripts/js/fetch_librariesio_projects.js
node scripts/js/fetch_osv_vulnerabilities.js
node scripts/js/fetch_osv_details.js
node scripts/js/extract_osv_npm.js
node scripts/js/build_osv_package_summary.js
node scripts/js/build_extracted_package_risk_summary.js

# Generate Visualizations
python scripts/python/generate_visualizations.py
```

### 4. Load Data into PostgreSQL
```powershell
# Sync local CSVs to the container
docker exec osv-postgres mkdir -p /data/cleaned /data/exports
docker cp data/cleaned/. osv-postgres:/data/cleaned/
docker cp data/exports/. osv-postgres:/data/exports/

# Load Data (PowerShell)
Get-Content sql/load_data.sql | docker exec -i osv-postgres psql -U postgres -d osv_analysis
```

## Key Findings
- **Vulnerability Density**: 13.5% of analyzed packages contain at least one known vulnerability.
- **Critical Exposure**: 9.8% of packages contain high-severity vulnerabilities.
- **Popularity Correlation**: High-severity packages have **~2x more stars** on average than non-vulnerable ones.
- **Scrutiny Bias**: Popular packages show higher disclosure rates, suggesting that increased usage leads to more intensive security audits.
- **Maintenance Paradox**: Recently maintained packages still exhibit high vulnerability counts, indicating that active development does not always outpace security debt.

## Key Outputs
- **PostgreSQL Database**: Structured vulnerability and maintenance metadata for complex analytical querying.
- **Consolidated Risk Dataset**: `extracted_package_risk_summary.csv` containing joined package metrics.
- **Analytical Visualizations**: Reproducible statistical charts in `reports/figures/`.

## Limitations
- **Public Disclosures**: Data is limited to publicly reported vulnerabilities in the OSV database.
- **Reporting Bias**: More popular projects are more heavily scrutinized, which may skew findings toward larger repositories.
- **Severity Mapping**: Some severity scores are estimated based on textual labels (e.g., HIGH -> 8.0) when official CVSS scores are missing.

## Repository Structure
```text
.
├── data/               # Raw and cleaned datasets (CSV/JSON)
├── scripts/
│   ├── js/             # Data extraction pipeline
│   └── python/         # Analysis and visualization
├── sql/                # Schema and data loading scripts
├── reports/
│   └── figures/        # Generated PNG charts
├── data_dictionary.md  # Detailed field documentation
├── docker-compose.yml  # Database environment configuration
└── README.md           # Project overview
```