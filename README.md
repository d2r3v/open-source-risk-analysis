# Open Source Vulnerability Analysis Pipeline

## Overview
End-to-end data pipeline integrating OSV vulnerability data with Libraries.io package metadata.

## Steps
1. Fetch package metadata (Libraries.io)
2. Fetch and enrich OSV vulnerabilities
3. Aggregate to package-level features
4. Merge into final dataset
5. Load into PostgreSQL
6. Perform SQL analysis and visualization

## Run Pipeline
```bash
node scripts/js/extract_osv_npm.js
node scripts/js/build_osv_package_summary.js
node scripts/js/fetch_librariesio_projects.js
node scripts/js/build_extracted_package_risk_summary.js