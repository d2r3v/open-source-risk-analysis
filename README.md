# Open Source Vulnerability & Risk Analysis Pipeline

## Overview
End-to-end data pipeline integrating OSV vulnerability data with Libraries.io package metadata to assess security risk and maintenance patterns.

## Execution Flow

1. **Extraction & Enrichment**
   - Flatten detailed OSV records into CSV:
     ```bash
     node scripts/js/extract_osv_npm.js
     ```
2. **Aggregation**
   - Summarize vulnerability metrics per package:
     ```bash
     node scripts/js/build_osv_package_summary.js
     ```
3. **Risk Integration**
   - Join OSV summary with Libraries.io metadata:
     ```bash
     node scripts/js/build_extracted_package_risk_summary.js
     ```

## Database Loading (Docker)

To load the final datasets into your PostgreSQL container, run the following sequence:

```powershell
# 1. Create directories inside the container
docker exec osv-postgres mkdir -p /data/cleaned /data/exports

# 2. Upload latest CSVs from host to container
docker cp data/cleaned/. osv-postgres:/data/cleaned/
docker cp data/exports/. osv-postgres:/data/exports/

# 3. Apply Schema
Get-Content sql/schema.sql | docker exec -i osv-postgres psql -U postgres -d osv_analysis

# 4. Load Data
Get-Content sql/load_data.sql | docker exec -i osv-postgres psql -U postgres -d osv_analysis
```

## Dataset Documentation
See [data_dictionary.md](data_dictionary.md) for a full breakdown of all 40+ fields and transformation logic.