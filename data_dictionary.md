# Open-Source Package Vulnerabilities Analysis - Data Dictionary

## Overview

This data dictionary documents all fields used in the project analyzing open-source package vulnerabilities and maintenance patterns. The project combines data from the Open Source Vulnerabilities (OSV) database and Libraries.io.

## Data Organization

### Raw vs. Cleaned Data

- **`data/raw/`** - Original JSON data from APIs (resumable cache).
- **`data/cleaned/`** - Processed, flattened, and aggregated CSV files.
- **`data/exports/`** - Final, joined datasets for risk assessment.

---

## Dataset: osv_npm_flat.csv

**Source:** `extract_osv_npm.js`

| Field Name | Type | Meaning | Transformation Notes |
|---|---|---|---|
| `osv_id` | String | Unique OSV identifier | Extracted from JSON root `id` |
| `package_name` | String | NPM package name | Normalized to lowercase |
| `ecosystem` | String | Ecosystem (always 'npm') | Filtered from `affected` |
| `published` | Date | Publication date | ISO 8601 |
| `modified` | Date | Last modified date | ISO 8601 |
| `severity_type` | String | Severity rating (CRITICAL, HIGH, etc.) | From `severity` or `database_specific` |
| `severity_score` | Numeric | CVSS score (0.0 - 10.0) | Heuristic: Malware = 10.0; High = 8.0 etc. |
| `is_high_severity` | Boolean | TRUE if score >= 7.0 | Derived from `severity_score` |
| `is_malware` | Boolean | TRUE if tagged as MALWARE | Based on OSV record prefix or database labels |

---

## Dataset: osv_package_summary.csv

**Source:** `build_osv_package_summary.js`

| Field Name | Type | Meaning | Transformation Notes |
|---|---|---|---|
| `package_name` | String | Normalized package name | Primary Key |
| `ecosystem` | String | Ecosystem (always 'npm') | Primary Key |
| `vulnerability_count` | Integer | Total distinct OSV records | COUNT(DISTINCT osv_id) |
| `high_severity_count` | Integer | Number of high-severity vulns | COUNT where is_high_severity = TRUE |
| `max_severity_score` | Numeric | Highest CVSS score found | MAX(severity_score) |
| `latest_vulnerability_published_at` | Date | Newest vuln date | MAX(published) |
| `has_high_severity_vulnerability` | Boolean | TRUE if high_count > 0 | Logical check |
| `osv_ids` | String | List of affected OSV IDs | Pipe-separated list: `ID1|ID2|...` |

---

## Dataset: extracted_package_risk_summary.csv

**Source:** `build_extracted_package_risk_summary.js`

| Field Name | Type | Meaning | Source |
|---|---|---|---|
| `package_name` | String | Normalized package name | Combined |
| `ecosystem` | String | Ecosystem (npm) | Combined |
| `stars` | Integer | GitHub/GitLab stars | Libraries.io |
| `forks` | Integer | Repository forks | Libraries.io |
| `contributions_count` | Integer | Total contributors | Libraries.io |
| `dependent_repos_count` | Integer | Usage in repositories | Libraries.io |
| `dependents_count` | Integer | Usage in packages | Libraries.io |
| `rank` | Numeric | Libraries.io quality rank | Libraries.io |
| `repository_status` | String | Active, Unmaintained, etc. | Libraries.io |
| `latest_release_published_at` | Date | Newest release date | Libraries.io |
| `versions_count` | Integer | Maturity indicator | Libraries.io |
| `days_since_last_release` | Integer | Recency metric | Computed at export time |
| `has_repository` | Boolean | TRUE if repo URL exists | Logical check |
| `is_unmaintained` | Boolean | TRUE if status = Unmaintained | Explicit check |
| `vulnerability_count` | Integer | Total OSV records | OSV Summary |
| `high_severity_count` | Integer | High-risk vulns | OSV Summary |
| `max_severity_score` | Numeric | Peak threat level | OSV Summary |
| `has_high_severity_vulnerability` | Boolean | Overall risk flag | OSV Summary |

---

## SQL Table Mapping

- `raw_osv_vulnerabilities` matches `osv_npm_flat.csv`
- `package_vulnerability_summary` matches `osv_package_summary.csv`
- `extracted_package_risk_summary` matches `extracted_package_risk_summary.csv`
