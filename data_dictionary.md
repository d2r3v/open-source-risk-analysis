# Open-Source Package Vulnerabilities Analysis - Data Dictionary

## Overview

This data dictionary documents all fields used in the course project analyzing open-source package vulnerabilities and maintenance patterns. The project combines data from the Open Source Vulnerabilities (OSV) database and Libraries.io to assess risk profiles and maintenance patterns of npm packages.

## Data Organization

### Raw vs. Cleaned Data

The project follows a structured data pipeline:

- **`data/raw/`** - Original, unmodified data as received from external APIs and sources
  - `osv/` - Individual OSV vulnerability JSON files
  - `librariesio/projects/` - Individual Libraries.io project JSON responses
  - `librariesio/dependencies/` - Individual Libraries.io dependency JSON responses
  
- **`data/cleaned/`** - Processed, flattened, and aggregated CSV files ready for analysis
  - Contains derived datasets created through extraction and transformation scripts
  - Fields are normalized, duplicate records removed, and relationships resolved
  
- **`data/exports/`** - Final, joined datasets combining multiple sources for analysis
  - Contains comprehensive risk assessments and joined metrics
  - Ready for machine learning, visualization, or further analysis

---

## Dataset: osv_npm_flat.csv

**Source:** `extract_osv_npm.js` (extracted from `data/raw/osv/*.json`)

**Purpose:** Flattened vulnerability records from the Open Source Vulnerabilities (OSV) database, one row per affected npm package.

| Field Name | Type | Meaning | Transformation Notes |
|---|---|---|---|
| `osv_id` | String | Unique vulnerability identifier from OSV database (e.g., GHSA-xxxx-yyyy-zzzz, CVE-XXXX-XXXXX) | Extracted directly from OSV JSON payload |
| `package_name` | String | Name of the affected npm package | Normalized to lowercase and trimmed; extracted from `affected[].package.name` |
| `ecosystem` | String | Package ecosystem identifier; always 'npm' in this dataset | Filtered to include only npm ecosystem; lowercase normalized |
| `published` | ISO 8601 Date | Date when the vulnerability was first published | Extracted from OSV JSON; includes timezone information |
| `modified` | ISO 8601 Date | Date when the vulnerability record was last modified | Extracted from OSV JSON; includes timezone information |
| `severity_type` | String | Severity rating string (e.g., 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN') | Extracted from first `severity[].rating` found in OSV data; defaults to 'UNKNOWN' |
| `severity_score` | Numeric (1 decimal) | Numeric CVSS score (0.0 - 10.0); maximum score if multiple severities exist | Extracted from severity objects; takes maximum value across multiple severity entries; rounded to 1 decimal place |
| `is_high_severity` | Boolean | Boolean flag indicating if severity_score >= 7.0 | Computed from severity_score; 'true' or 'false' |

---

## Dataset: osv_package_summary.csv

**Source:** `build_osv_package_summary.js` (aggregated from `osv_npm_flat.csv`)

**Purpose:** Aggregated vulnerability metrics by package, one row per unique (package_name, ecosystem) pair.

| Field Name | Type | Meaning | Transformation Notes |
|---|---|---|---|
| `package_name` | String | Normalized package name | Same normalization as osv_npm_flat; composite key with ecosystem |
| `ecosystem` | String | Package ecosystem; always 'npm' | Same normalization as osv_npm_flat; composite key with package_name |
| `vulnerability_count` | Integer | Total number of distinct vulnerabilities affecting this package | Aggregated count of unique osv_ids per package; treats each OSV record once per package |
| `high_severity_count` | Integer | Count of vulnerabilities with is_high_severity = 'true' | Filtered count where severity_score >= 7.0 |
| `max_severity_score` | Numeric (1 decimal) | Maximum CVSS score across all vulnerabilities for this package | Computed as MAX of severity_score values; empty if no scores available |
| `latest_vulnerability_published_at` | ISO 8601 Date | Most recent vulnerability publication date for this package | Computed as MAX of published dates; represents most recent threat |
| `has_high_severity_vulnerability` | Boolean | Boolean flag indicating if package has any high-severity vulnerabilities | 'true' if high_severity_count > 0, else 'false' |

---

## Dataset: librariesio_projects.csv

**Source:** `fetch_librariesio_projects.js` (extracted from Libraries.io API responses cached in `data/raw/librariesio/projects/*.json`)

**Purpose:** Project metadata from Libraries.io, one row per npm package.

| Field Name | Type | Meaning | Transformation Notes |
|---|---|---|---|
| `package_name` | String | NPM package name | Normalized to lowercase for consistency; matches OSV data naming |
| `platform` | String | Package platform/ecosystem; always 'npm' for this dataset | Extracted directly from Libraries.io API response |
| `description` | Text | Package description from package.json or NPM registry | Text field; may contain newlines or special characters |
| `language` | String | Primary programming language of the package | Inferred by Libraries.io from repository content or package metadata |
| `stars` | Integer | Number of GitHub/GitLab stars if repository is hosted there | May be empty if repository is not hosted on major platforms |
| `forks` | Integer | Number of GitHub/GitLab forks | May be empty if repository is not hosted on major platforms |
| `contributions_count` | Integer | Total number of contributions to the repository | Count from GitHub/GitLab API |
| `dependent_repos_count` | Integer | Number of repositories that depend on this package | Computed by Libraries.io |
| `dependents_count` | Integer | Total number of packages that depend on this package | Includes both direct and transitive dependents |
| `rank` | Numeric | Libraries.io ranking score for package importance/quality | Numeric score; higher is better; composite metric |
| `repository_status` | String | Status of the repository (e.g., 'Active', 'Unmaintained', 'Archived') | Categorical value; key indicator of maintenance status |
| `repository_url` | String (URL) | Full URL to the package repository | May be GitHub, GitLab, or other version control hosts |
| `licenses` | String | License information from package metadata | May be single license or comma-separated list |
| `normalized_licenses` | String | Libraries.io normalized license names | Standardized license names for comparison |
| `latest_release_number` | String | Version number of the most recent release | Semantic versioning format (e.g., '1.2.3'); may include pre-release tags |
| `latest_release_published_at` | ISO 8601 Date | Publication date of the latest version | Timestamp of when latest release was published to NPM |
| `versions_count` | Integer | Total number of versions/releases published | Indicator of project maturity and release frequency |

---

## Dataset: librariesio_dependencies.csv

**Source:** `fetch_librariesio_dependencies.js` (extracted from Libraries.io API responses cached in `data/raw/librariesio/dependencies/*.json`)

**Purpose:** Dependency metrics for npm packages, one row per package-version combination analyzed.

| Field Name | Type | Meaning | Transformation Notes |
|---|---|---|---|
| `package_name` | String | NPM package name | Normalized to lowercase; matches OSV data naming |
| `platform` | String | Package platform; always 'npm' | Extracted from Libraries.io API response |
| `runtime_dependencies_count` | Integer | Count of direct runtime (non-development) dependencies | Filtered to exclude dev dependencies; count of direct dependencies only |
| `dependents_count` | Integer | Total packages that depend on this package | Propagated from librariesio_projects data |
| `dependent_repos_count` | Integer | Number of repositories that depend on this package | Propagated from librariesio_projects data |
| `score` | Numeric | Libraries.io score for the package | Quality/importance metric; higher is better |
| `latest_release_number` | String | Version number analyzed | Matches the release version for which dependency data was fetched |
| `latest_release_published_at` | ISO 8601 Date | Publication date of the analyzed version | Indicates when this version was released |
| `versions_count` | Integer | Total historical versions of this package | Indicator of project maturity |

---

## Dataset: extracted_package_risk_summary.csv

**Source:** `build_extracted_package_risk_summary.js` (joined from osv_package_summary, librariesio_projects, and librariesio_dependencies)

**Purpose:** Comprehensive risk assessment combining vulnerability exposure, maintenance patterns, and popularity metrics. One row per unique npm package.

| Field Name | Type | Meaning | Transformation Notes |
|---|---|---|---|
| `package_name` | String | Normalized npm package name | Composite key with ecosystem; normalized to lowercase |
| `ecosystem` | String | Package ecosystem; always 'npm' | Normalized to lowercase |
| `stars` | Integer | GitHub/GitLab repository stars | From librariesio_projects; empty if no repository |
| `forks` | Integer | GitHub/GitLab repository forks | From librariesio_projects; empty if no repository |
| `contributions_count` | Integer | Total repository contributions | From librariesio_projects |
| `dependent_repos_count` | Integer | Number of dependent repositories | From librariesio_projects; indicates usage breadth |
| `dependents_count` | Integer | Total packages depending on this package | From librariesio_projects; indirect impact of vulnerabilities |
| `rank` | Numeric | Libraries.io package rank | From librariesio_projects; composite quality metric |
| `repository_status` | String | Repository maintenance status | Values like 'Active', 'Unmaintained', 'Archived'; key risk indicator |
| `latest_release_published_at` | ISO 8601 Date | Date of latest release | From librariesio_projects; used to compute maintenance recency |
| `versions_count` | Integer | Total historical versions | From librariesio_projects; maturity indicator |
| `runtime_dependencies_count` | Integer | Direct runtime dependencies | From librariesio_dependencies; transitive risk indicator |
| `score` | Numeric | Libraries.io quality score | From librariesio_dependencies; composite metric |
| `days_since_last_release` | Integer | Days elapsed since latest release to current date (April 2, 2026) | **Computed field:** `(April 2, 2026) - latest_release_published_at`; key maintenance metric |
| `has_repository` | Boolean | Flag indicating if repository URL is available | Computed as 'true' if repository_url is non-empty; important for code review access |
| `is_unmaintained` | Boolean | Flag indicating if repository_status is 'Unmaintained' | Computed field; case-insensitive comparison; critical risk indicator |
| `vulnerability_count` | Integer | Total distinct vulnerabilities in OSV database | From osv_package_summary; empty if no OSV records |
| `high_severity_count` | Integer | Count of high-severity vulnerabilities (CVSS >= 7.0) | From osv_package_summary; critical risk metric |
| `max_severity_score` | Numeric (1 decimal) | Maximum CVSS score across all vulnerabilities | From osv_package_summary; empty if no vulnerabilities |
| `has_high_severity_vulnerability` | Boolean | Flag indicating presence of high-severity vulnerabilities | From osv_package_summary; 'true' if any vulnerability with CVSS >= 7.0 |

---

## Data Quality Notes

### Package Name Normalization

All datasets normalize package names consistently:
- Convert to lowercase
- Trim leading/trailing whitespace
- Composite keys use format: `package_name|ecosystem`

This ensures reliable joining across datasets from different sources.

### Missing Data Handling

- **OSV Vulnerabilities:** Packages without OSV records are treated as having no known vulnerabilities (vulnerability_count = empty/0)
- **Repository Data:** Fields like `stars`, `forks` may be empty for packages without public repositories
- **Severity Scores:** Empty if not available in source data; this differs from zero

### Date Fields

- All timestamps use ISO 8601 format with timezone information
- Relative date calculations (e.g., `days_since_last_release`) are computed relative to the analysis date of April 2, 2026
- Missing publication dates result in empty relative date fields

### Aggregation Rules

- **Vulnerability Counts:** Distinct osv_id values per package; each vulnerability counted once per package
- **Severity Scores:** Maximum score used when package has multiple vulnerabilities with different scores
- **Dependencies:** Count of direct dependencies only; excludes transitive/indirect dependencies

---

## Common Analysis Patterns

### Risk Assessment
Combine:
- `vulnerability_count` and `high_severity_count` for exposure
- `days_since_last_release` and `is_unmaintained` for maintenance risk
- `dependent_repos_count` and `dependents_count` for impact scope

### Maintenance Health Indicators
- `is_unmaintained` - Critical flag
- `days_since_last_release` - Recency metric (lower = more maintained)
- `repository_status` - Explicit status indicator
- `latest_release_published_at` - Timestamp for verification

### Popularity & Impact
- `stars`, `forks` - Community engagement
- `dependents_count` - Downstream impact of security issues
- `rank` - Libraries.io composite quality metric

### Dependency Complexity
- `runtime_dependencies_count` - Direct dependency burden
- `dependents_count` - Dependency burden on others

---

## References

- **OSV Database:** https://osv.dev/
- **Libraries.io API:** https://libraries.io/api
- **CVSS Scoring:** https://www.first.org/cvss/
- **Semantic Versioning:** https://semver.org/
