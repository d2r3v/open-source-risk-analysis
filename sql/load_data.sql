-- ============================================================================
-- Open-Source Package Vulnerabilities and Maintenance Patterns Analysis
-- Data Loading Script (Optimized for Enriched CSVs)
-- ============================================================================

-- Note: Ensure paths are correct for your local environment.
-- The following commands assume you are running from the project root.

-- 1. Load Raw OSV Vulnerabilities
TRUNCATE raw_osv_vulnerabilities;
\COPY raw_osv_vulnerabilities (osv_id, package_name, ecosystem, published, modified, severity_type, severity_score, is_high_severity, is_malware) FROM 'data/cleaned/osv_npm_flat.csv' WITH (FORMAT csv, HEADER true);

-- 2. Load Raw Libraries.io Projects
TRUNCATE raw_librariesio_projects;
\COPY raw_librariesio_projects (package_name, ecosystem, stars, forks, contributions_count, dependent_repos_count, dependents_count, rank, repository_status, latest_release_published_at, versions_count, repository_url) FROM 'data/cleaned/librariesio_projects.csv' WITH (FORMAT csv, HEADER true);

-- 3. Load Package Vulnerability Summary
TRUNCATE package_vulnerability_summary;
\COPY package_vulnerability_summary (package_name, ecosystem, vulnerability_count, high_severity_count, max_severity_score, latest_vulnerability_published_at, has_high_severity_vulnerability, osv_ids) FROM 'data/cleaned/osv_package_summary.csv' WITH (FORMAT csv, HEADER true);

-- 4. Load Extracted Package Risk Summary (Final Joined Dataset)
TRUNCATE extracted_package_risk_summary;
\COPY extracted_package_risk_summary (package_name, ecosystem, stars, forks, contributions_count, dependent_repos_count, dependents_count, rank, repository_status, latest_release_published_at, versions_count, days_since_last_release, has_repository, is_unmaintained, vulnerability_count, high_severity_count, max_severity_score, has_high_severity_vulnerability) FROM 'data/exports/extracted_package_risk_summary.csv' WITH (FORMAT csv, HEADER true);

-- Verification: Print row counts
SELECT 'raw_osv_vulnerabilities' as table_name, COUNT(*) FROM raw_osv_vulnerabilities
UNION ALL
SELECT 'package_vulnerability_summary', COUNT(*) FROM package_vulnerability_summary
UNION ALL
SELECT 'extracted_package_risk_summary', COUNT(*) FROM extracted_package_risk_summary;
