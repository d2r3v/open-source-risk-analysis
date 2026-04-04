-- ============================================================================
-- PostgreSQL Data Load Script
-- Open-Source Package Vulnerabilities and Maintenance Patterns Analysis
-- ============================================================================
-- This script loads cleaned CSV data into the PostgreSQL database.
-- 
-- Usage: psql -U username -d database_name -f sql/load_data.sql
--
-- Note: Ensure CSV files are in the correct paths relative to the database
-- server's file system, or adjust paths as needed.
-- ============================================================================

-- Set some useful session variables
SET search_path TO public;
SET statement_timeout = 0;

-- ============================================================================
-- Step 1: Load raw_osv_vulnerabilities
-- ============================================================================
-- Purpose: Load flattened OSV vulnerability records from osv_npm_flat.csv
-- 
-- This table stores extracted vulnerability data for npm packages from the
-- OSV database. Each row represents one affected package per vulnerability.
--
-- Expected CSV columns:
--   osv_id, package_name, ecosystem, published, modified, severity_type,
--   severity_score, is_high_severity
--
-- Note: We manually parse severity_score as NUMERIC since CSV contains
-- formatted numbers like "7.5"
--

COPY raw_osv_vulnerabilities (
  osv_id,
  package_name,
  ecosystem,
  published_at,
  modified_at,
  summary,
  severity,
  cvss_score,
  ingested_at
)
FROM PROGRAM 'awk -F'','' ''NR>1 {
  split($1, a, "\"");
  osv_id = (a[1] == "") ? a[2] : a[1];
  package_name = ($(NF-6) ~ /"/) ? substr($(NF-6), 2, length($(NF-6))-2) : $(NF-6);
  ecosystem = ($(NF-5) ~ /"/) ? substr($(NF-5), 2, length($(NF-5))-2) : $(NF-5);
  published = ($(NF-4) ~ /"/) ? substr($(NF-4), 2, length($(NF-4))-2) : $(NF-4);
  modified = ($(NF-3) ~ /"/) ? substr($(NF-3), 2, length($(NF-3))-2) : $(NF-3);
  severity_type = ($(NF-2) ~ /"/) ? substr($(NF-2), 2, length($(NF-2))-2) : $(NF-2);
  severity_score = ($(NF-1) ~ /"/) ? substr($(NF-1), 2, length($(NF-1))-2) : $(NF-1);
  print osv_id, package_name, ecosystem, published, modified, "", severity_type, severity_score, "NOW()"
}'' data/cleaned/osv_npm_flat.csv'
WITH (
  FORMAT CSV,
  DELIMITER E'\t'
);

-- Alternative method using direct CSV COPY (if file structure is simple):
-- Note: Uncomment below and comment out above if direct COPY works better

/*
COPY raw_osv_vulnerabilities (
  osv_id,
  package_name,
  ecosystem,
  summary,
  severity,
  cvss_score,
  ingested_at
)
FROM 'data/cleaned/osv_npm_flat.csv'
WITH (
  FORMAT CSV,
  HEADER,
  DELIMITER ',',
  NULL '',
  DEFAULT NOW()
);
*/

COMMIT;
SELECT 'Loaded raw_osv_vulnerabilities:' AS status,
       COUNT(*) AS record_count
FROM raw_osv_vulnerabilities;

-- ============================================================================
-- Step 2: Load raw_librariesio_projects
-- ============================================================================
-- Purpose: Load project metadata from Libraries.io into raw_librariesio_projects
--
-- This table stores raw project information from Libraries.io API including
-- repository details, statistics, and version information.
--
-- Expected CSV columns:
--   package_name, platform, description, language, stars, forks,
--   contributions_count, dependent_repos_count, dependents_count, rank,
--   repository_status, repository_url, licenses, normalized_licenses,
--   latest_release_number, latest_release_published_at, versions_count
--

COPY raw_librariesio_projects (
  package_name,
  platform,
  description,
  language,
  stars_count,
  forks_count,
  contributions_count,
  dependent_repositories_count,
  dependent_count,
  rank,
  repository_url,
  license,
  latest_version,
  latest_release_published_at,
  dependent_projects_count,
  ingested_at
)
FROM 'data/cleaned/librariesio_projects.csv'
WITH (
  FORMAT CSV,
  HEADER,
  DELIMITER ',',
  NULL '',
  DEFAULT NOW()
);

COMMIT;
SELECT 'Loaded raw_librariesio_projects:' AS status,
       COUNT(*) AS record_count
FROM raw_librariesio_projects;

-- ============================================================================
-- Step 3: Load raw_librariesio_dependencies
-- ============================================================================
-- Purpose: Load dependency data from Libraries.io
--
-- This table stores the dependency graph showing which packages depend
-- on which others, with version constraints.
--
-- Expected CSV columns:
--   package_name, platform, runtime_dependencies_count, dependents_count,
--   dependent_repos_count, score, latest_release_number,
--   latest_release_published_at, versions_count
--

COPY raw_librariesio_dependencies (
  package_name,
  platform,
  package_version,
  dependency_name,
  dependency_platform,
  version_requirement,
  kind,
  ingested_at
)
FROM 'data/cleaned/librariesio_dependencies.csv'
WITH (
  FORMAT CSV,
  HEADER,
  DELIMITER ',',
  NULL '',
  DEFAULT NOW()
);

COMMIT;
SELECT 'Loaded raw_librariesio_dependencies:' AS status,
       COUNT(*) AS record_count
FROM raw_librariesio_dependencies;

-- ============================================================================
-- Step 4: Populate cleaned_package_metadata from raw_librariesio_projects
-- ============================================================================
-- Purpose: Create normalized package metadata from Libraries.io project data
--
-- This step transforms raw project data into a clean, deduplicated dimension
-- table that serves as the primary package reference.
--

INSERT INTO cleaned_package_metadata (
  package_name,
  ecosystem,
  description,
  homepage_url,
  repository_url,
  repository_host,
  license,
  language,
  latest_version,
  latest_release_published_at,
  first_release_published_at,
  stars_count,
  forks_count,
  watchers_count,
  contributions_count,
  sourcerank,
  dependent_projects_count,
  dependent_repositories_count,
  last_updated_at
)
SELECT DISTINCT ON (package_name, platform)
  LOWER(TRIM(package_name)) AS package_name,
  LOWER(COALESCE(platform, 'npm')) AS ecosystem,
  description,
  NULL::VARCHAR AS homepage_url,
  repository_url,
  NULL::VARCHAR AS repository_host,
  license,
  language,
  latest_version,
  latest_release_published_at,
  NULL::TIMESTAMP WITH TIME ZONE AS first_release_published_at,
  COALESCE(stars_count, 0) AS stars_count,
  COALESCE(forks_count, 0) AS forks_count,
  COALESCE(watchers_count, 0) AS watchers_count,
  COALESCE(contributions_count, 0) AS contributions_count,
  rank AS sourcerank,
  COALESCE(dependent_projects_count, 0) AS dependent_projects_count,
  COALESCE(dependent_repositories_count, 0) AS dependent_repositories_count,
  CURRENT_TIMESTAMP AS last_updated_at
FROM raw_librariesio_projects
WHERE package_name IS NOT NULL
ORDER BY package_name, platform, ingested_at DESC;

COMMIT;
SELECT 'Populated cleaned_package_metadata:' AS status,
       COUNT(*) AS record_count
FROM cleaned_package_metadata;

-- ============================================================================
-- Step 5: Load package_vulnerability_summary
-- ============================================================================
-- Purpose: Load aggregated vulnerability metrics by package
--
-- This table provides a summary view of vulnerability exposure for each
-- package including counts by severity and temporal metrics.
--
-- Expected CSV columns:
--   package_name, ecosystem, vulnerability_count, high_severity_count,
--   max_severity_score, latest_vulnerability_published_at,
--   has_high_severity_vulnerability
--

COPY package_vulnerability_summary (
  package_name,
  ecosystem,
  total_vulnerabilities,
  high_vulnerabilities,
  highest_cvss_score,
  newest_vulnerability_published_at,
  has_withdrawn_vulnerabilities,
  calculated_at
)
FROM 'data/cleaned/osv_package_summary.csv'
WITH (
  FORMAT CSV,
  HEADER,
  DELIMITER ',',
  NULL '',
  DEFAULT CURRENT_TIMESTAMP
);

-- Update package_id foreign key references
UPDATE package_vulnerability_summary pvs
SET package_id = cpm.package_id
FROM cleaned_package_metadata cpm
WHERE LOWER(TRIM(pvs.package_name)) = cpm.package_name
  AND LOWER(COALESCE(pvs.ecosystem, 'npm')) = cpm.ecosystem;

COMMIT;
SELECT 'Loaded package_vulnerability_summary:' AS status,
       COUNT(*) AS record_count,
       SUM(CASE WHEN package_id IS NOT NULL THEN 1 ELSE 0 END) AS with_package_id
FROM package_vulnerability_summary;

-- ============================================================================
-- Step 6: Load extracted_package_risk_summary
-- ============================================================================
-- Purpose: Load comprehensive risk assessment combining all data sources
--
-- This table provides a holistic risk profile for each package combining
-- vulnerability metrics, maintenance patterns, and popularity indicators.
--
-- Expected CSV columns:
--   package_name, ecosystem, stars, forks, contributions_count,
--   dependent_repos_count, dependents_count, rank, repository_status,
--   latest_release_published_at, versions_count, runtime_dependencies_count,
--   score, days_since_last_release, has_repository, is_unmaintained,
--   vulnerability_count, high_severity_count, max_severity_score,
--   has_high_severity_vulnerability
--

COPY extracted_package_risk_summary (
  package_name,
  ecosystem,
  risk_score,
  risk_category,
  vulnerability_risk_score,
  maintenance_risk_score,
  popularity_risk_score,
  is_actively_maintained,
  maintenance_frequency,
  last_release_days_ago,
  project_age_years,
  contributors_count,
  recent_activity_score,
  vulnerability_trend_direction,
  version_adoption_stability,
  dependency_count,
  dependent_count,
  transitive_vulnerability_risk,
  recommendations,
  calculated_at
)
FROM 'data/exports/extracted_package_risk_summary.csv'
WITH (
  FORMAT CSV,
  HEADER,
  DELIMITER ',',
  NULL '',
  DEFAULT CURRENT_TIMESTAMP
);

-- Update package_id foreign key references
UPDATE extracted_package_risk_summary eprs
SET package_id = cpm.package_id
FROM cleaned_package_metadata cpm
WHERE LOWER(TRIM(eprs.package_name)) = cpm.package_name
  AND LOWER(COALESCE(eprs.ecosystem, 'npm')) = cpm.ecosystem;

COMMIT;
SELECT 'Loaded extracted_package_risk_summary:' AS status,
       COUNT(*) AS record_count,
       SUM(CASE WHEN package_id IS NOT NULL THEN 1 ELSE 0 END) AS with_package_id
FROM extracted_package_risk_summary;

-- ============================================================================
-- Step 7: Verify Data Integrity
-- ============================================================================
-- Purpose: Run sanity checks on loaded data
--

-- Check for orphaned vulnerability records
SELECT 'Vulnerability summary records without metadata:' AS check_name,
       COUNT(*) AS issue_count
FROM package_vulnerability_summary pvs
WHERE package_id IS NULL
HAVING COUNT(*) > 0;

-- Check for orphaned risk summary records
SELECT 'Risk summary records without metadata:' AS check_name,
       COUNT(*) AS issue_count
FROM extracted_package_risk_summary eprs
WHERE package_id IS NULL
HAVING COUNT(*) > 0;

-- Summary statistics
SELECT 'Total packages:' AS metric, COUNT(*)::TEXT AS value
FROM cleaned_package_metadata
UNION ALL
SELECT 'Total vulnerabilities:', COUNT(*)::TEXT
FROM raw_osv_vulnerabilities
UNION ALL
SELECT 'Packages with vulnerabilities:', COUNT(DISTINCT package_name)::TEXT
FROM package_vulnerability_summary
WHERE total_vulnerabilities > 0
UNION ALL
SELECT 'High-severity vulnerabilities:', SUM(high_vulnerabilities)::TEXT
FROM package_vulnerability_summary;

-- ============================================================================
-- Step 8: Final Summary
-- ============================================================================
-- Purpose: Display summary of all loaded data
--

\echo ''
\echo '=========================================='
\echo 'Data Load Summary'
\echo '=========================================='

\echo 'Raw OSV Vulnerabilities'
SELECT '  Records loaded:' AS metric, COUNT(*) AS count FROM raw_osv_vulnerabilities;

\echo 'Raw Libraries.io Projects'
SELECT '  Records loaded:' AS metric, COUNT(*) AS count FROM raw_librariesio_projects;

\echo 'Raw Libraries.io Dependencies'
SELECT '  Records loaded:' AS metric, COUNT(*) AS count FROM raw_librariesio_dependencies;

\echo 'Cleaned Package Metadata'
SELECT '  Records loaded:' AS metric, COUNT(*) AS count FROM cleaned_package_metadata;

\echo 'Package Vulnerability Summary'
SELECT '  Records loaded:' AS metric, COUNT(*) AS count FROM package_vulnerability_summary;

\echo 'Extracted Package Risk Summary'
SELECT '  Records loaded:' AS metric, COUNT(*) AS count FROM extracted_package_risk_summary;

\echo ''
\echo 'Data load complete!'
\echo '=========================================='

-- ============================================================================
-- End of Load Script
-- ============================================================================
