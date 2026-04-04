-- sql/load_minimal.sql

-- ============================================================================
-- 1. Load raw_osv_vulnerabilities
-- ============================================================================
COPY raw_osv_vulnerabilities (
    osv_id,
    package_name,
    ecosystem,
    published,
    modified,
    severity_type,
    severity_score,
    is_high_severity
)
FROM 'data/cleaned/osv_npm_flat.csv'
WITH (
    FORMAT CSV,
    HEADER,
    DELIMITER ',',
    NULL ''
);

-- ============================================================================
-- 2. Load raw_librariesio_projects
-- ============================================================================
COPY raw_librariesio_projects (
    package_name,
    platform,
    description,
    language,
    stars,
    forks,
    contributions_count,
    dependent_repos_count,
    dependents_count,
    rank,
    repository_status,
    repository_url,
    licenses,
    normalized_licenses,
    latest_release_number,
    latest_release_published_at,
    versions_count
)
FROM 'data/cleaned/librariesio_projects.csv'
WITH (
    FORMAT CSV,
    HEADER,
    DELIMITER ',',
    NULL ''
);

-- ============================================================================
-- 3. Load package_vulnerability_summary
-- ============================================================================
COPY package_vulnerability_summary (
    package_name,
    ecosystem,
    vulnerability_count,
    high_severity_count,
    max_severity_score,
    latest_vulnerability_published_at,
    has_high_severity_vulnerability
)
FROM 'data/cleaned/osv_package_summary.csv'
WITH (
    FORMAT CSV,
    HEADER,
    DELIMITER ',',
    NULL ''
);

-- ============================================================================
-- 4. Load extracted_package_risk_summary
-- ============================================================================
COPY extracted_package_risk_summary (
    package_name,
    ecosystem,
    stars,
    forks,
    contributions_count,
    dependent_repos_count,
    dependents_count,
    rank,
    repository_status,
    latest_release_published_at,
    versions_count,
    days_since_last_release,
    has_repository,
    is_unmaintained,
    vulnerability_count,
    high_severity_count,
    max_severity_score,
    has_high_severity_vulnerability
)
FROM 'data/exports/extracted_package_risk_summary.csv'
WITH (
    FORMAT CSV,
    HEADER,
    DELIMITER ',',
    NULL ''
);
