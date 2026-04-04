-- ============================================================================
-- Open-Source Package Vulnerabilities and Maintenance Patterns Analysis
-- PostgreSQL Schema
-- ============================================================================
-- This schema defines the data structures for analyzing vulnerabilities,
-- dependencies, and maintenance patterns across open-source packages.
-- ============================================================================

-- Drop existing tables if they exist (idempotent schema)
DROP TABLE IF EXISTS extracted_package_risk_summary CASCADE;
DROP TABLE IF EXISTS package_vulnerability_summary CASCADE;
DROP TABLE IF EXISTS cleaned_package_metadata CASCADE;
DROP TABLE IF EXISTS raw_librariesio_dependencies CASCADE;
DROP TABLE IF EXISTS raw_librariesio_projects CASCADE;
DROP TABLE IF EXISTS raw_osv_vulnerabilities CASCADE;

-- ============================================================================
-- Table 1: raw_osv_vulnerabilities
-- ============================================================================
-- Purpose: Stores raw vulnerability data from the Open Source Vulnerabilities
-- (OSV) database. Each record contains a complete vulnerability report with
-- all metadata preserved as JSONB for flexible querying.
--
-- Key fields:
--   - osv_id: Unique vulnerability identifier (e.g., "GHSA-xxxx-yyyy-zzzz")
--   - package_name + ecosystem: Composite identifier for affected package
--   - raw_payload: Complete OSV JSON record for archival and detailed analysis
--
CREATE TABLE raw_osv_vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    osv_id VARCHAR(255) NOT NULL UNIQUE,
    package_name VARCHAR(500) NOT NULL,
    ecosystem VARCHAR(100) NOT NULL,
    affected_versions TEXT[],
    published_at TIMESTAMP WITH TIME ZONE,
    modified_at TIMESTAMP WITH TIME ZONE,
    withdrawn_at TIMESTAMP WITH TIME ZONE,
    summary TEXT,
    details TEXT,
    severity VARCHAR(20),
    cvss_score NUMERIC(3, 1),
    cvss_vector VARCHAR(255),
    cwe_ids VARCHAR(20)[],
    references JSONB,
    raw_payload JSONB NOT NULL,
    ingested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_osv_package ON (package_name, ecosystem),
    INDEX idx_osv_ecosystem ON (ecosystem),
    INDEX idx_osv_published ON (published_at),
    INDEX idx_osv_severity ON (severity)
);

COMMENT ON TABLE raw_osv_vulnerabilities IS
'Raw vulnerability data from the Open Source Vulnerabilities (OSV) database. 
Stores complete OSV records with all metadata for comprehensive vulnerability analysis.';

COMMENT ON COLUMN raw_osv_vulnerabilities.osv_id IS
'Unique vulnerability identifier from OSV database (e.g., GHSA-, CVE-, GHSA-)';

COMMENT ON COLUMN raw_osv_vulnerabilities.package_name IS
'Package name (consistent naming across ecosystems)';

COMMENT ON COLUMN raw_osv_vulnerabilities.ecosystem IS
'Package ecosystem/platform (npm, pip, nuget, cargo, etc.)';

COMMENT ON COLUMN raw_osv_vulnerabilities.affected_versions IS
'Array of version specifiers affected by this vulnerability';

COMMENT ON COLUMN raw_osv_vulnerabilities.raw_payload IS
'Complete original JSON payload from OSV API for archival and detailed analysis';

-- ============================================================================
-- Table 2: raw_librariesio_projects
-- ============================================================================
-- Purpose: Stores raw project metadata from Libraries.io API. This table
-- captures package-level information including repository details, latest
-- versions, and project statistics.
--
-- Key fields:
--   - package_name + platform: Composite natural key for projects
--   - raw_payload: Complete Libraries.io JSON for flexibility
--
CREATE TABLE raw_librariesio_projects (
    id BIGSERIAL PRIMARY KEY,
    package_name VARCHAR(500) NOT NULL,
    platform VARCHAR(100) NOT NULL,
    librariesio_id BIGINT UNIQUE,
    description TEXT,
    homepage_url VARCHAR(1000),
    repository_url VARCHAR(1000),
    repository_host VARCHAR(100),
    latest_version VARCHAR(100),
    latest_release_published_at TIMESTAMP WITH TIME ZONE,
    latest_download_url VARCHAR(1000),
    rank NUMERIC,
    stars_count INT,
    forks_count INT,
    watchers_count INT,
    contributions_count INT,
    sourcerank NUMERIC,
    code_of_conduct_url VARCHAR(1000),
    license VARCHAR(255),
    changelog_url VARCHAR(1000),
    documentation_url VARCHAR(1000),
    package_manager_url VARCHAR(1000),
    first_release_published_at TIMESTAMP WITH TIME ZONE,
    dependent_projects_count INT,
    dependent_repositories_count INT,
    dependent_count INT,
    language VARCHAR(100),
    raw_payload JSONB NOT NULL,
    ingested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_project_platform ON (package_name, platform),
    INDEX idx_project_name ON (package_name),
    INDEX idx_project_stars ON (stars_count DESC),
    INDEX idx_project_rank ON (rank DESC)
);

COMMENT ON TABLE raw_librariesio_projects IS
'Raw project metadata from Libraries.io API. Contains package information including
repository details, version history, and project statistics.';

COMMENT ON COLUMN raw_librariesio_projects.package_name IS
'Package name (consistent with OSV and dependencies data)';

COMMENT ON COLUMN raw_librariesio_projects.platform IS
'Package platform/ecosystem (npm, PyPI, NuGet, crates.io, etc.)';

COMMENT ON COLUMN raw_librariesio_projects.raw_payload IS
'Complete original JSON payload from Libraries.io API';

-- ============================================================================
-- Table 3: raw_librariesio_dependencies
-- ============================================================================
-- Purpose: Stores raw dependency data from Libraries.io API. Records the
-- dependency graph showing which packages depend on which others, including
-- version requirements and constraint information.
--
-- Key fields:
--   - package_name + ecosystem: The dependent package
--   - dependency_name + dependency_ecosystem: The dependency
--   - version_requirement: Version constraint specification
--
CREATE TABLE raw_librariesio_dependencies (
    id BIGSERIAL PRIMARY KEY,
    package_name VARCHAR(500) NOT NULL,
    platform VARCHAR(100) NOT NULL,
    package_version VARCHAR(100) NOT NULL,
    dependency_name VARCHAR(500) NOT NULL,
    dependency_platform VARCHAR(100) NOT NULL,
    version_requirement VARCHAR(255),
    kind VARCHAR(100),
    optional BOOLEAN,
    raw_payload JSONB NOT NULL,
    ingested_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_dep_package ON (package_name, platform),
    INDEX idx_dep_dependency ON (dependency_name, dependency_platform),
    INDEX idx_dep_version ON (package_name, platform, package_version)
);

COMMENT ON TABLE raw_librariesio_dependencies IS
'Raw dependency relationships from Libraries.io API. Captures the dependency
graph showing how packages depend on one another with version constraints.';

COMMENT ON COLUMN raw_librariesio_dependencies.package_name IS
'Name of the package that has dependencies';

COMMENT ON COLUMN raw_librariesio_dependencies.platform IS
'Platform/ecosystem of the dependent package';

COMMENT ON COLUMN raw_librariesio_dependencies.dependency_name IS
'Name of the dependency package';

COMMENT ON COLUMN raw_librariesio_dependencies.dependency_platform IS
'Platform/ecosystem of the dependency package';

COMMENT ON COLUMN raw_librariesio_dependencies.version_requirement IS
'Version constraint specification (e.g., "^1.0.0", ">=1.0,<2.0")';

COMMENT ON COLUMN raw_librariesio_dependencies.kind IS
'Type of dependency (runtime, development, peer, optional, etc.)';

-- ============================================================================
-- Table 4: cleaned_package_metadata
-- ============================================================================
-- Purpose: Cleaned and normalized package metadata derived from raw Libraries.io
-- project data. This is the primary dimension table for packages used in analysis.
--
-- Key fields:
--   - package_name + ecosystem: Unique package identifier
--   - Primary key on this composite for query optimization
--
CREATE TABLE cleaned_package_metadata (
    package_id SERIAL PRIMARY KEY,
    package_name VARCHAR(500) NOT NULL,
    ecosystem VARCHAR(100) NOT NULL,
    description TEXT,
    homepage_url VARCHAR(1000),
    repository_url VARCHAR(1000),
    repository_host VARCHAR(100),
    license VARCHAR(255),
    language VARCHAR(100),
    latest_version VARCHAR(100),
    latest_release_published_at TIMESTAMP WITH TIME ZONE,
    first_release_published_at TIMESTAMP WITH TIME ZONE,
    stars_count INT DEFAULT 0,
    forks_count INT DEFAULT 0,
    watchers_count INT DEFAULT 0,
    contributions_count INT DEFAULT 0,
    sourcerank NUMERIC,
    dependent_projects_count INT DEFAULT 0,
    dependent_repositories_count INT DEFAULT 0,
    days_since_first_release INT,
    days_since_last_release INT,
    last_updated_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(package_name, ecosystem),
    INDEX idx_pkg_ecosystem ON (ecosystem),
    INDEX idx_pkg_name ON (package_name),
    INDEX idx_pkg_stars ON (stars_count DESC),
    INDEX idx_pkg_sourcerank ON (sourcerank DESC)
);

COMMENT ON TABLE cleaned_package_metadata IS
'Cleaned and normalized package metadata from Libraries.io. Primary dimension table
for packages used in vulnerability and maintenance pattern analysis.';

COMMENT ON COLUMN cleaned_package_metadata.ecosystem IS
'Package ecosystem/platform (npm, pip, nuget, cargo, etc.)';

COMMENT ON COLUMN cleaned_package_metadata.days_since_first_release IS
'Number of days since the first version was released (project age)';

COMMENT ON COLUMN cleaned_package_metadata.days_since_last_release IS
'Number of days since the most recent version was released (maintenance recency)';

-- ============================================================================
-- Table 5: package_vulnerability_summary
-- ============================================================================
-- Purpose: Aggregated vulnerability metrics by package. Provides a summary
-- view of vulnerability exposure for each package including counts by severity,
-- affected version ranges, and temporal metrics.
--
-- Key fields:
--   - package_name + ecosystem: Links to cleaned_package_metadata
--   - vulnerability counts and severity breakdown
--   - temporal metrics for oldest and newest vulnerabilities
--
CREATE TABLE package_vulnerability_summary (
    summary_id SERIAL PRIMARY KEY,
    package_id INT REFERENCES cleaned_package_metadata(package_id),
    package_name VARCHAR(500) NOT NULL,
    ecosystem VARCHAR(100) NOT NULL,
    total_vulnerabilities INT DEFAULT 0,
    critical_vulnerabilities INT DEFAULT 0,
    high_vulnerabilities INT DEFAULT 0,
    medium_vulnerabilities INT DEFAULT 0,
    low_vulnerabilities INT DEFAULT 0,
    unknown_severity_vulnerabilities INT DEFAULT 0,
    vulnerabilities_in_latest_version INT DEFAULT 0,
    vulnerabilities_in_current_majors INT DEFAULT 0,
    oldest_vulnerability_published_at TIMESTAMP WITH TIME ZONE,
    newest_vulnerability_published_at TIMESTAMP WITH TIME ZONE,
    days_to_patch_median NUMERIC,
    days_to_patch_avg NUMERIC,
    highest_cvss_score NUMERIC(3, 1),
    avg_cvss_score NUMERIC(3, 1),
    affected_versions_count INT DEFAULT 0,
    unique_cve_count INT DEFAULT 0,
    unique_ghsa_count INT DEFAULT 0,
    has_withdrawn_vulnerabilities BOOLEAN DEFAULT FALSE,
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(package_name, ecosystem),
    INDEX idx_summary_total_vuln ON (total_vulnerabilities DESC),
    INDEX idx_summary_critical ON (critical_vulnerabilities DESC),
    INDEX idx_summary_package ON (package_name, ecosystem)
);

COMMENT ON TABLE package_vulnerability_summary IS
'Aggregated vulnerability metrics by package. Provides summary counts, severity
breakdowns, and temporal metrics for vulnerability exposure analysis.';

COMMENT ON COLUMN package_vulnerability_summary.package_id IS
'Foreign key reference to cleaned_package_metadata for relational integrity';

COMMENT ON COLUMN package_vulnerability_summary.total_vulnerabilities IS
'Total count of distinct vulnerabilities affecting this package';

COMMENT ON COLUMN package_vulnerability_summary.vulnerabilities_in_latest_version IS
'Count of vulnerabilities affecting the latest released version';

COMMENT ON COLUMN package_vulnerability_summary.vulnerabilities_in_current_majors IS
'Count of vulnerabilities affecting current major version branches';

COMMENT ON COLUMN package_vulnerability_summary.days_to_patch_median IS
'Median number of days between vulnerability publication and package patch';

COMMENT ON COLUMN package_vulnerability_summary.affected_versions_count IS
'Number of distinct versions affected by recorded vulnerabilities';

-- ============================================================================
-- Table 6: extracted_package_risk_summary
-- ============================================================================
-- Purpose: Comprehensive risk assessment and maintenance pattern analysis
-- derived from multiple data sources. Combines vulnerability metrics with
-- maintenance indicators to create a holistic risk profile.
--
-- Key fields:
--   - package_name + ecosystem: Unique package identifier
--   - risk_score: Composite risk metric (0-100)
--   - maintenance metrics: activity, update frequency, age
--   - vulnerability metrics: from package_vulnerability_summary
--
CREATE TABLE extracted_package_risk_summary (
    risk_id SERIAL PRIMARY KEY,
    package_id INT REFERENCES cleaned_package_metadata(package_id),
    package_name VARCHAR(500) NOT NULL,
    ecosystem VARCHAR(100) NOT NULL,
    risk_score NUMERIC(5, 2) DEFAULT 0,
    risk_category VARCHAR(50),
    vulnerability_risk_score NUMERIC(5, 2) DEFAULT 0,
    maintenance_risk_score NUMERIC(5, 2) DEFAULT 0,
    popularity_risk_score NUMERIC(5, 2) DEFAULT 0,
    is_actively_maintained BOOLEAN,
    maintenance_frequency VARCHAR(50),
    last_release_days_ago INT,
    release_frequency_days INT,
    expected_next_release_days INT,
    project_age_years NUMERIC(4, 2),
    contributors_count INT,
    recent_activity_score NUMERIC(5, 2),
    vulnerability_trend_direction VARCHAR(20),
    version_adoption_stability NUMERIC(5, 2),
    dependency_count INT DEFAULT 0,
    dependent_count INT DEFAULT 0,
    transitive_vulnerability_risk BOOLEAN DEFAULT FALSE,
    recommendations TEXT[],
    analysis_metadata JSONB,
    calculated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(package_name, ecosystem),
    INDEX idx_risk_score ON (risk_score DESC),
    INDEX idx_risk_category ON (risk_category),
    INDEX idx_risk_package ON (package_name, ecosystem),
    INDEX idx_risk_maintenance ON (is_actively_maintained),
    INDEX idx_risk_ecosystem ON (ecosystem)
);

COMMENT ON TABLE extracted_package_risk_summary IS
'Comprehensive risk assessment combining vulnerability metrics with maintenance
patterns. Provides holistic risk profiles and actionable recommendations for
package selection and dependency management.';

COMMENT ON COLUMN extracted_package_risk_summary.risk_score IS
'Composite risk metric (0-100) combining vulnerability and maintenance factors';

COMMENT ON COLUMN extracted_package_risk_summary.risk_category IS
'Risk classification (e.g., Critical, High, Medium, Low, Minimal)';

COMMENT ON COLUMN extracted_package_risk_summary.vulnerability_risk_score IS
'Risk component based on vulnerability metrics (count, severity, recency)';

COMMENT ON COLUMN extracted_package_risk_summary.maintenance_risk_score IS
'Risk component based on maintenance patterns (activity, update frequency)';

COMMENT ON COLUMN extracted_package_risk_summary.is_actively_maintained IS
'Boolean flag indicating if the project has recent activity/updates';

COMMENT ON COLUMN extracted_package_risk_summary.maintenance_frequency IS
'Categorization of update frequency (daily, weekly, monthly, quarterly, yearly, dormant)';

COMMENT ON COLUMN extracted_package_risk_summary.last_release_days_ago IS
'Number of days since the most recent version release';

COMMENT ON COLUMN extracted_package_risk_summary.vulnerability_trend_direction IS
'Trend in vulnerability reports (increasing, stable, decreasing)';

COMMENT ON COLUMN extracted_package_risk_summary.transitive_vulnerability_risk IS
'Flag indicating if dependencies introduce additional vulnerability risks';

COMMENT ON COLUMN extracted_package_risk_summary.recommendations IS
'Array of actionable recommendations based on risk assessment';

COMMENT ON COLUMN extracted_package_risk_summary.analysis_metadata IS
'Additional metadata and calculation details in JSON format';

-- ============================================================================
-- End of Schema Definition
-- ============================================================================
