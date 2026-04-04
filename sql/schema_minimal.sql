DROP TABLE IF EXISTS extracted_package_risk_summary CASCADE;
DROP TABLE IF EXISTS package_vulnerability_summary CASCADE;
DROP TABLE IF EXISTS raw_librariesio_projects CASCADE;
DROP TABLE IF EXISTS raw_osv_vulnerabilities CASCADE;

CREATE TABLE raw_osv_vulnerabilities (
    id BIGSERIAL PRIMARY KEY,
    osv_id TEXT NOT NULL,
    package_name TEXT NOT NULL,
    ecosystem TEXT NOT NULL,
    published TIMESTAMPTZ,
    modified TIMESTAMPTZ,
    severity_type TEXT,
    severity_score NUMERIC,
    is_high_severity BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_raw_osv_vulnerabilities_package_name ON raw_osv_vulnerabilities(package_name);
CREATE INDEX idx_raw_osv_vulnerabilities_osv_id ON raw_osv_vulnerabilities(osv_id);

CREATE TABLE raw_librariesio_projects (
    id BIGSERIAL PRIMARY KEY,
    package_name TEXT NOT NULL,
    platform TEXT NOT NULL,
    description TEXT,
    language TEXT,
    stars INTEGER,
    forks INTEGER,
    contributions_count INTEGER,
    dependent_repos_count INTEGER,
    dependents_count INTEGER,
    rank INTEGER,
    repository_status TEXT,
    repository_url TEXT,
    licenses TEXT,
    normalized_licenses TEXT,
    latest_release_number TEXT,
    latest_release_published_at TIMESTAMPTZ,
    versions_count INTEGER
);

CREATE INDEX idx_raw_librariesio_projects_package_name ON raw_librariesio_projects(package_name);

CREATE TABLE package_vulnerability_summary (
    package_name TEXT PRIMARY KEY,
    ecosystem TEXT NOT NULL,
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    high_severity_count INTEGER NOT NULL DEFAULT 0,
    max_severity_score NUMERIC,
    latest_vulnerability_published_at TIMESTAMPTZ,
    has_high_severity_vulnerability BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE extracted_package_risk_summary (
    package_name TEXT PRIMARY KEY,
    ecosystem TEXT NOT NULL,
    stars INTEGER,
    forks INTEGER,
    contributions_count INTEGER,
    dependent_repos_count INTEGER,
    dependents_count INTEGER,
    rank INTEGER,
    repository_status TEXT,
    latest_release_published_at TIMESTAMPTZ,
    versions_count INTEGER,
    days_since_last_release INTEGER,
    has_repository BOOLEAN NOT NULL DEFAULT FALSE,
    is_unmaintained BOOLEAN NOT NULL DEFAULT FALSE,
    vulnerability_count INTEGER NOT NULL DEFAULT 0,
    high_severity_count INTEGER NOT NULL DEFAULT 0,
    max_severity_score NUMERIC,
    has_high_severity_vulnerability BOOLEAN NOT NULL DEFAULT FALSE
);
