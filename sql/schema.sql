-- ============================================================================
-- Open-Source Package Vulnerabilities and Maintenance Patterns Analysis
-- PostgreSQL Schema
-- ============================================================================

-- Drop existing tables if they exist (idempotent schema)
DROP TABLE IF EXISTS extracted_package_risk_summary CASCADE;
DROP TABLE IF EXISTS package_vulnerability_summary CASCADE;
DROP TABLE IF EXISTS raw_osv_vulnerabilities CASCADE;
DROP TABLE IF EXISTS raw_librariesio_projects CASCADE;
DROP TABLE IF EXISTS raw_librariesio_dependencies CASCADE;

-- ============================================================================
-- Table 1: raw_osv_vulnerabilities
-- ============================================================================
CREATE TABLE raw_osv_vulnerabilities (
    id SERIAL PRIMARY KEY,
    osv_id VARCHAR(50) NOT NULL,
    package_name VARCHAR(255) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL,
    published TIMESTAMP,
    modified TIMESTAMP,
    severity_type VARCHAR(50),
    severity_score NUMERIC(3, 1),
    is_high_severity BOOLEAN DEFAULT FALSE,
    is_malware BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- Table 2: raw_librariesio_projects
-- ============================================================================
CREATE TABLE raw_librariesio_projects (
    id SERIAL PRIMARY KEY,
    package_name VARCHAR(255) NOT NULL,
    platform VARCHAR(50),
    description TEXT,
    language VARCHAR(100),
    stars INTEGER DEFAULT 0,
    forks INTEGER DEFAULT 0,
    contributions_count INTEGER DEFAULT 0,
    dependent_repos_count INTEGER DEFAULT 0,
    dependents_count INTEGER DEFAULT 0,
    rank INTEGER DEFAULT 0,
    repository_status VARCHAR(50),
    repository_url TEXT,
    licenses VARCHAR(255),
    normalized_licenses VARCHAR(255),
    latest_release_number VARCHAR(100),
    latest_release_published_at TIMESTAMP,
    versions_count INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- Table 3: package_vulnerability_summary
-- ============================================================================
CREATE TABLE package_vulnerability_summary (
    id SERIAL PRIMARY KEY,
    package_name VARCHAR(255) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL,
    vulnerability_count INTEGER DEFAULT 0,
    high_severity_count INTEGER DEFAULT 0,
    max_severity_score NUMERIC(3, 1),
    latest_vulnerability_published_at TIMESTAMP,
    has_high_severity_vulnerability BOOLEAN DEFAULT FALSE,
    osv_ids TEXT,
    last_updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(package_name, ecosystem)
);

-- ============================================================================
-- Table 4: extracted_package_risk_summary
-- ============================================================================
CREATE TABLE extracted_package_risk_summary (
    id SERIAL PRIMARY KEY,
    package_name VARCHAR(255) NOT NULL,
    ecosystem VARCHAR(50) NOT NULL,
    stars INTEGER,
    forks INTEGER,
    contributions_count INTEGER,
    dependent_repos_count INTEGER,
    dependents_count INTEGER,
    rank INTEGER,
    repository_status VARCHAR(50),
    latest_release_published_at TIMESTAMP,
    versions_count INTEGER,
    days_since_last_release INTEGER,
    has_repository BOOLEAN,
    is_unmaintained BOOLEAN,
    vulnerability_count INTEGER,
    high_severity_count INTEGER,
    max_severity_score NUMERIC(3, 1),
    has_high_severity_vulnerability BOOLEAN,
    
    -- Analysis / Scored Fields (computed later)
    risk_score NUMERIC(5, 2),
    risk_category VARCHAR(50),
    
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(package_name, ecosystem)
);

-- Add indexes for common analytical queries
CREATE INDEX idx_osv_pkg ON raw_osv_vulnerabilities(package_name, ecosystem);
CREATE INDEX idx_risk_score ON extracted_package_risk_summary(risk_score DESC);
CREATE INDEX idx_risk_pkg ON extracted_package_risk_summary(package_name, ecosystem);
