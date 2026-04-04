-- ============================================================================
-- Analytical Queries for Extracted Package Risk Summary
-- Open-Source Package Vulnerabilities and Maintenance Patterns Analysis
-- ============================================================================
-- This file contains 10 key analytical queries for exploring vulnerability
-- patterns, maintenance characteristics, and risk profiles across packages.
--
-- Tables used: extracted_package_risk_summary
-- ============================================================================

-- ============================================================================
-- Query 1: Total Package Count and Vulnerable Package Count
-- ============================================================================
-- Purpose: Get high-level summary of dataset composition
-- Shows total packages analyzed and how many have known vulnerabilities
--
SELECT
  COUNT(*) AS total_packages,
  SUM(CASE WHEN vulnerability_count > 0 THEN 1 ELSE 0 END) AS vulnerable_packages,
  SUM(CASE WHEN vulnerability_count = 0 OR vulnerability_count IS NULL THEN 1 ELSE 0 END) AS non_vulnerable_packages,
  ROUND(100.0 * SUM(CASE WHEN vulnerability_count > 0 THEN 1 ELSE 0 END) / COUNT(*), 2) AS vulnerability_percentage,
  SUM(CASE WHEN has_high_severity_vulnerability = 'true' THEN 1 ELSE 0 END) AS packages_with_high_severity,
  ROUND(100.0 * SUM(CASE WHEN has_high_severity_vulnerability = 'true' THEN 1 ELSE 0 END) / COUNT(*), 2) AS high_severity_percentage
FROM extracted_package_risk_summary;

-- ============================================================================
-- Query 2: Average Stars for High-Severity vs Non-High-Severity Packages
-- ============================================================================
-- Purpose: Compare popularity between vulnerable and non-vulnerable packages
-- Insight: Do more popular packages have more vulnerabilities discovered?
--
SELECT
  CASE
    WHEN has_high_severity_vulnerability = 'true' THEN 'High-Severity Vulnerable'
    ELSE 'No High-Severity Vulnerabilities'
  END AS vulnerability_status,
  COUNT(*) AS package_count,
  ROUND(AVG(CASE WHEN stars IS NOT NULL AND stars > 0 THEN stars ELSE NULL END), 2) AS avg_stars,
  MIN(CASE WHEN stars IS NOT NULL AND stars > 0 THEN stars ELSE NULL END) AS min_stars,
  MAX(CASE WHEN stars IS NOT NULL AND stars > 0 THEN stars ELSE NULL END) AS max_stars,
  ROUND(STDDEV(CASE WHEN stars IS NOT NULL AND stars > 0 THEN stars ELSE NULL END), 2) AS stddev_stars
FROM extracted_package_risk_summary
WHERE stars IS NOT NULL AND stars > 0
GROUP BY has_high_severity_vulnerability
ORDER BY vulnerability_status DESC;

-- ============================================================================
-- Query 3: Average Runtime Dependencies Count by Vulnerability Status
-- ============================================================================
-- Purpose: Analyze relationship between dependency complexity and vulnerabilities
-- Insight: Do packages with more dependencies have more vulnerabilities?
--
SELECT
  CASE
    WHEN has_high_severity_vulnerability = 'true' THEN 'High-Severity Vulnerable'
    ELSE 'No High-Severity Vulnerabilities'
  END AS vulnerability_status,
  COUNT(*) AS package_count,
  ROUND(AVG(CASE WHEN runtime_dependencies_count > 0 THEN runtime_dependencies_count ELSE NULL END), 2) AS avg_runtime_dependencies,
  MIN(CASE WHEN runtime_dependencies_count > 0 THEN runtime_dependencies_count ELSE NULL END) AS min_dependencies,
  MAX(CASE WHEN runtime_dependencies_count > 0 THEN runtime_dependencies_count ELSE NULL END) AS max_dependencies,
  ROUND(STDDEV(CASE WHEN runtime_dependencies_count > 0 THEN runtime_dependencies_count ELSE NULL END), 2) AS stddev_dependencies
FROM extracted_package_risk_summary
WHERE runtime_dependencies_count IS NOT NULL AND runtime_dependencies_count > 0
GROUP BY has_high_severity_vulnerability
ORDER BY vulnerability_status DESC;

-- ============================================================================
-- Query 4: Top 20 Packages by Vulnerability Count
-- ============================================================================
-- Purpose: Identify packages with the most known vulnerabilities
-- Insight: Which packages pose the highest direct vulnerability risk?
--
SELECT
  package_name,
  ecosystem,
  vulnerability_count,
  high_severity_count,
  max_severity_score,
  stars,
  forks,
  dependents_count,
  is_unmaintained,
  days_since_last_release,
  CASE
    WHEN has_high_severity_vulnerability = 'true' THEN 'HIGH RISK'
    WHEN vulnerability_count > 0 THEN 'MEDIUM RISK'
    ELSE 'LOW RISK'
  END AS risk_category
FROM extracted_package_risk_summary
WHERE vulnerability_count IS NOT NULL AND vulnerability_count > 0
ORDER BY vulnerability_count DESC, high_severity_count DESC, max_severity_score DESC
LIMIT 20;

-- ============================================================================
-- Query 5: Repository Status Distribution
-- ============================================================================
-- Purpose: Understand maintenance status across the package ecosystem
-- Insight: What percentage of packages are actively maintained?
--
SELECT
  repository_status,
  COUNT(*) AS package_count,
  ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM extracted_package_risk_summary), 2) AS percentage_of_total,
  SUM(CASE WHEN vulnerability_count > 0 THEN 1 ELSE 0 END) AS vulnerable_packages,
  ROUND(100.0 * AVG(CASE WHEN vulnerability_count > 0 THEN 1 ELSE 0 END), 2) AS vulnerability_rate,
  ROUND(AVG(CASE WHEN stars IS NOT NULL AND stars > 0 THEN stars ELSE NULL END), 2) AS avg_stars,
  ROUND(AVG(CASE WHEN days_since_last_release IS NOT NULL THEN days_since_last_release ELSE NULL END), 1) AS avg_days_since_release
FROM extracted_package_risk_summary
GROUP BY repository_status
ORDER BY package_count DESC;

-- ============================================================================
-- Query 6: Average Days Since Last Release by Vulnerability Label
-- ============================================================================
-- Purpose: Analyze maintenance recency for vulnerable packages
-- Insight: Are vulnerable packages slower to receive updates?
--
SELECT
  CASE
    WHEN has_high_severity_vulnerability = 'true' THEN 'High-Severity Vulnerable'
    WHEN vulnerability_count > 0 THEN 'Other Vulnerabilities'
    ELSE 'No Known Vulnerabilities'
  END AS vulnerability_category,
  COUNT(*) AS package_count,
  ROUND(AVG(CASE WHEN days_since_last_release >= 0 THEN days_since_last_release ELSE NULL END), 1) AS avg_days_since_release,
  MIN(CASE WHEN days_since_last_release >= 0 THEN days_since_last_release ELSE NULL END) AS min_days,
  MAX(CASE WHEN days_since_last_release >= 0 THEN days_since_last_release ELSE NULL END) AS max_days,
  ROUND(STDDEV(CASE WHEN days_since_last_release >= 0 THEN days_since_last_release ELSE NULL END), 1) AS stddev_days
FROM extracted_package_risk_summary
WHERE days_since_last_release IS NOT NULL
GROUP BY vulnerability_category
ORDER BY CASE vulnerability_category
  WHEN 'High-Severity Vulnerable' THEN 1
  WHEN 'Other Vulnerabilities' THEN 2
  ELSE 3
END;

-- ============================================================================
-- Query 7: Packages with Highest Maximum CVSS Severity Scores
-- ============================================================================
-- Purpose: Identify packages with the most severe known vulnerabilities
-- Insight: Which packages have the worst individual vulnerabilities?
--
SELECT
  package_name,
  ecosystem,
  max_severity_score,
  vulnerability_count,
  high_severity_count,
  stars,
  dependents_count,
  is_unmaintained,
  repository_status,
  days_since_last_release,
  CASE
    WHEN max_severity_score >= 9.0 THEN 'CRITICAL'
    WHEN max_severity_score >= 7.0 THEN 'HIGH'
    WHEN max_severity_score >= 4.0 THEN 'MEDIUM'
    ELSE 'LOW'
  END AS severity_category
FROM extracted_package_risk_summary
WHERE max_severity_score IS NOT NULL AND max_severity_score > 0
ORDER BY max_severity_score DESC, vulnerability_count DESC
LIMIT 25;

-- ============================================================================
-- Query 8: Summary Statistics by Stars Bucket
-- ============================================================================
-- Purpose: Analyze vulnerability patterns across popularity tiers
-- Insight: Do more popular packages have more vulnerabilities discovered or reported?
--
SELECT
  CASE
    WHEN stars IS NULL OR stars = 0 THEN '0 stars'
    WHEN stars > 0 AND stars <= 100 THEN '1-100 stars'
    WHEN stars > 100 AND stars <= 500 THEN '101-500 stars'
    WHEN stars > 500 AND stars <= 1000 THEN '501-1K stars'
    WHEN stars > 1000 AND stars <= 5000 THEN '1K-5K stars'
    WHEN stars > 5000 AND stars <= 10000 THEN '5K-10K stars'
    ELSE '10K+ stars'
  END AS stars_bucket,
  COUNT(*) AS package_count,
  ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM extracted_package_risk_summary), 2) AS percentage,
  ROUND(AVG(CASE WHEN vulnerability_count > 0 THEN vulnerability_count ELSE NULL END), 2) AS avg_vulnerabilities,
  SUM(CASE WHEN vulnerability_count > 0 THEN 1 ELSE 0 END) AS vulnerable_packages,
  ROUND(100.0 * AVG(CASE WHEN vulnerability_count > 0 THEN 1 ELSE 0 END), 2) AS vulnerability_rate,
  ROUND(AVG(CASE WHEN high_severity_count > 0 THEN high_severity_count ELSE NULL END), 2) AS avg_high_severity,
  ROUND(AVG(CASE WHEN max_severity_score > 0 THEN max_severity_score ELSE NULL END), 2) AS avg_max_severity_score
FROM extracted_package_risk_summary
GROUP BY stars_bucket
ORDER BY
  CASE stars_bucket
    WHEN '0 stars' THEN 1
    WHEN '1-100 stars' THEN 2
    WHEN '101-500 stars' THEN 3
    WHEN '501-1K stars' THEN 4
    WHEN '1K-5K stars' THEN 5
    WHEN '5K-10K stars' THEN 6
    ELSE 7
  END;

-- ============================================================================
-- Query 9: Summary Statistics by Runtime Dependencies Bucket
-- ============================================================================
-- Purpose: Analyze how dependency complexity correlates with vulnerabilities
-- Insight: Do packages with more dependencies have more vulnerabilities?
--
SELECT
  CASE
    WHEN runtime_dependencies_count IS NULL OR runtime_dependencies_count = 0 THEN '0 dependencies'
    WHEN runtime_dependencies_count > 0 AND runtime_dependencies_count <= 5 THEN '1-5 dependencies'
    WHEN runtime_dependencies_count > 5 AND runtime_dependencies_count <= 10 THEN '6-10 dependencies'
    WHEN runtime_dependencies_count > 10 AND runtime_dependencies_count <= 20 THEN '11-20 dependencies'
    WHEN runtime_dependencies_count > 20 AND runtime_dependencies_count <= 50 THEN '21-50 dependencies'
    ELSE '50+ dependencies'
  END AS dependencies_bucket,
  COUNT(*) AS package_count,
  ROUND(100.0 * COUNT(*) / (SELECT COUNT(*) FROM extracted_package_risk_summary), 2) AS percentage,
  ROUND(AVG(CASE WHEN vulnerability_count > 0 THEN vulnerability_count ELSE NULL END), 2) AS avg_vulnerabilities,
  SUM(CASE WHEN vulnerability_count > 0 THEN 1 ELSE 0 END) AS vulnerable_packages,
  ROUND(100.0 * AVG(CASE WHEN vulnerability_count > 0 THEN 1 ELSE 0 END), 2) AS vulnerability_rate,
  ROUND(AVG(CASE WHEN high_severity_count > 0 THEN high_severity_count ELSE NULL END), 2) AS avg_high_severity,
  ROUND(AVG(CASE WHEN dependents_count > 0 THEN dependents_count ELSE NULL END), 1) AS avg_dependents
FROM extracted_package_risk_summary
GROUP BY dependencies_bucket
ORDER BY
  CASE dependencies_bucket
    WHEN '0 dependencies' THEN 1
    WHEN '1-5 dependencies' THEN 2
    WHEN '6-10 dependencies' THEN 3
    WHEN '11-20 dependencies' THEN 4
    WHEN '21-50 dependencies' THEN 5
    ELSE 6
  END;

-- ============================================================================
-- Query 10: Top Unmaintained Packages with High-Severity Vulnerabilities
-- ============================================================================
-- Purpose: Identify highest-risk packages with no active maintenance
-- Insight: Which unmaintained packages present the greatest risk due to vulnerabilities?
--
SELECT
  package_name,
  ecosystem,
  vulnerability_count,
  high_severity_count,
  max_severity_score,
  stars,
  dependents_count,
  dependent_repos_count,
  days_since_last_release,
  repository_status,
  rank,
  CASE
    WHEN has_high_severity_vulnerability = 'true' AND dependents_count > 100 THEN 'CRITICAL'
    WHEN has_high_severity_vulnerability = 'true' THEN 'HIGH'
    WHEN vulnerability_count > 0 AND dependents_count > 100 THEN 'MEDIUM'
    WHEN vulnerability_count > 0 THEN 'LOW'
    ELSE 'MINIMAL'
  END AS risk_assessment,
  ROUND(100.0 * dependents_count / NULLIF(SUM(dependents_count) OVER (), 0), 2) AS percentage_of_total_dependents
FROM extracted_package_risk_summary
WHERE is_unmaintained = 'true' AND vulnerability_count > 0
ORDER BY
  CASE
    WHEN has_high_severity_vulnerability = 'true' AND dependents_count > 100 THEN 1
    WHEN has_high_severity_vulnerability = 'true' THEN 2
    WHEN vulnerability_count > 0 AND dependents_count > 100 THEN 3
    ELSE 4
  END,
  dependents_count DESC,
  high_severity_count DESC,
  max_severity_score DESC
LIMIT 30;

-- ============================================================================
-- End of Analytical Queries
-- ============================================================================
