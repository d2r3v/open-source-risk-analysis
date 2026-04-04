#!/usr/bin/env node

/**
 * Extracted Package Risk Summary Builder
 * 
 * Purpose: Join OSV vulnerability data with Libraries.io project metadata
 * to create a comprehensive risk assessment file.
 * 
 * Inputs:
 *   - data/cleaned/osv_package_summary.csv (vulnerability metrics)
 *   - data/cleaned/librariesio_projects.csv (project metadata)
 * 
 * Output:
 *   - data/exports/extracted_package_risk_summary.csv (joined risk assessment)
 * 
 * Process:
 * 1. Read OSV package summary into a Map (keyed by normalized package_name)
 * 2. Read Libraries.io projects into a Map (keyed by normalized package_name)
 * 3. Join on normalized package name (case-insensitive)
 * 4. Compute derived fields (days_since_last_release, has_repository, is_unmaintained)
 * 5. Write output CSV with only specified columns
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { createReadStream, createWriteStream } from 'fs';
import readline from 'readline';
import Papa from 'papaparse';

// Get directory paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..', '..');

const OSV_SUMMARY_FILE = path.join(projectRoot, 'data', 'cleaned', 'osv_package_summary.csv');
const LIBRARIESIO_PROJECTS_FILE = path.join(projectRoot, 'data', 'cleaned', 'librariesio_projects.csv');
const OUTPUT_DIR = path.join(projectRoot, 'data', 'exports');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'extracted_package_risk_summary.csv');

// CSV Headers for output (in order)
const OUTPUT_HEADERS = [
  'package_name',
  'ecosystem',
  'stars',
  'forks',
  'contributions_count',
  'dependent_repos_count',
  'dependents_count',
  'rank',
  'repository_status',
  'latest_release_published_at',
  'versions_count',
  'days_since_last_release',
  'has_repository',
  'is_unmaintained',
  'vulnerability_count',
  'high_severity_count',
  'max_severity_score',
  'has_high_severity_vulnerability'
];

// Current date for computing relative dates
const CURRENT_DATE = new Date();

/**
 * Normalize package name (lowercase and trim)
 * 
 * @param {string} packageName - Original package name
 * @returns {string} Normalized package name
 */
function normalizePackageName(packageName) {
  return (packageName || '').toLowerCase().trim();
}

/**
 * Calculate days since a given date until current date
 * 
 * @param {string} dateStr - ISO date string or any parseable date
 * @returns {number|null} Number of days elapsed or null if date is invalid
 */
function calculateDaysSinceDate(dateStr) {
  if (!dateStr || dateStr.trim() === '') {
    return null;
  }
  
  try {
    const date = new Date(dateStr);
    if (isNaN(date.getTime())) {
      return null;
    }
    
    const diffMs = CURRENT_DATE - date;
    const daysDiff = Math.floor(diffMs / (1000 * 60 * 60 * 24));
    return daysDiff >= 0 ? daysDiff : null;
  } catch {
    return null;
  }
}

/**
 * Safely parse integer from string
 * 
 * @param {string|number} value - Value to parse
 * @returns {number|string} Parsed integer or empty string
 */
function safeParseInt(value) {
  if (value === null || value === undefined || value === '') {
    return '';
  }
  const parsed = parseInt(value, 10);
  return isNaN(parsed) ? '' : parsed;
}

/**
 * Safely parse float from string
 * 
 * @param {string|number} value - Value to parse
 * @returns {number|string} Parsed float or empty string
 */
function safeParseFloat(value) {
  if (value === null || value === undefined || value === '') {
    return '';
  }
  const parsed = parseFloat(value);
  return isNaN(parsed) ? '' : parsed;
}

/**
 * Check if a repository URL exists and is non-empty
 * 
 * @param {string} repoUrl - Repository URL string
 * @returns {string} 'true' or 'false'
 */
function hasRepository(repoUrl) {
  return (repoUrl && repoUrl.trim().length > 0) ? 'true' : 'false';
}

/**
 * Check if repository is unmaintained
 * 
 * @param {string} repoStatus - Repository status string
 * @returns {string} 'true' or 'false'
 */
function isUnmaintained(repoStatus) {
  return (repoStatus && repoStatus.toLowerCase().trim() === 'unmaintained') ? 'true' : 'false';
}

/**
 * Convert record object to CSV line
 * 
 * @param {Object} record - Record with CSV fields
 * @returns {string} CSV formatted line
 */
function recordToCsv(record) {
  return OUTPUT_HEADERS
    .map(header => {
      const value = record[header];
      if (value === null || value === undefined) {
        return '';
      }
      // Escape quotes and wrap in quotes if contains comma, quote, or newline
      const escaped = value.toString().replace(/"/g, '""');
      if (escaped.includes(',') || escaped.includes('"') || escaped.includes('\n')) {
        return `"${escaped}"`;
      }
      return escaped;
    })
    .join(',');
}

/**
 * Read OSV package summary CSV into a Map
 * 
 * @returns {Promise<Map>} Map of package data keyed by normalized package_name
 */
async function readOsvSummary() {
  console.log('Reading OSV package summary...');
  return new Promise((resolve, reject) => {
    const osvMap = new Map();
    let csvData = '';
    
    const rl = readline.createInterface({
      input: createReadStream(OSV_SUMMARY_FILE, { encoding: 'utf-8' }),
      crlfDelay: Infinity
    });
    
    rl.on('line', (line) => {
      csvData += line + '\n';
    });
    
    rl.on('close', () => {
      try {
        // Use PapaParse to properly parse CSV with quoted fields
        const parseResult = Papa.parse(csvData, {
          header: true,
          skipEmptyLines: true,
          dynamicTyping: false
        });
        
        if (parseResult.errors && parseResult.errors.length > 0) {
          console.warn('CSV parsing warnings:', parseResult.errors);
        }
        
        // Load data into map
        parseResult.data.forEach(row => {
          const packageName = normalizePackageName(row.package_name);
          if (packageName) {
            osvMap.set(packageName, row);
          }
        });
        
        console.log(`  ✓ Loaded ${osvMap.size} OSV records`);
        resolve(osvMap);
      } catch (error) {
        reject(error);
      }
    });
    
    rl.on('error', reject);
  });
}

/**
 * Read Libraries.io projects CSV into a Map
 * 
 * @returns {Promise<Map>} Map of project data keyed by normalized package_name
 */
async function readLibrariesioProjects() {
  console.log('Reading Libraries.io projects...');
  return new Promise((resolve, reject) => {
    const projectsMap = new Map();
    let csvData = '';
    
    const rl = readline.createInterface({
      input: createReadStream(LIBRARIESIO_PROJECTS_FILE, { encoding: 'utf-8' }),
      crlfDelay: Infinity
    });
    
    rl.on('line', (line) => {
      csvData += line + '\n';
    });
    
    rl.on('close', () => {
      try {
        // Use PapaParse to properly parse CSV with quoted fields
        const parseResult = Papa.parse(csvData, {
          header: true,
          skipEmptyLines: true,
          dynamicTyping: false
        });
        
        if (parseResult.errors && parseResult.errors.length > 0) {
          console.warn('CSV parsing warnings:', parseResult.errors);
        }
        
        // Load data into map
        parseResult.data.forEach(row => {
          const packageName = normalizePackageName(row.package_name);
          if (packageName) {
            projectsMap.set(packageName, row);
          }
        });
        
        console.log(`  ✓ Loaded ${projectsMap.size} Libraries.io project records`);
        resolve(projectsMap);
      } catch (error) {
        reject(error);
      }
    });
    
    rl.on('error', reject);
  });
}

/**
 * Build the combined risk summary record
 * 
 * @param {string} packageName - Normalized package name
 * @param {Object} osvRecord - OSV summary record
 * @param {Object} projectRecord - Libraries.io project record
 * @returns {Object} Combined risk record
 */
function buildRiskRecord(packageName, osvRecord, projectRecord) {
  // Use original casing from project record if available
  const displayName = projectRecord?.package_name || packageName;
  
  // Extract OSV data (with defaults)
  const vulnerabilityCount = osvRecord 
    ? safeParseInt(osvRecord.vulnerability_count || 0) 
    : 0;
  const highSeverityCount = osvRecord 
    ? safeParseInt(osvRecord.high_severity_count || 0) 
    : 0;
  const maxSeverityScore = osvRecord && osvRecord.max_severity_score
    ? safeParseFloat(osvRecord.max_severity_score)
    : null;
  const hasHighSeverity = (highSeverityCount > 0) ? 'true' : 'false';
  
  // Extract Libraries.io data
  const daysLastRelease = projectRecord && projectRecord.latest_release_published_at
    ? calculateDaysSinceDate(projectRecord.latest_release_published_at)
    : null;
  
  const hasRepo = projectRecord && projectRecord.repository_url
    ? hasRepository(projectRecord.repository_url)
    : 'false';
  
  const unmaintained = projectRecord && projectRecord.repository_status
    ? isUnmaintained(projectRecord.repository_status)
    : 'false';
  
  return {
    package_name: displayName,
    ecosystem: 'npm',
    stars: projectRecord?.stars || '',
    forks: projectRecord?.forks || '',
    contributions_count: projectRecord?.contributions_count || '',
    dependent_repos_count: projectRecord?.dependent_repos_count || '',
    dependents_count: projectRecord?.dependents_count || '',
    rank: projectRecord?.rank || '',
    repository_status: projectRecord?.repository_status || '',
    latest_release_published_at: projectRecord?.latest_release_published_at || '',
    versions_count: projectRecord?.versions_count || '',
    days_since_last_release: daysLastRelease !== null ? daysLastRelease : '',
    has_repository: hasRepo,
    is_unmaintained: unmaintained,
    vulnerability_count: vulnerabilityCount,
    high_severity_count: highSeverityCount,
    max_severity_score: maxSeverityScore !== null ? maxSeverityScore : '',
    has_high_severity_vulnerability: hasHighSeverity
  };
}

/**
 * Ensure output directory exists
 */
async function ensureOutputDir() {
  try {
    await fs.mkdir(OUTPUT_DIR, { recursive: true });
  } catch (error) {
    console.error(`Error creating output directory: ${error.message}`);
    throw error;
  }
}

/**
 * Main process
 */
async function main() {
  try {
    console.log('Building extracted package risk summary...');
    console.log(`OSV summary input: ${OSV_SUMMARY_FILE}`);
    console.log(`Libraries.io projects input: ${LIBRARIESIO_PROJECTS_FILE}`);
    console.log(`Output file: ${OUTPUT_FILE}`);
    console.log('');
    
    // Check if input files exist
    try {
      await fs.access(OSV_SUMMARY_FILE);
    } catch {
      console.error(`Error: OSV summary file not found: ${OSV_SUMMARY_FILE}`);
      process.exit(1);
    }
    
    try {
      await fs.access(LIBRARIESIO_PROJECTS_FILE);
    } catch {
      console.error(`Error: Libraries.io projects file not found: ${LIBRARIESIO_PROJECTS_FILE}`);
      process.exit(1);
    }
    
    // Ensure output directory exists
    await ensureOutputDir();
    
    // Read both input files
    console.log('');
    const osvMap = await readOsvSummary();
    console.log('');
    const projectsMap = await readLibrariesioProjects();
    console.log('');
    
    // Get union of all package names
    const allPackageNames = new Set([
      ...osvMap.keys(),
      ...projectsMap.keys()
    ]);
    
    console.log(`Merging data from ${osvMap.size} OSV and ${projectsMap.size} project records...`);
    console.log(`  Total unique packages to process: ${allPackageNames.size}`);
    console.log('');
    
    // Open output CSV file
    const outputStream = createWriteStream(OUTPUT_FILE, { encoding: 'utf-8' });
    outputStream.write(OUTPUT_HEADERS.join(',') + '\n');
    
    let recordsWritten = 0;
    
    // Build and write combined records
    for (const packageName of allPackageNames) {
      const osvRecord = osvMap.get(packageName);
      const projectRecord = projectsMap.get(packageName);
      
      const riskRecord = buildRiskRecord(packageName, osvRecord, projectRecord);
      outputStream.write(recordToCsv(riskRecord) + '\n');
      recordsWritten++;
    }
    
    // Close output stream
    outputStream.end();
    
    // Wait for stream to finish
    await new Promise((resolve, reject) => {
      outputStream.on('finish', resolve);
      outputStream.on('error', reject);
    });
    
    // Print summary
    console.log('--- Build Complete ---');
    console.log(`Records written: ${recordsWritten}`);
    console.log(`Output file: ${OUTPUT_FILE}`);
    console.log(`Current date: ${CURRENT_DATE.toISOString()}`);
    
  } catch (error) {
    console.error(`Fatal error: ${error.message}`);
    process.exit(1);
  }
}

// Run main function
main();
