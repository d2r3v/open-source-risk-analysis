#!/usr/bin/env node

/**
 * Libraries.io Dependencies Data Fetcher
 * 
 * Purpose: Fetch dependency data from Libraries.io API for npm packages
 * and save both raw JSON responses and a combined CSV summary.
 * 
 * Input:  data/cleaned/librariesio_projects.csv (with package_name and latest_release_number)
 * Output: 
 *   - data/raw/librariesio/dependencies/*.json (individual raw responses)
 *   - data/cleaned/librariesio_dependencies.csv (combined extracted data)
 * 
 * Process:
 * 1. Read package names and versions from librariesio_projects.csv
 * 2. Skip packages without version information
 * 3. For each package, fetch dependencies from Libraries.io API (with caching)
 * 4. Save raw JSON responses to individual files
 * 5. Extract key fields and build combined CSV
 * 6. Implement retry logic for transient errors
 * 7. Include delays between requests
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { createWriteStream, createReadStream, existsSync } from 'fs';
import readline from 'readline';
import dotenv from 'dotenv';
import Papa from 'papaparse';

// Get directory paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..', '..');

// Load environment variables from .env file
dotenv.config({ path: path.resolve(projectRoot, '.env') });

const INPUT_FILE = path.join(projectRoot, 'data', 'cleaned', 'librariesio_projects.csv');
const RAW_OUTPUT_DIR = path.join(projectRoot, 'data', 'raw', 'librariesio', 'dependencies');
const CLEANED_OUTPUT_DIR = path.join(projectRoot, 'data', 'cleaned');
const CLEANED_OUTPUT_FILE = path.join(CLEANED_OUTPUT_DIR, 'librariesio_dependencies.csv');

// API Configuration
const API_BASE = 'https://libraries.io/api/npm';
const API_KEY = process.env.LIBRARIES_IO_API_KEY;
const REQUEST_DELAY_MS = 200; // Delay between requests (in milliseconds)
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 1000; // Initial retry delay

// CSV Headers for output
const CSV_HEADERS = [
  'package_name',
  'platform',
  'runtime_dependencies_count',
  'dependents_count',
  'dependent_repos_count',
  'score',
  'latest_release_number',
  'latest_release_published_at',
  'versions_count'
];

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
 * Sleep for a specified duration
 * 
 * @param {number} ms - Milliseconds to sleep
 * @returns {Promise<void>}
 */
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Safely parse JSON with error handling
 * 
 * @param {string} jsonStr - JSON string to parse
 * @returns {Object|null} Parsed object or null if invalid
 */
function safeJsonParse(jsonStr) {
  try {
    return JSON.parse(jsonStr);
  } catch (error) {
    return null;
  }
}

/**
 * Sanitize filename from package name and version
 * 
 * @param {string} packageName - Package name
 * @param {string} version - Version string
 * @returns {string} Sanitized filename
 */
function sanitizeFilename(packageName, version) {
  const safePkg = packageName.replace(/[^a-z0-9\-_.]/g, '_');
  const safeVer = version.replace(/[^a-z0-9\-_.]/g, '_');
  return `${safePkg}@${safeVer}`;
}

/**
 * Fetch dependency data from Libraries.io API with retry logic
 * 
 * @param {string} packageName - Normalized package name
 * @param {string} version - Version string
 * @param {number} retryCount - Current retry attempt
 * @returns {Promise<Object|null>} API response or null if failed
 */
async function fetchDependencyData(packageName, version, retryCount = 0) {
  try {
    if (!API_KEY) {
      throw new Error('LIBRARIES_IO_API_KEY environment variable not set');
    }
    
    const url = `${API_BASE}/${packageName}/${version}/dependencies?api_key=${API_KEY}`;
    console.log(`  Requesting: ${packageName}@${version}`);
    const response = await fetch(url);
    
    if (!response.ok) {
      // Don't retry on 404 (package/version not found)
      if (response.status === 404) {
        console.warn(`  Version not found (404): ${packageName}@${version}`);
        return null;
      }
      
      // Retry on transient errors (429, 500, 502, 503, 504)
      if ([429, 500, 502, 503, 504].includes(response.status) && retryCount < MAX_RETRIES) {
        const delayMs = RETRY_DELAY_MS * Math.pow(2, retryCount); // Exponential backoff
        console.warn(`  HTTP ${response.status} - retrying ${packageName}@${version} after ${delayMs}ms (attempt ${retryCount + 1}/${MAX_RETRIES})`);
        await sleep(delayMs);
        return fetchDependencyData(packageName, version, retryCount + 1);
      }
      
      throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    }
    
    const data = await response.json();
    return data;
    
  } catch (error) {
    if (retryCount < MAX_RETRIES) {
      const delayMs = RETRY_DELAY_MS * Math.pow(2, retryCount);
      console.warn(`  Error fetching ${packageName}@${version}: ${error.message} - retrying after ${delayMs}ms (attempt ${retryCount + 1}/${MAX_RETRIES})`);
      await sleep(delayMs);
      return fetchDependencyData(packageName, version, retryCount + 1);
    }
    
    console.error(`  Failed to fetch ${packageName}@${version}: ${error.message}`);
    return null;
  }
}

/**
 * Get the raw JSON file path for a package version
 * 
 * @param {string} packageName - Package name
 * @param {string} version - Version string
 * @returns {string} File path
 */
function getRawJsonPath(packageName, version) {
  const sanitized = sanitizeFilename(packageName, version);
  return path.join(RAW_OUTPUT_DIR, `${sanitized}.json`);
}

/**
 * Load dependency data from cache or fetch from API
 * 
 * @param {string} packageName - Normalized package name
 * @param {string} version - Version string
 * @param {boolean} forceRefresh - Force fetch even if cached
 * @returns {Promise<Object|null>} Dependency data
 */
async function loadDependencyData(packageName, version, forceRefresh = false) {
  const jsonPath = getRawJsonPath(packageName, version);
  
  // Check if cached file exists
  if (!forceRefresh && existsSync(jsonPath)) {
    try {
      const content = await fs.readFile(jsonPath, 'utf-8');
      const data = safeJsonParse(content);
      if (data) {
        console.log(`  ✓ Loaded from cache`);
        return data;
      }
    } catch (error) {
      console.warn(`  Warning: Could not read cached file: ${error.message}`);
    }
  }
  
  // Fetch from API
  console.log(`  Fetching from Libraries.io API...`);
  const data = await fetchDependencyData(packageName, version);
  
  if (!data) {
    return null;
  }
  
  // Save to cache
  try {
    await fs.writeFile(jsonPath, JSON.stringify(data, null, 2), 'utf-8');
    console.log(`  ✓ Saved to cache`);
  } catch (error) {
    console.warn(`  Warning: Could not save cache file: ${error.message}`);
  }
  
  return data;
}

/**
 * Count runtime dependencies from API response
 * 
 * @param {Object} depData - Dependency data from API
 * @returns {number} Count of runtime dependencies
 */
function countRuntimeDependencies(depData) {
  if (!depData || !Array.isArray(depData.dependencies)) {
    return 0;
  }
  
  return depData.dependencies
    .filter(dep => !dep.kind || dep.kind === 'runtime')
    .length;
}

/**
 * Extract fields from API response to match CSV schema
 * 
 * @param {string} packageName - Package name
 * @param {string} version - Version string
 * @param {Object} projectData - Raw project data (from librariesio_projects)
 * @param {Object} depData - Raw dependency data from API
 * @returns {Object} Extracted fields
 */
function extractFields(packageName, version, projectData, depData) {
  const runtimeDepCount = countRuntimeDependencies(depData);
  
  return {
    package_name: packageName,
    platform: projectData.platform || 'npm',
    runtime_dependencies_count: runtimeDepCount,
    dependents_count: projectData.dependents_count || '',
    dependent_repos_count: projectData.dependent_repos_count || '',
    score: projectData.score || '',
    latest_release_number: version || '',
    latest_release_published_at: projectData.latest_release_published_at || '',
    versions_count: projectData.versions_count || ''
  };
}

/**
 * Convert record object to CSV line
 * 
 * @param {Object} record - Record with CSV fields
 * @returns {string} CSV formatted line
 */
function recordToCsv(record) {
  return CSV_HEADERS
    .map(header => {
      const value = record[header] || '';
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
 * Ensure output directories exist
 */
async function ensureOutputDirs() {
  try {
    await fs.mkdir(RAW_OUTPUT_DIR, { recursive: true });
    await fs.mkdir(CLEANED_OUTPUT_DIR, { recursive: true });
  } catch (error) {
    console.error(`Error creating output directories: ${error.message}`);
    throw error;
  }
}

/**
 * Read packages from input CSV using proper CSV parsing
 * 
 * @returns {Promise<Array>} Array of {packageName, version} objects
 */
async function readPackagesWithVersions() {
  return new Promise((resolve, reject) => {
    const packages = [];
    let csvData = '';
    
    const rl = readline.createInterface({
      input: createReadStream(INPUT_FILE, { encoding: 'utf-8' }),
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
        
        // Extract packages with versions
        parseResult.data.forEach(row => {
          const packageName = normalizePackageName(row.package_name);
          const version = (row.latest_release_number || '').trim();
          
          // Skip rows without version information
          if (packageName && version) {
            packages.push({
              packageName: packageName,
              version: version,
              rowData: row // Store original parsed row data
            });
          }
        });
        
        resolve(packages);
      } catch (error) {
        reject(error);
      }
    });
    
    rl.on('error', reject);
  });
}

/**
 * Main process
 */
async function main() {
  try {
    console.log('Starting Libraries.io dependency data fetcher...');
    console.log(`Input file: ${INPUT_FILE}`);
    console.log(`Raw output directory: ${RAW_OUTPUT_DIR}`);
    console.log(`CSV output file: ${CLEANED_OUTPUT_FILE}`);
    console.log('');
    
    // Validate API key
    if (!API_KEY) {
      console.error('Error: LIBRARIES_IO_API_KEY environment variable not set');
      console.error('Set it with: export LIBRARIES_IO_API_KEY=your_api_key');
      process.exit(1);
    }
    
    // Check if input file exists
    try {
      await fs.access(INPUT_FILE);
    } catch {
      console.error(`Error: Input file not found: ${INPUT_FILE}`);
      console.error('Please run fetch_librariesio_projects.js first to generate the input file.');
      process.exit(1);
    }
    
    // Ensure output directories exist
    await ensureOutputDirs();
    
    // Read packages with versions
    console.log('Reading packages from input file...');
    const packages = await readPackagesWithVersions();
    console.log(`Found ${packages.length} packages with version information`);
    console.log('');
    
    // Open CSV output file
    const outputStream = createWriteStream(CLEANED_OUTPUT_FILE, { encoding: 'utf-8' });
    outputStream.write(CSV_HEADERS.join(',') + '\n');
    
    let successCount = 0;
    let skipCount = 0;
    let errorCount = 0;
    
    // Process each package
    for (let i = 0; i < packages.length; i++) {
      const pkg = packages[i];
      const { packageName, version, rowData } = pkg;
      
      process.stdout.write(`[${i + 1}/${packages.length}] Processing ${packageName}@${version}... `);
      
      try {
        // Load dependency data (with caching)
        const depData = await loadDependencyData(packageName, version);
        
        if (depData) {
          // Use parsed row data directly
          const projectData = rowData;
          
          // Extract fields
          const record = extractFields(packageName, version, projectData, depData);
          
          // Write to CSV
          if (record) {
            outputStream.write(recordToCsv(record) + '\n');
            console.log('✓ Extracted to CSV');
            successCount++;
          }
        } else {
          console.log('⊘ No data received');
          errorCount++;
        }
        
        // Delay before next request
        if (i < packages.length - 1) {
          await sleep(REQUEST_DELAY_MS);
        }
        
      } catch (error) {
        console.log(`✗ Error: ${error.message}`);
        errorCount++;
      }
    }
    
    // Close output stream
    outputStream.end();
    
    // Wait for stream to finish
    await new Promise((resolve, reject) => {
      outputStream.on('finish', resolve);
      outputStream.on('error', reject);
    });
    
    // Print summary
    console.log('');
    console.log('--- Fetch Complete ---');
    console.log(`Total packages processed: ${packages.length}`);
    console.log(`Successfully processed: ${successCount}`);
    console.log(`Errors: ${errorCount}`);
    console.log(`Raw data directory: ${RAW_OUTPUT_DIR}`);
    console.log(`CSV output file: ${CLEANED_OUTPUT_FILE}`);
    
  } catch (error) {
    console.error(`Fatal error: ${error.message}`);
    process.exit(1);
  }
}

// Run main function
main();
