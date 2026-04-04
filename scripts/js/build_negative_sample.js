#!/usr/bin/env node

/**
 * Negative Sample Builder
 * 
 * Purpose: Build a curated list of packages without high-severity vulnerabilities
 * by filtering candidate packages against known vulnerable packages from OSV.
 * 
 * Input:
 *   - data/inputs/candidate_negative_packages.csv (candidate packages)
 *   - data/cleaned/osv_package_summary.csv (packages with vulnerabilities)
 * 
 * Output:
 *   - data/inputs/negative_packages.csv (cleaned negative samples)
 * 
 * Process:
 * 1. Read candidate packages from input file
 * 2. Read packages with high-severity vulnerabilities from OSV summary
 * 3. Filter out any candidates that appear in OSV vulnerable set
 * 4. Remove duplicates and normalize names
 * 5. Write cleaned negative samples to output
 * 6. Report statistics on filtering process
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { createReadStream, createWriteStream } from 'fs';
import readline from 'readline';

// Get directory paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..', '..');

const CANDIDATES_INPUT_FILE = path.join(projectRoot, 'data', 'inputs', 'candidate_negative_packages.csv');
const OSV_SUMMARY_FILE = path.join(projectRoot, 'data', 'cleaned', 'osv_package_summary.csv');
const OUTPUT_DIR = path.join(projectRoot, 'data', 'inputs');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'negative_packages.csv');

// CSV Headers for output
const OUTPUT_HEADERS = [
  'package_name',
  'ecosystem'
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
 * Create a composite key from package name and ecosystem
 * 
 * @param {string} packageName - Package name
 * @param {string} ecosystem - Ecosystem/platform
 * @returns {string} Composite key
 */
function createPackageKey(packageName, ecosystem) {
  const normalizedName = normalizePackageName(packageName);
  const normalizedEcosystem = (ecosystem || 'npm').toLowerCase().trim();
  return `${normalizedName}|${normalizedEcosystem}`;
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
 * Read OSV vulnerable packages into a Set for fast lookup
 * 
 * @returns {Promise<Set>} Set of package keys from OSV summary
 */
async function readOsvVulnerablePackages() {
  return new Promise((resolve, reject) => {
    const vulnerablePackages = new Set();
    let headerMap = {};
    let lineCount = 0;
    
    const rl = readline.createInterface({
      input: createReadStream(OSV_SUMMARY_FILE, { encoding: 'utf-8' }),
      crlfDelay: Infinity
    });
    
    rl.on('line', (line) => {
      lineCount++;
      
      // Parse CSV header on first line
      if (lineCount === 1) {
        const fields = line.split(',').map(f => f.trim().toLowerCase());
        fields.forEach((field, index) => {
          headerMap[field] = index;
        });
        return;
      }
      
      // Parse data lines
      const fields = line.split(',').map(f => f.trim());
      const packageNameIndex = headerMap['package_name'];
      const ecosystemIndex = headerMap['ecosystem'];
      
      if (packageNameIndex !== undefined && ecosystemIndex !== undefined) {
        const packageName = fields[packageNameIndex];
        const ecosystem = fields[ecosystemIndex] || 'npm';
        
        if (packageName) {
          const key = createPackageKey(packageName, ecosystem);
          vulnerablePackages.add(key);
        }
      }
    });
    
    rl.on('close', () => {
      console.log(`Loaded ${vulnerablePackages.size} vulnerable packages from OSV summary`);
      resolve(vulnerablePackages);
    });
    
    rl.on('error', reject);
  });
}

/**
 * Read candidate packages and filter against vulnerable set
 * 
 * @param {Set} vulnerablePackages - Set of vulnerable package keys
 * @returns {Promise<Map>} Map of {packageKey -> {packageName, ecosystem}}
 */
async function readAndFilterCandidatePackages(vulnerablePackages) {
  return new Promise((resolve, reject) => {
    const filteredPackages = new Map();
    let headerMap = {};
    let lineCount = 0;
    let totalCandidates = 0;
    let removedCount = 0;
    let duplicateCount = 0;
    
    const rl = readline.createInterface({
      input: createReadStream(CANDIDATES_INPUT_FILE, { encoding: 'utf-8' }),
      crlfDelay: Infinity
    });
    
    rl.on('line', (line) => {
      lineCount++;
      
      // Parse CSV header on first line
      if (lineCount === 1) {
        const fields = line.split(',').map(f => f.trim().toLowerCase());
        fields.forEach((field, index) => {
          headerMap[field] = index;
        });
        return;
      }
      
      // Parse data lines
      const fields = line.split(',').map(f => f.trim());
      const packageNameIndex = headerMap['package_name'];
      
      // Skip if no package_name column
      if (packageNameIndex === undefined) {
        return;
      }
      
      const packageName = fields[packageNameIndex];
      const ecosystem = (fields[headerMap['ecosystem']] || 'npm').toLowerCase().trim();
      
      if (!packageName) {
        return;
      }
      
      totalCandidates++;
      const key = createPackageKey(packageName, ecosystem);
      
      // Check if this package is in the vulnerable set
      if (vulnerablePackages.has(key)) {
        removedCount++;
        return;
      }
      
      // Check for duplicates
      if (filteredPackages.has(key)) {
        duplicateCount++;
        return;
      }
      
      // Add to filtered packages
      filteredPackages.set(key, {
        package_name: normalizePackageName(packageName),
        ecosystem: ecosystem
      });
    });
    
    rl.on('close', () => {
      console.log(`\nCandidate Packages Statistics:`);
      console.log(`  Total candidates: ${totalCandidates}`);
      console.log(`  Removed (OSV vulnerable): ${removedCount}`);
      console.log(`  Removed (duplicates): ${duplicateCount}`);
      console.log(`  Final negatives kept: ${filteredPackages.size}`);
      
      resolve(filteredPackages);
    });
    
    rl.on('error', reject);
  });
}

/**
 * Write filtered packages to output CSV
 * 
 * @param {Map} filteredPackages - Map of filtered packages
 */
async function writeOutputCsv(filteredPackages) {
  return new Promise((resolve, reject) => {
    const outputStream = createWriteStream(OUTPUT_FILE, { encoding: 'utf-8' });
    
    // Write header
    outputStream.write(OUTPUT_HEADERS.join(',') + '\n');
    
    let recordCount = 0;
    
    // Write each filtered package
    for (const [key, data] of filteredPackages) {
      const record = {
        package_name: data.package_name,
        ecosystem: data.ecosystem
      };
      
      outputStream.write(recordToCsv(record) + '\n');
      recordCount++;
    }
    
    outputStream.end();
    
    outputStream.on('finish', () => {
      console.log(`Wrote ${recordCount} negative sample packages to output file`);
      resolve();
    });
    
    outputStream.on('error', reject);
  });
}

/**
 * Main process
 */
async function main() {
  try {
    console.log('Starting negative sample builder...');
    console.log(`Candidates input file: ${CANDIDATES_INPUT_FILE}`);
    console.log(`OSV summary file: ${OSV_SUMMARY_FILE}`);
    console.log(`Output file: ${OUTPUT_FILE}`);
    console.log('');
    
    // Check if input files exist
    try {
      await fs.access(CANDIDATES_INPUT_FILE);
    } catch {
      console.error(`Error: Candidates input file not found: ${CANDIDATES_INPUT_FILE}`);
      console.error('Create a CSV file with a "package_name" column (and optional "ecosystem" column)');
      process.exit(1);
    }
    
    try {
      await fs.access(OSV_SUMMARY_FILE);
    } catch {
      console.error(`Error: OSV summary file not found: ${OSV_SUMMARY_FILE}`);
      console.error('Please run build_osv_package_summary.js first to generate the OSV summary');
      process.exit(1);
    }
    
    // Ensure output directory exists
    await ensureOutputDir();
    
    // Read vulnerable packages from OSV summary
    console.log('Reading vulnerable packages from OSV summary...');
    const vulnerablePackages = await readOsvVulnerablePackages();
    
    // Read and filter candidate packages
    console.log('Reading and filtering candidate packages...');
    const filteredPackages = await readAndFilterCandidatePackages(vulnerablePackages);
    
    // Write output
    console.log('Writing filtered packages to CSV...');
    await writeOutputCsv(filteredPackages);
    
    // Print summary
    console.log('');
    console.log('--- Negative Sample Building Complete ---');
    console.log(`Output file: ${OUTPUT_FILE}`);
    
  } catch (error) {
    console.error(`Fatal error: ${error.message}`);
    process.exit(1);
  }
}

// Run main function
main();
