#!/usr/bin/env node

/**
 * OSV npm Vulnerability Extractor (Enriched & Smarter Severity)
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { createWriteStream } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..', '..');

const INPUT_DIR = path.join(projectRoot, 'data', 'raw', 'osv', 'details');
const OUTPUT_DIR = path.join(projectRoot, 'data', 'cleaned');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'osv_npm_flat.csv');

const CSV_HEADERS = [
  'osv_id',
  'package_name',
  'ecosystem',
  'published',
  'modified',
  'severity_type',
  'severity_score',
  'is_high_severity'
];

/**
 * Severity score mapping for string values
 */
const SEVERITY_LEVELS_MAP = {
  'CRITICAL': 9.5,
  'HIGH': 8.0,
  'MODERATE': 5.5,
  'MEDIUM': 5.5,
  'LOW': 2.5,
  'MALWARE': 10.0 // Malicious packages are critical
};

/**
 * Extract severity from various OSV fields
 */
function extractSeverityData(osvData, affectedItem) {
  let score = null;
  let type = 'UNKNOWN';

  // 1. Try numeric score from database_specific.cvss.score
  if (osvData.database_specific?.cvss?.score !== undefined) {
    score = parseFloat(osvData.database_specific.cvss.score);
    type = 'CVSS_V3';
  }

  // 2. Try top-level severity array
  if (score === null && Array.isArray(osvData.severity)) {
    for (const sev of osvData.severity) {
      if (typeof sev.score === 'number') {
        score = sev.score;
        type = sev.type || 'CVSS';
        break;
      }
      // If it's a vector string, we still don't have a numeric score here yet
    }
  }

  // 3. Try database_specific.severity level string
  if (score === null) {
    const level = (osvData.database_specific?.severity || '').toUpperCase();
    if (SEVERITY_LEVELS_MAP[level]) {
      score = SEVERITY_LEVELS_MAP[level];
      type = level;
    }
  }

  // 4. Fallback for MAL- prefix (Malware)
  if (score === null && (osvData.id.startsWith('MAL-') || osvData.database_specific?.malicious_packages_origins)) {
    score = 10.0;
    type = 'MALWARE';
  }

  return {
    score: score,
    type: type
  };
}

function isHighSeverity(score) {
  return score !== null && score >= 7.0;
}

function normalizePackageName(packageName) {
  return (packageName || '').toLowerCase().trim();
}

function extractVulnerabilitiesFromRecord(osvData) {
  const records = [];
  if (!osvData || !osvData.affected) return records;

  const osvId = osvData.id;
  const published = osvData.published || '';
  const modified = osvData.modified || '';

  osvData.affected.forEach(affectedItem => {
    if (!affectedItem.package) return;

    const packageName = normalizePackageName(affectedItem.package.name);
    const ecosystem = (affectedItem.package.ecosystem || '').toLowerCase();
    if (ecosystem !== 'npm') return;

    const severityData = extractSeverityData(osvData, affectedItem);
    const score = severityData.score;
    const high = isHighSeverity(score);

    records.push({
      osv_id: osvId,
      package_name: packageName,
      ecosystem: ecosystem,
      published: published,
      modified: modified,
      severity_type: severityData.type,
      severity_score: score !== null ? score.toFixed(1) : '',
      is_high_severity: high ? 'true' : 'false'
    });
  });

  return records;
}

function recordToCsv(record) {
  return CSV_HEADERS.map(header => {
    const value = record[header] || '';
    const escaped = value.toString().replace(/"/g, '""');
    return (escaped.includes(',') || escaped.includes('"') || escaped.includes('\n'))
      ? `"${escaped}"`
      : escaped;
  }).join(',');
}

async function main() {
  try {
    console.log('Extracting enriched OSV npm vulnerability data...');
    await fs.mkdir(OUTPUT_DIR, { recursive: true });

    const entries = await fs.readdir(INPUT_DIR);
    const jsonFiles = entries.filter(f => f.endsWith('.json'));
    console.log(`Processing ${jsonFiles.length} detail files...`);

    const outputStream = createWriteStream(OUTPUT_FILE, { encoding: 'utf-8' });
    outputStream.write(CSV_HEADERS.join(',') + '\n');

    let totalRows = 0;
    let scoredRows = 0;

    for (const fileName of jsonFiles) {
      try {
        const content = await fs.readFile(path.join(INPUT_DIR, fileName), 'utf-8');
        const osvData = JSON.parse(content);
        const vulns = extractVulnerabilitiesFromRecord(osvData);

        vulns.forEach(v => {
          outputStream.write(recordToCsv(v) + '\n');
          totalRows++;
          if (v.severity_score !== '') scoredRows++;
        });
      } catch (err) {
        console.warn(`✗ ${fileName}: ${err.message}`);
      }
    }

    outputStream.end();
    await new Promise(r => outputStream.on('finish', r));

    console.log(`\nExtraction complete: ${totalRows} rows (${scoredRows} with severity scores).`);
    console.log(`Output: ${OUTPUT_FILE}`);
  } catch (err) {
    console.error(`Fatal: ${err.message}`);
  }
}

main();
