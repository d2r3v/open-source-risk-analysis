#!/usr/bin/env node

/**
 * OSV Package Summary Builder (Enriched)
 * 
 * Purpose: Aggregate enriched OSV vulnerability records to create a summary
 * with severity metrics per package.
 * 
 * Input:  data/cleaned/osv_npm_flat.csv (Enriched version)
 * Output: data/cleaned/osv_package_summary.csv
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

const INPUT_FILE = path.join(projectRoot, 'data', 'cleaned', 'osv_npm_flat.csv');
const OUTPUT_DIR = path.join(projectRoot, 'data', 'cleaned');
const OUTPUT_FILE = path.join(OUTPUT_DIR, 'osv_package_summary.csv');

// CSV Headers for output
const OUTPUT_HEADERS = [
  'package_name',
  'ecosystem',
  'vulnerability_count',
  'high_severity_count',
  'max_severity_score',
  'latest_vulnerability_published_at',
  'has_high_severity_vulnerability',
  'osv_ids'
];

function normalizeValue(value) {
  return (value || '').toLowerCase().trim();
}

function parseCsvLine(line) {
  const fields = [];
  let current = '';
  let inQuotes = false;

  for (let i = 0; i < line.length; i++) {
    const char = line[i];
    const nextChar = line[i + 1];

    if (char === '"') {
      if (inQuotes && nextChar === '"') {
        current += '"';
        i++;
      } else {
        inQuotes = !inQuotes;
      }
    } else if (char === ',' && !inQuotes) {
      fields.push(current);
      current = '';
    } else {
      current += char;
    }
  }
  fields.push(current);
  return fields;
}

function parseSeverityScore(scoreStr) {
  if (!scoreStr || scoreStr.trim() === '') return null;
  const score = parseFloat(scoreStr);
  return isNaN(score) ? null : score;
}

function getLatestDate(date1, date2) {
  if (!date1 && !date2) return null;
  if (!date1) return date2;
  if (!date2) return date1;
  return date1 > date2 ? date1 : date2;
}

function recordToCsv(record) {
  return OUTPUT_HEADERS
    .map(header => {
      const value = record[header] || '';
      const escaped = value.toString().replace(/"/g, '""');
      if (escaped.includes(',') || escaped.includes('"') || escaped.includes('\n')) {
        return `"${escaped}"`;
      }
      return escaped;
    })
    .join(',');
}

async function aggregateFromCsv() {
  return new Promise((resolve, reject) => {
    const aggregated = new Map();
    let lineCount = 0;
    let headerMap = {};

    const rl = readline.createInterface({
      input: createReadStream(INPUT_FILE, { encoding: 'utf-8' }),
      crlfDelay: Infinity
    });

    rl.on('line', (line) => {
      lineCount++;
      const fields = parseCsvLine(line);

      if (lineCount === 1) {
        fields.forEach((field, index) => {
          headerMap[field.toLowerCase().trim()] = index;
        });
        return;
      }

      try {
        const osv_id = (fields[headerMap['osv_id']] || '').trim();
        const package_name = normalizeValue(fields[headerMap['package_name']] || '');
        const ecosystem = normalizeValue(fields[headerMap['ecosystem']] || 'npm');
        const published = (fields[headerMap['published']] || '').trim();
        const severity_score = parseSeverityScore(fields[headerMap['severity_score']] || '');
        const is_high_severity = (fields[headerMap['is_high_severity']] || '').toLowerCase().trim();

        if (!package_name) return;

        const key = `${package_name}|${ecosystem}`;

        if (!aggregated.has(key)) {
          aggregated.set(key, {
            package_name: package_name,
            ecosystem: ecosystem,
            vulnerability_count: 0,
            high_severity_count: 0,
            max_severity_score: null,
            latest_vulnerability_published_at: null,
            has_high_severity_vulnerability: false,
            osv_ids: new Set()
          });
        }

        const record = aggregated.get(key);

        if (osv_id && !record.osv_ids.has(osv_id)) {
          record.osv_ids.add(osv_id);
          record.vulnerability_count++;

          if (is_high_severity === 'true') {
            record.high_severity_count++;
            record.has_high_severity_vulnerability = true;
          }

          if (severity_score !== null) {
            if (record.max_severity_score === null || severity_score > record.max_severity_score) {
              record.max_severity_score = severity_score;
            }
          }

          record.latest_vulnerability_published_at = getLatestDate(
            record.latest_vulnerability_published_at,
            published
          );
        }

      } catch (error) {
        console.warn(`Warning: Error processing line ${lineCount}: ${error.message}`);
      }
    });

    rl.on('close', () => {
      console.log(`Read ${lineCount - 1} data rows from input file`);
      resolve(aggregated);
    });

    rl.on('error', reject);
  });
}

async function main() {
  try {
    console.log('Starting Enriched OSV package summary aggregation...');

    await fs.access(INPUT_FILE);
    await fs.mkdir(OUTPUT_DIR, { recursive: true });

    const aggregated = await aggregateFromCsv();

    console.log(`Writing ${aggregated.size} unique package summary rows...`);
    const outputStream = createWriteStream(OUTPUT_FILE, { encoding: 'utf-8' });
    outputStream.write(OUTPUT_HEADERS.join(',') + '\n');

    for (const [key, data] of aggregated) {
      const record = {
        package_name: data.package_name,
        ecosystem: data.ecosystem,
        vulnerability_count: String(data.vulnerability_count),
        high_severity_count: String(data.high_severity_count),
        max_severity_score: data.max_severity_score !== null ? data.max_severity_score.toFixed(1) : '',
        latest_vulnerability_published_at: data.latest_vulnerability_published_at || '',
        has_high_severity_vulnerability: data.has_high_severity_vulnerability ? 'true' : 'false',
        osv_ids: [...data.osv_ids].join('|')
      };
      outputStream.write(recordToCsv(record) + '\n');
    }

    outputStream.end();
    await new Promise((resolve, reject) => {
      outputStream.on('finish', resolve);
      outputStream.on('error', reject);
    });

    console.log('\n--- Aggregation Complete ---');
    console.log(`Total unique packages: ${aggregated.size}`);
    console.log(`Output file: ${OUTPUT_FILE}`);

  } catch (error) {
    console.error(`Fatal error: ${error.message}`);
    process.exit(1);
  }
}

main();
