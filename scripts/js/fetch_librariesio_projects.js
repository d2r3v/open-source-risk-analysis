#!/usr/bin/env node

/**
 * Libraries.io Project Data Fetcher
 *
 * Purpose: Fetch project metadata from Libraries.io API for npm packages
 * and save both raw JSON responses and a combined CSV summary.
 *
 * Input:  data/inputs/package_list.csv (with package_name column)
 * Output:
 *   - data/raw/librariesio/projects/<package>.json  (one file per package)
 *   - data/cleaned/librariesio_projects.csv         (append/update rows)
 *
 * Safe for overnight / resumable runs:
 *   - Skips packages whose raw JSON cache file already exists (no API call).
 *   - Appends only new rows to the CSV (reads existing rows on startup).
 *   - 1200 ms delay between live requests to stay under 60 req/min.
 *   - Exponential backoff for transient errors and 429 responses.
 *   - 404 responses are logged and counted separately, not retried.
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { createReadStream, existsSync } from 'fs';
import readline from 'readline';
import dotenv from 'dotenv';

// ── Paths ────────────────────────────────────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..', '..');

dotenv.config({ path: path.resolve(projectRoot, '.env') });

const INPUT_FILE        = path.join(projectRoot, 'data', 'inputs', 'package_list.csv');
const RAW_OUTPUT_DIR    = path.join(projectRoot, 'data', 'raw', 'librariesio', 'projects');
const CLEANED_OUTPUT_DIR  = path.join(projectRoot, 'data', 'cleaned');
const CLEANED_OUTPUT_FILE = path.join(CLEANED_OUTPUT_DIR, 'librariesio_projects.csv');

// ── API config ────────────────────────────────────────────────────────────────
const API_BASE          = 'https://libraries.io/api/npm';
const API_KEY           = process.env.LIBRARIES_IO_API_KEY;
const REQUEST_DELAY_MS  = 1200;   // ≤ 60 req/min
const MAX_RETRIES       = 4;
const RETRY_BASE_MS     = 2000;   // doubles on each retry

// Sentinel returned when a package is definitively not found (404).
const NOT_FOUND = Symbol('NOT_FOUND');

// ── CSV schema ────────────────────────────────────────────────────────────────
const CSV_HEADERS = [
  'package_name',
  'platform',
  'description',
  'language',
  'stars',
  'forks',
  'contributions_count',
  'dependent_repos_count',
  'dependents_count',
  'rank',
  'repository_status',
  'repository_url',
  'licenses',
  'normalized_licenses',
  'latest_release_number',
  'latest_release_published_at',
  'versions_count',
];

// ── Utilities ─────────────────────────────────────────────────────────────────
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function normalizePackageName(name) {
  return (name || '').toLowerCase().trim();
}

function safeJsonParse(str) {
  try { return JSON.parse(str); } catch { return null; }
}

function getRawJsonPath(packageName) {
  const safe = packageName.replace(/[^a-z0-9\-_.@/]/g, '_');
  // Scoped packages like @scope/pkg → store as @scope%2Fpkg.json
  const filename = safe.replace('/', '%2F') + '.json';
  return path.join(RAW_OUTPUT_DIR, filename);
}

// ── CSV helpers ───────────────────────────────────────────────────────────────
function escapeCsvField(value) {
  const str = (value == null ? '' : String(value));
  const escaped = str.replace(/"/g, '""');
  return (escaped.includes(',') || escaped.includes('"') || escaped.includes('\n'))
    ? `"${escaped}"`
    : escaped;
}

function recordToCsvLine(record) {
  return CSV_HEADERS.map((h) => escapeCsvField(record[h])).join(',');
}

/** Read the set of package_name values already present in the CSV. */
async function loadExistingCsvPackages() {
  const existing = new Set();
  if (!existsSync(CLEANED_OUTPUT_FILE)) return existing;

  const rl = readline.createInterface({
    input: createReadStream(CLEANED_OUTPUT_FILE, { encoding: 'utf-8' }),
    crlfDelay: Infinity,
  });

  let firstLine = true;
  let nameIndex = 0;

  for await (const line of rl) {
    const fields = line.split(',').map((f) => f.trim().replace(/^"|"$/g, ''));
    if (firstLine) {
      nameIndex = fields.findIndex((f) => f.toLowerCase() === 'package_name');
      firstLine = false;
      continue;
    }
    if (fields[nameIndex]) existing.add(fields[nameIndex].toLowerCase());
  }

  return existing;
}

// ── Field extraction ──────────────────────────────────────────────────────────
function extractFields(packageName, apiData) {
  const versionsCount = Array.isArray(apiData.versions) ? apiData.versions.length : '';
  return {
    package_name:               packageName,
    platform:                   apiData.platform                 ?? 'npm',
    description:                apiData.description              ?? '',
    language:                   apiData.language                 ?? '',
    stars:                      apiData.stars                    ?? '',
    forks:                      apiData.forks                    ?? '',
    contributions_count:        apiData.contributions_count      ?? '',
    dependent_repos_count:      apiData.dependent_repos_count    ?? '',
    dependents_count:           apiData.dependents_count         ?? '',
    rank:                       apiData.rank                     ?? '',
    repository_status:          apiData.repository_status        ?? '',
    repository_url:             apiData.repository_url           ?? '',
    licenses:                   apiData.licenses                 ?? '',
    normalized_licenses:        Array.isArray(apiData.normalized_licenses)
                                  ? apiData.normalized_licenses.join(';')
                                  : (apiData.normalized_licenses ?? ''),
    latest_release_number:      apiData.latest_release_number    ?? '',
    latest_release_published_at: apiData.latest_release_published_at ?? '',
    versions_count:             versionsCount,
  };
}

// ── API fetch with retry / backoff ────────────────────────────────────────────
/**
 * Returns:
 *   - Object  : successful API response
 *   - NOT_FOUND symbol : HTTP 404 (log and continue, no retry)
 *   - null    : unrecoverable error after all retries
 */
async function fetchProjectData(packageName, attempt = 0) {
  const url = `${API_BASE}/${encodeURIComponent(packageName)}?api_key=${API_KEY}`;

  let response;
  try {
    response = await fetch(url);
  } catch (err) {
    // Network / DNS error — retry with backoff
    if (attempt < MAX_RETRIES) {
      const wait = RETRY_BASE_MS * Math.pow(2, attempt);
      console.warn(`    network error (${err.message}) — retrying in ${wait}ms [${attempt + 1}/${MAX_RETRIES}]`);
      await sleep(wait);
      return fetchProjectData(packageName, attempt + 1);
    }
    console.error(`    failed after ${MAX_RETRIES} retries: ${err.message}`);
    return null;
  }

  if (response.status === 404) {
    return NOT_FOUND;
  }

  if ([429, 500, 502, 503, 504].includes(response.status)) {
    if (attempt < MAX_RETRIES) {
      const wait = RETRY_BASE_MS * Math.pow(2, attempt);
      console.warn(`    HTTP ${response.status} — retrying in ${wait}ms [${attempt + 1}/${MAX_RETRIES}]`);
      await sleep(wait);
      return fetchProjectData(packageName, attempt + 1);
    }
    console.error(`    HTTP ${response.status} — giving up after ${MAX_RETRIES} retries`);
    return null;
  }

  if (!response.ok) {
    console.error(`    HTTP ${response.status} ${response.statusText} — skipping`);
    return null;
  }

  try {
    return await response.json();
  } catch (err) {
    console.error(`    JSON parse error: ${err.message}`);
    return null;
  }
}

// ── Input reader ──────────────────────────────────────────────────────────────
async function readPackageNames() {
  return new Promise((resolve, reject) => {
    const names = [];
    let headerMap = {};
    let lineCount = 0;

    const rl = readline.createInterface({
      input: createReadStream(INPUT_FILE, { encoding: 'utf-8' }),
      crlfDelay: Infinity,
    });

    rl.on('line', (line) => {
      lineCount++;
      const fields = line.split(',').map((f) => f.trim());
      if (lineCount === 1) {
        fields.forEach((f, i) => { headerMap[f.toLowerCase()] = i; });
        return;
      }
      const idx = headerMap['package_name'];
      if (idx !== undefined) {
        const name = normalizePackageName(fields[idx]);
        if (name) names.push(name);
      }
    });

    rl.on('close', () => resolve(names));
    rl.on('error', reject);
  });
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
  // ── Pre-flight checks
  if (!API_KEY) {
    console.error('Error: LIBRARIES_IO_API_KEY environment variable not set.');
    console.error('  Set it with: set LIBRARIES_IO_API_KEY=your_key   (Windows)');
    console.error('           or: export LIBRARIES_IO_API_KEY=your_key (Unix)');
    process.exit(1);
  }

  try { await fs.access(INPUT_FILE); } catch {
    console.error(`Error: Input file not found: ${INPUT_FILE}`);
    process.exit(1);
  }

  await fs.mkdir(RAW_OUTPUT_DIR,    { recursive: true });
  await fs.mkdir(CLEANED_OUTPUT_DIR, { recursive: true });

  console.log('Libraries.io project fetcher — safe overnight mode');
  console.log(`  Input  : ${INPUT_FILE}`);
  console.log(`  Raw    : ${RAW_OUTPUT_DIR}`);
  console.log(`  CSV    : ${CLEANED_OUTPUT_FILE}`);
  console.log(`  Delay  : ${REQUEST_DELAY_MS} ms between live requests`);
  console.log('');

  // ── Load state
  const packages   = await readPackageNames();
  const total      = packages.length;
  const inCsv      = await loadExistingCsvPackages();
  const needHeader = !existsSync(CLEANED_OUTPUT_FILE);

  // Open CSV in append mode
  const csvFd = await fs.open(CLEANED_OUTPUT_FILE, 'a');

  if (needHeader) {
    await csvFd.write(CSV_HEADERS.join(',') + '\n');
  }

  console.log(`Found ${total} packages. ${inCsv.size} already in CSV.`);
  console.log('');

  // ── Counters
  let successCount  = 0;
  let skippedCount  = 0;
  let notFoundCount = 0;
  let failedCount   = 0;

  // ── Process
  for (let i = 0; i < total; i++) {
    const pkg     = packages[i];
    const label   = `[${i + 1}/${total}] ${pkg}`;
    const jsonPath = getRawJsonPath(pkg);

    // Cache hit — skip API call entirely
    if (existsSync(jsonPath)) {
      // If the CSV row is also there, fully skip
      if (inCsv.has(pkg)) {
        console.log(`${label} ... skipped (cached)`);
        skippedCount++;
        continue;
      }

      // JSON exists but not yet in CSV — extract and append
      try {
        const raw  = await fs.readFile(jsonPath, 'utf-8');
        const data = safeJsonParse(raw);
        if (data) {
          const row = extractFields(pkg, data);
          await csvFd.write(recordToCsvLine(row) + '\n');
          inCsv.add(pkg);
          console.log(`${label} ... success (from cache, appended to CSV)`);
          successCount++;
        } else {
          console.log(`${label} ... skipped (corrupt cache, rerun with cache cleared)`);
          skippedCount++;
        }
      } catch (err) {
        console.log(`${label} ... failed (cache read error: ${err.message})`);
        failedCount++;
      }
      continue;
    }

    // Live fetch
    const result = await fetchProjectData(pkg);

    if (result === NOT_FOUND) {
      console.log(`${label} ... 404 not found`);
      notFoundCount++;
      // Delay before the next live request
      if (i < total - 1) await sleep(REQUEST_DELAY_MS);
      continue;
    }

    if (result === null) {
      console.log(`${label} ... failed`);
      failedCount++;
      if (i < total - 1) await sleep(REQUEST_DELAY_MS);
      continue;
    }

    // Save raw JSON
    try {
      await fs.writeFile(jsonPath, JSON.stringify(result, null, 2), 'utf-8');
    } catch (err) {
      console.warn(`  Warning: could not write cache file: ${err.message}`);
    }

    // Append CSV row
    try {
      const row = extractFields(pkg, result);
      await csvFd.write(recordToCsvLine(row) + '\n');
      inCsv.add(pkg);
      console.log(`${label} ... success`);
      successCount++;
    } catch (err) {
      console.log(`${label} ... failed (CSV write error: ${err.message})`);
      failedCount++;
    }

    // Throttle
    if (i < total - 1) await sleep(REQUEST_DELAY_MS);
  }

  await csvFd.close();

  // ── Summary
  console.log('');
  console.log('━━━ Done ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
  console.log(`  Total    : ${total}`);
  console.log(`  Success  : ${successCount}`);
  console.log(`  Skipped  : ${skippedCount}`);
  console.log(`  404      : ${notFoundCount}`);
  console.log(`  Failed   : ${failedCount}`);
  console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
}

main().catch((err) => {
  console.error(`Fatal: ${err.message}`);
  process.exit(1);
});
