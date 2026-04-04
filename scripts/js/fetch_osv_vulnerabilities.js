#!/usr/bin/env node

/**
 * OSV Vulnerability Data Fetcher
 *
 * Purpose: Fetch vulnerability data from the OSV API for npm packages
 * using the querybatch endpoint and save raw JSON responses locally.
 *
 * Input:  data/inputs/package_list.csv  (column: package_name)
 * Output: data/raw/osv/batch_<index>.json  (one file per batch of 100)
 *
 * Safe to rerun: existing batch files are skipped automatically.
 */

import fs from 'fs/promises';
import path from 'path';
import { fileURLToPath } from 'url';
import { createReadStream, existsSync } from 'fs';
import readline from 'readline';

// ── Paths ─────────────────────────────────────────────────────────────────────
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..', '..');

const INPUT_FILE = path.join(projectRoot, 'data', 'inputs', 'package_list.csv');
const RAW_OUTPUT_DIR = path.join(projectRoot, 'data', 'raw', 'osv');

// ── Config ────────────────────────────────────────────────────────────────────
const OSV_QUERYBATCH_URL = 'https://api.osv.dev/v1/querybatch';
const BATCH_SIZE = 100;   // packages per request
const BATCH_DELAY_MS = 500;   // delay between batches
const MAX_RETRIES = 3;
const RETRY_BASE_MS = 1000;  // doubles on each retry

// ── Utilities ─────────────────────────────────────────────────────────────────
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function normalizePackageName(name) {
    return (name || '').toLowerCase().trim();
}

/** Split an array into chunks of at most `size` elements. */
function chunkArray(arr, size) {
    const chunks = [];
    for (let i = 0; i < arr.length; i += size) {
        chunks.push(arr.slice(i, i + size));
    }
    return chunks;
}

// ── Input reader ──────────────────────────────────────────────────────────────
/**
 * Read unique, normalised package names from the input CSV.
 * Expects a header row with a "package_name" column.
 *
 * @returns {Promise<string[]>}
 */
async function readPackageNames() {
    return new Promise((resolve, reject) => {
        const seen = new Set();
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
                // Build index map from header row
                fields.forEach((f, i) => { headerMap[f.toLowerCase()] = i; });
                return;
            }

            const idx = headerMap['package_name'];
            if (idx === undefined) return;

            const name = normalizePackageName(fields[idx]);
            if (name && !seen.has(name)) {
                seen.add(name);
                names.push(name);
            }
        });

        rl.on('close', () => resolve(names));
        rl.on('error', reject);
    });
}

// ── OSV API ───────────────────────────────────────────────────────────────────
/**
 * Build the querybatch request body for a list of package names.
 *
 * @param {string[]} packageNames
 * @returns {Object}
 */
function buildRequestBody(packageNames) {
    return {
        queries: packageNames.map((name) => ({
            package: { name, ecosystem: 'npm' },
        })),
    };
}

/**
 * POST a batch to the OSV querybatch endpoint with retry / exponential backoff.
 *
 * @param {string[]} packageNames  - Names in this batch
 * @param {number}   batchIndex   - 0-based index (for logging)
 * @param {number}   attempt      - Current attempt number (0-based)
 * @returns {Promise<Object|null>} Parsed JSON response, or null on failure
 */
async function fetchBatch(packageNames, batchIndex, attempt = 0) {
    const body = JSON.stringify(buildRequestBody(packageNames));

    let response;
    try {
        response = await fetch(OSV_QUERYBATCH_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body,
        });
    } catch (err) {
        // Network / DNS error
        if (attempt < MAX_RETRIES) {
            const wait = RETRY_BASE_MS * Math.pow(2, attempt);
            console.warn(`  batch ${batchIndex + 1}: network error (${err.message}) — retrying in ${wait}ms [${attempt + 1}/${MAX_RETRIES}]`);
            await sleep(wait);
            return fetchBatch(packageNames, batchIndex, attempt + 1);
        }
        console.error(`  batch ${batchIndex + 1}: failed after ${MAX_RETRIES} retries — ${err.message}`);
        return null;
    }

    // Retry on transient HTTP errors
    if ([429, 500, 502, 503, 504].includes(response.status)) {
        if (attempt < MAX_RETRIES) {
            const wait = RETRY_BASE_MS * Math.pow(2, attempt);
            console.warn(`  batch ${batchIndex + 1}: HTTP ${response.status} — retrying in ${wait}ms [${attempt + 1}/${MAX_RETRIES}]`);
            await sleep(wait);
            return fetchBatch(packageNames, batchIndex, attempt + 1);
        }
        console.error(`  batch ${batchIndex + 1}: HTTP ${response.status} — giving up after ${MAX_RETRIES} retries`);
        return null;
    }

    if (!response.ok) {
        console.error(`  batch ${batchIndex + 1}: HTTP ${response.status} ${response.statusText} — skipping`);
        return null;
    }

    try {
        return await response.json();
    } catch (err) {
        console.error(`  batch ${batchIndex + 1}: JSON parse error — ${err.message}`);
        return null;
    }
}

// ── Output helpers ────────────────────────────────────────────────────────────
/**
 * Return the file path for a given 0-based batch index.
 * Uses 1-based naming for readability: batch_1.json, batch_2.json, …
 *
 * @param {number} batchIndex
 * @returns {string}
 */
function getBatchFilePath(batchIndex) {
    return path.join(RAW_OUTPUT_DIR, `batch_${batchIndex + 1}.json`);
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
    // Pre-flight: input file must exist
    try { await fs.access(INPUT_FILE); } catch {
        console.error(`Error: Input file not found: ${INPUT_FILE}`);
        process.exit(1);
    }

    // Ensure output directory exists
    await fs.mkdir(RAW_OUTPUT_DIR, { recursive: true });

    console.log('OSV vulnerability fetcher');
    console.log(`  Input  : ${INPUT_FILE}`);
    console.log(`  Output : ${RAW_OUTPUT_DIR}`);
    console.log(`  Batch  : ${BATCH_SIZE} packages / request`);
    console.log(`  Delay  : ${BATCH_DELAY_MS} ms between batches`);
    console.log('');

    // Read and deduplicate packages
    const packages = await readPackageNames();
    const batches = chunkArray(packages, BATCH_SIZE);
    const total = batches.length;

    console.log(`Found ${packages.length} unique packages → ${total} batch(es)`);
    console.log('');

    let successCount = 0;
    let skippedCount = 0;
    let failedCount = 0;
    let totalProcessed = 0;

    for (let i = 0; i < total; i++) {
        const batch = batches[i];
        const filePath = getBatchFilePath(i);

        // Resumability: skip if output file already exists
        if (existsSync(filePath)) {
            console.log(`[batch ${i + 1}/${total}] skipped (already cached) — ${batch.length} packages`);
            skippedCount++;
            totalProcessed += batch.length;
            continue;
        }

        // Fetch from OSV
        const result = await fetchBatch(batch, i);

        if (result === null) {
            console.log(`[batch ${i + 1}/${total}] failed — ${batch.length} packages`);
            failedCount++;
            totalProcessed += batch.length;
        } else {
            // Attach metadata so the file is self-describing
            const payload = {
                _meta: {
                    batch_index: i + 1,
                    batch_total: total,
                    package_count: batch.length,
                    packages: batch,
                    fetched_at: new Date().toISOString(),
                },
                ...result,
            };

            try {
                await fs.writeFile(filePath, JSON.stringify(payload, null, 2), 'utf-8');
                console.log(`[batch ${i + 1}/${total}] processed ${batch.length} packages`);
                successCount++;
                totalProcessed += batch.length;
            } catch (err) {
                console.error(`[batch ${i + 1}/${total}] write error: ${err.message}`);
                failedCount++;
                totalProcessed += batch.length;
            }
        }

        // Throttle between batches (skip delay after the last one)
        if (i < total - 1) await sleep(BATCH_DELAY_MS);
    }

    // Summary
    console.log('');
    console.log('━━━ Done ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`  Total packages processed : ${totalProcessed} / ${packages.length}`);
    console.log(`  Batches succeeded        : ${successCount}`);
    console.log(`  Batches skipped (cached) : ${skippedCount}`);
    console.log(`  Batches failed           : ${failedCount}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
}

main().catch((err) => {
    console.error(`Fatal: ${err.message}`);
    process.exit(1);
});
