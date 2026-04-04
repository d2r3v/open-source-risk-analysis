#!/usr/bin/env node

/**
 * OSV Vulnerability Detail Fetcher
 *
 * Purpose: Fetch full vulnerability objects from the OSV API for each unique
 * OSV ID found in the flat npm vulnerability CSV.
 *
 * Input:  data/cleaned/osv_npm_flat.csv
 * Output: data/raw/osv/details/{id}.json
 *
 * Safe to rerun: existing detail files are skipped automatically.
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

const INPUT_FILE = path.join(projectRoot, 'data', 'cleaned', 'osv_npm_flat.csv');
const DETAILS_OUTPUT_DIR = path.join(projectRoot, 'data', 'raw', 'osv', 'details');

// ── Config ────────────────────────────────────────────────────────────────────
const OSV_VULN_URL_BASE = 'https://api.osv.dev/v1/vulns';
const REQUEST_DELAY_MS = 500;   // delay between requests
const MAX_RETRIES = 3;
const RETRY_BASE_MS = 1000;  // doubles on each retry

// ── Utilities ─────────────────────────────────────────────────────────────────
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ── Input reader ──────────────────────────────────────────────────────────────
/**
 * Read unique OSV IDs from the flat CSV.
 *
 * @returns {Promise<string[]>}
 */
async function readUniqueOsvIds() {
    return new Promise((resolve, reject) => {
        const ids = new Set();
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

            const idx = headerMap['osv_id'];
            if (idx !== undefined && fields[idx]) {
                ids.add(fields[idx]);
            }
        });

        rl.on('close', () => resolve([...ids]));
        rl.on('error', reject);
    });
}

// ── API Fetch ─────────────────────────────────────────────────────────────────
/**
 * Fetch a single vulnerability by ID with retry and exponential backoff.
 */
async function fetchVulnerability(id, attempt = 0) {
    const url = `${OSV_VULN_URL_BASE}/${encodeURIComponent(id)}`;

    try {
        const response = await fetch(url);

        if (response.status === 404) {
            console.error(`  ${id}: 404 not found`);
            return null;
        }

        if ([429, 500, 502, 503, 504].includes(response.status)) {
            if (attempt < MAX_RETRIES) {
                const wait = RETRY_BASE_MS * Math.pow(2, attempt);
                console.warn(`  ${id}: HTTP ${response.status} — retrying in ${wait}ms [${attempt + 1}/${MAX_RETRIES}]`);
                await sleep(wait);
                return fetchVulnerability(id, attempt + 1);
            }
            console.error(`  ${id}: HTTP ${response.status} — giving up after ${MAX_RETRIES} retries`);
            return null;
        }

        if (!response.ok) {
            console.error(`  ${id}: HTTP ${response.status} ${response.statusText} — skipping`);
            return null;
        }

        return await response.json();
    } catch (err) {
        if (attempt < MAX_RETRIES) {
            const wait = RETRY_BASE_MS * Math.pow(2, attempt);
            console.warn(`  ${id}: network error (${err.message}) — retrying in ${wait}ms [${attempt + 1}/${MAX_RETRIES}]`);
            await sleep(wait);
            return fetchVulnerability(id, attempt + 1);
        }
        console.error(`  ${id}: failed after ${MAX_RETRIES} retries — ${err.message}`);
        return null;
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────
async function main() {
    try {
        await fs.access(INPUT_FILE);
    } catch {
        console.error(`Error: Input file not found: ${INPUT_FILE}`);
        process.exit(1);
    }

    await fs.mkdir(DETAILS_OUTPUT_DIR, { recursive: true });

    console.log('OSV Detail Fetcher');
    console.log(`  Input  : ${INPUT_FILE}`);
    console.log(`  Output : ${DETAILS_OUTPUT_DIR}`);
    console.log(`  Delay  : ${REQUEST_DELAY_MS} ms between requests`);
    console.log('');

    const ids = await readUniqueOsvIds();
    const total = ids.length;

    console.log(`Found ${total} unique OSV IDs to fetch`);
    console.log('');

    let successCount = 0;
    let skippedCount = 0;
    let failedCount = 0;

    for (let i = 0; i < total; i++) {
        const id = ids[i];
        const filePath = path.join(DETAILS_OUTPUT_DIR, `${id}.json`);

        if (existsSync(filePath)) {
            console.log(`[${i + 1}/${total}] ${id} ... skipped (cached)`);
            skippedCount++;
            continue;
        }

        const result = await fetchVulnerability(id);

        if (result) {
            try {
                await fs.writeFile(filePath, JSON.stringify(result, null, 2), 'utf-8');
                console.log(`[${i + 1}/${total}] ${id} ... success`);
                successCount++;
            } catch (err) {
                console.error(`[${i + 1}/${total}] ${id} ... write error: ${err.message}`);
                failedCount++;
            }
        } else {
            console.log(`[${i + 1}/${total}] ${id} ... failed`);
            failedCount++;
        }

        if (i < total - 1) await sleep(REQUEST_DELAY_MS);
    }

    console.log('');
    console.log('━━━ Done ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
    console.log(`  IDs to fetch : ${total}`);
    console.log(`  Success      : ${successCount}`);
    console.log(`  Skipped      : ${skippedCount}`);
    console.log(`  Failed       : ${failedCount}`);
    console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
}

main().catch((err) => {
    console.error(`Fatal: ${err.message}`);
    process.exit(1);
});
