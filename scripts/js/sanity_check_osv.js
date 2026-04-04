#!/usr/bin/env node

/**
 * Sanity Check for OSV Package Summary
 * 
 * Verifies:
 * 1. No empty high_severity_count fields.
 * 2. Logical consistency: high_severity_count > 0 iff max_severity_score >= 7.0.
 * 3. Distribution overview.
 */

import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const projectRoot = path.resolve(__dirname, '..', '..');

const SUMMARY_FILE = path.join(projectRoot, 'data', 'cleaned', 'osv_package_summary.csv');

function parseCsvLine(line) {
    const fields = [];
    let current = '';
    let inQuotes = false;
    for (let i = 0; i < line.length; i++) {
        const char = line[i];
        if (char === '"') inQuotes = !inQuotes;
        else if (char === ',' && !inQuotes) {
            fields.push(current);
            current = '';
        } else current += char;
    }
    fields.push(current);
    return fields;
}

try {
    const content = fs.readFileSync(SUMMARY_FILE, 'utf-8');
    const lines = content.split('\n').filter(l => l.trim());
    const headers = lines[0].split(',');
    const hMap = {};
    headers.forEach((h, i) => hMap[h.trim()] = i);

    const data = lines.slice(1).map(parseCsvLine);
    const total = data.length;

    let blankCount = 0;
    let logicErrors = [];
    let highSeverityPkgs = 0;
    let zeroVulnPkgs = 0; // Should be 0 since we only list packages with vulns here

    console.log(`Verifying ${total} packages...\n`);

    data.forEach((row, idx) => {
        const name = row[hMap['package_name']];
        const hscStr = row[hMap['high_severity_count']] || '';
        const mssStr = row[hMap['max_severity_score']] || '';

        if (hscStr === '') blankCount++;

        const hsc = parseInt(hscStr) || 0;
        const mss = mssStr === '' ? null : parseFloat(mssStr);

        if (hsc > 0) {
            highSeverityPkgs++;
            if (mss === null || mss < 7.0) {
                logicErrors.push(`[${name}] high_severity_count=${hsc} but max_severity_score=${mss}`);
            }
        } else {
            if (mss !== null && mss >= 7.0) {
                logicErrors.push(`[${name}] high_severity_count=0 but max_severity_score=${mss}`);
            }
        }
    });

    console.log(`1. Blank check: ${blankCount === 0 ? 'PASS' : 'FAIL (' + blankCount + ' blanks found)'}`);
    console.log(`2. Logic check: ${logicErrors.length === 0 ? 'PASS' : 'FAIL'}`);
    if (logicErrors.length > 0) {
        console.log('   Errors found:');
        logicErrors.slice(0, 5).forEach(e => console.log(`    - ${e}`));
        if (logicErrors.length > 5) console.log(`    ... and ${logicErrors.length - 5} more`);
    }

    console.log(`\n3. Distribution:`);
    console.log(`   Packages with High Severity : ${highSeverityPkgs} (${((highSeverityPkgs / total) * 100).toFixed(1)}%)`);
    console.log(`   Packages with Low/Med Only  : ${total - highSeverityPkgs} (${(((total - highSeverityPkgs) / total) * 100).toFixed(1)}%)`);

    if (highSeverityPkgs > 0 && highSeverityPkgs < total * 0.95) {
        console.log(`   Distribution check: PASS (Healthy mix)`);
    } else {
        console.log(`   Distribution check: CAUTION (Skewed data)`);
    }

} catch (err) {
    console.error(`Error: ${err.message}`);
}
