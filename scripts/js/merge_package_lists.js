
import fs from 'fs';
import path from 'path';
import Papa from 'papaparse';

const projectRoot = process.cwd();
const topPackagesFile = path.join(projectRoot, 'data', 'inputs', 'top_packages.csv');
const osvSummaryFile = path.join(projectRoot, 'data', 'cleaned', 'osv_package_summary.csv');
const outputFile = path.join(projectRoot, 'data', 'inputs', 'package_list.csv');

const readCsv = (filePath) => {
    return new Promise((resolve, reject) => {
        if (!fs.existsSync(filePath)) {
            console.warn(`Warning: File not found at ${filePath}. Skipping.`);
            return resolve([]);
        }
        const fileContent = fs.readFileSync(filePath, 'utf8');
        Papa.parse(fileContent, {
            header: true,
            skipEmptyLines: true,
            complete: (results) => resolve(results.data),
            error: (error) => reject(error),
        });
    });
};

const run = async () => {
    try {
        console.log('Starting package list merge...');
        const [topPackages, osvPackages] = await Promise.all([
            readCsv(topPackagesFile),
            readCsv(osvSummaryFile)
        ]);

        console.log(`Read ${topPackages.length} packages from top_packages.csv.`);
        console.log(`Read ${osvPackages.length} packages from osv_package_summary.csv.`);

        const packageNames = new Set();

        topPackages.forEach(row => {
            if (row.package_name) {
                packageNames.add(row.package_name.trim().toLowerCase());
            }
        });

        osvPackages.forEach(row => {
            if (row.package_name) {
                packageNames.add(row.package_name.trim().toLowerCase());
            }
        });

        const uniquePackageNames = Array.from(packageNames);
        console.log(`Found ${uniquePackageNames.length} unique package names.`);

        const outputCsv = Papa.unparse({
            fields: ['package_name'],
            data: uniquePackageNames.map(name => [name])
        });

        fs.writeFileSync(outputFile, outputCsv);
        console.log(`Successfully wrote merged package list to ${outputFile}`);

    } catch (error) {
        console.error('An error occurred during the merge process:', error);
        process.exit(1);
    }
};

run();
