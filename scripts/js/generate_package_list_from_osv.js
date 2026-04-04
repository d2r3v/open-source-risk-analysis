
import fs from 'fs';
import path from 'path';
import Papa from 'papaparse';

const __dirname = path.dirname(new URL(import.meta.url).pathname.substring(1));
const projectRoot = path.resolve(__dirname, '..', '..');

const OSV_SUMMARY_PATH = path.join(projectRoot, 'data', 'cleaned', 'osv_package_summary.csv');
const OUTPUT_PATH = path.join(projectRoot, 'data', 'inputs', 'package_list.csv');

/**
 * Reads a CSV file, extracts unique package names, and writes them to a new CSV.
 * @param {string} inputPath - The path to the input CSV file.
 * @param {string} outputPath - The path to the output CSV file.
 */
function generatePackageList(inputPath, outputPath) {
    if (!fs.existsSync(inputPath)) {
        console.error(`Error: Input file not found at ${inputPath}`);
        process.exit(1);
    }

    const packageNames = new Set();
    let rowCount = 0;

    const fileStream = fs.createReadStream(inputPath);

    console.log(`Reading package names from ${inputPath}...`);

    Papa.parse(fileStream, {
        header: true,
        worker: true,
        step: (results) => {
            const row = results.data;
            if (row && row.package_name) {
                const normalizedName = row.package_name.trim().toLowerCase();
                if (normalizedName) {
                    packageNames.add(normalizedName);
                }
            }
            rowCount++;
        },
        complete: () => {
            console.log(`Processed ${rowCount} rows.`);
            if (packageNames.size === 0) {
                console.warn('Warning: No package names were extracted. The output file will be empty.');
                // Still create the file with a header
            }

            const uniquePackages = Array.from(packageNames);
            const csvOutput = Papa.unparse({
                fields: ['package_name'],
                data: uniquePackages.map(name => [name])
            });

            try {
                // Ensure the output directory exists
                const outputDir = path.dirname(outputPath);
                if (!fs.existsSync(outputDir)) {
                    fs.mkdirSync(outputDir, { recursive: true });
                }

                fs.writeFileSync(outputPath, csvOutput);
                console.log(`Successfully wrote ${uniquePackages.length} unique package names to ${outputPath}`);
            } catch (error) {
                console.error(`Error writing to output file ${outputPath}:`, error);
                process.exit(1);
            }
        },
        error: (error) => {
            console.error('An error occurred during CSV parsing:', error);
            process.exit(1);
        }
    });
}

generatePackageList(OSV_SUMMARY_PATH, OUTPUT_PATH);
