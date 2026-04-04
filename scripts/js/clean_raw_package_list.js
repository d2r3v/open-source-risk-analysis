
import fs from 'fs';
import path from 'path';

const projectRoot = process.cwd();
const inputFile = path.join(projectRoot, 'data', 'inputs', 'raw_package_list.txt');
const outputFile = path.join(projectRoot, 'data', 'inputs', 'package_list.csv');

console.log(`Reading raw package list from: ${inputFile}`);

try {
    const fileContent = fs.readFileSync(inputFile, 'utf8');
    const lines = fileContent.split(/\r?\n/);

    const cleanedNames = lines
        .map(line => {
            // Take the part before " - " and trim whitespace
            return line.split(' - ')[0].trim();
        })
        .filter(name => name) // Remove any empty lines that might result
        .map(name => name.toLowerCase()); // Convert to lowercase

    // Use a Set to get unique names
    const uniqueNames = [...new Set(cleanedNames)];

    console.log(`Found ${uniqueNames.length} unique package names.`);

    // Format for CSV output
    const csvContent = "package_name\n" + uniqueNames.join('\n');

    fs.writeFileSync(outputFile, csvContent);
    console.log(`Cleaned package list saved to: ${outputFile}`);

} catch (error) {
    console.error(`An error occurred: ${error.message}`);
    process.exit(1);
}
