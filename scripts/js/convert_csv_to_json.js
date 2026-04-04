
import fs from 'fs';
import path from 'path';
import Papa from 'papaparse';

const csvFilePath = process.argv[2];

if (!csvFilePath) {
  console.error('Error: Please provide the path to the CSV file as an argument.');
  process.exit(1);
}

const resolvedCsvPath = path.resolve(csvFilePath);
if (!fs.existsSync(resolvedCsvPath)) {
  console.error(`Error: The file "${resolvedCsvPath}" does not exist.`);
  process.exit(1);
}

const csvFileContent = fs.readFileSync(resolvedCsvPath, 'utf8');

Papa.parse(csvFileContent, {
  header: true,
  skipEmptyLines: true,
  complete: (results) => {
    const jsonFilePath = resolvedCsvPath.replace(/\.csv$/, '.json');
    
    fs.writeFile(jsonFilePath, JSON.stringify(results.data, null, 2), (err) => {
      if (err) {
        console.error('Error writing JSON file:', err);
        process.exit(1);
      }
      console.log(`Successfully converted ${resolvedCsvPath} to ${jsonFilePath}`);
    });
  },
  error: (error) => {
    console.error('Error parsing CSV file:', error);
    process.exit(1);
  },
});
