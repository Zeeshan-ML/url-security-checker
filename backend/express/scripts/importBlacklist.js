import fs from 'fs';
import mysql from 'mysql2/promise';

const dbConfig = {
  host: 'localhost', // Database server address
  port: 3306,        // MySQL default port
  user: 'root',
  password: 'essa123',
  database: 'url_checker'
};

async function importWhitelist() {
  try {
    // Read the whitelist file (each domain on a new line)
    const fileContent = fs.readFileSync('blacklists.txt', 'utf-8');
    // Split into lines and filter out empty lines
    const domains = fileContent
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(line => line.length > 0);

    const connection = await mysql.createConnection(dbConfig);
    console.log(`Found ${domains.length} blacklist domains to import.`);

    for (const domain of domains) {
      try {
        // Use INSERT IGNORE to skip duplicates (assuming 'url' is UNIQUE)
        await connection.execute(
          'INSERT IGNORE INTO blacklist (url) VALUES (?)',
          [domain]
        );
        console.log(`Inserted: ${domain}`);
      } catch (err) {
        console.error(`Error inserting ${domain}:`, err);
      }
    }
    await connection.end();
    console.log('Blacklist import completed.');
  } catch (err) {
    console.error('Error reading the blacklist file:', err);
  }
}

importWhitelist();
