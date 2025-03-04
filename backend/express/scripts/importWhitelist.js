import fs from 'fs';
import mysql from 'mysql2/promise';

const dbConfig = {
  host: 'localhost',
  port: 3306,
  user: 'root',
  password: 'essa123',
  database: 'url_checker'
};

async function importWhitelist() {
  try {
    // Read the whitelist file (each domain on a new line)
    const fileContent = fs.readFileSync('whitelist.txt', 'utf-8');
    
    // Process each line, filter out empty lines
    const domains = fileContent
      .split(/\r?\n/)
      .map(line => line.trim())
      .filter(line => line.length > 0)
      .map(domain => {
        // Ensure the domain has http:// or https://
        return domain.startsWith('http://') || domain.startsWith('https://')
          ? domain
          : `http://${domain}`;
      });

    const connection = await mysql.createConnection(dbConfig);
    console.log(`Found ${domains.length} whitelist domains to import.`);

    for (const domain of domains) {
      try {
        // Use INSERT IGNORE to skip duplicates (assuming 'url' is UNIQUE)
        await connection.execute(
          'INSERT IGNORE INTO whitelist (url) VALUES (?)',
          [domain]
        );
        console.log(`Inserted: ${domain}`);
      } catch (err) {
        console.error(`Error inserting ${domain}:`, err);
      }
    }
    
    await connection.end();
    console.log('Whitelist import completed.');
  } catch (err) {
    console.error('Error reading the whitelist file:', err);
  }
}

importWhitelist();
