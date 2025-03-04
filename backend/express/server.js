import express from 'express';
import bodyParser from 'body-parser';
import mysql from 'mysql2/promise';
import { URL } from 'url';
import fetch from 'node-fetch';
import behaviorRoute from './routes/behaviorRoute.js';
import levenshtein from 'fast-levenshtein';
import natural from 'natural';
import { dbConfig } from './config/config.js';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import dotenv from 'dotenv';
import { logToSplunk } from './splunkLogger.js';
import https from 'https';
dotenv.config();

const app = express();
const PORT = process.env.PORT || 3000;
app.set('trust proxy', true);

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Middleware
app.use(bodyParser.json());
app.use(express.static(path.join(__dirname, '../../public')));
app.use(behaviorRoute);

// API Keys
const API_KEYS = {
  GOOGLE: 'Enter Your API Key',
  VIRUSTOTAL: 'Enter Your API Key',
  URLSCAN: 'Enter Your API Key'
};

const connection = await mysql.createConnection(dbConfig);
console.log('Connection Created Successfully.');
try {
  // Check if the database already exists
  const [databases] = await connection.query("SHOW DATABASES LIKE 'url_checker'");
  if (databases.length > 0) {
    console.log("Database 'url_checker' already exists.");
  } else {
    // Database doesn't exist; create it.
    const createDatabaseSql = 'CREATE DATABASE IF NOT EXISTS url_checker;';
    await connection.query(createDatabaseSql);
    console.log('Database created.');

    // Use the newly created database.
    const useDatabaseSql = 'USE url_checker;';
    await connection.query(useDatabaseSql);
    console.log('Database selected.');

    // Read the SQL file that contains table creation queries.
    const sqlFilePath = path.join(__dirname, '../../db/db.sql');
    const sqlFileContent = await fs.promises.readFile(sqlFilePath, 'utf8');

    // Split the SQL file into individual statements.
    const statements = sqlFileContent
      .split(/;\s*$/m)
      .map(stmt => stmt.trim())
      .filter(stmt => stmt.length > 0);

    // Execute each statement sequentially.
    for (const stmt of statements) {
      await connection.query(stmt);
      console.log('Executed statement:', stmt.split('\n')[0] + ' ...');
    }

    console.log('Schema initialized successfully.');
  }
} catch (err) {
  console.error('Error:', err);
}

// Helper function to validate URL format
const isValidURL = (str) => {
  try {
    new URL(str);
    return true;
  } catch (err) {
    return false;
  }
};

const wellKnownDomains = ["google.com", "facebook.com", "paypal.com", "amazon.com", "microsoft.com"];

const isTyposquatting = (domain) => {
  for (const knownDomain of wellKnownDomains) {
    const levenshteinDistance = levenshtein.get(domain, knownDomain);
    const maxLength = Math.max(domain.length, knownDomain.length);
    const levenshteinSimilarity = 1 - (levenshteinDistance / maxLength);
    
    const jaroWinklerSimilarity = natural.JaroWinklerDistance(domain, knownDomain);
    
    // If similarity is high enough, return true (typosquatting detected)
    if (levenshteinSimilarity > 0.8 || jaroWinklerSimilarity > 0.85) {
      return true;
    }
  }
  return false; // No typosquatting detected
};

const analyzeDomainAndLength = (inputUrl) => {
  const parsedUrl = new URL(inputUrl);
  const domain = parsedUrl.hostname;
  const urlLength = inputUrl.length;
  
  let score = 0;
  // Check for suspicious characteristics
  if (urlLength > 75) score += 1; // Long URL
  if (/[\d]{3,}/.test(domain)) score += 1; // 3+ consecutive digits
  if (domain.includes('-')) score += 1; // Hyphen in domain (common in phishing)
  if (domain.split('.').length > 3) score += 1; // Too many subdomains

  // Check for typosquatting
  if (isTyposquatting(domain)) score += 2;

  return { domain, urlLength, score };
};

// Check with Google Safe Browsing API
const checkGoogleSafeBrowsing = async (url) => {
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${API_KEYS.GOOGLE}`;
  const requestBody = {
    client: { clientId: "url-checker", clientVersion: "1.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };

  try {
    const response = await fetch(endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(requestBody),
    });
    
    if (!response.ok) {
      console.error(`Google Safe Browsing Error: ${response.status} ${response.statusText}`);
      return null;
    }

    const data = await response.json();
    console.log('Google Safe Browsing Response:', JSON.stringify(data, null, 2));
    return data.matches ? true : false;
  } catch (error) {
    console.error("Google Safe Browsing Network Error:", error);
    return null;
  }
};

// Check with VirusTotal API
const checkVirusTotal = async (url) => {
  const encodedUrl = Buffer.from(url).toString('base64').replace(/=/g, '');
  const endpoint = `https://www.virustotal.com/api/v3/urls/${encodedUrl}`;

  try {
    const response = await fetch(endpoint, {
      headers: { 'x-apikey': API_KEYS.VIRUSTOTAL }
    });

    if (response.status === 404) {
      console.log('VirusTotal: URL not found in database');
      return false;
    }

    if (!response.ok) {
      console.error(`VirusTotal Error: ${response.status} ${response.statusText}`);
      return null;
    }

    const data = await response.json();
    console.log('VirusTotal Response:', JSON.stringify(data, null, 2));
    return data.data?.attributes?.last_analysis_stats?.malicious > 0;
  } catch (error) {
    console.error("VirusTotal Network Error:", error);
    return null;
  }
};

// Check with URLScan.io API
const checkURLScan = async (url) => {
  const submitEndpoint = 'https://urlscan.io/api/v1/scan/';
  
  try {
    // Submit scan request
    const submitResponse = await fetch(submitEndpoint, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'API-Key': API_KEYS.URLSCAN
      },
      body: JSON.stringify({ 
        url, 
        public: "on",
        customagent: 'URLChecker/1.0'
      })
    });

    if (!submitResponse.ok) {
      console.error(`URLScan Submit Error: ${submitResponse.status} ${submitResponse.statusText}`);
      return null;
    }

    const submitData = await submitResponse.json();
    console.log('URLScan Submission:', JSON.stringify(submitData, null, 2));

    const { uuid } = submitData;
    if (!uuid) throw new Error('Missing UUID in URLScan response');

    // Poll results with retries
    const resultEndpoint = `https://urlscan.io/api/v1/result/${uuid}/`;
    let resultData;
    let attempts = 0;

    while (attempts < 12) { // 12 attempts * 5s = 1 minute timeout
      await new Promise(resolve => setTimeout(resolve, 5000));
      const resultResponse = await fetch(resultEndpoint);
      if (resultResponse.status === 404) {
        console.log(`URLScan Result Not Ready (attempt ${attempts + 1})`);
        attempts++;
        continue;
      }
      if (!resultResponse.ok) {
        console.error(`URLScan Result Error: ${resultResponse.status} ${resultResponse.statusText}`);
        return null;
      }
      resultData = await resultResponse.json();
      return resultData.verdicts?.overall?.malicious || false;
    }
    console.error('URLScan: Timed out waiting for results');
    return null;
  } catch (error) {
    console.error("URLScan Error:", error);
    return null;
  }
};

// API endpoint to analyze URLs
app.post('/analyze', async (req, res) => {
  const { url } = req.body;
  let clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (clientIp === '::1') {
    clientIp = '127.0.0.1';
  }
  console.log("Ip Address:",clientIp)
  if (!url || !isValidURL(url)) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }

  console.log(`\n=== Starting analysis for: ${url} ===`);

  try {
    // Check whitelist
    const [whitelist] = await connection.execute(
      'SELECT * FROM whitelist WHERE url = ?', [url]
    );
    if (whitelist.length > 0) {
      console.log('URL found in whitelist');
      await connection.execute(
        'INSERT INTO history (url, result, risk_level) VALUES (?, "Safe", "Low")', [url]
      );
      // Log the whitelist event to Splunk
      logToSplunk({
        event: "URL Analysis",
        url,
        ip: clientIp,
        whitelistStatus: true,
        blacklistStatus: false,
        externalChecks: {},
        domainAnalysis: {},
        riskLevel: "Low",
        finalResult: "Safe",
        details: "Whitelisted URL",
        timestamp: new Date().toISOString()
      });
      return res.json({
        result: 'Safe',
        riskLevel: 'Low',
        details: 'Whitelisted URL'
      });
    }

    // Check blacklist
    const [blacklist] = await connection.execute(
      'SELECT * FROM blacklist WHERE url = ?', [url]
    );
    if (blacklist.length > 0) {
      console.log('URL found in blacklist');
      await connection.execute(
        'INSERT INTO history (url, result, risk_level) VALUES (?, "Malicious", "High")', [url]
      );
      // Log the blacklist event to Splunk
      logToSplunk({
        event: "URL Analysis",
        url,
        ip: clientIp,
        whitelistStatus: false,
        blacklistStatus: true,
        externalChecks: {},
        domainAnalysis: {},
        riskLevel: "High",
        finalResult: "Malicious",
        details: "Blacklisted URL",
        timestamp: new Date().toISOString()
      });
      return res.json({
        result: 'Malicious',
        riskLevel: 'High',
        details: 'Blacklisted URL'
      });
    }

    // External API checks
    console.log('Starting external API checks...');
    const [gsbResult, vtResult, usResult] = await Promise.all([
      checkGoogleSafeBrowsing(url),
      checkVirusTotal(url),
      checkURLScan(url)
    ]);

    // Count only conclusive results (non-null)
    const apiResults = [gsbResult, vtResult, usResult].filter(r => r !== null);
    const apiFlags = apiResults.filter(Boolean).length;
    const totalChecks = apiResults.length;

    // Calculate risk level
    let riskLevel = 'Low';
    if (apiFlags >= 2 && totalChecks >= 2) riskLevel = 'High';
    else if (apiFlags >= 1 || totalChecks < 2) riskLevel = 'Moderate';

    // Domain analysis adjustment
    const { score, urlLength } = analyzeDomainAndLength(url);
    console.log('Domain Analysis Score:', score);
    console.log('Url Length:', urlLength);
    
    if (score >= 2) {
      riskLevel = riskLevel === 'Low' ? 'Moderate' : 'High';
    }

    // Final determination
    const result = riskLevel === 'High' ? 'Malicious' : 'Safe';
    
    // Log to history
    await connection.execute(
      'INSERT INTO history (url, result, risk_level) VALUES (?, ?, ?)',
      [url, result, riskLevel]
    );

    // Prepare details message
    const details = [
      `Google Safe Browsing: ${gsbResult === null ? 'Error - Unable to fetch data' : (gsbResult ? 'Flagged - Potential phishing/malicious URL' : 'Clear - No detected threats')}`,
      `VirusTotal: ${vtResult === null ? 'Error - Unable to fetch data' : (vtResult ? 'Flagged - Reported as harmful' : 'Clear - No issues found')}`,
      `URLScan.io: ${usResult === null ? 'Error - Scan unavailable' : (usResult ? 'Flagged - Suspicious activity detected' : 'Clear - No suspicious behavior')}`,
      `Url Length: ${urlLength} characters`,
      `Domain Analysis Score: ${score} (Higher score indicates higher risk)`
    ]; 

    console.log(`\n=== Final Result for ${url} ===`);
    console.log(`Result: ${result}`);
    console.log(`Risk Level: ${riskLevel}`);
    console.log(`Details: ${details}\n`);

    // Log the complete analysis event to Splunk
    logToSplunk({
      event: "URL Analysis",
      url,
      ip: clientIp,
      whitelistStatus: false,
      blacklistStatus: false,
      externalChecks: {
        googleSafeBrowsing: gsbResult,
        virusTotal: vtResult,
        urlScan: usResult
      },
      domainAnalysis: {
        score: score,
        urlLength: urlLength
      },
      riskLevel,
      finalResult: result,
      details,
      timestamp: new Date().toISOString()
    });

    res.json({ result, riskLevel, details });

  } catch (error) {
    console.error('Server Error:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
const sslDirectory = path.join(__dirname, '../../ssl');
const httpsOptions = {
  key: fs.readFileSync(path.join(sslDirectory, 'localhost-key.pem')),
  cert: fs.readFileSync(path.join(sslDirectory, 'localhost.pem'))
};

https.createServer(httpsOptions, app).listen(PORT, () => {
  console.log(`Server running securely on https://localhost:${PORT}`);
});
