import puppeteer from 'puppeteer';
import { dbConfig } from './config/config.js';
import mysql from 'mysql2/promise';
import { logToSplunk } from './splunkLogger.js';

const db = mysql.createConnection(dbConfig);

/**
 * Analyzes the behavior of the given URL by launching a headless browser,
 * injecting scripts to track 10 behavioral events, and then calculating a risk score.
 *
 * Behavioral Checks:
 *  1. Frequent redirects
 *  2. Mouse hover triggers
 *  3. Time spent on the page
 *  4. Right-click blocking
 *  5. IFrame usage
 *  6. Pop-ups & auto-downloads
 *  7. Form submission without user input
 *  8. Keystroke monitoring
 *  9. Clipboard access
 * 10. Obfuscated links
 *
 * @param {string} targetUrl - The URL to analyze.
 * @param {string} clientIp - The IP address of the client making the request.
 * @returns {Promise<object>} - Returns an object with the collected event data and a risk score.
 */
async function analyzeUrlBehavior(targetUrl, clientIp) {
  // Launch a headless browser
  const browser = await puppeteer.launch({ headless: true });
  const page = await browser.newPage();

  // Object to hold event data for each check
  const eventData = {
    redirects: 0,
    mouseHoverCount: 0,
    timeSpent: 0,
    rightClickBlocked: false,
    iframeCount: 0,
    popups: 0,
    autoFormSubmissions: 0,
    keystrokeListeners: 0,
    clipboardAccess: false,
    obfuscatedLinks: 0
  };

  // Record the start time for measuring time spent on page
  const startTime = Date.now();

  // Expose a function so the page’s injected code can report events back to Node.js
  await page.exposeFunction('reportBehavior', (eventName, value) => {
    switch (eventName) {
      case 'redirect':
        eventData.redirects++;
        break;
      case 'mouseHover':
        eventData.mouseHoverCount++;
        break;
      case 'rightClickBlocked':
        eventData.rightClickBlocked = true;
        break;
      case 'popup':
        eventData.popups++;
        break;
      case 'autoFormSubmit':
        eventData.autoFormSubmissions++;
        break;
      case 'keystrokeListener':
        eventData.keystrokeListeners++;
        break;
      case 'clipboardAccess':
        eventData.clipboardAccess = true;
        break;
      case 'obfuscatedLink':
        eventData.obfuscatedLinks++;
        break;
      default:
        break;
    }
  });

  // Monitor redirects (if the main frame navigates, count it)
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) {
      eventData.redirects++;
    }
  });

  // Inject a script to the target page to hook into various behaviors
  await page.evaluateOnNewDocument(() => {
    // --- Right-click Blocking ---
    document.addEventListener('contextmenu', (e) => {
      if (e.defaultPrevented) {
        window.reportBehavior('rightClickBlocked');
      }
    });

    // --- Mouse Hover Trigger ---
    let hoverCooldown = false;
    document.addEventListener('mouseover', () => {
      if (!hoverCooldown) {
        window.reportBehavior('mouseHover');
        hoverCooldown = true;
        setTimeout(() => (hoverCooldown = false), 1000);
      }
    });

    // --- Pop-ups & Auto-downloads ---
    const originalWindowOpen = window.open;
    window.open = function () {
      window.reportBehavior('popup');
      return originalWindowOpen.apply(this, arguments);
    };

    // --- Form Submission without User Input ---
    document.addEventListener('submit', (e) => {
      window.reportBehavior('autoFormSubmit');
    });

    // --- Keystroke Monitoring ---
    const originalAddEventListener = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function (type, listener, options) {
      if (type === 'keydown' || type === 'keyup') {
        window.reportBehavior('keystrokeListener');
      }
      return originalAddEventListener.call(this, type, listener, options);
    };

    // --- Clipboard Access ---
    if (navigator.clipboard) {
      const originalClipboardRead = navigator.clipboard.readText;
      navigator.clipboard.readText = function () {
        window.reportBehavior('clipboardAccess');
        return originalClipboardRead.apply(this, arguments);
      };
    }

    // --- Obfuscated Links ---
    document.addEventListener('DOMContentLoaded', () => {
      const links = Array.from(document.querySelectorAll('a'));
      links.forEach((link) => {
        const href = link.getAttribute('href');
        if (href && /(%[0-9A-Fa-f]{2})/.test(href)) {
          window.reportBehavior('obfuscatedLink');
        }
      });
    });
  });

  // Navigate to the target URL
  try {
    await page.goto(targetUrl, { waitUntil: 'networkidle2', timeout: 500000 });
    await new Promise(resolve => setTimeout(resolve, 5000));
    // --- IFrame Usage ---
    const iframeCount = await page.evaluate(() => document.getElementsByTagName('iframe').length);
    eventData.iframeCount = iframeCount;
  } catch (error) {
    console.error('Error navigating to the target URL:', error);
  }

  // Record time spent on page (in milliseconds)
  eventData.timeSpent = Date.now() - startTime;
  await browser.close();

  // --- Risk Scoring ---
  let riskScore = 0;
  if (eventData.redirects > 2) riskScore += 2;
  else if (eventData.redirects === 2) riskScore++;

  if (eventData.mouseHoverCount > 10) riskScore += 2;
  else if (eventData.mouseHoverCount > 5) riskScore++;

  if (eventData.timeSpent < 2000) riskScore += 2;
  else if (eventData.timeSpent < 5000) riskScore++;

  if (eventData.rightClickBlocked) riskScore += 2;
  if (eventData.iframeCount > 3) riskScore += 2;
  else if (eventData.iframeCount > 1) riskScore++;

  if (eventData.popups > 1) riskScore += 2;
  else if (eventData.popups === 1) riskScore++;

  if (eventData.autoFormSubmissions > 0) riskScore += 3;
  if (eventData.keystrokeListeners > 0) riskScore += 3;
  if (eventData.clipboardAccess) riskScore += 3;
  if (eventData.obfuscatedLinks > 3) riskScore += 3;
  else if (eventData.obfuscatedLinks > 0) riskScore++;

  riskScore = (isNaN(riskScore) || riskScore == null) ? 0 : riskScore;
  console.log('Behavior Analysis Risk Score:', riskScore);

  // Log behavioral analysis event to Splunk, including client IP
  logToSplunk({
    event: "Behavior Analysis",
    targetUrl,
    client_ip: clientIp,
    eventData,
    riskScore,
    timestamp: new Date().toISOString()
  });

  const query = 'INSERT INTO behavioral_analysis (target_url, redirects, mouse_hover_count, time_spent, right_click_blocked, iframe_count, popups, auto_form_submissions, keystroke_listeners, clipboard_access, obfuscated_links, risk_score) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
  const values = [
    targetUrl,
    eventData.redirects,
    eventData.mouseHoverCount,
    eventData.timeSpent,
    eventData.rightClickBlocked ? 1 : 0,
    eventData.iframeCount,
    eventData.popups,
    eventData.autoFormSubmissions,
    eventData.keystrokeListeners,
    eventData.clipboardAccess ? 1 : 0,
    eventData.obfuscatedLinks,
    riskScore
  ];

  (await db).execute(query, values, (err, result) => {
    if (err) {
      console.error('Error inserting into database:', err);
    } else {
      console.log('Behavioral data inserted with ID:', result.insertId);
    }
  });

  return { eventData, riskScore };
}

export default analyzeUrlBehavior;
