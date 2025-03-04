// splunkLogger.js
import { Logger } from 'splunk-logging';
import dotenv from 'dotenv';
dotenv.config();

const splunkConfig = {
  token: process.env.SPLUNK_HEC_TOKEN, // from .env
  url: process.env.SPLUNK_HEC_URL      // from .env
};

const splunkLogger = new Logger(splunkConfig);

/**
 * Logs an event to Splunk.
 * @param {Object} eventData - The event data to log.
 */
export function logToSplunk(eventData) {
  // Send the log data as a JSON string.
  splunkLogger.send({
    message: JSON.stringify(eventData)
  }, (err, resp, body) => {
    if (err) {
      console.error('Splunk logging error:', err);
    } else {
      console.log('Logged to Splunk:', body);
    }
  });
}
