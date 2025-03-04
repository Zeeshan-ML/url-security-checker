// // routes/behaviorRoute.js
// import express from 'express';
// import { URL } from 'url';
// import analyzeUrlBehavior from '../behavioralAnalysis.js';

// const router = express.Router();

// // Helper function to validate URL format
// const isValidURL = (str) => {
//   try {
//     new URL(str);
//     return true;
//   } catch (err) {
//     return false;
//   }
// };

// router.post('/analyze-behavior', async (req, res) => {
//   const { url } = req.body;
  
//   if (!url || !isValidURL(url)) {
//     return res.status(400).json({ error: 'Invalid URL format' });
//   }

//   try {
//     const analysis = await analyzeUrlBehavior(url);
//     res.json(analysis);
//   } catch (error) {
//     console.error("Behavior analysis error:", error);
//     res.status(500).json({ error: 'Error analyzing URL behavior.' });
//   }
// });

// export default router;
import express from 'express';
import { URL } from 'url';
import analyzeUrlBehavior from '../behavioralAnalysis.js';

const router = express.Router();

// Helper function to validate URL format
const isValidURL = (str) => {
  try {
    new URL(str);
    return true;
  } catch (err) {
    return false;
  }
};

router.post('/analyze-behavior', async (req, res) => {
  const { url } = req.body;
  
  if (!url || !isValidURL(url)) {
    return res.status(400).json({ error: 'Invalid URL format' });
  }
  
  // Capture the client's IP address
  let clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  if (clientIp === '::1') {
    clientIp = '127.0.0.1';
  }
  
  try {
    // Pass the clientIp to the behavioral analysis function
    const analysis = await analyzeUrlBehavior(url, clientIp);
    res.json(analysis);
  } catch (error) {
    console.error("Behavior analysis error:", error);
    res.status(500).json({ error: 'Error analyzing URL behavior.' });
  }
});

export default router;
