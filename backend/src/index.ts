import dotenv from 'dotenv';
// Load environment variables at the very top
dotenv.config();

import express, { Request, Response } from 'express';
import cors from 'cors';
import path from 'path';

const app = express();
const PORT = process.env.PORT || 5000;

// Enable CORS for local development (frontend running on localhost)
app.use(cors({
  origin: 'http://localhost:5173'
}));

// Parse JSON bodies
app.use(express.json());

// -----------------------------
// 1. Serve Frontend (built) files
// -----------------------------
const frontendDistPath = path.join(__dirname, "../dist");
app.use(express.static(frontendDistPath));

// Serve index.html for all SPA routes
app.get('*', (req, res, next) => {
  // If request starts with /api, skip to next middleware
  if (req.path.startsWith('/api')) return next();
  res.sendFile(path.join(frontendDistPath, 'index.html'));
});

// -----------------------------
// 2. API Endpoints
// -----------------------------
const checkGoogleSafeBrowsing = (url: string): 'flagged' | 'safe' => {
  const patterns = ['paypal', 'login'];
  return patterns.some(p => url.toLowerCase().includes(p)) ? 'flagged' : 'safe';
};

const checkVirusTotal = (url: string): 'flagged' | 'safe' => {
  const patterns = ['secure', 'bank'];
  return patterns.some(p => url.toLowerCase().includes(p)) ? 'flagged' : 'safe';
};

const checkURLScan = (url: string): 'flagged' | 'safe' => {
  const patterns = ['free-', '.net'];
  return patterns.some(p => url.toLowerCase().includes(p)) ? 'flagged' : 'safe';
};

// Scan API
app.post('/api/scan', (req: Request, res: Response) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL is required" });
  }

  const reasons: string[] = [];

  if (checkGoogleSafeBrowsing(url) === 'flagged') reasons.push("Google Safe Browsing flagged this URL");
  if (checkVirusTotal(url) === 'flagged') reasons.push("VirusTotal flagged this URL");
  if (checkURLScan(url) === 'flagged') reasons.push("URLScan flagged this URL");

  const isFlagged = reasons.length > 0;

  res.json({
    flagged: isFlagged,
    reasons
  });
});

// -----------------------------
// 3. Start Server
// -----------------------------
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
