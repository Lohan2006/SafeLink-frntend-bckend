import { Router } from 'express';
import { runScan } from '../services/scan.service.js';

const router = Router();

/**
 * POST /api/scan
 * Body: { url: string }
 */
router.post('/', async (req, res) => {
  const { url } = req.body;

  if (!url || typeof url !== 'string') {
    return res.status(400).json({
      error: 'Invalid request. URL is required.'
    });
  }

  try {
    const result = await runScan(url);
    res.json(result);
  } catch (err) {
    console.error('Scan failed:', err);
    res.status(500).json({
      error: 'Scan failed. Please try again later.'
    });
  }
});

export default router;
