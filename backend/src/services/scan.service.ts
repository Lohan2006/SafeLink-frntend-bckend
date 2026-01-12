import { normalizeUrl, isValidUrl } from '../utils/validators.js';
import { runRuleEngine } from '../scoring/ruleEngine.js';
import type { ScanResult, RiskTier } from '../types/scan.js';

export async function runScan(inputUrl: string): Promise<ScanResult> {
  const normalizedUrl = normalizeUrl(inputUrl);

  if (!isValidUrl(normalizedUrl)) {
    throw new Error('Invalid URL');
  }

  const { score, reasons, breakdown } = runRuleEngine(normalizedUrl);

  let tier: RiskTier = 'Safe';
  if (score <= 3) tier = 'High Risk';
  else if (score <= 6) tier = 'Be Careful';

  return {
    url: normalizedUrl,
    score,
    tier,
    confidence: score / 10,
    reasons,
    breakdown,
    timestamp: new Date().toISOString()
  };
}
