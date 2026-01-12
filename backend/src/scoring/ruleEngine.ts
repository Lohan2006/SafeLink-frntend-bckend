export function runRuleEngine(url: string) {
  let score = 10;
  const reasons: string[] = [];
  const breakdown: Record<string, number> = {};

  const parsed = new URL(url);
  const host = parsed.hostname;

  // Rule 1: IP-based URLs
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) {
    score -= 3;
    reasons.push('Uses raw IP address');
    breakdown.ipAddress = -3;
  }

  // Rule 2: Suspicious TLDs
  if (/\.(zip|xyz|top|tk)$/i.test(host)) {
    score -= 2;
    reasons.push('Suspicious top-level domain');
    breakdown.tld = -2;
  }

  // Rule 3: URL length
  if (url.length > 75) {
    score -= 1.5;
    reasons.push('Unusually long URL');
    breakdown.length = -1.5;
  }

  // Rule 4: Encoded characters
  if (/%[0-9A-Fa-f]{2}/.test(url)) {
    score -= 1;
    reasons.push('Contains encoded characters');
    breakdown.encoding = -1;
  }

  score = Math.max(0, Math.min(10, score));

  return { score, reasons, breakdown };
}
