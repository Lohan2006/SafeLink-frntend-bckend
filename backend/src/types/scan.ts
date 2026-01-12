export type RiskTier = 'Safe' | 'Be Careful' | 'High Risk';

export interface ScanResult {
  url: string;
  score: number;              // 0–10
  tier: RiskTier;
  confidence: number;         // 0–1
  reasons: string[];
  breakdown: Record<string, number>;
  timestamp: string;
}
