import express from "express";
import { runRuleBasedChecks } from "../rules/ruleEngine.js";
import { checkVirusTotal } from "../services/virusTotal.js";
import { checkGoogleSafeBrowsing } from "../services/googleSafeBrowsing.js";

const router = express.Router();

router.post("/check-url", async (req, res) => {
  const { url } = req.body;

  if (!url) {
    return res.status(400).json({ error: "URL required" });
  }

  try {
    // 1️⃣ Rule-based analysis
    const ruleResult = runRuleBasedChecks(url);

    // 2️⃣ API checks (only if suspicious)
    let apiScore = 0;
    let apiFlags = [];

    if (ruleResult.score >= 4) {
      const vt = await checkVirusTotal(url);
      const gsb = await checkGoogleSafeBrowsing(url);

      if (vt?.data) {
        apiScore += 2;
        apiFlags.push("VirusTotal flagged URL");
      }

      if (gsb?.matches) {
        apiScore += 3;
        apiFlags.push("Google Safe Browsing flagged URL");
      }
    }

    // 3️⃣ Final score
    const finalScore = Math.min(ruleResult.score + apiScore, 10);

    res.json({
      ruleBased: ruleResult,
      apiFlags,
      finalScore,
      finalVerdict:
        finalScore >= 7 ? "Phishing" :
        finalScore >= 4 ? "Suspicious" :
        "Safe"
    });

  } catch (err) {
    console.error("API ERROR:", err.message);
    res.status(500).json({
      finalVerdict: "unknown",
      note: "External API unavailable or quota exceeded"
    });
  }
});
