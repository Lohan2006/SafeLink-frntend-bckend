const gsbRes = await fetch(
  `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${process.env.GOOGLE_SAFE_BROWSING_KEY}`,
  {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      client: {
        clientId: "safe-link",
        clientVersion: "1.0"
      },
      threatInfo: {
        threatTypes: [
          "MALWARE",
          "SOCIAL_ENGINEERING",
          "UNWANTED_SOFTWARE"
        ],
        platformTypes: ["ANY_PLATFORM"],
        threatEntryTypes: ["URL"],
        threatEntries: [{ url }]
      }
    })
  }
);

const gsbData = await gsbRes.json();

if (gsbData?.matches?.length > 0) {
  riskScore += 3;
  notes.push("Flagged by Google Safe Browsing");
}
