import fetch from "node-fetch";

export async function checkVirusTotal(url) {
  const res = await fetch("https://www.virustotal.com/api/v3/urls", {
    method: "POST",
    headers: {
      "x-apikey": process.env.VIRUSTOTAL_API_KEY,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: `url=${encodeURIComponent(url)}`,
  });

  return await res.json();
}
let vtRisk = 0;

if (vtData?.data?.id) {
  notes.push("VirusTotal scan submitted");
}
