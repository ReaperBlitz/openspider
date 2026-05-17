const axios = require("axios");
const cheerio = require("cheerio");

// ================= CONFIG =================
const CONFIG = {
  OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY,
  MODEL: "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",
  DISCORD_WEBHOOK: process.env.DISCORD_WEBHOOK,
  MAX_PAGES: 30,
  REQUEST_DELAY: 2000
};

// ================= STATE =================
const visited = new Set();
const queue = [
  "https://example.com",
  "https://developer.mozilla.org"
];

// ================= UTIL =================
const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function extractLinks($, baseUrl) {
  const links = [];

  $("a").each((_, el) => {
    let href = $(el).attr("href");
    if (!href) return;

    try {
      const url = new URL(href, baseUrl).toString();
      links.push(url);
    } catch {}
  });

  return links;
}

// ================= AI ANALYSIS =================
async function analyzeWithAI(url, text) {
  try {
    const res = await axios.post(
      "https://openrouter.ai/api/v1/chat/completions",
      {
        model: CONFIG.MODEL,
        messages: [
          {
            role: "system",
            content:
              "You are a cybersecurity classifier. Return ONLY JSON: {risk:0-1, label, reasons:[...]}"
          },
          {
            role: "user",
            content: `Analyze this website:\nURL: ${url}\nCONTENT:\n${text.slice(0, 3000)}`
          }
        ]
      },
      {
        headers: {
          Authorization: `Bearer ${CONFIG.OPENROUTER_API_KEY}`,
          "Content-Type": "application/json"
        }
      }
    );

    const output = res.data.choices[0].message.content;

    return JSON.parse(output);
  } catch (e) {
    return { risk: 0, label: "UNKNOWN", reasons: ["AI error"] };
  }
}

// ================= DISCORD =================
async function sendDiscord(url, result) {
  try {
    await axios.post(CONFIG.DISCORD_WEBHOOK, {
      content:
        `@here ⚠️ **Security Report**\n` +
        `URL: ${url}\n` +
        `Risk: ${result.risk}\n` +
        `Label: ${result.label}\n` +
        `Reasons: ${(result.reasons || []).join(", ")}`
    });
  } catch (e) {
    console.log("Discord error");
  }
}

// ================= CRAWLER =================
async function crawl() {
  let pages = 0;

  while (queue.length && pages < CONFIG.MAX_PAGES) {
    const url = queue.shift();

    if (visited.has(url)) continue;
    visited.add(url);

    try {
      console.log("Crawling:", url);

      const res = await axios.get(url);
      const $ = cheerio.load(res.data);

      const text = $("body").text();

      // AI analysis
      const result = await analyzeWithAI(url, text);

      console.log("Result:", result);

      if (result.risk >= 0.7) {
        await sendDiscord(url, result);
      }

      // extract links
      const links = extractLinks($, url);
      for (const link of links) {
        if (!visited.has(link)) queue.push(link);
      }

      pages++;
      await sleep(CONFIG.REQUEST_DELAY);

    } catch (err) {
      console.log("Failed:", url);
    }
  }

  console.log("Crawl finished");
}

crawl();
