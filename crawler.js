const axios = require("axios");
const cheerio = require("cheerio");

// ================= CONFIG =================

const CONFIG = {
  OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY,
  DISCORD_WEBHOOK: process.env.DISCORD_WEBHOOK,

  MODEL: "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",

  MAX_PAGES: 25,
  REQUEST_DELAY: 2000,

  RISK_THRESHOLD: 0.7
};

// ================= SEED URLS =================

const queue = [
  "https://news.ycombinator.com",
  "https://reddit.com/r/scams",
  "https://openphish.com",
  "https://phishtank.org",
  "https://urlhaus.abuse.ch"
];

const visited = new Set();

// ================= TRUSTED DOMAINS =================

const TRUSTED_DOMAINS = [
  "developer.mozilla.org",
  "wikipedia.org",
  "github.com",
  "stackoverflow.com"
];

// ================= UTIL =================

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function getDomain(url) {
  try {
    return new URL(url).hostname.replace("www.", "");
  } catch {
    return "";
  }
}

function isTrusted(url) {
  const domain = getDomain(url);

  return TRUSTED_DOMAINS.some(d => domain.includes(d));
}

function shouldSkipLink(link) {
  if (!link) return true;

  const badStarts = [
    "mailto:",
    "javascript:",
    "#",
    "tel:"
  ];

  return badStarts.some(x => link.startsWith(x));
}

function extractLinks($, baseUrl) {
  const links = [];

  $("a").each((_, el) => {
    let href = $(el).attr("href");

    if (shouldSkipLink(href)) return;

    try {
      const absolute = new URL(href, baseUrl).toString();

      // only http/https
      if (
        absolute.startsWith("http://") ||
        absolute.startsWith("https://")
      ) {
        links.push(absolute);
      }

    } catch {}
  });

  return links;
}

// ================= LOCAL HEURISTICS =================

function localAnalyze(url, text) {
  let risk = 0;
  const reasons = [];

  const lowerUrl = url.toLowerCase();
  const lowerText = text.toLowerCase();

  const suspiciousWords = [
    "verify",
    "login",
    "secure",
    "wallet",
    "crypto",
    "bank",
    "account"
  ];

  for (const word of suspiciousWords) {
    if (lowerUrl.includes(word)) {
      risk += 0.15;
      reasons.push(`suspicious url keyword: ${word}`);
    }
  }

  if (
    lowerText.includes("password") &&
    lowerText.includes("email")
  ) {
    risk += 0.25;
    reasons.push("possible credential collection");
  }

  if (
    lowerUrl.includes("g00gle") ||
    lowerUrl.includes("paypaI")
  ) {
    risk += 0.5;
    reasons.push("possible spoof domain");
  }

  return {
    risk,
    reasons
  };
}

// ================= OPENROUTER AI =================

async function analyzeWithAI(url, text) {
  try {

    const response = await axios.post(
      "https://openrouter.ai/api/v1/chat/completions",
      {
        model: CONFIG.MODEL,

        messages: [
          {
            role: "system",
            content:
              "You are a cybersecurity classifier. " +
              "Return ONLY valid JSON. " +
              "Format: " +
              '{"risk":0-1,"label":"benign|suspicious|phishing|malware","reasons":["reason"]}'
          },
          {
            role: "user",
            content:
              `Analyze this website.\n\n` +
              `URL:\n${url}\n\n` +
              `CONTENT:\n${text.slice(0, 2500)}`
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

    const output =
      response.data.choices[0].message.content;

    console.log("AI OUTPUT:");
    console.log(output);

    try {
      return JSON.parse(output);

    } catch {

      return {
        risk: 0,
        label: "parse_error",
        reasons: ["AI returned invalid JSON"]
      };
    }

  } catch (err) {

    console.log("AI ERROR:", err.message);

    return {
      risk: 0,
      label: "ai_error",
      reasons: [err.message]
    };
  }
}

// ================= DISCORD =================

async function sendDiscord(message) {
  try {

    await axios.post(
      CONFIG.DISCORD_WEBHOOK,
      {
        content: message
      }
    );

  } catch (err) {

    console.log("DISCORD ERROR:", err.message);
  }
}

// ================= CRAWLER =================

async function crawl() {

  console.log("OpenSpider started");

  let pages = 0;

  while (
    queue.length > 0 &&
    pages < CONFIG.MAX_PAGES
  ) {

    const url = queue.shift();

    if (visited.has(url)) continue;

    visited.add(url);

    console.log(`\nCrawling: ${url}`);

    try {

      const response = await axios.get(url, {
        timeout: 10000,
        headers: {
          "User-Agent":
            "OpenSpider/1.0 Security Research Bot"
        }
      });

      const html = response.data;

      const $ = cheerio.load(html);

      const text = $("body").text();

      // ================= LOCAL ANALYSIS =================

      const localResult =
        localAnalyze(url, text);

      console.log(
        "Local risk:",
        localResult.risk
      );

      let finalResult = {
        risk: localResult.risk,
        label: "benign",
        reasons: localResult.reasons
      };

      // ================= AI ANALYSIS =================

      const trusted = isTrusted(url);

      if (
        !trusted &&
        localResult.risk >= 0.2
      ) {

        console.log("Sending to AI...");

        finalResult =
          await analyzeWithAI(url, text);
      }

      console.log("FINAL RESULT:");
      console.log(finalResult);

      // ================= DISCORD LOG =================

      await sendDiscord(
        `🌐 OpenSpider Crawl\n` +
        `URL: ${url}\n` +
        `Label: ${finalResult.label}\n` +
        `Risk: ${finalResult.risk}`
      );

      // ================= THREAT ALERT =================

      if (
        finalResult.risk >=
        CONFIG.RISK_THRESHOLD
      ) {

        await sendDiscord(
          `@here ⚠️ SECURITY ALERT\n\n` +
          `URL: ${url}\n` +
          `Label: ${finalResult.label}\n` +
          `Risk: ${finalResult.risk}\n\n` +
          `Reasons:\n- ${
            (finalResult.reasons || []).join("\n- ")
          }`
        );
      }

      // ================= LINK EXTRACTION =================

      const links =
        extractLinks($, url);

      console.log(
        `Found ${links.length} links`
      );

      for (const link of links) {

        if (!visited.has(link)) {
          queue.push(link);
        }
      }

      pages++;

      await sleep(CONFIG.REQUEST_DELAY);

    } catch (err) {

      console.log(
        `FAILED: ${url}`
      );

      console.log(err.message);
    }
  }

  console.log("\nOpenSpider finished");
}

crawl();
