const axios = require("axios");
const cheerio = require("cheerio");

// ================= CONFIG =================

const CONFIG = {
  OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY,
  DISCORD_WEBHOOK: process.env.DISCORD_WEBHOOK,

  MODEL:
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",

  MAX_PAGES: 1000,
  REQUEST_DELAY: 1500,
  MAX_DEPTH: 2,

  SUSPICIOUS_THRESHOLD: 0.3,
  ALERT_THRESHOLD: 0.7,

  REQUEST_TIMEOUT: 10000
};

// ================= STARTING SEEDS =================

const seedUrls = [
  "https://news.ycombinator.com",
  "https://reddit.com/r/scams",
  "https://openphish.com",
  "https://phishtank.org",
  "https://urlhaus.abuse.ch"
];

// ================= STATE =================

const visited = new Set();

const queue = [];

let pagesCrawled = 0;
let suspiciousCount = 0;
let alertCount = 0;
let aiCalls = 0;
let failedPages = 0;

// ================= TRUSTED DOMAINS =================

const TRUSTED_DOMAINS = [
  "wikipedia.org",
  "developer.mozilla.org",
  "github.com",
  "stackoverflow.com"
];

// ================= SUSPICIOUS KEYWORDS =================

const suspiciousKeywords = [
  "login",
  "verify",
  "wallet",
  "crypto",
  "bank",
  "secure",
  "account",
  "support",
  "password",
  "recovery",
  "signin",
  "unlock"
];

// ================= UTIL =================

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function normalizeUrl(url) {
  try {
    const u = new URL(url);

    u.hash = "";

    return u.toString();

  } catch {
    return null;
  }
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

  return TRUSTED_DOMAINS.some(d =>
    domain.includes(d)
  );
}

function shouldSkip(url) {
  if (!url) return true;

  const lower = url.toLowerCase();

  const blockedExtensions = [
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".pdf",
    ".zip",
    ".rar",
    ".mp4",
    ".mp3"
  ];

  if (
    lower.startsWith("mailto:") ||
    lower.startsWith("javascript:") ||
    lower.startsWith("tel:")
  ) {
    return true;
  }

  return blockedExtensions.some(ext =>
    lower.endsWith(ext)
  );
}

function calculatePriority(url) {
  const lower = url.toLowerCase();

  let score = 0;

  for (const keyword of suspiciousKeywords) {
    if (lower.includes(keyword)) {
      score += 1;
    }
  }

  return score;
}

function enqueue(url, depth = 0) {
  const normalized = normalizeUrl(url);

  if (!normalized) return;

  if (visited.has(normalized)) return;

  queue.push({
    url: normalized,
    priority: calculatePriority(normalized),
    depth
  });

  queue.sort((a, b) =>
    b.priority - a.priority
  );
}

// ================= LOCAL ANALYSIS =================

function localAnalyze(url, text) {

  const lowerUrl = url.toLowerCase();
  const lowerText = text.toLowerCase();

  let risk = 0;
  const reasons = [];

  for (const keyword of suspiciousKeywords) {

    if (lowerUrl.includes(keyword)) {
      risk += 0.1;
      reasons.push(
        `suspicious keyword: ${keyword}`
      );
    }
  }

  if (
    lowerText.includes("password") &&
    lowerText.includes("email")
  ) {
    risk += 0.25;

    reasons.push(
      "possible credential collection"
    );
  }

  if (
    lowerText.includes("crypto") &&
    lowerText.includes("wallet")
  ) {
    risk += 0.2;

    reasons.push(
      "crypto wallet targeting"
    );
  }

  if (
    lowerText.includes("verify account")
  ) {
    risk += 0.2;

    reasons.push(
      "account verification language"
    );
  }

  if (
    lowerUrl.includes("g00gle") ||
    lowerUrl.includes("paypaI")
  ) {
    risk += 0.5;

    reasons.push(
      "possible spoof domain"
    );
  }

  return {
    risk: Math.min(risk, 1),
    reasons
  };
}

// ================= AI ANALYSIS =================

async function analyzeWithAI(url, text) {

  aiCalls++;

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
              'Format: {"risk":0-1,"label":"benign|suspicious|phishing|malware","reasons":["reason"]}'
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
          Authorization:
            `Bearer ${CONFIG.OPENROUTER_API_KEY}`,
          "Content-Type":
            "application/json"
        }
      }
    );

    const output =
      response.data.choices[0].message.content;

    try {
      return JSON.parse(output);

    } catch {

      return {
        risk: 0,
        label: "parse_error",
        reasons: [
          "AI returned invalid JSON"
        ]
      };
    }

  } catch (err) {

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

    console.log(
      "Discord error:",
      err.message
    );
  }
}

// ================= EXTRACT LINKS =================

function extractLinks($, baseUrl) {

  const found = [];

  $("a").each((_, el) => {

    let href = $(el).attr("href");

    if (shouldSkip(href)) return;

    try {

      const absolute =
        new URL(href, baseUrl).toString();

      found.push(absolute);

    } catch {}
  });

  return found;
}

// ================= MAIN CRAWLER =================

async function crawl() {

  console.log("OpenSpider started");

  for (const seed of seedUrls) {
    enqueue(seed, 0);
  }

  while (
    queue.length &&
    pagesCrawled < CONFIG.MAX_PAGES
  ) {

    const current = queue.shift();

    const url = current.url;
    const depth = current.depth;

    if (visited.has(url)) continue;

    visited.add(url);

    console.log(
      `Crawling: ${url}`
    );

    try {

      const response = await axios.get(url, {
        timeout: CONFIG.REQUEST_TIMEOUT,

        headers: {
          "User-Agent":
            "OpenSpider/2.0 Security Research Bot"
        }
      });

      const html = response.data;

      const $ = cheerio.load(html);

      const text =
        $("body").text().slice(0, 10000);

      // ================= LOCAL ANALYSIS =================

      const local =
        localAnalyze(url, text);

      let result = {
        risk: local.risk,
        label: "benign",
        reasons: local.reasons
      };

      // ================= AI ONLY IF NEEDED =================

      if (
        !isTrusted(url) &&
        local.risk >= 0.2
      ) {

        console.log(
          "AI analysis triggered"
        );

        result =
          await analyzeWithAI(url, text);
      }

      // ================= SUSPICIOUS REPORT =================

      if (
        result.risk >=
        CONFIG.SUSPICIOUS_THRESHOLD
      ) {

        suspiciousCount++;

        await sendDiscord(
          `🌐 Suspicious Website\n\n` +
          `URL: ${url}\n` +
          `Label: ${result.label}\n` +
          `Risk: ${result.risk}`
        );
      }

      // ================= HIGH ALERT =================

      if (
        result.risk >=
        CONFIG.ALERT_THRESHOLD
      ) {

        alertCount++;

        await sendDiscord(
          `@here ⚠️ SECURITY ALERT\n\n` +
          `URL: ${url}\n` +
          `Label: ${result.label}\n` +
          `Risk: ${result.risk}\n\n` +
          `Reasons:\n- ${
            (result.reasons || [])
              .join("\n- ")
          }`
        );
      }

      // ================= LINK EXTRACTION =================

      if (
        depth < CONFIG.MAX_DEPTH
      ) {

        const links =
          extractLinks($, url);

        for (const link of links) {
          enqueue(link, depth + 1);
        }
      }

      pagesCrawled++;

      await sleep(
        CONFIG.REQUEST_DELAY
      );

    } catch (err) {

      failedPages++;

      console.log(
        "Failed:",
        url
      );

      console.log(err.message);
    }
  }

  // ================= FINAL SUMMARY =================

  await sendDiscord(
    `✅ OpenSpider Finished\n\n` +
    `Pages Crawled: ${pagesCrawled}\n` +
    `Suspicious Pages: ${suspiciousCount}\n` +
    `High Alerts: ${alertCount}\n` +
    `AI Calls: ${aiCalls}\n` +
    `Failed Pages: ${failedPages}\n` +
    `Queue Remaining: ${queue.length}`
  );

  console.log("OpenSpider finished");
}

crawl();
