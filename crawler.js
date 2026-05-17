const axios = require("axios");
const cheerio = require("cheerio");
const fs = require("fs");

// ================= CONFIG =================

const CONFIG = {
  OPENROUTER_API_KEY:
    process.env.OPENROUTER_API_KEY,

  DISCORD_WEBHOOK:
    process.env.DISCORD_WEBHOOK,

  MODEL:
    "nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free",

  MAX_PAGES: 100,

  REQUEST_DELAY: 1500,

  MAX_DEPTH: 2,

  SUSPICIOUS_THRESHOLD: 0.3,

  ALERT_THRESHOLD: 0.7
};

// ================= STATE =================

const STATE_PATH = "./data/state.json";

let state = {
  visited: [],
  queue: [],
  stats: {
    totalCrawled: 0,
    totalAlerts: 0
  }
};

if (fs.existsSync(STATE_PATH)) {

  state = JSON.parse(
    fs.readFileSync(STATE_PATH, "utf8")
  );
}

const visited = new Set(state.visited);

const queue = state.queue;

// ================= TRUSTED DOMAINS =================

const TRUSTED_DOMAINS = [
  "wikipedia.org",
  "developer.mozilla.org",
  "github.com",
  "stackoverflow.com"
];

// ================= KEYWORDS =================

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
  "signin"
];

// ================= UTIL =================

function sleep(ms) {
  return new Promise(r => setTimeout(r, ms));
}

function saveState() {

  const data = {
    visited: [...visited],
    queue,
    stats: state.stats
  };

  fs.writeFileSync(
    STATE_PATH,
    JSON.stringify(data, null, 2)
  );
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

    return new URL(url)
      .hostname
      .replace("www.", "");

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

  const blocked = [
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".pdf",
    ".zip",
    ".rar",
    ".mp4",
    ".mp3"
  ];

  if (
    lower.startsWith("mailto:") ||
    lower.startsWith("javascript:") ||
    lower.startsWith("#") ||
    lower.startsWith("tel:")
  ) {
    return true;
  }

  return blocked.some(ext =>
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

  const normalized =
    normalizeUrl(url);

  if (!normalized) return;

  if (visited.has(normalized)) return;

  queue.push({
    url: normalized,
    priority:
      calculatePriority(normalized),
    depth
  });

  queue.sort((a, b) =>
    b.priority - a.priority
  );
}

// ================= LOCAL ANALYSIS =================

function localAnalyze(url, text) {

  const lowerUrl =
    url.toLowerCase();

  const lowerText =
    text.toLowerCase();

  let risk = 0;

  const reasons = [];

  for (const keyword of suspiciousKeywords) {

    if (lowerUrl.includes(keyword)) {

      risk += 0.1;

      reasons.push(
        `keyword: ${keyword}`
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
    lowerText.includes("verify account")
  ) {

    risk += 0.2;

    reasons.push(
      "account verification language"
    );
  }

  return {
    risk: Math.min(risk, 1),
    reasons
  };
}

// ================= AI =================

async function analyzeWithAI(url, text) {

  try {

    const response =
      await axios.post(
        "https://openrouter.ai/api/v1/chat/completions",
        {
          model: CONFIG.MODEL,

          messages: [
            {
              role: "system",
              content:
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
      response.data
      .choices[0]
      .message
      .content;

    try {

      return JSON.parse(output);

    } catch {

      return {
        risk: 0,
        label: "parse_error",
        reasons: [
          "invalid ai json"
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

// ================= LINKS =================

function extractLinks($, baseUrl) {

  const found = [];

  $("a").each((_, el) => {

    let href =
      $(el).attr("href");

    if (shouldSkip(href)) return;

    try {

      const absolute =
        new URL(href, baseUrl)
        .toString();

      found.push(absolute);

    } catch {}
  });

  return found;
}

// ================= MAIN =================

async function crawl() {

  console.log(
    "OpenSpider started"
  );

  // initial seeds only if queue empty
  if (queue.length === 0) {

    enqueue(
      "https://news.ycombinator.com"
    );

    enqueue(
      "https://reddit.com/r/scams"
    );

    enqueue(
      "https://openphish.com"
    );

    enqueue(
      "https://phishtank.org"
    );
  }

  let pages = 0;

  while (
    queue.length &&
    pages < CONFIG.MAX_PAGES
  ) {

    const current =
      queue.shift();

    const url =
      current.url;

    const depth =
      current.depth;

    if (
      visited.has(url)
    ) continue;

    visited.add(url);

    console.log(
      `Crawling: ${url}`
    );

    try {

      const response =
        await axios.get(url, {
          timeout: 10000,

          headers: {
            "User-Agent":
              "OpenSpider/3.0"
          }
        });

      const html =
        response.data;

      const $ =
        cheerio.load(html);

      const text =
        $("body")
        .text()
        .slice(0, 10000);

      // ================= ANALYSIS =================

      const local =
        localAnalyze(url, text);

      let result = {
        risk: local.risk,
        label: "benign",
        reasons: local.reasons
      };

      // AI only if suspicious
      if (
        !isTrusted(url) &&
        local.risk >= 0.2
      ) {

        result =
          await analyzeWithAI(
            url,
            text
          );
      }

      // ================= DISCORD =================

      if (
        result.risk >=
        CONFIG.SUSPICIOUS_THRESHOLD
      ) {

        await sendDiscord(
          `🌐 Suspicious Website\n\n` +
          `URL: ${url}\n` +
          `Label: ${result.label}\n` +
          `Risk: ${result.risk}`
        );
      }

      if (
        result.risk >=
        CONFIG.ALERT_THRESHOLD
      ) {

        state.stats.totalAlerts++;

        await sendDiscord(
          `@here ⚠️ SECURITY ALERT\n\n` +
          `URL: ${url}\n` +
          `Label: ${result.label}\n` +
          `Risk: ${result.risk}\n\n` +
          `Reasons:\n- ${
            result.reasons.join(
              "\n- "
            )
          }`
        );
      }

      // ================= LINKS =================

      if (depth < CONFIG.MAX_DEPTH) {

        const links =
          extractLinks($, url);

        for (const link of links) {

          enqueue(
            link,
            depth + 1
          );
        }
      }

      // ================= SAVE =================

      state.stats.totalCrawled++;

      saveState();

      pages++;

      await sleep(
        CONFIG.REQUEST_DELAY
      );

    } catch (err) {

      console.log(
        "Failed:",
        url
      );

      console.log(
        err.message
      );
    }
  }

  // ================= SUMMARY =================

  await sendDiscord(
    `✅ OpenSpider Finished\n\n` +
    `Pages Crawled: ${pages}\n` +
    `Total Crawled: ${
      state.stats.totalCrawled
    }\n` +
    `Total Alerts: ${
      state.stats.totalAlerts
    }\n` +
    `Queue Remaining: ${
      queue.length
    }`
  );

  console.log(
    "OpenSpider finished"
  );
}

crawl();
