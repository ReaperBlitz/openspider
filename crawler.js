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

  MAX_PAGES: 250,

  REQUEST_DELAY: 1200,

  MAX_DEPTH: 2,

  MAX_QUEUE_SIZE: 1000,

  MAX_VISITED_SIZE: 5000,

  MAX_RUNTIME_MS:
    1000 * 60 * 25,

  AI_MIN_RISK: 0.2,

  SUSPICIOUS_THRESHOLD: 0.3,

  ALERT_THRESHOLD: 0.7
};

// ================= STATE =================

const STATE_PATH =
  "./data/state.json";

let state = {
  visited: [],
  queue: [],
  stats: {
    totalCrawled: 0,
    totalAlerts: 0,
    totalAIRequests: 0,
    startedAt: new Date()
      .toISOString()
  }
};

if (
  fs.existsSync(STATE_PATH)
) {

  try {

    state = JSON.parse(
      fs.readFileSync(
        STATE_PATH,
        "utf8"
      )
    );

  } catch {

    console.log(
      "State corrupted, resetting..."
    );
  }
}

const visited =
  new Set(state.visited);

const queue = state.queue;

const queuedUrls =
  new Set(
    queue.map(q => q.url)
  );

const domainCounts = {};

const recentAlerts =
  new Set();

// ================= TRUSTED DOMAINS =================

const TRUSTED_DOMAINS = [
  "wikipedia.org",
  "developer.mozilla.org",
  "github.com",
  "stackoverflow.com",
  "mozilla.org",
  "microsoft.com",
  "google.com",
  "apple.com",
  "discord.com",
  "reddit.com",
  "amazon.com",
  "facebook.com",
  "instagram.com",
  "x.com",
  "twitter.com"
];

// ================= SUSPICIOUS TLDS =================

const suspiciousTlds = [
  ".xyz",
  ".top",
  ".click",
  ".gq",
  ".tk",
  ".ru",
  ".cn"
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
  "signin",
  "gift",
  "free",
  "claim",
  "reward",
  "unlock",
  "bonus",
  "authenticate",
  "recovery"
];

// ================= UTIL =================

function sleep(ms) {

  return new Promise(
    r => setTimeout(r, ms)
  );
}

function saveState() {

  const data = {
    visited:
      [...visited]
      .slice(
        -CONFIG.MAX_VISITED_SIZE
      ),

    queue:
      queue.slice(
        0,
        CONFIG.MAX_QUEUE_SIZE
      ),

    stats: state.stats
  };

  fs.writeFileSync(
    STATE_PATH,
    JSON.stringify(
      data,
      null,
      2
    )
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

  const domain =
    getDomain(url);

  return TRUSTED_DOMAINS.some(
    d => domain.includes(d)
  );
}

function isTrustedLoginPage(
  url,
  text
) {

  const domain =
    getDomain(url);

  if (
    !isTrusted(url)
  ) return false;

  const lower =
    text.toLowerCase();

  const authWords = [
    "sign in",
    "login",
    "password",
    "2fa",
    "authenticate"
  ];

  return authWords.some(
    w => lower.includes(w)
  );
}

function shouldSkip(url) {

  if (!url) return true;

  const lower =
    url.toLowerCase();

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
    ".mp3",
    ".exe",
    ".dmg",
    ".iso"
  ];

  if (
    lower.startsWith(
      "mailto:"
    ) ||
    lower.startsWith(
      "javascript:"
    ) ||
    lower.startsWith("#") ||
    lower.startsWith("tel:")
  ) {

    return true;
  }

  return blocked.some(
    ext =>
      lower.endsWith(ext)
  );
}

function calculatePriority(
  url
) {

  const lower =
    url.toLowerCase();

  let score = 0;

  for (
    const keyword of
    suspiciousKeywords
  ) {

    if (
      lower.includes(keyword)
    ) {

      score += 1;
    }
  }

  return score;
}

function enqueue(
  url,
  depth = 0
) {

  const normalized =
    normalizeUrl(url);

  if (!normalized)
    return;

  if (
    visited.has(normalized)
  ) return;

  if (
    queuedUrls.has(normalized)
  ) return;

  if (
    queue.length >=
    CONFIG.MAX_QUEUE_SIZE
  ) return;

  const domain =
    getDomain(normalized);

  domainCounts[domain] =
    (domainCounts[domain] || 0) + 1;

  // prevent flooding
  if (
    domainCounts[domain] > 100
  ) return;

  queue.push({
    url: normalized,
    priority:
      calculatePriority(
        normalized
      ),
    depth
  });

  queuedUrls.add(
    normalized
  );

  queue.sort(
    (a, b) =>
      b.priority -
      a.priority
  );
}

function shouldUseAI(
  localRisk
) {

  return (
    localRisk >=
    CONFIG.AI_MIN_RISK
  );
}

function isValidHtml(
  contentType
) {

  if (!contentType)
    return false;

  return contentType.includes(
    "text/html"
  );
}

function analyzeUrlRisk(
  url
) {

  const lower =
    url.toLowerCase();

  let risk = 0;

  const reasons = [];

  // IP URLs
  if (
    /https?:\/\/\d+\.\d+\.\d+\.\d+/.test(
      lower
    )
  ) {

    risk += 0.4;

    reasons.push(
      "ip address url"
    );
  }

  // suspicious tlds
  for (
    const tld of suspiciousTlds
  ) {

    if (
      lower.includes(tld)
    ) {

      risk += 0.25;

      reasons.push(
        `suspicious tld ${tld}`
      );
    }
  }

  // many subdomains
  const parts =
    getDomain(url)
    .split(".");

  if (
    parts.length >= 5
  ) {

    risk += 0.2;

    reasons.push(
      "many subdomains"
    );
  }

  return {
    risk,
    reasons
  };
}

// ================= LOCAL ANALYSIS =================

function localAnalyze(
  url,
  text,
  $
) {

  const lowerUrl =
    url.toLowerCase();

  const lowerText =
    text.toLowerCase();

  let risk = 0;

  const reasons = [];

  // trusted auth bypass
  if (
    isTrustedLoginPage(
      url,
      text
    )
  ) {

    return {
      risk: 0,
      reasons: [
        "trusted auth page"
      ]
    };
  }

  // keyword analysis
  for (
    const keyword of
    suspiciousKeywords
  ) {

    if (
      lowerUrl.includes(
        keyword
      )
    ) {

      risk += 0.08;

      reasons.push(
        `keyword ${keyword}`
      );
    }
  }

  // credential collection
  if (
    lowerText.includes(
      "password"
    ) &&
    lowerText.includes(
      "email"
    )
  ) {

    risk += 0.25;

    reasons.push(
      "credential collection"
    );
  }

  // verify account
  if (
    lowerText.includes(
      "verify account"
    )
  ) {

    risk += 0.2;

    reasons.push(
      "account verification"
    );
  }

  // crypto scams
  if (
    lowerText.includes(
      "wallet connect"
    )
  ) {

    risk += 0.25;

    reasons.push(
      "wallet connect"
    );
  }

  if (
    lowerText.includes(
      "seed phrase"
    )
  ) {

    risk += 0.5;

    reasons.push(
      "seed phrase"
    );
  }

  // nitro scam
  if (
    lowerText.includes(
      "free nitro"
    )
  ) {

    risk += 0.4;

    reasons.push(
      "discord nitro scam"
    );
  }

  // form analysis
  const forms =
    $("form");

  if (
    forms.length >= 1
  ) {

    risk += 0.1;

    reasons.push(
      "contains forms"
    );

    forms.each(
      (_, form) => {

        const action =
          $(form)
          .attr("action");

        if (
          action &&
          !action.includes(
            getDomain(url)
          )
        ) {

          risk += 0.2;

          reasons.push(
            "external form action"
          );
        }
      }
    );
  }

  // iframes
  if (
    $("iframe").length >= 3
  ) {

    risk += 0.15;

    reasons.push(
      "multiple iframes"
    );
  }

  // hidden inputs
  if (
    $('input[type="hidden"]')
      .length >= 5
  ) {

    risk += 0.1;

    reasons.push(
      "many hidden inputs"
    );
  }

  // url risk
  const urlRisk =
    analyzeUrlRisk(url);

  risk +=
    urlRisk.risk;

  reasons.push(
    ...urlRisk.reasons
  );

  return {
    risk:
      Math.min(risk, 1),

    reasons
  };
}

// ================= AI ANALYSIS =================

async function analyzeWithAI(
  url,
  text
) {

  try {

    state.stats.totalAIRequests++;

    const response =
      await axios.post(
        "https://openrouter.ai/api/v1/chat/completions",
        {
          model:
            CONFIG.MODEL,

          messages: [
            {
              role:
                "system",

              content:
                "You are a cybersecurity threat analysis AI. " +
                "Return ONLY valid JSON. " +
                'Format: {"risk":0-1,"label":"benign|suspicious|phishing|malware","reasons":["reason"]}'
            },

            {
              role:
                "user",

              content:
                `Analyze this webpage.\n\n` +
                `URL:\n${url}\n\n` +
                `CONTENT:\n${text.slice(0, 3000)}`
            }
          ]
        },

        {
          headers: {
            Authorization:
              `Bearer ${CONFIG.OPENROUTER_API_KEY}`,

            "Content-Type":
              "application/json"
          },

          timeout: 30000
        }
      );

    const output =
      response.data
      .choices[0]
      .message
      .content;

    try {

      return JSON.parse(
        output
      );

    } catch {

      return {
        risk: 0,
        label:
          "parse_error",
        reasons: [
          "invalid ai json"
        ]
      };
    }

  } catch (err) {

    return {
      risk: 0,
      label: "ai_error",
      reasons: [
        err.message
      ]
    };
  }
}

// ================= DISCORD =================

async function sendDiscord(
  message
) {

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

// ================= LINK EXTRACTION =================

function extractLinks(
  $,
  baseUrl
) {

  const found = [];

  $("a").each(
    (_, el) => {

      const href =
        $(el).attr("href");

      if (
        shouldSkip(href)
      ) return;

      try {

        const absolute =
          new URL(
            href,
            baseUrl
          ).toString();

        found.push(
          absolute
        );

      } catch {}
    }
  );

  return found;
}

// ================= MAIN =================

async function crawl() {

  console.log(
    "OpenSpider started"
  );

  const startTime =
    Date.now();

  // ================= SEEDS =================

  if (
    queue.length === 0
  ) {

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

    enqueue(
      "https://ahmia.fi"
    );

    enqueue(
      "https://urlhaus.abuse.ch"
    );
  }

  let pages = 0;

  while (
    queue.length &&
    pages <
      CONFIG.MAX_PAGES
  ) {

    // runtime protection
    if (
      Date.now() -
        startTime >
      CONFIG.MAX_RUNTIME_MS
    ) {

      console.log(
        "Runtime limit reached"
      );

      break;
    }

    const current =
      queue.shift();

    const url =
      current.url;

    const depth =
      current.depth;

    queuedUrls.delete(
      url
    );

    if (
      visited.has(url)
    ) continue;

    visited.add(url);

    console.log(
      `Crawling: ${url}`
    );

    try {

      const response =
        await axios.get(
          url,
          {
            timeout: 10000,

            maxRedirects: 5,

            validateStatus:
              status =>
                status < 400,

            headers: {
              "User-Agent":
                "OpenSpider/5.0 Security Research Bot"
            }
          }
        );

      const contentType =
        response.headers[
          "content-type"
        ];

      if (
        !isValidHtml(
          contentType
        )
      ) {

        continue;
      }

      const html =
        response.data;

      const $ =
        cheerio.load(
          html
        );

      const text =
        $("body")
        .text()
        .replace(
          /\s+/g,
          " "
        )
        .slice(
          0,
          10000
        );

      // ================= LOCAL ANALYSIS =================

      const local =
        localAnalyze(
          url,
          text,
          $
        );

      let result = {
        risk:
          local.risk,

        label:
          "benign",

        reasons:
          local.reasons
      };

      // ================= AI =================

      if (
        !isTrusted(url) &&
        shouldUseAI(
          local.risk
        )
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
          CONFIG.SUSPICIOUS_THRESHOLD &&
        !recentAlerts.has(url)
      ) {

        recentAlerts.add(
          url
        );

        await sendDiscord(
          `@here 🌐 Suspicious Website\n\n` +
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

      // ================= LINK DISCOVERY =================

      if (
        depth <
        CONFIG.MAX_DEPTH
      ) {

        const links =
          extractLinks(
            $,
            url
          );

        for (
          const link of
          links.slice(
            0,
            50
          )
        ) {

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
      state.stats
      .totalCrawled
    }\n` +

    `Total Alerts: ${
      state.stats
      .totalAlerts
    }\n` +

    `AI Requests: ${
      state.stats
      .totalAIRequests
    }\n` +

    `Visited URLs: ${
      visited.size
    }\n` +

    `Queue Remaining: ${
      queue.length
    }\n` +

    `Runtime: ${
      Math.floor(
        (
          Date.now() -
          startTime
        ) / 1000
      )
    } seconds`
  );

  console.log(
    "OpenSpider finished"
  );
}

crawl();
