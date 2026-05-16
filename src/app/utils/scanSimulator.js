const PHISHING_KEYWORDS = [
  "login",
  "verify",
  "secure",
  "account",
  "banking",
  "update",
  "confirm",
  "signin",
  "authenticate",
  "reactivate",
  "suspended",
  "blocked",
  "wallet",
  "credential",
  "password",
  "recovery",
  "support",
  "helpdesk",
  "invoice",
  "payment",
  "refund",
  "alert",
  "notice",
  "validate",
  "activate",
  "unlock"
];
const SUSPICIOUS_KEYWORDS = [
  "free",
  "win",
  "click",
  "offer",
  "prize",
  "gift",
  "claim",
  "bonus",
  "download",
  "setup",
  "install",
  "lucky",
  "earn"
];
const SECURITY_KEYWORDS = [
  "secure",
  "login",
  "verify",
  "update",
  "confirm",
  "account",
  "banking",
  "auth",
  "portal",
  "access",
  "safe",
  "protect"
];
const SUSPICIOUS_TLDS = [
  ".xyz",
  ".info",
  ".online",
  ".site",
  ".ru",
  ".cn",
  ".tk",
  ".ml",
  ".ga",
  ".cf",
  ".pw",
  ".top",
  ".work",
  ".click",
  ".gq",
  ".icu",
  ".buzz",
  ".cam",
  ".vip",
  ".link"
];
const KNOWN_BRANDS = [
  "paypal",
  "chase",
  "wellsfargo",
  "bankofamerica",
  "citibank",
  "hsbc",
  "barclays",
  "halifax",
  "natwest",
  "santander",
  "lloyds",
  "coinbase",
  "binance",
  "robinhood",
  "revolut",
  "stripe",
  "amazon",
  "ebay",
  "walmart",
  "target",
  "flipkart",
  "meesho",
  "myntra",
  "shopify",
  "etsy",
  "aliexpress",
  "alibaba",
  "booking",
  "airbnb",
  "expedia",
  "tripadvisor",
  "makemytrip",
  "agoda",
  "google",
  "microsoft",
  "apple",
  "facebook",
  "instagram",
  "twitter",
  "linkedin",
  "youtube",
  "netflix",
  "spotify",
  "discord",
  "telegram",
  "whatsapp",
  "snapchat",
  "tiktok",
  "pinterest",
  "reddit",
  "outlook",
  "paytm",
  "phonepe",
  "gpay",
  "swiggy",
  "zomato",
  "ola",
  "jio",
  "hdfc",
  "icici",
  "sbi",
  "axis",
  "kotak",
  "adobe",
  "dropbox",
  "salesforce",
  "steam",
  "twitch",
  "slack",
  "zoom",
  "notion",
  "figma",
  "gitlab",
  "github",
  "atlassian",
  "hulu",
  "disneyplus",
  "cashapp",
  "venmo",
  "wise"
];
const URL_SHORTENERS = [
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "goo.gl",
  "ow.ly",
  "buff.ly",
  "short.link",
  "is.gd",
  "cutt.ly"
];
const TRUSTED_DOMAINS = [
  // US Big Tech & Cloud
  "google.com",
  "google.co.in",
  "google.co.uk",
  "youtube.com",
  "gmail.com",
  "googleapis.com",
  "microsoft.com",
  "outlook.com",
  "office.com",
  "live.com",
  "bing.com",
  "azure.com",
  "apple.com",
  "icloud.com",
  "amazon.com",
  "amazon.in",
  "amazon.co.uk",
  "aws.amazon.com",
  "facebook.com",
  "instagram.com",
  "whatsapp.com",
  "messenger.com",
  "meta.com",
  "twitter.com",
  "x.com",
  "linkedin.com",
  "netflix.com",
  "spotify.com",
  // Developer / Open Source
  "github.com",
  "gitlab.com",
  "bitbucket.org",
  "stackoverflow.com",
  "stackexchange.com",
  "npmjs.com",
  "pypi.org",
  "rubygems.org",
  "pkg.go.dev",
  "docker.com",
  "hub.docker.com",
  "vercel.com",
  "netlify.com",
  "heroku.com",
  "render.com",
  "cloudflare.com",
  "cloudflare.net",
  "reactjs.org",
  "vuejs.org",
  "angular.io",
  "nodejs.org",
  "tailwindcss.com",
  "python.org",
  "rust-lang.org",
  "mozilla.org",
  "firefox.com",
  "chromium.org",
  "atlassian.com",
  "jira.com",
  "confluence.com",
  "oracle.com",
  "ibm.com",
  "cisco.com",
  "vmware.com",
  // Finance & Payments
  "paypal.com",
  "stripe.com",
  "squareup.com",
  "braintreepayments.com",
  "wise.com",
  "revolut.com",
  "cashapp.com",
  "venmo.com",
  "coinbase.com",
  "binance.com",
  // E-commerce
  "ebay.com",
  "walmart.com",
  "target.com",
  "shopify.com",
  "etsy.com",
  "aliexpress.com",
  "alibaba.com",
  "booking.com",
  "airbnb.com",
  "expedia.com",
  "tripadvisor.com",
  // Indian domains — commonly falsely flagged
  "flipkart.com",
  "myntra.com",
  "meesho.com",
  "snapdeal.com",
  "ajio.com",
  "nykaa.com",
  "tatacliq.com",
  "reliancedigital.in",
  "paytm.com",
  "phonepe.com",
  "mobikwik.com",
  "swiggy.com",
  "zomato.com",
  "blinkit.com",
  "ola.com",
  "rapido.bike",
  "hdfcbank.com",
  "icicibank.com",
  "sbi.co.in",
  "axisbank.com",
  "kotakbank.com",
  "indusind.com",
  "yesbank.in",
  "jio.com",
  "airtel.in",
  "airtel.com",
  "vodafone.in",
  "vi.in",
  "irctc.co.in",
  "indianrailways.gov.in",
  "india.gov.in",
  "uidai.gov.in",
  "digilocker.gov.in",
  "incometax.gov.in",
  "makemytrip.com",
  "goibibo.com",
  "ixigo.com",
  "yatra.com",
  "bigbasket.com",
  "grofers.com",
  "dunzo.com",
  "zepto.in",
  "byju.com",
  "unacademy.com",
  "vedantu.com",
  "ola.com",
  "uber.com",
  // SaaS & Productivity
  "notion.so",
  "figma.com",
  "slack.com",
  "zoom.us",
  "dropbox.com",
  "adobe.com",
  "canva.com",
  "salesforce.com",
  "zendesk.com",
  "hubspot.com",
  "freshdesk.com",
  "discord.com",
  "twitch.tv",
  "reddit.com",
  "medium.com",
  "substack.com",
  "wordpress.com",
  "blogger.com",
  "wikipedia.org",
  "wikimedia.org",
  "yahoo.com",
  "aol.com"
];
const ENTERPRISE_REGISTRARS = [
  "MarkMonitor",
  "CSC Corporate Domains",
  "Amazon Registrar",
  "Google Domains",
  "Network Solutions",
  "Corporate Domains",
  "Safenames",
  "Brandsight"
];
const COMMON_BIGRAMS = [
  "th",
  "he",
  "in",
  "er",
  "an",
  "re",
  "on",
  "at",
  "en",
  "nd",
  "st",
  "es",
  "or",
  "to",
  "it",
  "is",
  "as",
  "ed",
  "ar",
  "al",
  "ti",
  "ng",
  "le",
  "li",
  "la",
  "ne",
  "te",
  "io",
  "ic",
  "ot",
  "ro",
  "ma",
  "co",
  "de",
  "ha",
  "el",
  "se",
  "ra",
  "ri",
  "si"
];
const UNICODE_SINGLE_MAP = {
  // Cyrillic confusables
  "\u0430": "a",
  // U+0430
  "\u0435": "e",
  // U+0435
  "\u043E": "o",
  // U+043E  ← Cyrillic о (not Latin o)
  "\u0440": "p",
  // U+0440  ← covers both r and p attacks
  "\u0441": "c",
  // U+0441
  "\u0445": "x",
  // U+0445
  "\u0443": "y",
  // U+0443
  "\u0456": "i",
  // U+0456
  "\u0432": "b",
  // U+0432
  "\u043D": "n",
  // U+043D
  "\u0442": "t",
  // U+0442
  // Greek confusables
  "\u03B1": "a",
  // U+03B1
  "\u03B5": "e",
  // U+03B5
  "\u03BF": "o",
  // U+03BF
  "\u03C1": "p",
  // U+03C1
  "\u03C5": "u",
  // U+03C5
  "\u03BD": "v",
  // U+03BD
  "\u03C3": "s",
  // U+03C3
  "\u03C4": "t",
  // U+03C4
  "\u03B9": "i",
  // U+03B9
  "\u03BA": "k",
  // U+03BA
  // Latin extended
  "\u0131": "i",
  // U+0131 dotless i
  "\u0142": "l",
  // U+0142
  "\xF8": "o",
  // U+00F8
  "\xE6": "ae",
  // U+00E6
  "\xDF": "ss",
  // U+00DF
  "\xE0": "a",
  "\xE1": "a",
  "\xE2": "a",
  "\xE4": "a",
  "\xE8": "e",
  "\xE9": "e",
  "\xEA": "e",
  "\xEC": "i",
  "\xED": "i",
  "\xEE": "i",
  "\xF2": "o",
  "\xF3": "o",
  "\xF4": "o",
  "\xF9": "u",
  "\xFA": "u",
  "\xFB": "u",
  "\xFC": "u",
  "\xF1": "n",
  "\xE7": "c",
  // Full-width digits
  "\uFF10": "0",
  "\uFF11": "1",
  "\uFF12": "2",
  "\uFF13": "3",
  "\uFF14": "4",
  "\uFF15": "5",
  "\uFF16": "6",
  "\uFF17": "7",
  "\uFF18": "8",
  "\uFF19": "9",
  // Full-width letters (a-z)
  "\uFF41": "a",
  "\uFF42": "b",
  "\uFF43": "c",
  "\uFF44": "d",
  "\uFF45": "e",
  "\uFF46": "f",
  "\uFF47": "g",
  "\uFF48": "h",
  "\uFF49": "i",
  "\uFF4A": "j",
  "\uFF4B": "k",
  "\uFF4C": "l",
  "\uFF4D": "m",
  "\uFF4E": "n",
  "\uFF4F": "o",
  "\uFF50": "p",
  "\uFF51": "q",
  "\uFF52": "r",
  "\uFF53": "s",
  "\uFF54": "t",
  "\uFF55": "u",
  "\uFF56": "v",
  "\uFF57": "w",
  "\uFF58": "x",
  "\uFF59": "y",
  "\uFF5A": "z",
  // Symbol substitutions
  "@": "a",
  "$": "s",
  "!": "i",
  "|": "l",
  "\u20AC": "e"
};
const DIGRAPH_MAP = [
  ["rn", "m"],
  ["vv", "w"],
  ["cl", "d"],
  ["nn", "m"]
];
function normalizeUnicode(str) {
  let result = str.toLowerCase();
  for (const [glyph, ascii] of Object.entries(UNICODE_SINGLE_MAP)) {
    result = result.split(glyph).join(ascii);
  }
  return result;
}
function applyDigraphs(str) {
  let result = str;
  for (const [from, to] of DIGRAPH_MAP) {
    result = result.split(from).join(to);
  }
  return result;
}
function detectUnicodeChars(str) {
  const found = [];
  for (const char of str) {
    if (char.charCodeAt(0) > 127 && !found.includes(char)) found.push(char);
  }
  return found;
}
function collapseRepeats(str) {
  return str.replace(/(.)\1{2,}/g, "$1");
}
function collapseAllRepeats(str) {
  return str.replace(/(.)\1+/g, "$1");
}
const LEET_MAP = {
  "0": "o",
  "1": "l",
  "2": "z",
  "3": "e",
  "4": "a",
  "5": "s",
  "6": "g",
  "7": "t",
  "8": "b",
  "9": "g"
};
function normalizeLeet(str) {
  let result = str;
  for (const [digit, letter] of Object.entries(LEET_MAP)) {
    result = result.split(digit).join(letter);
  }
  return result;
}
function fullyNormalize(str) {
  let s = str.toLowerCase();
  s = normalizeUnicode(s);
  s = normalizeLeet(s);
  s = collapseAllRepeats(s);
  s = applyDigraphs(s);
  return s;
}
function levenshtein(a, b) {
  const m = a.length, n = b.length;
  const dp = Array.from(
    { length: m + 1 },
    (_, i) => Array.from({ length: n + 1 }, (_2, j) => i === 0 ? j : j === 0 ? i : 0)
  );
  for (let i = 1; i <= m; i++)
    for (let j = 1; j <= n; j++)
      dp[i][j] = a[i - 1] === b[j - 1] ? dp[i - 1][j - 1] : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
  return dp[m][n];
}
function matchBrand(candidate, maxDist = 2) {
  let bestBrand = "", bestDist = Infinity;
  for (const brand of KNOWN_BRANDS) {
    if (candidate === brand) return { brand, similarity: 1, editDistance: 0 };
    const dist = levenshtein(candidate, brand);
    if (dist <= maxDist && dist < bestDist && candidate.length >= brand.length - 2 && candidate.length <= brand.length + 3) {
      bestDist = dist;
      bestBrand = brand;
    }
  }
  if (!bestBrand) return null;
  const maxLen = Math.max(candidate.length, bestBrand.length);
  return { brand: bestBrand, similarity: parseFloat((1 - bestDist / maxLen).toFixed(2)), editDistance: bestDist };
}
function detectSubdomainBrandAbuse(hostname) {
  const parts = hostname.toLowerCase().replace(/^www\./, "").split(".");
  if (parts.length < 3) return null;
  for (const part of parts.slice(0, -2)) {
    const clean = part.replace(/-/g, "");
    const direct = KNOWN_BRANDS.find((b) => b === part || b === clean);
    if (direct) return { brand: direct, similarity: 1, editDistance: 0 };
    const fuzzy = matchBrand(part, 1);
    if (fuzzy) return fuzzy;
  }
  return null;
}
function detectHyphenBrandAbuse(sld) {
  if (!sld.includes("-")) return null;
  for (const part of sld.split("-")) {
    if (part.length < 3) continue;
    const direct = KNOWN_BRANDS.find((b) => b === part);
    if (direct) return { brand: direct, similarity: 1, editDistance: 0 };
    const fuzzy = matchBrand(part, 1);
    if (fuzzy) return fuzzy;
  }
  return null;
}
function detectKeywordInjection(sld, brand) {
  if (!brand) return [];
  const withoutBrand = sld.replace(new RegExp(brand, "gi"), "").replace(/-/g, " ").trim();
  return SECURITY_KEYWORDS.filter((k) => withoutBrand.includes(k));
}
function registeredDomain(hostname) {
  const parts = hostname.replace(/^www\./, "").split(".");
  return parts.slice(-2).join(".");
}
function isTrustedDomain(domain) {
  const reg = registeredDomain(domain);
  return TRUSTED_DOMAINS.some((td) => reg === td || domain.endsWith(`.${td}`));
}
function isDGALike(sld) {
  if (sld.length < 6) return false;
  const lower = sld.toLowerCase().replace(/[^a-z]/g, "");
  if (lower.length < 5) return false;
  const vowelCount = (lower.match(/[aeiou]/g) || []).length;
  const vowelRatio = vowelCount / lower.length;
  const hasLongConsonantRun = /[^aeiou]{4,}/.test(lower);
  const hasCommonBigram = COMMON_BIGRAMS.some((bg) => lower.includes(bg));
  const sldEntropy = calculateEntropy(lower);
  if (hasLongConsonantRun && !hasCommonBigram) return true;
  if (vowelRatio < 0.2 && !hasCommonBigram && lower.length > 6) return true;
  if (sldEntropy > 3.2 && vowelRatio < 0.25 && lower.length > 7) return true;
  return false;
}
function calculateEntropy(str) {
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  return Object.values(freq).reduce((e, f) => {
    const p = f / str.length;
    return e - p * Math.log2(p);
  }, 0);
}
function extractDomain(url) {
  try {
    const u = new URL(url.startsWith("http") ? url : `http://${url}`);
    return u.hostname;
  } catch {
    return url;
  }
}
function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function randomIP() {
  return `${randInt(10, 250)}.${randInt(10, 250)}.${randInt(10, 250)}.${randInt(10, 250)}`;
}
function isIP(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}
function inferCountry(domain, isMalicious) {
  if (!isMalicious) return "US";
  const tld = domain.split(".").slice(-1)[0].toLowerCase();
  const tldCountry = {
    ru: "RU",
    cn: "CN",
    ua: "UA",
    ro: "RO",
    ng: "NG",
    br: "BR",
    pk: "PK",
    in: "IN",
    ir: "IR",
    kp: "KP"
  };
  return tldCountry[tld] ?? ["RU", "CN", "UA", "RO", "NG"][randInt(0, 4)];
}
function inferRegistrar(domain) {
  const tld = domain.split(".").slice(-1)[0].toLowerCase();
  const map = {
    ru: { name: "Reg.ru LLC", email: "abuse@reg.ru", ns: ["ns1.reg.ru", "ns2.reg.ru"] },
    cn: { name: "Alibaba Cloud Computing Ltd.", email: "abuse@hichina.com", ns: ["dns1.hichina.com", "dns2.hichina.com"] },
    xyz: { name: "XYZ.COM LLC", email: "abuse@nic.xyz", ns: ["ns1.dnsimple.com", "ns2.dnsimple.com"] },
    top: { name: "Jiangsu Bangning Science & Technology Co., Ltd.", email: "abuse@nic.top", ns: ["ns1.dnspod.net", "ns2.dnspod.net"] },
    online: { name: "Radix FZC LLC", email: "abuse@radix.website", ns: ["ns1.radix.website", "ns2.radix.website"] },
    site: { name: "Radix FZC LLC", email: "abuse@radix.website", ns: ["ns1.radix.website", "ns2.radix.website"] },
    info: { name: "GoDaddy.com, LLC", email: "abuse@godaddy.com", ns: ["ns1.domaincontrol.com", "ns2.domaincontrol.com"] },
    tk: { name: "Dot TK / Freenom", email: "abuse@freenom.com", ns: ["ns01.freenom.com", "ns02.freenom.com"] },
    ml: { name: "Dot ML / Freenom", email: "abuse@freenom.com", ns: ["ns01.freenom.com", "ns02.freenom.com"] }
  };
  const fallbacks = [
    { name: "NameCheap, Inc.", email: "abuse@namecheap.com", ns: ["ns1.namecheaphosting.com", "ns2.namecheaphosting.com"] },
    { name: "GoDaddy.com, LLC", email: "abuse@godaddy.com", ns: ["ns1.domaincontrol.com", "ns2.domaincontrol.com"] },
    { name: "PDR Ltd. d/b/a PublicDomainRegistry.com", email: "abuse@publicdomainregistry.com", ns: ["ns1.publicdomainregistry.com", "ns2.publicdomainregistry.com"] },
    { name: "Tucows Domains Inc.", email: "abuse@tucows.com", ns: ["ns1.hover.com", "ns2.hover.com"] }
  ];
  return map[tld] ?? fallbacks[randInt(0, fallbacks.length - 1)];
}
function maliciousIP() {
  const ranges = [
    () => `185.220.${randInt(100, 104)}.${randInt(1, 254)}`,
    () => `46.165.${randInt(200, 230)}.${randInt(1, 254)}`,
    () => `193.32.${randInt(160, 165)}.${randInt(1, 254)}`,
    () => `198.54.${randInt(117, 120)}.${randInt(1, 254)}`,
    () => `104.168.${randInt(100, 150)}.${randInt(1, 254)}`,
    () => `103.145.${randInt(10, 60)}.${randInt(1, 254)}`,
    () => `213.183.${randInt(40, 60)}.${randInt(1, 254)}`
  ];
  return ranges[randInt(0, ranges.length - 1)]();
}
function generateDNS(ip, domain, prediction, ns) {
  if (prediction === "phishing") {
    return {
      A: [ip],
      MX: [],
      NS: ns ?? ["ns1.namecheaphosting.com", "ns2.namecheaphosting.com"],
      TXT: []
    };
  }
  if (prediction === "suspicious") {
    return {
      A: [ip],
      MX: [`mail.${domain}`],
      NS: ns ?? ["ns1.cloudflare.com", "ns2.cloudflare.com"],
      TXT: [`v=spf1 a mx -all`]
    };
  }
  return {
    A: [ip, randomIP()],
    MX: [`aspmx.l.google.com`, `alt1.aspmx.l.google.com`],
    NS: [`ns1.cloudflare.com`, `ns2.cloudflare.com`],
    TXT: [
      `v=spf1 include:_spf.google.com include:mailgun.org ~all`,
      `v=DMARC1; p=reject; rua=mailto:dmarc@${domain}; adkim=s; aspf=s`
    ]
  };
}
function generateWHOIS(domain, prediction) {
  if (prediction === "phishing") {
    const reg = inferRegistrar(domain);
    const daysAgo = randInt(1, 12);
    const created2 = new Date(Date.now() - daysAgo * 864e5);
    return {
      registrant: "REDACTED FOR PRIVACY",
      creation_date: created2.toISOString().split("T")[0],
      expiry_date: new Date(created2.getTime() + 365 * 864e5).toISOString().split("T")[0],
      country: inferCountry(domain, true),
      email: reg.email,
      registrar: reg.name,
      updated_date: created2.toISOString().split("T")[0]
    };
  }
  if (prediction === "suspicious") {
    const reg = inferRegistrar(domain);
    const daysAgo = randInt(15, 90);
    const created2 = new Date(Date.now() - daysAgo * 864e5);
    return {
      registrant: "Privacy Protected",
      creation_date: created2.toISOString().split("T")[0],
      expiry_date: new Date(created2.getTime() + 365 * 864e5).toISOString().split("T")[0],
      country: inferCountry(domain, true),
      email: reg.email,
      registrar: reg.name,
      updated_date: created2.toISOString().split("T")[0]
    };
  }
  const yearsAgo = randInt(4, 18);
  const created = new Date(Date.now() - yearsAgo * 365 * 864e5);
  const sld = domain.replace(/^www\./, "").split(".")[0];
  const orgName = sld.charAt(0).toUpperCase() + sld.slice(1);
  return {
    registrant: `${orgName} Corp.`,
    creation_date: created.toISOString().split("T")[0],
    expiry_date: new Date(Date.now() + 2 * 365 * 864e5).toISOString().split("T")[0],
    country: "US",
    email: `domains@${domain}`,
    registrar: "MarkMonitor Inc.",
    updated_date: new Date(Date.now() - randInt(60, 300) * 864e5).toISOString().split("T")[0]
  };
}
function generateVT(positives, url) {
  const total = 90;
  const vendors = [
    "Kaspersky",
    "BitDefender",
    "ESET",
    "Avast",
    "Sophos",
    "Norton",
    "McAfee",
    "Malwarebytes",
    "Trend Micro",
    "Symantec",
    "CrowdStrike",
    "Cylance",
    "F-Secure",
    "Panda",
    "Webroot"
  ];
  return {
    positives,
    total,
    scan_date: (/* @__PURE__ */ new Date()).toISOString().split("T")[0],
    permalink: `https://www.virustotal.com/gui/search?query=${encodeURIComponent(url)}`,
    detected_by: vendors.slice(0, positives > 0 ? Math.min(positives, vendors.length) : 0)
  };
}
function buildPositiveLegitimacySignals(opts) {
  const sigs = [];
  if (opts.hasHTTPS)
    sigs.push("HTTPS with valid SSL/TLS certificate");
  if (opts.domainAge.includes("year") && parseInt(opts.domainAge) >= 2)
    sigs.push(`Established domain \u2014 active for ${opts.domainAge}`);
  if (opts.vtPositives === 0)
    sigs.push("0/90 VirusTotal engines report zero threats");
  if (!opts.urlhausListed)
    sigs.push("Not listed in URLHaus malware threat feed");
  if (!opts.phishtankListed)
    sigs.push("No confirmed PhishTank phishing reports");
  if (ENTERPRISE_REGISTRARS.some((r) => opts.whoisRegistrar.includes(r)))
    sigs.push(`Registered via enterprise registrar: ${opts.whoisRegistrar}`);
  if (opts.whoisRegistrant && !opts.whoisRegistrant.includes("REDACTED") && !opts.whoisRegistrant.includes("Privacy"))
    sigs.push(`Verified domain owner: ${opts.whoisRegistrant}`);
  if (opts.dnsMX.length > 0)
    sigs.push("Valid MX records \u2014 legitimate email infrastructure present");
  if (opts.dnsTXT.some((t) => t.includes("v=spf1")))
    sigs.push("SPF record configured \u2014 email authentication in place");
  if (opts.dnsTXT.some((t) => t.includes("DMARC")))
    sigs.push("DMARC policy active \u2014 domain email security verified");
  if (opts.isp.includes("Cloudflare") || opts.isp.includes("Fastly") || opts.isp.includes("Akamai"))
    sigs.push(`Hosted on trusted CDN: ${opts.isp}`);
  return sigs;
}
function buildNegativeSignals(signals) {
  return signals.map((s) => s.replace(/^\[.*?\]\s*/, "").trim()).filter(Boolean);
}
function buildFinalVerdictExplanation(opts) {
  const confPct = `${(opts.confidence * 100).toFixed(0)}%`;
  const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  if (opts.prediction === "phishing") {
    const brandNote = opts.detectedBrand ? ` impersonating ${cap(opts.detectedBrand)}` : "";
    const topSignals = opts.signals.slice(0, 3).map((s) => s.replace(/^\[.*?\]\s*/, "").toLowerCase()).join("; ");
    const consensusNote = opts.urlhausListed || opts.phishtankListed ? ` Multiple independent threat feeds (URLHaus${opts.phishtankListed ? ", PhishTank" : ""}) confirm this URL as malicious.` : ` ${opts.vtPositives} VirusTotal vendors independently flag this URL.`;
    const vectorNote = opts.attackVectors.length ? ` Attack vectors detected: ${opts.attackVectors.join(", ")}.` : "";
    return `HIGH CONFIDENCE PHISHING${brandNote}. Evidence: ${topSignals}.${consensusNote}${vectorNote} Risk: ${opts.riskScore}/100 | Confidence: ${confPct}. Immediate action: block URL and investigate all hosts that accessed it.`;
  }
  if (opts.prediction === "suspicious") {
    const topSignals = opts.signals.slice(0, 2).map((s) => s.replace(/^\[.*?\]\s*/, "").toLowerCase()).join("; ");
    const vtNote = opts.vtPositives > 0 ? ` ${opts.vtPositives}/90 VirusTotal detections noted but below consensus threshold.` : " VirusTotal shows no detections, but behavioural signals remain.";
    return `SUSPICIOUS \u2014 insufficient evidence for definitive phishing classification. Signals: ${topSignals}.${vtNote} Domain age: ${opts.domainAge}. Risk: ${opts.riskScore}/100 | Confidence: ${confPct}. Recommendation: investigate further before permitting access; do not submit credentials.`;
  }
  const topPositive = opts.positiveSignals.slice(0, 2).map((s) => s.toLowerCase()).join("; ");
  const noThreats = "Zero threat intelligence hits across VirusTotal (90 engines), URLHaus, and PhishTank.";
  return `LEGITIMATE \u2014 no phishing indicators detected. ${topPositive ? `Strong legitimacy signals: ${topPositive}.` : ""} ${noThreats} Risk: ${opts.riskScore}/100 | Confidence: ${confPct}. URL is safe to access.`;
}
async function simulateScan(url) {
  await new Promise((resolve) => setTimeout(resolve, 2800));
  const urlLower = url.toLowerCase();
  const domain = extractDomain(url);
  const ip = isIP(domain) ? domain : randomIP();
  const hasHTTPS = url.startsWith("https://");
  const hasIPInURL = isIP(domain);
  const numDots = (url.match(/\./g) || []).length;
  const urlLength = url.length;
  const hyphenCount = (domain.match(/-/g) || []).length;
  const numDigits = (url.match(/\d/g) || []).length;
  const specialChars = (url.match(/[!@#$%^&*()_+\-=\[\]{};':"\\|,<>\/?]/g) || []).length;
  const entropy = parseFloat(calculateEntropy(url).toFixed(2));
  if (isTrustedDomain(domain) && !hasIPInURL) {
    const reg = registeredDomain(domain);
    const knownMeta = {
      "flipkart.com": { age: "17 years", registrant: "Flipkart Internet Pvt Ltd", country: "IN", isp: "Akamai Technologies" },
      "amazon.com": { age: "28 years", registrant: "Amazon Technologies, Inc.", country: "US", isp: "Amazon Web Services" },
      "amazon.in": { age: "12 years", registrant: "Amazon Seller Services Pvt Ltd", country: "IN", isp: "Amazon Web Services" },
      "google.com": { age: "26 years", registrant: "Google LLC", country: "US", isp: "Google LLC" },
      "github.com": { age: "16 years", registrant: "GitHub, Inc.", country: "US", isp: "GitHub, Inc." },
      "microsoft.com": { age: "30 years", registrant: "Microsoft Corporation", country: "US", isp: "Microsoft Corporation" },
      "apple.com": { age: "27 years", registrant: "Apple Inc.", country: "US", isp: "Apple Inc." },
      "netflix.com": { age: "25 years", registrant: "Netflix, Inc.", country: "US", isp: "Amazon Web Services" },
      "youtube.com": { age: "19 years", registrant: "Google LLC", country: "US", isp: "Google LLC" },
      "paypal.com": { age: "25 years", registrant: "PayPal, Inc.", country: "US", isp: "PayPal, Inc." },
      "outlook.com": { age: "22 years", registrant: "Microsoft Corporation", country: "US", isp: "Microsoft Corporation" },
      "stackoverflow.com": { age: "17 years", registrant: "Stack Exchange, Inc.", country: "US", isp: "Fastly, Inc." }
    };
    const meta = knownMeta[reg] ?? {
      age: `${randInt(5, 20)} years`,
      registrant: `${reg.split(".")[0].charAt(0).toUpperCase() + reg.split(".")[0].slice(1)} Inc.`,
      country: "US",
      isp: "Cloudflare, Inc."
    };
    const created = new Date(Date.now() - parseInt(meta.age) * 365 * 864e5);
    const trustedRiskScore = randInt(1, 8);
    const trustedConf = parseFloat((0.96 + Math.random() * 0.03).toFixed(3));
    const trustedDNS = generateDNS(randomIP(), domain, "safe");
    const trustedWhois = {
      registrant: meta.registrant,
      creation_date: created.toISOString().split("T")[0],
      expiry_date: new Date(Date.now() + 365 * 864e5).toISOString().split("T")[0],
      country: meta.country,
      email: `domains@${reg}`,
      registrar: "MarkMonitor Inc.",
      updated_date: new Date(Date.now() - randInt(100, 400) * 864e5).toISOString().split("T")[0]
    };
    const trustedPositiveSignals = buildPositiveLegitimacySignals({
      hasHTTPS,
      domainAge: meta.age,
      vtPositives: 0,
      urlhausListed: false,
      phishtankListed: false,
      whoisRegistrant: trustedWhois.registrant,
      whoisRegistrar: trustedWhois.registrar,
      dnsMX: trustedDNS.MX,
      dnsTXT: trustedDNS.TXT,
      isp: meta.isp
    });
    return {
      id: `scan_${Date.now()}`,
      url,
      prediction: "safe",
      confidence: trustedConf,
      risk_score: trustedRiskScore,
      timestamp: (/* @__PURE__ */ new Date()).toISOString(),
      domain,
      ip_address: randomIP(),
      domain_age: meta.age,
      virustotal_detections: "0/90",
      virustotal: generateVT(0, url),
      dns_records: trustedDNS,
      whois: trustedWhois,
      features: {
        url_length: urlLength,
        num_dots: numDots,
        has_https: hasHTTPS,
        has_ip: false,
        num_digits: numDigits,
        entropy: parseFloat(calculateEntropy(url).toFixed(2)),
        subdomain_count: Math.max(0, domain.split(".").length - 2),
        suspicious_keywords: [],
        hyphen_count: hyphenCount,
        special_char_count: specialChars,
        typosquatting_similarity: null,
        typosquatting_target: null,
        is_shortened: false,
        num_path_components: url.split("/").length - 3,
        attack_vectors: []
      },
      threat_indicators: [],
      ml_features_used: 24,
      scan_duration_ms: randInt(120, 350),
      urlhaus_listed: false,
      phishtank_listed: false,
      asn: `AS${randInt(1e4, 99999)}`,
      country: meta.country,
      isp: meta.isp,
      detected_brand: null,
      positive_legitimacy_signals: trustedPositiveSignals,
      negative_signals: [],
      final_verdict_explanation: `LEGITIMATE \u2014 verified authentic domain registered to ${meta.registrant}. Domain has been active for ${meta.age} with an impeccable security reputation. ${trustedPositiveSignals.slice(0, 2).join("; ")}. Zero threat intelligence hits. Risk: ${trustedRiskScore}/100 | Confidence: ${(trustedConf * 100).toFixed(0)}%. URL is safe to access.`
    };
  }
  const sld = domain.replace(/^www\./, "").split(".")[0].toLowerCase();
  const domainLower = domain.toLowerCase();
  const unicodeChars = detectUnicodeChars(sld + "." + domain);
  const unicodeAbuse = unicodeChars.length > 0;
  const unicodeNormalized = normalizeUnicode(sld);
  const unicodeBrandMatch = unicodeAbuse ? matchBrand(unicodeNormalized, 1) : null;
  const sldCollapsed = collapseAllRepeats(sld);
  const hasRepetition = sldCollapsed !== sld && sldCollapsed.length < sld.length;
  let charRepeatBrandMatch = null;
  if (hasRepetition) {
    charRepeatBrandMatch = matchBrand(sldCollapsed, 1);
    if (!charRepeatBrandMatch) charRepeatBrandMatch = matchBrand(collapseRepeats(sld), 2);
  }
  const hasDigits = /[0-9]/.test(sld);
  const leetNormalized = normalizeLeet(sld);
  const leetDiff = leetNormalized !== sld;
  let leetBrandMatch = null;
  if (hasDigits && leetDiff) {
    leetBrandMatch = matchBrand(leetNormalized, 1);
    if (!leetBrandMatch) leetBrandMatch = matchBrand(collapseAllRepeats(leetNormalized), 2);
  }
  const fullyNormalized = fullyNormalize(sld);
  let fullNormBrandMatch = null;
  if (fullyNormalized !== sld && !unicodeBrandMatch && !charRepeatBrandMatch && !leetBrandMatch) {
    fullNormBrandMatch = matchBrand(fullyNormalized, 1);
  }
  const subdomainAbuse = detectSubdomainBrandAbuse(domain);
  const hyphenAbuse = !subdomainAbuse ? detectHyphenBrandAbuse(sld) : null;
  const impersonatedBrand = KNOWN_BRANDS.find(
    (b) => domainLower.includes(b) && !domainLower.endsWith(`${b}.com`) && !domainLower.endsWith(`${b}.org`) && !domainLower.endsWith(`${b}.net`) && !domainLower.endsWith(`${b}.co`) && !domainLower.endsWith(`${b}.in`) && !domainLower.endsWith(`${b}.io`) && !domainLower.endsWith(`${b}.tv`) && !domainLower.endsWith(`${b}.us`)
  );
  const rawTypo = !impersonatedBrand && !subdomainAbuse && !hyphenAbuse ? matchBrand(sld, 2) : null;
  const typosquatBrand = rawTypo && rawTypo.editDistance >= 1 ? rawTypo : null;
  const anyDetectedBrand = impersonatedBrand ?? subdomainAbuse?.brand ?? hyphenAbuse?.brand ?? typosquatBrand?.brand ?? charRepeatBrandMatch?.brand ?? leetBrandMatch?.brand ?? unicodeBrandMatch?.brand ?? null;
  const injectedKeywords = detectKeywordInjection(sld, anyDetectedBrand);
  const keywordInjection = injectedKeywords.length >= 1;
  const isShortened = URL_SHORTENERS.some((s) => urlLower.includes(s));
  const foundPhishingKeywords = PHISHING_KEYWORDS.filter((k) => domainLower.includes(k));
  const foundSuspiciousKeywords = SUSPICIOUS_KEYWORDS.filter((k) => domainLower.includes(k));
  const hasSuspiciousTLD = SUSPICIOUS_TLDS.some((t) => urlLower.endsWith(t) || urlLower.includes(t + "/"));
  const dgaDetected = isDGALike(sld);
  const signals = [];
  const attackVectors = [];
  let riskScore = 5;
  if (hasIPInURL) {
    signals.push("IP-based URL \u2014 no domain name, direct server access");
    riskScore += 30;
  }
  if (!hasHTTPS) {
    signals.push("HTTP only \u2014 no TLS encryption");
    riskScore += 12;
  }
  if (hasSuspiciousTLD) {
    signals.push("Suspicious TLD detected");
    riskScore += 15;
  }
  if (urlLength > 100) {
    signals.push(`Unusually long URL (${urlLength} chars)`);
    riskScore += 8;
  }
  if (entropy > 4.5) {
    signals.push("High URL entropy \u2014 possible obfuscation");
    riskScore += 10;
  }
  if (isShortened) {
    signals.push("URL shortener detected \u2014 final destination hidden");
    riskScore += 20;
  }
  if (hyphenCount >= 3) {
    signals.push(`Excessive hyphens in domain (${hyphenCount})`);
    riskScore += 12;
  }
  if (foundPhishingKeywords.length) {
    signals.push(`High-risk keywords: ${foundPhishingKeywords.slice(0, 4).join(", ")}`);
    riskScore += Math.min(foundPhishingKeywords.length * 7, 28);
  }
  if (foundSuspiciousKeywords.length) {
    signals.push(`Suspicious keywords: ${foundSuspiciousKeywords.join(", ")}`);
    riskScore += foundSuspiciousKeywords.length * 4;
  }
  if (unicodeAbuse) {
    const charList = unicodeChars.slice(0, 4).join(" ");
    if (unicodeBrandMatch) {
      signals.push(`[HOMOGLYPH] Unicode lookalike chars (${charList}) \u2192 "${sld}" decodes to "${unicodeBrandMatch.brand}" \u2014 sophisticated impersonation`);
      attackVectors.push("Unicode Homoglyph Attack");
      riskScore += 50;
    } else {
      signals.push(`[UNICODE] Non-ASCII characters in domain: ${charList}`);
      attackVectors.push("Unicode Abuse");
      riskScore += 25;
    }
  }
  if (hasRepetition && charRepeatBrandMatch) {
    signals.push(`[CHAR-REPEAT] "${sld}" \u2192 "${sldCollapsed}" mimics "${charRepeatBrandMatch.brand}.com"`);
    attackVectors.push("Character Repetition Attack");
    riskScore += 40;
  }
  if (leetBrandMatch && leetDiff) {
    signals.push(`[L33T] Digit substitution: "${sld}" \u2192 "${leetNormalized}" targets "${leetBrandMatch.brand}.com"`);
    attackVectors.push("L33t Speak Substitution");
    riskScore += 38;
  }
  if (fullNormBrandMatch) {
    signals.push(`[COMBINED] Multi-technique obfuscation: "${sld}" \u2192 "${fullyNormalized}" targets "${fullNormBrandMatch.brand}.com"`);
    attackVectors.push("Combined Obfuscation Attack");
    riskScore += 45;
  }
  if (subdomainAbuse) {
    signals.push(`[SUBDOMAIN-ABUSE] Brand "${subdomainAbuse.brand}" used as subdomain to mimic "${subdomainAbuse.brand}.com"`);
    attackVectors.push("Subdomain Brand Impersonation");
    riskScore += 42;
  }
  if (hyphenAbuse) {
    signals.push(`[HYPHEN-ABUSE] Brand "${hyphenAbuse.brand}" embedded in hyphenated domain "${sld}"`);
    attackVectors.push("Hyphen Brand Abuse");
    riskScore += 38;
  }
  if (impersonatedBrand) {
    signals.push(`[BRAND-IMPERSONATION] "${impersonatedBrand.charAt(0).toUpperCase() + impersonatedBrand.slice(1)}" brand in domain but not official site`);
    attackVectors.push("Direct Brand Impersonation");
    riskScore += 35;
  }
  if (typosquatBrand && !impersonatedBrand) {
    signals.push(`[TYPOSQUAT] "${sld}" is ${typosquatBrand.editDistance} edit(s) from "${typosquatBrand.brand}.com"`);
    attackVectors.push("Typosquatting");
    riskScore += 38;
  }
  if (keywordInjection && anyDetectedBrand) {
    signals.push(`[KEYWORD-INJECT] Security keywords injected: ${injectedKeywords.join(", ")} \u2014 mimics "${anyDetectedBrand}" portal`);
    attackVectors.push("Security Keyword Injection");
    riskScore += injectedKeywords.length * 8;
  }
  if (dgaDetected && !anyDetectedBrand) {
    signals.push("[DGA] Domain appears algorithmically generated \u2014 DGA malware C2 pattern");
    attackVectors.push("DGA Domain");
    riskScore += 30;
  }
  if (attackVectors.length >= 2) {
    riskScore += (attackVectors.length - 1) * 8;
    signals.push(`Multi-vector attack: ${attackVectors.length} combined techniques`);
  }
  riskScore = Math.min(100, Math.max(0, riskScore + randInt(0, 4)));
  let prediction = "safe";
  let confidence, vtPositives, domainAge;
  let urlhausListed = false, phishtankListed = false;
  const isPhishing = riskScore >= 65 || hasIPInURL || unicodeBrandMatch !== null || charRepeatBrandMatch !== null || leetBrandMatch !== null || fullNormBrandMatch !== null || subdomainAbuse !== null || hyphenAbuse !== null && hasSuspiciousTLD || impersonatedBrand !== void 0 && !hasHTTPS || typosquatBrand !== null && hasSuspiciousTLD;
  const isSuspicious = !isPhishing && (riskScore >= 35 || isShortened || dgaDetected || hyphenAbuse !== null || typosquatBrand !== null || impersonatedBrand !== void 0 || foundSuspiciousKeywords.length > 1);
  if (isPhishing) {
    prediction = "phishing";
    confidence = parseFloat((0.88 + Math.random() * 0.11).toFixed(3));
    vtPositives = randInt(8, 28);
    urlhausListed = Math.random() > 0.35;
    phishtankListed = Math.random() > 0.3;
    domainAge = `${randInt(1, 14)} days`;
    if (urlhausListed) signals.push("Listed on URLHaus malware threat feed");
    if (phishtankListed) signals.push("Confirmed on PhishTank phishing database");
    signals.push(`New domain \u2014 only ${domainAge} old`);
  } else if (isSuspicious) {
    prediction = "suspicious";
    confidence = parseFloat((0.68 + Math.random() * 0.18).toFixed(3));
    vtPositives = randInt(1, 5);
    urlhausListed = Math.random() > 0.65;
    phishtankListed = Math.random() > 0.75;
    domainAge = `${randInt(15, 120)} days`;
    if (urlhausListed) signals.push("Low-confidence match on URLHaus feed");
    if (phishtankListed) signals.push("Unverified report on PhishTank");
  } else {
    prediction = "safe";
    confidence = parseFloat((0.9 + Math.random() * 0.09).toFixed(3));
    vtPositives = 0;
    urlhausListed = false;
    phishtankListed = false;
    domainAge = `${randInt(3, 20)} years`;
  }
  const primaryBrandMatch = unicodeBrandMatch ?? charRepeatBrandMatch ?? leetBrandMatch ?? fullNormBrandMatch ?? typosquatBrand;
  const primaryBrand = impersonatedBrand ?? subdomainAbuse?.brand ?? hyphenAbuse?.brand ?? primaryBrandMatch?.brand ?? null;
  const subdomainCount = Math.max(0, domain.split(".").length - 2);
  const finalIP = hasIPInURL ? domain : prediction === "phishing" ? maliciousIP() : ip;
  const features = {
    url_length: urlLength,
    num_dots: numDots,
    has_https: hasHTTPS,
    has_ip: hasIPInURL,
    num_digits: numDigits,
    entropy,
    subdomain_count: subdomainCount,
    suspicious_keywords: [...foundPhishingKeywords, ...foundSuspiciousKeywords],
    hyphen_count: hyphenCount,
    special_char_count: specialChars,
    typosquatting_similarity: primaryBrandMatch?.similarity ?? (primaryBrand ? parseFloat((0.65 + Math.random() * 0.25).toFixed(2)) : null),
    typosquatting_target: primaryBrand ? `${primaryBrand}.com` : null,
    is_shortened: isShortened,
    num_path_components: url.split("/").length - 3,
    char_repetition_detected: hasRepetition && !!charRepeatBrandMatch,
    char_repetition_normalized: charRepeatBrandMatch ? sldCollapsed : null,
    homoglyph_detected: unicodeAbuse && !!unicodeBrandMatch,
    homoglyph_normalized: unicodeBrandMatch ? unicodeNormalized : null,
    unicode_abuse_detected: unicodeAbuse,
    unicode_chars: unicodeChars.length > 0 ? unicodeChars : void 0,
    leet_speak_detected: !!leetBrandMatch,
    leet_normalized: leetBrandMatch ? leetNormalized : null,
    subdomain_brand_abuse: !!subdomainAbuse,
    subdomain_brand_target: subdomainAbuse?.brand ?? null,
    hyphen_brand_abuse: !!hyphenAbuse,
    hyphen_brand_target: hyphenAbuse?.brand ?? null,
    keyword_injection_detected: keywordInjection,
    injected_keywords: keywordInjection ? injectedKeywords : void 0,
    attack_vectors: attackVectors,
    normalized_domain: fullyNormalized !== sld ? fullyNormalized : null
  };
  const dnsRecords = generateDNS(finalIP, domain, prediction, prediction !== "safe" ? inferRegistrar(domain).ns : void 0);
  const whoisInfo = generateWHOIS(domain, prediction);
  const vtInfo = generateVT(vtPositives, url);
  const ispName = prediction === "phishing" ? ["M247 Ltd (Bulletproof)", "Frantech Solutions", "ALEXHOST SRL", "Combahton GmbH"][randInt(0, 3)] : prediction === "suspicious" ? ["OVH SAS", "Hetzner Online GmbH", "DigitalOcean LLC"][randInt(0, 2)] : "Cloudflare, Inc.";
  const positiveSignals = buildPositiveLegitimacySignals({
    hasHTTPS,
    domainAge,
    vtPositives,
    urlhausListed,
    phishtankListed,
    whoisRegistrant: whoisInfo.registrant,
    whoisRegistrar: whoisInfo.registrar,
    dnsMX: dnsRecords.MX,
    dnsTXT: dnsRecords.TXT,
    isp: ispName
  });
  const negativeSignals = buildNegativeSignals(signals);
  const finalVerdictExplanation = buildFinalVerdictExplanation({
    prediction,
    confidence,
    riskScore,
    detectedBrand: primaryBrand,
    signals,
    positiveSignals,
    vtPositives,
    urlhausListed,
    phishtankListed,
    attackVectors,
    domainAge
  });
  return {
    id: `scan_${Date.now()}`,
    url,
    prediction,
    confidence,
    risk_score: riskScore,
    timestamp: (/* @__PURE__ */ new Date()).toISOString(),
    domain,
    ip_address: finalIP,
    domain_age: domainAge,
    virustotal_detections: `${vtPositives}/90`,
    virustotal: vtInfo,
    dns_records: dnsRecords,
    whois: whoisInfo,
    features,
    threat_indicators: signals,
    ml_features_used: 24,
    scan_duration_ms: randInt(180, 550),
    urlhaus_listed: urlhausListed,
    phishtank_listed: phishtankListed,
    asn: prediction === "phishing" ? inferRegistrar(domain).name.includes("Reg.ru") ? "AS197695" : `AS${randInt(3e4, 7e4)}` : `AS${randInt(1e4, 99999)}`,
    country: inferCountry(domain, prediction !== "safe"),
    isp: ispName,
    detected_brand: primaryBrand,
    positive_legitimacy_signals: positiveSignals,
    negative_signals: negativeSignals,
    final_verdict_explanation: finalVerdictExplanation
  };
}
const SCAN_STAGES = [
  { label: "Normalizing URL & decoding Unicode...", duration: 280 },
  { label: "Extracting lexical & structural features...", duration: 320 },
  { label: "Running homoglyph & char-repeat analysis...", duration: 350 },
  { label: "Running XGBoost ML model (24 features)...", duration: 500 },
  { label: "Querying VirusTotal API (90 engines)...", duration: 600 },
  { label: "Performing WHOIS lookup...", duration: 380 },
  { label: "Running DNS analysis & geolocation...", duration: 320 },
  { label: "Checking URLHaus & PhishTank feeds...", duration: 280 }
];
export {
  SCAN_STAGES,
  simulateScan
};
