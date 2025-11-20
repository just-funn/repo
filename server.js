const express = require('express');
const path = require('path');
const dns = require('dns').promises;
const cors = require('cors');

require('dotenv').config();

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;

// Helper: simple TLD list considered higher-risk (heuristic)
const riskyTLDs = [
  '.xyz', '.top', '.icu', '.men', '.click', '.work', '.trade', '.download', '.party', '.stream'
];

// Known shorteners
const shorteners = [
  'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 'rb.gy'
];

function addCheck(result, name, weight, ok, message) {
  result.checks.push({ name, weight, ok, message });
  result.score += ok ? 0 : weight;
}

function isIpHostname(host) {
  // IPv4 or IPv6 (very simple)
  return /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(host) || host.includes(':');
}

app.post('/api/check', async (req, res) => {
  const { url: rawUrl } = req.body || {};
  if (!rawUrl) return res.status(400).json({ error: 'No url provided' });

  let url;
  try {
    // Ensure scheme; allow people to type without it
    let candidate = rawUrl.trim();
    if (!candidate.match(/^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//)) {
      candidate = 'http://' + candidate;
    }
    url = new URL(candidate);
  } catch (err) {
    return res.status(400).json({ error: 'Invalid URL' });
  }

  const result = {
    input: rawUrl,
    normalized: url.href,
    hostname: url.hostname,
    protocol: url.protocol,
    score: 0,
    checks: [],
    verdict: 'unknown',
    details: {}
  };

  // 1. Protocol check
  if (url.protocol !== 'https:') {
    addCheck(result, 'Missing HTTPS', 2, false, 'URL does not use HTTPS; not encrypted in transit.');
  } else {
    addCheck(result, 'Has HTTPS', 0, true, 'Secure protocol (HTTPS).');
  }

  // 2. Hostname is IP
  if (isIpHostname(url.hostname)) {
    addCheck(result, 'IP as hostname', 3, false, 'Hostname is an IP address — often used by malicious services.');
  } else {
    addCheck(result, 'Hostname format', 0, true, 'Hostname is a domain name.');
  }

  // 3. Punycode check
  if (url.hostname.includes('xn--')) {
    addCheck(result, 'Punycode / IDN', 2, false, 'Punycode (IDN) detected — may be used in homograph attacks.');
  }

  // 4. URL length
  if (url.href.length > 200) {
    addCheck(result, 'URL length', 2, false, `Very long URL (${url.href.length} chars) — often used to hide payloads.`);
  }

  // 5. @ sign
  if (url.href.includes('@')) {
    addCheck(result, 'At symbol', 2, false, 'Contains "@" which can be used to obfuscate real target.');
  }

  // 6. Shortener
  if (shorteners.some(s => url.hostname.toLowerCase().endsWith(s))) {
    addCheck(result, 'Known shortener', 3, false, 'URL uses a known shortener — redirect hides final destination.');
  }

  // 7. Suspicious keywords
  const suspiciousKeywords = ['login', 'secure', 'account', 'update', 'verify', 'confirm', 'password', 'bank', 'signin'];
  const concat = (url.pathname + url.search).toLowerCase();
  const foundKeys = suspiciousKeywords.filter(k => concat.includes(k));
  if (foundKeys.length > 0) {
    addCheck(result, 'Suspicious keywords', 2, false, `Found suspicious keywords: ${foundKeys.join(', ')}`);
  }

  // 8. Encoded payloads & suspicious characters
  if (/%[0-9A-Fa-f]{2}/.test(url.href) || url.href.includes('\\x') || url.href.includes('eval(')) {
    addCheck(result, 'Encoded payloads', 2, false, 'URL contains encoded characters or suspicious patterns.');
  }

  // 9. Hyphens / subdomain depth
  const subdomainParts = url.hostname.split('.');
  if (subdomainParts.length >= 4) {
    addCheck(result, 'Subdomain depth', 1, false, `Deep subdomain (${subdomainParts.length} parts) — sometimes used to mimic legitimate domains.`);
  }
  const hyphenCount = (url.hostname.match(/-/g) || []).length;
  if (hyphenCount >= 3) {
    addCheck(result, 'Multiple hyphens', 1, false, 'Multiple hyphens in hostname can indicate suspicious domain-generation.');
  }

  // 10. Risky TLDs
  for (const tld of riskyTLDs) {
    if (url.hostname.endsWith(tld)) {
      addCheck(result, 'Risky TLD', 2, false, `Top-level domain ${tld} is sometimes associated with low-cost or abusive registrations.`);
      break;
    }
  }

  // 11. DNS resolution
  try {
    const lookup = await dns.lookup(url.hostname);
    result.details.resolved = lookup.address;
    addCheck(result, 'DNS resolution', 0, true, `Hostname resolves to ${lookup.address}.`);
  } catch (err) {
    addCheck(result, 'DNS resolution failed', 3, false, 'Hostname did not resolve — could be transient or malicious.');
  }

  // 12. Port check
  if (url.port && url.port !== '443' && url.port !== '80') {
    addCheck(result, 'Nonstandard port', 1, false, `Uses nonstandard port ${url.port} — unusual for public websites.`);
  }

  // Final verdict thresholds
  let verdict = 'Safe';
  if (result.score >= 6) verdict = 'Danger';
  else if (result.score >= 3) verdict = 'Suspicious';
  result.verdict = verdict;

  res.json(result);
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`URL Checker (heuristics-only) running on http://localhost:${PORT}`);
});
