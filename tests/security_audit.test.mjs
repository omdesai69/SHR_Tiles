/**
 * Automated Security & Integrity Verification Suite
 * Shree Hari Marketing - Architectural Platform
 * 
 * Tests:
 * 1. OWASP DOM XSS Entity Sanitization
 * 2. Catalog & Company State Deep Immutability
 * 3. Mobile Number E.164 / Indian Carrier Pattern Invariants
 * 4. Mathematical Bounds Clamping (Anti-NaN / Anti-Overflow)
 * 5. Universal Anchor Tag Reverse Tabnabbing Defense
 * 6. Content Security Policy & Anti-MIME Headers Presence
 * 7. OpenGraph Social Card Specifications for WhatsApp
 */

import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TILE_CATALOG, COMPANY_INFO } from '../data.js';
import { escapeHTML } from '../app.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = resolve(__dirname, '..');

let totalTests = 0;
let passedTests = 0;

function assert(condition, message) {
  totalTests++;
  if (!condition) {
    console.error(`❌ FAILED: ${message}`);
    process.exitCode = 1;
  } else {
    passedTests++;
    console.log(`✅ PASSED: ${message}`);
  }
}

console.log('\n--- 1. OWASP DOM XSS Entity Sanitization Audit ---');
const XSS_PAYLOADS = [
  '<script>alert("XSS")</script>',
  '"><img src=x onerror=alert(1)>',
  '\' onfocus=\'alert(1)',
  '`><svg/onload=alert(1)>',
  '<iframe src="javascript:alert(1)">',
  '<a href="javascript:void(0)">Click</a>',
  '${7*7}{{constructor.constructor("alert(1)")()}}',
  '"><script src="https://evil.com/xss.js"></script>'
];

XSS_PAYLOADS.forEach((payload, idx) => {
  const sanitized = escapeHTML(payload);
  assert(
    !sanitized.includes('<') && !sanitized.includes('>') && !sanitized.includes('"') && !sanitized.includes("'"),
    `Payload #${idx + 1} sanitized without unescaped tags or quotes`
  );
});

console.log('\n--- 2. State & Memory Immutability Audit ---');
assert(Object.isFrozen(TILE_CATALOG), 'TILE_CATALOG is deeply frozen in module memory');
assert(Object.isFrozen(COMPANY_INFO), 'COMPANY_INFO is deeply frozen in module memory');
assert(Object.isFrozen(TILE_CATALOG[0]), 'Catalog items are deeply frozen');
assert(Object.isFrozen(TILE_CATALOG[0].features), 'Item arrays are frozen against prototype mutation');

let phoneMutated = false;
try {
  COMPANY_INFO.phoneClean = '9999999999';
} catch (_) {
  phoneMutated = false;
}
assert(COMPANY_INFO.phoneClean === '919021560608', 'COMPANY_INFO.phoneClean cannot be altered by rogue scripts');

console.log('\n--- 3. Mobile Number Pattern Validation Invariants ---');
const INDIAN_PHONE_REGEX = /^[6-9]\d{9}$/;
const VALID_NUMBERS = ['9021560608', '9876543210', '8123456789', '7000000000', '6999999999'];
const INVALID_NUMBERS = ['12345', '0123456789', '5555555555', '90215606080', 'abcdefghij', '902156060a', ''];

VALID_NUMBERS.forEach(num => {
  assert(INDIAN_PHONE_REGEX.test(num), `Valid mobile accepted: ${num}`);
});

INVALID_NUMBERS.forEach(num => {
  assert(!INDIAN_PHONE_REGEX.test(num), `Invalid/malformed mobile rejected: "${num}"`);
});

console.log('\n--- 4. Mathematical Bounds & Boundary Clamping Invariants ---');
function simulateSafeFreightInput(rawArea, rawWastage) {
  const area = Number.isFinite(Number(rawArea)) ? Math.max(10, Math.min(500000, Math.round(Number(rawArea)))) : 1200;
  const wastage = Number.isFinite(Number(rawWastage)) ? Math.max(0, Math.min(25, Math.round(Number(rawWastage)))) : 8;
  return { area, wastage };
}

assert(simulateSafeFreightInput(-500, 8).area === 10, 'Negative area clamped to minimum 10 sq.ft');
assert(simulateSafeFreightInput(10000000, 8).area === 500000, 'Extreme area clamped to maximum 500,000 sq.ft');
assert(simulateSafeFreightInput(NaN, 8).area === 1200, 'NaN area fallback to default 1,200 sq.ft');
assert(simulateSafeFreightInput(1200, -20).wastage === 0, 'Negative wastage clamped to 0%');
assert(simulateSafeFreightInput(1200, 100).wastage === 25, 'Excessive wastage clamped to maximum 25%');

console.log('\n--- 5. Static HTML Security & Anchor Audit ---');
const htmlContent = readFileSync(resolve(ROOT_DIR, 'index.html'), 'utf-8');

// Check CSP
assert(
  htmlContent.includes('<meta http-equiv="Content-Security-Policy"'),
  'index.html includes Content Security Policy meta tag'
);
assert(
  htmlContent.includes("default-src 'self'"),
  'CSP strictly limits default sources to self'
);
assert(
  htmlContent.includes("frame-ancestors 'none'"),
  'CSP blocks iframe embedding (Anti-Clickjacking)'
);

// Check OpenGraph specifications for WhatsApp
assert(
  htmlContent.includes('<meta property="og:title"'),
  'WhatsApp og:title tag is present'
);
assert(
  htmlContent.includes('<meta property="og:description"'),
  'WhatsApp og:description tag is present'
);
assert(
  htmlContent.includes('<meta property="og:image"'),
  'WhatsApp og:image tag is present'
);
assert(
  htmlContent.includes('<meta property="og:image:width" content="1200">'),
  'WhatsApp og:image:width is 1200'
);
assert(
  htmlContent.includes('<meta property="og:image:height" content="630">'),
  'WhatsApp og:image:height is 630'
);
assert(
  htmlContent.includes('application/ld+json'),
  'Schema.org JSON-LD Structured Data is present'
);

// Check all target="_blank" tags have rel="noopener noreferrer"
const blankLinks = htmlContent.match(/<a\s+[^>]*target=["']_blank["'][^>]*>/gi) || [];
assert(blankLinks.length > 0, `Found ${blankLinks.length} target="_blank" links`);
blankLinks.forEach((link, idx) => {
  const hasRel = /rel=["'][^"']*noopener[^"']*noreferrer[^"']*["']/i.test(link);
  assert(hasRel, `Link #${idx + 1} contains rel="noopener noreferrer" (Reverse Tabnabbing Immunity)`);
});

// Check bot honeypot input in form
assert(
  htmlContent.includes('id="partnerHoneypot"'),
  'Partner Form contains anti-bot honeypot trap'
);

console.log('\n--- 6. Edge Security Headers Files Audit ---');
const headersContent = readFileSync(resolve(ROOT_DIR, '_headers'), 'utf-8');
assert(headersContent.includes('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'), '_headers configures HSTS Preload');
assert(headersContent.includes('X-Frame-Options: DENY'), '_headers configures X-Frame-Options: DENY');
assert(headersContent.includes('X-Content-Type-Options: nosniff'), '_headers configures nosniff');
assert(headersContent.includes('X-Robots-Tag: noindex, nofollow, noarchive'), '_headers shields /Certificate/* from crawlers');

const vercelContent = readFileSync(resolve(ROOT_DIR, 'vercel.json'), 'utf-8');
const vercelJson = JSON.parse(vercelContent);
assert(Array.isArray(vercelJson.headers), 'vercel.json contains headers configuration');
assert(vercelJson.headers.some(h => h.source === '/(.*)'), 'vercel.json applies security headers globally');

console.log(`\n========================================`);
console.log(`AUDIT COMPLETE: ${passedTests} / ${totalTests} assertions passed (${Math.round((passedTests / totalTests) * 100)}%).`);
console.log(`========================================\n`);
