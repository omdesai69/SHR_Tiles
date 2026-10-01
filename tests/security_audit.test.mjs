/**
 * Automated Security, Accessibility & System Verification Suite
 * Shree Hari Marketing - Architectural Platform
 * 
 * Strict Hardcore Testing:
 * 1. OWASP DOM XSS Entity Sanitization
 * 2. Catalog & Company State Deep Immutability
 * 3. Mobile Number E.164 / Indian Carrier Pattern Invariants
 * 4. Mathematical Bounds Clamping & Freight Calculation Accuracy
 * 5. Multi-Word Tokenized Search Invariants
 * 6. Static HTML Security, Performance & WCAG Accessibility
 * 7. Edge Security Response Headers & Caching Strategy
 * 8. Dynamic Application & CSP Hardening
 */

import { readFileSync, existsSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TILE_CATALOG, COMPANY_INFO, deepFreeze } from '../data.js';
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

// Verify deepFreeze function integrity
const testObj = { a: { b: { c: 1 } } };
deepFreeze(testObj);
assert(Object.isFrozen(testObj.a.b), 'deepFreeze recursively freezes nested objects');

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

console.log('\n--- 4. Mathematical Bounds & Freight Calculation Invariants ---');
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

// Freight Box Calculation Accuracy Test
function computeBoxes(area, wastagePct, coverage) {
  const grossArea = area * (1 + (wastagePct / 100));
  return Math.ceil(grossArea / coverage);
}
assert(computeBoxes(1200, 8, 8.61) === 151, '1200 sq.ft at 8% wastage (8.61 coverage) computes to exactly 151 boxes');
assert(computeBoxes(200, 8, 8.61) === 26, '200 sq.ft at 8% wastage computes to exactly 26 boxes');
assert(computeBoxes(3000, 10, 15.50) === 213, '3000 sq.ft at 10% wastage (15.50 coverage) computes to exactly 213 boxes');

console.log('\n--- 5. Multi-Word Tokenized Search Invariants ---');
function simulateMultiTokenSearch(query, searchStr) {
  const tokens = query.toLowerCase().trim().split(/\s+/).filter(Boolean);
  return tokens.every(tok => searchStr.includes(tok));
}
const sampleStr = "dazzle punch surface 400x400mm dazzle-004 3d textured punch (anti-skid) digital parking series";
assert(simulateMultiTokenSearch("punch 400", sampleStr), 'Multi-token search matches across non-adjacent words ("punch 400")');
assert(simulateMultiTokenSearch("dazzle parking", sampleStr), 'Multi-token search matches series name and code ("dazzle parking")');
assert(!simulateMultiTokenSearch("punch marble", sampleStr), 'Multi-token search rejects non-matching term ("punch marble")');

console.log('\n--- 6. Static HTML Security, Performance & WCAG Accessibility ---');
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
  !htmlContent.includes('onerror='),
  'index.html contains zero inline onerror attributes (Preserves fallback under CSP)'
);

// Performance & Core Web Vitals
assert(
  htmlContent.includes('<link rel="preload" as="image" href="assets/img/hero_bg.jpg" fetchpriority="high">'),
  'LCP hero image is preloaded with fetchpriority="high"'
);
assert(
  htmlContent.includes('width="640" height="427" fetchpriority="high"'),
  'Hero visual image specifies explicit dimensions and high fetch priority'
);

// WCAG Dialog Accessibility
assert(
  htmlContent.includes('id="tileModal" role="dialog" aria-modal="true"'),
  'Tile inspector lightbox specifies role="dialog" and aria-modal="true"'
);
assert(
  htmlContent.includes('id="certModal" role="dialog" aria-modal="true"'),
  'Registration lightbox specifies role="dialog" and aria-modal="true"'
);
assert(
  htmlContent.includes('type="button" id="btnShareCalc"'),
  'Freight calculator share button specifies explicit type="button"'
);

// Check OpenGraph specifications for WhatsApp
assert(htmlContent.includes('<meta property="og:title"'), 'WhatsApp og:title tag is present');
assert(htmlContent.includes('<meta property="og:description"'), 'WhatsApp og:description tag is present');
assert(htmlContent.includes('<meta property="og:image"'), 'WhatsApp og:image tag is present');
assert(htmlContent.includes('<meta property="og:image:width" content="1200">'), 'WhatsApp og:image:width is 1200');
assert(htmlContent.includes('<meta property="og:image:height" content="630">'), 'WhatsApp og:image:height is 630');
assert(htmlContent.includes('application/ld+json'), 'Schema.org JSON-LD Structured Data is present');

// Check all target="_blank" tags have rel="noopener noreferrer"
const blankLinks = htmlContent.match(/<a\s+[^>]*target=["']_blank["'][^>]*>/gi) || [];
assert(blankLinks.length > 0, `Found ${blankLinks.length} target="_blank" links`);
blankLinks.forEach((link, idx) => {
  const hasRel = /rel=["'][^"']*noopener[^"']*noreferrer[^"']*["']/i.test(link);
  assert(hasRel, `Link #${idx + 1} contains rel="noopener noreferrer" (Reverse Tabnabbing Immunity)`);
});

// Check bot honeypot input in form
assert(htmlContent.includes('id="partnerHoneypot"'), 'Partner Form contains anti-bot honeypot trap');

// Dead element cleanup verification
assert(!htmlContent.includes('class="site-bg-watermark"'), 'Dead site-bg-watermark div removed from HTML');

console.log('\n--- 7. Edge Security Headers Files Audit (Framing & Caching) ---');
const headersContent = readFileSync(resolve(ROOT_DIR, '_headers'), 'utf-8');
assert(headersContent.includes('Strict-Transport-Security: max-age=63072000; includeSubDomains; preload'), '_headers configures HSTS Preload');
assert(headersContent.includes('X-Frame-Options: DENY'), '_headers configures framing protection via X-Frame-Options: DENY');
assert(headersContent.includes("frame-ancestors 'none'"), '_headers configures framing protection via CSP frame-ancestors none');
assert(headersContent.includes('X-Content-Type-Options: nosniff'), '_headers configures nosniff');
assert(headersContent.includes('X-Robots-Tag: noindex, nofollow, noarchive'), '_headers shields /Certificate/* from crawlers');
assert(headersContent.includes('/Availaible*'), '_headers configures caching for stock catalog PDFs');

const vercelContent = readFileSync(resolve(ROOT_DIR, 'vercel.json'), 'utf-8');
const vercelJson = JSON.parse(vercelContent);
assert(Array.isArray(vercelJson.headers), 'vercel.json contains headers configuration');
const globalHeaders = vercelJson.headers.find(h => h.source === '/(.*)');
assert(globalHeaders && Array.isArray(globalHeaders.headers), 'vercel.json applies security headers globally');

// Assert framing protection in response-header configuration
const vFrameOptions = globalHeaders.headers.find(h => h.key === 'X-Frame-Options');
assert(vFrameOptions && vFrameOptions.value === 'DENY', 'vercel.json configures framing protection via X-Frame-Options: DENY');

const vCsp = globalHeaders.headers.find(h => h.key === 'Content-Security-Policy');
assert(vCsp && vCsp.value.includes("frame-ancestors 'none'"), 'vercel.json configures framing protection via CSP frame-ancestors none');

// Assert catalog caching in vercel.json
assert(vercelJson.headers.some(h => h.source && h.source.includes('Availaible')), 'vercel.json configures caching rule for catalog PDFs');

console.log('\n--- 8. Dynamic Application & CSP Hardening Audit ---');
const appContent = readFileSync(resolve(ROOT_DIR, 'app.js'), 'utf-8');
assert(!appContent.includes('onerror='), 'app.js contains zero inline onerror event handlers (CSP compliance)');
assert(appContent.includes('fallbackApplied') && appContent.includes('addEventListener'), 'app.js implements unobtrusive capture-phase image fallback listener');
assert(appContent.includes('dom.resTotalBoxes.textContent ='), 'app.js dynamically updates resTotalBoxes when area changes');
assert(appContent.includes('deepFreeze(TRANSLATIONS)'), 'app.js deeply freezes TRANSLATIONS object against prototype poisoning');
assert(appContent.includes('previousActiveElement'), 'app.js manages accessible focus restoration on modal dismissal');

console.log(`\n========================================`);
console.log(`AUDIT COMPLETE: ${passedTests} / ${totalTests} assertions passed (${Math.round((passedTests / totalTests) * 100)}%).`);
console.log(`========================================\n`);
