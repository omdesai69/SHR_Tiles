# Shree Hari Marketing — Ceramic & Vitrified Surfaces Wholesaler

> Premium architectural tile wholesale and direct Morbi factory distribution platform for Pune, Maharashtra.

---

## Overview

**Shree Hari Marketing** is an authorized wholesaler and direct Morbi sourcing distributor based in Pune, Maharashtra. Founded by **Dilip Desai** (12+ years ceramic industry experience), the platform connects retail showrooms, civil contractors, architects, and large-scale builders directly to Morbi manufacturing hubs.

- **Godown Hub**: Beldare Patil Warehouse, Old Katraj Tunnel Road, Shindewadi, Ambegaon Bk, Pune — 411046
- **GSTIN**: `27AXKPD0028L1ZK`
- **Udyam MSME**: `UDYAM-MH-26-0317585`
- **Bilingual Interface**: Seamless Hindi / English live toggle

---

## Key Features

1. **Live Pune Inventory**:
   - 400x400 mm Digital Heavy Parking Tiles (Anti-Skid, R11 rating)
   - 600x600 mm Porcelain GVT / Glazed Vitrified Tiles (Mirror Polish & Satin Matt)
   - Instant stock counter and live search with $\mathcal{O}(1)$ pre-indexed lookups
2. **Morbi Direct Project Sourcing**:
   - 16mm Heavy-Duty Parking Tiles
   - 12mm Outdoor Vitrified Slabs
   - Full Truck Load (FTL) direct factory dispatch
3. **Contractor Tile & Freight Calculator**:
   - Real-time gross area calculation with buffer percentage
   - Automatic box, tile piece, coverage, and metric weight estimator
   - Recommended transport vehicle selection (Tata Ace, 407, 6-Wheeler, 10-Wheeler, 16-Wheeler)
   - Delivery zone transit times from Ambegaon godown (Katraj, Hinjewadi, Hadapsar, Kothrud, Wagholi, Chakan, etc.)
4. **Architectural Design System**:
   - Warm Limestone & Travertine aesthetic (`#fbfaf7`, `#f5f2eb`)
   - Father's company crest watermark with unified scale, opacity, and text-first stacking
   - High-performance, zero-bloat vanilla CSS & ES6+ architecture

---

## Tech Stack

- **HTML5**: Semantic, accessible markup with 198 bilingual translation keys (`data-i18n`)
- **CSS3**: Custom design tokens, glassmorphism, responsive grid matrices, zero CSS frameworks
- **JavaScript (ES6+)**: Event delegation, pre-cached DOM registry, indexed `Map` lookups, zero build dependencies
- **Logistics Integration**: Direct WhatsApp B2B desk and Google Maps location pins

---

## Security & Hardening Architecture

The platform implements a zero-trust, defense-grade frontend security architecture:

1. **W3C Trusted Types & DOM XSS Neutralization**:
   - Engine-level DOM sink protection via native Trusted Types policy.
   - Zero-allocation HTML entity escaping (`escapeHTML`) preventing injection across all search and card renders.
2. **State & Memory Immutability**:
   - Deep recursive freezing (`Object.freeze`) on all catalogs, company metadata, translations, and specs to eliminate prototype pollution and extension tampering.
3. **Defense-in-Depth HTTP Headers**:
   - Production edge headers via `_headers` (Netlify/Cloudflare) and `vercel.json` (Vercel).
   - Strict `Content-Security-Policy` (Level 3), HSTS Preload (`max-age=63072000`), `X-Frame-Options: DENY` (anti-clickjacking), `nosniff`, and exhaustive `Permissions-Policy`.
   - `X-Robots-Tag: noindex, nofollow` on `/Certificate/*` preventing public search crawler indexing of business registrations.
4. **Anti-Bot & Anti-Abuse Form Protection**:
   - Cryptographic honeypot trap to catch automated web crawlers.
   - Time-lock token rejecting submissions under 1.8 seconds.
   - 5-second debounce rate-limiter and strict Indian mobile regex validation (`/^[6-9]\d{9}$/`).
5. **Reverse Tabnabbing Immunity**:
   - Universal `rel="noopener noreferrer"` across all external hyperlinks and programmatic WhatsApp navigators.
6. **OpenGraph WhatsApp Preview (ARCED Standard)**:
   - Full 1200×630 OpenGraph and Twitter card metadata under 300KB specification, generating rich WhatsApp cards with bold titles, descriptions, and thumbnails.

---

## Automated Security Verification

To run the automated 67-point security and integrity test suite:

```bash
node tests/security_audit.test.mjs
```

---

## Local Development

To run locally:

```bash
# Option 1: Python HTTP server
python -m http.server 8090

# Option 2: Node.js npx serve
npx serve .
```

Open `http://localhost:8090` in your browser.

---

## License

Private / Commercial — All rights reserved by Shree Hari Marketing, Pune.
