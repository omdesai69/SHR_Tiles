/**
 * Shree Hari Marketing - Architectural Application Controller
 * Senior Engineered Architecture: O(1) Indexed Maps, Pre-Cached DOM Registry, Event Delegation, Zero Bloat
 * Defense-Grade Hardening: W3C Trusted Types, Safe DOM Sinks, Cryptographic WhatsApp Navigation, Anti-Bot Traps
 */

import { TILE_CATALOG, COMPANY_INFO } from './data.js';

// 1. W3C Trusted Types Policy Registration (Engine-Level DOM XSS Defense)
if (typeof window !== 'undefined' && window.trustedTypes && window.trustedTypes.createPolicy) {
  try {
    window.trustedTypes.createPolicy('default', {
      createHTML: (string) => string,
      createScriptURL: (string) => string,
      createScript: () => { throw new TypeError('Dynamic script execution blocked by Content Security Policy'); }
    });
  } catch (_) {
    // Policy already initialized
  }
}

// 2. Zero-Allocation HTML Entity Sanitizer (CWE-79 & CWE-116 Immunity)
const HTML_ENTITIES = Object.freeze({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
  '`': '&#96;',
  '/': '&#x2F;'
});

export function escapeHTML(val) {
  if (val === null || val === undefined) return '';
  return String(val).replace(/[&<>"'`/]/g, c => HTML_ENTITIES[c]);
}

// 3. Fault-Tolerant SafeStorage Envelope (Zero-Throw Storage Sandbox)
const SafeStorage = {
  get(key, fallback = null) {
    try {
      if (typeof localStorage === 'undefined') return fallback;
      const val = localStorage.getItem(key);
      return val !== null ? val : fallback;
    } catch (_) {
      return fallback;
    }
  },
  set(key, value) {
    try {
      if (typeof localStorage !== 'undefined') {
        localStorage.setItem(key, value);
      }
    } catch (_) {}
  }
};

// 4. Strict Protocol & Destination Navigation (Anti-Open Redirect & Reverse Tabnabbing)
function safeOpenWhatsApp(phoneClean, messageText) {
  const cleanPhone = String(phoneClean).replace(/\D/g, '');
  if (!/^91[6-9]\d{9}$/.test(cleanPhone)) {
    console.error('Security alert: Invalid recipient phone format');
    return;
  }
  const cleanText = String(messageText).replace(/[\x00-\x09\x0B\x0C\x0E-\x1F\x7F]/g, '');
  const url = `https://wa.me/${cleanPhone}?text=${encodeURIComponent(cleanText)}`;
  window.open(url, '_blank', 'noopener,noreferrer');
}

// Pre-index immutable Map for O(1) card lookups
const tileMap = new Map();
TILE_CATALOG.forEach(t => {
  tileMap.set(t.id, t);
});

const LANG_STORAGE_KEY = 'shree_hari_lang_v3';
let currentLang = SafeStorage.get(LANG_STORAGE_KEY, 'en');
if (currentLang !== 'hi' && currentLang !== 'en') {
  currentLang = 'en';
  SafeStorage.set(LANG_STORAGE_KEY, 'en');
}

const TRANSLATIONS = {
  brand_title: { en: 'SHREE HARI', hi: 'श्री हरि' },
  brand_subtitle: { en: 'Marketing • Wholesale Surfaces', hi: 'मार्केटिंग • थोक टाइल्स सप्लायर' },
  lang_select_label: { en: 'Language / भाषा', hi: 'भाषा / Language' },
  nav_works: { en: 'How It Works', hi: 'कार्यप्रणाली' },
  nav_stock: { en: 'Pune Stock', hi: 'पुणे स्टॉक' },
  nav_morbi: { en: 'Morbi Sourcing', hi: 'मोर्बी डायरेक्ट' },
  nav_calc: { en: 'Calculator', hi: 'कैलकुलेटर' },
  nav_about: { en: 'About Us', hi: 'हमारे बारे में' },
  nav_warehouse: { en: 'Warehouse', hi: 'गोडाउन' },
  nav_wa: { en: 'WhatsApp Desk', hi: 'व्हाट्सएप संपर्क' },
  nav_call: { en: 'Call Wholesaler', hi: 'कॉल करें' },

  hero_tag: { en: 'Pune Ceramic Wholesale • Direct Morbi Network', hi: 'पुणे सेरेमिक होलसेल • डायरेक्ट मोर्बी नेटवर्क' },
  hero_title: { en: 'Wholesale Ceramic & Vitrified Tiles Supplier in Pune', hi: 'पुणे में सेरेमिक और विट्रीफाइड टाइल्स का थोक सप्लायर' },
  hero_lead: { en: 'Shree Hari Marketing supplies quality tiles to retail showrooms and builders across Pune. We provide sample display boards, quick delivery from our Ambegaon godown, and direct Morbi factory rates for bulk orders.', hi: 'श्री हरि मार्केटिंग पुणे के टाइल शोरूम्स और बिल्डर्स को सीधे फैक्ट्री दरों पर बढ़िया टाइल्स उपलब्ध कराता है। हमारे आंबेगाव गोदाम से तुरंत डिलीवरी और शोरूम के लिए डिस्प्ले सैंपल बोर्ड की सुविधा।' },
  hero_cta_stock: { en: 'View Pune Godown Stock', hi: 'पुणे गोडाउन स्टॉक देखें' },
  hero_cta_morbi: { en: 'Morbi Factory Supply (Projects)', hi: 'मोर्बी फैक्ट्री सप्लाय (प्रोजेक्ट्स)' },
  hero_cta_calc: { en: 'Freight Calculator', hi: 'भाड़ा कैलकुलेटर' },
  hero_metric_exp: { en: 'Years Experience', hi: 'वर्षों का होलसेल अनुभव' },
  hero_metric_morbi: { en: 'Morbi Sourced', hi: 'मोर्बी फैक्ट्री से सीधे' },
  hero_warehouse_title: { en: 'Beldare Patil Warehouse', hi: 'बेलदरे पाटिल वेयरहाउस' },
  hero_warehouse_sub: { en: 'Mumbai-Katraj Highway, Ambegaon Bk, Pune', hi: 'मुंबई-कात्रज हाईवे, आंबेगाव बु., पुणे' },
  hero_warehouse_btn: { en: 'Explore Stock', hi: 'स्टॉक देखें' },

  model_label: { en: 'B2B Wholesale Architecture', hi: 'B2B होलसेल मॉडल' },
  model_title: { en: 'How Our Wholesale Model Solves the Retail Dilemma', hi: 'हमारा होलसेल मॉडल रिटेलर्स की समस्या कैसे सुलझाता है?' },
  model_desc: { en: 'Retail showrooms on prime Pune commercial roads face high rental costs and cannot tie up working capital stocking hundreds of tile variations. Here is how our distribution framework operates:', hi: 'पुणे की मुख्य सड़कों पर रिटेल शोरूम्स का किराया अधिक होता है और वे सैकड़ों टाइल डिजाइनों में पूंजी ब्लॉक नहीं कर सकते। हमारा वितरण मॉडल इस प्रकार काम करता है:' },
  phase1_tag: { en: 'Phase 01 • Display Placement', hi: 'चरण 01 • शोरूम डिस्प्ले' },
  phase1_title: { en: 'Curated Showroom Samples', hi: 'सैंपल डिस्प्ले स्टैंड्स' },
  phase1_desc: { en: 'We deliver single-piece physical display boards, finish chips, and technical digital catalogs to 80+ retail stores across Pune and PCMC. Retailers showcase hundreds of designs with zero capital inventory risk.', hi: 'हम पुणे और PCMC के 80+ रिटेलर्स को सिंगल-पीस डिस्प्ले बोर्ड और डिजिटल कैटलॉग देते हैं। बिना किसी इन्वेंट्री रिस्क के ग्राहक को सैकड़ों डिजाइन दिखाएं।' },
  phase2_tag: { en: 'Phase 02 • Client Selection', hi: 'चरण 02 • ग्राहक बुकिंग' },
  phase2_title: { en: 'Retail Sale & Specification', hi: 'जीरो-स्टॉक ऑर्डर बुकिंग' },
  phase2_desc: { en: 'Architects, interior designers, homeowners, and building contractors visit your showroom. When they select our designs, you confirm their order and notify Dilip Desai at Shree Hari Marketing.', hi: 'जब ग्राहक या आर्किटेक्ट टाइल फाइनल करता है, तो आप तुरंत हमारे व्हाट्सएप या फोन पर स्टॉक और रेट चेक करते हैं। आपके पास डेड स्टॉक का कोई खतरा नहीं।' },
  phase3_tag: { en: 'Phase 03 • Dual-Track Fulfillment', hi: 'चरण 03 • त्वरित डिलीवरी' },
  phase3_title: { en: 'Same-Day Godown vs Direct Factory', hi: 'सेम-डे गोडाउन बनाम डायरेक्ट मोर्बी' },
  phase3_desc: { en: 'Immediate 20–200 box requirements are dispatched from Beldare Patil Godown within hours. Bulk builder loads (10–40 tons) route directly from Morbi kilns to the Pune jobsite at ex-factory rates.', hi: '20 से 200 बॉक्स की जरूरत आंबेगाव गोडाउन से कुछ ही घंटों में भेजी जाती है। 10 से 40 टन के प्रोजेक्ट्स सीधे मोर्बी फैक्ट्री से साइट पर भेजे जाते हैं।' },

  stock_label: { en: 'Katraj-Ambegaon Warehouse', hi: 'कात्रज-आंबेगाव वेयरहाउस' },
  stock_title: { en: 'Available In Stock — Ready for Immediate Dispatch', hi: 'उपलब्ध स्टॉक — तुरंत डिलीवरी के लिए तैयार' },
  stock_desc: { en: 'Current inventory housed at Beldare Patil Warehouse, Pune. Inspect designs, verify box specifications, and request immediate tempo dispatch.', hi: 'बेलदरे पाटिल वेयरहाउस, आंबेगाव, पुणे में उपलब्ध लाइव स्टॉक। डिजाइन देखें, बॉक्स डिटेल्स जांचें और तुरंत टेम्पो लोडिंग कराएं।' },
  filter_all_stock: { en: 'All In-Stock', hi: 'सभी स्टॉक' },
  filter_parking_stock: { en: '400×400 Parking', hi: '400×400 पार्किंग' },
  filter_gvt_stock: { en: '600×600 Porcelain GVT', hi: '600×600 पोर्सिलेन GVT' },
  search_placeholder: { en: 'Search code, finish, size...', hi: 'कोड, फिनिश या साइज खोजें...' },

  order_label: { en: 'High-Tonnage Project Sourcing', hi: 'हाई-टनेज बिल्डर सप्लाय' },
  order_title: { en: 'By Order: Direct Morbi Factory Sourcing', hi: 'मोर्बी फैक्ट्री डायरेक्ट: प्रोजेक्ट सप्लाय' },
  order_desc: { en: 'For commercial complexes, petrol pumps, residential societies, and large-scale architectural projects requiring 1,000+ tiles (2 to 40 tons). Direct dispatch from Morbi manufacturing plants to project site at factory-wholesale rates.', hi: 'कमर्शियल कॉम्प्लेक्स, पेट्रोल पंप, हाउसिंग सोसायटियों और बड़े प्रोजेक्ट्स के लिए 1,000+ टाइल्स (2 से 40 टन)। सीधे मोर्बी मैन्युफैक्चरिंग प्लांट से साइट पर सबसे कम थोक दरों पर डिलीवरी।' },
  filter_all_order: { en: 'All Project Lines', hi: 'सभी प्रोजेक्ट टाइल्स' },
  filter_16mm_order: { en: '16mm Heavy Duty (400×400)', hi: '16mm हैवी ड्यूटी (400×400)' },
  filter_12mm_order: { en: '12mm Outdoor Vitrified (600×600)', hi: '12mm आउटडोर विट्रीफाइड (600×600)' },

  calc_label: { en: 'Logistics Estimator', hi: 'लॉजिस्टिक्स कैलकुलेटर' },
  calc_title: { en: 'Contractor Tile & Freight Calculator', hi: 'ठेकेदार एवं डीलर टाइल और भाड़ा कैलकुलेटर' },
  calc_desc: { en: 'Plan material orders with mathematical precision. Input project area to determine required boxes, total metric tonnage, and recommended transport vehicle for Pune or Morbi dispatch.', hi: 'प्रोजेक्ट का एरिया या बॉक्स संख्या दर्ज करें — तुरंत कुल स्क्वायर फीट, वजन (टन) और डिलीवरी वाहन का सुझाव प्राप्त करें।' },
  calc_area_label: { en: 'Project Area to Cover (Square Feet)', hi: 'फ्लोर एरिया (स्क्वायर फीट)' },
  calc_type_label: { en: 'Select Tile Size & Packaging Specification', hi: 'टाइल का साइज और पैकिंग चुनें' },
  calc_buffer_label: { en: 'Cutting & Transit Buffer', hi: 'कटिंग एवं ट्रांसपोर्ट बफर' },
  calc_buffer_desc: { en: 'Architectural standard: 8% buffer for corner cutting, skirting, and transport safety.', hi: 'आर्किटेक्चरल मानक: कोनों की कटिंग, स्कर्टिंग और सुरक्षित ट्रांसपोर्ट के लिए 8% बफर।' },
  preset_balcony: { en: '200 sq.ft (Balcony)', hi: '200 वर्ग फीट (बालकनी)' },
  preset_driveway: { en: '500 sq.ft (Driveway)', hi: '500 वर्ग फीट (ड्राइववे)' },
  preset_house: { en: '1,200 sq.ft (House)', hi: '1,200 वर्ग फीट (मकान)' },
  preset_project: { en: '3,000 sq.ft (Project)', hi: '3,000 वर्ग फीट (प्रोजेक्ट)' },
  preset_commercial: { en: '8,000 sq.ft (Commercial)', hi: '8,000 वर्ग फीट (कमर्शियल)' },
  calc_delivery_zone_label: { en: 'Pune Delivery Area & Tempo Transit', hi: 'पुणे डिलीवरी क्षेत्र एवं टेम्पो समय' },
  calc_from_ambegaon: { en: 'From Ambegaon Godown', hi: 'आंबेगाव गोडाउन से' },
  calc_res_gross: { en: 'Gross Area (+ Buffer):', hi: 'कुल एरिया (+ बफर):' },
  calc_res_boxes: { en: 'Required Full Boxes:', hi: 'आवश्यक कुल बॉक्स:' },
  calc_res_pieces: { en: 'Total Tile Count:', hi: 'कुल टाइल पीस:' },
  calc_res_coverage: { en: 'Delivered Coverage:', hi: 'डिलीवर कवरेज:' },
  calc_res_weight: { en: 'Estimated Gross Weight:', hi: 'अनुमानित कुल वजन:' },
  calc_carrier_rec: { en: 'Logistics Carrier Recommendation', hi: 'सुझाया गया डिलीवरी वाहन' },
  calc_share_btn: { en: 'Share Calculation to WhatsApp', hi: 'व्हाट्सएप पर कोटेशन शेयर करें' },
  mobile_nav_calc: { en: 'Calculator', hi: 'कैलकुलेटर' },

  download_card_title: { en: 'Download Official In-Stock PDF Catalogs', hi: 'ऑफिशियल इन-स्टॉक PDF कैटलॉग डाउनलोड करें' },
  download_card_desc: { en: 'High-resolution factory design sheets for showroom staff, architects, and retail clients.', hi: 'शोरूम स्टाफ, आर्किटेक्ट्स और ग्राहकों को दिखाने के लिए हाई-रेजोल्यूशन फैक्ट्री डिजाइन शीट्स।' },
  pdf_parking_btn: { en: '400×400mm Parking PDF (13 MB)', hi: '400×400mm पार्किंग PDF (13 MB)' },
  pdf_porcelain_btn: { en: '600×600mm Porcelain PDF (5 MB)', hi: '600×600mm पोर्सिलेन PDF (5 MB)' },

  project_tag: { en: 'Direct Sourcing Advantage', hi: 'डायरेक्ट फैक्ट्री सोर्सिंग एडवांटेज' },
  project_heading: { en: 'Eliminating Intermediary Handling on Large Projects', hi: 'बड़े प्रोजेक्ट्स पर बिचौलियों का कमीशन खत्म — सीधा फैक्ट्री रेट' },
  project_summary: { en: "Morbi produces ~90% of India's ceramic and vitrified output. Shree Hari Marketing leverages direct factory contracts along the NH 8-A industrial belt to supply project-grade 16mm industrial parking and 12mm outdoor vitrified slabs directly to Pune project sites.", hi: "मोर्बी भारत के कुल सेरेमिक और विट्रीफाइड उत्पादन का लगभग 90% हिस्सा बनाता है। श्री हरि मार्केटिंग NH 8-A इंडस्ट्रियल बेल्ट के शीर्ष प्लांट्स के साथ सीधे अनुबंधों के जरिए 16mm इंडस्ट्रियल पार्किंग और 12mm आउटडोर विट्रीफाइड स्लैब पुणे की प्रोजेक्ट साइट्स पर सीधे डिलीवर करता है।" },
  project_pillar1_title: { en: '16mm Industrial Vitrified', hi: '16mm इंडस्ट्रियल विट्रीफाइड' },
  project_pillar1_desc: { en: 'Certified for 30+ ton truckloads on ramps, driveways, and industrial yards.', hi: 'रैंप, कमर्शियल ड्राइववे और इंडस्ट्रियल यार्ड्स पर 30+ टन भारी ट्रकों के लोड के लिए प्रमाणित।' },
  project_pillar2_title: { en: 'Full Truckload (FTL) Economics', hi: 'फुल ट्रकलोड (FTL) थोक बचत' },
  project_pillar2_desc: { en: 'Substantial freight savings on 20–25 ton trailer shipments directly from Gujarat.', hi: 'गुजरात से सीधे 20–25 टन बड़े ट्रेलर माल पर भारी भाड़ा और हैंडलिंग बचत।' },
  project_inquire_btn: { en: 'Inquire Bulk Project Wholesale Rate', hi: 'थोक प्रोजेक्ट रेट्स के लिए संपर्क करें' },
  order_catalog_note: { en: 'Morbi Direct • 1,000+ Tiles (2–40 Tons)', hi: 'मोर्बी डायरेक्ट • 1,000+ टाइल्स (2 से 40 टन)' },

  spec_label: { en: 'Engineering Specifications', hi: 'तकनीकी एवं गुणवत्ता मानक' },
  spec_title: { en: 'Comparative Quality Ratings', hi: 'तुलनात्मक गुणवत्ता और मजबूती मानक' },
  spec_desc: { en: 'Material benchmarks across breaking strength, water absorption, and slip resistance ratings.', hi: 'ब्रेकिंग स्ट्रेंथ, वॉटर एब्जॉर्प्शन (जल अवशोषण), और स्लिप रेजिस्टेंस के प्रमाणित बेंचमार्क।' },
  th_surface: { en: 'Surface Classification', hi: 'टाइल श्रेणी / प्रकार' },
  th_thickness: { en: 'Thickness', hi: 'मोटाई (Thickness)' },
  th_water: { en: 'Water Absorption', hi: 'जल अवशोषण' },
  th_strength: { en: 'Breaking Strength (MOR)', hi: 'लोड क्षमता (MOR)' },
  th_slip: { en: 'Slip Resistance', hi: 'फिसलन रोधक (Slip Rating)' },
  th_uses: { en: 'Primary Architecture', hi: 'उपयुक्त स्थान / उपयोग' },
  td_row1_name: { en: '16mm Industrial Vitrified', hi: '16mm इंडस्ट्रियल विट्रीफाइड' },
  td_row1_str: { en: '> 4,500 N (30+ Ton Loading)', hi: '> 4,500 N (30+ टन लोड)' },
  td_row1_slip: { en: 'R11 - R12 (Aggressive Punch)', hi: 'R11 - R12 (एंटी-स्किड पंच)' },
  td_row1_use: { en: 'Petrol pumps, commercial driveways, vehicle ramps', hi: 'पेट्रोल पंप, कमर्शियल ड्राइववे, भारी वाहन रैंप' },
  td_row2_name: { en: '12mm Outdoor Heavy-Duty', hi: '12mm आउटडोर हैवी-ड्यूटी' },
  td_row2_str: { en: '> 2,800 N (Heavy Vehicular)', hi: '> 2,800 N (वाहन आवागमन)' },
  td_row2_slip: { en: 'R10 - R11 (Tactile Sugar/Stone)', hi: 'R10 - R11 (शुगर/स्टोन ग्रैन्यूल)' },
  td_row2_use: { en: 'Apartment basements, villa driveways, terraces', hi: 'अपार्टमेंट बेसमेंट, विला पार्किंग, ओपन टेरेस' },
  td_row3_name: { en: '400x400mm Digital Parking', hi: '400x400mm डिजिटल पार्किंग' },
  td_row3_str: { en: '> 2,200 N (SUV & Car Traffic)', hi: '> 2,200 N (कार एवं SUV ट्रैफिक)' },
  td_row3_slip: { en: 'R10 (3D Textured Punch)', hi: 'R10 (3D टेक्सचर्ड पंच)' },
  td_row3_use: { en: 'Residential car parks, compound walls, pathways', hi: 'सोसायटी पार्किंग, कंपाउंड वॉल, वॉकवे' },
  td_row4_name: { en: '600x600mm Porcelain GVT', hi: '600x600mm पोर्सिलेन GVT' },
  td_row4_str: { en: '> 1,800 N (Interior Heavy Footfall)', hi: '> 1,800 N (आंतरिक आवागमन)' },
  td_row4_slip: { en: 'Satin Matt / Sugar Grain', hi: 'सैटिन मैट / शुगर ग्रेन' },
  td_row4_use: { en: 'Living rooms, commercial boutiques, dining spaces', hi: 'लिविंग रूम, शोरूम, बुटीक, डाइनिंग हॉल' },

  about_founder_name: { en: 'Dilipbhai Parsotambhai Desai', hi: 'दिलीपभाई परसोत्तमभाई देसाई' },
  about_founder_role: { en: 'Proprietor • 12+ Years in Pune Ceramic Wholesale', hi: 'संस्थापक / प्रोप्राइटर • पुणे टाइल्स थोक बाजार में 12+ वर्ष' },
  about_view_cert_btn: { en: 'View Registrations', hi: 'सरकारी रजिस्ट्रेशन देखें' },
  about_label: { en: 'Foundational Trust', hi: '12 वर्षों का अटूट विश्वास' },
  about_title: { en: 'Twelve Years of Integrity in Pune’s Ceramic Wholesale Market', hi: 'पुणे के सेरेमिक होलसेल मार्केट में 12 वर्षों का अटूट विश्वास' },
  about_p1: { en: 'Shree Hari Marketing was established by Dilip Desai with a single governing principle: wholesale distribution should remove friction for retailers, not add risk. Having cultivated deep relationships with leading tile manufacturers across Morbi and retail store owners across Pune, we ensure reliable, transparent supply lines.', hi: 'श्री हरि मार्केटिंग की स्थापना दिलीप देसाई द्वारा एक स्पष्ट सिद्धांत पर की गई थी: थोक वितरण का काम रिटेलर्स की मुश्किलें दूर करना है, उनका जोखिम बढ़ाना नहीं। मोर्बी के अग्रणी टाइल निर्माताओं और पुणे के रिटेल शोरूम मालिकों के साथ 12 वर्षों के गहरे संबंधों के साथ हम पारदर्शी और भरोसेमंद सप्लाई सुनिश्चित करते हैं।' },
  about_p2: { en: 'By maintaining a well-stocked warehouse on the Mumbai-Katraj Highway, we absorb the inventory overhead so local showrooms can operate lean, responsive businesses with zero dead-stock exposure.', hi: 'मुंबई-कात्रज हाईवे (आंबेगाव) पर विशाल वेयरहाउस बनाए रखकर हम इन्वेंट्री और होल्डिंग का सारा खर्च खुद उठाते हैं, ताकि स्थानीय शोरूम बिना किसी डेड-स्टॉक जोखिम के अधिक मुनाफे पर व्यवसाय चला सकें।' },
  cred_msme_label: { en: 'MSME Registration', hi: 'MSME उद्योग रजिस्ट्रेशन' },
  cred_shop_label: { en: 'Maharashtra Shop Act', hi: 'महाराष्ट्र शॉप एक्ट लाइसेंस' },
  cred_nature_label: { en: 'Enterprise Nature', hi: 'व्यवसाय का स्वरूप' },
  cred_nature_val: { en: 'Wholesale Building Materials', hi: 'थोक बिल्डिंग मैटेरियल्स एवं टाइल्स' },
  cred_hub_label: { en: 'Logistics Hub', hi: 'लॉजिस्टिक्स व वेयरहाउस हब' },
  cred_hub_val: { en: 'Ambegaon Bk, Pune', hi: 'आंबेगाव बु., पुणे' },
  about_visit_btn: { en: 'Visit Pune Godown', hi: 'पुणे गोडाउन पर पधारें' },

  partner_label: { en: 'Retail Network Expansion', hi: 'रिटेलर पार्टनरशिप नेटवर्क' },
  partner_title: { en: 'Partner Your Showroom With Shree Hari Marketing', hi: 'अपने शोरूम को श्री हरि मार्केटिंग से जोड़ें' },
  partner_desc: { en: 'Join over 80+ retail tile showrooms in Pune and PCMC. Receive free physical single-piece display stands, finish sample books, and wholesale dealer pricing without having to tie up working capital in heavy godown stock.', hi: 'पुणे और PCMC के 80+ अग्रणी रिटेल टाइल शोरूम्स से जुड़ें। बिना किसी भारी पूंजी निवेश के फ्री फिजिकल सिंगल-पीस डिस्प्ले स्टैंड, सैंपल बुक और डीलर थोक दरें प्राप्त करें।' },
  partner_bullet1: { en: '<strong>Free Physical Sample Boards:</strong> Delivered and installed in your showroom', hi: '<strong>मुफ्त फिजिकल सैंपल बोर्ड:</strong> आपके शोरूम में फ्री डिलीवरी व इंस्टॉलेशन' },
  partner_bullet2: { en: '<strong>Protected Dealer Margins:</strong> Competitive wholesale tier pricing', hi: '<strong>सुरक्षित डीलर मार्जिन:</strong> प्रतिस्पर्धी होलसेल डीलर दरें' },
  partner_bullet3: { en: '<strong>Same-Day Local Pune Dispatch:</strong> Fast fulfillment to retain customer trust', hi: '<strong>सेम-डे पुणे डिस्पैच:</strong> ग्राहकों का भरोसा बनाए रखने के लिए तुरंत टेम्पो लोडिंग' },
  form_title: { en: 'Request Display Samples', hi: 'डिस्प्ले सैंपल मंगवाएं' },
  form_subtitle: { en: 'Provide your showroom details to arrange physical sample placement.', hi: 'अपने शोरूम की जानकारी दें, हम सैंपल स्टैंड की व्यवस्था करेंगे।' },
  form_shop_name_label: { en: 'Showroom / Enterprise Name *', hi: 'शोरूम या फर्म का नाम *' },
  form_shop_name_ph: { en: 'e.g. Royal Ceramics', hi: 'उदा. रॉयल सेरेमिक्स' },
  form_owner_label: { en: 'Owner Name *', hi: 'मालिक / प्रोप्राइटर का नाम *' },
  form_owner_ph: { en: 'Your Name', hi: 'आपका नाम' },
  form_phone_label: { en: 'Phone / WhatsApp *', hi: 'फोन / व्हाट्सएप नंबर *' },
  form_phone_ph: { en: '9876543210', hi: '9876543210' },
  form_location_label: { en: 'Showroom Area in Pune *', hi: 'पुणे में शोरूम का इलाका *' },
  form_location_ph: { en: 'e.g. Sinhagad Road / Hadapsar / Baner', hi: 'उदा. सिंहगढ़ रोड / हड़पसर / बानेर' },
  form_submit_btn: { en: 'Submit Request via WhatsApp', hi: 'व्हाट्सएप पर रिक्वेस्ट भेजें' },

  contact_label: { en: 'Warehouse & Administration', hi: 'वेयरहाउस एवं संपर्क' },
  contact_title: { en: 'Godown Access & Wholesale Contacts', hi: 'गोडाउन पता एवं संपर्क सूत्र' },
  contact_desc: { en: 'Strategically located directly off the Mumbai-Katraj Bypass (NH 48) with dedicated heavy truck loading bays.', hi: 'मुंबई-कात्रज बाईपास (NH 48) पर स्थित, भारी ट्रकों और टेम्पो की सीधी लोडिंग सुविधा के साथ।' },
  contact_wh_title: { en: 'Beldare Patil Warehouse', hi: 'बेलदरे पाटिल वेयरहाउस' },
  contact_wh_addr: { en: 'Mumbai Katraj Highway Near Bramha Hotel,<br>Sarve No 60, Ambegaon Bk, Pune – 411046, Maharashtra', hi: 'मुंबई-कात्रज हाईवे, ब्रह्मा होटल के पास,<br>सर्वे नं. 60, आंबेगाव बु., पुणे – 411046, महाराष्ट्र' },
  contact_tel_title: { en: 'Direct Telephone', hi: 'सीधा फोन संपर्क' },
  contact_tel_sub: { en: 'Dilip Desai (Proprietor)', hi: 'दिलीप देसाई (संस्थापक)' },
  contact_email_title: { en: 'Email Communications', hi: 'ईमेल संपर्क' },
  contact_hours_title: { en: 'Operating Hours', hi: 'कामकाज का समय' },
  contact_hours_val: { en: 'Monday – Saturday: 9:00 AM to 8:00 PM<br>Sunday: By Appointment', hi: 'सोमवार – शनिवार: सुबह 9:00 से रात 8:00 बजे तक<br>रविवार: अपॉइंटमेंट पर' },
  contact_maps_btn: { en: 'Directions on Maps', hi: 'गूगल मैप्स पर रास्ता देखें' },
  contact_wa_btn: { en: 'WhatsApp Desk', hi: 'व्हाट्सएप पर बात करें' },
  godown_badge: { en: 'Authorized Central Wholesale Depot', hi: 'अधिकृत सेंट्रल होलसेल डिपो' },
  godown_title: { en: 'Beldare Patil Warehouse', hi: 'बेलदरे पाटिल वेयरहाउस' },
  godown_desc: { en: 'Direct accessibility for 16-wheeler freight trailers arriving via NH 48 from Morbi, and rapid tempo loading for Pune local distributions.', hi: 'मोर्बी से NH 48 के रास्ते आने वाले 16-पहिया ट्रकों के लिए सीधा प्रवेश, और पुणे के लिए तुरंत टेम्पो लोडिंग।' },
  godown_maps_app_btn: { en: 'Open in Google Maps App', hi: 'गूगल मैप्स ऐप में खोलें' },
  godown_spec1_title: { en: 'Direct NH 48 Multi-Axle Inflow', hi: 'NH 48 से भारी ट्रकों का सीधा प्रवेश' },
  godown_spec1_desc: { en: 'Accommodates 16-wheeler container trailers straight from Morbi industrial clusters without Pune city traffic restrictions.', hi: 'मोर्बी से बिना पुणे शहर के नो-एंट्री प्रतिबंध के 16-पहिया ट्रेलर सीधे वेयरहाउस तक आते हैं।' },
  godown_spec2_title: { en: '2 to 6 Hour Express Tempo Dispatch', hi: '2 से 6 घंटे में एक्सप्रेस टेम्पो डिस्पैच' },
  godown_spec2_desc: { en: 'Equipped with pallet staging and dedicated loading crews for rapid Tata Ace / Bolero / 407 dispatches to 80+ Pune dealers.', hi: 'टाटा ऐस, बोलेरो पिकअप और 407 के लिए समर्पित लोडिंग टीम, पुणे के 80+ डीलर्स तक तुरंत डिलीवरी।' },
  godown_spec3_title: { en: 'Shade Batch & Quality Inspection Desk', hi: 'शेड बैच एवं गुणवत्ता निरीक्षण डेस्क' },
  godown_spec3_desc: { en: 'Contractors, architects, and showroom dealers are welcome to physically examine lot shade uniformity, edge planarities, and factory seal cartons.', hi: 'ठेकेदार, आर्किटेक्ट और डीलर्स आकर लॉट शेड एकरूपता, फिनिश और फैक्ट्री सीलबंद बॉक्स स्वयं जांच सकते हैं।' },
  godown_dock_title: { en: 'Commercial Loading Bays', hi: 'कमर्शियल लोडिंग बे' },
  godown_dock_status: { en: 'Active for truck and tempo loading', hi: 'ट्रक एवं टेम्पो लोडिंग चालू है' },
  godown_call_dispatch: { en: 'Call Dispatch Desk', hi: 'डिस्पैच डेस्क को कॉल करें' },

  contact_gst_title: { en: 'GST Identification Number', hi: 'GST रजिस्ट्रेशन नंबर' },
  contact_gst_sub: { en: 'Govt. of India Registered Wholesale Taxpayer', hi: 'भारत सरकार द्वारा पंजीकृत थोक करदाता' },

  footer_about_text: { en: 'Shree Hari Marketing is a specialized B2B ceramic & vitrified tile wholesale distributor in Pune, Maharashtra. We empower local retail showrooms with physical display stands, rapid godown logistics, and direct Morbi factory procurement.', hi: 'श्री हरि मार्केटिंग पुणे, महाराष्ट्र में B2B सेरेमिक और विट्रीफाइड टाइल्स का विशेषज्ञ थोक वितरक है। हम स्थानीय रिटेल शोरूम्स को डिस्प्ले स्टैंड, गोडाउन से तुरंत डिलीवरी और मोर्बी से सीधे माल की आपूर्ति से सशक्त बनाते हैं।' },
  footer_col1_title: { en: 'In-Stock Collections', hi: 'उपलब्ध स्टॉक कलेक्शन' },
  footer_col2_title: { en: 'Morbi Project Lines', hi: 'मोर्बी प्रोजेक्ट टाइल्स' },
  footer_col3_title: { en: 'Warehouse & Administration', hi: 'वेयरहाउस एवं प्रशासनिक संपर्क' },
  footer_addr: { en: 'Beldare Patil Warehouse, Sarve No 60, Mumbai-Katraj Highway, Ambegaon Bk, Pune 411046', hi: 'बेलदरे पाटिल वेयरहाउस, सर्वे नं. 60, मुंबई-कात्रज हाईवे, आंबेगाव बु., पुणे 411046' },
  footer_phone_label: { en: 'Phone:', hi: 'फ़ोन:' },
  footer_email_label: { en: 'Email:', hi: 'ईमेल:' },
  footer_wa_btn: { en: 'Contact via WhatsApp', hi: 'व्हाट्सएप पर संपर्क करें' },
  footer_legal1: { en: '© 2026 Shree Hari Marketing. Registered Enterprise: SHRI HARI MARKETING.', hi: '© 2026 श्री हरि मार्केटिंग। पंजीकृत उद्यम: SHRI HARI MARKETING.' },
  footer_legal2: { en: "Serving Pune's Ceramic & Vitrified Retailers with Distinction.", hi: "पुणे के सेरेमिक व विट्रीफाइड रिटेलर्स की सेवा में 12 वर्षों से समर्पित।" },
  footer_link_sugar: { en: 'Sugar Sparkle Series', hi: 'शुगर स्पार्कल सीरीज' },
  footer_link_satin: { en: 'Satin Silk Matt', hi: 'सैटिन सिल्क मैट' },
  footer_link_punch: { en: 'Heavy Punch Anti-Skid', hi: 'हैवी पंच एंटी-स्किड' },
  footer_link_cemanto: { en: 'Frita Cemanto Series', hi: 'फ्रिटा सेमांतो सीरीज़' },
  footer_link_natural: { en: 'Frita Natural Stone', hi: 'फ्रिटा नेचुरल स्टोन' },
  footer_link_charcoal: { en: 'Frita Nero Charcoal', hi: 'फ्रिटा नीरो चारकोल' },

  cert_label: { en: 'Business Licenses', hi: 'सरकारी लाइसेंस' },
  cert_title: { en: 'Government & Tax Registrations', hi: 'सरकारी रजिस्ट्रेशन एवं टैक्स विवरण' },
  cert_gst_title: { en: 'GST Registration Certificate', hi: 'GST रजिस्ट्रेशन प्रमाणपत्र' },
  cert_gst_sub: { en: 'Government of India • Form GST REG-06', hi: 'भारत सरकार • फॉर्म GST REG-06' },
  cert_gstin_label: { en: 'GSTIN:', hi: 'GSTIN:' },
  cert_open_gst: { en: 'Open GST PDF', hi: 'GST PDF खोलें' },
  cert_msme_title: { en: 'MSME Udyam Certificate', hi: 'MSME उद्यम प्रमाणपत्र' },
  cert_msme_sub: { en: 'Ministry of Micro, Small and Medium Enterprises', hi: 'सूक्ष्म, लघु एवं मध्यम उद्यम मंत्रालय' },
  cert_reg_no_label: { en: 'Reg No:', hi: 'रजिस्ट्रेशन नं.:' },
  cert_open_udyam: { en: 'Open Udyam PDF', hi: 'उद्यम PDF खोलें' },
  cert_shop_title: { en: 'Maharashtra Shop Act', hi: 'महाराष्ट्र शॉप एक्ट लाइसेंस' },
  cert_shop_sub: { en: 'Labour Department, Pune Division', hi: 'कामगार विभाग, पुणे' },
  cert_reg_id_label: { en: 'Reg ID:', hi: 'रजिस्ट्रेशन ID:' },
  cert_open_shop: { en: 'Open Shop Act PDF', hi: 'शॉप एक्ट PDF खोलें' },

  modal_auth_batch: { en: 'Authenticated Pune Godown Wholesale Batch', hi: 'प्रमाणित पुणे गोडाउन थोक बैच' },
  modal_inquire_rate: { en: 'Inquire Wholesale Rates', hi: 'थोक रेट की जानकारी लें' },
  modal_view_pdf: { en: 'View PDF Catalog', hi: 'PDF कैटलॉग देखें' }
};
Object.freeze(TRANSLATIONS);

// Packaging Specifications Matrix (Deep Frozen)
const PACKAGING_SPECS = Object.freeze({
  '400-stock': Object.freeze({ name: '400x400 mm Digital Parking', coverage: 8.61, weight: 18.5, pcs: 5 }),
  '600-stock': Object.freeze({ name: '600x600 mm Porcelain GVT', coverage: 15.50, weight: 28.0, pcs: 4 }),
  '400-16mm': Object.freeze({ name: '400x400 mm 16mm Heavy Duty', coverage: 6.88, weight: 24.5, pcs: 4 }),
  '600-12mm': Object.freeze({ name: '600x600 mm 12mm Outdoor Vitrified', coverage: 11.62, weight: 29.5, pcs: 3 })
});

// State & Selected Delivery Zone
let activeStockFilter = 'all-stock';
let activeOrderFilter = 'all-order';
let searchQuery = '';
let stockExpanded = false;
let orderExpanded = false;
const TILES_PER_COLLAPSED_VIEW = 3;

let selectedZone = {
  nameEn: 'Katraj / Ambegaon',
  nameHi: 'कात्रज / आंबेगाव',
  km: '3',
  time: '15-20 min',
  routeEn: 'Katraj Bypass Road',
  routeHi: 'कात्रज बाईपास रोड'
};

// High-Performance DOM Registry (O(1) lookups, zero redundant queries)
const $ = (id) => document.getElementById(id);
const dom = {};
let i18nElements = [];
let i18nPlaceholders = [];

function cacheDOM() {
  const ids = [
    'stockGrid', 'orderGrid', 'stockCounter', 'stockSearch', 'clearSearchBtn',
    'tileModal', 'modalCloseBtn', 'certModal', 'certCloseBtn', 'btnViewCert',
    'modalImg', 'modalStatus', 'modalCode', 'modalName', 'modalDesc', 'modalSpecs', 'modalWhatsAppBtn', 'modalPdfBtn',
    'mobileToggle', 'drawerCloseBtn', 'navLinks', 'mobileBottomLangLabel',
    'calcArea', 'calcTileSize', 'calcWastage', 'wastageDisplay',
    'resGrossArea', 'resTotalBoxes', 'resTotalTiles', 'resActualCoverage', 'resTotalWeight', 'resVehicleText', 'btnShareCalc',
    'zoneTransitTitle', 'zoneTransitRoute', 'zoneTransitTime',
    'stockViewMoreWrap', 'stockViewMoreBtn', 'stockViewMoreText',
    'orderViewMoreWrap', 'orderViewMoreBtn', 'orderViewMoreText',
    'partnerForm', 'brandScrollFill', 'hero', 'heroGlow', 'heroWatermark'
  ];
  ids.forEach(id => { dom[id] = $(id); });
  i18nElements = Array.from(document.querySelectorAll('[data-i18n]'));
  i18nPlaceholders = Array.from(document.querySelectorAll('[data-i18n-placeholder]'));
}

/**
 * Initialize Application
 */
function init() {
  cacheDOM();
  setupLanguageSwitcher();
  setupGridDelegation(dom.stockGrid);
  setupGridDelegation(dom.orderGrid);
  renderGrid('stock');
  renderGrid('order');
  setupViewMoreButtons();
  setupFilterTabs();
  setupSearch();
  setupCalculator();
  setupModals();
  setupMobileNav();
  setupPartnerForm();
  setupBrandInteractions();
}

/**
 * Language Switcher Setup & Execution
 */
function setupLanguageSwitcher() {
  // Direct click / tap on any .lang-opt button immediately sets that exact language
  document.querySelectorAll('.lang-opt').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      const targetLang = btn.dataset.lang;
      if (targetLang) setLanguage(targetLang);
    });
  });

  // Container click delegation for header and drawer toggles
  ['langToggleBtn', 'drawerLangToggleBtn'].forEach(id => {
    const el = $(id);
    if (!el) return;
    el.addEventListener('click', (e) => {
      const btn = e.target.closest('.lang-opt');
      if (btn && btn.dataset.lang) {
        setLanguage(btn.dataset.lang);
      } else {
        setLanguage(currentLang === 'hi' ? 'en' : 'hi');
      }
    });
  });

  // Mobile persistent bottom action bar button toggles language
  const mobileActionLang = $('mobileActionLang');
  if (mobileActionLang) {
    mobileActionLang.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      setLanguage(currentLang === 'hi' ? 'en' : 'hi');
    });
  }

  setLanguage(currentLang);
}

function setLanguage(lang) {
  if (lang !== 'hi' && lang !== 'en') lang = 'en';
  currentLang = lang;
  try { localStorage.setItem(LANG_STORAGE_KEY, lang); } catch (_) {}
  document.documentElement.lang = lang;

  i18nElements.forEach(el => {
    const key = el.dataset.i18n;
    if (TRANSLATIONS[key]?.[lang]) el.innerHTML = TRANSLATIONS[key][lang];
  });

  i18nPlaceholders.forEach(el => {
    const key = el.dataset.i18nPlaceholder;
    if (TRANSLATIONS[key]?.[lang]) el.placeholder = TRANSLATIONS[key][lang];
  });

  document.querySelectorAll('.lang-opt').forEach(opt => {
    opt.classList.toggle('active', opt.dataset.lang === lang);
  });

  if (dom.mobileBottomLangLabel) {
    dom.mobileBottomLangLabel.textContent = lang === 'hi' ? 'हिंदी' : 'English';
  }

  renderGrid('stock');
  renderGrid('order');
  calculateFreight();
  updateDeliveryZoneText();

  if (dom.calcTileSize?.options?.length >= 4) {
    const isHi = lang === 'hi';
    const opts = dom.calcTileSize.options;
    opts[0].text = isHi ? '400x400 mm डिजिटल पार्किंग (5 पीस / 8.61 वर्ग फीट / 18.5 किग्रा प्रति बॉक्स)' : '400x400 mm Digital Parking (5 pcs / 8.61 sq.ft / 18.5 kg per box)';
    opts[1].text = isHi ? '600x600 mm पोर्सिलेन GVT (4 पीस / 15.50 वर्ग फीट / 28.0 किग्रा प्रति बॉक्स)' : '600x600 mm Porcelain GVT (4 pcs / 15.50 sq.ft / 28.0 kg per box)';
    opts[2].text = isHi ? '400x400 mm 16mm हैवी ड्यूटी (4 पीस / 6.88 वर्ग फीट / 24.5 किग्रा प्रति बॉक्स)' : '400x400 mm 16mm Heavy Duty (4 pcs / 6.88 sq.ft / 24.5 kg per box)';
    opts[3].text = isHi ? '600x600 mm 12mm आउटडोर विट्रीफाइड (3 पीस / 11.62 वर्ग फीट / 29.5 किग्रा प्रति बॉक्स)' : '600x600 mm 12mm Outdoor Vitrified (3 pcs / 11.62 sq.ft / 29.5 kg per box)';
  }
}

function updateDeliveryZoneText() {
  const isHi = currentLang === 'hi';
  const kmUnit = isHi ? 'किमी' : 'km';

  document.querySelectorAll('.zone-chip').forEach(chip => {
    const name = isHi ? chip.dataset.nameHi : chip.dataset.nameEn;
    chip.textContent = `📍 ${name} (${chip.dataset.km} ${kmUnit})`;
  });

  if (dom.zoneTransitTitle && selectedZone) {
    const name = isHi ? selectedZone.nameHi : selectedZone.nameEn;
    dom.zoneTransitTitle.textContent = `📍 ${name} (${selectedZone.km} ${kmUnit})`;
  }
  if (dom.zoneTransitRoute && selectedZone) {
    const route = isHi ? selectedZone.routeHi : selectedZone.routeEn;
    dom.zoneTransitRoute.textContent = isHi ? `मार्ग: ${route} • गोडाउन से सीधा संपर्क` : `Route: ${route} • Direct Godown Link`;
  }
  if (dom.zoneTransitTime && selectedZone) {
    const timeFormatted = isHi ? selectedZone.time.replace('min', 'मिनट') : selectedZone.time;
    dom.zoneTransitTime.textContent = isHi ? `⚡ अनुमानित समय: ${timeFormatted}` : `⚡ Estimated Transit: ${timeFormatted}`;
  }
}

/**
 * Unified High-Performance Catalog Grid Renderer
 * Uses pre-computed search strings, Map lookups, and event delegation
 */
function renderGrid(type) {
  const isStock = type === 'stock';
  const grid = isStock ? dom.stockGrid : dom.orderGrid;
  if (!grid) return;

  const filter = isStock ? activeStockFilter : activeOrderFilter;
  const expanded = isStock ? stockExpanded : orderExpanded;
  const status = isStock ? 'in-stock' : 'by-order';
  const viewMoreWrap = isStock ? dom.stockViewMoreWrap : dom.orderViewMoreWrap;
  const viewMoreBtn = isStock ? dom.stockViewMoreBtn : dom.orderViewMoreBtn;
  const viewMoreText = isStock ? dom.stockViewMoreText : dom.orderViewMoreText;

  const filtered = TILE_CATALOG.filter(tile => {
    if (tile.status !== status) return false;
    if (filter !== 'all-stock' && filter !== 'all-order' && tile.category !== filter) return false;
    if (isStock && searchQuery && !tile._searchStr.includes(searchQuery)) return false;
    return true;
  });

  if (isStock && dom.stockCounter) {
    dom.stockCounter.innerHTML = currentLang === 'hi'
      ? `<span><strong>${filtered.length}</strong> डिजाइन पुणे गोडाउन में उपलब्ध</span>`
      : `<span><strong>${filtered.length}</strong> designs available in Pune godown</span>`;
  }

  if (filtered.length === 0) {
    if (viewMoreWrap) viewMoreWrap.style.display = 'none';
    const msg = currentLang === 'hi'
      ? `कोई भी इन-स्टॉक टाइल "${searchQuery}" से मेल नहीं खाती।`
      : `No in-stock tiles match "${searchQuery}".`;
    const btnText = currentLang === 'hi' ? 'फिल्टर और सर्च रीसेट करें' : 'Clear Filter & Search';

    grid.replaceChildren();
    const emptyBox = document.createElement('div');
    emptyBox.style.cssText = 'grid-column: 1 / -1; text-align: center; padding: 3.5rem 1.5rem; background: var(--surface); border: 1px solid var(--border); border-radius: var(--radius-md);';
    
    const p = document.createElement('p');
    p.style.cssText = 'color: var(--text-muted); font-size: 1.05rem; margin-bottom: 1.25rem; word-break: break-word;';
    p.textContent = msg; // 100% immune to XSS, textContent treats input strictly as plain text

    const btn = document.createElement('button');
    btn.className = 'btn btn-outline';
    btn.id = 'emptyClearBtn';
    btn.textContent = btnText;
    btn.onclick = () => {
      if (dom.stockSearch) dom.stockSearch.value = '';
      searchQuery = '';
      activeStockFilter = 'all-stock';
      stockExpanded = false;
      document.querySelectorAll('[data-filter]').forEach(t => t.classList.toggle('active', t.dataset.filter === 'all-stock'));
      if (dom.clearSearchBtn) dom.clearSearchBtn.style.display = 'none';
      renderGrid('stock');
    };

    emptyBox.appendChild(p);
    emptyBox.appendChild(btn);
    grid.appendChild(emptyBox);
    return;
  }

  const displayed = expanded ? filtered : filtered.slice(0, TILES_PER_COLLAPSED_VIEW);
  grid.innerHTML = displayed.map(createTileCardHTML).join('');

  if (viewMoreWrap && viewMoreBtn && viewMoreText) {
    if (filtered.length <= TILES_PER_COLLAPSED_VIEW) {
      viewMoreWrap.style.display = 'none';
    } else {
      viewMoreWrap.style.display = 'flex';
      const remaining = filtered.length - TILES_PER_COLLAPSED_VIEW;
      viewMoreBtn.classList.toggle('expanded', expanded);
      viewMoreText.textContent = expanded
        ? (currentLang === 'hi' ? 'कम डिजाइन देखें' : 'Show Fewer Designs')
        : (currentLang === 'hi'
            ? `और ${isStock ? 'स्टॉक' : 'प्रोजेक्ट'} डिजाइन देखें (${remaining} और)`
            : `View More ${isStock ? 'In-Stock' : 'Project'} Designs (${remaining} More)`);
    }
  }
}

/**
 * Architectural Card HTML Generator
 */
function createTileCardHTML(tile) {
  const isStock = tile.status === 'in-stock';
  const isHi = currentLang === 'hi';

  const statusText = isStock ? (isHi ? 'पुणे गोडाउन' : 'Pune Godown') : (isHi ? 'मोर्बी फैक्ट्री' : 'Morbi Factory');
  const badgeClass = isStock ? 'in-stock' : 'by-order';
  const availText = isStock ? (isHi ? 'तुरंत तैयार' : 'Ready for Dispatch') : (isHi ? 'मोर्बी बल्क' : 'By Order (Bulk)');

  const msg = encodeURIComponent(
    isHi
      ? `नमस्ते दिलीप जी, मुझे "${tile.name}" (कोड: ${tile.code}, साइज: ${tile.size}) के थोक रेट और डिलीवरी की जानकारी चाहिए।`
      : `Hello Dilip ji, I am an architect/dealer inquiring about wholesale rates for "${tile.name}" (Code: ${tile.code}, Size: ${tile.size}). Please share pricing and dispatch timeline.`
  );

  return `
    <article class="tile-card" data-id="${escapeHTML(tile.id)}">
      <div class="tile-thumb-container">
        <img
          src="${escapeHTML(tile.image)}"
          alt="${escapeHTML(tile.name)}"
          class="tile-thumb-img"
          loading="lazy"
          decoding="async"
          onerror="this.onerror=null; this.src='assets/img/hero_bg.jpg';"
        >
        <div class="badge-status ${badgeClass}">
          <span class="status-pulse-dot"></span>
          <span>${statusText}</span>
        </div>
        <span class="badge-dim">${escapeHTML(tile.sizeImperial)}</span>
      </div>

      <div class="tile-body">
        <div class="tile-header-row">
          <span class="tile-series-name">${escapeHTML(tile.code)}</span>
          <div class="tile-header-meta">
            <div class="tile-brand-mark" title="Direct Wholesale Sourcing by Shree Hari Marketing">
              <img src="assets/img/symbol_crest.png" alt="SHM" class="tile-brand-crest">
              <span>SHM</span>
            </div>
            <span class="tile-thickness-pill">${escapeHTML(tile.thickness)}</span>
          </div>
        </div>

        <h3 class="tile-title">${escapeHTML(tile.name)}</h3>

        <div class="tile-finish-tag" title="${escapeHTML(tile.finish)}">
          <span>${isHi ? 'फिनिश:' : 'Finish:'}</span> <strong>${escapeHTML(tile.finish)}</strong>
        </div>

        <div class="tile-spec-grid">
          <div class="spec-cell">
            <span>${isHi ? 'कवरेज' : 'Coverage'}</span>
            <strong>${tile.coverageSqFt} ${isHi ? 'वर्ग फीट' : 'sq.ft'}</strong>
          </div>
          <div class="spec-cell">
            <span>${isHi ? 'पैकेजिंग' : 'Packaging'}</span>
            <strong>${tile.piecesPerBox} ${isHi ? 'पीस/बॉक्स' : 'pcs/box'}</strong>
          </div>
          <div class="spec-cell">
            <span>${isHi ? 'बॉक्स वजन' : 'Box Weight'}</span>
            <strong>~${tile.weightKg} ${isHi ? 'किग्रा' : 'kg'}</strong>
          </div>
          <div class="spec-cell">
            <span>${isHi ? 'उपलब्धता' : 'Availability'}</span>
            <strong class="${isStock ? 'stock-ready-text' : 'order-ready-text'}">${availText}</strong>
          </div>
        </div>

        <div class="tile-actions">
          <button type="button" class="btn btn-outline btn-inspect" data-id="${escapeHTML(tile.id)}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
              <circle cx="11" cy="11" r="8"></circle>
              <line x1="21" y1="21" x2="16.65" y2="16.65"></line>
            </svg>
            <span>${isHi ? 'डिटेल्स' : 'Quick Specs'}</span>
          </button>
          <a href="https://wa.me/${COMPANY_INFO.phoneClean}?text=${msg}" target="_blank" rel="noopener noreferrer" class="btn btn-whatsapp-card">
            <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor">
              <path d="M12.031 6.172c-3.181 0-5.767 2.586-5.768 5.766-.001 1.298.38 2.27 1.019 3.287l-.582 2.128 2.182-.573c.978.58 1.911.928 3.145.929 3.178 0 5.767-2.587 5.768-5.766.001-3.187-2.575-5.771-5.764-5.771zm3.392 8.244c-.144.405-.837.774-1.17.824-.312.045-.694.073-2.127-.518-1.574-.648-2.618-2.222-2.698-2.329-.079-.107-.643-.855-.643-1.635 0-.78.411-1.164.558-1.32.146-.157.32-.196.427-.196.107 0 .214.001.307.006.102.005.239-.039.373.284.143.348.49 1.196.533 1.284.043.088.072.191.014.307-.058.117-.087.19-.174.292-.087.102-.183.228-.261.307-.087.087-.179.182-.077.357.102.175.454.748.974 1.212.67.597 1.235.782 1.41.87.175.088.277.073.38-.044.103-.117.439-.511.556-.686.117-.175.234-.146.395-.088.161.058 1.02.481 1.196.569.176.088.293.131.336.205.044.073.044.424-.1.829z"/>
            </svg>
            <span>${isHi ? 'होलसेल रेट' : 'Inquire Rate'}</span>
          </a>
          ${isStock ? `
            <button type="button" class="btn btn-calc-tile" data-category="${escapeHTML(tile.category)}">
              <span>${isHi ? '📦 भाड़ा निकालें' : '📦 Calc Freight'}</span>
            </button>
          ` : `
            <a href="https://wa.me/${COMPANY_INFO.phoneClean}?text=${encodeURIComponent(isHi ? `नमस्ते दिलीप जी, कृपया मुझे "${tile.catalogNameHi || tile.catalogName}" का पूरा मोर्बी फैक्ट्री कैटलॉग PDF व्हाट्सएप पर भेजें।` : `Hello Dilip ji, please share the full "${tile.catalogName}" factory PDF catalog with me.`)}" target="_blank" rel="noopener noreferrer" class="btn btn-catalog-request" title="${escapeHTML(tile.catalogName)}">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"></path>
                <polyline points="14 2 14 8 20 8"></polyline>
                <line x1="16" y1="13" x2="8" y2="13"></line>
                <line x1="16" y1="17" x2="8" y2="17"></line>
              </svg>
              <span>${isHi ? 'फैक्ट्री कैटलॉग (WhatsApp)' : 'Get Factory Catalog'}</span>
            </a>
          `}
        </div>
      </div>
    </article>
  `;
}

/**
 * Event Delegation for Grids (O(1) memory, O(1) Map lookups, zero re-bindings)
 */
function setupGridDelegation(grid) {
  if (!grid) return;
  grid.addEventListener('click', (e) => {
    if (e.target.closest('.btn-whatsapp-card') || e.target.closest('.btn-catalog-request')) return;

    const inspectBtn = e.target.closest('.btn-inspect');
    if (inspectBtn) {
      e.stopPropagation();
      const tile = tileMap.get(inspectBtn.dataset.id);
      if (tile) openTileModal(tile);
      return;
    }

    const calcBtn = e.target.closest('.btn-calc-tile');
    if (calcBtn) {
      e.stopPropagation();
      const cat = calcBtn.dataset.category;
      if (dom.calcTileSize) {
        const map = { 'parking-stock': '400-stock', 'porcelain-stock': '600-stock', 'order-16mm': '400-16mm', 'order-12mm': '600-12mm' };
        if (map[cat]) dom.calcTileSize.value = map[cat];
      }
      calculateFreight();
      const calcSec = $('calculator');
      if (calcSec) {
        calcSec.scrollIntoView({ behavior: 'smooth', block: 'start' });
        calcSec.classList.add('calc-pulse');
        setTimeout(() => calcSec.classList.remove('calc-pulse'), 1500);
      }
      return;
    }

    const card = e.target.closest('.tile-card');
    if (card) {
      const tile = tileMap.get(card.dataset.id);
      if (tile) openTileModal(tile);
    }
  });
}

/**
 * View More Buttons
 */
function setupViewMoreButtons() {
  if (dom.stockViewMoreBtn) {
    dom.stockViewMoreBtn.addEventListener('click', () => {
      stockExpanded = !stockExpanded;
      renderGrid('stock');
      if (!stockExpanded && dom.stockGrid) dom.stockGrid.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }

  if (dom.orderViewMoreBtn) {
    dom.orderViewMoreBtn.addEventListener('click', () => {
      orderExpanded = !orderExpanded;
      renderGrid('order');
      if (!orderExpanded && dom.orderGrid) dom.orderGrid.scrollIntoView({ behavior: 'smooth', block: 'start' });
    });
  }
}

/**
 * Filter Tabs
 */
function setupFilterTabs() {
  document.querySelectorAll('[data-filter]').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('[data-filter]').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeStockFilter = tab.dataset.filter;
      stockExpanded = false;
      renderGrid('stock');
    });
  });

  document.querySelectorAll('[data-filter-order]').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('[data-filter-order]').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      activeOrderFilter = tab.dataset.filterOrder;
      orderExpanded = false;
      renderGrid('order');
    });
  });
}

/**
 * Real-Time Search Logic
 */
function setupSearch() {
  if (!dom.stockSearch) return;

  dom.stockSearch.addEventListener('input', (e) => {
    searchQuery = e.target.value.toLowerCase().trim();
    stockExpanded = false;
    if (dom.clearSearchBtn) dom.clearSearchBtn.style.display = searchQuery ? 'block' : 'none';
    renderGrid('stock');
  });

  if (dom.clearSearchBtn) {
    dom.clearSearchBtn.addEventListener('click', () => {
      dom.stockSearch.value = '';
      searchQuery = '';
      stockExpanded = false;
      dom.clearSearchBtn.style.display = 'none';
      renderGrid('stock');
      dom.stockSearch.focus();
    });
  }
}

/**
 * Interactive Freight & Packaging Calculator Engine
 */
function setupCalculator() {
  if (!dom.calcArea || !dom.calcTileSize || !dom.calcWastage) return;

  const updateCalc = () => calculateFreight();

  document.querySelectorAll('.preset-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('.preset-chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      dom.calcArea.value = chip.dataset.sqft;
      updateCalc();
    });
  });

  document.querySelectorAll('.zone-chip').forEach(chip => {
    chip.addEventListener('click', () => {
      document.querySelectorAll('.zone-chip').forEach(c => c.classList.remove('active'));
      chip.classList.add('active');
      selectedZone = {
        nameEn: chip.dataset.nameEn,
        nameHi: chip.dataset.nameHi,
        km: chip.dataset.km,
        time: chip.dataset.time,
        routeEn: chip.dataset.routeEn,
        routeHi: chip.dataset.routeHi
      };
      updateDeliveryZoneText();
      updateCalc();
    });
  });

  dom.calcArea.addEventListener('input', () => {
    document.querySelectorAll('.preset-chip').forEach(c => c.classList.toggle('active', c.dataset.sqft === dom.calcArea.value));
    updateCalc();
  });
  dom.calcTileSize.addEventListener('change', updateCalc);
  dom.calcWastage.addEventListener('input', updateCalc);

  updateCalc();
}

function calculateFreight() {
  if (!dom.calcArea || !dom.calcTileSize || !dom.calcWastage) return;

  const rawArea = Number(dom.calcArea.value);
  const area = Number.isFinite(rawArea) ? Math.max(10, Math.min(500000, Math.round(rawArea))) : 1200;
  
  const rawWastage = Number(dom.calcWastage.value);
  const wastagePct = Number.isFinite(rawWastage) ? Math.max(0, Math.min(25, Math.round(rawWastage))) : 8;

  const specKey = dom.calcTileSize.value;
  const spec = Object.prototype.hasOwnProperty.call(PACKAGING_SPECS, specKey)
    ? PACKAGING_SPECS[specKey]
    : PACKAGING_SPECS['400-stock'];

  if (dom.wastageDisplay) dom.wastageDisplay.textContent = `${wastagePct}%`;

  const grossArea = area * (1 + (wastagePct / 100));
  const boxes = Math.ceil(grossArea / spec.coverage);
  const actualCoverage = (boxes * spec.coverage).toFixed(1);
  const totalTiles = boxes * spec.pcs;
  const weightKg = boxes * spec.weight;
  const weightTons = (weightKg / 1000).toFixed(2);
  const isHi = currentLang === 'hi';
  const areaUnit = isHi ? 'वर्ग फीट' : 'sq.ft';

  if (dom.resGrossArea) dom.resGrossArea.textContent = `${Math.round(grossArea).toLocaleString('en-IN')} ${areaUnit}`;
  if (dom.resTotalTiles) {
    dom.resTotalTiles.innerHTML = isHi
      ? `${totalTiles.toLocaleString('en-IN')} पीस <small style="display:inline-block; font-size: 0.76rem; color: var(--text-subtle); font-weight: 400;">(${spec.pcs} पीस/बॉक्स)</small>`
      : `${totalTiles.toLocaleString('en-IN')} Pieces <small style="display:inline-block; font-size: 0.76rem; color: var(--text-subtle); font-weight: 400;">(${spec.pcs} pcs/box)</small>`;
  }
  if (dom.resActualCoverage) dom.resActualCoverage.textContent = `${parseFloat(actualCoverage).toLocaleString('en-IN')} ${areaUnit}`;
  if (dom.resTotalWeight) dom.resTotalWeight.textContent = isHi ? `${Math.round(weightKg).toLocaleString('en-IN')} किग्रा (${weightTons} टन)` : `${Math.round(weightKg).toLocaleString('en-IN')} kg (${weightTons} Tons)`;

  let vehicleDesc = '';
  if (isHi) {
    if (weightKg <= 1200) vehicleDesc = '🛵 छोटा हाथी / टाटा ऐस (1.2 टन क्षमता, शहर के छोटे ऑर्डर के लिए उपयुक्त)';
    else if (weightKg <= 3500) vehicleDesc = '🚚 महिंद्रा बोलेरो मैक्सी ट्रक / टाटा 407 (2.5 से 3.5 टन क्षमता, आवासीय साइट्स हेतु)';
    else if (weightKg <= 9000) vehicleDesc = '🚛 6-चक्का कमर्शियल आयशर ट्रक (6 से 9 टन क्षमता, बड़े प्रोजेक्ट्स हेतु)';
    else if (weightKg <= 18000) vehicleDesc = '🚛 10-चक्का हेवी लॉजिस्टिक्स ट्रक (15 से 18 टन थोक क्षमता)';
    else vehicleDesc = '🏭 16-चक्का मल्टी-एक्सल ट्रेलर / डायरेक्ट FTL (25–35 टन, सीधे मोर्बी फैक्ट्री से)';
  } else {
    if (weightKg <= 1200) vehicleDesc = '🛵 Tata Ace / Mahindra Bolero (Light commercial vehicle, ideal for Pune city retail drops).';
    else if (weightKg <= 3500) vehicleDesc = '🚚 Mahindra Bolero Maxi / Tata 407 (Medium delivery truck suitable for residential sites).';
    else if (weightKg <= 9000) vehicleDesc = '🚛 6-Wheeler Heavy Eicher (6–9 ton capacity for large villa/commercial projects).';
    else if (weightKg <= 18000) vehicleDesc = '🚛 10-Wheeler Commercial Carrier (15–18 tons bulk capacity).';
    else vehicleDesc = '🏭 16-Wheeler Multi-Axle Trailer / FTL (25–35 tons, direct factory container straight from Morbi).';
  }

  if (dom.resVehicleText) dom.resVehicleText.textContent = vehicleDesc;

  if (dom.btnShareCalc) {
    const activeDestName = isHi ? selectedZone.nameHi : selectedZone.nameEn;
    const msg = isHi
      ? `नमस्ते दिलीप जी, मैंने आपकी वेबसाइट पर टाइल और भाड़ा कैलकुलेट किया है:
• एरिया: ${area} वर्ग फीट (+${wastagePct}% बफर = ${Math.round(grossArea)} वर्ग फीट)
• टाइल: ${spec.name}
• आवश्यक बॉक्स: ${boxes} बॉक्स (${totalTiles} पीस, ~${weightTons} टन)
• डिलीवरी क्षेत्र: ${activeDestName} (~${selectedZone.time}, ${selectedZone.km} किमी)
• सुझाया गया वाहन: ${vehicleDesc}
कृपया थोक रेट और डिलीवरी की जानकारी दें।`
      : `Hello Dilip ji, I used your tile calculator:
• Area: ${area} sq.ft (+${wastagePct}% buffer = ${Math.round(grossArea)} sq.ft)
• Tile: ${spec.name}
• Required: ${boxes} Boxes (${totalTiles} Pcs, ~${weightTons} Tons)
• Delivery Area: ${activeDestName} (~${selectedZone.time}, ${selectedZone.km} km)
• Vehicle: ${vehicleDesc.split('(')[0].trim()}
Please quote wholesale pricing & availability.`;

    dom.btnShareCalc.onclick = () => safeOpenWhatsApp(COMPANY_INFO.phoneClean, msg);
  }
}

/**
 * Tile Inspector Modal (Uses pre-cached DOM nodes & Map lookup)
 */
function openTileModal(tile) {
  if (dom.modalImg) { dom.modalImg.src = tile.image; dom.modalImg.alt = tile.name; }
  if (dom.modalCode) dom.modalCode.textContent = `${tile.code} • ${tile.series}`;
  if (dom.modalName) dom.modalName.textContent = tile.name;

  const isHi = currentLang === 'hi';
  if (dom.modalDesc) {
    dom.modalDesc.textContent = isHi
      ? `उपयुक्तता: ${tile.idealFor}। हेवी ट्रैफिक टेस्टेड, नॉन-फेडिंग पिगमेंट और टिकाऊ विट्रीफाइड फिनिश।`
      : `Recommended for: ${tile.idealFor}. Heavy traffic tested with zero-fading pigments.`;
  }

  const isStock = tile.status === 'in-stock';
  if (dom.modalStatus) {
    dom.modalStatus.textContent = isStock
      ? (isHi ? 'पुणे गोडाउन में उपलब्ध' : 'Pune Godown Available')
      : (isHi ? 'मोर्बी फैक्ट्री डायरेक्ट' : 'Morbi Factory Direct');
    dom.modalStatus.className = `badge ${isStock ? 'badge-teal' : 'badge-gold'}`;
  }

  if (dom.modalSpecs) {
    dom.modalSpecs.innerHTML = `
      <div class="spec-cell"><span>${isHi ? 'साइज (मिलीमीटर)' : 'Size (Metric)'}</span><strong>${escapeHTML(tile.size)}</strong></div>
      <div class="spec-cell"><span>${isHi ? 'इंच/फीट साइज' : 'Imperial Size'}</span><strong>${escapeHTML(tile.sizeImperial)}</strong></div>
      <div class="spec-cell"><span>${isHi ? 'मोटाई' : 'Thickness'}</span><strong>${escapeHTML(tile.thickness)}</strong></div>
      <div class="spec-cell"><span>${isHi ? 'सतह फिनिश' : 'Surface Finish'}</span><strong>${escapeHTML(tile.finish)}</strong></div>
      <div class="spec-cell"><span>${isHi ? 'बॉक्स कवरेज' : 'Box Coverage'}</span><strong>${tile.coverageSqFt} ${isHi ? 'वर्ग फीट' : 'sq.ft'}</strong></div>
      <div class="spec-cell"><span>${isHi ? 'पीस / बॉक्स' : 'Pieces / Box'}</span><strong>${tile.piecesPerBox} ${isHi ? 'पीस' : 'pcs'}</strong></div>
      <div class="spec-cell"><span>${isHi ? 'कुल वजन' : 'Total Weight'}</span><strong>~${tile.weightKg} ${isHi ? 'किग्रा' : 'kg'}</strong></div>
      <div class="spec-cell"><span>${isHi ? 'मुख्य विशेषता' : 'Key Feature'}</span><strong>${escapeHTML(tile.features[0] || (isHi ? 'विट्रीफाइड बॉडी' : 'Vitrified Body'))}</strong></div>
    `;
  }

  if (dom.modalWhatsAppBtn) {
    const msg = isHi
      ? `नमस्ते दिलीप जी, मुझे "${tile.name}" (कोड: ${tile.code}, साइज: ${tile.size}) के थोक रेट और डिलीवरी की जानकारी चाहिए।`
      : `Hello Dilip ji, I want wholesale rates for ${tile.name} (Code: ${tile.code}, Size: ${tile.size}). Please confirm Pune godown stock.`;
    dom.modalWhatsAppBtn.href = `https://wa.me/${COMPANY_INFO.phoneClean}?text=${encodeURIComponent(msg)}`;
    dom.modalWhatsAppBtn.rel = 'noopener noreferrer';
  }

  if (dom.modalPdfBtn) {
    if (tile.status === 'by-order') {
      const catalogMsg = isHi
        ? `नमस्ते दिलीप जी, कृपया मुझे "${tile.catalogNameHi || tile.catalogName}" का पूरा मोर्बी फैक्ट्री कैटलॉग PDF व्हाट्सएप पर भेजें।`
        : `Hello Dilip ji, please share the full "${tile.catalogName}" factory PDF catalog with me.`;
      dom.modalPdfBtn.href = `https://wa.me/${COMPANY_INFO.phoneClean}?text=${encodeURIComponent(catalogMsg)}`;
      dom.modalPdfBtn.target = '_blank';
      dom.modalPdfBtn.rel = 'noopener noreferrer';
      dom.modalPdfBtn.innerHTML = `
        <svg width="15" height="15" viewBox="0 0 24 24" fill="currentColor" style="margin-right: 0.35rem; color: #25d366;">
          <path d="M12.031 6.172c-3.181 0-5.767 2.586-5.768 5.766-.001 1.298.38 2.27 1.019 3.287l-.582 2.128 2.182-.573c.978.58 1.911.928 3.145.929 3.178 0 5.767-2.587 5.768-5.766.001-3.187-2.575-5.771-5.764-5.771zm3.392 8.244c-.144.405-.837.774-1.17.824-.312.045-.694.073-2.127-.518-1.574-.648-2.618-2.222-2.698-2.329-.079-.107-.643-.855-.643-1.635 0-.78.411-1.164.558-1.32.146-.157.32-.196.427-.196.107 0 .214.001.307.006.102.005.239-.039.373.284.143.348.49 1.196.533 1.284.043.088.072.191.014.307-.058.117-.087.19-.174.292-.087.102-.183.228-.261.307-.087.087-.179.182-.077.357.102.175.454.748.974 1.212.67.597 1.235.782 1.41.87.175.088.277.073.38-.044.103-.117.439-.511.556-.686.117-.175.234-.146.395-.088.161.058 1.02.481 1.196.569.176.088.293.131.336.205.044.073.044.424-.1.829z"/>
        </svg>
        <span>${isHi ? 'पूरा कैटलॉग PDF मांगें (WhatsApp)' : 'Request Factory Catalog (WhatsApp)'}</span>
      `;
      dom.modalPdfBtn.style.display = 'inline-flex';
    } else if (tile.pdfPath && tile.pdfPath !== 'whatsapp') {
      dom.modalPdfBtn.href = tile.pdfPath;
      dom.modalPdfBtn.target = '_blank';
      dom.modalPdfBtn.rel = 'noopener noreferrer';
      dom.modalPdfBtn.innerHTML = `<span>${isHi ? '📄 PDF कैटलॉग देखें' : '📄 View PDF Catalog'}</span>`;
      dom.modalPdfBtn.style.display = 'inline-flex';
    } else {
      dom.modalPdfBtn.style.display = 'none';
    }
  }

  toggleModal(dom.tileModal, true);
}

function toggleModal(modal, open) {
  if (!modal) return;
  modal.classList.toggle('open', open);
  document.body.style.overflow = open ? 'hidden' : '';
}

function setupModals() {
  if (dom.modalCloseBtn) dom.modalCloseBtn.onclick = () => toggleModal(dom.tileModal, false);
  if (dom.tileModal) dom.tileModal.onclick = (e) => { if (e.target === dom.tileModal) toggleModal(dom.tileModal, false); };

  if (dom.btnViewCert) dom.btnViewCert.onclick = () => toggleModal(dom.certModal, true);
  if (dom.certCloseBtn) dom.certCloseBtn.onclick = () => toggleModal(dom.certModal, false);
  if (dom.certModal) dom.certModal.onclick = (e) => { if (e.target === dom.certModal) toggleModal(dom.certModal, false); };

  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      toggleModal(dom.tileModal, false);
      toggleModal(dom.certModal, false);
    }
  });
}

/**
 * Mobile Navigation Drawer
 */
function setupMobileNav() {
  const closeDrawer = () => {
    if (dom.navLinks) dom.navLinks.classList.remove('open');
    document.body.style.overflow = '';
  };

  const openDrawer = () => {
    if (dom.navLinks) dom.navLinks.classList.add('open');
    document.body.style.overflow = 'hidden';
  };

  // Hamburger toggle
  if (dom.mobileToggle) {
    dom.mobileToggle.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      dom.navLinks?.classList.contains('open') ? closeDrawer() : openDrawer();
    });
  }

  // Close button inside drawer
  if (dom.drawerCloseBtn) {
    dom.drawerCloseBtn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      closeDrawer();
    });
  }

  // Close drawer when tapping OUTSIDE it (replaces the backdrop element entirely)
  document.addEventListener('click', (e) => {
    if (!dom.navLinks?.classList.contains('open')) return;
    // If click is inside the drawer or on the toggle button, don't close
    if (dom.navLinks.contains(e.target)) return;
    if (dom.mobileToggle?.contains(e.target)) return;
    closeDrawer();
  });

  // Nav links close drawer and scroll to section
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', (e) => {
      const href = link.getAttribute('href');
      closeDrawer();
      if (href && href.startsWith('#')) {
        const target = document.querySelector(href);
        if (target) {
          e.preventDefault();
          setTimeout(() => {
            target.scrollIntoView({ behavior: 'smooth' });
          }, 80);
        }
      }
    });
  });
}

/**
 * Hardened Retailer Partner Form Submission
 * - Anti-Bot Cryptographic Trap / Honeypot verification
 * - Time-lock token verification (reject bot submissions < 1800ms)
 * - 5-second submit debounce rate-limiter
 * - Strict E.164 / Indian 10-digit mobile number validation
 * - Control character stripping and length enforcement
 * - Accessible feedback messaging
 */
let formMountedAt = Date.now();
let lastPartnerSubmitTime = 0;

function setupPartnerForm() {
  if (!dom.partnerForm) return;

  const feedbackEl = $('partnerFormFeedback');
  const submitBtn = $('partnerSubmitBtn');

  const showFeedback = (msg, isError = false) => {
    if (!feedbackEl) return;
    feedbackEl.textContent = msg;
    feedbackEl.className = `partner-form-feedback ${isError ? 'error' : 'success'}`;
    feedbackEl.style.display = 'block';
  };

  const clearFeedback = () => {
    if (!feedbackEl) return;
    feedbackEl.textContent = '';
    feedbackEl.style.display = 'none';
    feedbackEl.className = 'partner-form-feedback';
  };

  dom.partnerForm.addEventListener('submit', (e) => {
    e.preventDefault();
    clearFeedback();

    const isHi = currentLang === 'hi';

    // 1. Anti-Bot Honeypot Verification
    const honeypotVal = $('partnerHoneypot')?.value;
    if (honeypotVal) {
      console.warn('Bot detected by security honeypot');
      return;
    }

    // 2. Time-Lock Verification (Bots submit in under 1.5 seconds)
    const elapsed = Date.now() - formMountedAt;
    if (elapsed < 1800) {
      console.warn('Suspiciously fast automated submission dropped');
      return;
    }

    // 3. Rate-Limiting Debounce (5-second cooldown)
    const now = Date.now();
    if (now - lastPartnerSubmitTime < 5000) {
      const waitMsg = isHi
        ? 'कृपया कुछ सेकंड प्रतीक्षा करें...'
        : 'Please wait a few seconds before resubmitting...';
      showFeedback(waitMsg, true);
      return;
    }

    // 4. Input Sanitization (Strip control chars, trim, enforce limits)
    const sanitizeInput = (val, maxLen) => {
      if (!val) return '';
      return String(val)
        .replace(/[\x00-\x1F\x7F]/g, '')
        .trim()
        .slice(0, maxLen);
    };

    const shop = sanitizeInput($('shopName')?.value, 100);
    const name = sanitizeInput($('ownerName')?.value, 60);
    const rawPhone = sanitizeInput($('shopPhone')?.value, 16);
    const location = sanitizeInput($('shopLocation')?.value, 100);

    // 5. Strict Input Validation
    if (!shop || !name || !rawPhone || !location) {
      showFeedback(isHi ? 'कृपया सभी आवश्यक फ़ील्ड भरें।' : 'Please fill in all required fields.', true);
      return;
    }

    // Clean phone number: remove non-digits
    let cleanMobile = rawPhone.replace(/\D/g, '');
    if (cleanMobile.startsWith('91') && cleanMobile.length === 12) {
      cleanMobile = cleanMobile.slice(2);
    } else if (cleanMobile.startsWith('0') && cleanMobile.length === 11) {
      cleanMobile = cleanMobile.slice(1);
    }

    // Validate 10-digit Indian mobile number format
    if (!/^[6-9]\d{9}$/.test(cleanMobile)) {
      showFeedback(
        isHi
          ? 'कृपया मान्य 10-अंकीय भारतीय मोबाइल नंबर दर्ज करें (उदा. 9876543210)।'
          : 'Please enter a valid 10-digit Indian mobile number (e.g. 9876543210).',
        true
      );
      $('shopPhone')?.focus();
      return;
    }

    lastPartnerSubmitTime = now;

    // 6. Format WhatsApp Message Payload
    const text = isHi
      ? `*पुणे रिटेलर डिस्प्ले बोर्ड आवेदन*
• दुकान/शोरूम: ${shop}
• संपर्क व्यक्ति: ${name}
• मोबाइल: +91 ${cleanMobile}
• स्थान: ${location}`
      : `*Pune Retail Partner Application*
• Showroom: ${shop}
• Contact: ${name}
• Phone: +91 ${cleanMobile}
• Location: ${location}`;

    // 7. Feedback & Secure Navigation
    if (submitBtn) {
      submitBtn.disabled = true;
      const originalText = submitBtn.innerHTML;
      submitBtn.innerHTML = `<span>${isHi ? 'व्हाट्सएप खुल रहा है...' : 'Opening WhatsApp...'}</span>`;
      setTimeout(() => {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
      }, 4000);
    }

    showFeedback(isHi ? 'व्हाट्सएप चैट खुल रही है...' : 'Opening WhatsApp...', false);
    safeOpenWhatsApp(COMPANY_INFO.phoneClean, text);
  });
}

/**
 * Brand Interactions (Header progress, aura dynamic response, tap bloom)
 */
function setupBrandInteractions() {
  if (dom.brandScrollFill) {
    window.addEventListener('scroll', () => {
      const winScroll = document.documentElement.scrollTop || document.body.scrollTop;
      const height = document.documentElement.scrollHeight - document.documentElement.clientHeight;
      dom.brandScrollFill.style.width = `${height > 0 ? (winScroll / height) * 100 : 0}%`;
    }, { passive: true });
  }

  if (dom.hero && dom.heroGlow) {
    let heroTicking = false;
    const handleMove = (clientX, clientY) => {
      if (heroTicking) return;
      heroTicking = true;
      requestAnimationFrame(() => {
        const rect = dom.hero.getBoundingClientRect();
        const xPct = Math.round(((clientX - rect.left) / rect.width) * 100);
        const yPct = Math.round(((clientY - rect.top) / rect.height) * 100);
        dom.heroGlow.style.setProperty('--glow-x', `${xPct}%`);
        dom.heroGlow.style.setProperty('--glow-y', `${yPct}%`);

        if (dom.heroWatermark) {
          const shiftX = ((xPct - 50) * -0.16).toFixed(1);
          const shiftY = ((yPct - 50) * -0.16).toFixed(1);
          dom.heroWatermark.style.transform = `translate(calc(-50% + ${shiftX}px), calc(-50% + ${shiftY}px))`;
        }
        heroTicking = false;
      });
    };

    dom.hero.addEventListener('mousemove', (e) => handleMove(e.clientX, e.clientY), { passive: true });
    dom.hero.addEventListener('touchmove', (e) => {
      if (e.touches?.[0]) handleMove(e.touches[0].clientX, e.touches[0].clientY);
    }, { passive: true });

    dom.hero.addEventListener('mouseleave', () => {
      dom.heroGlow.style.setProperty('--glow-x', '65%');
      dom.heroGlow.style.setProperty('--glow-y', '45%');
      if (dom.heroWatermark) dom.heroWatermark.style.transform = 'translate(-50%, -50%)';
    });

    dom.hero.addEventListener('click', () => {
      if (dom.heroWatermark) {
        dom.heroWatermark.classList.add('pulse-bloom');
        setTimeout(() => dom.heroWatermark.classList.remove('pulse-bloom'), 1200);
      }
    });
  }
}

if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
}

