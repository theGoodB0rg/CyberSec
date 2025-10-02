const axios = require('axios');
const sanitizeHtml = require('sanitize-html');
const { URL } = require('url');
const crypto = require('crypto');
const Logger = require('./utils/logger');
let puppeteer = null;
try {
  // Lazy import to allow environments without Chromium to still run non-DOM checks
  puppeteer = require('puppeteer');
} catch (_) {
  puppeteer = null;
}

// Simple HTML normalizer to reduce cosmetic diffs
function normalizeHtml(html) {
  try {
    const cleaned = sanitizeHtml(String(html || ''), {
      allowedTags: [],
      allowedAttributes: {},
      textFilter: (text) => text
        .replace(/\s+/g, ' ') // collapse whitespace
        .replace(/\d{2,4}[-/: ]\d{1,2}[-/: ]\d{1,2}[ T]\d{1,2}:\d{2}(?::\d{2})?/g, '<time>') // timestamps
        .replace(/[A-Fa-f0-9]{16,}/g, '<hex>') // long hex tokens
        .trim()
    });
    return cleaned;
  } catch {
    return String(html || '');
  }
}

const MAX_EXCERPT_LENGTH = 480;

function sanitizeForPreview(value) {
  if (value == null) return '';
  let str = '';
  if (Buffer.isBuffer(value)) {
    try {
      str = value.toString('utf8');
    } catch {
      str = value.toString('latin1');
    }
  } else if (typeof value === 'string') {
    str = value;
  } else {
    try {
      str = JSON.stringify(value);
    } catch {
      str = String(value);
    }
  }

  if (!str) return '';

  const printable = str
    // eslint-disable-next-line no-control-regex
    .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();

  if (!printable) return '';

  return printable.length > MAX_EXCERPT_LENGTH
    ? `${printable.slice(0, MAX_EXCERPT_LENGTH)}…`
    : printable;
}

function detectBinary(body) {
  if (!body) return false;
  const sample = typeof body === 'string' ? body.slice(0, 512) : body;
  if (Buffer.isBuffer(sample)) {
    const ascii = sample.toString('binary');
    let controlCount = 0;
    for (let i = 0; i < ascii.length; i++) {
      const code = ascii.charCodeAt(i);
      if (code < 32 && ![9, 10, 13].includes(code)) controlCount++;
    }
    return controlCount / Math.max(1, ascii.length) > 0.15;
  }
  return false;
}

function buildExcerpt(body) {
  if (body == null) return null;
  if (detectBinary(body)) {
    const size = Buffer.isBuffer(body) ? body.length : Buffer.byteLength(String(body));
    return `[binary content ~${size} bytes]`;
  }
  return sanitizeForPreview(body);
}

function hashBody(body) {
  try {
    return crypto.createHash('sha256').update(typeof body === 'string' ? body : Buffer.from(String(body))).digest('hex');
  } catch {
    return null;
  }
}

const SENSITIVE_HEADER_KEYS = new Set(['authorization', 'cookie', 'proxy-authorization', 'set-cookie']);

function sanitizeHeadersForStorage(headers = {}) {
  const result = {};
  for (const [rawKey, rawValue] of Object.entries(headers || {})) {
    if (!rawKey) continue;
    const key = String(rawKey);
    const lower = key.toLowerCase();
    if (SENSITIVE_HEADER_KEYS.has(lower)) continue;
    if (Array.isArray(rawValue)) {
      result[lower] = rawValue.map((v) => (v == null ? '' : String(v))).filter(Boolean).join('; ');
    } else if (rawValue != null) {
      result[lower] = String(rawValue);
    }
  }
  return result;
}

function buildResponsePreview(response, variantMeta = {}) {
  if (!response) return null;
  const body = response.body || '';
  const length = typeof body === 'string' ? body.length : Buffer.isBuffer(body) ? body.length : String(body).length;
  return {
    status: typeof response.status === 'number' ? response.status : null,
    timeMs: typeof response.timeMs === 'number' ? response.timeMs : null,
    length,
    hash: hashBody(body),
    excerpt: buildExcerpt(body),
    headers: sanitizeHeadersForStorage(response.headers || {}),
    url: variantMeta.url || null,
    method: variantMeta.method || null
  };
}

function buildUrlWithParam(baseUrl, param, value) {
  const u = new URL(baseUrl);
  // If the parameter exists, replace, else append
  if (u.searchParams.has(param)) {
    u.searchParams.set(param, value);
  } else {
    u.searchParams.append(param, value);
  }
  return u.toString();
}

async function domReflectionCheck({ url, parameter, requestContext = {} }) {
  // Only support GET flow for DOM validation for now
  if (!puppeteer) {
    return { ok: false, reason: 'puppeteer-unavailable' };
  }
  try {
    const canary = `cybersec_canary_${Math.random().toString(36).slice(2, 10)}`;
    const target = buildUrlWithParam(url, parameter, canary);
    const launchArgs = ['--no-sandbox', '--disable-setuid-sandbox'];
  const browser = await puppeteer.launch({ headless: true, args: launchArgs });
    const page = await browser.newPage();
    try {
      // Apply context
      if (requestContext.userAgent) {
        await page.setUserAgent(String(requestContext.userAgent));
      }
      const extraHeaders = { ...(requestContext.headers || {}) };
      // Avoid passing sensitive headers
      for (const k of Object.keys(extraHeaders)) {
        if (['authorization', 'cookie'].includes(k.toLowerCase())) delete extraHeaders[k];
      }
      if (Object.keys(extraHeaders).length) await page.setExtraHTTPHeaders(extraHeaders);
      if (requestContext.cookie) {
        // Best-effort cookie parsing into name/value pairs
        const raw = String(requestContext.cookie);
        const parts = raw.split(';');
        const cookies = parts.map(p => p.trim()).filter(Boolean).map(pair => {
          const i = pair.indexOf('=');
          if (i === -1) return null;
          const name = pair.slice(0, i).trim();
          const value = pair.slice(i + 1).trim();
          return { name, value, url };
        }).filter(Boolean);
        if (cookies.length) await page.setCookie(...cookies);
      }

      const resp = await page.goto(target, { waitUntil: 'networkidle2', timeout: 20000 });
      const status = resp ? resp.status() : 0;

      // Evaluate DOM for canary reflection using a stringified function to avoid server-side ESLint parsing
      const DOM_EVAL_FN_SRC = [
        '(function(needle){',
        '  const matches = [];',
        '  const isTextHit = () => document.body && document.body.innerText && document.body.innerText.includes(needle);',
        '  let textHit = isTextHit();',
        '  if (textHit) {',
        "    const all = Array.from(document.querySelectorAll('*:not(script):not(style)'));",
        '    for (const el of all) {',
        '      try {',
        "        if ((el.innerText || el.textContent || '').includes(needle)) {",
        '          const path = [];',
        '          let cur = el;',
        '          while (cur && cur.nodeType === 1 && path.length < 6) {',
        '            const tag = cur.tagName.toLowerCase();',
        "            const id = cur.id ? '#' + cur.id : '';",
        "            const cls = (cur.className && typeof cur.className === 'string') ? '.' + cur.className.split(/\\s+/).filter(Boolean).slice(0,2).join('.') : '';",
        '            path.unshift(tag + id + cls);',
        '            cur = cur.parentElement;',
        '          }',
        "          matches.push({ selector: path.join(' > '), mode: 'text' });",
        '          if (matches.length >= 3) break;',
        '        }',
        '      } catch (_e) {}',
        '    }',
        '  }',
        "  const all = Array.from(document.querySelectorAll('*'));",
        '  for (const el of all) {',
        '    try {',
        '      for (const attr of Array.from(el.attributes || [])) {',
        "        if (String(attr.value || '').includes(needle)) {",
        '          const path = [];',
        '          let cur = el;',
        '          while (cur && cur.nodeType === 1 && path.length < 6) {',
        '            const tag = cur.tagName.toLowerCase();',
        "            const id = cur.id ? '#' + cur.id : '';",
        "            const cls = (cur.className && typeof cur.className === 'string') ? '.' + cur.className.split(/\\s+/).filter(Boolean).slice(0,2).join('.') : '';",
        '            path.unshift(tag + id + cls);',
        '            cur = cur.parentElement;',
        '          }',
        "          matches.push({ selector: path.join(' > '), mode: 'attribute', attribute: attr.name });",
        '          if (matches.length >= 3) break;',
        '        }',
        '      }',
        '      if (matches.length >= 3) break;',
        '    } catch (_e) {}',
        '  }',
        '  return { reflected: textHit || matches.length > 0, matches };',
        '})'
      ].join('\n');
      const result = await page.evaluate((fnSrc, needle) => { const f = eval(fnSrc); return f(needle); }, DOM_EVAL_FN_SRC, canary);

      // Screenshot evidence
      let screenshotBuffer = null;
      if (result.reflected) {
        try {
          if (result.matches && result.matches.length) {
            const first = result.matches[0];
            const el = await page.$(first.selector);
            if (el) {
              try {
                await page.evaluate((elem) => {
                  try { elem.scrollIntoView({ behavior: 'instant', block: 'center', inline: 'center' }); } catch (_) { /* noop */ }
                }, el);
              } catch (_) {}
              screenshotBuffer = await el.screenshot({ type: 'png' });
            }
          }
          if (!screenshotBuffer) {
            screenshotBuffer = await page.screenshot({ fullPage: true, type: 'png' });
          }
        } catch (_) {
          // ignore screenshot errors
        }
      }

      return { ok: true, status, url: target, canary, reflected: !!result.reflected, matches: result.matches || [], screenshotBuffer };
    } finally {
      await page.close().catch(()=>{});
      await browser.close().catch(()=>{});
    }
  } catch (e) {
    return { ok: false, reason: e.message };
  }
}

async function httpRequest({ url, method = 'GET', headers = {}, data = null }) {
  const started = Date.now();
  const res = await axios({
    url,
    method,
    headers: {
      'User-Agent': headers['User-Agent'] || headers['user-agent'] || 'CyberSec-Verify/1.0',
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
      ...headers
    },
    data,
    timeout: 15000,
    validateStatus: () => true,
    maxRedirects: 2
  });
  const ttfb = Date.now() - started;
  return {
    status: res.status,
    headers: res.headers,
    timeMs: ttfb,
    body: typeof res.data === 'string' ? res.data : JSON.stringify(res.data)
  };
}

function buildRequestVariant({ baseUrl, parameter, payload, method = 'GET', headers = {}, cookie, data }) {
  const hdrs = { ...headers };
  if (cookie) hdrs['Cookie'] = cookie;
  const upper = (method || 'GET').toUpperCase();
  if (upper !== 'GET') {
    const ctKey = Object.keys(hdrs).find(k => k.toLowerCase() === 'content-type');
    const contentType = ctKey ? hdrs[ctKey] : 'application/x-www-form-urlencoded';
    if (!ctKey) hdrs['Content-Type'] = contentType;
    let body = '';
    try {
      if (contentType.includes('application/json')) {
        const obj = data && typeof data === 'string' ? JSON.parse(data) : (data || {});
        obj[parameter] = payload;
        body = JSON.stringify(obj);
      } else {
        const usp = new URLSearchParams(typeof data === 'string' ? data : '');
        usp.set(parameter, payload);
        body = usp.toString();
      }
    } catch {
      const usp = new URLSearchParams();
      usp.set(parameter, payload);
      body = usp.toString();
    }
    return { url: baseUrl, method: upper, headers: hdrs, data: body };
  }
  return { url: buildUrlWithParam(baseUrl, parameter, payload), method: 'GET', headers: hdrs, data: null };
}

function detectWafIndicators(res) {
  try {
    const status = res?.status || 0;
    const headers = res?.headers || {};
    const body = (res?.body || '').toString();
    const hdrValues = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join('\n');
    const bodyHit = /(access denied|request denied|forbidden|blocked by|web application firewall|mod_security|modsecurity|incapsula|akamai|cloudflare|sucuri|barracuda|imperva)/i.test(body);
    const headerHit = /(cf-ray|cloudflare|akamai|incapsula|sucuri|x-sucuri|x-cdn|x-akamai|x-mod-security|x-waf)/i.test(hdrValues);
    const statusHit = [403, 406, 429].includes(Number(status));
    return { bodyHit, headerHit, statusHit, any: bodyHit || headerHit || statusHit };
  } catch {
    return { any: false };
  }
}

function wafSuggestions() {
  return [
    'Enable tamper flags (e.g., --tamper=space2comment,charencode,randomcase)',
    'Reduce concurrency (--threads=1) and increase delays (--delay=2-5)',
    'Use a stable user-agent and add realistic headers',
    'Consider authenticated scans with valid session cookies'
  ];
}

function simpleDiffSummary(a, b) {
  if (a === b) return { identical: true, added: 0, removed: 0, changed: 0 };
  const aTokens = a.split(/\s+/);
  const bTokens = b.split(/\s+/);
  let changed = 0;
  const len = Math.min(aTokens.length, bTokens.length);
  for (let i = 0; i < len; i++) {
    if (aTokens[i] !== bTokens[i]) changed++;
  }
  const added = Math.max(0, bTokens.length - aTokens.length);
  const removed = Math.max(0, aTokens.length - bTokens.length);
  return { identical: false, added, removed, changed };
}

function curlSnippet(variant) {
  if (!variant || !variant.url) return null;
  const parts = ['curl -i'];
  const method = (variant.method || 'GET').toUpperCase();
  if (method !== 'GET') {
    parts.push(`-X ${method}`);
  }
  const headers = variant.headers || {};
  const skipHeaders = new Set(['content-length', 'host']);
  const seen = new Set();
  for (const [rawKey, rawValue] of Object.entries(headers)) {
    if (rawValue == null) continue;
    const key = String(rawKey);
    const value = Array.isArray(rawValue) ? rawValue.join(', ') : String(rawValue);
    if (!value) continue;
    if (skipHeaders.has(key.toLowerCase())) continue;
    seen.add(key.toLowerCase());
    parts.push(`-H ${JSON.stringify(`${key}: ${value}`)}`);
  }
  if (!seen.has('user-agent')) {
    parts.push(`-H ${JSON.stringify('User-Agent: CyberSec-Verify/1.0')}`);
  }
  if (!seen.has('accept')) {
    parts.push(`-H ${JSON.stringify('Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')}`);
  }
  if (variant.data != null && variant.data !== '') {
    const body = typeof variant.data === 'string' ? variant.data : String(variant.data);
    parts.push(`--data-raw ${JSON.stringify(body)}`);
  }
  parts.push(JSON.stringify(variant.url));
  return parts.join(' ');
}

function snapshotResponse(res) {
  if (!res) return null;
  const rawHeaders = res.headers || {};
  const selected = {};
  const interesting = ['content-type', 'location', 'server', 'cache-control', 'vary', 'x-powered-by', 'via'];
  for (const [key, value] of Object.entries(rawHeaders)) {
    const lower = key.toLowerCase();
    if (lower === 'set-cookie') {
      const cookieCount = Array.isArray(value) ? value.length : (value ? 1 : 0);
      selected['set-cookie-count'] = cookieCount;
      continue;
    }
    if (interesting.includes(lower)) {
      selected[lower] = Array.isArray(value) ? value[0] : value;
    }
  }
  const body = res.body || '';
  return {
    status: typeof res.status === 'number' ? res.status : null,
    timeMs: typeof res.timeMs === 'number' ? res.timeMs : null,
    length: typeof body === 'string' ? body.length : String(body).length,
    headers: selected
  };
}

function diffSnapshots(base, candidate) {
  if (!base || !candidate) return null;
  const added = [];
  const removed = [];
  const changed = [];
  const allKeys = new Set([
    ...Object.keys(base.headers || {}),
    ...Object.keys(candidate.headers || {})
  ]);
  for (const key of allKeys) {
    const baseVal = base.headers?.[key];
    const candVal = candidate.headers?.[key];
    if (baseVal == null && candVal != null) {
      added.push(key);
    } else if (baseVal != null && candVal == null) {
      removed.push(key);
    } else if (baseVal != null && candVal != null && baseVal !== candVal) {
      changed.push(key);
    }
  }
  return {
    statusChanged: base.status !== candidate.status,
    lengthDelta: (candidate.length || 0) - (base.length || 0),
    headers: {
      added,
      removed,
      changed
    }
  };
}

// Attempt multi-signal verification with request context (method/headers/data)
async function verifyFinding({ targetUrl, parameter, strategy = 'auto', requestContext = {}, seedPayloads = [], originalConfidence = null, captureRawBodies = false }) {
  const verificationStartedAt = Date.now();
  const signalsTested = [];
  const confirmations = [];
  const attempts = [];
  const payloadAttempts = [];
  const extraSignals = [];
  let confidenceScore = 0.0;
  let wafDetected = false;
  let dom = { checked: false };
  let remediationSuspected = false;
  // Aggregate simple WAF indicators across attempts for auditing/UI hints
  const wafFlags = { header: false, body: false, status: false };
  const wafSources = new Set();

  const evidence = {
    baseline: null,
    signals: {
      boolean: null,
      time: null,
      error: null,
      payloads: []
    },
    drift: null,
    dom: null,
    waf: null
  };
  const rawBodies = captureRawBodies ? {} : null;

  const recordRawBody = (scope, tag, response, variant) => {
    if (!captureRawBodies || !response) return null;
    const key = tag ? `${scope}:${tag}` : scope;
    const sanitizedHeaders = sanitizeHeadersForStorage(variant?.headers || {});
    if (rawBodies[key]) {
      // ensure uniqueness by appending timestamp suffix
      const uniqueKey = `${key}-${Date.now()}`;
      return recordRawBody(uniqueKey, null, response, variant);
    }
    rawBodies[key] = {
      scope,
      tag: tag || null,
      url: variant?.url || null,
      method: variant?.method || null,
      data: variant?.data || null,
      headers: sanitizedHeaders,
      status: response.status,
      timeMs: response.timeMs,
      body: response.body
    };
    return key;
  };

  const seededPayloads = Array.isArray(seedPayloads)
    ? seedPayloads
        .map((value) => {
          if (value == null) return '';
          if (typeof value === 'number') return value.toString();
          return String(value).trim();
        })
        .filter(Boolean)
        .filter((value, index, arr) => arr.indexOf(value) === index)
        .slice(0, 4)
    : [];

  const baselineConfidence =
    originalConfidence && typeof originalConfidence === 'object'
      ? {
          label: typeof originalConfidence.label === 'string' ? originalConfidence.label : null,
          score: typeof originalConfidence.score === 'number' ? originalConfidence.score : null
        }
      : null;

  let baselineResponse = null;
  let baselineNormalized = null;
  let baselineSnapshot = null;
  let baselineStatus = null;
  let baselineRecorded = false;
  let postDriftCheck = null;
  let bestPayload = null;

  try {
    const method = (requestContext.method || 'GET').toUpperCase();
    const headers = { ...(requestContext.headers || {}) };
    if (requestContext.userAgent) headers['User-Agent'] = requestContext.userAgent;
    if (requestContext.cookie) headers['Cookie'] = requestContext.cookie;
    const baseData = requestContext.data || null;

    const recordBaseline = (variant, res) => {
      if (baselineRecorded) return;
      baselineRecorded = true;
      attempts.push({ kind: 'baseline', url: variant?.url || null, status: res.status, timeMs: res.timeMs });
      evidence.baseline = {
        preview: buildResponsePreview(res, variant),
        fingerprint: snapshotResponse(res)
      };
      if (captureRawBodies) {
        recordRawBody('baseline', null, res, variant || { url: targetUrl, method, headers, data: baseData });
      }
    };

    const ensureBaseline = async () => {
      if (baselineResponse) return baselineResponse;
      const variant = buildRequestVariant({
        baseUrl: targetUrl,
        parameter,
        payload: '1',
        method,
        headers,
        data: baseData,
        cookie: requestContext.cookie
      });
      const res = await httpRequest(variant);
  baselineResponse = res;
  baselineStatus = res.status;
  baselineNormalized = normalizeHtml(res.body);
  baselineSnapshot = snapshotResponse(res);
      const baseWaf = detectWafIndicators(res);
      wafDetected = wafDetected || baseWaf.any;
      if (baseWaf.any) wafSources.add('baseline');
      wafFlags.header = wafFlags.header || !!baseWaf.headerHit;
      wafFlags.body = wafFlags.body || !!baseWaf.bodyHit;
      wafFlags.status = wafFlags.status || !!baseWaf.statusHit;
      recordBaseline(variant, res);
      return res;
    };

    // Determine which strategies to run
    const runBoolean = strategy === 'auto' || strategy === 'boolean';
    const runTime = strategy === 'auto' || strategy === 'time';
    const runError = strategy === 'auto' || strategy === 'error';

    // Boolean-based test
    if (runBoolean) {
      const truePayloads = [
        '1 AND 1=1',
        "' OR '1'='1"
      ];
      const falsePayloads = [
        '1 AND 1=2',
        "' OR '1'='2"
      ];

      const vTrue = buildRequestVariant({ baseUrl: targetUrl, parameter, payload: truePayloads[Math.floor(Math.random() * truePayloads.length)], method, headers, data: baseData, cookie: requestContext.cookie });
      const vFalse = buildRequestVariant({ baseUrl: targetUrl, parameter, payload: falsePayloads[Math.floor(Math.random() * falsePayloads.length)], method, headers, data: baseData, cookie: requestContext.cookie });

      // Random small delay 100-400ms between requests
      const r1 = await httpRequest(vTrue);
      await new Promise(r => setTimeout(r, 100 + Math.floor(Math.random() * 300)));
      const r2 = await httpRequest(vFalse);

  const n1 = normalizeHtml(r1.body);
  const n2 = normalizeHtml(r2.body);
  const diff = simpleDiffSummary(n1, n2);
  const lenDelta = Math.abs(n1.length - n2.length);
  const snapshotTrue = snapshotResponse(r1);
  const snapshotFalse = snapshotResponse(r2);
  const fingerprintDiff = diffSnapshots(snapshotTrue, snapshotFalse);

      const booleanTrueRawKey = recordRawBody('boolean', 'true', r1, vTrue);
      const booleanFalseRawKey = recordRawBody('boolean', 'false', r2, vFalse);
      evidence.signals.boolean = {
        diff,
        lengthDelta: lenDelta,
        fingerprintDiff,
        responses: {
          true: {
            preview: buildResponsePreview(r1, vTrue),
            snapshot: snapshotTrue,
            rawKey: booleanTrueRawKey
          },
          false: {
            preview: buildResponsePreview(r2, vFalse),
            snapshot: snapshotFalse,
            rawKey: booleanFalseRawKey
          }
        }
      };

      attempts.push({
        kind: 'boolean',
        true: { url: vTrue.url, status: r1.status, timeMs: r1.timeMs },
        false: { url: vFalse.url, status: r2.status, timeMs: r2.timeMs },
        diff,
        fingerprintDiff,
        trueVariant: vTrue,
        falseVariant: vFalse
      });
      const bWaf1 = detectWafIndicators(r1);
      const bWaf2 = detectWafIndicators(r2);
      wafDetected = wafDetected || bWaf1.any || bWaf2.any;
      if (bWaf1.any || bWaf2.any) wafSources.add('boolean');
      wafFlags.header = wafFlags.header || !!bWaf1.headerHit || !!bWaf2.headerHit;
      wafFlags.body = wafFlags.body || !!bWaf1.bodyHit || !!bWaf2.bodyHit;
      wafFlags.status = wafFlags.status || !!bWaf1.statusHit || !!bWaf2.statusHit;

      if (!diff.identical || lenDelta > 50 || r1.status !== r2.status) {
        signalsTested.push('boolean');
        confirmations.push('boolean');
        confidenceScore += 0.45; // significant weight
        if (fingerprintDiff) {
          extraSignals.push({
            type: 'boolean-fingerprint',
            description: 'Boolean test altered response fingerprint',
            fingerprintDiff
          });
        }
      } else if (fingerprintDiff && (fingerprintDiff.statusChanged || Math.abs(fingerprintDiff.lengthDelta) > 120)) {
        extraSignals.push({
          type: 'boolean-fingerprint-anomaly',
          description: 'Boolean test found header/status drift without content diff',
          fingerprintDiff
        });
      }
    }

    // Time-based test (light)
    if (runTime) {
      const sleepVariants = ['SLEEP(3)', 'SLEEP%283%29'];
      const sleep = sleepVariants[Math.floor(Math.random() * sleepVariants.length)];
      const vTime = buildRequestVariant({ baseUrl: targetUrl, parameter, payload: `1 AND ${sleep}`, method, headers, data: baseData, cookie: requestContext.cookie });
      const vBase = buildRequestVariant({ baseUrl: targetUrl, parameter, payload: '1', method, headers, data: baseData, cookie: requestContext.cookie });

      const base = await httpRequest(vBase);
      await new Promise(r => setTimeout(r, 100 + Math.floor(Math.random() * 200)));
      const delayed = await httpRequest(vTime);

  const snapshotBase = snapshotResponse(base);
  const snapshotDelayed = snapshotResponse(delayed);
  const fingerprintDiff = diffSnapshots(snapshotBase, snapshotDelayed);

      const timeBaselineRawKey = recordRawBody('time', 'baseline', base, vBase);
      const timeDelayedRawKey = recordRawBody('time', 'delayed', delayed, vTime);
      evidence.signals.time = {
        deltaMs: delayed.timeMs - base.timeMs,
        fingerprintDiff,
        responses: {
          baseline: {
            preview: buildResponsePreview(base, vBase),
            snapshot: snapshotBase,
            rawKey: timeBaselineRawKey
          },
          delayed: {
            preview: buildResponsePreview(delayed, vTime),
            snapshot: snapshotDelayed,
            rawKey: timeDelayedRawKey
          }
        }
      };

      attempts.push({
        kind: 'time',
        baseline: { url: vBase.url, timeMs: base.timeMs },
        delayed: { url: vTime.url, timeMs: delayed.timeMs },
        fingerprintDiff,
        baselineVariant: vBase,
        delayedVariant: vTime
      });
      const tWaf1 = detectWafIndicators(base);
      const tWaf2 = detectWafIndicators(delayed);
      wafDetected = wafDetected || tWaf1.any || tWaf2.any;
      if (tWaf1.any || tWaf2.any) wafSources.add('time');
      wafFlags.header = wafFlags.header || !!tWaf1.headerHit || !!tWaf2.headerHit;
      wafFlags.body = wafFlags.body || !!tWaf1.bodyHit || !!tWaf2.bodyHit;
      wafFlags.status = wafFlags.status || !!tWaf1.statusHit || !!tWaf2.statusHit;

      if (!baselineResponse) {
        baselineResponse = base;
        baselineStatus = base.status;
        baselineNormalized = normalizeHtml(base.body);
        baselineSnapshot = snapshotResponse(base);
        recordBaseline(vBase, base);
      }

      if (delayed.timeMs - base.timeMs > 1800) {
        signalsTested.push('time');
        confirmations.push('time');
        confidenceScore += 0.35;
        if (fingerprintDiff) {
          extraSignals.push({
            type: 'time-drift',
            description: 'Time-based payload also changed response fingerprint',
            fingerprintDiff
          });
        }
      } else if (fingerprintDiff && (fingerprintDiff.statusChanged || Math.abs(fingerprintDiff.lengthDelta) > 150)) {
        extraSignals.push({
          type: 'time-fingerprint-anomaly',
          description: 'Timing payload created subtle fingerprint shift without slow response',
          fingerprintDiff
        });
      }
    }

    // Error-based test
    if (runError) {
      const vErr = buildRequestVariant({ baseUrl: targetUrl, parameter, payload: "'", method, headers, data: baseData, cookie: requestContext.cookie });
      const errRes = await httpRequest(vErr);
      const body = (errRes.body || '').toString();
      const errorPatterns = /(sql syntax|mysql|postgres|oracle|sqlite|mssql|odbc|warning|unclosed quotation|unterminated string)/i;
      const errorRawKey = recordRawBody('error', 'probe', errRes, vErr);
      evidence.signals.error = {
        keywordMatch: errorPatterns.test(body),
        preview: buildResponsePreview(errRes, vErr),
        rawKey: errorRawKey
      };
  attempts.push({ kind: 'error', url: vErr.url, status: errRes.status, variant: vErr });
      const eWaf = detectWafIndicators(errRes);
      wafDetected = wafDetected || eWaf.any;
      if (eWaf.any) wafSources.add('error');
      wafFlags.header = wafFlags.header || !!eWaf.headerHit;
      wafFlags.body = wafFlags.body || !!eWaf.bodyHit;
      wafFlags.status = wafFlags.status || !!eWaf.statusHit;
      if (errorPatterns.test(body)) {
        signalsTested.push('error');
        confirmations.push('error');
        confidenceScore += 0.35;
      }
    }

    if (seededPayloads.length > 0) {
      try {
        const base = await ensureBaseline();
        const baseNorm = baselineNormalized || normalizeHtml(base.body);
        const baseStatus = baselineStatus ?? base.status;
        let payloadConfirmed = false;
        const keywordPattern = /(sql syntax|mysql|postgres|oracle|sqlite|mssql|odbc|warning|unclosed quotation|unterminated string|select\b|union\b|database)/i;

        for (const payload of seededPayloads) {
          const variant = buildRequestVariant({ baseUrl: targetUrl, parameter, payload, method, headers, data: baseData, cookie: requestContext.cookie });
          const res = await httpRequest(variant);
          const normalized = normalizeHtml(res.body);
          const diff = simpleDiffSummary(baseNorm, normalized);
          const lenDelta = Math.abs(normalized.length - baseNorm.length);
          const statusChanged = res.status !== baseStatus;
          const attemptSnapshot = snapshotResponse(res);
          const fingerprintDiff = baselineSnapshot ? diffSnapshots(baselineSnapshot, attemptSnapshot) : null;
          const keywordHit = keywordPattern.test(String(res.body || '')) || keywordPattern.test(normalized);
          const payloadTag = crypto.createHash('sha1').update(String(payload)).digest('hex').slice(0, 12);
          const payloadRawKey = recordRawBody('payload', payloadTag, res, variant);
          const payloadPreview = buildResponsePreview(res, variant);

          const attempt = { kind: 'payload', payload, url: variant.url, status: res.status, timeMs: res.timeMs, diff, fingerprintDiff, variant, keywordHit };
          attempts.push(attempt);
          payloadAttempts.push({ payload, url: variant.url, status: res.status, timeMs: res.timeMs, diff, fingerprintDiff, variant, keywordHit, preview: payloadPreview, rawKey: payloadRawKey });
          evidence.signals.payloads.push({
            payload,
            keywordHit,
            diff,
            fingerprintDiff,
            preview: payloadPreview,
            rawKey: payloadRawKey
          });

          const pWaf = detectWafIndicators(res);
          wafDetected = wafDetected || pWaf.any;
          if (pWaf.any) wafSources.add('payload');
          wafFlags.header = wafFlags.header || !!pWaf.headerHit;
          wafFlags.body = wafFlags.body || !!pWaf.bodyHit;
          wafFlags.status = wafFlags.status || !!pWaf.statusHit;

          if (!payloadConfirmed && (statusChanged || !diff.identical || lenDelta > 60 || keywordHit)) {
            payloadConfirmed = true;
            bestPayload = payload;
            confirmations.push('payload');
            signalsTested.push('payload');
            confidenceScore += 0.3;
            if (fingerprintDiff) {
              extraSignals.push({
                type: 'payload-fingerprint',
                description: `Seeded payload ${payload} changed response fingerprint`,
                payload,
                fingerprintDiff
              });
            }
          }

          if (payloadConfirmed) {
            break;
          }

          if (!fingerprintDiff && (lenDelta > 120 || statusChanged)) {
            extraSignals.push({
              type: 'payload-anomaly',
              description: `Payload ${payload} altered status/content without fingerprint diff`,
              payload,
              statusChanged,
              lenDelta
            });
          } else if (fingerprintDiff && (fingerprintDiff.statusChanged || Math.abs(fingerprintDiff.lengthDelta) > 150 || fingerprintDiff.headers.added.length || fingerprintDiff.headers.removed.length || fingerprintDiff.headers.changed.length)) {
            extraSignals.push({
              type: 'payload-drift',
              description: `Payload ${payload} introduced notable header/status drift`,
              payload,
              fingerprintDiff
            });
          }
        }
      } catch (err) {
        attempts.push({ kind: 'payload-error', error: err.message });
      }
    }

    if (baselineResponse && baselineSnapshot) {
      try {
        const driftVariant = buildRequestVariant({
          baseUrl: targetUrl,
          parameter,
          payload: '1',
          method,
          headers,
          data: baseData,
          cookie: requestContext.cookie
        });
        const driftResponse = await httpRequest(driftVariant);
        const driftSnapshot = snapshotResponse(driftResponse);
        const baselineNorm = baselineNormalized || normalizeHtml(baselineResponse.body || '');
        const driftNormalized = normalizeHtml(driftResponse.body || '');
        const contentDiff = simpleDiffSummary(baselineNorm, driftNormalized);
        const fingerprintDiff = diffSnapshots(baselineSnapshot, driftSnapshot);
        const driftRawKey = recordRawBody('drift', 'post', driftResponse, driftVariant);
        evidence.drift = {
          preview: buildResponsePreview(driftResponse, driftVariant),
          fingerprintDiff,
          contentDiff,
          rawKey: driftRawKey
        };
        postDriftCheck = {
          url: driftVariant.url,
          status: driftResponse.status,
          timeMs: driftResponse.timeMs,
          fingerprintDiff,
          contentDiff
        };

        const largeContentShift = !contentDiff.identical && (contentDiff.changed > 45 || contentDiff.added + contentDiff.removed > 30);
        const fingerprintShift = fingerprintDiff && (
          fingerprintDiff.statusChanged ||
          Math.abs(fingerprintDiff.lengthDelta) > 180 ||
          fingerprintDiff.headers.added.length > 0 ||
          fingerprintDiff.headers.removed.length > 0 ||
          fingerprintDiff.headers.changed.length > 0
        );

        if (largeContentShift || fingerprintShift) {
          remediationSuspected = true;
          extraSignals.push({
            type: 'drift-detected',
            description: 'Baseline response drifted notably after verification attempts; remediation may have occurred.',
            fingerprintDiff,
            contentDiff
          });
        } else {
          extraSignals.push({
            type: 'drift-stable',
            description: 'Baseline response fingerprint remained stable after verification.',
            fingerprintDiff,
            contentDiff
          });
        }
      } catch (err) {
        extraSignals.push({ type: 'drift-check-error', description: `Drift validation failed: ${err.message}` });
      }
    }

    // Cap score to 1.0
    confidenceScore = Math.min(1.0, confidenceScore);

    let label = confidenceScore >= 0.85 && confirmations.length >= 2
      ? 'Confirmed'
      : confidenceScore >= 0.5
        ? 'Likely'
        : 'Suspected';

    if (wafDetected) {
      label = 'Inconclusive';
    }

    if (remediationSuspected && !wafDetected) {
      label = label === 'Confirmed' ? 'Likely' : label;
      if (confidenceScore > 0.75) {
        confidenceScore = Math.min(confidenceScore, 0.75);
      }
    }

    // DOM-based validation: only attempt if no WAF and method is GET-like (we mutate URL param)
    if (!wafDetected && method === 'GET') {
      try {
        const domRes = await domReflectionCheck({ url: targetUrl, parameter, requestContext });
        dom = { checked: true, ok: domRes.ok, reflected: !!domRes.reflected, matches: domRes.matches || [] };
        evidence.dom = {
          ok: domRes.ok,
          reflected: !!domRes.reflected,
          matches: Array.isArray(domRes.matches) ? domRes.matches.slice(0, 10) : [],
          url: domRes.url || null,
          screenshotCaptured: !!domRes.screenshotBuffer
        };
        if (domRes.ok && domRes.reflected) {
          // If HTTP signals exist, DOM alignment allows upgrade within bounds
          if (confirmations.length >= 2) {
            confidenceScore = Math.min(1.0, Math.max(confidenceScore, 0.9));
            label = confidenceScore >= 0.85 ? 'Confirmed' : label;
          } else if (confirmations.length >= 1) {
            confidenceScore = Math.min(1.0, confidenceScore + 0.1);
            if (confidenceScore >= 0.85 && confirmations.length >= 2) {
              label = 'Confirmed';
            } else if (confidenceScore >= 0.5) {
              label = 'Likely';
            }
          }
        } else if (domRes.ok && !domRes.reflected) {
          // DOM failed to reflect; avoid overconfidence
          if (label === 'Confirmed') {
            label = 'Likely';
            confidenceScore = Math.min(confidenceScore, 0.8);
            dom.domMismatch = true;
          }
        }
        // Attach transient screenshot buffer for caller to persist
        if (domRes.screenshotBuffer) {
          dom.screenshotBuffer = domRes.screenshotBuffer;
        }
        if (domRes.url) dom.url = domRes.url;
      } catch (e) {
        // Non-fatal: proceed without DOM check
        Logger.warn('DOM validation failed', { error: e.message });
      }
    }

  const verificationCompletedAt = Date.now();

  evidence.waf = {
    detected: wafDetected,
    indicators: wafDetected
      ? {
          ...wafFlags,
          sources: Array.from(wafSources)
        }
      : null
  };

  const signalSummary = `Signals: ${confirmations.join(', ') || 'none'}`;
    const domSummary = `DOM: ${dom.checked ? (dom.reflected ? 'reflected' : 'not-reflected') : 'skipped'}`;
    const payloadSummary = seededPayloads.length > 0
      ? ` Payloads tested: ${seededPayloads.length}${confirmations.includes('payload') ? ' (variance detected)' : ' (no change observed)'}.`
      : '';
    const remediationSummary = remediationSuspected
      ? ' Baseline drift detected after attempts; target may have remediated or altered responses.'
      : '';
    const extraSummary = extraSignals.length > 0
      ? ` Extra signals recorded (${extraSignals.length}).`
      : '';

    const why = wafDetected
      ? 'WAF indicators detected; results inconclusive. Consider suggested tamper and slower settings.'
      : `${signalSummary}; ${domSummary}.${payloadSummary}${remediationSummary}${extraSummary} Score ${Math.round(confidenceScore * 100)}%.`;

    const baselineAttempt = attempts.find(a => a.kind === 'baseline') || null;
    const booleanAttempt = attempts.find(a => a.kind === 'boolean') || null;
    const timeAttempt = attempts.find(a => a.kind === 'time') || null;
    const errorAttempt = attempts.find(a => a.kind === 'error') || null;

    // Return PoC entries enriched with expected signal metadata
    const poc = [];
    const booleanTrueCurl = curlSnippet(booleanAttempt?.trueVariant);
    const booleanFalseCurl = curlSnippet(booleanAttempt?.falseVariant);
    const booleanTrueAttempt = booleanAttempt ? booleanAttempt.true : null;
    const booleanFalseAttempt = booleanAttempt ? booleanAttempt.false : null;
    const booleanEvidence = evidence.signals.boolean;
    if (booleanTrueCurl && booleanFalseCurl) {
      const lengthDelta = booleanEvidence?.lengthDelta ?? null;
      poc.push({
        name: 'boolean-true',
        curl: booleanTrueCurl,
        expectedSignal: {
          type: 'boolean',
          summary: lengthDelta && lengthDelta !== 0
            ? `Injected payload should shift response length by ${lengthDelta} characters`
            : 'Injected payload should alter response fingerprint or status',
          metrics: {
            status: booleanTrueAttempt?.status ?? null,
            timeMs: booleanTrueAttempt?.timeMs ?? null,
            lengthDelta
          }
        },
        evidencePreview: booleanEvidence?.responses?.true?.preview || null,
        rawKey: booleanEvidence?.responses?.true?.rawKey || null
      });
      poc.push({
        name: 'boolean-false',
        curl: booleanFalseCurl,
        expectedSignal: {
          type: 'boolean-control',
          summary: 'Control payload should preserve baseline response',
          metrics: {
            status: booleanFalseAttempt?.status ?? null,
            timeMs: booleanFalseAttempt?.timeMs ?? null
          }
        },
        evidencePreview: booleanEvidence?.responses?.false?.preview || null,
        rawKey: booleanEvidence?.responses?.false?.rawKey || null
      });
    }
    const timeCurl = curlSnippet(timeAttempt?.delayedVariant);
    if (timeCurl) {
      poc.push({
        name: 'time-delay',
        curl: timeCurl,
        expectedSignal: {
          type: 'time',
          summary: 'Injected payload should incur measurable delay (>1.8s)',
          metrics: {
            baselineMs: timeAttempt?.baseline?.timeMs ?? null,
            delayedMs: timeAttempt?.delayed?.timeMs ?? null,
            deltaMs: evidence.signals.time?.deltaMs ?? null
          }
        },
        evidencePreview: evidence.signals.time?.responses?.delayed?.preview || null,
        rawKey: evidence.signals.time?.responses?.delayed?.rawKey || null
      });
    }
    const errorCurl = curlSnippet(errorAttempt?.variant);
    if (errorCurl) {
      poc.push({
        name: 'error-trigger',
        curl: errorCurl,
        expectedSignal: {
          type: 'error',
          summary: evidence.signals.error?.keywordMatch
            ? 'Payload should surface database error banners'
            : 'Payload expected to probe for error disclosure',
          metrics: {
            status: errorAttempt?.status ?? null
          }
        },
        evidencePreview: evidence.signals.error?.preview || null,
        rawKey: evidence.signals.error?.rawKey || null
      });
    }
    if (payloadAttempts.length > 0) {
      payloadAttempts.slice(0, 2).forEach((attempt, idx) => {
        const curl = curlSnippet(attempt.variant);
        if (curl) {
          const payloadEvidence = evidence.signals.payloads[idx] || null;
          poc.push({
            name: `payload-${idx + 1}`,
            curl,
            expectedSignal: {
              type: 'payload-replay',
              summary: payloadEvidence?.keywordHit
                ? 'Replay payload should reproduce SQL banner keywords'
                : 'Replay payload should alter fingerprint relative to baseline',
              metrics: {
                status: attempt.status ?? null,
                timeMs: attempt.timeMs ?? null,
                diffChanged: attempt.diff?.changed ?? null
              }
            },
            evidencePreview: payloadEvidence?.preview || attempt.preview || null,
            rawKey: payloadEvidence?.rawKey || attempt.rawKey || null
          });
        }
      });
    }

    // Diff view payload (sanitized)
  const sanitizedPayloadAttempts = payloadAttempts.map(({ variant: _variant, ...rest }) => rest);
    const diffView = {
      baseline: baselineAttempt,
      boolean: booleanAttempt
        ? {
            true: booleanAttempt.true,
            false: booleanAttempt.false,
            diff: booleanAttempt.diff,
            fingerprintDiff: booleanAttempt.fingerprintDiff
          }
        : null,
      time: timeAttempt
        ? {
            baseline: timeAttempt.baseline,
            delayed: timeAttempt.delayed,
            fingerprintDiff: timeAttempt.fingerprintDiff
          }
        : null,
      error: errorAttempt
        ? {
            url: errorAttempt.url,
            status: errorAttempt.status
          }
        : null,
      payload: sanitizedPayloadAttempts.length > 0 ? sanitizedPayloadAttempts : null
    };

    return {
      ok: true,
      label,
      confidenceScore,
      confirmations,
      signalsTested,
      remediationSuspected,
      verificationStartedAt,
  verificationCompletedAt,
      diffView,
      poc,
      wafDetected,
      wafIndicators: wafDetected ? { ...wafFlags, sources: Array.from(wafSources) } : undefined,
      suggestions: wafDetected ? wafSuggestions() : [],
      why,
      dom,
      seededPayloads: seededPayloads.length > 0 ? seededPayloads : undefined,
      payloadAttempts: sanitizedPayloadAttempts.length > 0 ? sanitizedPayloadAttempts : undefined,
      baselineConfidence: baselineConfidence || undefined,
      extraSignals: extraSignals.length > 0 ? extraSignals : undefined,
      bestPayload: bestPayload || undefined,
      driftCheck: postDriftCheck || undefined,
      evidence,
      rawBodies: captureRawBodies && rawBodies ? rawBodies : undefined
    };
  } catch (e) {
    Logger.warn('verifyFinding failed', { error: e.message });
    return { ok: false, error: e.message };
  }
}

module.exports = { verifyFinding, normalizeHtml };
