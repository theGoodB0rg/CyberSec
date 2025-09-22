const axios = require('axios');
const sanitizeHtml = require('sanitize-html');
const { URL } = require('url');
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

function curlSnippet(url) {
  return `curl -i -A "CyberSec-Verify/1.0" ${JSON.stringify(url)}`;
}

// Attempt multi-signal verification with request context (method/headers/data)
async function verifyFinding({ targetUrl, parameter, strategy = 'auto', requestContext = {} }) {
  const signalsTested = [];
  const confirmations = [];
  const attempts = [];
  let confidenceScore = 0.0;
  let wafDetected = false;
  let dom = { checked: false };
  // Aggregate simple WAF indicators across attempts for auditing/UI hints
  const wafFlags = { header: false, body: false, status: false };
  const wafSources = new Set();

  try {
    const method = (requestContext.method || 'GET').toUpperCase();
    const headers = { ...(requestContext.headers || {}) };
    if (requestContext.userAgent) headers['User-Agent'] = requestContext.userAgent;
    if (requestContext.cookie) headers['Cookie'] = requestContext.cookie;
    const baseData = requestContext.data || null;

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

    const vTrue = buildRequestVariant({ baseUrl: targetUrl, parameter, payload: truePayloads[Math.floor(Math.random()*truePayloads.length)], method, headers, data: baseData, cookie: requestContext.cookie });
    const vFalse = buildRequestVariant({ baseUrl: targetUrl, parameter, payload: falsePayloads[Math.floor(Math.random()*falsePayloads.length)], method, headers, data: baseData, cookie: requestContext.cookie });

    // Random small delay 100-400ms between requests
    const r1 = await httpRequest(vTrue);
    await new Promise(r => setTimeout(r, 100 + Math.floor(Math.random()*300)));
    const r2 = await httpRequest(vFalse);

    const n1 = normalizeHtml(r1.body);
    const n2 = normalizeHtml(r2.body);
    const diff = simpleDiffSummary(n1, n2);
    const lenDelta = Math.abs(n1.length - n2.length);

    attempts.push({ kind: 'boolean', true: { url: vTrue.url, status: r1.status, timeMs: r1.timeMs }, false: { url: vFalse.url, status: r2.status, timeMs: r2.timeMs }, diff });
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
    }
    }

    // Time-based test (light)
    if (runTime) {
    const sleepVariants = ['SLEEP(3)', 'SLEEP%283%29'];
    const sleep = sleepVariants[Math.floor(Math.random()*sleepVariants.length)];
    const vTime = buildRequestVariant({ baseUrl: targetUrl, parameter, payload: `1 AND ${sleep}`, method, headers, data: baseData, cookie: requestContext.cookie });
    const vBase = buildRequestVariant({ baseUrl: targetUrl, parameter, payload: '1', method, headers, data: baseData, cookie: requestContext.cookie });

    const base = await httpRequest(vBase);
    await new Promise(r => setTimeout(r, 100 + Math.floor(Math.random()*200)));
    const delayed = await httpRequest(vTime);

    attempts.push({ kind: 'time', baseline: { url: vBase.url, timeMs: base.timeMs }, delayed: { url: vTime.url, timeMs: delayed.timeMs } });
  const tWaf1 = detectWafIndicators(base);
  const tWaf2 = detectWafIndicators(delayed);
  wafDetected = wafDetected || tWaf1.any || tWaf2.any;
  if (tWaf1.any || tWaf2.any) wafSources.add('time');
  wafFlags.header = wafFlags.header || !!tWaf1.headerHit || !!tWaf2.headerHit;
  wafFlags.body = wafFlags.body || !!tWaf1.bodyHit || !!tWaf2.bodyHit;
  wafFlags.status = wafFlags.status || !!tWaf1.statusHit || !!tWaf2.statusHit;
    if (delayed.timeMs - base.timeMs > 1800) {
      signalsTested.push('time');
      confirmations.push('time');
      confidenceScore += 0.35;
    }
    }

    // Error-based test
    if (runError) {
    const vErr = buildRequestVariant({ baseUrl: targetUrl, parameter, payload: "'", method, headers, data: baseData, cookie: requestContext.cookie });
    const errRes = await httpRequest(vErr);
    const body = (errRes.body || '').toString();
    const errorPatterns = /(sql syntax|mysql|postgres|oracle|sqlite|mssql|odbc|warning|unclosed quotation|unterminated string)/i;
    attempts.push({ kind: 'error', url: vErr.url, status: errRes.status });
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

    // DOM-based validation: only attempt if no WAF and method is GET-like (we mutate URL param)
    if (!wafDetected && String(requestContext.method || 'GET').toUpperCase() === 'GET') {
      try {
        const domRes = await domReflectionCheck({ url: targetUrl, parameter, requestContext });
        dom = { checked: true, ok: domRes.ok, reflected: !!domRes.reflected, matches: domRes.matches || [] };
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

    const why = wafDetected
      ? 'WAF indicators detected; results inconclusive. Consider suggested tamper and slower settings.'
      : `Signals: ${confirmations.join(', ') || 'none'}; DOM: ${dom.checked ? (dom.reflected ? 'reflected' : 'not-reflected') : 'skipped'}. Score ${Math.round(confidenceScore*100)}%.`;

    // Diff view payload
    const diffView = {
      boolean: attempts.find(a => a.kind === 'boolean') || null,
      time: attempts.find(a => a.kind === 'time') || null,
      error: attempts.find(a => a.kind === 'error') || null
    };

    // Return minimal PoC pairs and cURL
    const poc = [];
    if (diffView.boolean?.true?.url && diffView.boolean?.false?.url) {
      poc.push({ name: 'boolean-true', curl: curlSnippet(diffView.boolean.true.url) });
      poc.push({ name: 'boolean-false', curl: curlSnippet(diffView.boolean.false.url) });
    }
    if (diffView.time?.delayed?.url) {
      poc.push({ name: 'time-delay', curl: curlSnippet(diffView.time.delayed.url) });
    }
    if (diffView.error?.url) {
      poc.push({ name: 'error-trigger', curl: curlSnippet(diffView.error.url) });
    }

    return {
      ok: true,
      label,
      confidenceScore,
      confirmations,
      signalsTested,
      diffView,
      poc,
      wafDetected,
      wafIndicators: wafDetected ? { ...wafFlags, sources: Array.from(wafSources) } : undefined,
      suggestions: wafDetected ? wafSuggestions() : [],
      why,
      dom
    };
  } catch (e) {
    Logger.warn('verifyFinding failed', { error: e.message });
    return { ok: false, error: e.message };
  }
}

module.exports = { verifyFinding, normalizeHtml };
