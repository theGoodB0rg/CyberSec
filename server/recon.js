const axios = require('axios');
const cheerio = require('cheerio');
const crypto = require('crypto');
const { URL } = require('url');
const Logger = require('./utils/logger');

/**
 * Phase 0 Recon & Parameter Discovery
 * - Fetch target (and limited same-domain links depth 1)
 * - Extract form inputs, query params, JSON keys
 * - Reflection scoring: inject canary tokens, detect echo & transformation
 * - Build parameter feature vectors for adaptive scanning
 */
class ReconEngine {
  constructor(options = {}) {
    this.maxPages = options.maxPages || 5;
    this.timeout = options.timeout || 10000;
    this.canary = options.canary || 'CYBERSEC_CANARY';
    this.userAgent = options.userAgent || 'CyberSec-Recon/1.0';
    this.samplePayloads = ["'", '"', '1 OR 1=1', this.canary];
  }

  async run(target) {
    const start = Date.now();
    const pagesCrawled = new Set();
  const queue = [{ url: target, depth: 0, parent: null }];
    const parameters = new Map(); // key: name, value: feature object
    const domain = new URL(target).hostname;
  const pageMeta = []; // crawl graph metadata
  const visited = new Map(); // url -> depth
  visited.set(target, 0);

    while (queue.length && pagesCrawled.size < this.maxPages) {
      const { url, depth, parent } = queue.shift();
      if (pagesCrawled.has(url)) continue;
      try {
        const fetchStart = Date.now();
        const res = await axios.get(url, { timeout: this.timeout, headers: { 'User-Agent': this.userAgent }});
        const fetchTime = Date.now() - fetchStart;
        pagesCrawled.add(url);
        const contentType = res.headers['content-type'] || '';
        if (contentType.includes('text/html')) {
          const { newLinks, foundParams } = this.parseHTML(url, res.data);
          // enqueue same-domain links
          newLinks.forEach(l => {
            if (new URL(l).hostname === domain && !pagesCrawled.has(l) && !visited.has(l) && queue.length + pagesCrawled.size < this.maxPages) {
              visited.set(l, depth + 1);
              queue.push({ url: l, depth: depth + 1, parent: url });
            }
          });
          foundParams.forEach(p => this.addOrMergeParam(parameters, p));
        } else if (contentType.includes('application/json')) {
          this.parseJSON(res.data, parameters);
        }
        pageMeta.push({
          id: crypto.randomUUID(),
          url,
          parent_url: parent || null,
          depth: depth || 0,
          status: res.status,
          content_type: contentType.substring(0,120),
          fetch_time_ms: fetchTime
        });
      } catch (err) {
        Logger.warn('Recon fetch failed', { url, error: err.message });
      }
    }

    // Reflection scoring (one lightweight request per parameter with canary)
    const reflectionResults = await this.computeReflectionScores(target, parameters);

    // Merge reflection metrics into parameter objects before scoring persistence externally
    for (const p of parameters.values()) {
      if (reflectionResults[p.name]) {
        const r = reflectionResults[p.name];
        p.reflection = {
          reflected: r.reflected,
          occurrences: r.occurrences,
          transformed: r.transformed,
          lengthDelta: r.lengthDelta,
          baseLatencyMs: r.baseLatencyMs,
          reflectionLatencyMs: r.reflectionLatencyMs,
          nameEntropy: r.nameEntropy,
          priorityScore: r.priorityScore
        };
        p.name_length = p.name.length;
        p.name_entropy = r.nameEntropy;
        p.base_latency_ms = r.baseLatencyMs;
        p.reflection_latency_ms = r.reflectionLatencyMs;
        p.priority_score = r.priorityScore;
      }
    }

    const result = {
      target,
      pagesCrawled: Array.from(pagesCrawled),
      parameterCount: parameters.size,
      parameters: Array.from(parameters.values()).map(p => ({
        ...p,
        sources: Array.from(p.sources),
        methods: Array.from(p.methods),
        actions: Array.from(p.actions),
        types: Array.from(p.types),
        reflection: reflectionResults[p.name] || null
      })),
  durationMs: Date.now() - start,
  pages: pageMeta,
  priorityRanking: Array.from(parameters.values()).sort((a,b)=>(b.reflection?.priorityScore||0)-(a.reflection?.priorityScore||0)).map(p=>({ name: p.name, score: p.reflection?.priorityScore||0 }))
    };

    Logger.info('Recon complete', { target, parameters: result.parameterCount, pages: result.pagesCrawled.length });
    return result;
  }

  parseHTML(baseUrl, html) {
    const $ = cheerio.load(html);
    const newLinks = new Set();
    const foundParams = [];

    $('a[href]').each((_, el) => {
      const href = $(el).attr('href');
      if (!href || href.startsWith('#') || href.startsWith('mailto:')) return;
      try { newLinks.add(new URL(href, baseUrl).toString()); } catch (_) {}
    });

    // Forms
    $('form').each((_, form) => {
      const method = ($(form).attr('method') || 'GET').toUpperCase();
      const actionRaw = $(form).attr('action') || baseUrl;
      let action;
      try { action = new URL(actionRaw, baseUrl).toString(); } catch { action = baseUrl; }
      $(form).find('input,textarea,select').each((__, field) => {
        const name = $(field).attr('name');
        if (!name) return;
        const type = ($(field).attr('type') || field.tagName || 'text').toLowerCase();
        foundParams.push({ name, source: 'form', method, action, type });
      });
    });

    // Query params from links
    newLinks.forEach(l => {
      try {
        const u = new URL(l);
        u.searchParams.forEach((_, key) => {
          foundParams.push({ name: key, source: 'query', method: 'GET', action: l, type: 'string' });
        });
      } catch (_) {}
    });

    return { newLinks, foundParams };
  }

  parseJSON(body, parameters) {
    try {
      const data = typeof body === 'string' ? JSON.parse(body) : body;
      const walk = (node, prefix = '') => {
        if (node && typeof node === 'object') {
          for (const [k, v] of Object.entries(node)) {
            const full = prefix ? `${prefix}.${k}` : k;
            if (typeof v !== 'object') {
              this.addOrMergeParam(parameters, { name: full, source: 'json', method: 'GET', action: 'inline', type: typeof v });
            } else {
              walk(v, full);
            }
          }
        }
      };
      walk(data);
    } catch (_) {}
  }

  addOrMergeParam(map, param) {
    if (!map.has(param.name)) {
      map.set(param.name, {
        id: crypto.randomUUID(),
        name: param.name,
        sources: new Set([param.source]),
        methods: new Set([param.method]),
        actions: new Set([param.action]),
        types: new Set([param.type]),
        observations: 1
      });
    } else {
      const existing = map.get(param.name);
      existing.sources.add(param.source);
      existing.methods.add(param.method);
      existing.actions.add(param.action);
      existing.types.add(param.type);
      existing.observations += 1;
    }
  }

  async computeReflectionScores(target, paramMap) {
    const scores = {};
    const base = await this.safeFetch(target);
    if (!base) return scores;
    const baseText = base.text;

    for (const p of paramMap.values()) {
      try {
        // Only test GET style reflection for now
        const testUrl = new URL(target);
        testUrl.searchParams.set(p.name, this.canary);
        const baseLatency = await this.measureLatency(target);
        const reflectionLatency = await this.measureLatency(testUrl.toString());
        const resp = await this.safeFetch(testUrl.toString());
        if (!resp) continue;
        const occurrences = (resp.text.match(new RegExp(this.escapeRegex(this.canary), 'g')) || []).length;
        const transformed = occurrences === 0 && resp.text.toLowerCase().includes(this.canary.toLowerCase());
        const nameEntropy = this.stringEntropy(p.name);
        const priority = this.computePriority({
          reflected: occurrences > 0,
          occurrences,
          nameEntropy,
          nameLength: p.name.length,
          lengthDelta: resp.text.length - baseText.length
        });
        scores[p.name] = {
          occurrences,
          reflected: occurrences > 0,
          transformed,
          lengthDelta: resp.text.length - baseText.length,
          baseLatencyMs: baseLatency,
          reflectionLatencyMs: reflectionLatency,
          nameEntropy,
          priorityScore: priority
        };
      } catch (e) {
        Logger.debug('Reflection test failed', { param: p.name, error: e.message });
      }
    }
    return scores;
  }

  computePriority({ reflected, occurrences, nameEntropy, nameLength, lengthDelta }) {
    // Heuristic: reflections weigh most, then occurrences, then lower entropy (less random) names, then length delta
    const reflectionWeight = reflected ? 60 : 0;
    const occurrenceWeight = Math.min(occurrences * 10, 30);
    const entropyWeight = (1 - Math.min(nameEntropy / 4, 1)) * 5; // penalize very high entropy
    const lengthDeltaWeight = Math.min(Math.abs(lengthDelta) / 500, 5);
    const shortNameBonus = nameLength <= 5 ? 5 : 0;
    return reflectionWeight + occurrenceWeight + entropyWeight + lengthDeltaWeight + shortNameBonus;
  }

  stringEntropy(str) {
    if (!str) return 0;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch]||0)+1;
    const len = str.length;
    let ent = 0;
    for (const f of Object.values(freq)) {
      const p = f/len;
      ent -= p * Math.log2(p);
    }
    return ent;
  }

  async measureLatency(url, samples = 2) {
    let total = 0, count = 0;
    for (let i=0;i<samples;i++) {
      const t0 = Date.now();
      const ok = await this.safeFetch(url);
      if (ok) { total += Date.now()-t0; count++; }
    }
    return count? Math.round(total / count): null;
  }

  async safeFetch(url) {
    try {
      const res = await axios.get(url, { timeout: this.timeout, headers: { 'User-Agent': this.userAgent }});
      if (typeof res.data === 'string') {
        return { text: res.data, status: res.status };
      }
      return { text: JSON.stringify(res.data).slice(0, 100000), status: res.status };
    } catch (err) {
      return null;
    }
  }

  escapeRegex(str) {
    return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }
}

module.exports = ReconEngine;
