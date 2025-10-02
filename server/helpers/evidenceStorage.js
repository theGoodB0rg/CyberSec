const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

function ensureDir(dirPath) {
  if (!fs.existsSync(dirPath)) {
    fs.mkdirSync(dirPath, { recursive: true });
  }
}

function safeSegment(value, fallback = 'part') {
  const base = String(value || fallback)
    .toLowerCase()
    .replace(/[^a-z0-9\-_.]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '');
  return base || fallback;
}

function toBuffer(value) {
  if (Buffer.isBuffer(value)) return value;
  if (typeof value === 'string') return Buffer.from(value, 'utf8');
  if (value == null) return Buffer.from('', 'utf8');
  if (typeof value === 'object') {
    try {
      return Buffer.from(JSON.stringify(value), 'utf8');
    } catch (_) {
      return Buffer.from(String(value), 'utf8');
    }
  }
  return Buffer.from(String(value), 'utf8');
}

function computeDigest(buffer, algo = 'sha256') {
  return crypto.createHash(algo).update(buffer).digest('hex');
}

function summarizeRawBodies(rawBodies = {}) {
  const summaries = [];
  for (const [key, entry] of Object.entries(rawBodies || {})) {
    const buffer = toBuffer(entry.body);
    const contentType = entry.headers?.['content-type'] || entry.headers?.['Content-Type'] || null;
    summaries.push({
      key,
      scope: entry.scope || null,
      tag: entry.tag || null,
      status: entry.status != null ? Number(entry.status) : null,
      timeMs: entry.timeMs != null ? Number(entry.timeMs) : null,
      bodyHash: computeDigest(buffer),
      bodyLength: buffer.length,
      contentType
    });
  }
  return summaries;
}

function persistQuickVerifyRawBodies({ baseDir, reportId, findingId, rawBodies = {}, timestamp = new Date() }) {
  if (!baseDir) {
    throw new Error('baseDir is required to persist quick verify evidence');
  }
  const tsSlug = safeSegment(timestamp.toISOString().replace(/[:.]/g, '-'), 'ts');
  const reportSegment = safeSegment(reportId, 'report');
  const findingSegment = safeSegment(findingId, 'finding');
  const outDir = path.join(baseDir, reportSegment, findingSegment, tsSlug);
  ensureDir(outDir);

  const persisted = [];
  for (const [key, entry] of Object.entries(rawBodies || {})) {
    const buffer = toBuffer(entry.body);
    const digest = computeDigest(buffer);
    const filename = `${safeSegment(key, 'sample')}-${digest.slice(0, 12)}.json`;
    const filePath = path.join(outDir, filename);
    const payload = {
      key,
      capturedAt: timestamp.toISOString(),
      scope: entry.scope || null,
      tag: entry.tag || null,
      status: entry.status != null ? Number(entry.status) : null,
      timeMs: entry.timeMs != null ? Number(entry.timeMs) : null,
      method: entry.method || null,
      url: entry.url || null,
      headers: entry.headers || {},
      data: entry.data || null,
      bodyEncoding: 'base64',
      bodyHash: digest,
      bodyLength: buffer.length,
      body: buffer.toString('base64')
    };
    fs.writeFileSync(filePath, JSON.stringify(payload, null, 2), { encoding: 'utf8' });
    persisted.push({
      key,
      scope: entry.scope || null,
      tag: entry.tag || null,
      status: entry.status != null ? Number(entry.status) : null,
      timeMs: entry.timeMs != null ? Number(entry.timeMs) : null,
      method: entry.method || null,
      url: entry.url || null,
      headers: entry.headers || {},
      storedPath: filePath,
      bodyHash: digest,
      bodyLength: buffer.length,
      contentType: entry.headers?.['content-type'] || entry.headers?.['Content-Type'] || null
    });
  }
  return persisted;
}

function remapEvidenceRawKeys(evidence, mapping = {}) {
  if (!evidence) return null;
  const clone = JSON.parse(JSON.stringify(evidence));
  const visit = (node) => {
    if (!node || typeof node !== 'object') return;
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    if (node.rawKey) {
      const mapped = mapping[node.rawKey];
      if (mapped) {
        node.rawEvidenceId = mapped.id;
        node.rawEvidenceHash = mapped.bodyHash;
        node.rawEvidenceLength = mapped.bodyLength;
        node.rawKey = mapped.id;
      } else {
        delete node.rawKey;
      }
    }
    Object.values(node).forEach(visit);
  };
  visit(clone);
  return clone;
}

module.exports = {
  persistQuickVerifyRawBodies,
  summarizeRawBodies,
  remapEvidenceRawKeys
};
