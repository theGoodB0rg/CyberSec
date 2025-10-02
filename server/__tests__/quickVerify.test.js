/* eslint-env jest */
const fs = require('fs');
const os = require('os');
const path = require('path');

const Database = require('../database');
const {
  persistQuickVerifyRawBodies,
  summarizeRawBodies
} = require('../helpers/evidenceStorage');

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function createTempDir(prefix) {
  return fs.mkdtempSync(path.join(os.tmpdir(), prefix));
}

async function waitForTable(database, tableName) {
  for (let attempt = 0; attempt < 25; attempt += 1) {
    // eslint-disable-next-line no-await-in-loop
    const exists = await new Promise((resolve) => {
      database.db.get(
        "SELECT name FROM sqlite_master WHERE type='table' AND name = ?",
        [tableName],
        (err, row) => {
          if (err) {
            resolve(false);
            return;
          }
          resolve(!!row);
        }
      );
    });
    if (exists) return;
    // eslint-disable-next-line no-await-in-loop
    await sleep(20);
  }
  throw new Error(`Timed out waiting for table ${tableName}`);
}

describe('Quick verify consent & evidence persistence', () => {
  let db;

  beforeEach(async () => {
    db = new Database(':memory:');
    await waitForTable(db, 'quick_verify_preferences');
    await waitForTable(db, 'quick_verify_evidence');
  });

  afterEach(async () => {
    if (db && db.db) {
      await new Promise((resolve, reject) => {
        db.db.close((err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    }
    db = null;
  });

  it('creates and updates quick verify preferences', async () => {
    const defaults = await db.getQuickVerifyPreference('user-1');
    expect(defaults.storeEvidence).toBeNull();
    expect(defaults.rememberChoice).toBe(false);
    expect(defaults.promptVersion).toBe(1);

    const firstUpdate = await db.upsertQuickVerifyPreference('user-1', {
      storeEvidence: true,
      rememberChoice: true,
      promptSuppressed: true,
      promptVersion: 3,
      lastPromptAt: '2024-01-01T00:00:00.000Z',
      lastDecisionAt: '2024-01-01T00:00:01.000Z',
      source: 'jest-test'
    });

    expect(firstUpdate.storeEvidence).toBe(true);
    expect(firstUpdate.rememberChoice).toBe(true);
    expect(firstUpdate.promptSuppressed).toBe(true);
    expect(firstUpdate.promptVersion).toBe(3);
    expect(firstUpdate.lastPromptAt).toBe('2024-01-01T00:00:00.000Z');
    expect(firstUpdate.lastDecisionAt).toBe('2024-01-01T00:00:01.000Z');
    expect(firstUpdate.source).toBe('jest-test');

    const merged = await db.upsertQuickVerifyPreference('user-1', {
      storeEvidence: false,
      rememberChoice: false
    });

    expect(merged.storeEvidence).toBe(false);
    expect(merged.rememberChoice).toBe(false);
    // unchanged values should persist
    expect(merged.promptVersion).toBe(3);
    expect(merged.source).toBe('jest-test');
  });

  it('persists and filters quick verify evidence records', async () => {
    const reportId = 'report-123';
    const findingId = 'finding-abc';

    const recordA = await db.addQuickVerifyEvidence({
      userId: 'user-a',
      orgId: 'org-1',
      reportId,
      findingId,
      rawKey: 'sample-A',
      scope: 'boolean',
      tag: 'true-response',
      status: 200,
      timeMs: 120,
      bodyHash: 'hash-a',
      bodyLength: 42,
      method: 'GET',
      url: 'https://example.test/a',
      headers: { 'content-type': 'application/json' },
      storedPath: 'a.json',
      contentType: 'application/json',
      source: 'jest'
    });

    const recordB = await db.addQuickVerifyEvidence({
      userId: 'user-b',
      orgId: 'org-2',
      reportId,
      findingId,
      rawKey: 'sample-B',
      scope: 'time',
      tag: 'delay-response',
      status: 504,
      timeMs: 980,
      bodyHash: 'hash-b',
      bodyLength: 128,
      method: 'POST',
      url: 'https://example.test/b',
      headers: { 'content-type': 'text/html' },
      storedPath: 'b.json',
      contentType: 'text/html',
      source: 'jest'
    });

    const ownRecords = await db.listQuickVerifyEvidence({
      reportId,
      findingId,
      userId: 'user-a',
      orgId: 'org-1',
      isAdmin: false,
      limit: 10
    });
    expect(ownRecords).toHaveLength(1);
    expect(ownRecords[0].id).toBe(recordA.id);
    expect(ownRecords[0].headers['content-type']).toBe('application/json');

    const orgPeerRecords = await db.listQuickVerifyEvidence({
      reportId,
      findingId,
      userId: 'user-c',
      orgId: 'org-1',
      isAdmin: false,
      limit: 10
    });
    expect(orgPeerRecords).toHaveLength(1);
    expect(orgPeerRecords[0].id).toBe(recordA.id);

    const forbiddenRecords = await db.listQuickVerifyEvidence({
      reportId,
      findingId,
      userId: 'user-z',
      orgId: 'org-z',
      isAdmin: false,
      limit: 10
    });
    expect(forbiddenRecords).toHaveLength(0);

    const adminRecords = await db.listQuickVerifyEvidence({
      reportId,
      findingId,
      userId: 'admin',
      isAdmin: true,
      limit: 10
    });
    expect(adminRecords).toHaveLength(2);
    const adminIds = adminRecords.map((entry) => entry.id).sort();
    expect(adminIds).toEqual([recordA.id, recordB.id].sort());

    const fetched = await db.getQuickVerifyEvidenceById(recordA.id);
    expect(fetched).toMatchObject({
      id: recordA.id,
      userId: 'user-a',
      orgId: 'org-1',
      reportId,
      findingId,
      rawKey: 'sample-A',
      status: 200,
      timeMs: 120,
      method: 'GET'
    });
    expect(fetched.headers['content-type']).toBe('application/json');
  });

  it('persists raw bodies to disk with metadata and summary hashes', () => {
    const tempDir = createTempDir('qv-evidence-');
    const timestamp = new Date('2024-01-01T00:00:00.000Z');
    const rawBodies = {
      baseline: {
        scope: 'baseline',
        tag: 'baseline-response',
        status: 200,
        timeMs: 150,
        method: 'GET',
        url: 'https://example.test/app',
        headers: { 'Content-Type': 'text/plain' },
        body: 'Hello world'
      },
      payload: {
        scope: 'payload',
        tag: 'sql-payload',
        status: 500,
        timeMs: 420,
        method: 'POST',
        url: 'https://example.test/app',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ok: false, error: 'boom' })
      }
    };

    const persisted = persistQuickVerifyRawBodies({
      baseDir: tempDir,
      reportId: 'report-9',
      findingId: 'finding-9',
      rawBodies,
      timestamp
    });

    expect(persisted).toHaveLength(2);
    persisted.forEach((entry) => {
      expect(fs.existsSync(entry.storedPath)).toBe(true);
      const fileContents = JSON.parse(fs.readFileSync(entry.storedPath, 'utf8'));
      expect(fileContents.key).toBe(entry.key);
      expect(fileContents.capturedAt).toBe(timestamp.toISOString());
      expect(fileContents.bodyEncoding).toBe('base64');
      const buffer = Buffer.from(fileContents.body, 'base64');
      expect(buffer.length).toBe(entry.bodyLength);
      expect(fileContents.bodyHash).toBe(entry.bodyHash);
    });

    const [baselineSummary] = summarizeRawBodies({ baseline: rawBodies.baseline });
    expect(baselineSummary.bodyHash).toBe(persisted.find((entry) => entry.tag === 'baseline-response').bodyHash);
    expect(baselineSummary.bodyLength).toBe(11);

    fs.rmSync(tempDir, { recursive: true, force: true });
  });
});
