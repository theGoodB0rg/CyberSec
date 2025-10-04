/* eslint-env jest */
const os = require('os');
const path = require('path');
const fs = require('fs');

const SQLMapIntegration = require('../sqlmap');

describe('SQLMap base flag metadata', () => {
  let integration;
  let validateSpy;

  beforeAll(() => {
    validateSpy = jest
      .spyOn(SQLMapIntegration.prototype, 'validateSQLMapInstallation')
      // Avoid invoking local sqlmap binary during tests
      .mockImplementation(() => Promise.resolve());
    // Ensure temp root is unique per test run
    process.env.SQLMAP_TEMP_DIR = path.join(os.tmpdir(), `cybersec-test-${Date.now()}`);
    if (!fs.existsSync(process.env.SQLMAP_TEMP_DIR)) {
      fs.mkdirSync(process.env.SQLMAP_TEMP_DIR, { recursive: true });
    }
  });

  afterAll(() => {
    if (validateSpy) validateSpy.mockRestore();
    delete process.env.SQLMAP_TEMP_DIR;
  });

  beforeEach(() => {
    integration = new SQLMapIntegration();
  });

  afterEach(() => {
    if (integration && integration.tempDir) {
      try {
        fs.rmSync(integration.tempDir, { recursive: true, force: true });
      } catch (_) {}
    }
    integration = null;
  });

  it('exposes well-formed base flag metadata with stable summary', () => {
    const meta = integration.getBaseFlagsMetadata();

    expect(meta).toBeTruthy();
    expect(Array.isArray(meta.baseFlags)).toBe(true);
    expect(meta.total).toBe(meta.baseFlags.length);
    expect(meta.baseFlags.length).toBeGreaterThan(10);
    expect(typeof meta.joined).toBe('string');
    expect(meta.joined).toContain('--batch');
    expect(Array.isArray(meta.profiles)).toBe(true);
    expect(meta.profiles.length).toBeGreaterThan(0);

    for (const entry of meta.baseFlags) {
      expect(typeof entry.flag).toBe('string');
      expect(entry.flag.length).toBeGreaterThan(2);
      expect(typeof entry.category).toBe('string');
      expect(entry.category.length).toBeGreaterThan(0);
      if (entry.caution != null) {
        expect(typeof entry.caution).toBe('string');
      }
      expect(typeof entry.description).toBe('string');
      expect(entry.description.length).toBeGreaterThan(0);
    }

    meta.profiles.forEach((profile) => {
      expect(typeof profile.id).toBe('string');
      expect(typeof profile.name).toBe('string');
      expect(Array.isArray(profile.flags)).toBe(true);
      expect(Array.isArray(profile.overlaps)).toBe(true);
      expect(Array.isArray(profile.additionalFlags)).toBe(true);
    });

    const basicProfile = meta.profiles.find((p) => p.id === 'basic');
    expect(basicProfile).toBeTruthy();
    expect(basicProfile.additionalFlags).toEqual(expect.arrayContaining(['--level=2', '--risk=2']));
  });

  it('builds default flags that include evidence, safety, and enumeration controls', () => {
    const fakeDir = path.join(os.tmpdir(), `sqlmap-base-${Date.now()}`);
    const flags = integration.buildBaseFlags(fakeDir);

    expect(flags).toEqual(expect.arrayContaining(['--batch', '--hex', '--fresh-queries']));

    const outputDirIndex = flags.indexOf('--output-dir');
    expect(outputDirIndex).toBeGreaterThan(-1);
    expect(flags[outputDirIndex + 1]).toContain(fakeDir);

    const sessionIndex = flags.indexOf('-s');
    expect(sessionIndex).toBeGreaterThan(-1);
    expect(flags[sessionIndex + 1]).toContain('session.sqlite');

    const trafficIndex = flags.indexOf('-t');
    expect(trafficIndex).toBeGreaterThan(-1);
    expect(flags[trafficIndex + 1]).toContain('traffic.log');
  });

  it('injects base flags exactly once when constructing sqlmap commands', () => {
    const { command } = integration.buildSQLMapCommand('https://example.test', {});

    const batchOccurrences = command.filter((token) => token === '--batch').length;
    expect(batchOccurrences).toBe(1);

    const outputDirOccurrences = command.filter((token) => token === '--output-dir').length;
    expect(outputDirOccurrences).toBe(1);

    // Profile defaults should still be present
    expect(command.some((token) => token.startsWith('--level='))).toBe(true);
    expect(command.some((token) => token.startsWith('--risk='))).toBe(true);
  });
});
