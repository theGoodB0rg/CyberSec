/* eslint-env jest */
const path = require('path');

describe('demoTargets safe hostname helpers', () => {
  const modulePath = path.join(__dirname, '..', 'utils', 'demoTargets');
  let originalEnv;

  beforeEach(() => {
    originalEnv = process.env.SAFE_PUBLIC_TARGETS;
    jest.resetModules();
  });

  afterEach(() => {
    process.env.SAFE_PUBLIC_TARGETS = originalEnv;
    jest.resetModules();
  });

  const loadModule = () => require(modulePath);

  it('treats built-in demo hosts as safe', () => {
    const { isSafeTargetHostname, isDemoHostname } = loadModule();
    expect(isDemoHostname('testphp.vulnweb.com')).toBe(true);
    expect(isSafeTargetHostname('testphp.vulnweb.com')).toBe(true);
    expect(isSafeTargetHostname('shop.testphp.vulnweb.com')).toBe(true);
  });

  it('allows configuring additional safe hosts from environment', () => {
    process.env.SAFE_PUBLIC_TARGETS = 'example.com, training.safe.test';
    const { isSafeTargetHostname, getAdditionalSafeHostnames, getAllSafeHostnames, DEMO_HOSTNAMES } = loadModule();

    expect(getAdditionalSafeHostnames()).toEqual(['example.com', 'training.safe.test']);
    expect(isSafeTargetHostname('example.com')).toBe(true);
    expect(isSafeTargetHostname('api.example.com')).toBe(true);
    expect(isSafeTargetHostname('training.safe.test')).toBe(true);
    expect(isSafeTargetHostname('portal.training.safe.test')).toBe(true);

    const merged = getAllSafeHostnames();
    DEMO_HOSTNAMES.forEach((demoHost) => {
      expect(merged).toContain(demoHost);
    });
    expect(merged).toContain('example.com');
    expect(merged).toContain('training.safe.test');
  });

  it('dedupes workspace hosts that overlap built-in catalog', () => {
    process.env.SAFE_PUBLIC_TARGETS = 'testphp.vulnweb.com, EXTRA.safe';
    const { getAllSafeHostnames } = loadModule();
    const merged = getAllSafeHostnames();
    const occurrences = merged.filter((host) => host === 'testphp.vulnweb.com');
    expect(occurrences).toHaveLength(1);
    expect(merged).toContain('extra.safe');
  });

  it('does not mark arbitrary hosts as safe when not configured', () => {
    delete process.env.SAFE_PUBLIC_TARGETS;
    const { isSafeTargetHostname } = loadModule();

    expect(isSafeTargetHostname('example.com')).toBe(false);
    expect(isSafeTargetHostname('')).toBe(false);
  });
});
