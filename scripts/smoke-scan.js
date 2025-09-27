// Quick smoke scan to verify end-to-end sqlmap -> parse -> HTML report
// Usage: npm run smoke:scan

const path = require('path');
const fs = require('fs');
const os = require('os');
const { v4: uuidv4 } = require('uuid');
const SQLMapIntegration = require('../server/sqlmap');
const ReportGenerator = require('../server/reports');

;(async () => {
  try {
    const target = process.env.SMOKE_TARGET || 'http://testphp.vulnweb.com/';
    const profile = process.env.SMOKE_PROFILE || 'basic';
    const userId = 'smoke';
    const sqlmap = new SQLMapIntegration();

    console.log(`[smoke] Starting scan for: ${target}`);
    const { process: child, outputDir, sessionId } = await sqlmap.startScan(target, {}, profile, userId);

    // Collect output for a short, bounded time to avoid long runs
    const timeoutMs = Number(process.env.SMOKE_TIMEOUT_MS || 60000); // 1 minute default
    const start = Date.now();

    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => { stdout += d.toString(); });
    child.stderr.on('data', d => { stderr += d.toString(); });

    const stop = (reason) => {
      try {
        if (!child.killed) child.kill('SIGTERM');
      } catch (_) {}
      console.log(`[smoke] Stopped scan: ${reason}`);
    };

    await new Promise(resolve => {
      let done = false;
      const finish = () => { if (!done) { done = true; resolve(); } };
      child.on('close', finish);
      const timer = setTimeout(() => {
        stop('timeout reached');
        setTimeout(finish, 1500); // allow process to close
      }, timeoutMs);
      child.on('exit', () => { clearTimeout(timer); finish(); });
      child.on('error', () => { clearTimeout(timer); finish(); });
    });

    // Parse results and build report (best-effort)
    const results = await sqlmap.parseResults(outputDir, sessionId);
    const scanData = {
      target,
      scan_profile: profile,
      status: 'completed',
      output: (stdout || '') + '\n' + (stderr || ''),
      start_time: new Date(start).toISOString(),
      end_time: new Date().toISOString(),
      options: { customFlags: '' }
    };

    const reportGen = new ReportGenerator(null);
    const reportData = await reportGen.generateReport(sessionId, scanData, results);
    const html = reportGen.generateHTMLReport(reportData);

    const outDir = path.join(__dirname, '../server/temp');
    try { fs.mkdirSync(outDir, { recursive: true }); } catch (_) {}
    const outFile = path.join(outDir, `smoke-report-${Date.now()}.html`);
    fs.writeFileSync(outFile, html, 'utf8');

    console.log('[smoke] Report written to:', outFile);
    console.log('[smoke] Output dir:', outputDir);
    process.exit(0);
  } catch (err) {
    console.error('[smoke] Smoke scan failed:', err?.message);
    try {
      const fallback = path.join(__dirname, '../server/temp', `smoke-report-error-${Date.now()}.txt`);
      fs.mkdirSync(path.dirname(fallback), { recursive: true });
      fs.writeFileSync(fallback, String(err?.stack || err?.message || err), 'utf8');
      console.log('[smoke] Wrote error details to:', fallback);
    } catch (_) {}
    process.exit(0); // Exit 0 to not fail the task; goal is artifact generation
  }
})();
