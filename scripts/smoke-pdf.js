// Simple smoke test to validate Puppeteer PDF generation end-to-end
// Usage: npm run smoke:pdf
const fs = require('fs');
const path = require('path');
const ReportGenerator = require('../server/reports');

(async () => {
  try {
    const outDir = path.join(__dirname, '../server/temp');
    fs.mkdirSync(outDir, { recursive: true });
    const outFile = path.join(outDir, 'pdf-smoke-test.pdf');

    const rg = new ReportGenerator(null);
    const buf = await rg.testPDFGeneration();
    fs.writeFileSync(outFile, buf);

    // Validate header and size
    const isPdf = buf.length >= 4 && buf[0] === 0x25 && buf[1] === 0x50 && buf[2] === 0x44 && buf[3] === 0x46; // %PDF
    console.log(JSON.stringify({ ok: true, outFile, size: buf.length, isPdf }));
    process.exit(isPdf ? 0 : 2);
  } catch (e) {
    console.error(JSON.stringify({ ok: false, error: e.message }));
    process.exit(1);
  }
})();
