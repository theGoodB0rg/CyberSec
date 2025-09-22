const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

// Import custom modules
const Database = require('./database');
const SQLMapIntegration = require('./sqlmap');
const ReportGenerator = require('./reports');
const SecurityMiddleware = require('./middleware/security');
const AuthMiddleware = require('./middleware/auth');
const createAuthRouter = require('./routes/auth');
const Logger = require('./utils/logger');
const ReconEngine = require('./recon');
const createTargetsRouter = require('./routes/targets');
const { verifyFinding } = require('./verifier');

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: process.env.NODE_ENV === 'production' 
      ? false 
      : /http:\/\/localhost:\d+/, // Allow all localhost ports in dev
    methods: ["GET", "POST"]
  }
});

// Configuration
const PORT = process.env.PORT || 3001;
const DB_PATH = path.join(__dirname, 'data', 'cybersecurity.db');

// Ensure data directory exists
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Security middleware
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "ws:", "wss:"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});
app.use(limiter);

// CORS configuration (allow any localhost port while developing)
app.use(cors({
  origin: process.env.NODE_ENV === 'production' ? false : /http:\/\/localhost:\d+/,
  credentials: true,
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Static file serving
if (process.env.NODE_ENV === 'production') {
  app.use(express.static(path.join(__dirname, '../client/dist')));
}

// Initialize database
const database = new Database(DB_PATH);
const sqlmapIntegration = new SQLMapIntegration();
const reportGenerator = new ReportGenerator(database);
const reconEngine = new ReconEngine();

// Track running scans and their output directories and ownership
let scanProcesses = new Map();
// Lightweight per-user start locks to prevent race conditions on rapid clicks
const userStartLocks = new Map();

// Security middleware
app.use('/api', SecurityMiddleware.validateInput);
app.use('/api', SecurityMiddleware.sanitizeInput);
// Request-level threat scanner (blocks obvious injection/command abuse)
app.use('/api', SecurityMiddleware.securityScanner);

// Public auth routes
app.use('/api/auth', createAuthRouter(database));
// Targets verification routes
app.use('/api/targets', createTargetsRouter(database));

// API Routes
app.get('/api/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Authenticated routes
app.use('/api', AuthMiddleware.requireAuth);

// Get user-scoped scans
app.get('/api/scans', async (req, res) => {
  try {
    const scans = await database.getScansForUser(
      req.user.id,
      req.user.orgId,
      req.user.role === 'admin'
    );
    res.json(scans);
  } catch (error) {
    Logger.error('Error fetching scans:', error);
    res.status(500).json({ error: 'Failed to fetch scans' });
  }
});

// Get a specific scan (ownership enforced)
app.get('/api/scans/:id', async (req, res) => {
  try {
    const scan = await database.getScan(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (req.user.role !== 'admin') {
      const owns = (scan.user_id === req.user.id) || (req.user.orgId && scan.org_id === req.user.orgId);
      if (!owns) return res.status(403).json({ error: 'Forbidden' });
    }
    return res.json(scan);
  } catch (e) {
    Logger.error('Error fetching scan by id', e);
    return res.status(500).json({ error: 'Failed to fetch scan' });
  }
});

// HTTP initiation endpoint for scans (mirrors WS behavior)
app.post('/api/scans', SecurityMiddleware.createScanRateLimit(), async (req, res) => {
  try {
    const { target, options = {}, scanProfile = 'basic' } = req.body || {};

    // Validate input
    if (!target || !SecurityMiddleware.isValidURL(target)) {
      return res.status(400).json({ error: 'Valid target URL required' });
    }

    // Enforce proxy requirement if configured
    const proxyCheck = SecurityMiddleware.requireProxyIfEnabled(options || {});
    if (!proxyCheck.ok) {
      return res.status(400).json({ error: proxyCheck.error });
    }

    const userId = req.user.id;
    const orgId = req.user.orgId || null;
    const isAdmin = req.user.role === 'admin';

    // Per-user start lock to avoid races
    if (userStartLocks.get(userId)) {
      return res.status(429).json({ error: 'Another scan is being started. Please wait a moment and try again.' });
    }
    userStartLocks.set(userId, true);
    const releaseLock = () => userStartLocks.delete(userId);

    try {
      // Concurrency limit
      const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT_SCANS_PER_USER || '2', 10);
      const runningForUser = Array.from(scanProcesses.values()).filter(p => p.userId === userId).length;
      if (!isAdmin && runningForUser >= MAX_CONCURRENT) {
        return res.status(429).json({ error: `Concurrent scan limit reached (${MAX_CONCURRENT}). Please wait for existing scans to finish.` });
      }

      // Monthly quota
      const period = new Date().toISOString().slice(0,7);
      const MAX_SCANS_MONTH = parseInt(process.env.MAX_SCANS_PER_MONTH || '100', 10);
      if (!isAdmin) {
        const usage = await database.getUsageForUser(userId, period);
        if ((usage?.scans_started || 0) >= MAX_SCANS_MONTH) {
          return res.status(429).json({ error: `Monthly scan quota reached (${MAX_SCANS_MONTH} in ${period}).` });
        }
      }

      // Debounce duplicates for the same user/target
      try {
        const windowSec = parseInt(process.env.DUPLICATE_SCAN_WINDOW_SECONDS || '10', 10);
        const dup = await database.hasRecentSimilarScan(userId, target, windowSec);
        if (dup) {
          return res.status(409).json({ error: 'A similar scan was just started. Please wait a few seconds before trying again.' });
        }
      } catch (e) {
        Logger.warn('Duplicate-start check failed (HTTP)', { error: e.message });
      }

      // Require verified target unless explicitly allowed
      const allowUnverified = ['true','1','yes','on'].includes(String(process.env.ALLOW_UNVERIFIED_TARGETS).toLowerCase());
      if (!allowUnverified && !isAdmin) {
        try {
          const hostname = new URL(target).hostname;
          const verified = await database.getVerifiedTargetForUser(hostname, userId, orgId, isAdmin);
          if (!verified) {
            Logger.suspiciousActivity('unverified-target', { userId, orgId, hostname, target });
            return res.status(403).json({ error: `Target ${hostname} is not verified for your account. Verify ownership before scanning.` });
          }
        } catch (e) {
          return res.status(400).json({ error: 'Unable to parse target hostname for verification.' });
        }
      }

      // Start scan
      const { process: proc, outputDir } = await sqlmapIntegration.startScan(target, options, scanProfile, userId);

      // Record scan
      const startTimeIso = new Date().toISOString();
      const scanId = await database.createScan({
        target,
        options,
        scanProfile,
        user_id: userId,
        org_id: orgId,
        output_dir: outputDir,
        status: 'running',
        start_time: startTimeIso
      });

      // Audit start
      database.logScanEvent({
        scan_id: scanId,
        user_id: userId,
        org_id: orgId,
        event_type: 'started',
        metadata: { target, scanProfile, options }
      }).catch(()=>{});

      // Increment usage started counter
      database.incrementUsageOnStart(userId, period).catch(()=>{});

      // Track process
      scanProcesses.set(scanId, {
        process: proc,
        outputDir,
        target,
        scanProfile,
        startTime: new Date(),
        userId,
        orgId
      });

      // Stream output to user room if socket connection exists
      proc.stdout.on('data', (data) => {
        const output = data.toString();
        database.appendScanOutput(scanId, output, 'stdout');
        database.logScanEvent({ scan_id: scanId, user_id: userId, org_id: orgId, event_type: 'output', metadata: { type: 'stdout', chunk: output.slice(0,1000) } }).catch(()=>{});
        try { io.to(`user:${userId}`).emit('scan-output', { scanId, output, type: 'stdout' }); } catch (_) {}
      });

      proc.stderr.on('data', (data) => {
        const output = data.toString();
        database.appendScanOutput(scanId, output, 'stderr');
        database.logScanEvent({ scan_id: scanId, user_id: userId, org_id: orgId, event_type: 'output', metadata: { type: 'stderr', chunk: output.slice(0,1000) } }).catch(()=>{});
        try { io.to(`user:${userId}`).emit('scan-output', { scanId, output, type: 'stderr' }); } catch (_) {}
      });

      proc.on('close', async (code) => {
        const endTime = new Date().toISOString();
        try {
          await database.updateScan(scanId, { status: code === 0 ? 'completed' : 'failed', end_time: endTime, exit_code: code });
          const scanData = await database.getScan(scanId);
          let sqlmapResults = null;
          if (code === 0) {
            try {
              const outDir = scanProcesses.get(scanId)?.outputDir;
              if (outDir && fs.existsSync(outDir)) {
                sqlmapResults = await sqlmapIntegration.parseResults(outDir, scanId);
              }
            } catch (e) {
              Logger.error('Error parsing SQLMap results (HTTP):', e);
            }
          }
          const reportData = await reportGenerator.generateReport(scanId, scanData, sqlmapResults);
          const reportId = await database.createReport({ ...reportData, user_id: userId, org_id: orgId });
          database.logScanEvent({ scan_id: scanId, user_id: userId, org_id: orgId, event_type: code === 0 ? 'completed' : 'failed', metadata: { exit_code: code, reportId, hasStructuredResults: !!sqlmapResults } }).catch(()=>{});
          // Usage completion
          try {
            const runtime = (new Date(scanData.end_time).getTime() - new Date(scanData.start_time).getTime()) || 0;
            await database.incrementUsageOnComplete(userId, period, Math.max(0, runtime));
          } catch (e) {}
          // Notify via socket if connected
          try { io.to(`user:${userId}`).emit('scan-completed', { scanId, status: code === 0 ? 'completed' : 'failed', reportId, exit_code: code, hasStructuredResults: !!sqlmapResults }); } catch (_) {}
        } catch (e) {
          Logger.error('HTTP scan close handler error:', e);
        } finally {
          scanProcesses.delete(scanId);
        }
      });

      proc.on('error', (error) => {
        Logger.error('SQLMap process error (HTTP):', error);
        database.updateScan(scanId, { status: 'failed', error: error.message }).catch(()=>{});
        database.logScanEvent({ scan_id: scanId, user_id: userId, org_id: orgId, event_type: 'process-error', metadata: { message: error.message } }).catch(()=>{});
        scanProcesses.delete(scanId);
        try { io.to(`user:${userId}`).emit('scan-error', { scanId, message: error.message }); } catch (_) {}
      });

      // Respond immediately with scan info
      return res.status(202).json({ scanId, status: 'running', startTime: startTimeIso, target, scanProfile });
    } finally {
      releaseLock();
    }
  } catch (error) {
    Logger.error('Error starting HTTP scan:', error);
    return res.status(500).json({ error: 'Failed to start scan', details: error.message });
  }
});

// Get running scans for current user (admin may see all)
app.get('/api/scans/running', async (req, res) => {
  try {
    const scans = await database.getScansForUser(
      req.user.id,
      req.user.orgId,
      req.user.role === 'admin',
      200,
      0
    );
    res.json(scans.filter(s => s.status === 'running'));
  } catch (e) {
    Logger.error('Error fetching running scans', e);
    res.status(500).json({ error: 'Failed to fetch running scans' });
  }
});

// Phase 0 Recon endpoint
app.post('/api/recon', async (req, res) => {
  try {
    const { target } = req.body;
    if (!target || !SecurityMiddleware.isValidURL(target)) {
      return res.status(400).json({ error: 'Valid target URL required' });
    }
    Logger.info('Starting recon', { target });
    const reconResult = await reconEngine.run(target);
    await database.saveReconParameters(target, reconResult.parameters.map(p => ({
      ...p,
      name_length: p.name_length,
      name_entropy: p.name_entropy,
      base_latency_ms: p.base_latency_ms,
      reflection_latency_ms: p.reflection_latency_ms,
      priority_score: p.priority_score
    })));
    await database.saveReconPages(target, reconResult.pages || []);
    res.json(reconResult);
  } catch (error) {
    Logger.error('Recon error', error);
    res.status(500).json({ error: 'Recon failed', details: error.message });
  }
});

app.get('/api/recon', async (req, res) => {
  try {
    const { target } = req.query;
    if (!target) return res.status(400).json({ error: 'target query param required' });
    const params = await database.getReconParameters(target);
    res.json({ target, parameters: params });
  } catch (e) {
    Logger.error('Fetch recon params error', e);
    res.status(500).json({ error: 'Failed to fetch recon parameters' });
  }
});

// Get all scan reports
app.get('/api/reports', async (req, res) => {
  try {
    const reports = await database.getReportsForUser(
      req.user.id,
      req.user.orgId,
      req.user.role === 'admin'
    );
    res.json(reports);
  } catch (error) {
    Logger.error('Error fetching reports:', error);
    res.status(500).json({ error: 'Failed to fetch reports' });
  }
});

// Usage summary endpoint
app.get('/api/usage', async (req, res) => {
  try {
    const period = new Date().toISOString().slice(0,7);
    const usage = await database.getUsageForUser(req.user.id, period);
    const limits = {
      concurrent: parseInt(process.env.MAX_CONCURRENT_SCANS_PER_USER || '2', 10),
      monthly: parseInt(process.env.MAX_SCANS_PER_MONTH || '100', 10)
    };
    res.json({ period, usage, limits });
  } catch (e) {
    Logger.error('Usage endpoint error', e);
    res.status(500).json({ error: 'Failed to retrieve usage' });
  }
});

// Get specific report
app.get('/api/reports/:id', async (req, res) => {
  try {
    const report = await database.getReport(req.params.id);
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }
    // Enforce ownership unless admin
    if (req.user.role !== 'admin' && report.user_id && report.user_id !== req.user.id && (!req.user.orgId || report.org_id !== req.user.orgId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    res.json(report);
  } catch (error) {
    Logger.error('Error fetching report:', error);
    res.status(500).json({ error: 'Failed to fetch report' });
  }
});

// Export report
app.get('/api/reports/:id/export/:format', async (req, res) => {
  try {
    const { id, format } = req.params;
    const report = await database.getReport(id);
    
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }

    // Enforce ownership unless admin
    if (req.user.role !== 'admin' && report.user_id && report.user_id !== req.user.id && (!req.user.orgId || report.org_id !== req.user.orgId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const exportedData = await reportGenerator.exportReport(report, format);
    
    // Handle PDF fallback case
    if (format.toLowerCase() === 'pdf' && typeof exportedData === 'object' && exportedData.length && exportedData[0] === 0x3C) {
      // This looks like HTML content (starts with '<'), so it's likely a fallback
      Logger.warn('PDF export returned HTML fallback', { reportId: id });
      res.setHeader('Content-Disposition', `attachment; filename="report-${id}-fallback.html"`);
      res.setHeader('Content-Type', 'text/html');
      res.setHeader('X-PDF-Fallback', 'true'); // Custom header to indicate fallback
    } else {
      res.setHeader('Content-Disposition', `attachment; filename="report-${id}.${format}"`);
      res.setHeader('Content-Type', reportGenerator.getContentType(format));
    }
    
    res.send(exportedData);
  } catch (error) {
    Logger.error('Error exporting report:', error);
    res.status(500).json({ error: 'Failed to export report' });
  }
});

// Download CSV results file
app.get('/api/reports/:id/files/:filename', async (req, res) => {
  try {
    const { id, filename } = req.params;
    const report = await database.getReport(id);
    
    if (!report) {
      return res.status(404).json({ error: 'Report not found' });
    }
    // Enforce ownership unless admin
    if (req.user.role !== 'admin' && report.user_id && report.user_id !== req.user.id && (!req.user.orgId || report.org_id !== req.user.orgId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

  // Check if the report has structured results with files (stored under extractedData)
  const dumps = report.extractedData && report.extractedData.outputFiles && report.extractedData.outputFiles.dumps;
    if (!dumps || !Array.isArray(dumps)) {
      return res.status(404).json({ error: 'No output files found for this report' });
    }

    // Find the requested file
    const file = dumps.find(f => f.name === filename);
    if (!file || !fs.existsSync(file.path)) {
      return res.status(404).json({ error: 'File not found' });
    }

    // Security check - ensure file path is within recorded output_dir for this scan
    const scan = await database.getScan(report.scan_id);
    const normalizedPath = path.normalize(file.path);
    const recordedDir = scan?.output_dir ? path.normalize(scan.output_dir) : '';
    const rel = recordedDir ? path.relative(recordedDir, normalizedPath) : '..';
    if (!recordedDir || rel.startsWith('..') || path.isAbsolute(rel)) {
      // Log and deny path traversal or out-of-scope access
      Logger.unauthorizedAccess('report-file-access', {
        userId: req.user?.id,
        reportId: id,
        filename,
        requestedPath: normalizedPath,
        allowedBase: recordedDir || null
      });
      return res.status(403).json({ error: 'Access denied' });
    }

    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', 'text/csv');
    res.sendFile(file.path);
  } catch (error) {
    Logger.error('Error downloading file:', error);
    res.status(500).json({ error: 'Failed to download file' });
  }
});

// Delete report
app.delete('/api/reports/:id', async (req, res) => {
  try {
    const report = await database.getReport(req.params.id);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    if (req.user.role !== 'admin' && report.user_id && report.user_id !== req.user.id && (!req.user.orgId || report.org_id !== req.user.orgId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    // Best-effort: remove output directory for the underlying scan if it exists and is owned by the same user/org
    try {
      const scan = report.scan_id ? await database.getScan(report.scan_id) : null;
      if (scan?.output_dir) {
        // Double-check ownership matches report
        const owns = (req.user.role === 'admin') || (scan.user_id === req.user.id) || (req.user.orgId && scan.org_id === req.user.orgId);
        if (owns) {
          const recordedDir = scan.output_dir;
          // Remove the directory recursively (safe because we validated ownership and use normalized path checks below if needed)
          try {
            if (recordedDir && fs.existsSync(recordedDir)) {
              fs.rmSync(recordedDir, { recursive: true, force: true });
            }
            // Clear reference in DB
            await database.clearScanOutputDir(scan.id);
          } catch (e) {
            Logger.warn('Failed to remove output dir during report delete', { error: e.message, dir: recordedDir });
          }
        }
      }
    } catch (e) {
      Logger.warn('Cleanup on report delete failed', { error: e.message });
    }

    const success = await database.deleteReport(req.params.id);
    if (!success) {
      return res.status(404).json({ error: 'Report not found' });
    }
    res.json({ message: 'Report deleted successfully' });
  } catch (error) {
    Logger.error('Error deleting report:', error);
    res.status(500).json({ error: 'Failed to delete report' });
  }
});

// Verify a specific finding: re-run minimal PoCs and return confidence/diff
app.post('/api/findings/:findingId/verify', async (req, res) => {
  try {
    const { findingId } = req.params;
    const { reportId } = req.body || {};
    if (!reportId || !findingId) return res.status(400).json({ error: 'reportId and findingId required' });

    const report = await database.getReport(reportId);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    if (req.user.role !== 'admin' && report.user_id && report.user_id !== req.user.id && (!req.user.orgId || report.org_id !== req.user.orgId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const scan = await database.getScan(report.scan_id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });

    const findings = (report.vulnerabilities && report.vulnerabilities.findings) || (report.extractedData && report.extractedData.structuredFindings) || [];
    const flatFindings = Array.isArray(findings?.findings) ? findings.findings : findings;
    const finding = (flatFindings || []).find(f => f.id === findingId) || null;
    if (!finding) return res.status(404).json({ error: 'Finding not found in report' });
    if (!scan?.target) return res.status(400).json({ error: 'Scan target missing' });

    // Only support simple GET parameter verification for now
    const param = finding.parameter || null;
    if (!param) return res.status(400).json({ error: 'Finding has no parameter to verify' });

    // Build request context from original scan options (method, headers, cookie, data, userAgent)
    const opts = scan.options || {};
    const requestContext = {
      method: opts.method || 'GET',
      headers: opts.headers || {},
      cookie: opts.cookie || undefined,
      data: opts.data || undefined,
      userAgent: opts.userAgent || undefined
    };

    const result = await verifyFinding({ targetUrl: scan.target, parameter: param, requestContext });

    // Log event
    try {
      await database.logScanEvent({
        scan_id: String(report.scan_id),
        user_id: req.user.id,
        org_id: req.user.orgId || null,
        event_type: 'verification',
        metadata: { reportId, findingId, label: result.label, score: result.confidenceScore, ok: result.ok }
      });
      if (result.wafDetected) {
        await database.logScanEvent({
          scan_id: String(report.scan_id),
          user_id: req.user.id,
          org_id: req.user.orgId || null,
          event_type: 'waf-detected',
          metadata: { reportId, findingId, suggestions: result.suggestions || [] }
        });
      }
    } catch (_) {}

    // Persist a lightweight summary under metadata.verifications[findingId]
    try {
      await database.updateReportMetadata(reportId, (m) => {
        const verifications = m.verifications || {};
        verifications[findingId] = {
          at: new Date().toISOString(),
          label: result.label,
          score: result.confidenceScore,
          confirmations: result.confirmations,
          signals: result.signalsTested,
          wafDetected: !!result.wafDetected,
          suggestions: result.suggestions || []
        };
        return { ...m, verifications };
      });
    } catch (e) {
      Logger.warn('Failed to persist verification metadata', { error: e.message, reportId, findingId });
    }

    return res.json({ ok: result.ok, label: result.label, score: result.confidenceScore, confirmations: result.confirmations, signals: result.signalsTested, diff: result.diffView, poc: result.poc, why: result.why, wafDetected: !!result.wafDetected, suggestions: result.suggestions || [] });
  } catch (e) {
    Logger.error('Finding verification failed', e);
    res.status(500).json({ error: 'Verification failed', details: e.message });
  }
});

// Test PDF generation endpoint
app.get('/api/test-pdf', async (req, res) => {
  try {
    Logger.info('PDF generation test requested');
    const testPdfBuffer = await reportGenerator.testPDFGeneration();
    
    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', 'attachment; filename="pdf-test.pdf"');
    res.send(testPdfBuffer);
    
  } catch (error) {
    Logger.error('PDF test failed:', error);
    res.status(500).json({ 
      error: 'PDF test failed', 
      details: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
});

// Serve React app in production
if (process.env.NODE_ENV === 'production') {
  app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, '../client/dist/index.html'));
  });
}

// Socket.io connection handling
// Authenticate socket connections
io.use(AuthMiddleware.verifySocketAuth);

io.on('connection', (socket) => {
  Logger.info(`Client connected: ${socket.id}`);

  // Join a user-specific room to allow multi-tab updates
  if (socket.user?.id) {
    try {
      socket.join(`user:${socket.user.id}`);
    } catch (e) {
      Logger.warn('Failed to join user room', { error: e.message });
    }
  }

  // Announce successful auth
  try {
    socket.emit('auth-ok', { userId: socket.user?.id, role: socket.user?.role, orgId: socket.user?.orgId || null });
  } catch (_) {}

  // On connect, inform the client about any scans still running for this user
  try {
    const userId = socket.user?.id;
    if (userId) {
      const running = Array.from(scanProcesses.entries())
        .filter(([scanId, p]) => p.userId === userId)
        .map(([scanId, p]) => ({ scanId, target: p.target, scanProfile: p.scanProfile, startTime: p.startTime }));
      if (running.length) {
        socket.emit('scan-still-running', running);
      }
    }
  } catch (e) {
    Logger.warn('Failed to emit running scans on connect', { error: e.message });
  }

  // Handle SQLMap scan initiation
  socket.on('start-sqlmap-scan', async (data) => {
    try {
      const { target, options, scanProfile } = data;
      
      // Validate input
      if (!target || !SecurityMiddleware.isValidURL(target)) {
        socket.emit('scan-error', { message: 'Invalid target URL provided' });
        return;
      }

      // Enforce proxy requirement if configured
      const proxyCheck = SecurityMiddleware.requireProxyIfEnabled(options || {});
      if (!proxyCheck.ok) {
        socket.emit('scan-error', { message: proxyCheck.error });
        return;
      }

      // Enforce per-user concurrency and quotas
      const userId = socket.user?.id || 'system';
      const orgId = socket.user?.orgId || null;
      const isAdmin = socket.user?.role === 'admin';

      // Acquire per-user lock (best-effort). If already locked, reject quickly.
      if (userStartLocks.get(userId)) {
        socket.emit('scan-error', { message: 'Another scan is being started. Please wait a moment and try again.' });
        return;
      }
      userStartLocks.set(userId, true);
      const releaseLock = () => userStartLocks.delete(userId);

      // Concurrency limit
      const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT_SCANS_PER_USER || '2', 10);
      const runningForUser = Array.from(scanProcesses.values()).filter(p => p.userId === userId).length;
      if (!isAdmin && runningForUser >= MAX_CONCURRENT) {
        socket.emit('scan-error', { message: `Concurrent scan limit reached (${MAX_CONCURRENT}). Please wait for existing scans to finish.` });
        releaseLock();
        return;
      }

      // Monthly quota (YYYY-MM)
      const period = new Date().toISOString().slice(0,7);
      const MAX_SCANS_MONTH = parseInt(process.env.MAX_SCANS_PER_MONTH || '100', 10);
      if (!isAdmin) {
        const usage = await database.getUsageForUser(userId, period);
        if ((usage?.scans_started || 0) >= MAX_SCANS_MONTH) {
          socket.emit('scan-error', { message: `Monthly scan quota reached (${MAX_SCANS_MONTH} in ${period}).` });
          releaseLock();
          return;
        }
      }

      // Debounce rapid duplicate starts for same user and target
      try {
        const windowSec = parseInt(process.env.DUPLICATE_SCAN_WINDOW_SECONDS || '10', 10);
        const dup = await database.hasRecentSimilarScan(userId, target, windowSec);
        if (dup) {
          socket.emit('scan-error', { message: 'A similar scan was just started. Please wait a few seconds before trying again.' });
          releaseLock();
          return;
        }
      } catch (e) {
        // Non-fatal; log and continue
        Logger.warn('Duplicate-start check failed', { error: e.message });
      }

      // Require verified target unless explicitly allowed
      const allowUnverified = ['true','1','yes','on'].includes(String(process.env.ALLOW_UNVERIFIED_TARGETS).toLowerCase());
      if (!allowUnverified && !isAdmin) {
        try {
          const hostname = new URL(target).hostname;
          const verified = await database.getVerifiedTargetForUser(hostname, userId, orgId, isAdmin);
          if (!verified) {
            // Log security event for visibility/audit
            Logger.suspiciousActivity('unverified-target', { userId, orgId, hostname, target });
            socket.emit('scan-error', { message: `Target ${hostname} is not verified for your account. Verify ownership before scanning.` });
            releaseLock();
            return;
          }
        } catch (e) {
          socket.emit('scan-error', { message: 'Unable to parse target hostname for verification.' });
          releaseLock();
          return;
        }
      }

      // Start SQLMap scan (creates per-user output directory)
  const { process: proc, outputDir, sessionId: _sessionId } = await sqlmapIntegration.startScan(target, options, scanProfile, userId);

      // Create scan session and record output directory
      const startTimeIso = new Date().toISOString();
      const scanId = await database.createScan({
        target,
        options,
        scanProfile,
        user_id: userId,
        org_id: orgId,
        output_dir: outputDir,
        status: 'running',
        start_time: startTimeIso
      });

      // Log audit event: started
      try {
        await database.logScanEvent({
          scan_id: scanId,
          user_id: userId,
          org_id: orgId,
          event_type: 'started',
          metadata: { target, scanProfile, options }
        });
      } catch (e) {
        Logger.warn('Failed to log scan start event', { error: e.message, scanId });
      }

      // Increment usage started counter
      try { await database.incrementUsageOnStart(userId, period); } catch (e) { Logger.warn('Failed to increment usage on start', { error: e.message }); }

      // Store the scan process and its output directory for tracking
      scanProcesses.set(scanId, {
        process: proc,
        outputDir: outputDir,
        target,
        scanProfile,
        startTime: new Date(),
        userId,
        orgId
      });
      
      // Handle real-time output
      proc.stdout.on('data', (data) => {
        const output = data.toString();
        socket.emit('scan-output', { scanId, output, type: 'stdout' });
        database.appendScanOutput(scanId, output, 'stdout');
        // Opportunistic event logging with throttling by chunk size
        if (output && output.trim()) {
          database.logScanEvent({
            scan_id: scanId,
            user_id: userId,
            org_id: orgId,
            event_type: 'output',
            metadata: { type: 'stdout', chunk: output.slice(0, 1000) }
          }).catch(()=>{});
        }
      });

      proc.stderr.on('data', (data) => {
        const output = data.toString();
        socket.emit('scan-output', { scanId, output, type: 'stderr' });
        database.appendScanOutput(scanId, output, 'stderr');
        if (output && output.trim()) {
          database.logScanEvent({
            scan_id: scanId,
            user_id: userId,
            org_id: orgId,
            event_type: 'output',
            metadata: { type: 'stderr', chunk: output.slice(0, 1000) }
          }).catch(()=>{});
        }
      });

      proc.on('close', async (code) => {
        const endTime = new Date().toISOString();
        let scanData = await database.getScan(scanId);
        
        // Update scan status
        await database.updateScan(scanId, {
          status: code === 0 ? 'completed' : 'failed',
          end_time: endTime,
          exit_code: code
        });

        // Get updated scan data with end time
        scanData = await database.getScan(scanId);

        // Generate report with structured results
        try {
          let sqlmapResults = null;
          
          // Parse structured SQLMap results from tracked output directory
          if (code === 0) {
            try {
              const processInfo = scanProcesses.get(scanId);
              const outDir = processInfo?.outputDir;
              if (outDir && fs.existsSync(outDir)) {
                sqlmapResults = await sqlmapIntegration.parseResults(outDir, scanId);
                Logger.info(`Successfully parsed SQLMap results for scan ${scanId}`);
              } else {
                Logger.warn(`No valid output directory found for scan ${scanId}`);
              }
              
            } catch (parseError) {
              Logger.error('Error parsing SQLMap results:', parseError.message);
              // Continue without structured results
            }
          }

          const reportData = await reportGenerator.generateReport(scanId, scanData, sqlmapResults);
          const reportId = await database.createReport({ ...reportData, user_id: socket.user?.id || 'system', org_id: socket.user?.orgId || null });
          
          socket.emit('scan-completed', { 
            scanId, 
            status: code === 0 ? 'completed' : 'failed',
            reportId: reportId,
            exit_code: code,
            hasStructuredResults: !!sqlmapResults
          });
          try {
            await database.logScanEvent({
              scan_id: scanId,
              user_id: userId,
              org_id: orgId,
              event_type: code === 0 ? 'completed' : 'failed',
              metadata: { exit_code: code, reportId, hasStructuredResults: !!sqlmapResults }
            });
          } catch (e) { Logger.warn('Failed to log completion event', { scanId, error: e.message }); }
          
          Logger.info(`Report generated successfully for scan ${scanId}, report ID: ${reportId}`);
          // Increment usage completion counters
          try {
            const runtime = (new Date(scanData.end_time).getTime() - new Date(scanData.start_time).getTime()) || 0;
            await database.incrementUsageOnComplete(userId, period, Math.max(0, runtime));
          } catch (e) {
            Logger.warn('Failed to increment usage on complete', { error: e.message });
          }
          
        } catch (reportError) {
          Logger.error('Error generating report:', reportError);
          socket.emit('scan-error', { 
            scanId, 
            message: 'Scan completed but failed to generate report' 
          });
        } finally {
          // Clean up the scan process tracking
          scanProcesses.delete(scanId);
        }
      });

      proc.on('error', (error) => {
        Logger.error('SQLMap process error:', error);
        socket.emit('scan-error', { scanId, message: error.message });
        database.updateScan(scanId, { status: 'failed', error: error.message });
        database.logScanEvent({
          scan_id: scanId,
          user_id: socket.user?.id || 'system',
          org_id: socket.user?.orgId || null,
          event_type: 'process-error',
          metadata: { message: error.message }
        }).catch(()=>{});
        scanProcesses.delete(scanId);
      });

      // Store process reference for potential termination
      socket.scanProcess = proc;
      socket.scanId = scanId;

  socket.emit('scan-started', { scanId, target, scanProfile, startTime: startTimeIso });
  releaseLock();

    } catch (error) {
      Logger.error('Error starting scan:', error);
      socket.emit('scan-error', { message: error.message });
      try { userStartLocks.delete(socket.user?.id || 'system'); } catch (_) {}
    }
  });

  // Handle scan termination (Ctrl+C functionality)
  socket.on('terminate-scan', (payload = {}) => {
    const reqScanId = payload.scanId || socket.scanId;
    const procInfo = scanProcesses.get(reqScanId);
    if (!procInfo) {
      socket.emit('scan-error', { message: 'Scan not found or already finished.' });
      return;
    }
    const isAdmin = socket.user?.role === 'admin';
    const sameUser = procInfo.userId === (socket.user?.id || '');
    const sameOrg = socket.user?.orgId && procInfo.orgId && socket.user.orgId === procInfo.orgId;
    if (!(isAdmin || sameUser || sameOrg)) {
      // Explicit security log for unauthorized termination attempt
      Logger.unauthorizedAccess('scan-terminate', { scanId: reqScanId, owner: procInfo.userId, by: socket.user?.id, byOrg: socket.user?.orgId || null });
      socket.emit('scan-error', { message: 'You do not have permission to terminate this scan.' });
      return;
    }
    try {
      procInfo.process.kill('SIGTERM');
      socket.emit('scan-terminated', { scanId: reqScanId });
      database.updateScan(reqScanId, { 
        status: 'terminated',
        end_time: new Date().toISOString()
      });
      database.logScanEvent({
        scan_id: reqScanId,
        user_id: procInfo.userId,
        org_id: procInfo.orgId || null,
        event_type: 'terminated',
        metadata: { by: socket.user?.id, role: socket.user?.role }
      }).catch(()=>{});
      scanProcesses.delete(reqScanId);
    } catch (e) {
      socket.emit('scan-error', { message: 'Failed to terminate scan.' });
    }
  });

  // Handle terminal command execution
  socket.on('execute-command', async (data) => {
    try {
      const { command, args } = data;
      
      // Validate and sanitize command
      if (!SecurityMiddleware.isAllowedCommand(command)) {
        socket.emit('command-error', { message: 'Command not allowed' });
        return;
      }

      // Execute allowed commands
      const result = await sqlmapIntegration.executeCommand(command, args);
      socket.emit('command-output', result);
      
    } catch (error) {
      Logger.error('Error executing command:', error);
      socket.emit('command-error', { message: error.message });
    }
  });

  // Handle disconnect
  socket.on('disconnect', () => {
    Logger.info(`Client disconnected: ${socket.id}`);
    // Do not kill running processes on disconnect; scans continue in background
  });
});

// Graceful shutdown
process.on('SIGTERM', () => {
  Logger.info('SIGTERM received, shutting down gracefully');
  server.close(() => {
    database.close();
    process.exit(0);
  });
});

process.on('SIGINT', () => {
  Logger.info('SIGINT received, shutting down gracefully');
  server.close(() => {
    database.close();
    process.exit(0);
  });
});

// Error handling
process.on('uncaughtException', (error) => {
  Logger.error('Uncaught Exception:', error);
  process.exit(1);
});

process.on('unhandledRejection', (reason, promise) => {
  Logger.error('Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Authenticated routes: scan events API
app.get('/api/scans/:id/events', async (req, res) => {
  try {
    // Optional: ensure scan exists and ownership
    const scan = await database.getScan(req.params.id);
    if (!scan) return res.status(404).json({ error: 'Scan not found' });
    if (req.user.role !== 'admin') {
      const owns = (scan.user_id === req.user.id) || (req.user.orgId && scan.org_id === req.user.orgId);
      if (!owns) return res.status(403).json({ error: 'Forbidden' });
    }
    // Pagination with caps
    const maxLimit = 1000;
    const defaultLimit = 200;
    const limit = Math.max(1, Math.min(maxLimit, parseInt(req.query.limit || defaultLimit, 10) || defaultLimit));
    const offset = Math.max(0, parseInt(req.query.offset || 0, 10) || 0);
    const events = await database.getScanEventsForUser(
      req.params.id,
      req.user.id,
      req.user.orgId,
      req.user.role === 'admin',
      limit,
      offset
    );
    res.json(events);
  } catch (e) {
    Logger.error('Failed to fetch scan events', e);
    res.status(500).json({ error: 'Failed to fetch events' });
  }
});

// Start server
server.listen(PORT, async () => {
  Logger.info(`Server running on port ${PORT}`);
  Logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
  // Startup recovery: mark previously running scans as interrupted and log audit
  try {
    const interrupted = await database.interruptRunningScans();
    if (interrupted && interrupted.length) {
      Logger.warn(`Marked ${interrupted.length} running scans as interrupted on startup`);
      for (const s of interrupted) {
        try {
          await database.logScanEvent({
            scan_id: s.id,
            user_id: s.user_id || 'system',
            org_id: s.org_id || null,
            event_type: 'server-restart',
            metadata: { note: 'Server restarted while scan was running; status set to interrupted' }
          });
        } catch (_) {}
      }
    }
  } catch (e) {
    Logger.error('Startup recovery failed', e);
  }

  // Schedule a daily cleanup of old scan output directories (default retention 7 days)
  try {
    const cron = require('node-cron');
    const retentionDays = parseInt(process.env.OUTPUT_RETENTION_DAYS || '7', 10);
    if (retentionDays > 0) {
      cron.schedule('30 3 * * *', async () => {
        try {
          const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
          const stale = await database.getScansWithOutputBefore(cutoff);
          for (const s of stale) {
            const dir = s.output_dir;
            try {
              if (dir && fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
              await database.clearScanOutputDir(s.id);
            } catch (e) {
              Logger.warn('Failed retention cleanup for dir', { dir, error: e.message });
            }
          }
          if (stale.length) Logger.info(`Retention cleanup removed ${stale.length} output directories older than ${retentionDays} days`);
        } catch (e) {
          Logger.warn('Retention cleanup task failed', { error: e.message });
        }
      });
      Logger.info(`Output retention cleanup scheduled daily at 03:30, retention=${retentionDays} days`);
    }
  } catch (e) {
    Logger.warn('Failed to schedule retention cleanup', { error: e.message });
  }

  // Schedule pruning of old scan_events (default retention 90 days)
  try {
    const cron = require('node-cron');
    const eventsRetentionDays = parseInt(process.env.EVENTS_RETENTION_DAYS || '90', 10);
    if (eventsRetentionDays > 0) {
      cron.schedule('15 4 * * *', async () => {
        try {
          const cutoff = new Date(Date.now() - eventsRetentionDays * 24 * 60 * 60 * 1000).toISOString();
          const deleted = await database.pruneScanEventsBefore(cutoff);
          if (deleted) {
            Logger.info(`Pruned ${deleted} scan_events older than ${eventsRetentionDays} days`);
          }
        } catch (e) {
          Logger.warn('Scan events prune task failed', { error: e.message });
        }
      });
      Logger.info(`Scan events prune scheduled daily at 04:15, retention=${eventsRetentionDays} days`);
    }
  } catch (e) {
    Logger.warn('Failed to schedule scan events prune', { error: e.message });
  }
}); 