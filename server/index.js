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
const { shutdown, killPid } = require('./shutdown');
const ReportGenerator = require('./reports');
const SecurityMiddleware = require('./middleware/security');
const AuthMiddleware = require('./middleware/auth');
const createAuthRouter = require('./routes/auth');
const Logger = require('./utils/logger');
const ReconEngine = require('./recon');
const createTargetsRouter = require('./routes/targets');
const { verifyFinding } = require('./verifier');
const QueueRunner = require('./queue');
const { sanitizeOptionsForStorage, prepareAuthContext } = require('./helpers/scanHelpers');

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

// Trust proxy configuration (pre-middleware):
// Allow configuring Express trust proxy via env and admin settings.
let __currentTrustProxySetting = String(process.env.TRUST_PROXY || 'auto').toLowerCase();
const applyTrustProxy = (setting) => {
  try {
    let value;
    const s = String(setting || '').toLowerCase();
    if (['true','1','yes','on'].includes(s)) value = true;
    else if (['false','0','no','off'].includes(s)) value = false;
    else if (s === 'auto' || !s) {
      // Trust local and private networks (loopback, link-local, unique-local)
      value = ['loopback','linklocal','uniquelocal'];
    } else if (s.includes(',')) {
      value = s.split(',').map(x => x.trim()).filter(Boolean);
    } else {
      // Accept single token: ip, cidr, or named preset
      value = s;
    }
    app.set('trust proxy', value);
    __currentTrustProxySetting = s || 'auto';
    try { Logger.info('Express trust proxy configured', { setting: value }); } catch (_) {}
  } catch (e) {
    try { Logger.warn('Failed to apply trust proxy setting; using default auto', { error: e.message }); } catch (_) {}
    app.set('trust proxy', ['loopback','linklocal','uniquelocal']);
    __currentTrustProxySetting = 'auto';
  }
};
applyTrustProxy(__currentTrustProxySetting);

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

// More strict rate limit just for telemetry ingestion to avoid spam
const telemetryLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  limit: 30, // allow up to 30 telemetry events per minute per IP
  standardHeaders: true,
  legacyHeaders: false,
});

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
let queueRunner = null;
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

// Lightweight telemetry ingestion (privacy-respecting): page visits etc.
app.post('/api/telemetry/visit', telemetryLimiter, async (req, res) => {
  try {
    const { path: pagePath } = req.body || {};
    // Only store path and coarse timestamp; no IP/user-agent; associate with user_id
    await database.logTelemetry({ user_id: req.user.id, event_type: 'visit', metadata: { path: String(pagePath || '') } });
    res.json({ ok: true });
  } catch (e) {
    Logger.warn('Telemetry visit failed', e);
    res.status(500).json({ error: 'telemetry-failed' });
  }
});

// Scheduler APIs
app.post('/api/scans/schedule', async (req, res) => {
  try {
    const { target, options = {}, scanProfile = 'basic', runAt, maxRetries } = req.body || {};
    if (!target || !SecurityMiddleware.isValidURL(target)) {
      return res.status(400).json({ error: 'Valid target URL required' });
    }
    // Enforce proxy requirement if configured
    const proxyCheck = SecurityMiddleware.requireProxyIfEnabled(options || {});
    if (!proxyCheck.ok) {
      return res.status(400).json({ error: proxyCheck.error });
    }
    const when = runAt ? new Date(runAt) : new Date();
    if (isNaN(when.getTime())) return res.status(400).json({ error: 'Invalid runAt datetime' });
    const userId = req.user.id;
    const orgId = req.user.orgId || null;

    // Require verified target unless explicitly allowed
    const isAdmin = req.user.role === 'admin';
    const allowUnverified = ['true','1','yes','on'].includes(String(process.env.ALLOW_UNVERIFIED_TARGETS).toLowerCase());
    if (!allowUnverified && !isAdmin) {
      try {
        const hostname = new URL(target).hostname;
        const verified = await database.getVerifiedTargetForUser(hostname, userId, orgId, isAdmin);
        if (!verified) {
          Logger.suspiciousActivity('unverified-target-schedule', { userId, orgId, hostname, target });
          return res.status(403).json({ error: `Target ${hostname} is not verified for your account. Verify ownership before scheduling.` });
        }
      } catch (e) {
        return res.status(400).json({ error: 'Unable to parse target hostname for verification.' });
      }
    }

    const retries = Math.min(Math.max(parseInt(maxRetries ?? '3', 10) || 3, 0), 10);
    const jobId = await database.createJob({
      user_id: userId,
      org_id: orgId,
      run_at: when.toISOString(),
      target,
      options,
      scan_profile: scanProfile,
      max_retries: retries,
      created_by_admin: isAdmin ? 1 : 0,
    });

    return res.status(201).json({ ok: true, jobId, status: 'scheduled', runAt: when.toISOString() });
  } catch (e) {
    Logger.error('Schedule job error', e);
    return res.status(500).json({ error: 'Failed to schedule job', details: e.message });
  }
});

app.delete('/api/jobs/:id', async (req, res) => {
  try {
    const job = await database.getJob(req.params.id);
    if (!job) return res.status(404).json({ error: 'Job not found' });
    if (req.user.role !== 'admin') {
      const owns = (job.user_id === req.user.id) || (req.user.orgId && job.org_id === req.user.orgId);
      if (!owns) return res.status(403).json({ error: 'Forbidden' });
    }
    const canceled = await database.cancelJob(req.params.id);
    if (!canceled) return res.status(409).json({ error: 'Job cannot be canceled (already running or finished)' });
    // Optional: log an audit event if scan_id exists later
    try { await database.logScanEvent({ scan_id: job.scan_id || 'n/a', user_id: req.user.id, org_id: req.user.orgId || null, event_type: 'job-canceled', metadata: { jobId: job.id } }); } catch(_) {}
    // Telemetry: increment cancel counter for current period
    try {
      const period = new Date().toISOString().slice(0,7);
      await database.incrementCancelCount(req.user.id, period);
    } catch (_) {}
    res.json({ ok: true, status: 'canceled' });
  } catch (e) {
    Logger.error('Cancel job error', e);
    res.status(500).json({ error: 'Failed to cancel job' });
  }
});

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

// SQLMap profiles (server-defined) for client display
app.get('/api/sqlmap/profiles', async (req, res) => {
  try {
    const profiles = sqlmapIntegration.scanProfiles || {};
    // Normalize to an array for easier client rendering
    const list = Object.entries(profiles).map(([key, value]) => ({ key, ...value }));
    res.json(list);
  } catch (e) {
    Logger.error('Failed to fetch sqlmap profiles', e);
    res.status(500).json({ error: 'Failed to fetch profiles' });
  }
});

// Server-side validation of flags/profile (no sqlmap spawn)
app.post('/api/sqlmap/validate', async (req, res) => {
  try {
  const { target = '', profile = 'basic', customFlags = '' } = req.body || {};
    const result = { ok: true, disallowed: [], warnings: [], normalizedArgs: [], commandPreview: '', description: '', impact: { speed: 'medium', stealth: 'medium', exfil: 'low' } };

    // Validate/normalize flags using server whitelist
    const profileObj = sqlmapIntegration.scanProfiles[profile] || sqlmapIntegration.scanProfiles.basic;
    const custom = sqlmapIntegration.parseCustomFlags(typeof customFlags === 'string' ? customFlags : '');
    const normalized = [
      '-u', target || 'http://example.com',
      ...(profileObj?.flags || []),
      ...custom
    ];

    // Collect disallowed (client may send flags that were dropped)
    if (customFlags) {
      const tokens = String(customFlags).trim().split(/\s+/);
      for (const t of tokens) {
        if (t.startsWith('--')) {
          const name = t.split('=')[0];
          // If not present in normalized and appears to be a flag, consider disallowed
          if (!normalized.find(x => x === name || x.startsWith(name + '='))) {
            result.disallowed.push(name);
          }
        }
      }
    }

    // Basic numeric sanity checks
    const findNum = (prefix) => {
      const tok = normalized.find(x => x.startsWith(prefix));
      if (!tok) return null;
      const val = Number(tok.split('=')[1]);
      return Number.isFinite(val) ? val : null;
    };
    const level = findNum('--level=') ?? 2;
    const risk = findNum('--risk=') ?? 2;
    const threads = findNum('--threads=') ?? 1;
    if (level < 1 || level > 5) result.warnings.push('Level should be between 1 and 5.');
    if (risk < 1 || risk > 3) result.warnings.push('Risk should be between 1 and 3.');
    if (threads > 5) result.warnings.push('High threads can be noisy and unstable.');

    // Impact heuristics
    const hasDump = normalized.includes('--dump') || normalized.includes('--dump-all');
    const hasTamper = normalized.some(x => x.startsWith('--tamper='));
    const hasDelay = normalized.some(x => x.startsWith('--delay='));
    result.impact = {
      speed: threads >= 3 || level >= 4 ? 'high' : level <= 2 ? 'low' : 'medium',
      stealth: hasTamper || hasDelay ? 'higher' : threads >= 3 ? 'lower' : 'medium',
      exfil: hasDump ? 'high' : 'low'
    };

    // Command preview (no output-dir/session flags)
    result.normalizedArgs = normalized;
    result.commandPreview = `${sqlmapIntegration.sqlmapPath} ${normalized.join(' ')}`.trim();
    result.description = `Profile '${profileObj?.name || profile}' with ${hasTamper ? 'tamper scripts' : 'no tamper'}, level ${level}, risk ${risk}, ${threads} thread(s)${hasDump ? ' and data extraction' : ''}.`;
    result.ok = result.disallowed.length === 0;
    res.json(result);
  } catch (e) {
    Logger.warn('SQLMap validate failed', { error: e.message });
    res.status(400).json({ error: 'Validation failed', details: e.message });
  }
});

// User scan settings
app.get('/api/user/scan-settings', async (req, res) => {
  try {
    const settings = await database.getUserSettings(req.user.id);
    res.json(settings);
  } catch (e) {
    Logger.error('Get user settings failed', e);
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

app.put('/api/user/scan-settings', async (req, res) => {
  try {
    const { default_profile = 'basic', defaults = {}, last_used_profile = null } = req.body || {};
    // Basic validation for numeric ranges to protect DB
    const clamp = (n, min, max) => Math.max(min, Math.min(max, n));
    if (defaults && typeof defaults === 'object') {
      if (defaults.level != null) defaults.level = clamp(Number(defaults.level) || 1, 1, 5);
      if (defaults.risk != null) defaults.risk = clamp(Number(defaults.risk) || 1, 1, 3);
      if (defaults.threads != null) defaults.threads = clamp(Number(defaults.threads) || 1, 1, 10);
    }
    await database.upsertUserSettings(req.user.id, { default_profile, defaults, last_used_profile });
    const fresh = await database.getUserSettings(req.user.id);
    res.json(fresh);
  } catch (e) {
    Logger.error('Update user settings failed', e);
    res.status(500).json({ error: 'Failed to update settings' });
  }
});

// User custom profiles CRUD
app.get('/api/user/profiles', async (req, res) => {
  try {
    const profiles = await database.getUserProfiles(req.user.id);
    res.json(profiles);
  } catch (e) {
    Logger.error('List user profiles failed', e);
    res.status(500).json({ error: 'Failed to list profiles' });
  }
});

app.post('/api/user/profiles', async (req, res) => {
  try {
    const { name, description = '', flags = [] } = req.body || {};
    if (!name || typeof name !== 'string') return res.status(400).json({ error: 'Profile name is required' });
    // Validate flags via server whitelist
    const normalized = Array.isArray(flags) ? sqlmapIntegration.parseCustomFlags(flags.join(' ')) : [];
    const id = await database.createUserProfile(req.user.id, { name, description, flags: normalized, is_custom: 1 });
    const profile = await database.getUserProfileById(id, req.user.id);
    res.status(201).json(profile);
  } catch (e) {
    Logger.error('Create user profile failed', e);
    const status = /UNIQUE/i.test(e.message) ? 409 : 500;
    res.status(status).json({ error: 'Failed to create profile', details: e.message });
  }
});

app.put('/api/user/profiles/:id', async (req, res) => {
  try {
    const { name, description, flags } = req.body || {};
    let normalizedFlags = undefined;
    if (Array.isArray(flags)) normalizedFlags = sqlmapIntegration.parseCustomFlags(flags.join(' '));
    const ok = await database.updateUserProfile(req.params.id, req.user.id, { name, description, flags: normalizedFlags });
    if (!ok) return res.status(404).json({ error: 'Profile not found' });
    const fresh = await database.getUserProfileById(req.params.id, req.user.id);
    res.json(fresh);
  } catch (e) {
    Logger.error('Update user profile failed', e);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

app.delete('/api/user/profiles/:id', async (req, res) => {
  try {
    const ok = await database.deleteUserProfile(req.params.id, req.user.id);
    if (!ok) return res.status(404).json({ error: 'Profile not found' });
    res.json({ ok: true });
  } catch (e) {
    Logger.error('Delete user profile failed', e);
    res.status(500).json({ error: 'Failed to delete profile' });
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
    const { target, options = {}, scanProfile = 'basic', userProfileId = null, userProfileName = null } = req.body || {};

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
          // Telemetry: track duplicate-window detection on HTTP path
          try { await database.incrementDuplicateWindowRetries(userId, period); } catch (_) {}
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

  // Prepare auth context (cookie/header/login)
  const { preparedOptions, authMeta } = await prepareAuthContext(options, target, userId);

  // If user specified a saved profile, merge its flags as customFlags and force profile 'custom'
  let effectiveProfile = scanProfile;
  let mergedOptions = { ...preparedOptions };
  if (userProfileId || userProfileName) {
    try {
      let profile = null;
      if (userProfileId) {
        profile = await database.getUserProfileById(userProfileId, userId);
      }
      // Optional: name-based lookup for convenience
      if (!profile && userProfileName) {
        const profiles = await database.getUserProfiles(userId);
        profile = profiles.find(p => (p.name || '').toLowerCase() === String(userProfileName).toLowerCase()) || null;
      }
      if (profile && Array.isArray(profile.flags) && profile.flags.length) {
        effectiveProfile = 'custom';
        const joined = profile.flags.join(' ');
        mergedOptions.customFlags = mergedOptions.customFlags ? `${mergedOptions.customFlags} ${joined}` : joined;
      }
    } catch (e) {
      Logger.warn('Failed to apply user profile flags', { error: e.message });
    }
  }

  // Start scan
  const { process: proc, outputDir } = await sqlmapIntegration.startScan(target, mergedOptions, effectiveProfile, userId);

      // Record scan
      const startTimeIso = new Date().toISOString();
      const scanId = await database.createScan({
        target,
        options: sanitizeOptionsForStorage({ ...preparedOptions, auth: { ...(preparedOptions.auth || {}), type: authMeta.mode } }),
        scanProfile: effectiveProfile,
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
        metadata: { target, scanProfile: effectiveProfile, options: mergedOptions, auth: authMeta }
      }).catch(()=>{});

      // Remember last used profile for this user
      database.setLastUsedProfile(userId, effectiveProfile).catch(()=>{});

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

  // Determine requested format and whether PDF export is enabled
  const fmt = String(format || '').toLowerCase();
  const pdfEnabled = ['true','1','yes','on'].includes(String(process.env.ENABLE_PDF_EXPORT || 'false').toLowerCase());
  const effectiveFormat = (fmt === 'pdf' && !pdfEnabled) ? 'html' : fmt;
  const exportedData = await reportGenerator.exportReport(report, effectiveFormat);

    // Determine payload as Buffer for binary-safe send
    let payload;
    if (Buffer.isBuffer(exportedData)) {
      payload = exportedData;
    } else if (typeof exportedData === 'string') {
      // If PDF came as string, detect if it's an actual PDF or HTML fallback
      const looksPdf = exportedData.startsWith('%PDF');
      payload = Buffer.from(exportedData, looksPdf ? 'binary' : 'utf8');
    } else if (exportedData && exportedData.type === 'Buffer' && Array.isArray(exportedData.data)) {
      payload = Buffer.from(exportedData.data);
    } else {
      // Fallback to JSON serialization
      const txt = typeof exportedData === 'object' ? JSON.stringify(exportedData) : String(exportedData ?? '');
      payload = Buffer.from(txt, 'utf8');
    }

    // If request is for PDF, robustly validate payload and attempt to fix leading noise
  if (fmt === 'pdf' && effectiveFormat === 'pdf') {
      const MAGIC = Buffer.from('%PDF');
      const hasPdfAtZero = payload.length >= 4 && payload[0] === 0x25 && payload[1] === 0x50 && payload[2] === 0x44 && payload[3] === 0x46;
      let fixed = payload;
      let pdfOffset = -1;
      if (!hasPdfAtZero) {
        // Search for %PDF within the first 2KB; sometimes extra bytes/BOM prepend output
        const searchWindow = payload.slice(0, Math.min(payload.length, 2048));
        const idx = searchWindow.indexOf(MAGIC);
        if (idx > 0) {
          pdfOffset = idx;
          fixed = payload.slice(idx);
        } else {
          // Not a PDF at all; check if it's HTML and fallback
          let start = 0;
          if (payload.length >= 3 && payload[0] === 0xEF && payload[1] === 0xBB && payload[2] === 0xBF) start = 3; // UTF-8 BOM
          while (start < payload.length) {
            const b = payload[start];
            if (b === 0x20 || b === 0x09 || b === 0x0A || b === 0x0D) start++; else break;
          }
          const head = payload.slice(start, Math.min(start + 128, payload.length)).toString('utf8').toLowerCase();
          const looksHtml = head.startsWith('<!doctype html') || head.startsWith('<html') || head.startsWith('<');
          if (looksHtml) {
            Logger.warn('PDF export fell back to HTML; sending HTML with fallback headers', { reportId: id });
            res.setHeader('Content-Disposition', `attachment; filename="report-${id}-fallback.html"`);
            res.setHeader('Content-Type', 'text/html; charset=utf-8');
            res.setHeader('X-PDF-Fallback', 'true');
            res.setHeader('Content-Length', String(payload.length));
            return res.send(payload);
          }
        }
      }
      // If we found a later %PDF, use the sliced buffer and include debug header
      if (pdfOffset > 0) {
        res.setHeader('X-PDF-Offset-Fixed', String(pdfOffset));
        payload = fixed;
      }
    }

    // If PDF was requested but disabled, signal fallback via headers and use HTML content type
    if (fmt === 'pdf' && effectiveFormat !== 'pdf') {
      res.setHeader('X-PDF-Fallback', 'true');
    }

    const filename = effectiveFormat === 'csv' ? `report-${id}.csv` : `report-${id}.${effectiveFormat}`;
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
    res.setHeader('Content-Type', reportGenerator.getContentType(effectiveFormat));
    res.setHeader('Content-Length', String(payload.length));
    res.send(payload);
  } catch (error) {
    Logger.error('Error exporting report:', error);
    res.status(500).json({ error: 'Failed to export report' });
  }
});

// Dev-only PDF test endpoint to validate Puppeteer output end-to-end
if (process.env.NODE_ENV !== 'production') {
  app.get('/api/debug/pdf-test', async (req, res) => {
    try {
      const buf = await reportGenerator.testPDFGeneration();
      res.setHeader('Content-Type', 'application/pdf');
      res.setHeader('Content-Disposition', 'inline; filename="pdf-test.pdf"');
      res.setHeader('Content-Length', String(buf.length));
      res.send(buf);
    } catch (e) {
      Logger.error('PDF test endpoint failed', e);
      res.status(500).json({ error: 'PDF test failed', details: e.message });
    }
  });
}

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

    // Locate dumps list from the report
    let dumps = [];
    if (report.outputFiles && Array.isArray(report.outputFiles.dumps)) {
      dumps = report.outputFiles.dumps;
    } else if (report.sqlmapResults && report.sqlmapResults.files && Array.isArray(report.sqlmapResults.files.dumps)) {
      dumps = report.sqlmapResults.files.dumps;
    } else if (report.extractedData && Array.isArray(report.extractedData.csvFiles)) {
      // Back-compat: some reports keep csv files under extractedData.csvFiles
      dumps = report.extractedData.csvFiles;
    }
    if (!dumps || dumps.length === 0) {
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

// Serve DOM proof screenshot (PNG), read-only with ownership and path checks
app.get('/api/reports/:id/proof/:filename', async (req, res) => {
  try {
    const { id, filename } = req.params;
    if (!filename || !/^[a-zA-Z0-9._-]+$/.test(filename)) {
      return res.status(400).json({ error: 'Invalid filename' });
    }

    const report = await database.getReport(id);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    if (req.user.role !== 'admin' && report.user_id && report.user_id !== req.user.id && (!req.user.orgId || report.org_id !== req.user.orgId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const baseDir = path.join(__dirname, 'temp', 'verifications', String(id));
    const filePath = path.join(baseDir, filename);
    const normalizedBase = path.normalize(baseDir);
    const normalizedPath = path.normalize(filePath);
    const rel = path.relative(normalizedBase, normalizedPath);
    if (!rel || rel.startsWith('..') || path.isAbsolute(rel)) {
      Logger.unauthorizedAccess('dom-proof-access', { userId: req.user?.id, reportId: id, filename, requestedPath: normalizedPath, allowedBase: normalizedBase });
      return res.status(403).json({ error: 'Access denied' });
    }
    if (!fs.existsSync(normalizedPath)) {
      return res.status(404).json({ error: 'Proof file not found' });
    }

    res.setHeader('Content-Type', 'image/png');
    // Suggest inline display but leave it to the browser
    res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
    res.sendFile(normalizedPath);
  } catch (e) {
    Logger.error('Error serving dom proof', e);
    res.status(500).json({ error: 'Failed to serve proof image' });
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
          metadata: { reportId, findingId, suggestions: result.suggestions || [], indicators: result.wafIndicators || null }
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
          suggestions: result.suggestions || [],
          indicators: result.wafIndicators || null
        };
        return { ...m, verifications };
      });
    } catch (e) {
      Logger.warn('Failed to persist verification metadata', { error: e.message, reportId, findingId });
    }

    // If DOM screenshot present, persist it under a safe per-report folder
    let domProof = null;
    try {
      if (result.dom && result.dom.screenshotBuffer) {
        const outRoot = require('path').join(__dirname, 'temp');
        const fs = require('fs');
        const reportDir = require('path').join(outRoot, 'verifications', String(reportId));
        fs.mkdirSync(reportDir, { recursive: true });
        const fname = `dom-proof-${findingId}-${Date.now()}.png`;
        const fpath = require('path').join(reportDir, fname);
        fs.writeFileSync(fpath, result.dom.screenshotBuffer);
        domProof = { path: fpath, filename: fname };
        // Remove buffer from response
        delete result.dom.screenshotBuffer;
        // Log event with relative info only
        try {
          await database.logScanEvent({
            scan_id: String(report.scan_id),
            user_id: req.user.id,
            org_id: req.user.orgId || null,
            event_type: 'dom-validation',
            metadata: { reportId, findingId, reflected: !!result.dom.reflected, matches: (result.dom.matches||[]).slice(0,3) }
          });
        } catch (_) {}
      }
    } catch (e) {
      Logger.warn('Failed to persist DOM screenshot', { error: e.message });
    }

  return res.json({ ok: result.ok, label: result.label, score: result.confidenceScore, confirmations: result.confirmations, signals: result.signalsTested, diff: result.diffView, poc: result.poc, why: result.why, wafDetected: !!result.wafDetected, suggestions: result.suggestions || [], wafIndicators: result.wafIndicators || undefined, dom: { checked: !!result.dom?.checked, reflected: !!result.dom?.reflected, matches: result.dom?.matches || [], url: result.dom?.url, proof: domProof } });
  } catch (e) {
    Logger.error('Finding verification failed', e);
    res.status(500).json({ error: 'Verification failed', details: e.message });
  }
});

// Mark/unmark a finding as false positive (admin or owner of report)
app.post('/api/reports/:id/findings/:findingId/false-positive', async (req, res) => {
  try {
    const { id, findingId } = req.params;
    const { value } = req.body || {}; // boolean
    const report = await database.getReport(id);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    if (req.user.role !== 'admin' && report.user_id && report.user_id !== req.user.id && (!req.user.orgId || report.org_id !== req.user.orgId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    await database.updateReportMetadata(id, (m) => {
      const fp = m.falsePositives || {};
      if (value) fp[findingId] = { at: new Date().toISOString(), by: req.user.id };
      else delete fp[findingId];
      return { ...m, falsePositives: fp };
    });
    // Telemetry
    try { await database.logTelemetry({ user_id: req.user.id, event_type: 'false-positive', metadata: { reportId: id, findingId, value: !!value } }); } catch(_) {}
    res.json({ ok: true });
  } catch (e) {
    Logger.error('False-positive toggle failed', e);
    res.status(500).json({ error: 'Failed to update flag' });
  }
});

// Admin-only metrics endpoints
app.get('/api/admin/metrics', async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const now = new Date();
    const cutoff7 = new Date(now.getTime() - 7*24*60*60*1000).toISOString();
    const cutoff30 = new Date(now.getTime() - 30*24*60*60*1000).toISOString();
    const [userCount, adminCount, scans7, scans30, ttfb7, verify7, fp7, visitsSeries, topPages] = await Promise.all([
      database.getUserCount(),
      database.getAdminCount(),
      database.getScansStatsSince(cutoff7),
      database.getScansStatsSince(cutoff30),
      database.getAverageTimeToFirstReportSince(cutoff7),
      database.countVerificationEventsSince(cutoff7),
      database.countFalsePositivesSince(cutoff7),
      database.getVisitsSeries(14),
      database.getTopPages(14, 10)
    ]);
    res.json({
      users: { total: userCount, admins: adminCount },
      scans: { last7d: scans7, last30d: scans30 },
      timeToFirstReportMsAvg7d: ttfb7,
      verifications7d: verify7,
      falsePositives7d: fp7,
      visits: { series: visitsSeries, topPages }
    });
  } catch (e) {
    Logger.error('Admin metrics failed', e);
    res.status(500).json({ error: 'Failed to fetch metrics' });
  }
});

app.get('/api/admin/visits', async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const days = Math.max(1, Math.min(60, parseInt(String(req.query.days || '14'), 10) || 14));
    const [series, pages] = await Promise.all([
      database.getVisitsSeries(days),
      database.getTopPages(days, 20)
    ]);
    res.json({ series, topPages: pages });
  } catch (e) {
    Logger.error('Admin visits failed', e);
    res.status(500).json({ error: 'Failed to fetch visits' });
  }
});

// Admin: graceful shutdown endpoint (responds 202 then initiates shutdown)
app.post('/api/admin/shutdown', async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    res.status(202).json({ ok: true, message: 'Shutdown initiated' });
    setTimeout(() => handleSignal('API'), 50);
  } catch (e) {
    Logger.error('Admin shutdown failed to schedule', e);
  }
});

// Admin settings endpoints: allow toggling sitewide settings like proxy enforcement and trust proxy
app.get('/api/admin/settings', async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const [requireProxyDb, trustProxyDb] = await Promise.all([
      database.getSetting('require_proxy', null),
      database.getSetting('trust_proxy', null)
    ]);
    const requireProxyEnv = process.env.REQUIRE_PROXY;
    const effectiveRequireProxy = ['true','1','yes','on'].includes(String(requireProxyDb ?? requireProxyEnv).toLowerCase());
    res.json({
      settings: {
        require_proxy: {
          effective: effectiveRequireProxy,
          env: requireProxyEnv ?? null,
          db: requireProxyDb
        },
        trust_proxy: {
          effective: __currentTrustProxySetting,
          env: process.env.TRUST_PROXY || null,
          db: trustProxyDb
        }
      }
    });
  } catch (e) {
    Logger.error('Admin settings fetch failed', e);
    res.status(500).json({ error: 'Failed to fetch settings' });
  }
});

app.put('/api/admin/settings', async (req, res) => {
  try {
    if (req.user.role !== 'admin') return res.status(403).json({ error: 'Forbidden' });
    const { require_proxy, trust_proxy } = req.body || {};
    const updates = {};
    if (require_proxy !== undefined) {
      const val = String(require_proxy);
      await database.setSetting('require_proxy', val);
      process.env.REQUIRE_PROXY = val; // picked up by SecurityMiddleware.requireProxyIfEnabled
      updates.require_proxy = val;
    }
    if (trust_proxy !== undefined) {
      const val = String(trust_proxy);
      await database.setSetting('trust_proxy', val);
      applyTrustProxy(val); // apply live
      process.env.TRUST_PROXY = val;
      updates.trust_proxy = val;
    }
    res.json({ ok: true, updated: updates });
  } catch (e) {
    Logger.error('Admin settings update failed', e);
    res.status(500).json({ error: 'Failed to update settings', details: e.message });
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
        // scanId is unused in this filter, prefix with underscore to satisfy eslint no-unused-vars
        .filter(([_scanId, p]) => p.userId === userId)
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
  const { target, options, scanProfile, userProfileId = null, userProfileName = null } = data;
      
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
          // Telemetry: track duplicate-window detection on WS path
          try { await database.incrementDuplicateWindowRetries(userId, period); } catch (_) {}
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

    // Prepare auth context (cookie/header/login)
    const { preparedOptions, authMeta } = await prepareAuthContext(options || {}, target, userId);

    // If user specified a saved profile, merge its flags as customFlags and force profile 'custom'
    let effectiveProfile = scanProfile || 'basic';
    let mergedOptions = { ...preparedOptions };
    try {
      if (userProfileId || userProfileName) {
        let profile = null;
        if (userProfileId) {
          profile = await database.getUserProfileById(userProfileId, userId);
        }
        if (!profile && userProfileName) {
          const profiles = await database.getUserProfiles(userId);
          profile = profiles.find(p => (p.name || '').toLowerCase() === String(userProfileName).toLowerCase()) || null;
        }
        if (profile && Array.isArray(profile.flags) && profile.flags.length) {
          effectiveProfile = 'custom';
          const joined = profile.flags.join(' ');
          mergedOptions.customFlags = mergedOptions.customFlags ? `${mergedOptions.customFlags} ${joined}` : joined;
        }
      }
    } catch (e) {
      Logger.warn('Failed to apply user profile flags (WS)', { error: e.message });
    }

    // Start SQLMap scan (creates per-user output directory)
    const { process: proc, outputDir, sessionId: _sessionId } = await sqlmapIntegration.startScan(target, mergedOptions, effectiveProfile, userId);

      // Create scan session and record output directory
      const startTimeIso = new Date().toISOString();
      const scanId = await database.createScan({
        target,
        options: sanitizeOptionsForStorage({ ...mergedOptions, auth: { ...(mergedOptions.auth || {}), type: authMeta.mode } }),
        scanProfile: effectiveProfile,
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
          metadata: { target, scanProfile: effectiveProfile, options: mergedOptions, auth: authMeta }
        });
      } catch (e) {
        Logger.warn('Failed to log scan start event', { error: e.message, scanId });
      }

      // Remember last used profile for this user
      try { await database.setLastUsedProfile(userId, effectiveProfile); } catch(_) {}

      // Increment usage started counter
      try { await database.incrementUsageOnStart(userId, period); } catch (e) { Logger.warn('Failed to increment usage on start', { error: e.message }); }

      // Store the scan process and its output directory for tracking
      scanProcesses.set(scanId, {
        process: proc,
        outputDir: outputDir,
        target,
        scanProfile: effectiveProfile,
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

  socket.emit('scan-started', { scanId, target, scanProfile: effectiveProfile, startTime: startTimeIso });
  releaseLock();

    } catch (error) {
      Logger.error('Error starting scan:', error);
      socket.emit('scan-error', { message: error.message });
      try { userStartLocks.delete(socket.user?.id || 'system'); } catch (_) {}
    }
  });

  // Restart a scan: either by prior scanId (reuse saved target/options/profile) or by explicit payload
  socket.on('restart-scan', async (payload = {}) => {
    try {
      const userId = socket.user?.id || 'system';
      const orgId = socket.user?.orgId || null;
      const isAdmin = socket.user?.role === 'admin';

      // Resolve target/options/profile
      let target = payload.target;
      let options = payload.options || {};
      let scanProfile = payload.scanProfile || 'basic';

      if (!target && payload.scanId) {
        // Load previous scan and reuse its parameters
        const prev = await database.getScan(String(payload.scanId));
        if (!prev) {
          socket.emit('scan-error', { message: 'Previous scan not found' });
          return;
        }
        // Ownership check
        const owns = isAdmin || prev.user_id === userId || (orgId && prev.org_id === orgId);
        if (!owns) {
          Logger.unauthorizedAccess('scan-restart', { scanId: payload.scanId, owner: prev.user_id, by: userId, byOrg: orgId });
          socket.emit('scan-error', { message: 'You do not have permission to restart this scan.' });
          return;
        }
        target = prev.target;
        // prev.options may be JSON string; parse safely
        try { options = typeof prev.options === 'string' ? JSON.parse(prev.options) : (prev.options || {}); } catch (_) { options = {}; }
        scanProfile = prev.scan_profile || 'basic';
      }

      if (!target || !SecurityMiddleware.isValidURL(target)) {
        socket.emit('scan-error', { message: 'Invalid or missing target for restart' });
        return;
      }

      // Proxy requirement
      const proxyCheck = SecurityMiddleware.requireProxyIfEnabled(options || {});
      if (!proxyCheck.ok) {
        socket.emit('scan-error', { message: proxyCheck.error });
        return;
      }

      // Per-user start lock
      if (userStartLocks.get(userId)) {
        socket.emit('scan-error', { message: 'Another scan is being started. Please wait a moment and try again.' });
        return;
      }
      userStartLocks.set(userId, true);
      const releaseLock = () => userStartLocks.delete(userId);

      try {
        // Concurrency
        const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT_SCANS_PER_USER || '2', 10);
        const runningForUser = Array.from(scanProcesses.values()).filter(p => p.userId === userId).length;
        if (!isAdmin && runningForUser >= MAX_CONCURRENT) {
          socket.emit('scan-error', { message: `Concurrent scan limit reached (${MAX_CONCURRENT}). Please wait for existing scans to finish.` });
          return;
        }

        // Quotas
        const period = new Date().toISOString().slice(0,7);
        const MAX_SCANS_MONTH = parseInt(process.env.MAX_SCANS_PER_MONTH || '100', 10);
        if (!isAdmin) {
          const usage = await database.getUsageForUser(userId, period);
          if ((usage?.scans_started || 0) >= MAX_SCANS_MONTH) {
            socket.emit('scan-error', { message: `Monthly scan quota reached (${MAX_SCANS_MONTH} in ${period}).` });
            return;
          }
        }

        // Restart semantics: bypass duplicate-start debounce window intentionally

        // Verified target policy unless explicitly allowed
        const allowUnverified = ['true','1','yes','on'].includes(String(process.env.ALLOW_UNVERIFIED_TARGETS).toLowerCase());
        if (!allowUnverified && !isAdmin) {
          try {
            const hostname = new URL(target).hostname;
            const verified = await database.getVerifiedTargetForUser(hostname, userId, orgId, isAdmin);
            if (!verified) {
              Logger.suspiciousActivity('unverified-target-restart', { userId, orgId, hostname, target });
              socket.emit('scan-error', { message: `Target ${hostname} is not verified for your account. Verify ownership before scanning.` });
              return;
            }
          } catch (e) {
            socket.emit('scan-error', { message: 'Unable to parse target hostname for verification.' });
            return;
          }
        }

        // Prepare auth context
        const { preparedOptions, authMeta } = await prepareAuthContext(options || {}, target, userId);

        // Start scan
        const { process: proc, outputDir } = await sqlmapIntegration.startScan(target, preparedOptions, scanProfile, userId);

        const startTimeIso = new Date().toISOString();
        const scanId = await database.createScan({
          target,
          options: sanitizeOptionsForStorage({ ...preparedOptions, auth: { ...(preparedOptions.auth || {}), type: authMeta.mode } }),
          scanProfile,
          user_id: userId,
          org_id: orgId,
          output_dir: outputDir,
          status: 'running',
          start_time: startTimeIso
        });

        // Audit event: restarted
        database.logScanEvent({
          scan_id: scanId,
          user_id: userId,
          org_id: orgId,
          event_type: 'restarted',
          metadata: { target, scanProfile, via: 'ws', fromScanId: payload.scanId || null, options: preparedOptions, auth: authMeta }
        }).catch(()=>{});

        // Remember last used profile on restart as well
        database.setLastUsedProfile(userId, scanProfile).catch(()=>{});

        // Usage increment
        database.incrementUsageOnStart(userId, period).catch(()=>{});

        scanProcesses.set(scanId, { process: proc, outputDir, target, scanProfile, startTime: new Date(), userId, orgId });

        // Stream output
        proc.stdout.on('data', (data) => {
          const output = data.toString();
          socket.emit('scan-output', { scanId, output, type: 'stdout' });
          database.appendScanOutput(scanId, output, 'stdout');
          if (output && output.trim()) {
            database.logScanEvent({
              scan_id: scanId,
              user_id: userId,
              org_id: orgId,
              event_type: 'output',
              metadata: { type: 'stdout', chunk: output.slice(0, 1000) }
            }).catch(() => {});
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
            }).catch(() => {});
          }
        });

        proc.on('close', async (code) => {
          const endTime = new Date().toISOString();
          let scanData = await database.getScan(scanId);
          await database.updateScan(scanId, { status: code === 0 ? 'completed' : 'failed', end_time: endTime, exit_code: code });
          scanData = await database.getScan(scanId);
          try {
            let sqlmapResults = null;
            if (code === 0) {
              try {
                const processInfo = scanProcesses.get(scanId);
                const outDir = processInfo?.outputDir;
                if (outDir && fs.existsSync(outDir)) {
                  sqlmapResults = await sqlmapIntegration.parseResults(outDir, scanId);
                }
              } catch (e) { Logger.error('Restart parse results error', e); }
            }
            const reportData = await reportGenerator.generateReport(scanId, scanData, sqlmapResults);
            const reportId = await database.createReport({ ...reportData, user_id: userId, org_id: orgId });
            socket.emit('scan-completed', { scanId, status: code === 0 ? 'completed' : 'failed', reportId, exit_code: code, hasStructuredResults: !!sqlmapResults });
            database.logScanEvent({ scan_id: scanId, user_id: userId, org_id: orgId, event_type: code === 0 ? 'completed' : 'failed', metadata: { exit_code: code, reportId, hasStructuredResults: !!sqlmapResults, via: 'ws', restartOf: payload.scanId || null } }).catch(()=>{});
            try {
              const runtime = (new Date(scanData.end_time).getTime() - new Date(scanData.start_time).getTime()) || 0;
              await database.incrementUsageOnComplete(userId, period, Math.max(0, runtime));
            } catch (_) {}
          } catch (e) {
            Logger.error('Restart scan close handler error', e);
            socket.emit('scan-error', { scanId, message: 'Scan completed but failed to generate report' });
          } finally {
            scanProcesses.delete(scanId);
          }
        });

        proc.on('error', (error) => {
          Logger.error('SQLMap process error (restart):', error);
          socket.emit('scan-error', { scanId, message: error.message });
          database.updateScan(scanId, { status: 'failed', error: error.message });
          database.logScanEvent({ scan_id: scanId, user_id: userId, org_id: orgId, event_type: 'process-error', metadata: { message: error.message, via: 'ws', restartOf: payload.scanId || null } }).catch(()=>{});
          scanProcesses.delete(scanId);
        });

        socket.emit('scan-started', { scanId, target, scanProfile, startTime: startTimeIso });
      } finally {
        releaseLock();
      }
    } catch (e) {
      Logger.error('Restart-scan failed', e);
      socket.emit('scan-error', { message: e.message || 'Failed to restart scan' });
    }
  });

  // Handle scan termination (Ctrl+C functionality)
  socket.on('terminate-scan', (payload = {}) => {
    // Be robust to non-object payloads or undefined
    const safePayload = (payload && typeof payload === 'object') ? payload : {};
    let reqScanId = safePayload.scanId || socket.scanId;

    // If scanId wasn't provided and none is bound to the socket, try to infer
    // the most recent running scan for this user
    let procInfo = reqScanId ? scanProcesses.get(reqScanId) : undefined;
    if (!procInfo) {
      const userId = socket.user?.id;
      if (userId) {
        const entries = Array.from(scanProcesses.entries()).filter(([, p]) => p.userId === userId);
        if (entries.length) {
          entries.sort((a, b) => new Date(b[1].startTime).getTime() - new Date(a[1].startTime).getTime());
          reqScanId = entries[0][0];
          procInfo = entries[0][1];
        }
      }
    }

    if (!procInfo || !reqScanId) {
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
      const pid = procInfo.process?.pid;
      if (pid) {
        // Kill entire tree cross-platform
        killPid(pid, 'SIGTERM', 6000).then(()=>{});
      } else {
        procInfo.process?.kill?.('SIGTERM');
      }
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
const handleSignal = async (sig) => {
  try { Logger.info(`${sig} received, shutting down gracefully`); } catch (_) {}
  try {
    await shutdown({ httpServer: server, io, db: database, queue: queueRunner, sqlmap: sqlmapIntegration, scanProcessesRef: scanProcesses });
  } finally {
    process.exit(0);
  }
};

process.on('SIGTERM', () => handleSignal('SIGTERM'));
process.on('SIGINT', () => handleSignal('SIGINT'));
// Windows specific: handle Ctrl+Break when available
try { process.on('SIGBREAK', () => handleSignal('SIGBREAK')); } catch (_) {}

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
  // Ensure a default admin exists (env-provided or dev fallback)
  try {
    const adminCount = await database.getAdminCount();
    if (adminCount === 0) {
      const email = process.env.ADMIN_EMAIL || 'admin@local.test';
      const password = process.env.ADMIN_PASSWORD || 'admin1234';
      const bcrypt = require('bcrypt');
      const hash = await bcrypt.hash(password, 12);
      await database.createUser({ email, password_hash: hash, role: 'admin' });
      Logger.warn('No admin found. Seeded default admin credentials.');
      Logger.warn(`Admin Email: ${email}`);
      Logger.warn(`Admin Password: ${password}`);
    }
  } catch (e) {
    Logger.warn('Admin seeding failed', { error: e.message });
  }
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

  // Start queue runner
  try {
    const enableQueue = String(process.env.ENABLE_JOB_QUEUE || 'true').toLowerCase();
    if (['true','1','yes','on'].includes(enableQueue)) {
      queueRunner = new QueueRunner({ database, io, scanProcessesRef: scanProcesses, sqlmap: sqlmapIntegration, reportGenerator });
      queueRunner.start();
      Logger.info('Job queue enabled');
    } else {
      Logger.info('Job queue disabled via ENABLE_JOB_QUEUE');
    }
  } catch (e) {
    Logger.warn('Failed to start queue runner', { error: e.message });
  }

  // Load and apply admin-configured settings (overrides env) after DB ready
  try {
    const requireProxyDb = await database.getSetting('require_proxy', null);
    if (requireProxyDb !== null && requireProxyDb !== undefined) {
      process.env.REQUIRE_PROXY = String(requireProxyDb);
      Logger.info('Applied admin setting: REQUIRE_PROXY', { value: process.env.REQUIRE_PROXY });
    }
    const trustProxyDb = await database.getSetting('trust_proxy', null);
    if (trustProxyDb !== null && trustProxyDb !== undefined) {
      applyTrustProxy(String(trustProxyDb));
      Logger.info('Applied admin setting: TRUST_PROXY', { value: String(trustProxyDb) });
    }
  } catch (e) {
    Logger.warn('Failed to load admin settings on startup', { error: e.message });
  }
}); 