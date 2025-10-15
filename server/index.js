const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const cors = require('cors');
const _helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const fs = require('fs');

const DB_PATH = process.env.DB_PATH
  ? path.resolve(process.env.DB_PATH)
  : path.join(__dirname, 'data', 'cybersecurity.db');

// Derived application directories (ensure they exist)
const DATA_DIR = path.dirname(DB_PATH);
const APP_TEMP_DIR = process.env.TEMP_DIR
  ? (path.isAbsolute(process.env.TEMP_DIR)
      ? process.env.TEMP_DIR
      : path.join(__dirname, process.env.TEMP_DIR))
  : path.join(__dirname, 'temp');
const QUICK_VERIFY_EVIDENCE_DIR = process.env.EVIDENCE_DIR
  ? (path.isAbsolute(process.env.EVIDENCE_DIR)
      ? process.env.EVIDENCE_DIR
      : path.join(__dirname, process.env.EVIDENCE_DIR))
  : path.join(APP_TEMP_DIR, 'quick-verify-evidence');
const VERIFICATIONS_DIR = path.join(APP_TEMP_DIR, 'verifications');

for (const dir of [DATA_DIR, APP_TEMP_DIR, QUICK_VERIFY_EVIDENCE_DIR, VERIFICATIONS_DIR]) {
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

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
const createContactRouter = require('./routes/contact');
const { verifyFinding } = require('./verifier');
const QueueRunner = require('./queue');
const { sanitizeOptionsForStorage, prepareAuthContext } = require('./helpers/scanHelpers');
const { persistQuickVerifyRawBodies, summarizeRawBodies, remapEvidenceRawKeys } = require('./helpers/evidenceStorage');
const { createContactMailer } = require('./utils/contactMailer');
const {
  isSafeTargetHostname,
  getAdditionalSafeHostnames,
  getAllSafeHostnames,
  DEMO_HOSTNAMES
} = require('./utils/demoTargets');
const { evaluateConcurrencyForUser } = require('./utils/concurrency');

const normalizeOrigin = (value) => {
  if (!value) return '';
  const trimmed = String(value).trim().replace(/\/$/, '');
  if (!trimmed) return '';
  try {
    const parsed = new URL(trimmed);
    return `${parsed.protocol}//${parsed.host}`.toLowerCase();
  } catch (error) {
    return trimmed.toLowerCase();
  }
};

const escapeRegex = (value) => value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const extractHostname = (target) => {
  if (!target) return null;
  try {
    return new URL(target).hostname.toLowerCase();
  } catch (_) {
    return null;
  }
};

const buildOriginPolicy = () => {
  const raw = process.env.ALLOWED_ORIGINS || '';
  const tokens = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);

  const exact = new Set();
  const wildcardPatterns = [];
  const wildcardRegex = [];
  let allowAll = false;

  for (const token of tokens) {
    if (token === '*') {
      allowAll = true;
      break;
    }

    if (token.includes('*')) {
      const pattern = token.replace(/\/$/, '').toLowerCase();
      wildcardPatterns.push(pattern);
      const regexPattern = '^' + escapeRegex(pattern).replace(/\\\*/g, '.*') + '$';
      wildcardRegex.push(new RegExp(regexPattern, 'i'));
      continue;
    }

    const normalized = normalizeOrigin(token);
    if (!normalized) {
      Logger.warn('Ignoring invalid origin in ALLOWED_ORIGINS', { origin: token });
      continue;
    }
    exact.add(normalized);
  }

  if (allowAll) {
    return { mode: 'allow-all', allowAll: true, exact, wildcardPatterns, wildcardRegex };
  }

  if (exact.size === 0 && wildcardRegex.length === 0) {
    if (process.env.NODE_ENV === 'production') {
      return { mode: 'same-origin-only', allowAll: false, exact, wildcardPatterns, wildcardRegex };
    }
    wildcardRegex.push(/^http:\/\/localhost:\d+$/i);
    wildcardPatterns.push('http://localhost:*');
    return { mode: 'dev-localhost', allowAll: false, exact, wildcardPatterns, wildcardRegex };
  }

  return { mode: 'configured', allowAll: false, exact, wildcardPatterns, wildcardRegex };
};

const originPolicy = buildOriginPolicy();

const isOriginAllowed = (origin) => {
  if (!originPolicy) return false;
  const normalized = normalizeOrigin(origin);
  if (!normalized) return true; // Same-origin or non-browser client
  if (originPolicy.allowAll) return true;
  if (originPolicy.exact.has(normalized)) return true;
  return originPolicy.wildcardRegex.some((re) => re.test(normalized));
};

const createOriginCallback = (context) => (origin, callback) => {
  if (isOriginAllowed(origin)) {
    return callback(null, true);
  }
  try { Logger.warn(`Blocked ${context} request from disallowed origin`, { origin }); } catch (_) {}
  return callback(null, false);
};

const corsOriginCallback = createOriginCallback('HTTP');
const socketOriginCallback = createOriginCallback('WebSocket');

try {
  Logger.info('CORS policy configured', {
    mode: originPolicy.mode,
    allowAll: originPolicy.allowAll,
    exact: Array.from(originPolicy.exact.values()),
    wildcards: originPolicy.wildcardPatterns,
  });
} catch (_) {}

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
  cors: {
    origin: socketOriginCallback,
    methods: ["GET", "POST"],
    credentials: true
  }
});

const TRUST_PROXY_AUTO_VALUE = 'loopback, linklocal, uniquelocal';

const resolveTrustProxySetting = (raw) => {
  if (raw === undefined || raw === null) {
    return { effective: 'auto', applied: TRUST_PROXY_AUTO_VALUE };
  }

  const value = String(raw).trim();
  if (!value) {
    return { effective: 'auto', applied: TRUST_PROXY_AUTO_VALUE };
  }

  const lower = value.toLowerCase();
  if (lower === 'auto') {
    return { effective: 'auto', applied: TRUST_PROXY_AUTO_VALUE };
  }
  if (lower === 'true') {
    return { effective: 'true', applied: true };
  }
  if (lower === 'false') {
    return { effective: 'false', applied: false };
  }

  const numeric = Number(value);
  if (!Number.isNaN(numeric)) {
    return { effective: value, applied: numeric };
  }

  if (value.includes(',')) {
    const tokens = value.split(',').map((token) => token.trim()).filter(Boolean);
    if (!tokens.length) {
      return { effective: 'auto', applied: TRUST_PROXY_AUTO_VALUE };
    }
    if (tokens.length === 1) {
      return { effective: tokens[0], applied: tokens[0] };
    }
    return { effective: tokens.join(', '), applied: tokens };
  }

  return { effective: value, applied: value };
};

let currentTrustProxySetting = 'auto';

const applyTrustProxy = (raw) => {
  const { effective, applied } = resolveTrustProxySetting(raw);
  try {
    app.set('trust proxy', applied);
    currentTrustProxySetting = effective;
  } catch (error) {
    currentTrustProxySetting = 'auto';
    app.set('trust proxy', TRUST_PROXY_AUTO_VALUE);
    Logger.warn('Failed to apply trust proxy setting; reverted to auto.', {
      attempted: raw,
      error: error.message
    });
  }
  return currentTrustProxySetting;
};

applyTrustProxy(process.env.TRUST_PROXY);

// Configuration
const PORT = process.env.PORT || 3001;

// Rate limiting
const skipGlobalRateLimit = (req) => {
  try {
    const path = (req.path || req.originalUrl || '').toLowerCase();
    if (path === '/api/health' || path === '/api/health/') {
      return true;
    }
    if (path.startsWith('/api/admin/scans/running')) {
      return true;
    }
  } catch (_) {}
  return false;
};

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
  skip: skipGlobalRateLimit,
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
  origin: corsOriginCallback,
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
const contactMailer = createContactMailer();

const logSafeHostUsage = async ({ userId, orgId = null, hostname, target, via, email }) => {
  try {
    const actor = email || (userId ? `user:${userId}` : 'unknown-user');
    Logger.audit('safe-host-used', actor, hostname, {
      via,
      target,
      orgId
    });
  } catch (error) {
    Logger.debug('Safe host audit logging failed', { error: error.message, hostname, via });
  }

  try {
    await database.logTelemetry({
      user_id: userId || null,
      event_type: 'safe-host-used',
      metadata: {
        hostname,
        target,
        via,
        orgId: orgId || null
      }
    });
  } catch (error) {
    Logger.debug('Safe host telemetry logging failed', { error: error.message, hostname, via });
  }
};

// Track running scans and their output directories and ownership
let scanProcesses = new Map();
let queueRunner = null;
// Lightweight per-user start locks to prevent race conditions on rapid clicks
const userStartLocks = new Map();

const requireAdmin = (req, res, next) => {
  if (req.user?.role !== 'admin') {
    Logger.unauthorizedAccess('admin-route', { userId: req.user?.id, path: req.path });
    return res.status(403).json({ error: 'Admin privileges required' });
  }
  return next();
};

const buildActiveScanSnapshot = async () => {
  const [dbActive, sqlmapProcesses] = await Promise.all([
    database.listActiveScans(true),
    Promise.resolve(sqlmapIntegration.listRunningProcesses())
  ]);

  const sqlmapBySession = new Map((sqlmapProcesses || []).map((p) => [p.sessionId, p]));
  const processEntries = Array.from(scanProcesses.entries());
  const processByScanId = new Map(processEntries);
  const seen = new Set();

  const items = dbActive.map((row) => {
    const procInfo = processByScanId.get(row.id);
    const sqlmapInfo = row.session_id ? sqlmapBySession.get(row.session_id) : null;
    seen.add(row.id);

    const startTime = procInfo?.startTime instanceof Date
      ? procInfo.startTime.toISOString()
      : (procInfo?.startTime || row.start_time);

    return {
      scanId: row.id,
      target: row.target,
      status: row.status,
      scanProfile: row.scan_profile,
      sessionId: row.session_id || procInfo?.sessionId || sqlmapInfo?.sessionId || null,
      userId: row.user_id,
      userEmail: row.user_email || null,
      userRole: row.user_role || null,
      orgId: row.org_id || null,
      startTime,
      pid: procInfo?.process?.pid ?? sqlmapInfo?.pid ?? null,
      processInfo: procInfo ? {
        pid: procInfo.process?.pid ?? null,
        startTime: procInfo.startTime instanceof Date ? procInfo.startTime.toISOString() : procInfo.startTime,
        target: procInfo.target,
        scanProfile: procInfo.scanProfile
      } : null,
      sqlmapContext: sqlmapInfo ? {
        pid: sqlmapInfo.pid,
        context: sqlmapInfo.context || {},
        userId: sqlmapInfo.userId,
        scanProfile: sqlmapInfo.scanProfile,
        startTime: sqlmapInfo.startTime instanceof Date ? sqlmapInfo.startTime.toISOString() : sqlmapInfo.startTime
      } : null
    };
  });

  processEntries.forEach(([scanId, info]) => {
    if (seen.has(scanId)) return;
    items.push({
      scanId,
      target: info.target,
      status: 'running',
      scanProfile: info.scanProfile,
      sessionId: info.sessionId || null,
      userId: info.userId,
      userEmail: null,
      userRole: null,
      orgId: info.orgId || null,
      startTime: info.startTime instanceof Date ? info.startTime.toISOString() : info.startTime,
      pid: info.process?.pid ?? null,
      processInfo: {
        pid: info.process?.pid ?? null,
        startTime: info.startTime instanceof Date ? info.startTime.toISOString() : info.startTime,
        target: info.target,
        scanProfile: info.scanProfile
      },
      sqlmapContext: null
    });
  });

  return {
    items,
    totals: {
      database: dbActive.length,
      processes: processEntries.length,
      sqlmap: sqlmapProcesses.length
    }
  };
};

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
app.get('/api/health', async (req, res) => {
  const response = {
    status: 'healthy',
    uptimeSeconds: Math.round(process.uptime()),
    environment: process.env.NODE_ENV || 'development',
    timestamp: new Date().toISOString(),
    database: { ok: true },
    queue: queueRunner ? { enabled: true, ...(queueRunner.getStatus?.() || {}) } : { enabled: false },
    sqlmap: {
      available: Boolean(sqlmapIntegration?.sqlmapPath),
      path: sqlmapIntegration?.sqlmapPath || null
    }
  };

  let statusCode = 200;

  try {
    await database.healthCheck();
  } catch (error) {
    response.database = { ok: false, error: error.message };
    response.status = 'degraded';
    statusCode = 503;
  }

  if (response.queue.enabled && !response.queue.timerActive) {
    response.queue.ok = false;
    response.status = 'degraded';
    statusCode = Math.max(statusCode, 503);
  } else if (response.queue.enabled) {
    response.queue.ok = true;
  }

  if (!response.sqlmap.available) {
    response.sqlmap.ok = false;
    response.status = 'degraded';
    statusCode = Math.max(statusCode, 503);
  } else {
    response.sqlmap.ok = true;
  }

  res.status(statusCode).json(response);
});

app.use('/api/contact', createContactRouter(contactMailer, database));


// Authenticated routes
app.use('/api', AuthMiddleware.requireAuth);

app.get('/api/config/safe-hosts', (req, res) => {
  try {
    const builtin = [...DEMO_HOSTNAMES];
    const additional = getAdditionalSafeHostnames();
    const all = getAllSafeHostnames();
    res.json({ builtin, additional, all });
  } catch (error) {
    Logger.error('Failed to fetch safe hosts', { error: error.message });
    res.status(500).json({ error: 'Failed to fetch safe hosts' });
  }
});

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
      const hostname = extractHostname(target);
      if (!hostname) {
        return res.status(400).json({ error: 'Unable to parse target hostname for verification.' });
      }
      const safeHost = isSafeTargetHostname(hostname);
      if (!safeHost) {
        const verified = await database.getVerifiedTargetForUser(hostname, userId, orgId, isAdmin);
        if (!verified) {
          Logger.suspiciousActivity('unverified-target-schedule', { userId, orgId, hostname, target });
          return res.status(403).json({ error: `Target ${hostname} is not verified for your account. Verify ownership before scheduling.` });
        }
      } else {
        logSafeHostUsage({
          userId,
          orgId,
          hostname,
          target,
          via: 'api:scans:schedule',
          email: req.user.email
        }).catch(() => {});
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

// Expose server-enforced base flags for transparency (authenticated users only)
app.get('/api/sqlmap/base-flags', (req, res) => {
  try {
    const payload = sqlmapIntegration.getBaseFlagsMetadata();
    res.json(payload);
  } catch (e) {
    Logger.error('Failed to fetch sqlmap base flags', e);
    res.status(500).json({ error: 'Failed to fetch base flags' });
  }
});

// Server-side validation of flags/profile (no sqlmap spawn)
app.post('/api/sqlmap/validate', async (req, res) => {
  try {
    const { target = '', profile = 'basic', customFlags = '' } = req.body || {};
    const isAdmin = req.user?.role === 'admin';
    const result = { ok: true, disallowed: [], warnings: [], normalizedArgs: [], commandPreview: '', description: '', impact: { speed: 'medium', stealth: 'medium', exfil: 'low' } };

    // Validate/normalize flags using server whitelist
    const profileObj = sqlmapIntegration.scanProfiles[profile] || sqlmapIntegration.scanProfiles.basic;
    const custom = sqlmapIntegration.parseCustomFlags(typeof customFlags === 'string' ? customFlags : '', { isAdmin });
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
    const isAdmin = req.user?.role === 'admin';
    const normalized = Array.isArray(flags) ? sqlmapIntegration.parseCustomFlags(flags.join(' '), { isAdmin }) : [];
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
    const isAdmin = req.user?.role === 'admin';
    if (Array.isArray(flags)) normalizedFlags = sqlmapIntegration.parseCustomFlags(flags.join(' '), { isAdmin });
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
  const concurrency = await evaluateConcurrencyForUser({ userId, isAdmin, database, scanProcesses });
      if (!concurrency.hasCapacity) {
        const message = concurrency.limit === 1
          ? 'You already have an active scan running. Wait for it to finish before starting another.'
          : `Concurrent scan limit reached (${concurrency.limit}). Please wait for existing scans to finish.`;
        return res.status(concurrency.limit === 1 ? 429 : 409).json({
          error: message,
          limit: concurrency.limit,
          activeScan: concurrency.activeScan
        });
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
        const hostname = extractHostname(target);
        if (!hostname) {
          return res.status(400).json({ error: 'Unable to parse target hostname for verification.' });
        }
        const safeHost = isSafeTargetHostname(hostname);
        if (!safeHost) {
          const verified = await database.getVerifiedTargetForUser(hostname, userId, orgId, isAdmin);
          if (!verified) {
            Logger.suspiciousActivity('unverified-target', { userId, orgId, hostname, target });
            return res.status(403).json({ error: `Target ${hostname} is not verified for your account. Verify ownership before scanning.` });
          }
        } else {
          logSafeHostUsage({
            userId,
            orgId,
            hostname,
            target,
            via: 'api:scans:start',
            email: req.user.email
          }).catch(() => {});
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
  const { process: proc, outputDir, sessionId } = await sqlmapIntegration.startScan(target, mergedOptions, effectiveProfile, userId, { isAdmin });

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
        start_time: startTimeIso,
        session_id: sessionId
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
        scanProfile: effectiveProfile,
        startTime: new Date(),
        userId,
        orgId,
        sessionId
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
          let verdictMeta = null;
          if (code === 0) {
            try {
              const outDir = scanProcesses.get(scanId)?.outputDir;
              if (outDir && fs.existsSync(outDir)) {
                sqlmapResults = await sqlmapIntegration.parseResults(outDir, scanId);
                if (sqlmapResults?.analysis) {
                  try {
                    const verdictPayload = {
                      ...sqlmapResults.analysis,
                      summary: {
                        ...(sqlmapResults.analysis.summary || {}),
                        exitCode: code,
                        completedAt: endTime,
                      }
                    };
                    await database.updateScan(scanId, { verdict_meta: JSON.stringify(verdictPayload) });
                    verdictMeta = verdictPayload;
                  } catch (verdictError) {
                    Logger.debug('HTTP handler failed to persist verdict metadata', { scanId, error: verdictError?.message });
                  }
                }
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
          try { io.to(`user:${userId}`).emit('scan-completed', { scanId, status: code === 0 ? 'completed' : 'failed', reportId, exit_code: code, hasStructuredResults: !!sqlmapResults, verdictMeta }); } catch (_) {}
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
  return res.status(202).json({ scanId, status: 'running', startTime: startTimeIso, target, scanProfile: effectiveProfile });
    } finally {
      releaseLock();
    }
  } catch (error) {
    Logger.error('Error starting HTTP scan:', error);
    return res.status(500).json({ error: 'Failed to start scan', details: error.message });
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
  concurrent: parseInt(process.env.MAX_CONCURRENT_SCANS_PER_USER || '1', 10),
      monthly: parseInt(process.env.MAX_SCANS_PER_MONTH || '100', 10)
    };
    res.json({ period, usage, limits });
  } catch (e) {
    Logger.error('Usage endpoint error', e);
    res.status(500).json({ error: 'Failed to retrieve usage' });
  }
});

app.get('/api/analytics/summary', async (req, res) => {
  try {
    const parseWindow = (value) => {
      if (value === undefined) return undefined;
      const num = Number(value);
      return Number.isFinite(num) ? num : undefined;
    };

    const summary = await database.getAnalyticsSummary({
      userId: req.user.id,
      orgId: req.user.orgId || null,
      isAdmin: req.user.role === 'admin',
      dailyWindowDays: parseWindow(req.query.dailyWindowDays),
      statusWindowDays: parseWindow(req.query.statusWindowDays),
      demoWindowDays: parseWindow(req.query.demoWindowDays),
      feedbackWindowDays: parseWindow(req.query.feedbackWindowDays),
    });

    res.json(summary);
  } catch (error) {
    Logger.error('Analytics summary error', error);
    res.status(500).json({ error: 'Failed to load analytics summary' });
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

  const baseDir = path.join(VERIFICATIONS_DIR, String(id));
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

    const methodHints = [
      finding.httpMethod,
      finding.method,
      (finding.sqlmapMetadata && finding.sqlmapMetadata.method) || null,
      (finding.sqlmapMetadata && finding.sqlmapMetadata.place) || null,
      (() => {
        const csv = finding.sqlmapMetadata && finding.sqlmapMetadata.csv;
        if (csv && typeof csv === 'object') {
          return csv.method || csv.place || csv.httpMethod || null;
        }
        return null;
      })()
    ]
      .map((value) => (value ? String(value).toUpperCase() : ''))
      .filter((value) => ['GET', 'POST', 'PUT', 'DELETE', 'PATCH'].includes(value));
    if (methodHints.length > 0) {
      requestContext.method = methodHints[0];
    }

    const payloadCandidates = [];
    if (typeof finding.payload === 'string' && finding.payload.trim().length > 0) {
      payloadCandidates.push(finding.payload.trim());
    }
    if (finding.sqlmapMetadata && typeof finding.sqlmapMetadata === 'object') {
      const meta = finding.sqlmapMetadata;
      if (typeof meta.payload === 'string' && meta.payload.trim().length > 0) {
        payloadCandidates.push(meta.payload.trim());
      }
      const csv = meta.csv;
      if (csv && typeof csv === 'object') {
        for (const [key, value] of Object.entries(csv)) {
          if (typeof value === 'string' && /payload/i.test(key) && value.trim().length > 0) {
            payloadCandidates.push(value.trim());
          }
        }
      }
    }
    const seedPayloads = Array.from(new Set(payloadCandidates)).slice(0, 5);

    const originalConfidence = {
      label: finding.confidenceLabel || null,
      score: typeof finding.confidenceScore === 'number' ? finding.confidenceScore : null
    };

    const consentInput = (req.body && req.body.consent) || null;
    const preferenceBefore = await database.getQuickVerifyPreference(req.user.id);
    const nowIso = new Date().toISOString();
    let shouldCaptureRawBodies = !!(preferenceBefore.rememberChoice && preferenceBefore.storeEvidence === true);
    let consentLogged = false;

    if (consentInput && typeof consentInput.storeEvidence === 'boolean') {
      shouldCaptureRawBodies = consentInput.storeEvidence === true;
      try {
        await database.upsertQuickVerifyPreference(req.user.id, {
          storeEvidence: consentInput.storeEvidence,
          rememberChoice: consentInput.rememberChoice !== undefined ? !!consentInput.rememberChoice : preferenceBefore.rememberChoice,
          promptSuppressed: consentInput.promptSuppressed === true,
          promptVersion: consentInput.promptVersion != null ? Number(consentInput.promptVersion) : undefined,
          lastPromptAt: consentInput.lastPromptAt || nowIso,
          lastDecisionAt: nowIso,
          source: consentInput.source || 'quick-verify'
        });
        consentLogged = true;
      } catch (err) {
        Logger.warn('Failed to persist quick verify consent', { error: err.message, userId: req.user.id });
      }
    }

    if (!consentInput && req.body && typeof req.body.captureRawBodies === 'boolean') {
      shouldCaptureRawBodies = !!req.body.captureRawBodies;
    }

    const activePreference = await database.getQuickVerifyPreference(req.user.id);

    const result = await verifyFinding({
      targetUrl: scan.target,
      parameter: param,
      requestContext,
      seedPayloads,
      originalConfidence,
      captureRawBodies: shouldCaptureRawBodies
    });

    const rawBodies = result.rawBodies || null;
    let rawEvidenceSummary = [];
    const evidenceMapping = {};
    if (shouldCaptureRawBodies && rawBodies && Object.keys(rawBodies).length > 0) {
      try {
        const persisted = persistQuickVerifyRawBodies({
          baseDir: QUICK_VERIFY_EVIDENCE_DIR,
          reportId,
          findingId,
          rawBodies
        });
        for (const sample of persisted) {
          try {
            const storedRecord = await database.addQuickVerifyEvidence({
              userId: req.user.id,
              orgId: req.user.orgId || null,
              reportId,
              findingId,
              rawKey: sample.key,
              scope: sample.scope,
              tag: sample.tag,
              status: sample.status,
              timeMs: sample.timeMs,
              bodyHash: sample.bodyHash,
              bodyLength: sample.bodyLength,
              method: sample.method,
              url: sample.url,
              headers: sample.headers,
              storedPath: path.relative(QUICK_VERIFY_EVIDENCE_DIR, sample.storedPath),
              contentType: sample.contentType,
              source: 'quick-verify'
            });
            evidenceMapping[sample.key] = storedRecord;
          } catch (insertErr) {
            Logger.error('Failed to record quick verify evidence metadata', { error: insertErr.message, key: sample.key, reportId, findingId });
          }
        }
        rawEvidenceSummary = persisted.map((sample) => {
          const record = evidenceMapping[sample.key];
          if (record) {
            return {
              id: record.id,
              key: record.rawKey,
              scope: record.scope,
              tag: record.tag,
              status: record.status,
              timeMs: record.timeMs,
              bodyHash: record.bodyHash,
              bodyLength: record.bodyLength,
              method: record.method,
              url: record.url,
              createdAt: record.createdAt,
              contentType: record.contentType,
              stored: true
            };
          }
          return {
            id: null,
            key: sample.key,
            scope: sample.scope,
            tag: sample.tag,
            status: sample.status,
            timeMs: sample.timeMs,
            bodyHash: sample.bodyHash,
            bodyLength: sample.bodyLength,
            method: sample.method,
            url: sample.url,
            createdAt: null,
            contentType: sample.contentType,
            stored: false
          };
        });
        if (rawEvidenceSummary.length > 0) {
          try {
            await database.logScanEvent({
              scan_id: String(report.scan_id),
              user_id: req.user.id,
              org_id: req.user.orgId || null,
              event_type: 'quick-verify-evidence-stored',
              metadata: {
                reportId,
                findingId,
                count: rawEvidenceSummary.length,
                keys: rawEvidenceSummary.map((item) => item.key).slice(0, 10)
              }
            });
          } catch (_) {}
        }
      } catch (persistErr) {
        Logger.error('Failed to persist quick verify raw evidence', { error: persistErr.message, reportId, findingId });
        rawEvidenceSummary = summarizeRawBodies(rawBodies).map((entry) => ({ ...entry, stored: false }));
      }
    } else if (rawBodies) {
      rawEvidenceSummary = summarizeRawBodies(rawBodies).map((entry) => ({ ...entry, stored: false }));
    }

    delete result.rawBodies;
    const evidenceForResponse = remapEvidenceRawKeys(result.evidence, evidenceMapping);

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
      if (result.remediationSuspected) {
        await database.logScanEvent({
          scan_id: String(report.scan_id),
          user_id: req.user.id,
          org_id: req.user.orgId || null,
          event_type: 'post-verify-drift',
          metadata: { reportId, findingId, drift: result.driftCheck || null, extraSignals: (result.extraSignals || []).slice(0, 5) }
        });
      }
    } catch (_) {}

    if (consentLogged) {
      try {
        await database.logScanEvent({
          scan_id: String(report.scan_id),
          user_id: req.user.id,
          org_id: req.user.orgId || null,
          event_type: 'quick-verify-consent',
          metadata: {
            reportId,
            findingId,
            storeEvidence: typeof consentInput?.storeEvidence === 'boolean' ? consentInput.storeEvidence : shouldCaptureRawBodies,
            rememberChoice: consentInput?.rememberChoice ?? activePreference.rememberChoice
          }
        });
      } catch (_) {}
    }

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
          indicators: result.wafIndicators || null,
          payloadsTested: Array.isArray(result.seededPayloads) && result.seededPayloads.length > 0 ? result.seededPayloads : undefined,
          payloadConfirmed: Array.isArray(result.confirmations) ? result.confirmations.includes('payload') : undefined,
          baselineConfidence: result.baselineConfidence || undefined,
          remediationSuspected: !!result.remediationSuspected,
          extraSignals: Array.isArray(result.extraSignals) ? result.extraSignals.slice(0, 10) : undefined,
          bestPayload: result.bestPayload || undefined,
          driftCheck: result.driftCheck || undefined
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
  const outRoot = VERIFICATIONS_DIR;
  const fs = require('fs');
  const pathLib = require('path');
  const reportDir = pathLib.join(outRoot, String(reportId));
        fs.mkdirSync(reportDir, { recursive: true });
        const fname = `dom-proof-${findingId}-${Date.now()}.png`;
  const fpath = pathLib.join(reportDir, fname);
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

  return res.json({
    ok: result.ok,
    label: result.label,
    score: result.confidenceScore,
    confirmations: result.confirmations,
    signals: result.signalsTested,
    remediationSuspected: !!result.remediationSuspected,
    diff: result.diffView,
    poc: result.poc,
  evidence: evidenceForResponse || result.evidence || null,
  rawEvidence: rawEvidenceSummary,
    why: result.why,
    wafDetected: !!result.wafDetected,
    suggestions: result.suggestions || [],
    wafIndicators: result.wafIndicators || undefined,
    seededPayloads: result.seededPayloads || [],
    payloadAttempts: result.payloadAttempts || undefined,
    baselineConfidence: result.baselineConfidence || undefined,
    extraSignals: result.extraSignals || [],
    bestPayload: result.bestPayload || null,
    driftCheck: result.driftCheck || null,
    verificationStartedAt: result.verificationStartedAt,
    verificationCompletedAt: result.verificationCompletedAt,
    verificationDurationMs: (typeof result.verificationStartedAt === 'number' && typeof result.verificationCompletedAt === 'number')
      ? Math.max(0, result.verificationCompletedAt - result.verificationStartedAt)
      : null,
    dom: {
      checked: !!result.dom?.checked,
      reflected: !!result.dom?.reflected,
      matches: result.dom?.matches || [],
      url: result.dom?.url,
      proof: domProof
    },
    consent: {
      decision: shouldCaptureRawBodies,
      preference: {
        storeEvidence: activePreference.storeEvidence,
        rememberChoice: activePreference.rememberChoice,
        promptSuppressed: activePreference.promptSuppressed,
        promptVersion: activePreference.promptVersion,
        lastPromptAt: activePreference.lastPromptAt,
        lastDecisionAt: activePreference.lastDecisionAt,
        updatedAt: activePreference.updatedAt,
        createdAt: activePreference.createdAt,
        source: activePreference.source
      }
    }
  });
  } catch (e) {
    Logger.error('Finding verification failed', e);
    res.status(500).json({ error: 'Verification failed', details: e.message });
  }
});

app.get('/api/quick-verify/preferences', async (req, res) => {
  try {
    const preference = await database.getQuickVerifyPreference(req.user.id);
    res.json({ ok: true, preference });
  } catch (e) {
    Logger.error('Fetch quick verify preference failed', e);
    res.status(500).json({ error: 'Failed to fetch preference' });
  }
});

app.post('/api/quick-verify/preferences', async (req, res) => {
  try {
    const {
      storeEvidence = undefined,
      rememberChoice = undefined,
      promptSuppressed = undefined,
      promptVersion = undefined,
      suppressPrompt = undefined,
      lastPromptAt = undefined,
      source = 'user'
    } = req.body || {};
    const nowIso = new Date().toISOString();
    const preference = await database.upsertQuickVerifyPreference(req.user.id, {
      storeEvidence,
      rememberChoice,
      promptSuppressed: promptSuppressed !== undefined ? !!promptSuppressed : (suppressPrompt !== undefined ? !!suppressPrompt : undefined),
      promptVersion,
      lastPromptAt: lastPromptAt || nowIso,
      lastDecisionAt: nowIso,
      source
    });
    res.json({ ok: true, preference });
  } catch (e) {
    Logger.error('Update quick verify preference failed', e);
    res.status(500).json({ error: 'Failed to update preference', details: e.message });
  }
});

app.delete('/api/quick-verify/preferences', async (req, res) => {
  try {
    await database.clearQuickVerifyPreference(req.user.id);
    res.json({ ok: true });
  } catch (e) {
    Logger.error('Clear quick verify preference failed', e);
    res.status(500).json({ error: 'Failed to clear preference' });
  }
});

app.get('/api/reports/:id/findings/:findingId/quick-verify/evidence', async (req, res) => {
  try {
    const { id, findingId } = req.params;
    const report = await database.getReport(id);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    if (req.user.role !== 'admin' && report.user_id && report.user_id !== req.user.id && (!req.user.orgId || report.org_id !== req.user.orgId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }
    const limit = Math.max(1, Math.min(200, parseInt(String(req.query.limit || '50'), 10) || 50));
    const evidence = await database.listQuickVerifyEvidence({
      reportId: id,
      findingId,
      userId: req.user.id,
      orgId: req.user.orgId || null,
      isAdmin: req.user.role === 'admin',
      limit
    });
    res.json({ ok: true, evidence });
  } catch (e) {
    Logger.error('List quick verify evidence failed', e);
    res.status(500).json({ error: 'Failed to fetch evidence', details: e.message });
  }
});

app.get('/api/quick-verify/evidence/:evidenceId/download', async (req, res) => {
  try {
    const { evidenceId } = req.params;
    const record = await database.getQuickVerifyEvidenceById(evidenceId);
    if (!record) return res.status(404).json({ error: 'Evidence not found' });
    const report = await database.getReport(record.reportId);
    if (!report) return res.status(404).json({ error: 'Report not found' });
    const userIsAdmin = req.user.role === 'admin';
    const sameUser = record.userId === req.user.id;
    const sameOrg = req.user.orgId && record.orgId && req.user.orgId === record.orgId;
    if (!userIsAdmin && !sameUser && !sameOrg) {
      if (report.user_id && report.user_id !== req.user.id && (!req.user.orgId || report.org_id !== req.user.orgId)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
    }
    if (!record.storedPath) return res.status(410).json({ error: 'Evidence file not stored' });
    const baseResolved = path.resolve(QUICK_VERIFY_EVIDENCE_DIR);
    const absolutePath = path.resolve(QUICK_VERIFY_EVIDENCE_DIR, record.storedPath);
    const relativeCheck = path.relative(baseResolved, absolutePath);
    if (relativeCheck.startsWith('..') || path.isAbsolute(relativeCheck)) {
      return res.status(400).json({ error: 'Invalid evidence path' });
    }
    if (!fs.existsSync(absolutePath)) {
      return res.status(410).json({ error: 'Evidence file missing' });
    }
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="qv-${record.id}.json"`);
    const stream = fs.createReadStream(absolutePath);
    stream.on('error', (err) => {
      Logger.error('Stream quick verify evidence failed', err);
      if (!res.headersSent) {
        res.status(500).end();
      }
    });
    stream.pipe(res);
  } catch (e) {
    Logger.error('Download quick verify evidence failed', e);
    if (!res.headersSent) {
      res.status(500).json({ error: 'Failed to download evidence', details: e.message });
    }
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

app.get('/api/admin/scans/running', requireAdmin, async (req, res) => {
  try {
    const snapshot = await buildActiveScanSnapshot();
    res.json(snapshot);
  } catch (error) {
    Logger.error('Admin running scans fetch failed', error);
    res.status(500).json({ error: 'Failed to fetch running scans' });
  }
});

app.post('/api/admin/scans/:scanId/terminate', requireAdmin, async (req, res) => {
  const scanId = String(req.params.scanId);
  const reasonRaw = req.body?.reason;
  const reason = typeof reasonRaw === 'string' && reasonRaw.trim().length > 0
    ? reasonRaw.trim()
    : 'Terminated by administrator';

  try {
    const scan = await database.getScan(scanId);
    if (!scan) {
      return res.status(404).json({ error: 'Scan not found' });
    }

    let terminated = false;
    const procInfo = scanProcesses.get(scanId);
    const sessionId = scan.session_id || procInfo?.sessionId || null;

    if (sessionId) {
      try {
        const result = await sqlmapIntegration.stopScan(sessionId);
        if (result) terminated = true;
      } catch (error) {
        Logger.warn('Admin stopScan failed', { scanId, sessionId, error: error.message });
      }
    }

    if (procInfo?.process) {
      const pid = procInfo.process.pid;
      try {
        if (pid) {
          await killPid(pid, 'SIGTERM', 6000);
        } else if (typeof procInfo.process.kill === 'function') {
          procInfo.process.kill('SIGTERM');
        }
        terminated = true;
      } catch (error) {
        Logger.warn('Admin SIGTERM failed', { scanId, pid, error: error.message });
        try {
          if (typeof procInfo.process.kill === 'function') {
            procInfo.process.kill('SIGKILL');
          }
        } catch (_) {}
      }
    }

    scanProcesses.delete(scanId);

    const endTime = new Date().toISOString();
    await database.updateScan(scanId, { status: 'terminated', end_time: endTime });

    try {
      await database.logScanEvent({
        scan_id: scanId,
        user_id: scan.user_id,
        org_id: scan.org_id,
        event_type: 'terminated',
        metadata: {
          by: req.user.id,
          role: req.user.role,
          reason
        }
      });
    } catch (error) {
      Logger.warn('Admin termination event logging failed', { scanId, error: error.message });
    }

    try {
      io.to(`user:${scan.user_id}`).emit('scan-terminated', { scanId, reason });
    } catch (_) {}

    res.json({ scanId, status: 'terminated', reason, terminated });
  } catch (error) {
    Logger.error('Admin scan termination failed', error);
    res.status(500).json({ error: 'Failed to terminate scan' });
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
          effective: currentTrustProxySetting,
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

  const emitToUserRoom = (event, payload, targetUserId = null) => {
    const userId = targetUserId || socket.user?.id || null;
    if (userId) {
      try {
        io.to(`user:${userId}`).emit(event, payload);
        return;
      } catch (_) {}
    }
    try {
      socket.emit(event, payload);
    } catch (_) {}
  };

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
  socket.on('start-sqlmap-scan', async (data = {}) => {
    const userRoomId = socket.user?.id || null;
    const userId = socket.user?.id || 'system';
    const orgId = socket.user?.orgId || null;
    const isAdmin = socket.user?.role === 'admin';

    try {
      const {
        target,
        options,
        scanProfile,
        userProfileId = null,
        userProfileName = null
      } = data || {};

      // Validate input
      if (!target || !SecurityMiddleware.isValidURL(target)) {
        emitToUserRoom('scan-error', { message: 'Invalid target URL provided' }, userRoomId);
        return;
      }

      // Enforce proxy requirement if configured
      const proxyCheck = SecurityMiddleware.requireProxyIfEnabled(options || {});
      if (!proxyCheck.ok) {
        emitToUserRoom('scan-error', { message: proxyCheck.error }, userRoomId);
        return;
      }

      // Acquire per-user lock (best-effort). If already locked, reject quickly.
      if (userStartLocks.get(userId)) {
        emitToUserRoom('scan-error', { message: 'Another scan is being started. Please wait a moment and try again.' }, userRoomId);
        return;
      }
      userStartLocks.set(userId, true);
      const releaseLock = () => userStartLocks.delete(userId);

  const concurrency = await evaluateConcurrencyForUser({ userId, isAdmin, database, scanProcesses });
      if (!concurrency.hasCapacity) {
        emitToUserRoom('scan-error', {
          message: concurrency.limit === 1
            ? 'You already have an active scan running. Wait for it to finish before starting another.'
            : `Concurrent scan limit reached (${concurrency.limit}). Please wait for existing scans to finish.`,
          limit: concurrency.limit,
          activeScan: concurrency.activeScan
        }, userRoomId);
        releaseLock();
        return;
      }

      // Monthly quota (YYYY-MM)
      const period = new Date().toISOString().slice(0,7);
      const MAX_SCANS_MONTH = parseInt(process.env.MAX_SCANS_PER_MONTH || '100', 10);
      if (!isAdmin) {
        const usage = await database.getUsageForUser(userId, period);
        if ((usage?.scans_started || 0) >= MAX_SCANS_MONTH) {
          emitToUserRoom('scan-error', { message: `Monthly scan quota reached (${MAX_SCANS_MONTH} in ${period}).` }, userRoomId);
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
          emitToUserRoom('scan-error', { message: 'A similar scan was just started. Please wait a few seconds before trying again.' }, userRoomId);
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
        const hostname = extractHostname(target);
        if (!hostname) {
          emitToUserRoom('scan-error', { message: 'Unable to parse target hostname for verification.' }, userRoomId);
          releaseLock();
          return;
        }
        const safeHost = isSafeTargetHostname(hostname);
        if (!safeHost) {
          const verified = await database.getVerifiedTargetForUser(hostname, userId, orgId, isAdmin);
          if (!verified) {
            // Log security event for visibility/audit
            Logger.suspiciousActivity('unverified-target', { userId, orgId, hostname, target });
            emitToUserRoom('scan-error', { message: `Target ${hostname} is not verified for your account. Verify ownership before scanning.` }, userRoomId);
            releaseLock();
            return;
          }
        } else {
          logSafeHostUsage({
            userId,
            orgId,
            hostname,
            target,
            via: 'ws:scans:start',
            email: socket.user?.email
          }).catch(() => {});
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
    const { process: proc, outputDir, sessionId } = await sqlmapIntegration.startScan(target, mergedOptions, effectiveProfile, userId, { isAdmin });

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
        start_time: startTimeIso,
        session_id: sessionId
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
        orgId,
        sessionId
      });
      
      // Handle real-time output
      proc.stdout.on('data', (data) => {
        const output = data.toString();
        emitToUserRoom('scan-output', { scanId, output, type: 'stdout' }, userRoomId);
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
        emitToUserRoom('scan-output', { scanId, output, type: 'stderr' }, userRoomId);
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
          let verdictMeta = null;
          
          // Parse structured SQLMap results from tracked output directory
          if (code === 0) {
            try {
              const processInfo = scanProcesses.get(scanId);
              const outDir = processInfo?.outputDir;
              if (outDir && fs.existsSync(outDir)) {
                sqlmapResults = await sqlmapIntegration.parseResults(outDir, scanId);
                Logger.info(`Successfully parsed SQLMap results for scan ${scanId}`);
                if (sqlmapResults?.analysis) {
                  try {
                    const verdictPayload = {
                      ...sqlmapResults.analysis,
                      summary: {
                        ...(sqlmapResults.analysis.summary || {}),
                        exitCode: code,
                        completedAt: endTime,
                      }
                    };
                    await database.updateScan(scanId, { verdict_meta: JSON.stringify(verdictPayload) });
                    verdictMeta = verdictPayload;
                  } catch (verdictError) {
                    Logger.debug('Socket handler failed to persist verdict metadata', { scanId, error: verdictError?.message });
                  }
                }
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
          
          emitToUserRoom('scan-completed', { 
            scanId, 
            status: code === 0 ? 'completed' : 'failed',
            reportId: reportId,
            exit_code: code,
            hasStructuredResults: !!sqlmapResults,
            verdictMeta
          }, userRoomId);
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
          emitToUserRoom('scan-error', { 
            scanId, 
            message: 'Scan completed but failed to generate report' 
          }, userRoomId);
        } finally {
          // Clean up the scan process tracking
          scanProcesses.delete(scanId);
        }
      });

      proc.on('error', (error) => {
        Logger.error('SQLMap process error:', error);
        emitToUserRoom('scan-error', { scanId, message: error.message }, userRoomId);
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

      emitToUserRoom('scan-started', { scanId, target, scanProfile: effectiveProfile, startTime: startTimeIso, sessionId }, userRoomId);
      releaseLock();

    } catch (error) {
      Logger.error('Error starting scan:', error);
      emitToUserRoom('scan-error', { message: error.message }, userRoomId);
      try { userStartLocks.delete(socket.user?.id || 'system'); } catch (_) {}
    }
  });

  // Restart a scan: either by prior scanId (reuse saved target/options/profile) or by explicit payload
  socket.on('restart-scan', async (payload = {}) => {
    try {
      const userId = socket.user?.id || 'system';
      const orgId = socket.user?.orgId || null;
      const isAdmin = socket.user?.role === 'admin';
      const userRoomId = socket.user?.id || null;

      // Resolve target/options/profile
      let target = payload.target;
      let options = payload.options || {};
      let scanProfile = payload.scanProfile || 'basic';

      if (!target && payload.scanId) {
        // Load previous scan and reuse its parameters
        const prev = await database.getScan(String(payload.scanId));
        if (!prev) {
          emitToUserRoom('scan-error', { message: 'Previous scan not found' }, userRoomId);
          return;
        }
        // Ownership check
        const owns = isAdmin || prev.user_id === userId || (orgId && prev.org_id === orgId);
        if (!owns) {
          Logger.unauthorizedAccess('scan-restart', { scanId: payload.scanId, owner: prev.user_id, by: userId, byOrg: orgId });
          emitToUserRoom('scan-error', { message: 'You do not have permission to restart this scan.' }, userRoomId);
          return;
        }
        target = prev.target;
        // prev.options may be JSON string; parse safely
        try { options = typeof prev.options === 'string' ? JSON.parse(prev.options) : (prev.options || {}); } catch (_) { options = {}; }
        scanProfile = prev.scan_profile || 'basic';
      }

      if (!target || !SecurityMiddleware.isValidURL(target)) {
        emitToUserRoom('scan-error', { message: 'Invalid or missing target for restart' }, userRoomId);
        return;
      }

      // Proxy requirement
      const proxyCheck = SecurityMiddleware.requireProxyIfEnabled(options || {});
      if (!proxyCheck.ok) {
        emitToUserRoom('scan-error', { message: proxyCheck.error }, userRoomId);
        return;
      }

      // Per-user start lock
      if (userStartLocks.get(userId)) {
        emitToUserRoom('scan-error', { message: 'Another scan is being started. Please wait a moment and try again.' }, userRoomId);
        return;
      }
      userStartLocks.set(userId, true);
      const releaseLock = () => userStartLocks.delete(userId);

      try {
  const concurrency = await evaluateConcurrencyForUser({ userId, isAdmin, database, scanProcesses });
        if (!concurrency.hasCapacity) {
          emitToUserRoom('scan-error', {
            message: concurrency.limit === 1
              ? 'You already have an active scan running. Wait for it to finish before starting another.'
              : `Concurrent scan limit reached (${concurrency.limit}). Please wait for existing scans to finish.`,
            limit: concurrency.limit,
            activeScan: concurrency.activeScan
          }, userRoomId);
          return;
        }

        // Quotas
        const period = new Date().toISOString().slice(0,7);
        const MAX_SCANS_MONTH = parseInt(process.env.MAX_SCANS_PER_MONTH || '100', 10);
        if (!isAdmin) {
          const usage = await database.getUsageForUser(userId, period);
          if ((usage?.scans_started || 0) >= MAX_SCANS_MONTH) {
            emitToUserRoom('scan-error', { message: `Monthly scan quota reached (${MAX_SCANS_MONTH} in ${period}).` }, userRoomId);
            return;
          }
        }

        // Restart semantics: bypass duplicate-start debounce window intentionally

        // Verified target policy unless explicitly allowed
        const allowUnverified = ['true','1','yes','on'].includes(String(process.env.ALLOW_UNVERIFIED_TARGETS).toLowerCase());
        if (!allowUnverified && !isAdmin) {
          const hostname = extractHostname(target);
          if (!hostname) {
            emitToUserRoom('scan-error', { message: 'Unable to parse target hostname for verification.' }, userRoomId);
            return;
          }
          const safeHost = isSafeTargetHostname(hostname);
          if (!safeHost) {
            const verified = await database.getVerifiedTargetForUser(hostname, userId, orgId, isAdmin);
            if (!verified) {
              Logger.suspiciousActivity('unverified-target-restart', { userId, orgId, hostname, target });
              emitToUserRoom('scan-error', { message: `Target ${hostname} is not verified for your account. Verify ownership before scanning.` }, userRoomId);
              return;
            }
          } else {
            logSafeHostUsage({
              userId,
              orgId,
              hostname,
              target,
              via: 'ws:scans:restart',
              email: socket.user?.email
            }).catch(() => {});
          }
        }

        // Prepare auth context
        const { preparedOptions, authMeta } = await prepareAuthContext(options || {}, target, userId);

    // Start scan
    const { process: proc, outputDir, sessionId } = await sqlmapIntegration.startScan(target, preparedOptions, scanProfile, userId, { isAdmin });

        const startTimeIso = new Date().toISOString();
        const scanId = await database.createScan({
          target,
          options: sanitizeOptionsForStorage({ ...preparedOptions, auth: { ...(preparedOptions.auth || {}), type: authMeta.mode } }),
          scanProfile,
          user_id: userId,
          org_id: orgId,
          output_dir: outputDir,
          status: 'running',
          start_time: startTimeIso,
          session_id: sessionId
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

  scanProcesses.set(scanId, { process: proc, outputDir, target, scanProfile, startTime: new Date(), userId, orgId, sessionId });

        // Stream output
        proc.stdout.on('data', (data) => {
          const output = data.toString();
          emitToUserRoom('scan-output', { scanId, output, type: 'stdout' }, userRoomId);
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
          emitToUserRoom('scan-output', { scanId, output, type: 'stderr' }, userRoomId);
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
            let verdictMeta = null;
            if (code === 0) {
              try {
                const processInfo = scanProcesses.get(scanId);
                const outDir = processInfo?.outputDir;
                if (outDir && fs.existsSync(outDir)) {
                  sqlmapResults = await sqlmapIntegration.parseResults(outDir, scanId);
                  if (sqlmapResults?.analysis) {
                    try {
                      const verdictPayload = {
                        ...sqlmapResults.analysis,
                        summary: {
                          ...(sqlmapResults.analysis.summary || {}),
                          exitCode: code,
                          completedAt: endTime,
                        }
                      };
                      await database.updateScan(scanId, { verdict_meta: JSON.stringify(verdictPayload) });
                      verdictMeta = verdictPayload;
                    } catch (verdictError) {
                      Logger.debug('Restart handler failed to persist verdict metadata', { scanId, error: verdictError?.message });
                    }
                  }
                }
              } catch (e) { Logger.error('Restart parse results error', e); }
            }
            const reportData = await reportGenerator.generateReport(scanId, scanData, sqlmapResults);
            const reportId = await database.createReport({ ...reportData, user_id: userId, org_id: orgId });
            emitToUserRoom('scan-completed', { scanId, status: code === 0 ? 'completed' : 'failed', reportId, exit_code: code, hasStructuredResults: !!sqlmapResults, verdictMeta }, userRoomId);
            database.logScanEvent({ scan_id: scanId, user_id: userId, org_id: orgId, event_type: code === 0 ? 'completed' : 'failed', metadata: { exit_code: code, reportId, hasStructuredResults: !!sqlmapResults, verdictMeta, via: 'ws', restartOf: payload.scanId || null } }).catch(()=>{});
            try {
              const runtime = (new Date(scanData.end_time).getTime() - new Date(scanData.start_time).getTime()) || 0;
              await database.incrementUsageOnComplete(userId, period, Math.max(0, runtime));
            } catch (_) {}
          } catch (e) {
            Logger.error('Restart scan close handler error', e);
            emitToUserRoom('scan-error', { scanId, message: 'Scan completed but failed to generate report' }, userRoomId);
          } finally {
            scanProcesses.delete(scanId);
          }
        });

        proc.on('error', (error) => {
          Logger.error('SQLMap process error (restart):', error);
          emitToUserRoom('scan-error', { scanId, message: error.message }, userRoomId);
          database.updateScan(scanId, { status: 'failed', error: error.message });
          database.logScanEvent({ scan_id: scanId, user_id: userId, org_id: orgId, event_type: 'process-error', metadata: { message: error.message, via: 'ws', restartOf: payload.scanId || null } }).catch(()=>{});
          scanProcesses.delete(scanId);
        });

  emitToUserRoom('scan-started', { scanId, target, scanProfile, startTime: startTimeIso, sessionId }, userRoomId);
      } finally {
        releaseLock();
      }
    } catch (e) {
      Logger.error('Restart-scan failed', e);
      emitToUserRoom('scan-error', { message: e.message || 'Failed to restart scan' }, socket.user?.id || null);
    }
  });

  // Handle scan termination (Ctrl+C functionality)
  socket.on('terminate-scan', (payload = {}) => {
    // Be robust to non-object payloads or undefined
    const safePayload = (payload && typeof payload === 'object') ? payload : {};
    let reqScanId = safePayload.scanId || socket.scanId;
    const userRoomId = socket.user?.id || null;

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
      emitToUserRoom('scan-error', { message: 'Scan not found or already finished.' }, userRoomId);
      return;
    }

    const isAdmin = socket.user?.role === 'admin';
    const sameUser = procInfo.userId === (socket.user?.id || '');
    const sameOrg = socket.user?.orgId && procInfo.orgId && socket.user.orgId === procInfo.orgId;
    if (!(isAdmin || sameUser || sameOrg)) {
      // Explicit security log for unauthorized termination attempt
      Logger.unauthorizedAccess('scan-terminate', { scanId: reqScanId, owner: procInfo.userId, by: socket.user?.id, byOrg: socket.user?.orgId || null });
      emitToUserRoom('scan-error', { message: 'You do not have permission to terminate this scan.' }, userRoomId);
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
  emitToUserRoom('scan-terminated', { scanId: reqScanId }, procInfo.userId || userRoomId);
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
      emitToUserRoom('scan-error', { message: 'Failed to terminate scan.' }, userRoomId);
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