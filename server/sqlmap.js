const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { v4: uuidv4 } = require('uuid');
const Logger = require('./utils/logger');
const killTree = require('tree-kill');

const DEFAULT_USER_AGENT = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36';

// eslint-disable-next-line no-control-regex
const ANSI_ESCAPE_REGEX = /\u001b\[[0-9;]*m/g;
const LEADING_DELIMITER_REGEX = /^(?:\[[^\]]+\]|\([^)]+\)|<[^>]+>)\s*/g;

const BASE_FLAG_DISPLAY = [
  {
    flag: '--batch',
    category: 'Stability',
    description: 'Skip interactive prompts so scans remain non-blocking in automation contexts.'
  },
  {
    flag: '--random-agent',
    category: 'Stealth',
    description: 'Rotate user-agents to reduce basic detection heuristics.'
  },
  {
    flag: '--output-dir "<per-scan temp dir>"',
    category: 'Evidence',
    description: 'Persist scan artefacts in an isolated, per-run directory managed server-side.',
    caution: 'Directory path never leaves the server and is unique per user session.'
  },
  {
    flag: '-s "<session.sqlite>"',
    category: 'Evidence',
    description: 'Capture SQLMap session data to support resume operations and auditing.'
  },
  {
    flag: '-t "<traffic.log>"',
    category: 'Evidence',
    description: 'Log HTTP traffic for traceability and post-scan review.'
  },
  {
    flag: '--hex',
    category: 'Data Handling',
    description: 'Return extracted data in hexadecimal to avoid encoding ambiguity.'
  },
  {
    flag: '--flush-session',
    category: 'Freshness',
    description: 'Clear prior SQLMap caches to guarantee new queries on every run.'
  },
  {
    flag: '--delay=1',
    category: 'Operational Safety',
    description: 'Add a one second delay between requests to temper load on the target.'
  },
  {
    flag: '--timeout=30',
    category: 'Resilience',
    description: 'Abort individual HTTP requests after 30 seconds to avoid hanging scans.'
  },
  {
    flag: '--retries=3',
    category: 'Resilience',
    description: 'Retry failed requests up to three times before abandoning them.'
  },
  {
    flag: '--keep-alive',
    category: 'Performance',
    description: 'Reuse HTTP connections when targets support persistent sessions.'
  },
  {
    flag: '--threads=1',
    category: 'Stability',
    description: 'Restrict to a single worker thread for predictable behaviour on fragile targets.'
  },
  {
    flag: `--user-agent="${DEFAULT_USER_AGENT}"`,
    category: 'Stealth',
    description: 'Spoof a modern desktop browser user-agent string to blend with normal traffic.'
  },
  {
    flag: '--skip-heuristics',
    category: 'Performance',
    description: 'Disable heuristic checks for marginally faster reconnaissance.'
  },
  {
    flag: '--banner',
    category: 'Enumeration',
    description: 'Request DBMS banner information for reporting context.'
  },
  {
    flag: '--current-user',
    category: 'Enumeration',
    description: 'Identify the database account being used in the session.'
  },
  {
    flag: '--current-db',
    category: 'Enumeration',
    description: 'Reveal the name of the current database context.'
  },
  {
    flag: '--hostname',
    category: 'Enumeration',
    description: 'Capture the database server hostname when possible.'
  },
  {
    flag: '--is-dba',
    category: 'Enumeration',
    description: 'Confirm whether the current DB user has DBA privileges.'
  },
  {
    flag: '--passwords',
    category: 'Extraction',
    description: 'Attempt to enumerate password hashes for credential audits.',
    caution: 'May increase the volume of retrieved sensitive data; ensure authorisation covers this scope.'
  },
  {
    flag: '--privileges',
    category: 'Enumeration',
    description: 'List database privileges assigned to discovered accounts.'
  },
  {
    flag: '--roles',
    category: 'Enumeration',
    description: 'Enumerate database roles tied to the compromised context.'
  },
  {
    flag: '--schema',
    category: 'Enumeration',
    description: 'Collect schema information (databases, tables, columns).'
  },
  {
    flag: '--count',
    category: 'Enumeration',
    description: 'Count table entries to gauge data volume.'
  },
  {
    flag: '--fresh-queries',
    category: 'Freshness',
    description: 'Bypass cached results to ensure live verification of findings.'
  }
];

class SQLMapIntegration {
  constructor() {
    // Allow environment override
    const envPath = process.env.SQLMAP_PATH && process.env.SQLMAP_PATH.trim();
    if (envPath) {
      try {
        // Basic existence / executable check (if absolute path)
        if (envPath.includes(path.sep)) {
          if (!fs.existsSync(envPath)) {
            Logger.warn(`SQLMAP_PATH provided but file does not exist: ${envPath}. Falling back to auto-detect.`);
            this.sqlmapPath = this.findSQLMapPath();
          } else {
            this.sqlmapPath = envPath;
            Logger.info(`Using SQLMap path from environment: ${envPath}`);
          }
        } else {
          // Likely a command name; accept and rely on downstream validation
          this.sqlmapPath = envPath;
          Logger.info(`Using SQLMap command from environment: ${envPath}`);
        }
      } catch (e) {
        Logger.warn(`Failed to use SQLMAP_PATH override (${envPath}): ${e.message}. Falling back to detection.`);
        this.sqlmapPath = this.findSQLMapPath();
      }
    } else {
      this.sqlmapPath = this.findSQLMapPath();
    }

    const resolveTempRoot = () => {
      const candidate = (process.env.SQLMAP_TEMP_DIR || process.env.TEMP_DIR || '').trim();
      if (!candidate) {
        return path.join(os.tmpdir(), 'cybersec-temp');
      }
  return path.isAbsolute(candidate) ? candidate : path.join(__dirname, candidate);
    };

    this.baseTempDir = resolveTempRoot();
    this.tempDir = path.join(this.baseTempDir, 'sqlmap');
    this.runningProcesses = new Map();
    
    // Ensure temp directory exists
    for (const dir of [this.baseTempDir, this.tempDir]) {
      if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
      }
    }

    // Initialize scan profiles
    this.scanProfiles = {
      'basic': {
        name: 'Basic SQL Injection Scan',
        description: 'Enhanced basic scan with better detection',
        flags: ['--level=2', '--risk=2', '--technique=BEUSTQ', '--forms', '--crawl=1', '--tamper=space2comment,charencode,randomcase']
      },
      'deep': {
        name: 'Deep Scan',
        description: 'Comprehensive scan with advanced techniques',
        flags: ['--batch', '--random-agent', '--level=4', '--risk=3', '--forms', '--crawl=2', '--threads=2', '--tamper=apostrophemask,base64encode,charencode,equaltolike,space2comment,randomcase,unionalltounion', '--technique=BEUSTQ']
      },
      'aggressive': {
        name: 'Aggressive Scan',
        description: 'Maximum detection with all techniques',
        flags: ['--batch', '--random-agent', '--level=5', '--risk=3', '--forms', '--crawl=3', '--smart', '--threads=2', '--tamper=apostrophemask,apostrophenullencode,base64encode,charencode,charunicodeencode,equaltolike,space2comment,space2dash,space2hash,space2plus,randomcase,randomcomments,unionalltounion,versionedkeywords', '--technique=BEUSTQ']
      },
      'enumeration': {
        name: 'Database Enumeration',
        description: 'Enumerate database structure and contents',
        flags: ['--batch', '--random-agent', '--level=3', '--risk=2', '--dbs', '--tables', '--columns', '--exclude-sysdbs', '--threads=2']
      },
      'dump': {
        name: 'Data Extraction',
        description: 'Extract data from vulnerable parameters',
        flags: ['--batch', '--random-agent', '--level=3', '--risk=2', '--dump', '--exclude-sysdbs', '--threads=2']
      },
      'custom': {
        name: 'Custom Scan',
        description: 'User-defined custom parameters',
        flags: ['--level=2', '--risk=2', '--technique=BEUSTQ']
      }
    };

    this.baseFlagDisplay = BASE_FLAG_DISPLAY;

    // Log the detected SQLMap path
    Logger.info(`SQLMap integration initialized with path: ${this.sqlmapPath}`);
    
    // Validate SQLMap installation
    this.validateSQLMapInstallation();
  }

  async validateSQLMapInstallation() {
    try {
      let versionOutput;
      
      if (this.sqlmapPath.includes(' -m ')) {
        const parts = this.sqlmapPath.split(' ');
        versionOutput = execSync(`${parts[0]} -m sqlmap --batch --version`, { 
          stdio: 'pipe', 
          timeout: 10000,
          encoding: 'utf8'
        });
      } else if (this.sqlmapPath.includes(' ')) {
        versionOutput = execSync(`${this.sqlmapPath} --batch --version`, { 
          stdio: 'pipe', 
          timeout: 10000,
          encoding: 'utf8'
        });
      } else {
        versionOutput = execSync(`${this.sqlmapPath} --batch --version`, { 
          stdio: 'pipe', 
          timeout: 10000,
          encoding: 'utf8'
        });
      }
      
      Logger.info('SQLMap installation validated successfully');
      Logger.info(`SQLMap version: ${versionOutput.trim()}`);
    } catch (error) {
      Logger.error('SQLMap validation failed:', error.message);
      Logger.warn('SQLMap may not be properly installed.');
      
      // Try to suggest installation
      this.suggestInstallation();
    }
  }

  suggestInstallation() {
    const isWindows = process.platform === 'win32';
    
    if (isWindows) {
      Logger.info('To install SQLMap on Windows:');
      Logger.info('1. Install Python: https://python.org/downloads/');
      Logger.info('2. Run: pip install sqlmapapi');
      Logger.info('3. Or download SQLMap: https://github.com/sqlmapproject/sqlmap');
    } else {
      Logger.info('To install SQLMap on Linux/Mac:');
      Logger.info('1. sudo apt install sqlmap  (Ubuntu/Debian)');
      Logger.info('2. brew install sqlmap  (macOS)');
      Logger.info('3. pip install sqlmapapi');
    }
  }

  findSQLMapPath() {
    const isWindows = process.platform === 'win32';
    
    // Try direct sqlmap command first (most common)
    try {
      execSync('sqlmap --batch --version', { stdio: 'pipe', timeout: 10000 });
      Logger.info('Found SQLMap command in PATH');
      return 'sqlmap';
    } catch (cmdError) {
      Logger.info('Direct sqlmap command not available, trying alternatives...');
    }
    
    if (isWindows) {
      // Try common Python + SQLMap combinations for Windows
      const pythonCommands = ['python', 'python3', 'py'];
      
      for (const pythonCmd of pythonCommands) {
        try {
          // Test if python is available
          execSync(`${pythonCmd} --version`, { stdio: 'pipe' });
          
          // Try to find sqlmap module
          try {
            execSync(`${pythonCmd} -m sqlmap --batch --version`, { stdio: 'pipe', timeout: 10000 });
            Logger.info(`Found SQLMap via Python module: ${pythonCmd} -m sqlmap`);
            return `${pythonCmd} -m sqlmap`;
          } catch (moduleError) {
            // Continue to next python command
            Logger.info(`SQLMap module not available for ${pythonCmd}`);
          }
        } catch (pythonError) {
          // Python not available with this command, try next
          Logger.info(`${pythonCmd} not available`);
        }
      }
    } else {
      // Unix/Linux paths
      const unixPaths = [
      '/usr/bin/sqlmap',
      '/usr/local/bin/sqlmap',
      '/opt/sqlmap/sqlmap.py',
        'sqlmap'
    ];

      for (const sqlmapPath of unixPaths) {
      try {
          execSync(`${sqlmapPath} --batch --version`, { stdio: 'pipe', timeout: 10000 });
            Logger.info(`Found SQLMap at: ${sqlmapPath}`);
            return sqlmapPath;
      } catch (error) {
        // Continue to next path
      }
      }
    }

    // Default fallback - assume sqlmap is in PATH
    Logger.warn('SQLMap not found via version check, using default command');
    return 'sqlmap';
  }

  validateTarget(target) {
    // Basic URL validation
    const urlRegex = /^https?:\/\/.+/i;
    if (!urlRegex.test(target)) {
      throw new Error('Invalid target URL. Must start with http:// or https://');
    }

    // Check for dangerous characters
    const dangerousChars = [';', '&', '|', '`', '$', '(', ')', '{', '}'];
    for (const char of dangerousChars) {
      if (target.includes(char)) {
        throw new Error(`Target URL contains potentially dangerous character: ${char}`);
      }
    }

    return true;
  }

  buildBaseFlags(outputDir) {
    const quotedOutputDir = `"${outputDir}"`;
    const sessionFile = `"${path.join(outputDir, 'session.sqlite')}"`;
    const trafficLog = `"${path.join(outputDir, 'traffic.log')}"`;

    return [
      '--batch',
      '--random-agent',
      '--output-dir', quotedOutputDir,
      '-s', sessionFile,
      '-t', trafficLog,
      '--hex',
      '--flush-session',
      '--delay=1',
      '--timeout=30',
      '--retries=3',
      '--keep-alive',
      '--threads=1',
      `--user-agent="${DEFAULT_USER_AGENT}"`,
      '--skip-heuristics',
      '--banner',
      '--current-user',
      '--current-db',
      '--hostname',
      '--is-dba',
      '--passwords',
      '--privileges',
      '--roles',
      '--schema',
      '--count',
      '--fresh-queries'
    ];
  }

  getBaseFlagsMetadata() {
    const baseFlags = this.baseFlagDisplay || [];
    const baseFlagTokens = this.buildBaseFlags(path.join(this.tempDir, '__metadata__'));
    const normalizeFlag = (flag) => {
      if (typeof flag !== 'string') return flag;
      const trimmed = flag.trim();
      if (!trimmed.startsWith('-')) return trimmed;
      const eqIndex = trimmed.indexOf('=');
      return eqIndex > 0 ? trimmed.slice(0, eqIndex) : trimmed;
    };

    const baseFlagSet = new Set(
      baseFlagTokens
        .filter((token) => typeof token === 'string' && token.trim().startsWith('-'))
        .map((token) => normalizeFlag(token))
    );

    const profileInsights = Object.entries(this.scanProfiles).map(([key, profile]) => {
      const profileFlags = Array.isArray(profile.flags) ? [...profile.flags] : [];
      const normalizedProfile = profileFlags.map((flag) => ({
        flag,
        normalized: normalizeFlag(flag)
      }));

      const overlaps = normalizedProfile
        .filter((entry) => baseFlagSet.has(entry.normalized))
        .map((entry) => entry.flag);

      const additionalFlags = normalizedProfile
        .filter((entry) => !baseFlagSet.has(entry.normalized))
        .map((entry) => entry.flag);

      return {
        id: key,
        name: profile.name,
        description: profile.description,
        flags: profileFlags,
        overlaps,
        additionalFlags,
      };
    });

    return {
      baseFlags,
      joined: baseFlags.map((item) => item.flag).join(' '),
      total: baseFlags.length,
      profiles: profileInsights
    };
  }

  buildSQLMapCommand(target, options = {}, scanProfile = 'basic', context = {}) {
    this.validateTarget(target);

    const command = [];
    const profile = this.scanProfiles[scanProfile] || this.scanProfiles.basic;

    // Start with SQLMap path
    if (this.sqlmapPath.includes('python')) {
      const parts = this.sqlmapPath.split(' ');
      command.push(parts[0]); // python/python3
      command.push(parts[1]); // sqlmap.py path
    } else {
      command.push(this.sqlmapPath);
    }

    // Add target URL
    command.push('-u', target);

    // Add output directory and base flags
    const outputDir = path.join(this.tempDir, uuidv4());
    fs.mkdirSync(outputDir, { recursive: true });
    const baseFlags = this.buildBaseFlags(outputDir);
    command.push(...baseFlags);

    // Add profile flags
    command.push(...profile.flags);

    // Add custom options
    if (options.cookie) {
      command.push('--cookie', options.cookie);
    }

    if (options.userAgent) {
      command.push('--user-agent', options.userAgent);
    }

    if (options.headers) {
      for (const [key, value] of Object.entries(options.headers)) {
        command.push('--header', `${key}: ${value}`);
      }
    }

    if (options.data) {
      command.push('--data', options.data);
    }

    if (options.method && options.method.toUpperCase() !== 'GET') {
      command.push('--method', options.method.toUpperCase());
    }

    if (options.timeout) {
      command.push('--timeout', options.timeout.toString());
    }

    if (options.delay) {
      command.push('--delay', options.delay.toString());
    }

    if (options.proxy) {
      command.push('--proxy', options.proxy);
    }

    if (scanProfile === 'custom' && options.customFlags) {
      // Parse and validate custom flags
      const customFlags = this.parseCustomFlags(options.customFlags, context);
      command.push(...customFlags);
    }

    return { command, outputDir };
  }

  parseCustomFlags(customFlags, context = {}) {
    if (typeof customFlags !== 'string') {
      return [];
    }

    const { isAdmin = false } = context || {};

    // Tokenize while preserving quoted segments
    const tokens = customFlags.match(/"[^"]*"|'[^']*'|\S+/g) || [];
    const sanitizedTokens = tokens.map(token => token.trim()).filter(Boolean);
    const validatedFlags = [];

    // Whitelist of allowed flags for standard users
    const allowedFlags = [
      '--level', '--risk', '--threads', '--delay', '--timeout',
      '--tamper', '--technique', '--dbms', '--os', '--random-agent',
      '--batch', '--flush-session', '--fresh-queries', '--hex',
      '--dump-all', '--exclude-sysdbs', '--limit', '--start', '--stop',
      '--first', '--last', '--dbs', '--tables', '--columns', '--schema',
      '--count', '--dump', '--dump-table', '--dump-format', '--search',
      '--check-waf', '--identify-waf', '--skip-waf', '--mobile',
      '--smart', '--skip-heuristics', '--skip-static', '--unstable'
    ];

    const previousFlagRequiresValue = () => {
      if (!validatedFlags.length) return false;
      const last = validatedFlags[validatedFlags.length - 1];
      return typeof last === 'string' && last.startsWith('-') && !last.includes('=');
    };

    for (let i = 0; i < sanitizedTokens.length; i++) {
      const token = sanitizedTokens[i];
      if (!token) continue;

      if (!token.startsWith('-')) {
        if (isAdmin || previousFlagRequiresValue()) {
          validatedFlags.push(token);
        }
        continue;
      }

      if (isAdmin) {
        validatedFlags.push(token);
        continue;
      }

      if (!token.startsWith('--')) {
        Logger.warn(`Skipping disallowed flag: ${token}`);
        continue;
      }

      const flagName = token.split('=')[0];
      if (allowedFlags.includes(flagName)) {
        validatedFlags.push(token);

        if (!token.includes('=') && i + 1 < sanitizedTokens.length) {
          const valueCandidate = sanitizedTokens[i + 1];
          if (valueCandidate && !valueCandidate.startsWith('--')) {
            validatedFlags.push(valueCandidate);
            i++;
          }
        }
      } else {
        Logger.warn(`Skipping disallowed flag: ${token}`);
      }
    }

    return validatedFlags;
  }

  async startScan(target, options = {}, scanProfile = 'basic', userId = 'system', context = {}) {
  const sessionId = uuidv4();
  // Use per-user directory inside the configured temp directory
  const outputDir = path.join(this.tempDir, String(userId), sessionId);
    
    // Ensure output directory exists
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    // Get profile flags (now includes enhanced defaults)
    const profile = this.scanProfiles[scanProfile] || this.scanProfiles.basic;
    
    const defaultFlags = this.buildBaseFlags(outputDir);
    
    // Merge profile flags with any custom options
    const profileFlags = profile.flags || [];
  const customFlags = options.customFlags ? this.parseCustomFlags(options.customFlags, context) : [];

    const args = [
      '-u', target,
      ...defaultFlags,
      ...profileFlags,
      ...customFlags
    ];

    // Map selected HTTP/auth options into sqlmap arguments (Phase 1 Auth support)
    try {
      if (options) {
        // Cookie header
        if (options.cookie && typeof options.cookie === 'string') {
          const cookieVal = options.cookie.replace(/"/g, '\\"');
          args.push('--cookie', `"${cookieVal}"`);
        }

        // User-Agent override
        if (options.userAgent && typeof options.userAgent === 'string') {
          const ua = options.userAgent.replace(/"/g, '\\"');
          args.push('--user-agent', `"${ua}"`);
        }

        // Additional headers
        if (options.headers && typeof options.headers === 'object') {
          for (const [hk, hv] of Object.entries(options.headers)) {
            if (!hk) continue;
            const headerLine = `${hk}: ${String(hv ?? '').replace(/\n/g, ' ').replace(/"/g, '\\"')}`;
            args.push('--header', `"${headerLine}"`);
          }
        }

        // POST data / request body
        if (options.data && typeof options.data === 'string') {
          const dataStr = options.data.replace(/"/g, '\\"');
          args.push('--data', `"${dataStr}"`);
        }

        // HTTP method
        if (options.method && typeof options.method === 'string' && options.method.toUpperCase() !== 'GET') {
          args.push('--method', options.method.toUpperCase());
        }

        // Timeouts / delays
        if (options.timeout && Number.isFinite(Number(options.timeout))) {
          args.push('--timeout', String(options.timeout));
        }
        if (options.delay && Number.isFinite(Number(options.delay))) {
          args.push('--delay', String(options.delay));
        }

        // Proxy
        if (options.proxy && typeof options.proxy === 'string') {
          args.push('--proxy', options.proxy);
        }
      }
    } catch (e) {
      Logger.warn('Failed to map options into sqlmap args', { error: e.message });
    }

    Logger.info(`Executing SQLMap with command: ${this.sqlmapPath} ${args.join(' ')}`);
    
    // Handle different command formats
    let command, commandArgs;
    
    if (this.sqlmapPath.includes(' -m ')) {
      // Python module format: "python -m sqlmap"
      const parts = this.sqlmapPath.split(' ');
      command = parts[0]; // python/python3/py
      commandArgs = [...parts.slice(1), ...args]; // [-m, sqlmap, ...args]
    } else if (this.sqlmapPath.includes(' ')) {
      // Space-separated format: "python sqlmap.py"
      const parts = this.sqlmapPath.split(' ');
      command = parts[0];
      commandArgs = [...parts.slice(1), ...args];
    } else {
      // Single command: "sqlmap"
      command = this.sqlmapPath;
      commandArgs = args;
    }

    Logger.info(`Spawning: ${command} with args: ${commandArgs.join(' ')}`);

    // Enhanced spawn configuration for better output capture
    const spawnOptions = {
      shell: true,
      windowsHide: true,
      detached: false,
      stdio: ['pipe', 'pipe', 'pipe'],
      cwd: outputDir,
      // Add environment variables to ensure proper output
      env: {
        ...process.env,
        PYTHONUNBUFFERED: '1', // Force Python to not buffer output
        PYTHONIOENCODING: 'utf-8' // Ensure proper encoding
      }
    };

    const childProcess = spawn(command, commandArgs, spawnOptions);
    
    // Add error handling for spawn process
    childProcess.on('error', (error) => {
      Logger.error(`SQLMap spawn error: ${error.message}`);
    });

    // Track process for management/cleanup
    this.runningProcesses.set(sessionId, {
      process: childProcess,
      outputDir,
      target,
      scanProfile,
      startTime: new Date(),
      userId,
      context
    });

    // On close, remove from map
    childProcess.on('close', () => {
      this.runningProcesses.delete(sessionId);
    });

    return { process: childProcess, outputDir, sessionId };
  }

  stopScan(sessionId, signal = 'SIGTERM') {
    return new Promise((resolve, reject) => {
      const entry = this.runningProcesses.get(sessionId);
      if (!entry || !entry.process) {
        return resolve(false);
      }

      const proc = entry.process;
      const finalize = (err) => {
        if (err) {
          return reject(err);
        }
        this.runningProcesses.delete(sessionId);
        resolve(true);
      };

      try {
        if (proc.pid) {
          killTree(proc.pid, signal, (err) => finalize(err));
        } else {
          const result = proc.kill?.(signal) ?? false;
          finalize(result ? null : new Error('Failed to send kill signal'));
        }
      } catch (error) {
        reject(error);
      }
    });
  }

  listRunningProcesses() {
    return Array.from(this.runningProcesses.entries()).map(([sessionId, entry]) => ({
      sessionId,
      target: entry.target,
      scanProfile: entry.scanProfile,
      startTime: entry.startTime,
      userId: entry.userId,
      context: entry.context || {},
      pid: entry.process?.pid ?? null,
    }));
  }

  // Parse SQLMap results for structured report generation
  async parseResults(outputDir, sessionId) {
    const results = {
      sessionId,
      timestamp: new Date().toISOString(),
      findings: [],
      databases: [],
      tables: [],
      vulnerabilities: [],
      analysis: this.createEmptyAnalysis(sessionId),
      files: {
        session: path.join(outputDir, 'session.sqlite'),
        traffic: path.join(outputDir, 'traffic.log'),
        results: path.join(outputDir, 'results.csv'),
        dumps: []
      }
    };

    try {
      // Parse session data if available
      const sessionFile = path.join(outputDir, 'session.sqlite');
      if (fs.existsSync(sessionFile)) {
        results.files.session = sessionFile;
      }

      // Parse traffic log
      const trafficFile = path.join(outputDir, 'traffic.log');
      if (fs.existsSync(trafficFile)) {
        results.files.traffic = trafficFile;
        // You could parse HTTP requests/responses here
      }

      // Parse CSV results file (support both results.csv and results-*.csv)
      let resultsFile = path.join(outputDir, 'results.csv');
      if (!fs.existsSync(resultsFile)) {
        try {
          const candidates = fs.readdirSync(outputDir).filter(f => /^results-.*\.csv$/i.test(f));
          if (candidates.length > 0) {
            // Choose the latest by mtime
            const latest = candidates
              .map(name => ({ name, mtime: fs.statSync(path.join(outputDir, name)).mtimeMs }))
              .sort((a, b) => b.mtime - a.mtime)[0];
            resultsFile = path.join(outputDir, latest.name);
          }
        } catch (_) {}
      }
      if (fs.existsSync(resultsFile)) {
        const csvData = fs.readFileSync(resultsFile, 'utf8');
        results.csvData = csvData;
        results.files.results = resultsFile;
        try {
          const parsedCsv = this.parseResultsCsv(csvData);
          if (Array.isArray(parsedCsv) && parsedCsv.length > 0) {
            this.integrateCsvAnalysis(results.analysis, parsedCsv);
          }
        } catch (csvError) {
          Logger.warn('Failed to parse SQLMap CSV results', csvError?.message || csvError);
        }
      }

      // Find and catalog dump files
      const glob = require('glob');
      if (glob) {
        const dumpPattern = path.join(outputDir, '**/*.csv');
        const dumpFiles = glob.sync(dumpPattern);
        results.files.dumps = dumpFiles.map(file => ({
          path: file,
          name: path.basename(file),
          size: fs.statSync(file).size,
          modified: fs.statSync(file).mtime
        }));
      }

      // Parse target-specific output directory
      const targetDirs = fs.readdirSync(outputDir).filter(item => {
        const itemPath = path.join(outputDir, item);
        return fs.statSync(itemPath).isDirectory();
      });

      for (const targetDir of targetDirs) {
        const targetPath = path.join(outputDir, targetDir);
        const logFile = path.join(targetPath, 'log');
        
        if (fs.existsSync(logFile)) {
          try {
            const logContent = fs.readFileSync(logFile, 'utf8');
            const parsedLog = this.parseLogFile(logContent, sessionId);
            if (parsedLog?.findings?.length) {
              results.findings.push(...parsedLog.findings);
            }
            if (parsedLog?.analysis) {
              this.mergeAnalyses(results.analysis, parsedLog.analysis);
            }
          } catch (error) {
            Logger.error(`Error parsing log file: ${error.message}`);
          }
        }

        // Look for CSV dump files in target directory
        const csvFiles = fs.readdirSync(targetPath)
          .filter(file => file.endsWith('.csv'))
          .map(file => path.join(targetPath, file));
        
        results.files.dumps.push(...csvFiles.map(file => ({
          path: file,
          name: path.basename(file),
          size: fs.statSync(file).size,
          modified: fs.statSync(file).mtime
        })));
      }

    } catch (error) {
      Logger.error(`Error parsing SQLMap results: ${error.message}`);
    }

    try {
      this.finalizeAnalysis(results.analysis);
    } catch (analysisError) {
      Logger.warn('Failed to finalize SQLMap analysis', analysisError?.message || analysisError);
    }

    return results;
  }

  createEmptyAnalysis(sessionId = null) {
    const analysis = {
      sessionId,
      generatedAt: new Date().toISOString(),
      parameters: [],
      heuristics: {
        flaggedParameters: [],
        dismissedParameters: []
      },
      timeline: [],
      summary: {
        outcome: 'unknown',
        reason: null,
        rawVerdictLine: null,
        evidenceCount: 0
      },
      stats: {
        confirmed: 0,
        suspected: 0,
        dismissed: 0,
        totalTested: 0
      }
    };

    Object.defineProperty(analysis, '_paramIndex', {
      enumerable: false,
      configurable: true,
      value: new Map()
    });

    return analysis;
  }

  ensureParameterEntry(analysis, name = 'unknown', place = 'unknown') {
    const normalizedName = String(name || 'unknown').trim() || 'unknown';
    const normalizedPlace = this.normalizeParameterPlace(place);
    const key = `${normalizedPlace}::${normalizedName.toLowerCase()}`;
    const paramIndex = analysis?._paramIndex;

    if (!paramIndex.has(key)) {
      paramIndex.set(key, {
        name: normalizedName,
        place: normalizedPlace,
        finalStatus: 'unknown',
        statuses: [],
        techniques: [],
        payloads: [],
        confidence: null,
        heuristics: {
          flagged: false,
          dismissed: false
        },
        notes: []
      });
      analysis.parameters.push(paramIndex.get(key));
    } else {
      const existing = paramIndex.get(key);
      if (normalizedPlace !== 'unknown' && existing.place === 'unknown') {
        existing.place = normalizedPlace;
      }
      if (normalizedName !== 'unknown' && existing.name === 'unknown') {
        existing.name = normalizedName;
      }
    }

    return paramIndex.get(key);
  }

  addTimelineEvent(analysis, event) {
    if (!analysis || !event) return;
    const cloned = {
      ...event,
      at: event.at || null
    };
    analysis.timeline.push(cloned);
  }

  setParameterStatus(parameterEntry, status, detail, at, meta = {}) {
    if (!parameterEntry) return;
    const resolvedStatus = this.resolveStatus(parameterEntry.finalStatus, status);
    if (resolvedStatus !== parameterEntry.finalStatus) {
      parameterEntry.finalStatus = resolvedStatus;
    }
    parameterEntry.statuses.push({
      status,
      detail,
      at: at || null,
      ...meta
    });
  }

  addTechnique(parameterEntry, technique) {
    if (!parameterEntry || !technique) return;
    if (!parameterEntry.techniques.includes(technique)) {
      parameterEntry.techniques.push(technique);
    }
  }

  addPayload(parameterEntry, payload) {
    if (!parameterEntry || !payload) return;
    if (!parameterEntry.payloads.includes(payload)) {
      parameterEntry.payloads.push(payload);
    }
  }

  resolveStatus(existingStatus = 'unknown', incomingStatus = 'unknown') {
    const weight = {
      confirmed: 5,
      dismissed: 4,
      suspected: 3,
      testing: 2,
      unknown: 1
    };
    const currentWeight = weight[existingStatus] ?? 0;
    const incomingWeight = weight[incomingStatus] ?? 0;
    return incomingWeight >= currentWeight ? incomingStatus : existingStatus;
  }

  normalizeParameterPlace(place) {
    if (!place) return 'unknown';
    const value = String(place).trim().toUpperCase();
    if (['GET', 'POST', 'COOKIE', 'HEADER', 'URI', 'JSON'].includes(value)) {
      return value;
    }
    if (/GET/i.test(value)) return 'GET';
    if (/POST/i.test(value)) return 'POST';
    if (/COOKIE/i.test(value)) return 'COOKIE';
    if (/HEADER|HTTP header/i.test(value)) return 'HEADER';
    if (/URI|URL/i.test(value)) return 'URI';
    if (/JSON/i.test(value)) return 'JSON';
    return 'unknown';
  }

  normalizeLogLine(line = '') {
    if (!line) return '';
    let cleaned = line.replace(ANSI_ESCAPE_REGEX, '');
    cleaned = cleaned.replace(LEADING_DELIMITER_REGEX, '');
    cleaned = cleaned.replace(/^\[[0-9:\-.]+\]\s*\[[A-Z]+\]\s*/i, '');
    cleaned = cleaned.replace(/^\[[A-Z]+\]\s*/i, '');
    return cleaned.trim();
  }

  extractTimestampFromLogLine(line = '') {
    const match = line.match(/^\[([0-9]{2}:[0-9]{2}:[0-9]{2})\]/);
    if (match) {
      return match[1];
    }
    const isoMatch = line.match(/^\[([0-9]{4}-[0-9]{2}-[0-9]{2}T[^\]]+)\]/);
    return isoMatch ? isoMatch[1] : null;
  }

  inferPlaceFromLine(line = '') {
    const lowered = line.toLowerCase();
    if (lowered.includes('get parameter')) return 'GET';
    if (lowered.includes('post parameter')) return 'POST';
    if (lowered.includes('cookie')) return 'COOKIE';
    if (lowered.includes('header')) return 'HEADER';
    if (lowered.includes('uri parameter') || lowered.includes('url parameter')) return 'URI';
    if (lowered.includes('json parameter')) return 'JSON';
    return 'unknown';
  }

  parseLogFile(logContent, sessionId = null) {
    const findings = [];
    const analysis = this.createEmptyAnalysis(sessionId);

    const lines = logContent.split(/\r?\n/);
    let inSummarySection = false;
    let currentSummaryBlock = null;

    const flushSummaryBlock = () => {
      if (!currentSummaryBlock) return;
      const { parameterEntry, data } = currentSummaryBlock;
      const technique = data.technique || data.type || data.title;
      const techniqueName = this.mapSqlmapTechnique(technique || '');

      this.addTechnique(parameterEntry, techniqueName);
      if (data.payload) {
        this.addPayload(parameterEntry, data.payload);
      }

      const description = data.rawText || data.raw.join('\n');
      findings.push({
        type: 'vulnerability',
        parameter: parameterEntry.name,
        technique: techniqueName,
        severity: 'high',
        description: description?.trim() || techniqueName
      });

      this.setParameterStatus(parameterEntry, 'confirmed', description, data.at, {
        source: 'summary-block'
      });

      analysis.summary.outcome = this.resolveOutcome(analysis.summary.outcome, 'vulnerable');
      analysis.summary.reason = analysis.summary.reason || 'SQLMap identified injection point(s).';
      analysis.summary.rawVerdictLine = analysis.summary.rawVerdictLine || data.verdictLine || null;

      currentSummaryBlock = null;
    };

    for (const rawLine of lines) {
      if (!rawLine) continue;
      const normalized = this.normalizeLogLine(rawLine);
      if (!normalized) continue;

      const lower = normalized.toLowerCase();
      const at = this.extractTimestampFromLogLine(rawLine);

      if (!inSummarySection && /sqlmap\s+identified\s+the\s+following\s+injection\s+point/i.test(lower)) {
        inSummarySection = true;
        analysis.summary.outcome = this.resolveOutcome(analysis.summary.outcome, 'vulnerable');
        analysis.summary.rawVerdictLine = analysis.summary.rawVerdictLine || normalized;
        this.addTimelineEvent(analysis, {
          type: 'summary-start',
          detail: normalized,
          at
        });
        continue;
      }

      if (/all tested parameters do not appear to be injectable/i.test(lower) || /not.*injectable/i.test(lower) && lower.includes('all tested parameters')) {
        analysis.summary.outcome = this.resolveOutcome(analysis.summary.outcome, 'clean');
        analysis.summary.reason = normalized;
        this.addTimelineEvent(analysis, {
          type: 'summary-clean',
          detail: normalized,
          at
        });
      }

      if (/no injection point/i.test(lower) || /unable to find any vulnerabilities/i.test(lower)) {
        analysis.summary.outcome = this.resolveOutcome(analysis.summary.outcome, 'clean');
        analysis.summary.reason = analysis.summary.reason || normalized;
      }

      const testingMatch = normalized.match(/testing\s+(?:for\s+SQL injection\s+on\s+)?(?:GET|POST|COOKIE|URI|parameter)\s+['"]?([^'"\s]+)['"]?/i);
      if (testingMatch) {
        const name = testingMatch[1];
        const place = this.inferPlaceFromLine(normalized);
        const paramEntry = this.ensureParameterEntry(analysis, name, place);
        this.setParameterStatus(paramEntry, 'testing', normalized, at, { source: 'testing' });
        this.addTimelineEvent(analysis, {
          type: 'testing',
          parameter: paramEntry.name,
          place: paramEntry.place,
          detail: normalized,
          at
        });
      }

      const heuristicsSuspectMatch = normalized.match(/heuristic.*?parameter\s+['"`]?(.*?)['"`]?\s+(?:might|may)\s+be\s+injectable/i);
      if (heuristicsSuspectMatch) {
        const name = heuristicsSuspectMatch[1];
        const place = this.inferPlaceFromLine(normalized);
        const paramEntry = this.ensureParameterEntry(analysis, name, place);
        paramEntry.heuristics.flagged = true;
        this.setParameterStatus(paramEntry, 'suspected', normalized, at, {
          source: 'heuristic'
        });
        this.addTimelineEvent(analysis, {
          type: 'heuristic-suspect',
          parameter: paramEntry.name,
          place: paramEntry.place,
          detail: normalized,
          at
        });
      }

      const dismissMatch = normalized.match(/parameter\s+['"`]?(.*?)['"`]?\s+(?:does\s+not\s+seem|is\s+not|isn'?t)\s+(?:to\s+be\s+)?(?:injectable|vulnerable)/i);
      if (dismissMatch) {
        const name = dismissMatch[1];
        const place = this.inferPlaceFromLine(normalized);
        const paramEntry = this.ensureParameterEntry(analysis, name, place);
        paramEntry.heuristics.dismissed = true;
        this.setParameterStatus(paramEntry, 'dismissed', normalized, at, {
          source: 'heuristic-dismiss'
        });
        this.addTimelineEvent(analysis, {
          type: 'heuristic-dismiss',
          parameter: paramEntry.name,
          place: paramEntry.place,
          detail: normalized,
          at
        });
      }

      const vulnerableMatch = normalized.match(/(?:GET|POST|COOKIE|URI)?\s*parameter\s+['"`]?(.*?)['"`]?\s+(?:is|appears to be)\s+[\w\s-]*(?:injectable|vulnerable)/i);
      if (vulnerableMatch) {
        const name = vulnerableMatch[1];
        const place = this.inferPlaceFromLine(normalized);
        const paramEntry = this.ensureParameterEntry(analysis, name, place);
        this.setParameterStatus(paramEntry, 'confirmed', normalized, at, {
          source: 'inline-confirmation'
        });
        this.addTimelineEvent(analysis, {
          type: 'confirmed-inline',
          parameter: paramEntry.name,
          place: paramEntry.place,
          detail: normalized,
          at
        });
        const technique = normalized.replace(/.*?(?:is|appears to be)/i, '').replace(/injectable|vulnerable/i, '').trim();
        const techniqueName = this.mapSqlmapTechnique(technique);
        this.addTechnique(paramEntry, techniqueName);
        findings.push({
          type: 'vulnerability',
          parameter: paramEntry.name,
          technique: techniqueName,
          severity: 'high',
          description: normalized
        });
      }

      if (inSummarySection) {
        if (/^---+$/.test(normalized)) {
          flushSummaryBlock();
          continue;
        }

        if ((normalized.startsWith('*') || normalized.startsWith('[')) && !lower.startsWith('parameter:')) {
          flushSummaryBlock();
          inSummarySection = false;
        }

        if (normalized.toLowerCase().startsWith('parameter:')) {
          flushSummaryBlock();

          const paramMatch = normalized.match(/Parameter:\s*([^()]+?)(?:\(([^)]+)\))?$/);
          let name = null;
          let place = 'unknown';
          if (paramMatch) {
            name = (paramMatch[1] || '').trim();
            place = this.normalizeParameterPlace(paramMatch[2] || this.inferPlaceFromLine(normalized));
          }
          const paramEntry = this.ensureParameterEntry(analysis, name, place);
          currentSummaryBlock = {
            parameterEntry: paramEntry,
            data: {
              raw: [normalized],
              rawText: normalized,
              at,
              verdictLine: normalized
            }
          };
          this.setParameterStatus(paramEntry, 'confirmed', normalized, at, {
            source: 'summary-parameter'
          });
          this.addTimelineEvent(analysis, {
            type: 'summary-parameter',
            parameter: paramEntry.name,
            place: paramEntry.place,
            detail: normalized,
            at
          });
          continue;
        }

        if (currentSummaryBlock) {
          currentSummaryBlock.data.raw.push(normalized);
          currentSummaryBlock.data.rawText = (currentSummaryBlock.data.rawText || '') + '\n' + normalized;
          if (normalized.toLowerCase().startsWith('type:')) {
            currentSummaryBlock.data.type = normalized.replace(/^[Tt]ype:\s*/, '');
          } else if (normalized.toLowerCase().startsWith('title:')) {
            currentSummaryBlock.data.title = normalized.replace(/^[Tt]itle:\s*/, '');
          } else if (normalized.toLowerCase().startsWith('payload:')) {
            currentSummaryBlock.data.payload = normalized.replace(/^[Pp]ayload:\s*/, '');
          } else if (normalized.toLowerCase().startsWith('vector:')) {
            currentSummaryBlock.data.vector = normalized.replace(/^[Vv]ector:\s*/, '');
          }
        }
      }

      if (/current database:/i.test(normalized)) {
        findings.push({
          type: 'database_info',
          info: normalized.split(':')[1]?.trim(),
          severity: 'info'
        });
      }

      if (/back-end DBMS:/i.test(normalized)) {
        findings.push({
          type: 'version_info',
          dbms: normalized.split(':')[1]?.trim(),
          severity: 'info'
        });
      }
    }

    flushSummaryBlock();

    return { findings, analysis };
  }

  resolveOutcome(existing = 'unknown', incoming = 'unknown') {
    const priority = {
      vulnerable: 4,
      suspected: 3,
      clean: 2,
      error: 1,
      unknown: 0
    };
    const eWeight = priority[existing] ?? -1;
    const iWeight = priority[incoming] ?? -1;
    return iWeight > eWeight ? incoming : existing;
  }

  mapSqlmapTechnique(raw = '') {
    const text = String(raw || '').toLowerCase();
    if (text.includes('boolean')) return 'Boolean-based blind SQL injection';
    if (text.includes('time-based')) return 'Time-based blind SQL injection';
    if (text.includes('union')) return 'Union query SQL injection';
    if (text.includes('stacked')) return 'Stacked queries SQL injection';
    if (text.includes('error')) return 'Error-based SQL injection';
    if (text.includes('inline query')) return 'Inline query SQL injection';
    return raw ? raw.trim() : 'SQL injection';
  }

  mergeAnalyses(targetAnalysis, sourceAnalysis) {
    if (!targetAnalysis || !sourceAnalysis) return;
    const sourceIndex = sourceAnalysis._paramIndex || new Map();

    for (const param of sourceIndex.values()) {
      const existing = this.ensureParameterEntry(targetAnalysis, param.name, param.place);
      for (const status of param.statuses) {
        this.setParameterStatus(existing, status.status, status.detail, status.at, {
          source: status.source
        });
      }
      for (const note of param.notes || []) {
        if (!existing.notes.includes(note)) existing.notes.push(note);
      }
      param.techniques.forEach((tech) => this.addTechnique(existing, tech));
      param.payloads.forEach((payload) => this.addPayload(existing, payload));
      existing.heuristics.flagged = existing.heuristics.flagged || param.heuristics.flagged;
      existing.heuristics.dismissed = existing.heuristics.dismissed || param.heuristics.dismissed;
      if (param.confidence !== null && param.confidence !== undefined) {
        existing.confidence = Math.max(existing.confidence ?? 0, Number(param.confidence));
      }
      existing.finalStatus = this.resolveStatus(existing.finalStatus, param.finalStatus);
    }

    targetAnalysis.timeline.push(...(sourceAnalysis.timeline || []));
    targetAnalysis.summary.outcome = this.resolveOutcome(targetAnalysis.summary.outcome, sourceAnalysis.summary?.outcome || 'unknown');
    targetAnalysis.summary.reason = targetAnalysis.summary.reason || sourceAnalysis.summary?.reason || null;
    targetAnalysis.summary.rawVerdictLine = targetAnalysis.summary.rawVerdictLine || sourceAnalysis.summary?.rawVerdictLine || null;
    if (sourceAnalysis.summary?.evidenceCount) {
      targetAnalysis.summary.evidenceCount += sourceAnalysis.summary.evidenceCount;
    }
  }

  integrateCsvAnalysis(analysis, csvRecords = []) {
    if (!analysis || !Array.isArray(csvRecords)) return;

    for (const record of csvRecords) {
      const name = record.parameter || record.param || 'unknown';
      const place = record.place || record.method || 'unknown';
      const confidence = Number(record.confidence || record.conf || 0);
      const technique = record.title || record.type || record.technique || '';
      const payload = record.payload || record.vector || null;

      const paramEntry = this.ensureParameterEntry(analysis, name, place);
      this.setParameterStatus(paramEntry, 'confirmed', 'Confirmed via CSV artefact', null, {
        source: 'csv-results'
      });
      if (confidence && !Number.isNaN(confidence)) {
        paramEntry.confidence = Math.max(paramEntry.confidence ?? 0, confidence);
      }
      this.addTechnique(paramEntry, this.mapSqlmapTechnique(technique));
      if (payload) {
        this.addPayload(paramEntry, payload);
      }
      analysis.summary.outcome = this.resolveOutcome(analysis.summary.outcome, 'vulnerable');
      analysis.summary.evidenceCount += 1;
    }
  }

  parseResultsCsv(csvText = '') {
    if (!csvText) return [];
    const rows = csvText.split(/\r?\n/).filter(line => line.trim().length > 0);
    if (rows.length < 2) return [];

    const header = this.splitCsvRow(rows[0]).map((cell) => cell.toLowerCase());
    const records = [];

    for (let i = 1; i < rows.length; i++) {
      const cells = this.splitCsvRow(rows[i]);
      if (!cells.length) continue;
      const record = {};
      header.forEach((key, index) => {
        record[key] = cells[index] || '';
      });
      records.push(record);
    }

    return records;
  }

  splitCsvRow(row = '') {
    const result = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < row.length; i++) {
      const char = row[i];
      if (char === '"') {
        if (inQuotes && row[i + 1] === '"') {
          current += '"';
          i++;
        } else {
          inQuotes = !inQuotes;
        }
      } else if (char === ',' && !inQuotes) {
        result.push(current.trim());
        current = '';
      } else {
        current += char;
      }
    }

    result.push(current.trim());
    return result;
  }

  finalizeAnalysis(analysis) {
    if (!analysis) return;

    const paramIndex = analysis._paramIndex || new Map();
    const flagged = new Set();
    const dismissed = new Set();

    for (const param of paramIndex.values()) {
      if (param.heuristics.flagged) {
        flagged.add(`${param.place}:${param.name}`);
      }
      if (param.heuristics.dismissed || param.finalStatus === 'dismissed') {
        dismissed.add(`${param.place}:${param.name}`);
      }

      if (analysis.summary.outcome === 'clean' && param.heuristics.flagged && param.finalStatus !== 'confirmed') {
        const alreadyDismissed = param.statuses.some((status) => status.status === 'dismissed');
        if (!alreadyDismissed) {
          this.setParameterStatus(param, 'dismissed', 'Automatically dismissed after clean verdict', null, {
            source: 'auto-dismiss'
          });
        }
        param.finalStatus = this.resolveStatus(param.finalStatus, 'dismissed');
        param.heuristics.dismissed = true;
        dismissed.add(`${param.place}:${param.name}`);
      }
    }

    const parameters = Array.from(paramIndex.values());
    analysis.parameters = parameters;
    analysis.stats.confirmed = parameters.filter(p => p.finalStatus === 'confirmed').length;
    analysis.stats.dismissed = parameters.filter(p => p.finalStatus === 'dismissed').length;
    analysis.stats.suspected = parameters.filter(p => p.finalStatus === 'suspected').length;
    analysis.stats.totalTested = parameters.length;

    if (analysis.summary.outcome === 'unknown') {
      if (analysis.stats.confirmed > 0) {
        analysis.summary.outcome = 'vulnerable';
        analysis.summary.reason = analysis.summary.reason || 'Confirmed injection point(s) detected.';
      } else if (analysis.stats.suspected > 0) {
        analysis.summary.outcome = 'suspected';
        analysis.summary.reason = analysis.summary.reason || 'Heuristic signals detected without confirmation.';
      } else {
        analysis.summary.outcome = 'clean';
        analysis.summary.reason = analysis.summary.reason || 'No injection point confirmed.';
      }
    }

    analysis.heuristics.flaggedParameters = Array.from(flagged);
    analysis.heuristics.dismissedParameters = Array.from(dismissed);

    analysis.timeline.sort((a, b) => {
      if (!a?.at) return 1;
      if (!b?.at) return -1;
      return String(a.at).localeCompare(String(b.at));
    });

    delete analysis._paramIndex;
  }

  // Generate structured report from parsed results
  generateReport(results, format = 'json') {
    const report = {
      metadata: {
        sessionId: results.sessionId,
        timestamp: results.timestamp,
        tool: 'SQLMap',
        version: 'Latest'
      },
      summary: {
        vulnerabilitiesFound: results.findings.filter(f => f.type === 'vulnerability').length,
        databasesEnumerated: results.databases.length,
        tablesFound: results.tables.length,
        filesGenerated: Object.keys(results.files).length
      },
      findings: results.findings,
      files: results.files
    };

    switch (format.toLowerCase()) {
      case 'json':
        return JSON.stringify(report, null, 2);
      case 'csv':
        return this.generateCSVReport(report);
      case 'html':
        return this.generateHTMLReport(report);
      default:
        return JSON.stringify(report, null, 2);
    }
  }

  generateCSVReport(report) {
    const headers = ['Type', 'Parameter', 'Technique', 'Severity', 'Description'];
    const rows = [headers.join(',')];

    for (const finding of report.findings) {
      const row = [
        finding.type || '',
        finding.parameter || '',
        finding.technique || '',
        finding.severity || '',
        `"${(finding.description || '').replace(/"/g, '""')}"` // Escape quotes
      ];
      rows.push(row.join(','));
    }

    return rows.join('\n');
  }

  generateHTMLReport(report) {
    return `
<!DOCTYPE html>
<html>
<head>
    <title>SQLMap Security Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f4f4f4; padding: 20px; border-radius: 5px; }
        .summary { margin: 20px 0; }
        .finding { border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }
        .vulnerability { border-left: 5px solid #d32f2f; }
        .info { border-left: 5px solid #1976d2; }
        .severity-high { color: #d32f2f; font-weight: bold; }
        .severity-info { color: #1976d2; }
    </style>
</head>
<body>
    <div class="header">
        <h1>SQLMap Security Assessment Report</h1>
        <p><strong>Session ID:</strong> ${report.metadata.sessionId}</p>
        <p><strong>Generated:</strong> ${new Date(report.metadata.timestamp).toLocaleString()}</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <ul>
            <li>Vulnerabilities Found: ${report.summary.vulnerabilitiesFound}</li>
            <li>Databases Enumerated: ${report.summary.databasesEnumerated}</li>
            <li>Tables Found: ${report.summary.tablesFound}</li>
        </ul>
    </div>
    
    <div class="findings">
        <h2>Detailed Findings</h2>
        ${report.findings.map(finding => `
            <div class="finding ${finding.type}">
                <h3 class="severity-${finding.severity}">${finding.type.toUpperCase()}: ${finding.parameter || 'N/A'}</h3>
                <p><strong>Technique:</strong> ${finding.technique || 'N/A'}</p>
                <p><strong>Severity:</strong> <span class="severity-${finding.severity}">${finding.severity}</span></p>
                <p><strong>Description:</strong> ${finding.description || 'No description available'}</p>
            </div>
        `).join('')}
    </div>
</body>
</html>`;
  }

  async executeCommand(command, args = []) {
    // Whitelist of allowed commands
    const allowedCommands = [
      'sqlmap-help',
      'sqlmap-version',
      'list-profiles',
      'validate-target'
    ];

    if (!allowedCommands.includes(command)) {
      throw new Error(`Command not allowed: ${command}`);
    }

    switch (command) {
      case 'sqlmap-help':
        return this.getSQLMapHelp();
      
      case 'sqlmap-version':
        return this.getSQLMapVersion();
      
      case 'list-profiles':
        return this.listScanProfiles();
      
      case 'validate-target':
        if (!args[0]) {
          throw new Error('Target URL required');
        }
        return this.validateTargetCommand(args[0]);
      
      default:
        throw new Error(`Unknown command: ${command}`);
    }
  }

  async getSQLMapHelp() {
    return new Promise((resolve, reject) => {
      const helpProcess = spawn(this.sqlmapPath, ['--help'], { stdio: 'pipe', windowsHide: true });
      let output = '';

      helpProcess.stdout.on('data', (data) => {
        output += data.toString();
      });

      helpProcess.on('close', (code) => {
        if (code === 0) {
          resolve({ output, type: 'help' });
        } else {
          reject(new Error('Failed to get SQLMap help'));
        }
      });

      helpProcess.on('error', (error) => {
        reject(error);
      });
    });
  }

  async getSQLMapVersion() {
    return new Promise((resolve, reject) => {
      const versionProcess = spawn(this.sqlmapPath, ['--version'], { stdio: 'pipe', windowsHide: true });
      let output = '';

      versionProcess.stdout.on('data', (data) => {
        output += data.toString();
      });

      versionProcess.on('close', (code) => {
        if (code === 0) {
          resolve({ output, type: 'version' });
        } else {
          reject(new Error('Failed to get SQLMap version'));
        }
      });

      versionProcess.on('error', (error) => {
        reject(error);
      });
    });
  }

  listScanProfiles() {
    const profiles = Object.entries(this.scanProfiles).map(([key, profile]) => ({
      id: key,
      name: profile.name,
      description: profile.description,
      flags: profile.flags
    }));

    return { output: JSON.stringify(profiles, null, 2), type: 'profiles' };
  }

  validateTargetCommand(target) {
    try {
      this.validateTarget(target);
      return { output: `Target URL is valid: ${target}`, type: 'validation' };
    } catch (error) {
      return { output: `Target URL validation failed: ${error.message}`, type: 'validation-error' };
    }
  }

  terminateProcess(processId) {
    const processInfo = this.runningProcesses.get(processId);
    if (processInfo) {
      try {
        const pid = processInfo.process?.pid;
        if (pid) {
          killTree(pid, 'SIGTERM');
        } else {
          processInfo.process.kill('SIGTERM');
        }
      } catch (_) {}
      this.runningProcesses.delete(processId);
      return true;
    }
    return false;
  }

  getRunningProcesses() {
    const processes = [];
    for (const [id, info] of this.runningProcesses.entries()) {
      processes.push({
        id,
        target: info.target,
        scanProfile: info.scanProfile,
        startTime: info.startTime,
        pid: info.process.pid
      });
    }
    return processes;
  }

  cleanupTempFiles(outputDir) {
    try {
      if (fs.existsSync(outputDir)) {
        fs.rmSync(outputDir, { recursive: true, force: true });
        Logger.info(`Cleaned up temp directory: ${outputDir}`);
      }
    } catch (error) {
      Logger.error(`Error cleaning up temp files: ${error.message}`);
    }
  }

  // Clean up all temp files and processes on shutdown
  cleanup() {
    Logger.info('Cleaning up SQLMap integration...');
    
    // Terminate all running processes
    for (const [id, info] of this.runningProcesses.entries()) {
      try {
        const pid = info.process?.pid;
        if (pid) {
          try { killTree(pid, 'SIGTERM'); } catch (_) {}
        } else {
          info.process?.kill?.('SIGTERM');
        }
        this.cleanupTempFiles(info.outputDir);
      } catch (error) {
        Logger.error(`Error terminating process ${id}: ${error.message}`);
      }
    }
    
    this.runningProcesses.clear();
    
    // Clean up temp directory
    try {
      if (fs.existsSync(this.tempDir)) {
        fs.rmSync(this.tempDir, { recursive: true, force: true });
      }
    } catch (error) {
      Logger.error(`Error cleaning up temp directory: ${error.message}`);
    }
  }
}

module.exports = SQLMapIntegration; 