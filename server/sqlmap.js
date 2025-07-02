const { spawn, execSync } = require('child_process');
const path = require('path');
const fs = require('fs');
const os = require('os');
const { v4: uuidv4 } = require('uuid');
const Logger = require('./utils/logger');

class SQLMapIntegration {
  constructor() {
    this.sqlmapPath = this.findSQLMapPath();
    this.tempDir = path.join(os.tmpdir(), 'cybersec-sqlmap');
    this.runningProcesses = new Map();
    
    // Ensure temp directory exists
    if (!fs.existsSync(this.tempDir)) {
      fs.mkdirSync(this.tempDir, { recursive: true });
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

  buildSQLMapCommand(target, options = {}, scanProfile = 'basic') {
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
      const customFlags = this.parseCustomFlags(options.customFlags);
      command.push(...customFlags);
    }

    // Add output directory
    const outputDir = path.join(this.tempDir, uuidv4());
    fs.mkdirSync(outputDir, { recursive: true });
    command.push('--output-dir', outputDir);

    return { command, outputDir };
  }

  parseCustomFlags(customFlags) {
    if (typeof customFlags !== 'string') {
      return [];
    }

    // Split flags and validate
    const flags = customFlags.split(' ').filter(flag => flag.trim());
    const validatedFlags = [];
    
    // Whitelist of allowed flags
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

    for (let i = 0; i < flags.length; i++) {
      const flag = flags[i];
      
      if (flag.startsWith('--')) {
        const flagName = flag.split('=')[0];
        if (allowedFlags.includes(flagName)) {
          validatedFlags.push(flag);
          
          // Check if next item is a value for this flag
          if (i + 1 < flags.length && !flags[i + 1].startsWith('--')) {
            validatedFlags.push(flags[i + 1]);
            i++; // Skip next iteration as we've processed the value
          }
        } else {
          Logger.warn(`Skipping disallowed flag: ${flag}`);
        }
      }
    }

    return validatedFlags;
  }

  async startScan(target, options = {}, scanProfile = 'basic') {
    const sessionId = uuidv4();
    // Use system temp directory to avoid issues with spaces in project path
    const outputDir = path.join(os.tmpdir(), 'cybersec-sqlmap', sessionId);
    
    // Ensure output directory exists
    if (!fs.existsSync(outputDir)) {
      fs.mkdirSync(outputDir, { recursive: true });
    }

    // Get profile flags (now includes enhanced defaults)
    const profile = this.scanProfiles[scanProfile] || this.scanProfiles.basic;
    
    const defaultFlags = [
      '--batch',        // Never ask for user input
      '--random-agent', // Use a random user-agent
      '--output-dir', `"${outputDir}"`,  // Quote the path for Windows compatibility
      '-s', `"${path.join(outputDir, 'session.sqlite')}"`,  // Session file for resuming
      '-t', `"${path.join(outputDir, 'traffic.log')}"`,     // HTTP traffic log
      '--hex',          // Use hex conversion for data retrieval
      '--flush-session', // Flush session files for fresh start
      '--delay=1',      // Reduced delay for faster scans
      '--timeout=30',   // Timeout for requests
      '--retries=3',    // Retry failed requests 3 times
      '--keep-alive',   // Use persistent connections
      '--threads=1',    // Conservative threading for stability
      '--user-agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"',  // Updated user-agent
      '--skip-heuristics', // Skip heuristic checks for faster results
      '--banner',       // Try to retrieve DBMS banner
      '--current-user', // Get current database user
      '--current-db',   // Get current database name
      '--hostname',     // Get database server hostname
      '--is-dba',       // Check if current user is DBA
      '--passwords',    // Enumerate password hashes
      '--privileges',   // Enumerate user privileges
      '--roles',        // Enumerate user roles
      '--schema',       // Enumerate database schema
      '--count',        // Count entries in tables
      '--fresh-queries' // Ignore query results stored in session
    ];
    
    // Merge profile flags with any custom options
    const profileFlags = profile.flags || [];
    const customFlags = options.customFlags ? this.parseCustomFlags(options.customFlags) : [];

    const args = [
      '-u', target,
      ...defaultFlags,
      ...profileFlags,
      ...customFlags
    ];

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

    return childProcess;
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

      // Parse CSV results file
      const resultsFile = path.join(outputDir, 'results.csv');
      if (fs.existsSync(resultsFile)) {
        const csvData = fs.readFileSync(resultsFile, 'utf8');
        results.csvData = csvData;
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
            // Parse SQLMap log for findings
            const findings = this.parseLogFile(logContent);
            results.findings.push(...findings);
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

    return results;
  }

  parseLogFile(logContent) {
    const findings = [];
    const lines = logContent.split('\n');

    for (const line of lines) {
      // Parse vulnerability findings
      if (line.includes('Parameter:') && line.includes('is vulnerable')) {
        findings.push({
          type: 'vulnerability',
          parameter: this.extractParameter(line),
          technique: this.extractTechnique(line),
          severity: 'high',
          description: line.trim()
        });
      }

      // Parse database information
      if (line.includes('current database:')) {
        findings.push({
          type: 'database_info',
          info: line.split(':')[1]?.trim(),
          severity: 'info'
        });
      }

      // Parse version information
      if (line.includes('back-end DBMS:')) {
        findings.push({
          type: 'version_info',
          dbms: line.split(':')[1]?.trim(),
          severity: 'info'
        });
      }
    }

    return findings;
  }

  extractParameter(line) {
    const match = line.match(/Parameter:\s*([^\s]+)/);
    return match ? match[1] : null;
  }

  extractTechnique(line) {
    const techniques = ['boolean-based', 'error-based', 'time-based', 'union query', 'stacked queries'];
    for (const technique of techniques) {
      if (line.toLowerCase().includes(technique)) {
        return technique;
      }
    }
    return 'unknown';
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
      processInfo.process.kill('SIGTERM');
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
        info.process.kill('SIGTERM');
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