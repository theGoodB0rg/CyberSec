const { v4: uuidv4 } = require('uuid');
const puppeteer = require('puppeteer');
const Logger = require('./utils/logger');

class ReportGenerator {
  constructor(database) {
    this.database = database;
    this.vulnerabilityDatabase = this.initializeVulnerabilityDatabase();
    this.pdfGenerationQueue = [];
    this.isGeneratingPdf = false;
    this.puppeteerChecked = false;
    const disableValidation = ['true','1','yes','on'].includes(String(process.env.DISABLE_PUPPETEER_VALIDATION).toLowerCase());
    if (disableValidation) {
      Logger.info('Puppeteer setup validation disabled via DISABLE_PUPPETEER_VALIDATION');
      this.puppeteerChecked = true;
    } else {
      this.validatePuppeteerSetup();
    }
  }

  stripSqlmapLogPrefixes(output = '') {
    if (!output) return '';
    const prefixPatterns = [
      /^\[[0-9]{4}-[0-9]{2}-[0-9]{2}T[^\]]+\]\s*\[(?:stdout|stderr)\]\s*/i,
      /^\[[0-9]{2}:[0-9]{2}:[0-9]{2}\]\s*\[[A-Z]+\]\s*/,
      /^\[[A-Z]+\]\s*/
    ];

    return output
      .split(/\r?\n/)
      .map((line) => {
        let cleaned = line;
        for (const pattern of prefixPatterns) {
          if (pattern.test(cleaned)) {
            cleaned = cleaned.replace(pattern, '');
            break;
          }
        }
        return cleaned;
      })
      .join('\n');
  }

  mapSqlmapTechnique(raw) {
    const text = (raw || '').toLowerCase();
    if (text.includes('boolean')) return 'Boolean-based blind SQL injection';
    if (text.includes('time-based')) return 'Time-based blind SQL injection';
    if (text.includes('union')) return 'Union query SQL injection';
    if (text.includes('stacked')) return 'Stacked queries';
    if (text.includes('error')) return 'Error-based SQL injection';
    return 'SQL Injection';
  }

  parseSqlmapSummary(rawOutput = '') {
    const summary = {
      confirmed: [],
      attempted: [],
      verdictLine: null,
      rawSection: null
    };

    if (!rawOutput) {
      return summary;
    }

    const cleanedOutput = this.stripSqlmapLogPrefixes(rawOutput);
    const lines = cleanedOutput.split(/\r?\n/);

    let inSummary = false;
    let current = null;
    const sectionLines = [];

    const flushCurrent = () => {
      if (!current) return;
      current.raw = current.raw || [];
      current.rawText = current.raw.join('\n');
      current.method = (current.place || current.method || '').toUpperCase() || undefined;
      current.parameter = current.parameter?.trim() || undefined;
      current.title = current.title?.trim() || undefined;
      current.type = current.type?.trim() || undefined;
      current.payload = current.payload?.trim() || undefined;
      current.techniqueName = this.mapSqlmapTechnique(current.type || current.title || '');
      summary.confirmed.push(current);
      current = null;
    };

    for (const rawLine of lines) {
      const line = rawLine;
      const trimmed = line.trim();

      if (!inSummary && trimmed.toLowerCase().includes('sqlmap identified the following injection point')) {
        inSummary = true;
        summary.verdictLine = trimmed;
        continue;
      }

      if (!inSummary) {
        const attemptMatch = trimmed.match(/testing\s+'([^']+)'/i);
        if (attemptMatch) {
          summary.attempted.push({ technique: attemptMatch[1], line: trimmed });
        }
        continue;
      }

      sectionLines.push(line);

      if (trimmed.startsWith('[*] ending') || trimmed.startsWith('[1] ending') || trimmed.startsWith('\x1b') || trimmed.startsWith('[INFO]')) {
        // summary section is complete
        break;
      }

      if (trimmed === '' || /^\*+$/.test(trimmed)) {
        continue;
      }

      if (trimmed.startsWith('---')) {
        flushCurrent();
        continue;
      }

      if (trimmed.toLowerCase().startsWith('parameter:')) {
        flushCurrent();
  const paramMatch = trimmed.match(/Parameter:\s*([^(]+)(?:\(([^)]+)\))?$/i);
        let parameter = null;
        let place = null;
        if (paramMatch) {
          parameter = (paramMatch[1] || '').trim();
          place = (paramMatch[2] || '').trim();
        } else {
          parameter = trimmed.replace(/^Parameter:/i, '').trim();
        }
        current = {
          parameter,
          place,
          method: place,
          raw: [line]
        };
        continue;
      }

      if (!current) {
        continue;
      }

      current.raw.push(line);

      if (trimmed.toLowerCase().startsWith('type:')) {
        current.type = trimmed.replace(/^[Tt]ype:\s*/, '');
      } else if (trimmed.toLowerCase().startsWith('title:')) {
        current.title = trimmed.replace(/^[Tt]itle:\s*/, '');
      } else if (trimmed.toLowerCase().startsWith('payload:')) {
        current.payload = trimmed.replace(/^[Pp]ayload:\s*/, '');
      } else if (trimmed.toLowerCase().startsWith('vector:')) {
        current.vector = trimmed.replace(/^[Vv]ector:\s*/, '');
      }
    }

    flushCurrent();

    if (sectionLines.length > 0) {
      summary.rawSection = sectionLines.join('\n').trim();
    }

    if (!summary.verdictLine) {
      // Look for alternative verdict cues when no injection was found
      const altVerdict = lines.find((line) => /all tested parameters|no injection point|not injectable/i.test(line));
      if (altVerdict) {
        summary.verdictLine = altVerdict.trim();
      }
    }

    return summary;
  }

  parseSqlmapArtifacts(rawOutput = '') {
    const artifacts = {
      dbms: [],
      banners: [],
      currentUser: null,
      currentDatabase: null,
      hostname: null,
      isDba: null,
      webTechnology: [],
      webServerOs: null,
      os: null
    };

    if (!rawOutput) {
      return artifacts;
    }

    const cleaned = this.stripSqlmapLogPrefixes(rawOutput);

    const pushUnique = (arr, value) => {
      if (!value) return;
      if (!arr.includes(value)) arr.push(value);
    };

    const dbmsMatch = cleaned.match(/back-?end\s+DBMS:?\s*([^\n]+)/i);
    if (dbmsMatch) {
      pushUnique(artifacts.dbms, dbmsMatch[1].trim());
    }

    const bannerMatches = cleaned.match(/banner:\s*'([^']+)'/gi) || [];
    for (const match of bannerMatches) {
      const value = match.replace(/banner:\s*/i, '').replace(/'/g, '').trim();
      pushUnique(artifacts.banners, value);
    }

    const currentDbMatch = cleaned.match(/current database:\s*'([^']+)'/i);
    if (currentDbMatch) {
      artifacts.currentDatabase = currentDbMatch[1];
    }

    const currentUserMatch = cleaned.match(/current user:\s*'([^']+)'/i);
    if (currentUserMatch) {
      artifacts.currentUser = currentUserMatch[1];
    }

    const hostnameMatch = cleaned.match(/server hostname:\s*'([^']+)'/i);
    if (hostnameMatch) {
      artifacts.hostname = hostnameMatch[1];
    }

    const webTechMatch = cleaned.match(/web application technology:\s*([^\n]+)/i);
    if (webTechMatch) {
      webTechMatch[1]
        .split(/,\s*/)
        .map((item) => item.trim())
        .filter(Boolean)
        .forEach((item) => pushUnique(artifacts.webTechnology, item));
    }

    const webServerOsMatch = cleaned.match(/web server operating system:\s*([^\n]+)/i);
    if (webServerOsMatch) {
      artifacts.webServerOs = webServerOsMatch[1].trim();
    }

    const dbmsOsMatch = cleaned.match(/back-end DBMS operating system:\s*([^\n]+)/i);
    if (dbmsOsMatch) {
      artifacts.os = dbmsOsMatch[1].trim();
    }

    const isDbaMatch = cleaned.match(/current user is DBA:\s*(yes|no)/i);
    if (isDbaMatch) {
      artifacts.isDba = isDbaMatch[1].toLowerCase() === 'yes';
    }

    return artifacts;
  }

  splitCsvLine(line = '') {
    const result = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
      const char = line[i];
      if (char === '"') {
        if (inQuotes && line[i + 1] === '"') {
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

  parseSqlmapCsv(csvText = '') {
    if (!csvText) return [];
    const rows = csvText.split(/\r?\n/).filter((line) => line.trim().length > 0);
    if (rows.length < 2) return [];

    const header = this.splitCsvLine(rows[0]).map((h) => h.toLowerCase());
    const records = [];

    for (let i = 1; i < rows.length; i++) {
      const cells = this.splitCsvLine(rows[i]);
      if (cells.length === 0 || cells.every((cell) => !cell.trim())) continue;
      const record = {};
      header.forEach((key, index) => {
        record[key] = cells[index] ? cells[index].trim() : '';
      });
      records.push(record);
    }

    return records;
  }

  async validatePuppeteerSetup() {
    if (this.puppeteerChecked) return;
    
    try {
      Logger.info('Validating Puppeteer setup...');
      
      // Check if Puppeteer is available
      if (!puppeteer) {
        throw new Error('Puppeteer is not available');
      }
      
      // Log Puppeteer version for debugging
      const puppeteerVersion = require('puppeteer/package.json').version;
      Logger.info(`Puppeteer version: ${puppeteerVersion}`);
      
      // Test browser launch capability
      let testBrowser = null;
      try {
        testBrowser = await puppeteer.launch({
          headless: true,
          args: ['--no-sandbox', '--disable-setuid-sandbox'],
          timeout: 10000
        });
        
        const testPage = await testBrowser.newPage();
        await testPage.close();
        await testBrowser.close();
        
        Logger.info('Puppeteer setup validation successful');
        this.puppeteerChecked = true;
      } catch (testError) {
        if (testBrowser) {
          try {
            await testBrowser.close();
          } catch (closeError) {
            Logger.warn('Error closing test browser:', closeError.message);
          }
        }
        Logger.error('Puppeteer test launch failed:', testError.message);
        Logger.warn('PDF generation may not work correctly');
      }
    } catch (error) {
      Logger.error('Puppeteer validation failed:', error.message);
      Logger.warn('PDF generation will be disabled');
    }
  }

  initializeVulnerabilityDatabase() {
    return {
      'SQL Injection': {
        severity: 'High',
        cvss: 8.1,
        description: 'SQL injection vulnerabilities allow attackers to manipulate database queries',
        impact: 'Data breach, unauthorized access, data manipulation',
        remediation: [
          'Use parameterized queries/prepared statements',
          'Implement input validation and sanitization',
          'Apply principle of least privilege for database accounts'
        ]
      },
      'Boolean-based blind SQL injection': {
        severity: 'High',
        cvss: 7.5,
        description: 'Boolean-based blind SQL injection allows data extraction through true/false responses',
        impact: 'Data enumeration, database structure discovery',
        remediation: [
          'Implement parameterized queries',
          'Use input validation and whitelist filtering',
          'Disable detailed error messages in production'
        ]
      },
      'Time-based blind SQL injection': {
        severity: 'High',
        cvss: 7.2,
        description: 'Time-based blind SQL injection exploits database response delays',
        impact: 'Data extraction, database enumeration',
        remediation: [
          'Use parameterized queries exclusively',
          'Implement query timeout controls',
          'Monitor and alert on unusual query patterns'
        ]
      },
      'Error-based SQL injection': {
        severity: 'High',
        cvss: 8.3,
        description: 'Error-based SQL injection leverages database error messages to extract data and metadata',
        impact: 'DBMS/version disclosure, schema enumeration via errors, potential data exfiltration through functions like EXTRACTVALUE/UPDATEXML (MySQL) or convert/error casting (other DBMS)',
        remediation: [
          'Use parameterized queries and stored procedures where appropriate',
          'Disable verbose error messages and avoid echoing DB errors to clients',
          'Implement centralized error handling and generic error responses',
          'Apply least privilege to DB users to limit metadata exposure'
        ]
      },
      'Union query SQL injection': {
        severity: 'High',
        cvss: 7.8,
        description: 'Union-based SQL injection appends UNION SELECT to extract arbitrary rows/columns',
        impact: 'Arbitrary data extraction across tables, potential credential disclosure if UNION aligns column counts/types',
        remediation: [
          'Always use parameterized queries and avoid dynamic column concatenation',
          'Validate and whitelist expected columns and sort/order parameters',
          'Restrict DB account permissions to the minimum required'
        ]
      },
      'Stacked queries': {
        severity: 'Critical',
        cvss: 8.8,
        description: 'Stacked (batched) queries allow execution of multiple statements in one request',
        impact: 'Data tampering (INSERT/UPDATE/DELETE), schema changes (DROP/ALTER), potential file read/write or command execution depending on DBMS configuration',
        remediation: [
          'Disable multiple statements in DB drivers if supported (e.g., disallow multiStatements)',
          'Use parameterized queries; never concatenate untrusted input into SQL',
          'Ensure DB user has no DDL privileges and minimal DML privileges',
          'Harden DBMS (e.g., restrict FILE/XP_CMDSHELL features, sandbox external procedures)'
        ]
      }
    };
  }

  getSeverityCriteriaOverview() {
    const criteria = {
      critical: {
        label: 'Critical',
        summary: 'Stacked (multi-statement) SQL injection confirmed.',
        detail: 'SQLMap proved the ability to append multiple SQL statements in a single request (e.g., statement terminators followed by INSERT/UPDATE/DELETE or DDL). Attackers can tamper with data, modify schema, or potentially reach file/command execution depending on DBMS privileges.',
        techniques: [],
        impacts: [
          'Data tampering and destructive writes',
          'Schema changes such as DROP/ALTER',
          'Opportunity for file read/write or OS command execution'
        ]
      },
      high: {
        label: 'High',
        summary: 'Single-statement SQL injection confirmed with data access.',
        detail: 'SQLMap demonstrated control of a query that leaks data or metadata through boolean/time-based, error-based, union-based, or classic payloads. Attackers can read sensitive information and pivot into additional manual exploitation.',
        techniques: [],
        impacts: [
          'Data disclosure and credential theft',
          'Authentication bypass or privilege abuse',
          'Database enumeration for follow-on attacks'
        ]
      }
    };

    for (const [technique, info] of Object.entries(this.vulnerabilityDatabase || {})) {
      const severity = ((info && info.severity) || '').toLowerCase();
      if (!severity) continue;
      const key = severity;
      if (!criteria[key]) {
        criteria[key] = {
          label: severity.charAt(0).toUpperCase() + severity.slice(1),
          summary: '',
          detail: '',
          techniques: [],
          impacts: []
        };
      }
      criteria[key].techniques.push(technique);
    }

    return criteria;
  }

  async generateReport(scanId, scanData, sqlmapResults = null) {
    try {
      Logger.info(`Generating report for scan: ${scanId}`);

      const reportId = uuidv4();
      const vulnerabilityAnalysis = await this.analyzeVulnerabilities(scanData, sqlmapResults);
      const extractedData = await this.analyzeExtractedData(scanData, sqlmapResults);
      const reportData = {
        id: reportId,
        scanId: scanId,
        title: this.generateReportTitle(scanData),
        target: scanData.target,
        command: this.reconstructCommand(scanData),
        vulnerabilities: vulnerabilityAnalysis,
        extractedData,
        recommendations: await this.generateRecommendations(scanData),
        scanDuration: this.calculateScanDuration(scanData),
        status: scanData.status,
        metadata: {
          generatedAt: new Date().toISOString(),
          scanProfile: scanData.scan_profile,
          reportVersion: '1.0',
          scanner: 'SQLMap Integration'
        }
      };

      try {
        const overallVerdict = this.determineOverallVerdict(reportData.vulnerabilities, reportData.extractedData);
        reportData.metadata = {
          ...reportData.metadata,
          overallVerdict,
          affectedParameters: overallVerdict?.affectedParameters || [],
          sqlmapSummary: vulnerabilityAnalysis?.sqlmapSummary,
          severityCriteria: this.getSeverityCriteriaOverview()
        };
      } catch (e) {
        Logger.warn('Unable to compute overall verdict for metadata', e?.message);
      }

      // If we have structured SQLMap results, merge them
      if (sqlmapResults) {
        reportData.sqlmapResults = sqlmapResults;
        reportData.structuredFindings = sqlmapResults.findings;
        reportData.outputFiles = sqlmapResults.files;
      }

      return reportData;
    } catch (error) {
      Logger.error('Error generating report:', error);
      throw error;
    }
  }

  generateReportTitle(scanData) {
    const timestamp = new Date().toISOString().split('T')[0];
    const domain = this.extractDomain(scanData.target);
    const profile = scanData.scan_profile || 'basic';
    
    return `SQL Injection Security Assessment - ${domain} (${profile}) - ${timestamp}`;
  }

  extractDomain(url) {
    try {
      const parsedUrl = new URL(url);
      return parsedUrl.hostname;
    } catch (error) {
      return 'unknown-target';
    }
  }

  reconstructCommand(scanData) {
    const parts = ['sqlmap'];
    parts.push('-u', scanData.target);
    
    if (scanData.options) {
      const options = typeof scanData.options === 'string' 
        ? JSON.parse(scanData.options) 
        : scanData.options;
      
      for (const [key, value] of Object.entries(options)) {
        if (key === 'customFlags') continue;
        if (value === undefined || value === null) continue;
        // Booleans: include flag only when true (no explicit value)
        if (typeof value === 'boolean') {
          if (value) parts.push(`--${key}`);
          continue;
        }
        // Objects/arrays: stringify for visibility
        const formatted = typeof value === 'object' ? JSON.stringify(value) : String(value);
        parts.push(`--${key}`, formatted);
      }
    }
    
    return parts.join(' ');
  }

  async analyzeVulnerabilities(scanData, sqlmapResults = null) {
    const vulnerabilities = [];
    const output = scanData.output || '';
    const summary = this.parseSqlmapSummary(output);

    const makeKey = (type, parameter, method) => {
      return [type || '', parameter || '', method || '']
        .map((part) => part.toString().toLowerCase())
        .join('|');
    };
    const registeredKeys = new Set();
    const registerKey = (type, parameter, method) => {
      registeredKeys.add(makeKey(type, parameter, method));
    };
    const hasKey = (type, parameter, method) => registeredKeys.has(makeKey(type, parameter, method));

    const parseParamMethod = (text) => {
      if (!text) return null;
      let match = text.match(/Parameter:\s*([^\s(]+)\s*\((GET|POST|PUT|DELETE)\)/i);
      if (match) {
        return { name: match[1], method: match[2].toUpperCase() };
      }
      match = text.match(/(GET|POST|PUT|DELETE)\s+parameter\s+['"`]([^'"`\s]+)['"`]/i);
      if (match) {
        return { name: match[2], method: match[1].toUpperCase() };
      }
      match = text.match(/parameter\s+['"`]([^'"`\s]+)['"`]\s+(?:is|appears|might)\s+[^\n]*?(?:injectable|vulnerable)/i);
      if (match) {
        return { name: match[1] };
      }
      return null;
    };

    const applyEvidenceContext = (vuln) => {
      if (!vuln) return;
      const evidenceTexts = Array.isArray(vuln.evidence)
        ? vuln.evidence.map(ev => ev?.content || '')
        : [];
      if (vuln.description) evidenceTexts.push(vuln.description);
      evidenceTexts.push(vuln.why || '');

      let resolved = null;
      for (const text of evidenceTexts) {
        const info = parseParamMethod(text);
        if (info) {
          resolved = info;
          if (info.method) break; // Prefer line that includes method
        }
      }

      if (resolved) {
        if (resolved.name) {
          vuln.parameter = resolved.name;
        }
        if (resolved.method) {
          vuln.httpMethod = resolved.method;
        }
      }
    };
    const normalizeConfidence = (vuln) => {
      if (typeof vuln.confidenceScore === 'number' && (vuln.confidenceScore < 0 || vuln.confidenceScore > 1)) {
        vuln.confidenceScore = Math.max(0, Math.min(1, vuln.confidenceScore));
      }
      if (!vuln.confidenceLabel) {
        const score = typeof vuln.confidenceScore === 'number' ? vuln.confidenceScore : null;
        if (score != null) {
          if (score >= 0.85) vuln.confidenceLabel = 'Confirmed';
          else if (score >= 0.6) vuln.confidenceLabel = 'Likely';
          else if (score >= 0.4) vuln.confidenceLabel = 'Suspected';
          else vuln.confidenceLabel = 'Tested';
        }
      }
      if (!vuln.confidenceScore && vuln.confidenceLabel) {
        const label = vuln.confidenceLabel.toLowerCase();
        if (label === 'confirmed') vuln.confidenceScore = 0.9;
        else if (label === 'likely') vuln.confidenceScore = 0.65;
        else if (label === 'suspected') vuln.confidenceScore = 0.4;
        else if (label === 'tested') vuln.confidenceScore = 0.2;
      }
    };
    const deriveStatus = (vuln) => {
      if (typeof vuln.status === 'string' && vuln.status.trim().length > 0) {
        return vuln.status;
      }
      const label = (vuln.confidenceLabel || '').toLowerCase();
      if (label === 'confirmed') return 'confirmed';
      if (label === 'likely' || label === 'suspected') return 'suspected';
      if (Array.isArray(vuln.signals) && vuln.signals.includes('explicit-tool-output')) return 'confirmed';
      if (typeof vuln.confidenceScore === 'number' && vuln.confidenceScore >= 0.85) return 'confirmed';
      if (typeof vuln.confidenceScore === 'number' && vuln.confidenceScore >= 0.4) return 'suspected';
      return 'tested';
    };

    let csvRecords = [];
    if (sqlmapResults?.csvData) {
      try {
        csvRecords = this.parseSqlmapCsv(sqlmapResults.csvData);
      } catch (err) {
        Logger.warn('Failed to parse SQLMap CSV data', err?.message || err);
      }
    }

    if (summary.confirmed.length > 0) {
      for (const confirmed of summary.confirmed) {
        const techniqueKey = confirmed.techniqueName || this.mapSqlmapTechnique(confirmed.type || confirmed.title || '');
        const vulnInfo = this.vulnerabilityDatabase[techniqueKey] ||
          this.vulnerabilityDatabase['SQL Injection'] || {
            severity: 'High',
            cvss: 7.0,
            description: 'SQLMap confirmed SQL injection vulnerability',
            impact: 'Potential data exfiltration and database compromise',
            remediation: ['Use parameterized queries', 'Implement strict input validation']
          };

        const parameter = confirmed.parameter || 'Unknown';
        const method = confirmed.method || (confirmed.place ? confirmed.place.toUpperCase() : undefined);
        if (hasKey(techniqueKey, parameter, method)) {
          continue;
        }

        const evidence = [];
        if (confirmed.rawText) {
          evidence.push({
            line: 0,
            content: confirmed.rawText,
            context: 'sqlmap-summary'
          });
        }
        if (confirmed.payload) {
          evidence.push({
            line: evidence.length + 1,
            content: confirmed.payload,
            context: 'payload'
          });
        }

        const vuln = {
          id: uuidv4(),
          type: techniqueKey,
          parameter,
          httpMethod: method,
          severity: vulnInfo.severity,
          cvss: vulnInfo.cvss,
          description: confirmed.title || confirmed.type || vulnInfo.description,
          impact: vulnInfo.impact,
          remediation: vulnInfo.remediation,
          confidenceLabel: 'Confirmed',
          confidenceScore: 0.98,
          status: 'confirmed',
          signals: ['explicit-tool-output', 'sqlmap-summary'],
          why: confirmed.title
            ? `SQLMap confirmed injection: ${confirmed.title}`
            : 'SQLMap confirmed the parameter as injectable.',
          evidence: evidence.length > 0 ? evidence : undefined,
          payload: confirmed.payload,
          techniqueSummary: confirmed.type || confirmed.title || undefined,
          sqlmapMetadata: {
            place: confirmed.place,
            method,
            type: confirmed.type,
            title: confirmed.title,
            payload: confirmed.payload,
            raw: confirmed.rawText
          },
          discoveredAt: new Date().toISOString()
        };

        vulnerabilities.push(vuln);
        registerKey(techniqueKey, parameter, method);
      }
    }

    if (csvRecords.length > 0) {
      const csvHeaderLookup = (record, ...keys) => {
        for (const key of keys) {
          if (record[key] != null && record[key] !== '') return record[key];
        }
        return undefined;
      };

      for (const record of csvRecords) {
        const place = csvHeaderLookup(record, 'place', 'method');
        const parameter = csvHeaderLookup(record, 'parameter', 'columns', 'column');
        const techniqueText = csvHeaderLookup(record, 'technique(s)', 'technique', 'title', 'type', 'notes', 'note(s)');
        const payload = csvHeaderLookup(record, 'payload');
        const notes = csvHeaderLookup(record, 'note(s)', 'notes');

        const method = place && /GET|POST|PUT|DELETE/i.test(place) ? place.toUpperCase() : undefined;
        const typeKey = this.mapSqlmapTechnique(techniqueText || notes || '');
        const keyType = typeKey || 'SQL Injection';
        const paramName = parameter || 'Unknown';

        if (hasKey(keyType, paramName, method)) {
          const existing = vulnerabilities.find((v) => makeKey(v.type, v.parameter, v.httpMethod) === makeKey(keyType, paramName, method));
          if (existing) {
            if (payload && !existing.payload) {
              existing.payload = payload;
            }
            existing.sqlmapMetadata = {
              ...(existing.sqlmapMetadata || {}),
              csv: record,
              technique: techniqueText || existing.sqlmapMetadata?.technique
            };
            if (!existing.description && notes) {
              existing.description = notes;
            }
          }
          continue;
        }

        const vulnInfo = this.vulnerabilityDatabase[keyType] || this.vulnerabilityDatabase['SQL Injection'] || {
          severity: 'High',
          cvss: 7.0,
          description: 'SQL injection finding reported by SQLMap',
          impact: 'Potential data exfiltration',
          remediation: ['Use parameterized queries', 'Implement strict input validation']
        };

        vulnerabilities.push({
          id: uuidv4(),
          type: keyType,
          parameter: paramName,
          httpMethod: method,
          severity: vulnInfo.severity,
          cvss: vulnInfo.cvss,
          description: techniqueText || notes || vulnInfo.description,
          impact: vulnInfo.impact,
          remediation: vulnInfo.remediation,
          confidenceLabel: summary.confirmed.length > 0 ? 'Confirmed' : 'Likely',
          confidenceScore: summary.confirmed.length > 0 ? 0.9 : 0.7,
          status: summary.confirmed.length > 0 ? 'confirmed' : 'suspected',
          signals: ['sqlmap-csv'],
          why: 'Parsed from SQLMap CSV results.',
          payload,
          sqlmapMetadata: {
            csv: record,
            technique: techniqueText,
            notes
          },
          evidence: payload ? [{ line: 0, content: payload, context: 'payload' }] : undefined,
          discoveredAt: new Date().toISOString()
        });
        registerKey(keyType, paramName, method);
      }
    }

    // If we have structured SQLMap results, use them first
    if (sqlmapResults && sqlmapResults.findings) {
      for (const finding of sqlmapResults.findings) {
        if (finding.type === 'vulnerability') {
          const vulnInfo = this.vulnerabilityDatabase[finding.technique] || 
                          this.vulnerabilityDatabase['SQL Injection'] || {
            severity: 'Medium',
            cvss: 5.0,
            description: `${finding.technique} vulnerability detected`,
            impact: 'Potential security risk',
            remediation: ['Implement proper input validation', 'Use parameterized queries']
          };

          const param = finding.parameter || 'Unknown';
          const method = finding.method || finding.place || undefined;
          if (hasKey(finding.technique || 'SQL Injection', param, method)) {
            continue;
          }

          vulnerabilities.push({
            id: uuidv4(),
            type: finding.technique || 'SQL Injection',
            parameter: param,
            httpMethod: method,
            severity: finding.severity === 'high' ? 'High' : vulnInfo.severity,
            cvss: vulnInfo.cvss,
            description: finding.description || vulnInfo.description,
            impact: vulnInfo.impact,
            remediation: vulnInfo.remediation,
            confidenceLabel: 'Likely',
            confidenceScore: 0.6,
            signals: ['tool-identified'],
            why: 'Detected by SQLMap structured output.',
            evidence: [{
              line: 1,
              content: finding.description
            }],
            discoveredAt: new Date().toISOString()
          });
          registerKey(finding.technique || 'SQL Injection', param, method);
        }
      }
    }

    // Enhanced fallback to parsing text output
    if (vulnerabilities.length === 0 && output) {
      Logger.info('No structured results available, parsing scan output for vulnerabilities');
      Logger.debug('Analyzing output length:', output.length);
      
      // Enhanced debugging - log more comprehensive sample
      const lines = output.split('\n');
      const totalLines = lines.length;
      const sampleLines = lines.slice(0, 20).filter(line => line.trim().length > 0);
      const middleLines = lines.slice(Math.floor(totalLines/2), Math.floor(totalLines/2) + 10).filter(line => line.trim().length > 0);
      const endLines = lines.slice(-20).filter(line => line.trim().length > 0);
      
      Logger.debug('Sample output lines (first 20):', sampleLines);
      Logger.debug('Sample output lines (middle 10):', middleLines);
      Logger.debug('Sample output lines (last 20):', endLines);
      
      // Debug: Check for key SQLMap phrases
      const keyPhrases = [
        'vulnerable', 'injectable', 'sqlmap identified', 'parameter', 'appears to be',
        'injection', 'back-end DBMS', 'Type:', 'Title:', 'Payload:', 'target appears'
      ];
      
      Logger.debug('Key phrase analysis:');
      for (const phrase of keyPhrases) {
        const count = (output.match(new RegExp(phrase, 'gi')) || []).length;
        if (count > 0) {
          Logger.debug(`- "${phrase}": ${count} occurrences`);
        }
      }
      
      const vulnPatterns = {
        'SQL Injection': /(?:vulnerable|injectable|sqlmap identified|parameter.*appears to be|injection|exploitable|back.end.*DBMS|database management system|target.*appears.*to.*be|heuristic.*positive|might.*be.*injectable)/i,
        'Boolean-based blind SQL injection': /(?:boolean.*based.*blind|AND.*boolean.*based|OR.*boolean.*based|Type:.*boolean.based|boolean.based.*blind.*SQL.*injection)/i,
        'Time-based blind SQL injection': /(?:time.*based.*blind|sleep.*based|delay.*based|Type:.*time.based|time.based.*blind.*SQL.*injection)/i,
        'Error-based SQL injection': /(?:error.*based|mysql.*error|postgresql.*error|oracle.*error|mssql.*error|Type:.*error.based|error.based.*SQL.*injection)/i,
        'Union query SQL injection': /(?:union.*query|union.*based|union.*select|Type:.*UNION.*query|UNION.*query.*SQL.*injection)/i,
        'Stacked queries': /(?:stacked.*queries|multiple.*statements|;\s*select|;\s*update|;\s*insert|;\s*delete|Type:.*stacked.*queries|stacked.*queries.*SQL.*injection)/i,
        'POST SQL Injection': /(?:POST.*parameter.*vulnerable|POST.*injectable|POST.*parameter.*appears.*to.*be)/i,
        'GET SQL Injection': /(?:GET.*parameter.*vulnerable|GET.*injectable|GET.*parameter.*appears.*to.*be)/i,
        'Generic Injectable Parameter': /(?:testing.*parameter|checking.*parameter|injectable.*parameter|vulnerable.*parameter|parameter.*might.*be.*vulnerable|parameter.*appears.*to.*be.*injectable)/i
      };

      // Ultra-comprehensive parameter extraction
      const parameterMatches = output.match(/(?:parameter[:\s]+['"`]?|testing\s+(?:parameter\s+)?['"`]?|GET\s+parameter\s+['"`]?|POST\s+parameter\s+['"`]?|URI\s+parameter\s+['"`]?)([^\s\n'",()]+)['"`]?/gi) || [];
      const additionalParams = output.match(/\((?:GET|POST|PUT|DELETE)\)\s+([^:\s\n]+)/gi) || [];
      // Capture lines like: "Parameter: searchFor (POST)"
      const namedParamMatches = output.match(/Parameter:\s*([^\s(]+)\s*\((GET|POST|PUT|DELETE)\)/gi) || [];
      // Lines like: POST parameter 'searchFor' is 'MySQL >= 5.1 AND error-based ...' injectable
      const injectableLineParams = (output.match(/\b(?:GET|POST|PUT|DELETE)\s+parameter\s+['"`]([^-'"`\s]+)['"`]\s+is\s+[^\n]*?injectable/gi) || [])
        .map(s => {
          const m = s.match(/parameter\s+['"`]([^-'"`\s]+)['"`]/i) || [];
          return m[1] || '';
        })
        .filter(Boolean);
      const allParamMatches = [...parameterMatches, ...additionalParams, ...namedParamMatches, ...injectableLineParams];
      
      const parameters = allParamMatches.map(match => {
        if (typeof match === 'string') {
          if (!/\s/.test(match) && !/[:()'"`]/.test(match)) return match.trim();
          return match.replace(/(?:parameter[:\s]+['"`]?|testing\s+(?:parameter\s+)?['"`]?|GET\s+parameter\s+['"`]?|POST\s+parameter\s+['"`]?|URI\s+parameter\s+['"`]?|\((?:GET|POST|PUT|DELETE)\)\s+)/i, '').replace(/['"`:\s]/g, '').trim();
        }
        return '';
      }).filter(param => param.length > 0);

      // Extract DBMS information for impact/context enrichment if present
      const dbmsMatch = output.match(/back-?end\s+DBMS:\s*([^\n]+)/i);
      const dbmsInfo = dbmsMatch ? dbmsMatch[1].trim() : null;

      // SQLMap success indicators (restricted to real vuln cues)
      const sqlmapSuccessPatterns = [
        /parameter\s+['"`]?([^'"`\s\n]+)['"`]?\s+is\s+vulnerable/gi,
        /(?:GET|POST|PUT|DELETE)\s+parameter\s+['"`]([^'"`\s\n]+)['"`]\s+is\s+[^\n]*?injectable/gi,
        /parameter\s+['"`]?([^'"`\s\n]+)['"`]?\s+appears\s+to\s+be\s+(?:['"`]?([^'"`\s\n]+)['"`]?\s+)?injectable/gi,
        /parameter\s+['"`]?([^'"`\s\n]+)['"`]?\s+might\s+be\s+(?:['"`]?([^'"`\s\n]+)['"`]?\s+)?vulnerable/gi,
        /(?:GET|POST|PUT|DELETE)\s+parameter\s+['"`]?([^'"`\s\n]+)['"`]?\s+is\s+vulnerable/gi,
        /(?:GET|POST|PUT|DELETE)\s+parameter\s+['"`]?([^'"`\s\n]+)['"`]?\s+appears\s+to\s+be\s+injectable/gi,
        /sqlmap.*identified.*the.*following.*injection.*point/gi,
        /injectable\s+parameter.*found/gi,
        /injection\s+point.*found/gi,
        /\d+\s+injection\s+point.*found/gi
      ];

      // Helper to upsert/merge findings (deduplicate)
      const addOrMerge = (arr, next) => {
        const normType = (t => {
          const map = {
            'POST SQL Injection': 'SQL Injection',
            'GET SQL Injection': 'SQL Injection',
            'Generic Injectable Parameter': 'SQL Injection',
            'Potential SQL Injection': 'SQL Injection'
          };
          return map[t] || t;
        })(next.type || 'SQL Injection');
        const keyParam = next.parameter || 'Unknown';
          const idx = arr.findIndex(f => (f.type === normType) && ((f.parameter || 'Unknown') === keyParam));
        if (idx === -1) {
          next.type = normType;
          arr.push(next);
            registerKey(normType, keyParam, next.httpMethod || next.method || undefined);
          return;
        }
        const cur = arr[idx];
        // Keep stronger confidence
        if ((next.confidenceScore || 0) > (cur.confidenceScore || 0)) {
          cur.confidenceScore = next.confidenceScore;
          cur.confidenceLabel = next.confidenceLabel;
          cur.why = next.why || cur.why;
        }
        // Prefer known parameter over Unknown
        if ((!cur.parameter || cur.parameter === 'Unknown') && keyParam !== 'Unknown') {
          cur.parameter = keyParam;
        }
        // Merge evidence and signals
        if (Array.isArray(next.evidence)) {
          const merged = [...(cur.evidence || []), ...next.evidence];
          cur.evidence = merged.filter((e, i, self) => i === self.findIndex(x => x.line === e.line && x.content === e.content)).slice(0, 20);
        }
        if (Array.isArray(next.signals)) {
          const sig = new Set([...(cur.signals || []), ...next.signals]);
          cur.signals = Array.from(sig);
        }
        // Upgrade impact/description if next mentions a concrete technique
        if (/error-?based/i.test(next.description || '') && !/error-?based/i.test(cur.description || '')) {
          cur.description = next.description;
        }
        if (next.impact && (!cur.impact || cur.impact === 'Potential security risk')) {
          cur.impact = next.impact;
        }
      };

      // Create condensed findings from success patterns
      for (const pattern of sqlmapSuccessPatterns) {
        const matches = output.match(new RegExp(pattern.source, 'gi'));
        if (!matches) continue;
        for (const match of matches) {
          const paramMatch = match.match(pattern) || [];
          const vulnInfo = this.vulnerabilityDatabase['SQL Injection'] || {
            severity: 'High',
            cvss: 7.5,
            description: 'SQL injection vulnerability detected by SQLMap',
            impact: 'Attacker may be able to access, modify, or delete database contents',
            remediation: ['Use parameterized queries', 'Implement input validation', 'Apply least privilege principle']
          };
          const paramName = (paramMatch[1] || paramMatch[2] || '').trim() || (parameters[0] || 'Unknown');
          const strongSignal = /\bis\s+[^\n]*?(?:vulnerable|injectable)\b/i.test(match) || /sqlmap\s+identified\s+the\s+following\s+injection\s+point/i.test(output);
          const baseScore = strongSignal ? 0.95 : 0.4;
          const enrichedDescription = dbmsInfo
            ? `${vulnInfo.description}: ${match.trim()} (DBMS: ${dbmsInfo})`
            : `${vulnInfo.description}: ${match.trim()}`;
          const techniqueImpact = (/error-?based/i.test(output) || /EXTRACTVALUE|UPDATEXML/i.test(output))
            ? (this.vulnerabilityDatabase['Error-based SQL injection']?.impact || 'Error-based SQLi detected. Likely DBMS/version disclosure, schema enumeration via errors, and potential data exfiltration.')
            : vulnInfo.impact;

          addOrMerge(vulnerabilities, {
            id: uuidv4(),
            type: 'SQL Injection',
            parameter: paramName,
            severity: vulnInfo.severity,
            cvss: vulnInfo.cvss,
            description: enrichedDescription,
            impact: techniqueImpact,
            remediation: vulnInfo.remediation,
            confidenceLabel: strongSignal ? 'Confirmed' : 'Suspected',
            confidenceScore: baseScore,
            signals: [strongSignal ? 'explicit-tool-output' : 'heuristic-output'],
            why: strongSignal ? 'Tool output explicitly reports an injectable/vulnerable parameter.' : 'Heuristic patterns in scan output indicate possible injection.',
            evidence: this.extractEvidence(output, 'SQL Injection'),
            discoveredAt: new Date().toISOString()
          });
        }
      }

      // Look for vulnerability indicators (fallback)
      for (const [vulnType, pattern] of Object.entries(vulnPatterns)) {
        if (pattern.test(output)) {
          // Check if we already found this type
          const alreadyFound = vulnerabilities.some(v => v.type === (vulnType === 'POST SQL Injection' || vulnType === 'GET SQL Injection' || vulnType === 'Generic Injectable Parameter' || vulnType === 'Potential SQL Injection' ? 'SQL Injection' : vulnType));
          if (!alreadyFound) {
            const vulnInfo = this.vulnerabilityDatabase[vulnType] || {
              severity: 'Medium',
              cvss: 5.0,
              description: `${vulnType} vulnerability detected in scan output`,
              impact: 'Potential security risk',
              remediation: ['Implement proper input validation', 'Use parameterized queries']
            };

            addOrMerge(vulnerabilities, {
              id: uuidv4(),
              type: vulnType,
              parameter: parameters.length > 0 ? parameters[0] : 'Unknown',
              severity: vulnInfo.severity,
              cvss: vulnInfo.cvss,
              description: vulnInfo.description,
              impact: dbmsInfo && /error-?based/i.test(vulnType)
                ? `${vulnInfo.impact}; DBMS disclosed: ${dbmsInfo}`
                : vulnInfo.impact,
              remediation: vulnInfo.remediation,
              confidenceLabel: 'Suspected',
              confidenceScore: 0.35,
              signals: ['pattern-match'],
              why: 'Output matched known vulnerability patterns.',
              evidence: this.extractEvidence(output, vulnType),
              discoveredAt: new Date().toISOString()
            });
          }
        }
      }

      // If we inferred exactly one parameter, apply it to Unknown entries
      if (parameters.length === 1) {
        for (const v of vulnerabilities) {
          if (!v.parameter || v.parameter === 'Unknown') {
            v.parameter = parameters[0];
          }
        }
      }

      // Prune noisy non-vuln entries accidentally captured (e.g., purely informational tech banners)
      const looksInformational = (v) => {
        if (v.type !== 'SQL Injection') return false;
        if (Array.isArray(v.signals) && v.signals.includes('explicit-tool-output')) return false;
        const ev = (v.evidence || []).map(e => (e.content || ''));
        const joined = ev.join('\n');
        const hasRealCue = /(injectable|vulnerable|injection point|Type:|Title:|Payload:)/i.test(joined);
        if (hasRealCue) return false;
        // Drop entries whose evidence only mentions tech banners
        return /(web\s+server\s+operating\s+system|web\s+application\s+technology)/i.test(joined);
      };
      const cleaned = vulnerabilities.filter(v => !looksInformational(v));
      // Replace the array with cleaned results
      vulnerabilities.length = 0;
      vulnerabilities.push(...cleaned);

      // Harmonize parameter/method based on evidence/descriptions
      for (const vuln of vulnerabilities) {
        applyEvidenceContext(vuln);
      }

      // If no specific vulnerabilities found but scan completed successfully, check for generic indicators
      if (vulnerabilities.length === 0 && scanData.status === 'completed' && scanData.exit_code === 0) {
        const successPatterns = [
          /target appears to be/i,
          /database management system/i,
          /current user/i,
          /current database/i,
          /back-end DBMS/i,
          /web server operating system/i,
          /web application technology/i
        ];

        // Check for possible missed vulnerabilities with ultra-aggressive patterns
        const missedVulnPatterns = [
          /heuristic.*test.*(?:positive|shows)/i,
          /URI.*might.*be.*injectable/i,
          /might.*be.*vulnerable/i,
          /might.*be.*injectable/i,
          /appears.*to.*be.*injectable/i,
          /appears.*to.*be.*vulnerable/i,
          /blind.*injection.*(?:found|detected|identified)/i,
          /injection.*point.*(?:found|detected|identified)/i,
          /payload.*worked/i,
          /\d+\s+(?:targets?|parameters?).*(?:vulnerable|injectable)/i,
          /testing.*for.*SQL.*injection/i,
          /checking.*if.*.*parameter.*is.*injectable/i,
          /target.*(?:URL|application).*appears.*to.*be/i,
          /back.end.*DBMS.*(?:is|appears)/i,
          /database.*management.*system/i,
          /web.*application.*technology/i,
          /web.*server.*operating.*system/i,
          /sqlmap.*identified/i,
          /sqlmap.*resumed/i,
          /Type:.*(?:boolean|time|error|union|stacked)/i,
          /Title:.*(?:SQL|injection)/i,
          /Payload:.*(?:SELECT|UNION|AND|OR)/i,
          /technique.*(?:boolean|time|error|union|stacked)/i,
          /vector.*(?:SQL|injection)/i,
          /current.*(?:user|database)/i,
          /hostname.*detected/i,
          /banner.*(?:MySQL|PostgreSQL|Oracle|MSSQL|SQLite)/i
        ];

        const hasResults = successPatterns.some(pattern => pattern.test(output));
        const hasMissedVulns = missedVulnPatterns.some(pattern => pattern.test(output));
        
        if (hasMissedVulns) {
          Logger.warn('Potential vulnerabilities detected that were missed by main patterns');
          vulnerabilities.push({
            id: uuidv4(),
            type: 'Potential SQL Injection',
            parameter: parameters.length > 0 ? parameters[0] : 'Unknown',
            severity: 'Medium',
            cvss: 5.0,
            description: 'SQLMap detected potential SQL injection indicators',
            impact: 'Possible SQL injection vulnerability requiring manual verification',
            remediation: ['Manual verification required', 'Implement input validation', 'Use parameterized queries'],
            confidenceLabel: 'Suspected',
            confidenceScore: 0.3,
            signals: ['weak-indicators'],
            why: 'Weak indicators suggest potential injection; manual verification recommended.',
            evidence: this.extractEvidence(output, 'potential'),
            discoveredAt: new Date().toISOString()
          });
        } else if (hasResults) {
          Logger.info('Scan completed successfully but no specific vulnerabilities detected');
          // Add an informational entry
          vulnerabilities.push({
            id: uuidv4(),
            type: 'Information Disclosure',
            parameter: 'Various',
            severity: 'Low',
            cvss: 2.0,
            description: 'SQLMap scan completed successfully and gathered information about the target',
            impact: 'Information about the database system was disclosed',
            remediation: ['Review exposed information', 'Implement proper error handling', 'Minimize information disclosure'],
            confidenceLabel: 'Confirmed',
            confidenceScore: 0.95,
            signals: ['tool-output'],
            why: 'Informational findings from tool output.',
            evidence: this.extractEvidence(output, 'success'),
            discoveredAt: new Date().toISOString()
          });
        }
      }
      
      Logger.info(`Found ${vulnerabilities.length} vulnerabilities after parsing`);
    }

    // Ensure parameter/method context for all findings
    for (const vuln of vulnerabilities) {
      applyEvidenceContext(vuln);
      normalizeConfidence(vuln);
      vuln.status = deriveStatus(vuln);
    }

    // Calculate risk score
    const riskScore = this.calculateRiskScore(vulnerabilities);

    const summaryForMetadata = (summary && (summary.confirmed.length > 0 || summary.attempted.length > 0 || summary.verdictLine))
      ? {
          verdictLine: summary.verdictLine,
          rawSection: summary.rawSection,
          confirmed: summary.confirmed.map((item) => ({
            parameter: item.parameter,
            method: item.method,
            place: item.place,
            type: item.type,
            title: item.title,
            payload: item.payload,
            techniqueName: item.techniqueName,
            raw: item.rawText
          })),
          attempted: summary.attempted
        }
      : undefined;
    
    return {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter(v => v.severity === 'Critical').length,
      high: vulnerabilities.filter(v => v.severity === 'High').length,
      medium: vulnerabilities.filter(v => v.severity === 'Medium').length,
      low: vulnerabilities.filter(v => v.severity === 'Low').length,
      riskScore: riskScore,
      riskLevel: this.getRiskLevel(riskScore),
      findings: vulnerabilities,
      sqlmapSummary: summaryForMetadata
    };
  }

  calculateRiskScore(vulnerabilities) {
    if (vulnerabilities.length === 0) return 0;

    const severityWeights = {
      'Critical': 10,
      'High': 7,
      'Medium': 4,
      'Low': 1
    };

    // Determine the highest severity weight present
    const highestWeight = Math.max(
      ...vulnerabilities.map(v => severityWeights[v.severity] || 0)
    );

    // Scale to 0-100 for a simple score (weight * 10)
    return highestWeight * 10;
  }

  getRiskLevel(score) {
    if (score >= 90) return 'Critical';
    if (score >= 70) return 'High';
    if (score >= 40) return 'Medium';
    if (score > 0) return 'Low';
    return 'Informational';
  }

  // Determine an overall verdict based on findings and extracted data
  determineOverallVerdict(vulnerabilities, extractedData) {
    try {
      const findings = Array.isArray(vulnerabilities?.findings) ? vulnerabilities.findings : [];
      const hasDataExtraction = !!(
        (extractedData?.databases && extractedData.databases.length) ||
        (extractedData?.users && extractedData.users.length) ||
        (extractedData?.tables && extractedData.tables.length) ||
        (extractedData?.systemInfo && extractedData.systemInfo.dbms && extractedData.systemInfo.dbms.length)
      );

      const anyConfirmed = findings.some(f => (f.status?.toLowerCase?.() === 'confirmed') || (f.confidenceLabel === 'Confirmed'));
      const anySuspected = findings.some(f => (f.status?.toLowerCase?.() === 'suspected') || (f.confidenceLabel === 'Likely' || f.confidenceLabel === 'Suspected'));

      // Prefer technique-specific status if present
      const affectedParameters = findings
        .map(f => ({ param: f.parameter || 'Unknown', type: f.type || 'SQL Injection' }))
        .filter((v, i, self) => i === self.findIndex(x => x.param === v.param && x.type === v.type));

      if (hasDataExtraction && anyConfirmed) {
        return {
          level: 'Exploited',
          rationale: 'At least one injection technique was confirmed and actual data/metadata was extracted from the target.',
          affectedParameters
        };
      }
      if (anyConfirmed) {
        return {
          level: 'Confirmed',
          rationale: 'One or more injection techniques were confirmed, but no data extraction was recorded.',
          affectedParameters
        };
      }
      if (anySuspected) {
        return {
          level: 'Suspected',
          rationale: 'Signals suggest possible injection but lack definitive proof or data extraction.',
          affectedParameters
        };
      }
      return {
        level: 'Inconclusive',
        rationale: 'No techniques were confirmed; testing did not yield decisive evidence.',
        affectedParameters
      };
    } catch (e) {
      Logger.warn('determineOverallVerdict failed; defaulting to Inconclusive', e?.message);
      return { level: 'Inconclusive', rationale: 'Unable to compute verdict', affectedParameters: [] };
    }
  }

  extractEvidence(output, vulnType) {
    const evidence = [];
    const lines = output.split('\n');
    const maxEvidenceLines = 10; // Limit evidence to prevent huge objects

    // Find relevant lines based on vulnerability type
    const searchPatterns = {
      'SQL Injection': [/vulnerable|injectable|sqlmap.*identified/i, /parameter.*appears.*to.*be/i],
      'Boolean-based blind SQL injection': [/boolean-based blind/i, /payload.*worked/i],
      'Time-based blind SQL injection': [/time-based blind/i, /delay.*detected/i],
      'Error-based SQL injection': [/error-based/i, /database.*error/i],
      'Union query SQL injection': [/union query/i, /union.*select/i],
      'Stacked queries': [/stacked queries/i, /multiple.*statements/i],
      'Information Disclosure': [/target appears to be/i, /database management system/i, /current user/i],
      'success': [/target appears to be/i, /database.*identified/i, /scan.*completed/i]
    };

    const patterns = searchPatterns[vulnType] || [new RegExp(vulnType, 'i')];

    for (let i = 0; i < lines.length && evidence.length < maxEvidenceLines; i++) {
      const line = lines[i].trim();
      
      if (line.length === 0) continue;

      // Check if line matches any of the patterns for this vulnerability type
      for (const pattern of patterns) {
        if (pattern.test(line)) {
          evidence.push({
            line: i + 1,
            content: line
          });
          
          // Also include some context lines (before and after)
          if (evidence.length < maxEvidenceLines) {
            // Add previous line if available and relevant
            if (i > 0 && lines[i - 1].trim().length > 0) {
              evidence.push({
                line: i,
                content: lines[i - 1].trim(),
                context: 'previous'
              });
            }
            
            // Add next line if available and relevant
            if (i < lines.length - 1 && lines[i + 1].trim().length > 0 && evidence.length < maxEvidenceLines) {
              evidence.push({
                line: i + 2,
                content: lines[i + 1].trim(),
                context: 'next'
              });
            }
          }
          break; // Only match first pattern per line
        }
      }
    }

    // If no specific evidence found, try to capture some general output
    if (evidence.length === 0) {
      const generalPatterns = [
        /\[.*\].*INFO/i,
        /testing.*parameter/i,
        /sqlmap.*identified/i,
        /target.*url/i,
        /checking.*connection/i
      ];

      for (let i = 0; i < lines.length && evidence.length < 3; i++) {
        const line = lines[i].trim();
        if (line.length === 0) continue;

        for (const pattern of generalPatterns) {
          if (pattern.test(line)) {
            evidence.push({
              line: i + 1,
              content: line
            });
            break;
          }
        }
      }
    }

    // Remove duplicates and sort by line number
    const uniqueEvidence = evidence
      .filter((item, index, self) => 
        index === self.findIndex(e => e.line === item.line && e.content === item.content)
      )
      .sort((a, b) => a.line - b.line);

    return uniqueEvidence.length > 0 ? uniqueEvidence : [{
      line: 1,
      content: `Evidence for ${vulnType} - scan output analysis completed`
    }];
  }

  async analyzeExtractedData(scanData, sqlmapResults = null) {
    const output = scanData.output || '';
    const artifacts = this.parseSqlmapArtifacts(output);
    const extractedData = {
      databases: [],
      tables: [],
      columns: [],
      users: [],
      systemInfo: {},
      csvFiles: [],
      structuredData: null
    };

    if (artifacts.dbms.length > 0) {
      extractedData.systemInfo.dbms = artifacts.dbms;
    }
    if (artifacts.banners.length > 0) {
      extractedData.systemInfo.banner = artifacts.banners;
    }
    if (artifacts.currentDatabase) {
      extractedData.databases = [artifacts.currentDatabase];
    }
    if (artifacts.currentUser) {
      extractedData.users = [artifacts.currentUser];
    }
    if (artifacts.hostname) {
      extractedData.systemInfo.hostname = artifacts.hostname;
    }
    if (typeof artifacts.isDba === 'boolean') {
      extractedData.systemInfo.isDba = artifacts.isDba;
    }
    if (artifacts.webTechnology.length > 0) {
      extractedData.systemInfo.webTechnology = artifacts.webTechnology;
    }
    if (artifacts.webServerOs) {
      extractedData.systemInfo.webServerOs = artifacts.webServerOs;
    }
    if (artifacts.os) {
      extractedData.systemInfo.dbmsOs = artifacts.os;
    }

    // If we have structured SQLMap results, use them
    if (sqlmapResults) {
      // Extract database information from findings
      const dbFindings = sqlmapResults.findings.filter(f => f.type === 'database_info');
      if (dbFindings.length > 0) {
        const existing = new Set(extractedData.databases);
        for (const finding of dbFindings) {
          if (finding.info) existing.add(finding.info);
        }
        extractedData.databases = Array.from(existing);
      }

      // Extract version information
      const versionFindings = sqlmapResults.findings.filter(f => f.type === 'version_info');
      if (versionFindings.length > 0) {
        const current = Array.isArray(extractedData.systemInfo.dbms)
          ? new Set(extractedData.systemInfo.dbms)
          : new Set();
        for (const finding of versionFindings) {
          if (finding.dbms) current.add(finding.dbms);
        }
        extractedData.systemInfo.dbms = Array.from(current);
      }

      // Include CSV data if available
      if (sqlmapResults.csvData) {
        extractedData.structuredData = sqlmapResults.csvData;
      }

      // Include dump files information
      if (sqlmapResults.files && sqlmapResults.files.dumps) {
        extractedData.csvFiles = sqlmapResults.files.dumps.map(file => ({
          name: file.name,
          path: file.path,
          size: file.size,
          modified: file.modified
        }));
      }
    }

    // Fallback to parsing text output if no structured results
    if (extractedData.databases.length === 0 && extractedData.csvFiles.length === 0) {
      const dataPatterns = {
        databases: /available databases.*?:\s*\[([^\]]+)\]/is,
        tables: /Database:.*?Table:.*?\[([^\]]+)\]/is,
        columns: /Table:.*?Column:.*?\[([^\]]+)\]/is,
        users: /database users.*?:\s*\[([^\]]+)\]/is
      };

      for (const [category, pattern] of Object.entries(dataPatterns)) {
        const match = output.match(pattern);
        if (match) {
          extractedData[category] = match[1]
            .split(',')
            .map(item => item.trim().replace(/['"]/g, ''))
            .filter(item => item);
        }
      }

      // Also try to capture DBMS banner or name lines from plain output
      const dbmsBanner = output.match(/back-?end\s+DBMS:?\s*([^\n]+)/i);
      if (dbmsBanner && dbmsBanner[1]) {
        const val = dbmsBanner[1].trim();
        if (!extractedData.systemInfo.dbms) extractedData.systemInfo.dbms = [];
        const arr = Array.isArray(extractedData.systemInfo.dbms) ? extractedData.systemInfo.dbms : [extractedData.systemInfo.dbms];
        if (!arr.includes(val)) arr.push(val);
        extractedData.systemInfo.dbms = arr;
      }
    }

    return extractedData;
  }

  async generateRecommendations(scanData) {
    const recommendations = [];
    const output = scanData.output || '';
    const vulnCount = (output.match(/vulnerable|injectable/gi) || []).length;

    recommendations.push({
      category: 'Input Validation',
      priority: 'High',
      title: 'Implement Parameterized Queries',
      description: 'Replace all dynamic SQL queries with parameterized queries or prepared statements.',
      implementation: [
        'Use ORM frameworks that handle parameterization',
        'Implement prepared statements for database operations',
        'Avoid string concatenation in SQL queries'
      ],
      effort: 'Medium',
      impact: 'High'
    });

    if (vulnCount > 0) {
      recommendations.push({
        category: 'Security Testing',
        priority: 'High',
        title: 'Regular Security Assessments',
        description: 'Implement regular security testing to identify vulnerabilities.',
        implementation: [
          'Integrate security testing into CI/CD pipeline',
          'Perform quarterly penetration testing',
          'Implement automated vulnerability scanning'
        ],
        effort: 'Medium',
        impact: 'High'
      });
    }

    return recommendations;
  }

  calculateScanDuration(scanData) {
    if (!scanData.start_time || !scanData.end_time) return null;
    
    const startTime = new Date(scanData.start_time);
    const endTime = new Date(scanData.end_time);
    
    // Check if dates are valid
    if (isNaN(startTime.getTime()) || isNaN(endTime.getTime())) return null;
    
    const durationMs = endTime - startTime; // milliseconds

    // Return null if duration is negative or unreasonably large (more than 24 hours)
    if (durationMs < 0 || durationMs > 86_400_000) return null;

    return durationMs;
  }

  sanitizeReportData(reportData) {
    // Ensure all required fields exist with proper defaults
    const sanitized = {
      id: reportData.id || 'unknown',
      title: reportData.title || 'Security Assessment Report',
      target: reportData.target || 'Unknown Target',
      command: reportData.command || 'sqlmap',
      status: reportData.status || 'completed',
      scanDuration: reportData.scanDuration || null,
      createdAt: reportData.created_at || reportData.createdAt || new Date().toISOString(),
      vulnerabilities: {
        total: 0,
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        findings: [],
        ...reportData.vulnerabilities || {}
      },
      extractedData: {
        databases: [],
        tables: [],
        columns: [],
        users: [],
        systemInfo: {},
        csvFiles: [],
        ...reportData.extractedData || reportData.extracted_data || {}
      },
      outputFiles: reportData.outputFiles || (reportData.sqlmapResults && reportData.sqlmapResults.files) || null,
      recommendations: reportData.recommendations || [],
      metadata: {
        generatedAt: new Date().toISOString(),
        scanProfile: 'basic',
        reportVersion: '1.0',
        scanner: 'SQLMap Integration',
        severityCriteria: this.getSeverityCriteriaOverview(),
        ...reportData.metadata || {}
      }
    };

    Logger.info('Report data sanitized', { 
      hasMetadata: !!reportData.metadata,
      hasVulnerabilities: !!reportData.vulnerabilities,
      vulnCount: sanitized.vulnerabilities.total
    });

    return sanitized;
  }

  async exportReport(reportData, format = 'json') {
    try {
      Logger.info('Exporting report', { 
        reportId: reportData.id, 
        format, 
        hasMetadata: !!reportData.metadata 
      });

      switch (format.toLowerCase()) {
        case 'pdf':
          try {
            return await this.queuePDFGeneration(reportData);
          } catch (pdfError) {
            Logger.error('PDF generation failed, attempting fallback options:', pdfError);
            
                          // Try with a simpler PDF generation approach (bypass queue for fallback)
              try {
                Logger.info('Attempting PDF generation with simpler configuration...');
                return await this.generatePDFReportSimple(reportData);
              } catch (simplePdfError) {
              Logger.error('Simple PDF generation also failed:', simplePdfError);
              
              // As a last resort, provide HTML with PDF-like styling
              Logger.warn('PDF generation completely failed, returning styled HTML as fallback');
              const htmlContent = this.generateHTMLReport(reportData, true); // PDF-styled HTML
              return Buffer.from(htmlContent, 'utf8');
            }
          }
        case 'csv': {
          // Create a compact CSV from the report findings
          const sanitized = this.sanitizeReportData(reportData);
          const rows = [];
          // Header
          rows.push('Type,Parameter,Severity,Confidence,Description');
          for (const v of (sanitized.vulnerabilities.findings || [])) {
            const type = (v.type || '').replace(/\s+/g, ' ').trim();
            const param = (v.parameter || '').replace(/\s+/g, ' ').trim();
            const sev = (v.severity || '').trim();
            const conf = typeof v.confidenceScore === 'number' ? `${Math.round(v.confidenceScore * 100)}%` : (v.confidenceLabel || '');
            const desc = (v.description || '').replace(/"/g, '""');
            rows.push([type, param, sev, conf, `"${desc}"`].join(','));
          }
          return rows.join('\n');
        }
        case 'html':
          return this.generateHTMLReport(reportData);
        case 'md':
        case 'markdown':
          return this.generateMarkdownReport(reportData);
        case 'json':
          return JSON.stringify(reportData, null, 2);
        default:
          throw new Error(`Unsupported report format: ${format}`);
      }
    } catch (error) {
      Logger.error('Error in exportReport:', error);
      throw error;
    }
  }

  async queuePDFGeneration(reportData, maxRetries = 2) {
    // Check if queue is overloaded
    if (this.pdfGenerationQueue.length > 10) {
      Logger.warn('PDF generation queue is overloaded, clearing old requests');
      this.resetPDFGenerationSystem();
    }
    
    return new Promise((resolve, reject) => {
      this.pdfGenerationQueue.push({
        reportData,
        maxRetries,
        resolve,
        reject,
        queuedAt: Date.now()
      });
      
      Logger.info('PDF generation request queued', { 
        reportId: reportData.id, 
        queueLength: this.pdfGenerationQueue.length,
        isProcessing: this.isGeneratingPdf
      });
      
      // Process queue if not already processing
      if (!this.isGeneratingPdf) {
        this.processPDFQueue();
      }
    });
  }

  resetPDFGenerationSystem() {
    Logger.warn('Resetting PDF generation system due to overload or cascading failures');
    
    // Reject all pending requests
    while (this.pdfGenerationQueue.length > 0) {
      const { reject, reportData } = this.pdfGenerationQueue.shift();
      reject(new Error('PDF generation system reset due to overload'));
      Logger.info('Rejected PDF request during reset', { reportId: reportData.id });
    }
    
    // Reset flags
    this.isGeneratingPdf = false;
    this.puppeteerChecked = false;
    
    // Re-validate Puppeteer
    setTimeout(() => {
      this.validatePuppeteerSetup();
    }, 5000);
    
    Logger.info('PDF generation system reset completed');
  }

  async processPDFQueue() {
    if (this.isGeneratingPdf || this.pdfGenerationQueue.length === 0) {
      return;
    }

    this.isGeneratingPdf = true;
    Logger.info('Starting PDF queue processing', { queueLength: this.pdfGenerationQueue.length });
    
    let consecutiveFailures = 0;
    const maxConsecutiveFailures = 3;
    
    try {
      while (this.pdfGenerationQueue.length > 0) {
        const { reportData, maxRetries, resolve, reject, queuedAt } = this.pdfGenerationQueue.shift();
        const waitTime = Date.now() - queuedAt;
        
        // Check if request is too old (over 2 minutes)
        if (waitTime > 120000) {
          Logger.warn('Rejecting old PDF request', { reportId: reportData.id, waitTime: `${waitTime}ms` });
          reject(new Error('PDF generation request timed out in queue'));
          continue;
        }
        
        Logger.info('Processing PDF from queue', { 
          reportId: reportData.id,
          waitTime: `${waitTime}ms`,
          remaining: this.pdfGenerationQueue.length,
          consecutiveFailures
        });
        
        try {
          const result = await this.generatePDFReport(reportData, maxRetries);
          Logger.info('PDF generated from queue successfully', { reportId: reportData.id });
          resolve(result);
          consecutiveFailures = 0; // Reset failure counter on success
        } catch (error) {
          consecutiveFailures++;
          Logger.error('PDF generation from queue failed', { 
            reportId: reportData.id, 
            error: error.message,
            consecutiveFailures 
          });
          
          // If too many consecutive failures, reset system
          if (consecutiveFailures >= maxConsecutiveFailures) {
            Logger.error('Too many consecutive PDF generation failures, resetting system');
            reject(new Error('PDF generation system experiencing issues, please try again later'));
            this.resetPDFGenerationSystem();
            return;
          }
          
          // Try fallback simple generation before complete failure
          try {
            Logger.info('Attempting fallback simple PDF generation', { reportId: reportData.id });
            const fallbackResult = await this.generatePDFReportSimple(reportData);
            Logger.info('Fallback PDF generated successfully', { reportId: reportData.id });
            resolve(fallbackResult);
            consecutiveFailures = Math.max(0, consecutiveFailures - 1); // Reduce failure count on fallback success
          } catch (fallbackError) {
            Logger.error('Fallback PDF generation also failed', { reportId: reportData.id, error: fallbackError.message });
            reject(new Error(`Both standard and fallback PDF generation failed: ${error.message}`));
          }
        }
        
        // Longer delay between generations, increased with consecutive failures
        if (this.pdfGenerationQueue.length > 0) {
          const delay = Math.min(2000 + (consecutiveFailures * 1000), 8000);
          await new Promise(resolve => setTimeout(resolve, delay));
        }
      }
    } catch (queueError) {
      Logger.error('PDF queue processing error:', queueError);
      this.resetPDFGenerationSystem();
    } finally {
      this.isGeneratingPdf = false;
      Logger.info('PDF queue processing completed');
    }
  }

  async generatePDFReport(reportData, maxRetries = 2) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
      let browser = null;
      let page = null;
      
      try {
        Logger.info('Starting PDF generation attempt', { 
          reportId: reportData.id, 
          attempt, 
          maxRetries 
        });
        
        // Check if Puppeteer is available
        if (!puppeteer) {
          throw new Error('Puppeteer is not available for PDF generation');
        }
        
        // Validate and sanitize report data before processing
        const sanitizedReportData = this.sanitizeReportData(reportData);
        
        const htmlContent = this.generateHTMLReport(sanitizedReportData);
        
        if (!htmlContent || htmlContent.length < 100) {
          throw new Error('Generated HTML content is too short or empty');
        }
        
        Logger.info('HTML content generated successfully', { htmlLength: htmlContent.length });
        
        // Launch browser with simplified, stable configuration
        browser = await puppeteer.launch({
          headless: true,
          args: [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-gpu',
            '--disable-web-security',
            '--disable-features=VizDisplayCompositor',
            '--run-all-compositor-stages-before-draw',
            '--no-first-run'
          ],
          timeout: 30000,
          protocolTimeout: 30000
        });

        // Set up browser error handling
        browser.on('disconnected', () => {
          Logger.warn('Browser disconnected unexpectedly');
        });

        page = await browser.newPage();
        
        // Set up page error handling with better cleanup
        page.on('error', (error) => {
          Logger.error('Page error:', error);
        });
        
        page.on('pageerror', (error) => {
          Logger.error('Page JavaScript error:', error);
        });
        
        // Set a reasonable viewport
        await page.setViewport({ width: 1200, height: 1600 });

        // Set content with timeout protection
        const contentTimeout = 20000;
        await page.setContent(htmlContent, { 
          waitUntil: 'networkidle0',
          timeout: contentTimeout
        });
        
        // Wait for fonts and external resources to load
        await new Promise(resolve => setTimeout(resolve, 3000));
        
        // Evaluate if the content is properly loaded
        const contentLength = await page.evaluate(() => {
          const d = globalThis.document;
          return d && d.body ? d.body.innerText.length : 0;
        });
        if (contentLength < 100) {
          throw new Error(`Page content appears to be incomplete (${contentLength} characters)`);
        }
        
        Logger.info('Page content set, generating PDF...');
        
        // Generate PDF with conservative timeout
        const pdfBuffer = await page.pdf({
          format: 'A4',
          printBackground: true,
          margin: {
            top: '20mm',
            right: '15mm',
            bottom: '20mm',
            left: '15mm'
          },
          timeout: 25000,
          preferCSSPageSize: false
        });

        // Clean up resources properly
        try {
          await page.close();
          page = null;
        } catch (pageCloseError) {
          Logger.warn('Error closing page:', pageCloseError.message);
        }
        
        try {
          await browser.close();
          browser = null;
        } catch (browserCloseError) {
          Logger.warn('Error closing browser:', browserCloseError.message);
        }
        
        if (!pdfBuffer || pdfBuffer.length === 0) {
          throw new Error('Generated PDF buffer is empty');
        }
        
        // Validate PDF buffer starts with PDF header (%PDF = 0x25504446)
        const isPDF = pdfBuffer[0] === 0x25 && pdfBuffer[1] === 0x50 && 
                     pdfBuffer[2] === 0x44 && pdfBuffer[3] === 0x46;
        if (!isPDF) {
          throw new Error('Generated buffer is not a valid PDF file');
        }
        
        // Check minimum PDF size (should be at least a few KB for a real PDF)
        if (pdfBuffer.length < 1024) {
          throw new Error(`Generated PDF is too small (${pdfBuffer.length} bytes), likely corrupted`);
        }
        
        Logger.info('PDF generated and validated successfully', { 
          pdfSize: pdfBuffer.length, 
          attempt
        });
        
        return pdfBuffer;
        
      } catch (error) {
        Logger.error(`PDF generation attempt ${attempt} failed:`, error);
        
        // Aggressive cleanup on error
        if (page && !page.isClosed()) {
          try {
            await page.close();
          } catch (closeError) {
            Logger.error('Error closing page:', closeError.message);
          }
        }
        
        if (browser && browser.isConnected()) {
          try {
            await browser.close();
          } catch (closeError) {
            Logger.error('Error closing browser:', closeError.message);
          }
        }
        
        // If this is the last attempt, throw the error
        if (attempt === maxRetries) {
          throw new Error(`Failed to generate PDF report after ${maxRetries} attempts: ${error.message}`);
        }
        
        // Wait before retrying with exponential backoff
        const retryDelay = Math.min(attempt * 3000, 10000); // 3s, 6s, max 10s
        Logger.info(`Retrying PDF generation in ${retryDelay}ms...`);
        await new Promise(resolve => setTimeout(resolve, retryDelay));
      }
    }
  }

  async testPDFGeneration() {
    Logger.info('Testing PDF generation with minimal content');
    let browser = null;
    let page = null;
    
    try {
      const testHTML = `
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="UTF-8">
          <title>PDF Test</title>
          <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            h1 { color: #333; }
            p { margin: 10px 0; }
          </style>
        </head>
        <body>
          <h1>PDF Generation Test</h1>
          <p>This is a test PDF to verify that PDF generation is working correctly.</p>
          <p>Generated at: ${new Date().toISOString()}</p>
          <p>If you can see this content in a PDF file, the PDF generation system is working.</p>
        </body>
        </html>
      `;
      
      browser = await puppeteer.launch({
        headless: true,
        args: ['--no-sandbox', '--disable-setuid-sandbox', '--disable-dev-shm-usage'],
        timeout: 15000
      });

      page = await browser.newPage();
      await page.setViewport({ width: 800, height: 600 });
      await page.setContent(testHTML, { waitUntil: 'networkidle0', timeout: 10000 });
      
      const pdfBuffer = await page.pdf({
        format: 'A4',
        printBackground: true,
        margin: { top: '20mm', right: '15mm', bottom: '20mm', left: '15mm' }
      });

      await page.close();
      await browser.close();
      
      // Validate PDF
      if (!pdfBuffer || pdfBuffer.length === 0) {
        throw new Error('Test PDF buffer is empty');
      }
      
      // Check if buffer starts with PDF magic bytes (25 50 44 46 = %PDF)
      const isPDF = pdfBuffer[0] === 0x25 && pdfBuffer[1] === 0x50 && 
                   pdfBuffer[2] === 0x44 && pdfBuffer[3] === 0x46;
      
      Logger.info('PDF buffer validation', { 
        pdfSize: pdfBuffer.length,
        isPDF: isPDF,
        firstBytes: Array.from(pdfBuffer.slice(0, 10)),
        isBuffer: Buffer.isBuffer(pdfBuffer)
      });
      
      if (!isPDF) {
        throw new Error(`Test PDF buffer is not valid. First bytes: ${Array.from(pdfBuffer.slice(0, 10))}`);
      }
      
      Logger.info('PDF test successful', { pdfSize: pdfBuffer.length });
      return pdfBuffer;
      
    } catch (error) {
      Logger.error('PDF test failed:', error);
      if (page && !page.isClosed()) await page.close();
      if (browser && browser.isConnected()) await browser.close();
      throw error;
    }
  }

  async generatePDFReportSimple(reportData) {
    let browser = null;
    let page = null;
    
    try {
      Logger.info('Starting simple PDF generation', { reportId: reportData.id });
      
      const sanitizedReportData = this.sanitizeReportData(reportData);
      const htmlContent = this.generateHTMLReport(sanitizedReportData);
      
      if (!htmlContent || htmlContent.length < 100) {
        throw new Error('Generated HTML content is too short or empty');
      }
      
      // Use minimal Puppeteer configuration for maximum compatibility
      browser = await puppeteer.launch({
        headless: true,
        args: [
          '--no-sandbox',
          '--disable-setuid-sandbox',
          '--disable-dev-shm-usage',
          '--disable-gpu'
        ],
        timeout: 25000,
        protocolTimeout: 25000
      });

      page = await browser.newPage();
      
      // Set reasonable viewport for simple generation
      await page.setViewport({ width: 1024, height: 1400 });
      
      await page.setContent(htmlContent, { 
        waitUntil: 'networkidle0',
        timeout: 20000 
      });
      
      // Wait for content and fonts to load
      await new Promise(resolve => setTimeout(resolve, 2000));
      
      // Validate content loaded properly
      const contentLength = await page.evaluate(() => {
        const d = globalThis.document;
        return d && d.body ? d.body.innerText.length : 0;
      });
      if (contentLength < 50) {
        throw new Error(`Page content appears incomplete (${contentLength} characters)`);
      }
      
      const pdfBuffer = await page.pdf({
        format: 'A4',
        printBackground: true,
        margin: {
          top: '15mm',
          right: '10mm',
          bottom: '15mm',
          left: '10mm'
        },
        timeout: 20000,
        preferCSSPageSize: false
      });

      // Clean up resources
      try {
        await page.close();
        page = null;
      } catch (pageCloseError) {
        Logger.warn('Error closing page in simple PDF generation:', pageCloseError.message);
      }
      
      try {
        await browser.close();
        browser = null;
      } catch (browserCloseError) {
        Logger.warn('Error closing browser in simple PDF generation:', browserCloseError.message);
      }
      
      if (!pdfBuffer || pdfBuffer.length === 0) {
        throw new Error('Generated PDF buffer is empty');
      }
      
      // Validate PDF buffer starts with PDF header (%PDF = 0x25504446)
      const isPDF = pdfBuffer[0] === 0x25 && pdfBuffer[1] === 0x50 && 
                   pdfBuffer[2] === 0x44 && pdfBuffer[3] === 0x46;
      if (!isPDF) {
        throw new Error('Generated buffer is not a valid PDF file');
      }
      
      if (pdfBuffer.length < 1024) {
        throw new Error(`Generated PDF is too small (${pdfBuffer.length} bytes), likely corrupted`);
      }
      
      Logger.info('Simple PDF generated and validated successfully', { 
        pdfSize: pdfBuffer.length
      });
      return pdfBuffer;
      
    } catch (error) {
      Logger.error('Simple PDF generation failed:', error);
      
      // Clean up resources on error
      if (page && !page.isClosed()) {
        try {
          await page.close();
        } catch (closeError) {
          Logger.error('Error closing page in simple PDF generation:', closeError.message);
        }
      }
      
      if (browser && browser.isConnected()) {
        try {
          await browser.close();
        } catch (closeError) {
          Logger.error('Error closing browser in simple PDF generation:', closeError.message);
        }
      }
      
      throw error;
    }
  }

  generateHTMLReport(reportData, pdfStyling = false) {
    try {
      Logger.info('Generating HTML report', { reportId: reportData.id });
      
      // Sanitize data if not already sanitized
      const sanitizedData = reportData.metadata ? reportData : this.sanitizeReportData(reportData);
      
      const {
        title, target, command, vulnerabilities, extractedData,
        recommendations, scanDuration, metadata, outputFiles
      } = sanitizedData;

      const severityCriteria = (metadata && metadata.severityCriteria) || this.getSeverityCriteriaOverview();
      const severityOrder = ['critical', 'high', 'medium', 'low', 'informational'];
      const orderedSeverityKeys = Object.keys(severityCriteria || {}).sort((a, b) => {
        const ai = severityOrder.indexOf(a.toLowerCase());
        const bi = severityOrder.indexOf(b.toLowerCase());
        const aIndex = ai === -1 ? severityOrder.length + a.localeCompare(b) : ai;
        const bIndex = bi === -1 ? severityOrder.length + b.localeCompare(a) : bi;
        return aIndex - bIndex;
      });
      const severityCardsHtml = orderedSeverityKeys
        .map((key) => {
          const info = severityCriteria[key];
          if (!info) return '';
          const titleLabel = info.label || key.charAt(0).toUpperCase() + key.slice(1);
          const summary = info.summary || '';
          const detail = info.detail || '';
          const impacts = Array.isArray(info.impacts) && info.impacts.length
            ? `<ul class="severity-impacts">${info.impacts.map(impact => `<li>${impact}</li>`).join('')}</ul>`
            : '';
          const techniques = Array.isArray(info.techniques) && info.techniques.length
            ? `<div class="severity-techniques"><strong>Techniques:</strong> ${info.techniques.join(', ')}</div>`
            : '';
          return `
            <div class="severity-card severity-${key.toLowerCase()}">
              <h3>${titleLabel}</h3>
              ${summary ? `<p class="severity-summary">${summary}</p>` : ''}
              ${detail ? `<p class="severity-detail">${detail}</p>` : ''}
              ${impacts}
              ${techniques}
            </div>
          `;
        })
        .filter(Boolean)
        .join('');
      const severitySection = severityCardsHtml
        ? `
            <div class="section severity-criteria">
              <h2>How we grade severity</h2>
              <p class="severity-intro">Severity ratings reflect what SQLMap actually proved during the scan. Critical findings mean stacked (multi-statement) execution was confirmed, which enables data tampering and destructive changes. High findings confirm controllable single statements that expose data or logic through boolean/time-based, error-based, union-based, or classical payloads.</p>
              <div class="severity-grid">
                ${severityCardsHtml}
              </div>
            </div>
          `
        : '';

      const humanizeDuration = (ms) => {
        if (typeof ms !== 'number' || !isFinite(ms) || ms < 0) return 'N/A';
        const sec = Math.floor(ms / 1000);
        const h = Math.floor(sec / 3600);
        const m = Math.floor((sec % 3600) / 60);
        const s = sec % 60;
        if (h > 0) return `${h}h ${m}m ${s}s`;
        if (m > 0) return `${m}m ${s}s`;
        return `${s}s`;
      };
      const scanDurationText = humanizeDuration(scanDuration);

      const riskScore = this.calculateRiskScore(vulnerabilities.findings || []);
      const riskLevel = this.getRiskLevel(riskScore);
      const riskColor = {
        'Critical': '#e74c3c',
        'High': '#e67e22',
        'Medium': '#f1c40f',
        'Low': '#2ecc71',
        'Informational': '#3498db'
      }[riskLevel] || '#95a5a6';

    // Derive an overall verdict for user-friendly summary
    const overallVerdict = this.determineOverallVerdict(vulnerabilities, extractedData);

    const getSeverityColor = (severity) => {
      switch(severity.toLowerCase()) {
        case 'critical': return '#e74c3c';
        case 'high': return '#e67e22';
        case 'medium': return '#f1c40f';
        case 'low': return '#2ecc71';
        default: return '#95a5a6';
      }
    };

    // Helpers for UI rendering
    // Derive status with evidence-driven upgrade to "confirmed"
    const deriveStatus = (v) => {
      const evText = Array.isArray(v.evidence) ? v.evidence.map(e => e.content || '').join('\n') : '';
      const hasInjectableCue = /(GET|POST|PUT|DELETE)\s+parameter\s+['"`][^'"`\s]+['"`]\s+is\s+[^\n]*?injectable/i.test(evText);
      const hasInjectionPointsCue = /sqlmap\s+identified\s+the\s+following\s+injection\s+point/i.test(evText);
      const hasTriad = /Parameter:\s*[^\s(]+\s*\((GET|POST|PUT|DELETE)\)/i.test(evText) && /(Type:|Title:|Payload:)/i.test(evText);
      const evidenceConfirmed = hasInjectableCue || hasInjectionPointsCue || hasTriad;

      if (v.status) return v.status;
      if (evidenceConfirmed) return 'confirmed';
      if (v.confidenceLabel === 'Confirmed') return 'confirmed';
      if (v.confidenceLabel === 'Likely' || v.confidenceLabel === 'Suspected') return 'suspected';
      return 'tested';
    };

    // Extract parameter and method from common sqlmap evidence lines
    const getParamMethodFromEvidence = (evidence = []) => {
      try {
        // Preferred: "Parameter: name (METHOD)"
        let line = evidence.find(ev => /Parameter:\s*[^\s(]+\s*\((GET|POST|PUT|DELETE)\)/i.test(ev.content));
        if (line) {
          const m = line.content.match(/Parameter:\s*([^\s(]+)\s*\((GET|POST|PUT|DELETE)\)/i);
          if (m) return { name: m[1], method: m[2] };
        }
        // Also support: "POST parameter 'name' is ... injectable"
        line = evidence.find(ev => /(GET|POST|PUT|DELETE)\s+parameter\s+['"`]([^'"`\s]+)['"`]\s+is\s+[^\n]*?injectable/i.test(ev.content));
        if (line) {
          const m = line.content.match(/(GET|POST|PUT|DELETE)\s+parameter\s+['"`]([^'"`\s]+)['"`]\s+is\s+[^\n]*?injectable/i);
          if (m) return { name: m[2], method: m[1] };
        }
        return null;
      } catch { return null; }
    };
    const getPayloadFromEvidence = (evidence = []) => {
      const row = evidence.find(ev => /Payload:/i.test(ev.content));
      if (!row) return null;
      const raw = row.content.replace(/^.*?Payload:\s*/i, '');
      const max = 400;
      return raw.length > max ? raw.slice(0, max) + ' …' : raw;
    };

    // Techniques summary table
    const techniquesRows = (vulnerabilities.findings || []).map(v => {
      const st = deriveStatus(v);
      const pm = getParamMethodFromEvidence(v.evidence) || { name: v.parameter || 'N/A', method: '' };
      return `
        <tr>
          <td>${v.type || 'SQL Injection'}</td>
          <td><code>${pm.name || 'N/A'}</code>${pm.method ? ` <span class="badge">${pm.method}</span>` : ''}</td>
          <td><span class="status ${st}">${st}</span></td>
          <td>${(v.confidenceLabel || 'Unknown')}${typeof v.confidenceScore === 'number' ? ` (${(v.confidenceScore*100).toFixed(0)}%)` : ''}</td>
        </tr>
      `;
    }).join('');

    const vulnerabilitiesHTML = (vulnerabilities.findings || []).map(vuln => {
      const payload = getPayloadFromEvidence(vuln.evidence);
      const st = deriveStatus(vuln);
      const pm = getParamMethodFromEvidence(vuln.evidence);
      const paramLabel = pm?.name || vuln.parameter || 'N/A';
      const methodLabel = pm?.method ? ` (${pm.method})` : '';
      // Simple, non-technical confidence explanation
      const confidenceWhy = (() => {
        const evText = Array.isArray(vuln.evidence) ? vuln.evidence.map(e => e.content || '').join('\n') : '';
        if (/(GET|POST|PUT|DELETE)\s+parameter\s+['"`][^'"`\s]+['"`]\s+is\s+[^\n]*?injectable/i.test(evText) || /sqlmap\s+identified\s+the\s+following\s+injection\s+point/i.test(evText)) {
          return 'Tool explicitly proved this input can be controlled to affect the database.';
        }
        if (/(Type:|Title:|Payload:)/i.test(evText)) {
          return 'Tool showed the technique details and a working test value (payload).';
        }
        return 'Tool saw signs that look like injection, but did not fully prove it.';
      })();
      return `
      <div class="vulnerability-card">
        <div class="vulnerability-header" style="border-left-color: ${getSeverityColor(vuln.severity)};">
          <h4>${vuln.type}</h4>
          <span class="severity" style="background-color: ${getSeverityColor(vuln.severity)};">${vuln.severity}</span>
        </div>
        <div class="vulnerability-body">
          <p><strong>Parameter:</strong> <code>${paramLabel}</code>${methodLabel}</p>
          <p><strong>Status:</strong> <span class="status ${st}">${st}</span> · <strong>Confidence:</strong> ${vuln.confidenceLabel || 'Unknown'}${typeof vuln.confidenceScore === 'number' ? ` (${(vuln.confidenceScore*100).toFixed(0)}%)` : ''}</p>
          <p><strong>Description:</strong> ${vuln.description}</p>
          <p><strong>Impact:</strong> ${vuln.impact || 'Not specified'}</p>
          <p><strong>Why this is shown:</strong> ${vuln.why || confidenceWhy}</p>
          ${payload ? `<details class="details"><summary>Show payload (sanitized)</summary><pre class="payload"><code>${payload}</code></pre></details>` : ''}
          ${(vuln.evidence && vuln.evidence.length) ? `<details class="details"><summary>Show evidence</summary>${vuln.evidence.slice(0,12).map(ev => `<div class="evidence-row"><span class="line">L${ev.line}</span><code>${ev.content}</code></div>`).join('')}</details>` : ''}
          <h5>Remediation</h5>
          <ul>
            ${(vuln.remediation || []).map(rec => `<li>${rec}</li>`).join('')}
          </ul>
        </div>
      </div>`;
    }).join('');

    return `
      <!DOCTYPE html>
      <html>
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>${title}</title>
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;700&display=swap" rel="stylesheet">
        <style>
          :root { --bg:#f4f7f9; --fg:#333; --muted:#7f8c8d; --panel:#ffffff; --primary:#2c3e50; --accent:#3498db; --ok:#2ecc71; --warn:#f1c40f; --high:#e67e22; --crit:#e74c3c; --info:#3498db; }
          * { box-sizing: border-box; }
          body { font-family: 'Roboto', sans-serif; margin: 0; padding: 0; background-color: ${pdfStyling ? '#fff' : 'var(--bg)'}; color: var(--fg); }
          .report-container { max-width: 1100px; margin: ${pdfStyling ? '0 auto' : '20px auto'}; background: var(--panel); border-radius: ${pdfStyling ? '0' : '12px'}; box-shadow: ${pdfStyling ? 'none' : '0 8px 24px rgba(0,0,0,0.08)'}; overflow: hidden; }
          .report-header { background: #2c3e50; color: #fff; padding: 40px; text-align: center; }
          .report-header h1 { margin: 0; font-size: 2.8em; }
          .report-header p { margin: 5px 0 0; font-size: 1.2em; color: #bdc3c7; }
          .main-content { padding: 24px; }
          .summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 24px; }
          .summary-item { background: #ecf0f1; padding: 18px; border-radius: 10px; text-align: center; display:flex; flex-direction:column; justify-content:center; align-items:center; gap:8px; min-height:120px; }
          .summary-item h3 { margin: 0; color: #2980b9; font-size: 1.05em; word-break: break-word; overflow-wrap:anywhere; max-width:100%; }
          .summary-item p, .summary-item .score { font-weight: 700; font-size: 1.6em; color: #2c3e50; margin:0; word-break: break-word; overflow-wrap:anywhere; line-height:1.2; max-width:100%; }
          .risk-score .score, .risk-score .level { color: ${riskColor}; }
          .section { margin-bottom: 30px; }
          .section h2 { font-size: 2em; color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-bottom: 20px; }
          .vulnerability-card { border: 1px solid #ddd; border-radius: 8px; margin-bottom: 20px; overflow: hidden; }
          .vulnerability-header { display: flex; justify-content: space-between; align-items: center; padding: 15px; border-left: 5px solid; }
          .vulnerability-header h4 { margin: 0; font-size: 1.4em; }
          .vulnerability-body { padding: 15px; }
          .severity { color: #fff; padding: 5px 12px; border-radius: 15px; font-weight: 700; font-size: 0.9em; }
          ul { padding-left: 20px; }
          li { margin-bottom: 8px; }
          code { background: #e8e8e8; padding: 3px 6px; border-radius: 3px; font-family: 'Courier New', monospace; font-size: 0.95em; word-break: break-word; overflow-wrap:anywhere; max-width:100%; display:inline-block; }
          .report-footer { text-align: center; padding: 20px; font-size: 0.9em; color: #7f8c8d; background: #ecf0f1; }
          ${pdfStyling ? '.pdf-fallback-notice { background: #fffbe6; border: 1px solid #ffd700; border-radius: 5px; padding: 15px; margin: 20px 0; text-align: center; color: #b7950b; } @media print { .pdf-fallback-notice { display: none; } }' : ''}

          .severity-criteria { background:#f8fafc; border-radius:12px; padding:18px; border:1px solid #e1e8f0; }
          .severity-intro { color:#4b5563; margin-bottom:16px; }
          .severity-grid { display:grid; grid-template-columns: repeat(auto-fit, minmax(240px,1fr)); gap:16px; }
          .severity-card { border-radius:10px; padding:16px; background:#fff; border:1px solid #dbe4f0; box-shadow:0 1px 2px rgba(15,23,42,0.05); }
          .severity-card h3 { margin-top:0; margin-bottom:8px; }
          .severity-card p { margin:0 0 8px; color:#334155; }
          .severity-summary { font-weight:600; }
          .severity-detail { font-size:0.95em; }
          .severity-impacts { margin:0 0 8px; padding-left:20px; color:#1f2937; }
          .severity-techniques { font-size:0.9em; color:#475569; }

          .severity-critical { border-left:5px solid #e74c3c; }
          .severity-high { border-left:5px solid #e67e22; }
          .severity-medium { border-left:5px solid #f1c40f; }
          .severity-low { border-left:5px solid #2ecc71; }
          .severity-informational { border-left:5px solid #3498db; }

          /* New UI additions */
          .verdict { display:flex; flex-wrap:wrap; gap:10px; align-items:center; background:#ecf0f1; padding:16px; border-radius:10px; }
          .badge { display:inline-block; background:#dde6ee; color:#2c3e50; padding:2px 8px; border-radius:999px; font-size:12px; margin-left:6px; }
          .status { text-transform: capitalize; padding:2px 8px; border-radius:999px; font-size:12px; }
          .status.confirmed { background:#eaf7ff; color:#0b6bab; }
          .status.suspected { background:#fff7e6; color:#a66a00; }
          .status.tested { background:#f0f0f0; color:#555; }
          .status.exploited { background:#ffecec; color:#a30000; }
          .tech-table { width:100%; border-collapse: collapse; }
          .tech-table th, .tech-table td { border-bottom:1px solid #eee; padding:10px; text-align:left; }
          .tech-table th { background:#f8fafc; font-weight:600; }
          .table-wrap { overflow:auto; border:1px solid #eee; border-radius:8px; }
          .details summary { cursor:pointer; color:#2c3e50; font-weight:600; margin:8px 0; }
          .confidence-note { background:#f1f5f9; border:1px solid #d5e3f6; border-radius:10px; padding:12px 16px; }
          .confidence-note summary { background:#e7f1ff; border-radius:8px; margin:-12px -16px 12px; padding:12px 16px; }
          .confidence-note[open] summary { border-bottom:1px solid #d5e3f6; border-bottom-left-radius:0; border-bottom-right-radius:0; }
          .confidence-note p { margin:0 0 12px; color:#334155; }
          .confidence-note ul { margin:0 0 12px; padding-left:20px; }
          .payload { background:#f7f7f7; padding:12px; border-radius:8px; overflow:auto; }
          .evidence-row { display:flex; gap:10px; align-items:flex-start; padding:6px 0; border-bottom:1px dashed #eee; }
          .evidence-row .line { color:#7f8c8d; min-width:40px; font-family:monospace; }

          /* Responsive tweaks */
          @media (max-width: 768px) {
            .summary-item { min-height:auto; padding:16px; }
            .summary-item p, .summary-item .score { font-size: 1.35em; }
          }

          @media (max-width: 640px) {
            .report-header h1 { font-size: 2em; }
            .section h2 { font-size: 1.5em; }
            .summary-grid { grid-template-columns: minmax(0, 1fr); }
            .summary-item { align-items:flex-start; text-align:left; }
            .summary-item p, .summary-item .score { font-size: 1.25em; }
          }
        </style>
      </head>
      <body>
        <div class="report-container">
          <div class="report-header">
            <h1>Security Assessment Report</h1>
            <p>${title}</p>
          </div>
          
          ${pdfStyling ? '<div class="pdf-fallback-notice"><strong>Note:</strong> PDF generation encountered issues. This HTML file contains the same report data and can be printed to PDF using your browser (Ctrl+P → Save as PDF).</div>' : ''}
          
          <div class="main-content">
            <div class="summary-grid">
              <div class="summary-item">
                <h3>Target</h3>
                <p>${target}</p>
              </div>
              <div class="summary-item">
                <h3>Scan Date</h3>
                <p>${new Date(metadata.generatedAt).toLocaleDateString()}</p>
              </div>
              <div class="summary-item risk-score">
                <h3>Overall Risk</h3>
                <p class="score level">${riskLevel}</p>
              </div>
              <div class="summary-item">
                <h3>Vulnerabilities</h3>
                <p>${vulnerabilities.total}</p>
              </div>
              <div class="summary-item">
                <h3>Scan Duration</h3>
                <p>${scanDurationText}</p>
              </div>
            </div>

            ${severitySection}

            <div class="section">
              <h2>Overall verdict</h2>
              <div class="verdict">
                <strong>Verdict:</strong> <span class="status ${overallVerdict.level.toLowerCase()}">${overallVerdict.level}</span>
                <span class="badge">evidence-driven</span>
                <div style="flex-basis:100%;height:0"></div>
                <div>${overallVerdict.rationale}</div>
              </div>
            </div>

            <div class="section">
              <h2>Techniques summary</h2>
              <div class="table-wrap">
                <table class="tech-table" role="table" aria-label="Techniques summary">
                  <thead>
                    <tr><th>Technique</th><th>Parameter</th><th>Status</th><th>Confidence</th></tr>
                  </thead>
                  <tbody>
                    ${techniquesRows || '<tr><td colspan="4">No techniques recorded.</td></tr>'}
                  </tbody>
                </table>
              </div>
            </div>

            <div class="section">
              <h2>Confidence scoring</h2>
              <details class="details confidence-note">
                <summary>Why confirmed findings can show 90%–99% confidence</summary>
                <p>Each technique SQLMap tries (error-based, boolean, time delay, union, stacked, etc.) gets its own confidence score. Even when a payload works, the tool keeps a little margin because different checks can return noisy signals.</p>
                <ul>
                  <li><strong>Multiple techniques:</strong> Scores reflect the reliability of the specific method, not a single global verdict.</li>
                  <li><strong>Protection against false positives:</strong> The remaining few percent covers edge cases like flaky responses or defensive systems altering replies.</li>
                  <li><strong>Anything above ~90% is treated as confirmed:</strong> In practice, these findings have already been demonstrated with working evidence.</li>
                </ul>
                <p>If a score ever drops much lower, investigate manually before acting on the result.</p>
              </details>
            </div>

            <div class="section">
              <h2>Detailed Findings</h2>
              ${vulnerabilitiesHTML}
            </div>

            <div class="section">
              <h2>General Recommendations</h2>
              <ul>
                ${Array.isArray(recommendations) && recommendations.length
                  ? recommendations.map(r => `<li><strong>${r.title || 'Recommendation'}:</strong> ${r.description || ''}</li>`).join('')
                  : '<li>No recommendations available.</li>'}
              </ul>
            </div>

            <div class="section">
              <h2>Extracted Data</h2>
              ${(() => {
                const parts = [];
                if (Array.isArray(extractedData.databases) && extractedData.databases.length) {
                  parts.push(`
                    <h3>Databases</h3>
                    <ul>${extractedData.databases.map(db => `<li>${db}</li>`).join('')}</ul>
                  `);
                }
                if (Array.isArray(extractedData.tables) && extractedData.tables.length) {
                  parts.push(`
                    <h3>Tables</h3>
                    <ul>${extractedData.tables.map(t => `<li>${t}</li>`).join('')}</ul>
                  `);
                }
                if (Array.isArray(extractedData.users) && extractedData.users.length) {
                  parts.push(`
                    <h3>Users</h3>
                    <ul>${extractedData.users.map(u => `<li>${u}</li>`).join('')}</ul>
                  `);
                }
                if (extractedData.systemInfo && (extractedData.systemInfo.dbms || extractedData.systemInfo.version)) {
                  parts.push(`
                    <h3>System Info</h3>
                    <ul>
                      ${extractedData.systemInfo.dbms ? `<li>DBMS: ${Array.isArray(extractedData.systemInfo.dbms) ? extractedData.systemInfo.dbms.join(', ') : extractedData.systemInfo.dbms}</li>` : ''}
                      ${extractedData.systemInfo.version ? `<li>Version: ${extractedData.systemInfo.version}</li>` : ''}
                    </ul>
                  `);
                }
                if (Array.isArray(extractedData.csvFiles) && extractedData.csvFiles.length) {
                  parts.push(`
                    <h3>Dumped Files</h3>
                    <ul>${extractedData.csvFiles.map(f => `<li>${f.name} (${f.size} bytes)</li>`).join('')}</ul>
                  `);
                }
                if (!parts.length) {
                  return '<p>No structured data was extracted.</p>';
                }
                return parts.join('');
              })()}
            </div>

            ${outputFiles ? `
            <div class="section">
              <h2>Artifacts</h2>
              <ul>
                ${outputFiles.session ? `<li>Session: <code>${outputFiles.session}</code></li>` : ''}
                ${outputFiles.traffic ? `<li>Traffic log: <code>${outputFiles.traffic}</code></li>` : ''}
                ${outputFiles.results ? `<li>Results CSV: <code>${outputFiles.results}</code></li>` : ''}
              </ul>
            </div>
            ` : ''}

            <div class="section">
              <h2>Scan Command</h2>
              <code>${command}</code>
            </div>
          </div>
          <div class="report-footer">
            <p>Generated on ${new Date().toUTCString()}</p>
          </div>
        </div>
      </body>
      </html>
    `;
    } catch (error) {
      Logger.error('Error generating HTML report:', error);
      throw new Error(`Failed to generate HTML report: ${error.message}`);
    }
  }

  generateMarkdownReport(reportData) {
    try {
      // Sanitize data if not already sanitized
      const sanitizedData = reportData.metadata ? reportData : this.sanitizeReportData(reportData);
      const severityCriteria = (sanitizedData.metadata && sanitizedData.metadata.severityCriteria) || this.getSeverityCriteriaOverview();
      const order = ['critical', 'high', 'medium', 'low', 'informational'];
      /** @type {Array<{ key: string, label: string, block: string }>} */
      const severityBlocks = Object.entries(severityCriteria || {}).reduce((acc, [rawKey, info]) => {
        const key = rawKey.toLowerCase();
        const label = info?.label || key.charAt(0).toUpperCase() + key.slice(1);
        const summary = info?.summary;
        const detail = info?.detail;
        const impacts = Array.isArray(info?.impacts) ? info.impacts.filter(Boolean) : [];
        const techniques = Array.isArray(info?.techniques) ? info.techniques.filter(Boolean) : [];
        const contentParts = [];
        if (summary) contentParts.push(summary);
        if (detail) contentParts.push(detail);
        if (impacts.length) {
          contentParts.push('**Impact if exploited:**');
          contentParts.push(impacts.map(impact => `- ${impact}`).join('\n'));
        }
        if (techniques.length) {
          contentParts.push(`**Includes techniques:** ${techniques.join(', ')}`);
        }
        const block = contentParts.filter(Boolean).join('\n\n');
        if (block) acc.push({ key, label, block });
        return acc;
      }, []);

      severityBlocks.sort((a, b) => {
        const ai = order.indexOf(a.key);
        const bi = order.indexOf(b.key);
        const aIndex = ai === -1 ? order.length + a.key.localeCompare(b.key) : ai;
        const bIndex = bi === -1 ? order.length + b.key.localeCompare(a.key) : bi;
        return aIndex - bIndex;
      });

      const severitySection = severityBlocks.length
        ? severityBlocks.map(block => `### ${block.label}\n${block.block}`).join('\n\n')
        : '_Severity metadata unavailable._';

      return `# ${sanitizedData.title}

**Target:** ${sanitizedData.target}
**Generated:** ${new Date(sanitizedData.metadata.generatedAt).toLocaleString()}

## Severity grading

Severity ratings capture what SQLMap actually proved during the scan. Critical findings confirm stacked multi-statement execution (data tampering risk). High findings confirm controllable single statements that expose sensitive data or logic.

${severitySection}

## Vulnerabilities (${sanitizedData.vulnerabilities.total})

${(sanitizedData.vulnerabilities.findings || []).map(v => `
### ${v.type} (${v.severity})
${v.description}

**Remediation:**
${(v.remediation || []).map(r => `- ${r}`).join('\n')}
`).join('')}

## Recommendations

${(sanitizedData.recommendations || []).map(r => `
### ${r.title || 'Recommendation'}
${r.description || 'No description available'}
`).join('')}
`;
    } catch (error) {
      Logger.error('Error generating Markdown report:', error);
      throw new Error(`Failed to generate Markdown report: ${error.message}`);
    }
  }

  getContentType(format) {
    const contentTypes = {
      'json': 'application/json',
      'pdf': 'application/pdf',
      'html': 'text/html',
      'markdown': 'text/markdown',
      'md': 'text/markdown',
      'csv': 'text/csv; charset=utf-8'
    };
    
    return contentTypes[format.toLowerCase()] || 'application/octet-stream';
  }
}

module.exports = ReportGenerator;