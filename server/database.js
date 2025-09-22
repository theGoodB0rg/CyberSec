const sqlite3 = require('sqlite3').verbose();
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const Logger = require('./utils/logger');

class Database {
  constructor(dbPath) {
    this.dbPath = dbPath;
    this.db = null;
    this.init();
  }

  init() {
    // Ensure directory exists
    const dir = path.dirname(this.dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    this.db = new sqlite3.Database(this.dbPath, (err) => {
      if (err) {
        console.error('Error opening database:', err);
        throw err;
      }
      console.log('Connected to SQLite database');
      this.createTables();
    });
  }

  createTables() {
    const createScansTable = `
      CREATE TABLE IF NOT EXISTS scans (
        id TEXT PRIMARY KEY,
        target TEXT NOT NULL,
        options TEXT,
        scan_profile TEXT,
        user_id TEXT,
        org_id TEXT,
        output_dir TEXT,
        status TEXT DEFAULT 'pending',
        start_time TEXT,
        end_time TEXT,
        exit_code INTEGER,
        error TEXT,
        output TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `;

    const createReportsTable = `
      CREATE TABLE IF NOT EXISTS reports (
        id TEXT PRIMARY KEY,
        scan_id TEXT,
        title TEXT,
        target TEXT,
        command TEXT,
        vulnerabilities TEXT,
        extracted_data TEXT,
        recommendations TEXT,
        scan_duration INTEGER,
        status TEXT,
        user_id TEXT,
        org_id TEXT,
        metadata TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans (id)
      )
    `;

    const createUsersTable = `
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT DEFAULT 'user',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login_at DATETIME
      )
    `;

    const createUsageCountersTable = `
      CREATE TABLE IF NOT EXISTS usage_counters (
        user_id TEXT NOT NULL,
        period TEXT NOT NULL, -- e.g., '2025-09' (YYYY-MM)
        scans_started INTEGER DEFAULT 0,
        scans_completed INTEGER DEFAULT 0,
        total_runtime_ms INTEGER DEFAULT 0,
        cancel_count INTEGER DEFAULT 0,
        duplicate_window_retries INTEGER DEFAULT 0,
        PRIMARY KEY (user_id, period)
      )
    `;

    const createVerifiedTargetsTable = `
      CREATE TABLE IF NOT EXISTS verified_targets (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        org_id TEXT,
        hostname TEXT NOT NULL,
        method TEXT NOT NULL, -- 'http-file' | 'dns-txt'
        token TEXT NOT NULL,
        verified_at TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `;

    const createSettingsTable = `
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `;

    const createScanEventsTable = `
      CREATE TABLE IF NOT EXISTS scan_events (
        id TEXT PRIMARY KEY,
        scan_id TEXT NOT NULL,
        user_id TEXT,
        org_id TEXT,
        event_type TEXT NOT NULL,
        at DATETIME DEFAULT CURRENT_TIMESTAMP,
        metadata TEXT,
        FOREIGN KEY (scan_id) REFERENCES scans (id)
      )
    `;

    const createJobsTable = `
      CREATE TABLE IF NOT EXISTS jobs (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL,
        org_id TEXT,
        status TEXT NOT NULL, -- scheduled | running | retrying | completed | failed | canceled
        run_at DATETIME NOT NULL,
        retries INTEGER DEFAULT 0,
        max_retries INTEGER DEFAULT 3,
        last_error TEXT,
        scan_id TEXT, -- populated once started
        target TEXT NOT NULL,
        options TEXT,
        scan_profile TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `;

    const createReconParams = `
      CREATE TABLE IF NOT EXISTS recon_parameters (
        id TEXT PRIMARY KEY,
        scan_target TEXT,
        name TEXT,
        sources TEXT,
        methods TEXT,
        actions TEXT,
        types TEXT,
        observations INTEGER,
        reflected INTEGER,
        occurrences INTEGER,
        transformed INTEGER,
        length_delta INTEGER,
        name_length INTEGER,
        name_entropy REAL,
        base_latency_ms INTEGER,
        reflection_latency_ms INTEGER,
        priority_score REAL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `;

    const createReconPages = `
      CREATE TABLE IF NOT EXISTS recon_pages (
        id TEXT PRIMARY KEY,
        scan_target TEXT,
        url TEXT,
        parent_url TEXT,
        depth INTEGER,
        status INTEGER,
        content_type TEXT,
        fetch_time_ms INTEGER,
        discovered_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `;

    this.db.serialize(() => {
      this.db.run(createScansTable);
      this.db.run(createReportsTable);
  this.db.run(createSettingsTable);
  this.db.run(createUsageCountersTable);
  this.db.run(createVerifiedTargetsTable);
  this.db.run(createReconParams);
      this.db.run(createReconPages);
    this.db.run(createUsersTable);
      this.db.run(createScanEventsTable);
  this.db.run(createJobsTable);

      // Helpful indices
      this.db.run(`CREATE INDEX IF NOT EXISTS idx_scans_output_dir ON scans(output_dir)`);
      // New indexes to support multi-tenant filtering and lookups
      this.db.run(`CREATE INDEX IF NOT EXISTS idx_scans_user ON scans(user_id, created_at DESC)`);
      this.db.run(`CREATE INDEX IF NOT EXISTS idx_scans_org ON scans(org_id, created_at DESC)`);
      this.db.run(`CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status, created_at DESC)`);
      this.db.run(`CREATE INDEX IF NOT EXISTS idx_scans_target ON scans(target)`);
      this.db.run(`CREATE INDEX IF NOT EXISTS idx_reports_user ON reports(user_id, created_at DESC)`);
      this.db.run(`CREATE INDEX IF NOT EXISTS idx_reports_org ON reports(org_id, created_at DESC)`);
      this.db.run(`CREATE INDEX IF NOT EXISTS idx_scan_events_scan ON scan_events(scan_id, at)`);
      this.db.run(`CREATE INDEX IF NOT EXISTS idx_verified_targets_lookup ON verified_targets(hostname, user_id, org_id, verified_at)`);
  this.db.run(`CREATE INDEX IF NOT EXISTS idx_jobs_status_runat ON jobs(status, run_at)`);
  this.db.run(`CREATE INDEX IF NOT EXISTS idx_jobs_user ON jobs(user_id, status, run_at)`);

      // Attempt to add new columns if upgrading existing recon_parameters
      const alterCols = [
        'ADD COLUMN name_length INTEGER',
        'ADD COLUMN name_entropy REAL',
        'ADD COLUMN base_latency_ms INTEGER',
        'ADD COLUMN reflection_latency_ms INTEGER',
        'ADD COLUMN priority_score REAL'
      ];
      alterCols.forEach(stmt => {
        this.db.run(`ALTER TABLE recon_parameters ${stmt}`, (err) => {
          if (err && !/duplicate column/i.test(err.message)) {
            Logger.debug('Alter table recon_parameters skipped', { stmt, error: err.message });
          }
        });
      });
      // Ensure new usage counters exist when upgrading existing installations
      const usageAlters = [
        'ADD COLUMN cancel_count INTEGER DEFAULT 0',
        'ADD COLUMN duplicate_window_retries INTEGER DEFAULT 0'
      ];
      usageAlters.forEach(stmt => {
        this.db.run(`ALTER TABLE usage_counters ${stmt}`, (err) => {
          if (err && !/duplicate column/i.test(err.message)) {
            Logger.debug('Alter table usage_counters skipped', { stmt, error: err.message });
          }
        });
      });
      // Migrate scans/reports to include user and org columns if not present
      const migrateStatements = [
        { table: 'scans', stmt: 'ADD COLUMN user_id TEXT' },
        { table: 'scans', stmt: 'ADD COLUMN org_id TEXT' },
        { table: 'scans', stmt: 'ADD COLUMN output_dir TEXT' },
        { table: 'reports', stmt: 'ADD COLUMN user_id TEXT' },
        { table: 'reports', stmt: 'ADD COLUMN org_id TEXT' }
      ];
      migrateStatements.forEach(({ table, stmt }) => {
        this.db.run(`ALTER TABLE ${table} ${stmt}`,(err)=>{
          if (err && !/duplicate column/i.test(err.message)) {
            Logger.debug(`Alter table ${table} skipped`, { stmt, error: err.message });
          }
        });
      });
      // Populate legacy rows with placeholder user_id
      this.db.run(`UPDATE scans SET user_id = COALESCE(user_id, 'system') WHERE user_id IS NULL`, ()=>{});
      this.db.run(`UPDATE reports SET user_id = COALESCE(user_id, 'system') WHERE user_id IS NULL`, ()=>{});
      
      // Add metadata column if it doesn't exist (migration)
      this.db.run(`ALTER TABLE reports ADD COLUMN metadata TEXT`, (err) => {
        if (err) {
          if (err.message.includes('duplicate column name')) {
            Logger.info('Metadata column already exists in reports table');
          } else {
            Logger.error('Error adding metadata column:', err);
          }
        } else {
          Logger.info('Successfully added metadata column to reports table');
        }
      });
    });
  }

  // Scan operations
  async hasRecentSimilarScan(userId, target, windowSeconds = 10) {
    // Debounce identical targets per user within a short window to prevent accidental double starts
    return new Promise((resolve, reject) => {
      const sec = Math.max(1, Math.min(60, Number(windowSeconds) || 10));
      // Use SQLite datetime arithmetic to compare against current time
      const sql = `
        SELECT 1 FROM scans
        WHERE user_id = ? AND target = ?
          AND status IN ('running','pending')
          AND created_at >= datetime('now', '-${sec} seconds')
        LIMIT 1
      `;
      this.db.get(sql, [userId, target], (err, row) => {
        if (err) return reject(err);
        resolve(!!row);
      });
    });
  }

  async interruptRunningScans() {
    // Fetch scans currently marked as running, then mark them as interrupted.
    return new Promise((resolve, reject) => {
      this.db.all(`SELECT id, user_id, org_id, start_time FROM scans WHERE status = 'running'`, [], (err, rows) => {
        if (err) return reject(err);
        const now = new Date().toISOString();
        this.db.run(`UPDATE scans SET status = 'interrupted', end_time = ?, updated_at = ? WHERE status = 'running'`, [now, now], (uErr) => {
          if (uErr) return reject(uErr);
          resolve(rows || []);
        });
      });
    });
  }

  async logScanEvent({ id = uuidv4(), scan_id, user_id = 'system', org_id = null, event_type, at = new Date().toISOString(), metadata = {} }) {
    return new Promise((resolve, reject) => {
      try {
        const redacted = this.redactSensitive(metadata || {});
        const stmt = this.db.prepare(`
          INSERT INTO scan_events (id, scan_id, user_id, org_id, event_type, at, metadata)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `);
        stmt.run([id, scan_id, user_id, org_id, event_type, at, JSON.stringify(redacted)], function(err) {
          if (err) return reject(err);
          resolve(id);
        });
        stmt.finalize();
      } catch (e) {
        reject(e);
      }
    });
  }

  // Best-effort redaction of sensitive metadata before persisting events
  redactSensitive(value, seen = new WeakSet()) {
    const SENSITIVE_KEYS = [
      'cookie','cookies','authorization','auth','token','access_token','refresh_token','id_token',
      'secret','password','passwd','api_key','apikey','x-api-key','session','set-cookie','proxy-authorization'
    ];
    const MASK = '***redacted***';

    const maskString = (str) => {
      if (typeof str !== 'string') return str;
      // Mask common bearer tokens or long secrets while preserving small prefix
      if (/bearer\s+/i.test(str)) return str.replace(/(bearer\s+)([^\s]+)/i, (_, p1) => p1 + MASK);
      if (str.length > 32) return str.slice(0, 6) + '...' + MASK;
      return MASK;
    };

    const redactObject = (obj) => {
      if (obj === null) return null;
      if (typeof obj !== 'object') {
        return typeof obj === 'string' ? maskString(obj) : obj;
      }
      if (seen.has(obj)) return '[circular]';
      seen.add(obj);

      if (Array.isArray(obj)) {
        return obj.map((item) => this.redactSensitive(item, seen));
      }

      const out = {};
      for (const [k, v] of Object.entries(obj)) {
        const keyLower = String(k).toLowerCase();
        if (SENSITIVE_KEYS.includes(keyLower)) {
          out[k] = maskString(typeof v === 'string' ? v : JSON.stringify(v));
          continue;
        }
        // Headers object: redact sensitive header names
        if (keyLower === 'headers' && v && typeof v === 'object') {
          const hdrs = {};
          for (const [hk, hv] of Object.entries(v)) {
            const hkLower = String(hk).toLowerCase();
            if (SENSITIVE_KEYS.includes(hkLower)) {
              hdrs[hk] = maskString(typeof hv === 'string' ? hv : JSON.stringify(hv));
            } else {
              hdrs[hk] = this.redactSensitive(hv, seen);
            }
          }
          out[k] = hdrs;
          continue;
        }
        out[k] = this.redactSensitive(v, seen);
      }
      return out;
    };

    return redactObject(value);
  }

  async pruneScanEventsBefore(cutoffIso) {
    return new Promise((resolve, reject) => {
      const sql = 'DELETE FROM scan_events WHERE at < ?';
      this.db.run(sql, [cutoffIso], function(err) {
        if (err) return reject(err);
        resolve(this.changes || 0);
      });
    });
  }

  async getScanEventsForUser(scanId, userId, orgId = null, isAdmin = false, limit = 200, offset = 0) {
    return new Promise((resolve, reject) => {
      // Build query with ownership constraint
      let sql = `
        SELECT e.* FROM scan_events e
        JOIN scans s ON s.id = e.scan_id
        WHERE e.scan_id = ?
      `;
      const params = [scanId];
      if (!isAdmin) {
        if (orgId) {
          sql += ' AND s.org_id = ?';
          params.push(orgId);
        } else {
          sql += ' AND s.user_id = ?';
          params.push(userId);
        }
      }
      sql += ' ORDER BY e.at ASC LIMIT ? OFFSET ?';
      params.push(limit, offset);

      this.db.all(sql, params, (err, rows) => {
        if (err) return reject(err);
        const events = (rows || []).map(r => ({
          ...r,
          metadata: this.safeJson(r.metadata, {})
        }));
        resolve(events);
      });
    });
  }
  async createScan(scanData) {
    return new Promise((resolve, reject) => {
      const id = uuidv4();
      const { target, options, scanProfile, status, start_time, user_id = 'system', org_id = null, output_dir = null } = scanData;
      
      const stmt = this.db.prepare(`
        INSERT INTO scans (id, target, options, scan_profile, user_id, org_id, output_dir, status, start_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      stmt.run([
        id,
        target,
        JSON.stringify(options),
        scanProfile,
        user_id,
        org_id,
        output_dir,
        status,
        start_time
      ], function(err) {
        if (err) {
          reject(err);
        } else {
          resolve(id);
        }
      });

      stmt.finalize();
    });
  }

  async getScan(scanId) {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT * FROM scans WHERE id = ?',
        [scanId],
        (err, row) => {
          if (err) {
            reject(err);
          } else {
            if (row) {
              if (row.options) {
                row.options = JSON.parse(row.options);
              }
              // Provide camelCase aliases expected by frontend
              row.createdAt = row.created_at;
              row.updatedAt = row.updated_at;
              row.startTime = row.start_time;
              row.endTime = row.end_time;
            }
            resolve(row);
          }
        }
      );
    });
  }

  async getScans(limit = 50, offset = 0) {
    return new Promise((resolve, reject) => {
      this.db.all(
        'SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?',
        [limit, offset],
        (err, rows) => {
          if (err) {
            reject(err);
          } else {
            const scans = rows.map(row => {
              if (row.options) {
                row.options = JSON.parse(row.options);
              }
              // Add camelCase aliases
              row.createdAt = row.created_at;
              row.updatedAt = row.updated_at;
              row.startTime = row.start_time;
              row.endTime = row.end_time;
              return row;
            });
            resolve(scans);
          }
        }
      );
    });
  }

  async getScansForUser(userId, orgId = null, isAdmin = false, limit = 50, offset = 0) {
    return new Promise((resolve, reject) => {
      let query = 'SELECT * FROM scans';
      const params = [];
      if (!isAdmin) {
        if (orgId) {
          query += ' WHERE org_id = ?';
          params.push(orgId);
        } else {
          query += ' WHERE user_id = ?';
          params.push(userId);
        }
      }
      query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
      params.push(limit, offset);

      this.db.all(query, params, (err, rows) => {
        if (err) return reject(err);
        const scans = rows.map(row => ({
          ...row,
          options: row.options ? JSON.parse(row.options) : null,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          startTime: row.start_time,
          endTime: row.end_time
        }));
        resolve(scans);
      });
    });
  }

  // Jobs API
  async createJob({ id = uuidv4(), user_id, org_id = null, run_at, target, options = {}, scan_profile = 'basic', max_retries = 3 }) {
    return new Promise((resolve, reject) => {
      const stmt = this.db.prepare(`
        INSERT INTO jobs (id, user_id, org_id, status, run_at, retries, max_retries, last_error, scan_id, target, options, scan_profile)
        VALUES (?, ?, ?, 'scheduled', ?, 0, ?, NULL, NULL, ?, ?, ?)
      `);
      stmt.run([id, user_id, org_id, run_at, max_retries, target, JSON.stringify(options || {}), scan_profile], function(err) {
        if (err) return reject(err);
        resolve(id);
      });
      stmt.finalize();
    });
  }

  async getDueJobs(limit = 20) {
    return new Promise((resolve, reject) => {
      const sql = `SELECT * FROM jobs WHERE status IN ('scheduled','retrying') AND run_at <= datetime('now') ORDER BY run_at ASC LIMIT ?`;
      this.db.all(sql, [limit], (err, rows) => {
        if (err) return reject(err);
        const parsed = (rows || []).map(r => ({ ...r, options: this.safeJson(r.options, {}) }));
        resolve(parsed);
      });
    });
  }

  async claimJob(id) {
    return new Promise((resolve, reject) => {
      const now = new Date().toISOString();
      const sql = `UPDATE jobs SET status = 'running', updated_at = ? WHERE id = ? AND status IN ('scheduled','retrying')`;
      this.db.run(sql, [now, id], function(err) {
        if (err) return reject(err);
        resolve(this.changes > 0);
      });
    });
  }

  async markJobRunning(id, scanId) {
    return new Promise((resolve, reject) => {
      const now = new Date().toISOString();
      this.db.run(`UPDATE jobs SET status = 'running', scan_id = ?, updated_at = ? WHERE id = ?`, [scanId, now, id], function(err) {
        if (err) return reject(err);
        resolve(this.changes > 0);
      });
    });
  }

  async markJobCompleted(id) {
    return new Promise((resolve, reject) => {
      const now = new Date().toISOString();
      this.db.run(`UPDATE jobs SET status = 'completed', updated_at = ? WHERE id = ?`, [now, id], function(err) {
        if (err) return reject(err);
        resolve(this.changes > 0);
      });
    });
  }

  async markJobFailed(id, errorMessage) {
    return new Promise((resolve, reject) => {
      const now = new Date().toISOString();
      this.db.run(`UPDATE jobs SET status = 'failed', last_error = ?, updated_at = ? WHERE id = ?`, [errorMessage || 'unknown', now, id], function(err) {
        if (err) return reject(err);
        resolve(this.changes > 0);
      });
    });
  }

  async scheduleJobRetry(id, retries, backoffSeconds) {
    return new Promise((resolve, reject) => {
      const now = new Date();
      const runAt = new Date(now.getTime() + Math.max(1, backoffSeconds) * 1000).toISOString();
      this.db.run(`UPDATE jobs SET status = 'retrying', retries = ?, run_at = ?, updated_at = ? WHERE id = ?`, [retries, runAt, new Date().toISOString(), id], function(err) {
        if (err) return reject(err);
        resolve(this.changes > 0);
      });
    });
  }

  async getJobsForUser(userId, orgId = null, isAdmin = false, limit = 50, offset = 0) {
    return new Promise((resolve, reject) => {
      let sql = 'SELECT * FROM jobs';
      const params = [];
      if (!isAdmin) {
        if (orgId) { sql += ' WHERE org_id = ?'; params.push(orgId); }
        else { sql += ' WHERE user_id = ?'; params.push(userId); }
      }
      sql += ' ORDER BY run_at ASC LIMIT ? OFFSET ?';
      params.push(limit, offset);
      this.db.all(sql, params, (err, rows) => {
        if (err) return reject(err);
        const parsed = (rows || []).map(r => ({ ...r, options: this.safeJson(r.options, {}) }));
        resolve(parsed);
      });
    });
  }

  async getJob(id) {
    return new Promise((resolve, reject) => {
      this.db.get('SELECT * FROM jobs WHERE id = ?', [id], (err, row) => {
        if (err) return reject(err);
        resolve(row ? { ...row, options: this.safeJson(row.options, {}) } : null);
      });
    });
  }

  async cancelJob(id) {
    return new Promise((resolve, reject) => {
      const now = new Date().toISOString();
      // Only cancel if not yet running
      const sql = `UPDATE jobs SET status = 'canceled', updated_at = ? WHERE id = ? AND status IN ('scheduled','retrying')`;
      this.db.run(sql, [now, id], function(err) {
        if (err) return reject(err);
        resolve(this.changes > 0);
      });
    });
  }

  async updateScan(scanId, updateData) {
    return new Promise((resolve, reject) => {
      const fields = Object.keys(updateData);
      const values = Object.values(updateData);
      const setClause = fields.map(field => `${field} = ?`).join(', ');
      
      values.push(new Date().toISOString()); // updated_at
      values.push(scanId);

      const query = `
        UPDATE scans 
        SET ${setClause}, updated_at = ?
        WHERE id = ?
      `;

      this.db.run(query, values, function(err) {
        if (err) {
          reject(err);
        } else {
          resolve(this.changes > 0);
        }
      });
    });
  }

  async appendScanOutput(scanId, output, type) {
    return new Promise((resolve, reject) => {
      // First get current output
      this.db.get(
        'SELECT output FROM scans WHERE id = ?',
        [scanId],
        (err, row) => {
          if (err) {
            reject(err);
            return;
          }

          const currentOutput = row ? (row.output || '') : '';
          const timestamp = new Date().toISOString();
          const newOutput = currentOutput + `\n[${timestamp}] [${type}] ${output}`;

          // Update with appended output
          this.db.run(
            'UPDATE scans SET output = ?, updated_at = ? WHERE id = ?',
            [newOutput, timestamp, scanId],
            function(err) {
              if (err) {
                reject(err);
              } else {
                resolve(this.changes > 0);
              }
            }
          );
        }
      );
    });
  }

  async deleteScan(scanId) {
    return new Promise((resolve, reject) => {
      this.db.run(
        'DELETE FROM scans WHERE id = ?',
        [scanId],
        function(err) {
          if (err) {
            reject(err);
          } else {
            resolve(this.changes > 0);
          }
        }
      );
    });
  }

  // Report operations
  async createReport(reportData) {
    return new Promise((resolve, reject) => {
      const {
        id,
        scanId,
        title,
        target,
        command,
        vulnerabilities,
        extractedData,
        recommendations,
        scanDuration,
        status,
        metadata,
        sqlmapResults,
        structuredFindings,
        outputFiles,
        user_id = 'system',
        org_id = null
      } = reportData;

      const stmt = this.db.prepare(`
        INSERT INTO reports (
          id, scan_id, title, target, command, vulnerabilities,
          extracted_data, recommendations, scan_duration, status, user_id, org_id, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);

      stmt.run([
        id,
        scanId,
        title,
        target,
        command,
        JSON.stringify(vulnerabilities),
        JSON.stringify({
          ...extractedData,
          sqlmapResults,
          structuredFindings,
          outputFiles
        }),
        JSON.stringify(recommendations),
        scanDuration,
        status,
        user_id,
        org_id,
        JSON.stringify(metadata || {})
      ], function(err) {
        if (err) {
          Logger.error('Error creating report:', err);
          reject(err);
        } else {
          Logger.info(`Report created with ID: ${id}`);
          resolve(id);
        }
      });

      stmt.finalize();
    });
  }

  async getReport(reportId) {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT * FROM reports WHERE id = ?',
        [reportId],
        (err, row) => {
          if (err) {
            reject(err);
          } else {
            if (row) {
              // Parse JSON fields
              row.vulnerabilities = JSON.parse(row.vulnerabilities || '[]');
              row.extracted_data = JSON.parse(row.extracted_data || '{}');
              row.recommendations = JSON.parse(row.recommendations || '[]');
              row.metadata = JSON.parse(row.metadata || '{}');

              // Provide camelCase aliases expected by frontend
              row.createdAt = row.created_at;
              row.scanDuration = row.scan_duration;
              row.extractedData = row.extracted_data;
            }
            resolve(row);
          }
        }
      );
    });
  }

  async getReports(limit = 50, offset = 0) {
    return new Promise((resolve, reject) => {
      this.db.all(
        'SELECT * FROM reports ORDER BY created_at DESC LIMIT ? OFFSET ?',
        [limit, offset],
        (err, rows) => {
          if (err) {
            reject(err);
          } else {
            const reports = rows.map(row => {
              // Parse JSON fields
              row.vulnerabilities = JSON.parse(row.vulnerabilities || '[]');
              row.extracted_data = JSON.parse(row.extracted_data || '{}');
              row.recommendations = JSON.parse(row.recommendations || '[]');
              row.metadata = JSON.parse(row.metadata || '{}');

              row.createdAt = row.created_at;
              row.scanDuration = row.scan_duration;
              row.extractedData = row.extracted_data;
              return row;
            });
            resolve(reports);
          }
        }
      );
    });
  }

  async getReportsForUser(userId, orgId = null, isAdmin = false, limit = 50, offset = 0) {
    return new Promise((resolve, reject) => {
      let query = 'SELECT * FROM reports';
      const params = [];
      if (!isAdmin) {
        if (orgId) {
          query += ' WHERE org_id = ?';
          params.push(orgId);
        } else {
          query += ' WHERE user_id = ?';
          params.push(userId);
        }
      }
      query += ' ORDER BY created_at DESC LIMIT ? OFFSET ?';
      params.push(limit, offset);

      this.db.all(query, params, (err, rows) => {
        if (err) return reject(err);
        const reports = rows.map(row => ({
          ...row,
          vulnerabilities: this.safeJson(row.vulnerabilities, []),
          extracted_data: this.safeJson(row.extracted_data, {}),
          recommendations: this.safeJson(row.recommendations, []),
          metadata: this.safeJson(row.metadata, {}),
          createdAt: row.created_at,
          scanDuration: row.scan_duration,
          extractedData: this.safeJson(row.extracted_data, {})
        }));
        resolve(reports);
      });
    });
  }

  // User operations
  async createUser({ id = uuidv4(), email, password_hash, role = 'user' }) {
    return new Promise((resolve, reject) => {
      const stmt = this.db.prepare(`
        INSERT INTO users (id, email, password_hash, role)
        VALUES (?, ?, ?, ?)
      `);
      stmt.run([id, email, password_hash, role], function(err) {
        if (err) return reject(err);
        resolve(id);
      });
      stmt.finalize();
    });
  }

  async getUserByEmail(email) {
    return new Promise((resolve, reject) => {
      this.db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      });
    });
  }

  async getUserById(id) {
    return new Promise((resolve, reject) => {
      this.db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      });
    });
  }

  async setUserLastLogin(id) {
    return new Promise((resolve, reject) => {
      this.db.run('UPDATE users SET last_login_at = ? WHERE id = ?', [new Date().toISOString(), id], function(err) {
        if (err) return reject(err);
        resolve(this.changes > 0);
      });
    });
  }

  async deleteReport(reportId) {
    return new Promise((resolve, reject) => {
      this.db.run(
        'DELETE FROM reports WHERE id = ?',
        [reportId],
        function(err) {
          if (err) {
            reject(err);
          } else {
            resolve(this.changes > 0);
          }
        }
      );
    });
  }

  async updateReportMetadata(reportId, updater) {
    return new Promise((resolve, reject) => {
      this.db.get('SELECT metadata FROM reports WHERE id = ?', [reportId], (err, row) => {
        if (err) return reject(err);
        const current = row && row.metadata ? this.safeJson(row.metadata, {}) : {};
        let next;
        try { next = typeof updater === 'function' ? updater({ ...current }) : current; } catch (e) { return reject(e); }
        const payload = JSON.stringify(next || {});
        this.db.run('UPDATE reports SET metadata = ? WHERE id = ?', [payload, reportId], function(uErr) {
          if (uErr) return reject(uErr);
          resolve(true);
        });
      });
    });
  }

  // Output retention helpers
  async getScansWithOutputBefore(cutoffIso) {
    return new Promise((resolve, reject) => {
      const sql = `SELECT id, output_dir FROM scans WHERE output_dir IS NOT NULL AND end_time IS NOT NULL AND end_time < ?`;
      this.db.all(sql, [cutoffIso], (err, rows) => {
        if (err) return reject(err);
        resolve(rows || []);
      });
    });
  }

  async clearScanOutputDir(scanId) {
    return new Promise((resolve, reject) => {
      this.db.run('UPDATE scans SET output_dir = NULL WHERE id = ?', [scanId], function(err) {
        if (err) return reject(err);
        resolve(this.changes > 0);
      });
    });
  }

  // Usage / Quota helpers
  async incrementUsageOnStart(userId, period) {
    return new Promise((resolve, reject) => {
      const sql = `
        INSERT INTO usage_counters (user_id, period, scans_started, scans_completed, total_runtime_ms)
        VALUES (?, ?, 1, 0, 0)
        ON CONFLICT(user_id, period) DO UPDATE SET scans_started = scans_started + 1
      `;
      this.db.run(sql, [userId, period], function(err) {
        if (err) return reject(err);
        resolve(true);
      });
    });
  }

  async incrementUsageOnComplete(userId, period, runtimeMs = 0) {
    return new Promise((resolve, reject) => {
      const sql = `
        INSERT INTO usage_counters (user_id, period, scans_started, scans_completed, total_runtime_ms)
        VALUES (?, ?, 0, 1, ?)
        ON CONFLICT(user_id, period) DO UPDATE SET 
          scans_completed = scans_completed + 1,
          total_runtime_ms = total_runtime_ms + excluded.total_runtime_ms
      `;
      this.db.run(sql, [userId, period, Math.max(0, runtimeMs || 0)], function(err) {
        if (err) return reject(err);
        resolve(true);
      });
    });
  }

  async incrementCancelCount(userId, period) {
    return new Promise((resolve, reject) => {
      const sql = `
        INSERT INTO usage_counters (user_id, period, scans_started, scans_completed, total_runtime_ms, cancel_count, duplicate_window_retries)
        VALUES (?, ?, 0, 0, 0, 1, 0)
        ON CONFLICT(user_id, period) DO UPDATE SET cancel_count = cancel_count + 1
      `;
      this.db.run(sql, [userId, period], function(err) {
        if (err) return reject(err);
        resolve(true);
      });
    });
  }

  async incrementDuplicateWindowRetries(userId, period) {
    return new Promise((resolve, reject) => {
      const sql = `
        INSERT INTO usage_counters (user_id, period, scans_started, scans_completed, total_runtime_ms, cancel_count, duplicate_window_retries)
        VALUES (?, ?, 0, 0, 0, 0, 1)
        ON CONFLICT(user_id, period) DO UPDATE SET duplicate_window_retries = duplicate_window_retries + 1
      `;
      this.db.run(sql, [userId, period], function(err) {
        if (err) return reject(err);
        resolve(true);
      });
    });
  }

  async getUsageForUser(userId, period) {
    return new Promise((resolve, reject) => {
      const sql = 'SELECT * FROM usage_counters WHERE user_id = ? AND period = ?';
      this.db.get(sql, [userId, period], (err, row) => {
        if (err) return reject(err);
        if (!row) {
          return resolve({ user_id: userId, period, scans_started: 0, scans_completed: 0, total_runtime_ms: 0, cancel_count: 0, duplicate_window_retries: 0 });
        }
        // Coalesce possibly NULL columns introduced via ALTER TABLE
        const safe = {
          ...row,
          scans_started: row.scans_started || 0,
          scans_completed: row.scans_completed || 0,
          total_runtime_ms: row.total_runtime_ms || 0,
          cancel_count: row.cancel_count || 0,
          duplicate_window_retries: row.duplicate_window_retries || 0
        };
        resolve(safe);
      });
    });
  }

  // Verified targets helpers
  async upsertVerifiedTarget({ id = uuidv4(), user_id, org_id = null, hostname, method, token, verified_at = null }) {
    return new Promise((resolve, reject) => {
      const stmt = this.db.prepare(`
        INSERT INTO verified_targets (id, user_id, org_id, hostname, method, token, verified_at)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET 
          user_id = excluded.user_id,
          org_id = excluded.org_id,
          hostname = excluded.hostname,
          method = excluded.method,
          token = excluded.token,
          verified_at = excluded.verified_at
      `);
      stmt.run([id, user_id, org_id, hostname, method, token, verified_at], function(err) {
        if (err) return reject(err);
        resolve(id);
      });
      stmt.finalize();
    });
  }

  async markVerifiedTarget(id, verified_at = new Date().toISOString()) {
    return new Promise((resolve, reject) => {
      this.db.run('UPDATE verified_targets SET verified_at = ? WHERE id = ?', [verified_at, id], function(err) {
        if (err) return reject(err);
        resolve(this.changes > 0);
      });
    });
  }

  async getVerifiedTargetForUser(hostname, userId, orgId = null, isAdmin = false) {
    return new Promise((resolve, reject) => {
      let sql = 'SELECT * FROM verified_targets WHERE hostname = ? AND verified_at IS NOT NULL';
      const params = [hostname];
      if (!isAdmin) {
        if (orgId) {
          sql += ' AND (org_id = ?)';
          params.push(orgId);
        } else {
          sql += ' AND (user_id = ?)';
          params.push(userId);
        }
      }
      this.db.get(sql, params, (err, row) => {
        if (err) return reject(err);
        resolve(row || null);
      });
    });
  }

  async listVerifiedTargets(userId, orgId = null, isAdmin = false) {
    return new Promise((resolve, reject) => {
      let sql = 'SELECT * FROM verified_targets';
      const params = [];
      if (!isAdmin) {
        if (orgId) {
          sql += ' WHERE org_id = ?';
          params.push(orgId);
        } else {
          sql += ' WHERE user_id = ?';
          params.push(userId);
        }
      }
      sql += ' ORDER BY created_at DESC';
      this.db.all(sql, params, (err, rows) => {
        if (err) return reject(err);
        resolve(rows || []);
      });
    });
  }

  async deleteVerifiedTarget(id) {
    return new Promise((resolve, reject) => {
      this.db.run('DELETE FROM verified_targets WHERE id = ?', [id], function(err) {
        if (err) return reject(err);
        resolve(this.changes > 0);
      });
    });
  }

  // Settings operations
  async getSetting(key, defaultValue = null) {
    return new Promise((resolve, reject) => {
      this.db.get(
        'SELECT value FROM settings WHERE key = ?',
        [key],
        (err, row) => {
          if (err) {
            reject(err);
          } else {
            resolve(row ? row.value : defaultValue);
          }
        }
      );
    });
  }

  async setSetting(key, value) {
    return new Promise((resolve, reject) => {
      const stmt = this.db.prepare(`
        INSERT OR REPLACE INTO settings (key, value, updated_at)
        VALUES (?, ?, ?)
      `);

      stmt.run([key, value, new Date().toISOString()], function(err) {
        if (err) {
          reject(err);
        } else {
          resolve(true);
        }
      });

      stmt.finalize();
    });
  }

  // Database maintenance
  async vacuum() {
    return new Promise((resolve, reject) => {
      this.db.run('VACUUM', (err) => {
        if (err) {
          reject(err);
        } else {
          resolve(true);
        }
      });
    });
  }

  // Recon parameter persistence
  async saveReconParameters(target, params = []) {
    return new Promise((resolve, reject) => {
      if (!params.length) return resolve(0);
      const stmt = this.db.prepare(`
        INSERT OR REPLACE INTO recon_parameters (
          id, scan_target, name, sources, methods, actions, types, observations,
          reflected, occurrences, transformed, length_delta,
          name_length, name_entropy, base_latency_ms, reflection_latency_ms, priority_score
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `);
      let inserted = 0;
      for (const p of params) {
        try {
          stmt.run([
            p.id,
            target,
            p.name,
            JSON.stringify(p.sources || []),
            JSON.stringify(p.methods || []),
            JSON.stringify(p.actions || []),
            JSON.stringify(p.types || []),
            p.observations || 1,
            p.reflection?.reflected ? 1 : 0,
            p.reflection?.occurrences || 0,
            p.reflection?.transformed ? 1 : 0,
            p.reflection?.lengthDelta || 0,
            p.name_length || p.name?.length || 0,
            p.name_entropy || null,
            p.base_latency_ms || null,
            p.reflection_latency_ms || null,
            p.priority_score || null
          ]);
          inserted++;
        } catch (e) {
          Logger.warn('Failed to insert recon parameter', { name: p.name, error: e.message });
        }
      }
      stmt.finalize(err => {
        if (err) reject(err); else resolve(inserted);
      });
    });
  }

  async saveReconPages(target, pages = []) {
    return new Promise((resolve, reject) => {
      if (!pages.length) return resolve(0);
      const stmt = this.db.prepare(`
        INSERT OR REPLACE INTO recon_pages (
          id, scan_target, url, parent_url, depth, status, content_type, fetch_time_ms
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `);
      let count = 0;
      for (const pg of pages) {
        try {
          stmt.run([
            pg.id,
            target,
            pg.url,
            pg.parent_url || null,
            pg.depth || 0,
            pg.status || null,
            pg.content_type || null,
            pg.fetch_time_ms || null
          ]);
          count++;
        } catch (e) {
          Logger.warn('Failed to insert recon page', { url: pg.url, error: e.message });
        }
      }
      stmt.finalize(err => err ? reject(err) : resolve(count));
    });
  }

  async getReconParameters(target) {
    return new Promise((resolve, reject) => {
      this.db.all('SELECT * FROM recon_parameters WHERE scan_target = ? ORDER BY created_at DESC', [target], (err, rows) => {
        if (err) return reject(err);
        const parsed = rows.map(r => ({
          ...r,
          sources: this.safeJson(r.sources, []),
          methods: this.safeJson(r.methods, []),
          actions: this.safeJson(r.actions, []),
          types: this.safeJson(r.types, [])
        }));
        resolve(parsed);
      });
    });
  }

  safeJson(str, fallback) {
    try { return JSON.parse(str); } catch { return fallback; }
  }

  async backup(backupPath) {
    return new Promise((resolve, reject) => {
      const backup = new sqlite3.Database(backupPath);
      this.db.backup(backup, (err) => {
        backup.close();
        if (err) {
          reject(err);
        } else {
          resolve(true);
        }
      });
    });
  }

  close() {
    if (this.db) {
      this.db.close((err) => {
        if (err) {
          console.error('Error closing database:', err);
        } else {
          console.log('Database connection closed');
        }
      });
    }
  }
}

module.exports = Database;