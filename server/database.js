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
        metadata TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (scan_id) REFERENCES scans (id)
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

    this.db.serialize(() => {
      this.db.run(createScansTable);
      this.db.run(createReportsTable);
      this.db.run(createSettingsTable);
      
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
  async createScan(scanData) {
    return new Promise((resolve, reject) => {
      const id = uuidv4();
      const { target, options, scanProfile, status, start_time } = scanData;
      
      const stmt = this.db.prepare(`
        INSERT INTO scans (id, target, options, scan_profile, status, start_time)
        VALUES (?, ?, ?, ?, ?, ?)
      `);

      stmt.run([
        id,
        target,
        JSON.stringify(options),
        scanProfile,
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
            if (row && row.options) {
              row.options = JSON.parse(row.options);
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
              return row;
            });
            resolve(scans);
          }
        }
      );
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
        outputFiles
      } = reportData;

      const stmt = this.db.prepare(`
        INSERT INTO reports (
          id, scan_id, title, target, command, vulnerabilities,
          extracted_data, recommendations, scan_duration, status, metadata
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
              return row;
            });
            resolve(reports);
          }
        }
      );
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