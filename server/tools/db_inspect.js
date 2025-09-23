/*
 Simple DB inspection script for local metrics snapshot.
 Usage: node server/tools/db_inspect.js
*/
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const DB_PATH = path.join(__dirname, '..', 'data', 'cybersecurity.db');

function get(db, sql, params = []) {
  return new Promise((resolve, reject) => db.get(sql, params, (e, r) => (e ? reject(e) : resolve(r || {}))));
}
function all(db, sql, params = []) {
  return new Promise((resolve, reject) => db.all(sql, params, (e, r) => (e ? reject(e) : resolve(r || []))));
}

(async () => {
  const db = new sqlite3.Database(DB_PATH);
  try {
    const now = new Date();
    const cutoff30 = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
    const cutoff90 = new Date(now.getTime() - 90 * 24 * 60 * 60 * 1000).toISOString();

    const users = await get(db, 'SELECT COUNT(*) c FROM users');
    const admins = await get(db, "SELECT COUNT(*) c FROM users WHERE role = 'admin'");
    const scans = await get(db, 'SELECT COUNT(*) c FROM scans');
    const scans30 = await get(db, 'SELECT COUNT(*) c FROM scans WHERE created_at >= ?', [cutoff30]);
    const reports = await get(db, 'SELECT COUNT(*) c FROM reports');
    const reports30 = await get(db, 'SELECT COUNT(*) c FROM reports WHERE created_at >= ?', [cutoff30]);
    const visitsAll = await get(db, "SELECT COUNT(*) c FROM telemetry_events WHERE event_type='visit'");
    const visits30 = await get(db, "SELECT COUNT(*) c FROM telemetry_events WHERE event_type='visit' AND at >= ?", [cutoff30]);
    const verifications30 = await get(db, "SELECT COUNT(*) c FROM scan_events WHERE event_type='verification' AND at >= ?", [cutoff30]);
    const falsePositives30 = await get(db, "SELECT COUNT(*) c FROM telemetry_events WHERE event_type='false-positive' AND at >= ?", [cutoff30]);

    const lastScan = await get(db, 'SELECT id, target, status, created_at, start_time, end_time FROM scans ORDER BY created_at DESC LIMIT 1');
    const lastReport = await get(db, 'SELECT id, scan_id, title, created_at FROM reports ORDER BY created_at DESC LIMIT 1');
    const recentScans = await all(db, 'SELECT id, target, status, created_at FROM scans ORDER BY created_at DESC LIMIT 10');
    const recentReports = await all(db, 'SELECT id, scan_id, created_at FROM reports ORDER BY created_at DESC LIMIT 10');
    const usageRows = await all(db, 'SELECT * FROM usage_counters ORDER BY period DESC LIMIT 12');
    const pagesTop = await all(db, "SELECT json_extract(metadata,'$.path') as path, COUNT(*) as c FROM telemetry_events WHERE event_type='visit' AND at >= ? GROUP BY path ORDER BY c DESC LIMIT 10", [cutoff90]);

    const out = {
      users: users.c || 0,
      admins: admins.c || 0,
      scans: scans.c || 0,
      scansLast30: scans30.c || 0,
      reports: reports.c || 0,
      reportsLast30: reports30.c || 0,
      visitsAll: visitsAll.c || 0,
      visitsLast30: visits30.c || 0,
      verificationsLast30: verifications30.c || 0,
      falsePositivesLast30: falsePositives30.c || 0,
      lastScan,
      lastReport,
      recentScans,
      recentReports,
      usageRows,
      topPages90d: pagesTop,
    };

    console.log(JSON.stringify(out, null, 2));
  } catch (e) {
    console.error('DB inspect failed:', e.message);
    process.exitCode = 1;
  } finally {
    db.close();
  }
})();
