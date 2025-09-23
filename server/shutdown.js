const Logger = require('./utils/logger');
const killTree = require('tree-kill');

// Utility to promisify tree-kill
function killPid(pid, signal = 'SIGTERM', timeoutMs = 8000) {
  return new Promise((resolve) => {
    if (!pid || pid <= 0) return resolve(false);
    let done = false;
    const timer = setTimeout(() => {
      if (done) return;
      // escalate to SIGKILL if still alive
      try { killTree(pid, 'SIGKILL'); } catch (_) {}
      done = true; resolve(true);
    }, timeoutMs);
    try {
      killTree(pid, signal, () => {
        if (done) return;
        clearTimeout(timer);
        done = true; resolve(true);
      });
    } catch (e) {
      clearTimeout(timer);
      resolve(false);
    }
  });
}

async function shutdown({ httpServer, io, db, queue, sqlmap, scanProcessesRef }) {
  try { Logger.info('Starting graceful shutdown sequence...'); } catch (_) {}

  // 1) Stop accepting new connections
  try {
    if (io?.httpServer) {
      io.close();
      Logger.info('Socket.io server closed');
    }
  } catch (e) { Logger.warn('Failed closing socket.io', { error: e.message }); }

  // 2) Stop queue polling
  try {
    if (queue && typeof queue.stop === 'function') {
      queue.stop();
      Logger.info('Queue runner stopped');
    }
  } catch (e) { Logger.warn('Failed stopping queue', { error: e.message }); }

  // 3) Mark running scans as terminated and terminate all running sqlmap child processes
  try {
    const procs = [];
    if (scanProcessesRef && scanProcessesRef.size) {
      for (const [scanId, info] of scanProcessesRef.entries()) {
        const pid = info?.process?.pid;
        // Best-effort DB update + audit
        try {
          db?.updateScan?.(scanId, { status: 'terminated', end_time: new Date().toISOString() });
          db?.logScanEvent?.({ scan_id: scanId, user_id: info.userId || 'system', org_id: info.orgId || null, event_type: 'terminated', metadata: { reason: 'server-shutdown' } });
        } catch (_) {}
        if (pid) {
          Logger.info('Killing child process tree', { scanId, pid });
          procs.push(killPid(pid, 'SIGTERM', 6000));
        }
      }
    }
    await Promise.allSettled(procs);
    Logger.info('All child processes signaled');
  } catch (e) { Logger.warn('Error while killing children', { error: e.message }); }

  // 4) Close HTTP server
  await new Promise((resolve) => {
    try {
      httpServer?.close?.(() => {
        Logger.info('HTTP server closed');
        resolve();
      });
      // Fallback timeout if close callback not invoked
      setTimeout(resolve, 4000);
    } catch (_) { resolve(); }
  });

  // 5) Cleanup sqlmap temp and registry
  try { sqlmap?.cleanup?.(); } catch (e) { Logger.warn('SQLMap cleanup failed', { error: e.message }); }

  // 6) Close database
  try { db?.close?.(); } catch (e) { Logger.warn('DB close failed', { error: e.message }); }

  Logger.info('Shutdown sequence complete. Exiting.');
}

module.exports = { shutdown, killPid };
