const fs = require('fs');
const Logger = require('./utils/logger');
const SQLMapIntegration = require('./sqlmap');
const ReportGenerator = require('./reports');
const { sanitizeOptionsForStorage, prepareAuthContext } = require('./helpers/scanHelpers');

class QueueRunner {
  constructor({ database, io, scanProcessesRef, sqlmap, reportGenerator }) {
    this.db = database;
    this.io = io;
    // Reuse provided SQLMapIntegration if available to avoid duplicate initialization/validation
    this.sqlmap = sqlmap || new SQLMapIntegration();
    // Reuse provided ReportGenerator to avoid duplicate Puppeteer validation
    this.reportGenerator = reportGenerator || new ReportGenerator(database);
    // Reference to the in-memory map in index.js for visibility/termination
    this.scanProcesses = scanProcessesRef;
  this.timer = null;
  this.running = false;
  this.pollIntervalMs = Math.max(1000, parseInt(process.env.JOB_POLL_INTERVAL_MS || '3000', 10));
  }

  // Count active running scans for a given user (from shared map)
  runningForUser(userId) {
    return Array.from(this.scanProcesses.values()).filter(p => p.userId === userId).length;
  }

  // Main tick: claim due jobs and process within concurrency constraints
  async tick() {
    try {
      const maxBatch = parseInt(process.env.JOB_FETCH_BATCH || '10', 10);
      const due = await this.db.getDueJobs(maxBatch);
      if (!due.length) return;

      for (const job of due) {
        const { id: jobId, user_id: userId, org_id: orgId, target, options, scan_profile: scanProfile, created_by_admin } = job;

        // Enforce per-user concurrency limit
        const MAX_CONCURRENT = parseInt(process.env.MAX_CONCURRENT_SCANS_PER_USER || '2', 10);
        if (this.runningForUser(userId) >= MAX_CONCURRENT) {
          // Skip for now; will be picked up next tick
          continue;
        }

        // Attempt to claim atomically
        const claimed = await this.db.claimJob(jobId);
        if (!claimed) continue;

        try {
          // Debounce recent similar scan for the same user/target
          try {
            const windowSec = parseInt(process.env.DUPLICATE_SCAN_WINDOW_SECONDS || '10', 10);
            const dup = await this.db.hasRecentSimilarScan(userId, target, windowSec);
            if (dup) {
              // Telemetry: track duplicate-window retries
              try {
                const period = new Date().toISOString().slice(0,7);
                await this.db.incrementDuplicateWindowRetries(userId, period);
              } catch (_) {}
              await this.handleRetry(job, 'duplicate-start-window');
              continue;
            }
          } catch (_) {}

          // Quotas (monthly)
          const period = new Date().toISOString().slice(0,7);
          const MAX_SCANS_MONTH = parseInt(process.env.MAX_SCANS_PER_MONTH || '100', 10);
          const usage = await this.db.getUsageForUser(userId, period);
          if ((usage?.scans_started || 0) >= MAX_SCANS_MONTH) {
            await this.db.markJobFailed(jobId, `Monthly scan quota reached (${MAX_SCANS_MONTH} in ${period})`);
            continue;
          }

          // Prepare auth context
          const { preparedOptions, authMeta } = await prepareAuthContext(options || {}, target, userId);

          // Verified target policy (non-admin path—queue runner lacks role; enforce strictly unless toggled)
          try {
            const allowUnverified = ['true','1','yes','on'].includes(String(process.env.ALLOW_UNVERIFIED_TARGETS).toLowerCase());
            const adminSkip = created_by_admin ? true : false;
            if (!allowUnverified && !adminSkip) {
              const hostname = new URL(target).hostname;
              const verified = await this.db.getVerifiedTargetForUser(hostname, userId, orgId, false);
              if (!verified) {
                await this.db.markJobFailed(jobId, `Target ${hostname} not verified (queue)`);
                continue;
              }
            }
          } catch (_) {}

          // Start scan
          const { process: proc, outputDir } = await this.sqlmap.startScan(target, preparedOptions, scanProfile || 'basic', userId);

          // Record scan in DB
          const startTimeIso = new Date().toISOString();
          const scanId = await this.db.createScan({
            target,
            options: sanitizeOptionsForStorage({ ...preparedOptions, auth: { ...(preparedOptions.auth || {}), type: authMeta.mode } }),
            scanProfile: scanProfile || 'basic',
            user_id: userId,
            org_id: orgId,
            output_dir: outputDir,
            status: 'running',
            start_time: startTimeIso
          });

          await this.db.markJobRunning(jobId, scanId);

          // Log start event
          this.db.logScanEvent({ scan_id: scanId, user_id: userId, org_id: orgId, event_type: 'started', metadata: { target, scanProfile, via: 'queue', jobId } }).catch(()=>{});

          // Track process
          this.scanProcesses.set(scanId, { process: proc, outputDir, target, scanProfile, startTime: new Date(), userId, orgId });

          // Stream output to user room if sockets exist
          proc.stdout.on('data', (data) => {
            const output = data.toString();
            this.db.appendScanOutput(scanId, output, 'stdout');
            this.db.logScanEvent({ scan_id: scanId, user_id: userId, org_id: orgId, event_type: 'output', metadata: { type: 'stdout', chunk: output.slice(0,1000) } }).catch(()=>{});
            try { this.io?.to?.(`user:${userId}`)?.emit?.('scan-output', { scanId, output, type: 'stdout' }); } catch (_) {}
          });
          proc.stderr.on('data', (data) => {
            const output = data.toString();
            this.db.appendScanOutput(scanId, output, 'stderr');
            this.db.logScanEvent({ scan_id: scanId, user_id: userId, org_id: orgId, event_type: 'output', metadata: { type: 'stderr', chunk: output.slice(0,1000) } }).catch(()=>{});
            try { this.io?.to?.(`user:${userId}`)?.emit?.('scan-output', { scanId, output, type: 'stderr' }); } catch (_) {}
          });

          proc.on('close', async (code) => {
            const endTime = new Date().toISOString();
            try {
              await this.db.updateScan(scanId, { status: code === 0 ? 'completed' : 'failed', end_time: endTime, exit_code: code });
              const scanData = await this.db.getScan(scanId);
              let sqlmapResults = null;
              if (code === 0) {
                try {
                  const outDir = this.scanProcesses.get(scanId)?.outputDir;
                  if (outDir && fs.existsSync(outDir)) {
                    sqlmapResults = await this.sqlmap.parseResults(outDir, scanId);
                  }
                } catch (e) { Logger.error('Queue parse results error', e); }
              }
              const reportData = await this.reportGenerator.generateReport(scanId, scanData, sqlmapResults);
              const reportId = await this.db.createReport({ ...reportData, user_id: userId, org_id: orgId });
              this.db.logScanEvent({ scan_id: scanId, user_id: userId, org_id: orgId, event_type: code === 0 ? 'completed' : 'failed', metadata: { exit_code: code, reportId, hasStructuredResults: !!sqlmapResults, via: 'queue', jobId } }).catch(()=>{});
              try { this.io?.to?.(`user:${userId}`)?.emit?.('scan-completed', { scanId, status: code === 0 ? 'completed' : 'failed', reportId, exit_code: code, hasStructuredResults: !!sqlmapResults }); } catch (_) {}

              // Mark job completion or schedule retry
              if (code === 0) {
                await this.db.markJobCompleted(jobId);
              } else {
                await this.handleRetry(job, `Exit code ${code}`);
              }
            } catch (e) {
              Logger.error('Queue close handler error', e);
              await this.handleRetry(job, e.message || 'close handler failure');
            } finally {
              this.scanProcesses.delete(scanId);
            }
          });

          proc.on('error', async (error) => {
            Logger.error('SQLMap process error (queue):', error);
            this.db.updateScan(scanId, { status: 'failed', error: error.message }).catch(()=>{});
            this.db.logScanEvent({ scan_id: scanId, user_id: userId, org_id: orgId, event_type: 'process-error', metadata: { message: error.message, via: 'queue', jobId } }).catch(()=>{});
            this.scanProcesses.delete(scanId);
            await this.handleRetry(job, error.message || 'spawn error');
          });

        } catch (err) {
          Logger.error('Queue failed to start scan', { jobId, error: err.message });
          await this.handleRetry(job, err.message || 'start failure');
        }
      }
    } catch (e) {
      Logger.warn('Queue tick error', { error: e.message });
    }
  }

  async handleRetry(job, errorMessage) {
    const { id: jobId, retries, max_retries } = job;
    const attempt = (Number(retries) || 0) + 1;
    if (attempt > (Number(max_retries) || 3)) {
      await this.db.markJobFailed(jobId, errorMessage);
      return;
    }
    const base = parseInt(process.env.JOB_BACKOFF_BASE_SECONDS || '10', 10);
    const factor = parseFloat(process.env.JOB_BACKOFF_FACTOR || '2.0');
    const maxCap = parseInt(process.env.JOB_BACKOFF_MAX_SECONDS || '600', 10);
    const backoff = Math.min(maxCap, Math.floor(base * Math.pow(factor, attempt - 1)));
    await this.db.scheduleJobRetry(jobId, attempt, backoff);
  }

  start() {
    if (this.running) return;
    this.running = true;
    const intervalMs = this.pollIntervalMs;
    this.timer = setInterval(() => this.tick(), intervalMs);
    Logger.info(`QueueRunner started with poll interval ${intervalMs}ms`);
  }

  getStatus() {
    return {
      running: this.running,
      timerActive: !!this.timer,
      pollIntervalMs: this.pollIntervalMs
    };
  }

  stop() {
    if (!this.running) return;
    clearInterval(this.timer);
    this.timer = null;
    this.running = false;
    Logger.info('QueueRunner stopped');
  }
}

module.exports = QueueRunner;
