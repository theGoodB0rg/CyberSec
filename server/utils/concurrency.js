const Logger = require('./logger');

const parsePositiveInt = (value, fallback = 1) => {
  if (value === undefined || value === null || value === '') return fallback;
  const parsed = parseInt(String(value), 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
};

const resolveConcurrentLimit = ({ isAdmin = false, env = process.env } = {}) => {
  const baseLimit = parsePositiveInt(env.MAX_CONCURRENT_SCANS_PER_USER, 1);
  const adminEnv = env.MAX_CONCURRENT_SCANS_PER_ADMIN ?? env.MAX_CONCURRENT_SCANS_PER_USER_ADMIN;
  const adminLimit = adminEnv ? parsePositiveInt(adminEnv, baseLimit) : baseLimit;
  return isAdmin ? adminLimit : baseLimit;
};

const shapeRunningProcess = (scanId, info) => ({
  id: scanId,
  target: info?.target,
  scanProfile: info?.scanProfile,
  startTime: info?.startTime instanceof Date ? info.startTime.toISOString() : info?.startTime,
  status: 'running',
  sessionId: info?.sessionId ?? null
});

const shapeActiveRecord = (record) => {
  if (!record) return null;
  return {
    id: record.id,
    target: record.target,
    scanProfile: record.scan_profile || record.scanProfile,
    startTime: record.start_time || record.startTime,
    status: record.status,
    sessionId: record.session_id || record.sessionId || null
  };
};

const evaluateConcurrencyForUser = async ({
  userId,
  isAdmin = false,
  database,
  scanProcesses,
  excludeScanIds = [],
  env = process.env
}) => {
  if (!userId) {
    return { hasCapacity: true, limit: Infinity, activeScan: null };
  }

  const limit = resolveConcurrentLimit({ isAdmin, env });

  let activeScanRecord = null;
  try {
    activeScanRecord = await database.getActiveScanForUser(userId);
    if (activeScanRecord && excludeScanIds.includes(activeScanRecord.id)) {
      activeScanRecord = null;
    }
  } catch (error) {
    Logger.warn('Active scan lookup failed', { userId, error: error.message });
  }

  const runningEntries = Array.from(scanProcesses.entries()).filter(([scanId, info]) => {
    if (!info || info.userId !== userId) return false;
    return !excludeScanIds.includes(scanId);
  });

  const activeCount = Math.max(activeScanRecord ? 1 : 0, runningEntries.length);
  const hasCapacity = limit <= 0 || activeCount < limit;

  if (hasCapacity) {
    return { hasCapacity: true, limit, activeScan: null };
  }

  const activeScan = shapeActiveRecord(activeScanRecord) || (runningEntries.length > 0 ? shapeRunningProcess(runningEntries[0][0], runningEntries[0][1]) : null);

  return { hasCapacity: false, limit, activeScan };
};

module.exports = {
  evaluateConcurrencyForUser,
  resolveConcurrentLimit,
  parsePositiveInt,
  shapeRunningProcess
};
