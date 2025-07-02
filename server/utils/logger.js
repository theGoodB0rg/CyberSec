const winston = require('winston');
const path = require('path');
const fs = require('fs');

// Ensure logs directory exists
const logsDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// Custom log format
const logFormat = winston.format.combine(
  winston.format.timestamp({
    format: 'YYYY-MM-DD HH:mm:ss'
  }),
  winston.format.errors({ stack: true }),
  winston.format.json(),
  winston.format.printf(({ timestamp, level, message, stack, ...meta }) => {
    let log = `${timestamp} [${level.toUpperCase()}]: ${message}`;
    
    if (Object.keys(meta).length > 0) {
      log += ` | ${JSON.stringify(meta)}`;
    }
    
    if (stack) {
      log += `\n${stack}`;
    }
    
    return log;
  })
);

// Console format for development
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({
    format: 'HH:mm:ss'
  }),
  winston.format.printf(({ timestamp, level, message, stack }) => {
    let log = `${timestamp} ${level}: ${message}`;
    if (stack) {
      log += `\n${stack}`;
    }
    return log;
  })
);

// Create Winston logger
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: logFormat,
  defaultMeta: { service: 'cybersecurity-app' },
  transports: [
    // File transport for all logs
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    new winston.transports.File({
      filename: path.join(logsDir, 'combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    // Separate file for security events
    new winston.transports.File({
      filename: path.join(logsDir, 'security.log'),
      level: 'warn',
      maxsize: 5242880, // 5MB
      maxFiles: 10,
    })
  ],
  // Handle uncaught exceptions
  exceptionHandlers: [
    new winston.transports.File({
      filename: path.join(logsDir, 'exceptions.log')
    })
  ],
  // Handle unhandled promise rejections
  rejectionHandlers: [
    new winston.transports.File({
      filename: path.join(logsDir, 'rejections.log')
    })
  ]
});

// Add console transport for development
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: consoleFormat,
    level: 'debug'
  }));
} else {
  // In production, only log warnings and errors to console
  logger.add(new winston.transports.Console({
    format: consoleFormat,
    level: 'warn'
  }));
}

// Custom logging methods
class Logger {
  static info(message, meta = {}) {
    logger.info(message, meta);
  }

  static warn(message, meta = {}) {
    logger.warn(message, meta);
  }

  static error(message, meta = {}) {
    if (message instanceof Error) {
      logger.error(message.message, { 
        stack: message.stack, 
        name: message.name,
        ...meta 
      });
    } else {
      logger.error(message, meta);
    }
  }

  static debug(message, meta = {}) {
    logger.debug(message, meta);
  }

  static security(event, details = {}) {
    logger.warn(`SECURITY EVENT: ${event}`, {
      type: 'security',
      event,
      timestamp: new Date().toISOString(),
      ...details
    });
  }

  static sqlmap(message, scanId, meta = {}) {
    logger.info(`SQLMap: ${message}`, {
      type: 'sqlmap',
      scanId,
      ...meta
    });
  }

  static api(method, path, statusCode, responseTime, meta = {}) {
    const level = statusCode >= 400 ? 'warn' : 'info';
    logger[level]('API Request', {
      type: 'api',
      method,
      path,
      statusCode,
      responseTime,
      ...meta
    });
  }

  static database(operation, table, meta = {}) {
    logger.debug(`Database: ${operation} on ${table}`, {
      type: 'database',
      operation,
      table,
      ...meta
    });
  }

  static performance(operation, duration, meta = {}) {
    logger.info(`Performance: ${operation} took ${duration}ms`, {
      type: 'performance',
      operation,
      duration,
      ...meta
    });
  }

  static audit(action, user, resource, meta = {}) {
    logger.info(`Audit: ${action} by ${user} on ${resource}`, {
      type: 'audit',
      action,
      user,
      resource,
      timestamp: new Date().toISOString(),
      ...meta
    });
  }

  // Log scan lifecycle events
  static scanStarted(scanId, target, profile) {
    this.sqlmap('Scan started', scanId, {
      target,
      profile,
      status: 'started'
    });
  }

  static scanCompleted(scanId, target, duration, status) {
    this.sqlmap('Scan completed', scanId, {
      target,
      duration,
      status,
      completed: true
    });
  }

  static scanError(scanId, target, error) {
    this.sqlmap('Scan error', scanId, {
      target,
      error: error.message,
      status: 'error'
    });
  }

  static scanTerminated(scanId, target) {
    this.sqlmap('Scan terminated', scanId, {
      target,
      status: 'terminated'
    });
  }

  // Log report generation events
  static reportGenerated(reportId, scanId, format) {
    this.info('Report generated', {
      type: 'report',
      reportId,
      scanId,
      format,
      status: 'generated'
    });
  }

  static reportExported(reportId, format, fileSize) {
    this.info('Report exported', {
      type: 'report',
      reportId,
      format,
      fileSize,
      status: 'exported'
    });
  }

  // Log security events with specific context
  static suspiciousActivity(type, details) {
    this.security('Suspicious Activity', {
      activityType: type,
      severity: 'medium',
      ...details
    });
  }

  static attackAttempt(type, details) {
    this.security('Attack Attempt', {
      attackType: type,
      severity: 'high',
      ...details
    });
  }

  static unauthorizedAccess(resource, details) {
    this.security('Unauthorized Access', {
      resource,
      severity: 'high',
      ...details
    });
  }

  static rateLimitExceeded(ip, endpoint, details) {
    this.security('Rate Limit Exceeded', {
      ip,
      endpoint,
      severity: 'medium',
      ...details
    });
  }

  // System events
  static systemStartup(version, environment) {
    this.info('System startup', {
      type: 'system',
      version,
      environment,
      nodeVersion: process.version,
      platform: process.platform
    });
  }

  static systemShutdown(reason) {
    this.info('System shutdown', {
      type: 'system',
      reason,
      uptime: process.uptime()
    });
  }

  static configLoaded(configFile, settings) {
    this.info('Configuration loaded', {
      type: 'config',
      configFile,
      settingsCount: Object.keys(settings).length
    });
  }

  // Database events
  static databaseConnected(dbPath) {
    this.info('Database connected', {
      type: 'database',
      dbPath,
      status: 'connected'
    });
  }

  static databaseError(operation, error) {
    this.error('Database error', {
      type: 'database',
      operation,
      error: error.message
    });
  }

  // Utility methods
  static getLogLevel() {
    return logger.level;
  }

  static setLogLevel(level) {
    logger.level = level;
    this.info(`Log level changed to: ${level}`);
  }

  static createRequestLogger() {
    return (req, res, next) => {
      const start = Date.now();
      
      res.on('finish', () => {
        const duration = Date.now() - start;
        this.api(
          req.method,
          req.path,
          res.statusCode,
          duration,
          {
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            contentLength: res.get('content-length')
          }
        );
      });
      
      next();
    };
  }

  static createErrorLogger() {
    return (err, req, res, next) => {
      this.error('Express error', {
        error: err.message,
        stack: err.stack,
        method: req.method,
        path: req.path,
        ip: req.ip,
        userAgent: req.get('User-Agent')
      });
      
      next(err);
    };
  }

  // Log cleanup utility
  static async cleanupOldLogs(daysToKeep = 30) {
    try {
      const files = fs.readdirSync(logsDir);
      const cutoffDate = new Date();
      cutoffDate.setDate(cutoffDate.getDate() - daysToKeep);

      for (const file of files) {
        const filePath = path.join(logsDir, file);
        const stats = fs.statSync(filePath);
        
        if (stats.mtime < cutoffDate) {
          fs.unlinkSync(filePath);
          this.info(`Deleted old log file: ${file}`);
        }
      }
    } catch (error) {
      this.error('Error cleaning up old logs', { error: error.message });
    }
  }

  // Export logs for analysis
  static async exportLogs(startDate, endDate, types = []) {
    try {
      const logFiles = ['combined.log', 'security.log', 'error.log'];
      const exportData = [];

      for (const logFile of logFiles) {
        const filePath = path.join(logsDir, logFile);
        if (!fs.existsSync(filePath)) continue;

        const content = fs.readFileSync(filePath, 'utf8');
        const lines = content.split('\n').filter(line => line.trim());

        for (const line of lines) {
          try {
            const logEntry = JSON.parse(line);
            const logDate = new Date(logEntry.timestamp);

            // Filter by date range
            if (startDate && logDate < new Date(startDate)) continue;
            if (endDate && logDate > new Date(endDate)) continue;

            // Filter by log types
            if (types.length > 0 && !types.includes(logEntry.type)) continue;

            exportData.push(logEntry);
          } catch (parseError) {
            // Skip malformed log entries
          }
        }
      }

      return exportData.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
    } catch (error) {
      this.error('Error exporting logs', { error: error.message });
      return [];
    }
  }
}

module.exports = Logger; 