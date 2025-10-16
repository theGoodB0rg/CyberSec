const validator = require('validator');
const sanitizeHtml = require('sanitize-html');
const rateLimit = require('express-rate-limit');
const Logger = require('../utils/logger');

class SecurityMiddleware {
  static requireProxyIfEnabled(options = {}) {
    // Env may be overridden at runtime by admin settings in the DB (index.js updates process.env)
    const requireProxyEnv = process.env.REQUIRE_PROXY;
    const enforced = ['true', '1', 'yes', 'on'].includes(String(requireProxyEnv).toLowerCase());
    if (!enforced) return { enforced: false, ok: true };

    const proxy = options.proxy || options.proxiedUrl || options.PROXY;
    if (!proxy) {
      return { enforced: true, ok: false, error: 'Proxy required: Set a proxy when REQUIRE_PROXY is enabled.' };
    }
    if (!SecurityMiddleware.isValidProxyURL(proxy)) {
      return { enforced: true, ok: false, error: 'Invalid proxy URL. Must be http(s):// or socks5:// host:port' };
    }
    return { enforced: true, ok: true };
  }

  static isValidProxyURL(url) {
    try {
      if (typeof url !== 'string') return false;
      const parsed = new URL(url);
      const allowedProtocols = ['http:', 'https:', 'socks5:'];
      if (!allowedProtocols.includes(parsed.protocol)) return false;
      if (!parsed.hostname || !parsed.port) return false;
      // Basic length checks
      if (parsed.username && parsed.username.length > 128) return false;
      if (parsed.password && parsed.password.length > 128) return false;
      return true;
    } catch (e) {
      return false;
    }
  }
  static validateInput(req, res, next) {
    try {
      // Skip validation for certain routes
      const isHealth = req.path === '/health' || (req.originalUrl && req.originalUrl.startsWith('/api/health'));
      if (isHealth) {
        return next();
      }

      // Validate request body size
      if (req.body && JSON.stringify(req.body).length > 10 * 1024 * 1024) { // 10MB limit
        return res.status(413).json({ error: 'Request body too large' });
      }

      // Validate common fields
      if (req.body) {
        // Validate URL fields
        const urlFields = ['target', 'url', 'proxy'];
        for (const field of urlFields) {
          if (req.body[field]) {
            if (field === 'proxy') {
              if (!SecurityMiddleware.isValidProxyURL(req.body[field])) {
                return res.status(400).json({
                  error: 'Invalid proxy: Must be http(s):// or socks5:// host:port'
                });
              }
            } else {
              if (!validator.isURL(req.body[field], {
                protocols: ['http', 'https'],
                require_protocol: true
              })) {
                return res.status(400).json({
                  error: `Invalid ${field}: Must be a valid HTTP/HTTPS URL`
                });
              }
            }
          }
        }

        // Validate string length limits
        const stringFields = {
          userAgent: 512,
          cookie: 2048,
          data: 8192,
          customFlags: 4096, // Increased to support complex commands with cookies and long URLs
          command: 256
        };

        for (const [field, maxLength] of Object.entries(stringFields)) {
          if (req.body[field] && req.body[field].length > maxLength) {
            return res.status(400).json({ 
              error: `${field} exceeds maximum length of ${maxLength} characters` 
            });
          }
        }

        // Validate numeric fields
        const numericFields = ['timeout', 'delay', 'threads', 'level', 'risk'];
        for (const field of numericFields) {
          if (req.body[field] !== undefined) {
            const value = parseInt(req.body[field]);
            if (isNaN(value) || value < 0 || value > 100) {
              return res.status(400).json({ 
                error: `Invalid ${field}: Must be a number between 0 and 100` 
              });
            }
          }
        }

        // Validate method field
        if (req.body.method) {
          const allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS'];
          if (!allowedMethods.includes(req.body.method.toUpperCase())) {
            return res.status(400).json({ 
              error: 'Invalid HTTP method' 
            });
          }
        }

        // Validate scan profile
        if (req.body.scanProfile) {
          const allowedProfiles = ['basic', 'deep', 'enumeration', 'dump', 'custom'];
          if (!allowedProfiles.includes(req.body.scanProfile)) {
            return res.status(400).json({ 
              error: 'Invalid scan profile' 
            });
          }
        }
      }

      next();
    } catch (error) {
      Logger.error('Input validation error:', error);
      res.status(400).json({ error: 'Invalid input data' });
    }
  }

  static sanitizeInput(req, res, next) {
    try {
      if (req.body) {
        // Sanitize HTML in string fields
        const sanitizeOptions = {
          allowedTags: [],
          allowedAttributes: {},
          disallowedTagsMode: 'discard'
        };

        const stringFields = [
          'target', 'userAgent', 'cookie', 'data', 'customFlags', 
          'command', 'title', 'description'
        ];

        for (const field of stringFields) {
          if (typeof req.body[field] === 'string') {
            req.body[field] = sanitizeHtml(req.body[field], sanitizeOptions).trim();
          }
        }

        // Sanitize headers object
        if (req.body.headers && typeof req.body.headers === 'object') {
          const sanitizedHeaders = {};
          for (const [key, value] of Object.entries(req.body.headers)) {
            const sanitizedKey = sanitizeHtml(key, sanitizeOptions).trim();
            const sanitizedValue = sanitizeHtml(value, sanitizeOptions).trim();
            
            // Validate header name format
            if (/^[a-zA-Z0-9\-_]+$/.test(sanitizedKey)) {
              sanitizedHeaders[sanitizedKey] = sanitizedValue;
            }
          }
          req.body.headers = sanitizedHeaders;
        }

        // Remove any potential script injections
        const dangerousPatterns = [
          /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi,
          /javascript:/gi,
          /on\w+\s*=/gi,
          /eval\s*\(/gi,
          /expression\s*\(/gi
        ];

        for (const field of stringFields) {
          if (typeof req.body[field] === 'string') {
            for (const pattern of dangerousPatterns) {
              req.body[field] = req.body[field].replace(pattern, '');
            }
          }
        }
      }

      next();
    } catch (error) {
      Logger.error('Input sanitization error:', error);
      res.status(400).json({ error: 'Failed to sanitize input' });
    }
  }

  static isValidURL(url) {
    try {
      // Basic URL validation
      if (!url || typeof url !== 'string') {
        return false;
      }

      // Check for protocol
      if (!/^https?:\/\//.test(url)) {
        return false;
      }

      // Use validator library for comprehensive validation
      if (!validator.isURL(url, { 
        protocols: ['http', 'https'],
        require_protocol: true,
        require_host: true,
        allow_query_components: true
      })) {
        return false;
      }

      // Additional security checks
      const parsedUrl = new URL(url);
      const hostname = parsedUrl.hostname.toLowerCase();
      const allowLocal = (
        ['true', '1', 'yes', 'on'].includes(String(process.env.ALLOW_LOCALHOST_TARGETS).toLowerCase())
        || process.env.NODE_ENV !== 'production'
      );
      
      // Block private/local IP ranges
      const privateRanges = [
        /^127\./,          // Loopback
        /^10\./,           // Private class A
        /^172\.(1[6-9]|2\d|3[01])\./,  // Private class B
        /^192\.168\./,     // Private class C
        /^169\.254\./,     // Link-local
        /^::1$/,           // IPv6 loopback
        /^fc00:/,          // IPv6 private
        /^fe80:/           // IPv6 link-local
      ];

      // Check if hostname is an IP address
      if (validator.isIP(hostname)) {
        // Allow loopback when enabled
        if (allowLocal && (/^127\./.test(hostname) || hostname === '::1')) {
          return true;
        }
        for (const range of privateRanges) {
          if (range.test(hostname)) {
            return false; // Block private IPs
          }
        }
      }

      // Block localhost variations
      const localhostVariations = ['localhost', '0.0.0.0', '127.0.0.1', '::1'];
      if (localhostVariations.includes(hostname)) {
        return allowLocal ? true : false;
      }

      return true;
    } catch (error) {
      Logger.warn(`URL validation error: ${error.message}`);
      return false;
    }
  }

  static isAllowedCommand(command) {
    const allowedCommands = [
      'sqlmap-help',
      'sqlmap-version',
      'list-profiles',
      'validate-target',
      'clear',
      'help',
      'version',
      'status'
    ];

    return allowedCommands.includes(command);
  }

  static createAPIRateLimit() {
    return rateLimit({
      windowMs: 15 * 60 * 1000, // 15 minutes
      max: 50, // limit each IP to 50 API requests per windowMs
      message: {
        error: 'Too many API requests, please try again later.',
        retryAfter: '15 minutes'
      },
      standardHeaders: true,
      legacyHeaders: false,
      handler: (req, res) => {
        Logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
        res.status(429).json({
          error: 'Too many API requests, please try again later.',
          retryAfter: '15 minutes'
        });
      }
    });
  }

  static createScanRateLimit() {
    return rateLimit({
      windowMs: 60 * 60 * 1000, // 1 hour
      max: 10, // limit each IP to 10 scans per hour
      message: {
        error: 'Too many scan requests, please try again later.',
        retryAfter: '1 hour'
      },
      standardHeaders: true,
      legacyHeaders: false,
      keyGenerator: (req) => {
        // Use IP + user agent for more specific limiting
        return `${req.ip}-${req.get('User-Agent') || 'unknown'}`;
      },
      handler: (req, res) => {
        Logger.warn(`Scan rate limit exceeded for IP: ${req.ip}`);
        res.status(429).json({
          error: 'Too many scan requests, please try again later.',
          retryAfter: '1 hour'
        });
      }
    });
  }

  static validateFileAccess(filePath) {
    const path = require('path');
    
    // Prevent path traversal attacks
    const normalizedPath = path.normalize(filePath);
    const basePath = path.resolve(__dirname, '..');
    
    if (!normalizedPath.startsWith(basePath)) {
      throw new Error('Access denied: Path traversal detected');
    }

    // Block access to sensitive files
    const blockedPatterns = [
      /\.env$/,
      /\.key$/,
      /\.pem$/,
      /passwd$/,
      /shadow$/,
      /\.ssh\//,
      /node_modules\//,
      /\.git\//
    ];

    for (const pattern of blockedPatterns) {
      if (pattern.test(normalizedPath)) {
        throw new Error('Access denied: Sensitive file access blocked');
      }
    }

    return normalizedPath;
  }

  static logSecurityEvent(event, details = {}) {
    Logger.warn('Security Event:', {
      event,
      timestamp: new Date().toISOString(),
      ...details
    });
  }

  static detectSQLInjection(input) {
    if (typeof input !== 'string') return false;

    const sqlPatterns = [
      /(\b(union|select|insert|update|delete|drop|create|alter|exec|execute)\b)/i,
      /(\b(or|and)\s+\d+\s*=\s*\d+)/i,
      /(\b(or|and)\s+['"]\w+['"])/i,
      /['"]\s*(or|and)\s*['"]/i,
      /--/,
      /\/\*/,
      /\*\//,
      /;/
    ];

    return sqlPatterns.some(pattern => pattern.test(input));
  }

  static detectXSS(input) {
    if (typeof input !== 'string') return false;

    const xssPatterns = [
      /<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/i,
      /javascript:/i,
      /on\w+\s*=/i,
      /<iframe/i,
      /<object/i,
      /<embed/i,
      /<link/i,
      /<meta/i,
      /expression\s*\(/i,
      /eval\s*\(/i
    ];

    return xssPatterns.some(pattern => pattern.test(input));
  }

  static detectCommandInjection(input) {
    if (typeof input !== 'string') return false;

    // Focus on high-signal separators and subshells; avoid matching JSON braces/parentheses
    const commandPatterns = [
      /(;|&&|\|\|)/,                 // common command separators
      /`/,                            // backticks for subshell
      /\$\(/,                         // $(subshell)
      /\$\{[^}]*\}/,                 // ${var}
      /\.\.\//,                       // path traversal
      /(\/etc\/|\/proc\/|\/sys\/)/,   // sensitive paths
      /\b(cmd\.exe|powershell|bash|sh)\b/i // known shells
    ];

    return commandPatterns.some(pattern => pattern.test(input));
  }

  static securityScanner(req, res, next) {
    try {
      // Skip lightweight endpoints that should never be blocked
      const isHealth = req.path === '/health' || (req.originalUrl && req.originalUrl.startsWith('/api/health'));
      const isAuthEndpoint = req.path && (/^\/auth\//.test(req.path));
      // Skip validation endpoint - it's designed to safely validate potentially malicious commands
      const isValidationEndpoint = req.path === '/api/sqlmap/validate' || req.path === '/sqlmap/validate';
      // Skip profile endpoints - they legitimately contain sqlmap flags with special characters
      const isProfileEndpoint = req.path && (/^\/user\/profiles/.test(req.path));
      
      if (isHealth || isAuthEndpoint || isValidationEndpoint || isProfileEndpoint) {
        return next();
      }

      // Helper to safely collect only string values from user-provided input
      const EXCLUDED_KEYS = new Set(['password', 'newPassword', 'currentPassword', 'confirmPassword', 'token']);
      const collectStrings = (val, depth = 0, keyHint = '') => {
        if (depth > 5) return [];
        if (typeof val === 'string') {
          if (keyHint && EXCLUDED_KEYS.has(String(keyHint))) return [];
          return [val];
        }
        if (Array.isArray(val)) return val.flatMap(v => collectStrings(v, depth + 1, keyHint));
        if (val && typeof val === 'object') {
          return Object.entries(val).flatMap(([k, v]) => collectStrings(v, depth + 1, k));
        }
        return [];
      };

      // Only scan concatenated string fields (avoid JSON structural characters like {})
      const requestData = [
        ...collectStrings(req.body || {}),
        ...collectStrings(req.query || {}),
        ...collectStrings(req.params || {})
      ].join('\n');

      // Scan for various attack patterns
      const threats = [];

      if (SecurityMiddleware.detectSQLInjection(requestData)) {
        threats.push('SQL Injection');
      }

      if (SecurityMiddleware.detectXSS(requestData)) {
        threats.push('XSS');
      }

      if (SecurityMiddleware.detectCommandInjection(requestData)) {
        threats.push('Command Injection');
      }

      if (threats.length > 0) {
        SecurityMiddleware.logSecurityEvent('Potential Attack Detected', {
          threats,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          path: req.path,
          method: req.method
        });

        // Only block on clear threats with non-GET methods; for GET, log and allow in dev
        const isProd = String(process.env.NODE_ENV || '').toLowerCase() === 'production';
        if (isProd || req.method !== 'GET') {
          return res.status(403).json({
            error: 'Request blocked due to security concerns',
            threats
          });
        }
      }

      next();
    } catch (error) {
      Logger.error('Security scanner error:', error);
      next(); // Continue on scanner error to avoid blocking legitimate requests
    }
  }
}

module.exports = SecurityMiddleware; 