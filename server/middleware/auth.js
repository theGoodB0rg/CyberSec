const jwt = require('jsonwebtoken');
const Logger = require('../utils/logger');

const JWT_SECRET = process.env.JWT_SECRET || 'dev-insecure-secret-change-me';

/**
 * Augments Express Request with user context
 * @typedef {Object} RequestUser
 * @property {string|number} id
 * @property {string|number|null} orgId
 * @property {string} role
 * @property {string|undefined} email
 */

module.exports = {
  /**
   * Verifies Authorization: Bearer <jwt> and attaches req.user
   * @param {import('express').Request & { user?: import('./auth').RequestUser }} req 
   * @param {import('express').Response} res
   * @param {import('express').NextFunction} next
   */
  requireAuth(req, res, next) {
    try {
      const header = req.headers['authorization'] || '';
      const token = header.startsWith('Bearer ') ? header.slice(7) : null;
      if (!token) return res.status(401).json({ error: 'Unauthorized' });
      const decoded = jwt.verify(token, JWT_SECRET);
      req.user = {
        id: decoded.sub || decoded.id,
        orgId: decoded.orgId || null,
        role: decoded.role || 'user',
        email: decoded.email || undefined,
      };
      // Basic validation
      if (!req.user.id) throw new Error('Missing subject in token');
      next();
    } catch (e) {
      Logger.warn('Auth verify failed', { error: e.message });
      return res.status(401).json({ error: 'Unauthorized' });
    }
  },

  /**
   * Requires the current user to be an admin
   */
  requireAdmin(req, res, next) {
    try {
      if (!req.user) {
        return res.status(401).json({ error: 'Unauthorized' });
      }
      if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'Forbidden' });
      }
      return next();
    } catch (e) {
      Logger.warn('Admin check failed', { error: e.message });
      return res.status(403).json({ error: 'Forbidden' });
    }
  },

  /**
   * Optionally attaches req.user if a valid Authorization header is present.
   */
  optionalAuth(req, _res, next) {
    try {
      const header = req.headers['authorization'] || '';
      const token = header.startsWith('Bearer ') ? header.slice(7) : null;
      if (token) {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = {
          id: decoded.sub || decoded.id,
          orgId: decoded.orgId || null,
          role: decoded.role || 'user',
          email: decoded.email || undefined,
        };
      }
    } catch (e) {
      Logger.warn('Optional auth token invalid', { error: e.message });
    } finally {
      next();
    }
  },

  // For socket.io middleware
  /**
   * Validates token at socket.io handshake and sets socket.user
   * @param {import('socket.io').Socket & { user?: RequestUser }} socket
   */
  verifySocketAuth(socket, next) {
    try {
      const token = socket.handshake.auth?.token || socket.handshake.headers?.authorization?.replace('Bearer ', '');
      if (!token) {
        return next(new Error('Unauthorized'));
      }
      const decoded = jwt.verify(token, JWT_SECRET);
      socket.user = {
        id: decoded.sub || decoded.id,
        orgId: decoded.orgId || null,
        role: decoded.role || 'user',
        email: decoded.email || undefined,
      };
      if (!socket.user.id) throw new Error('Missing subject in token');
      return next();
    } catch (e) {
      Logger.warn('Socket auth failed', { error: e.message });
      return next(new Error('Unauthorized'));
    }
  },

  /**
   * Signs a short user claim into a JWT
   */
  signToken(user) {
    const payload = {
      sub: user.id,
      email: user.email,
      role: user.role || 'user',
      orgId: user.orgId || null,
    };
    return jwt.sign(payload, JWT_SECRET, { expiresIn: '7d' });
  }
};
