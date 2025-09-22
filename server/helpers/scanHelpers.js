const axios = require('axios');
const Logger = require('../utils/logger');

// Helper: reduce options to safe-to-store snapshot (no secrets)
function sanitizeOptionsForStorage(options = {}) {
  try {
    const clone = JSON.parse(JSON.stringify(options || {}));
    // Redact known sensitive fields
    if (clone.cookie) clone.cookie = '***redacted***';
    if (clone.headers && typeof clone.headers === 'object') {
      const sensitive = ['authorization', 'cookie', 'x-csrf-token', 'x-xsrf-token'];
      for (const k of Object.keys(clone.headers)) {
        if (sensitive.includes(String(k).toLowerCase())) clone.headers[k] = '***redacted***';
      }
    }
    if (clone.auth) {
      const type = clone.auth.type || clone.auth.mode || 'unknown';
      clone.auth = { type, used: type !== 'none' };
    }
    if (clone.data && typeof clone.data === 'string' && clone.data.length > 0) {
      // Avoid storing raw bodies which may contain secrets
      clone.data = '[omitted]';
    }
    return clone;
  } catch {
    return {};
  }
}

// Helper: build authenticated HTTP context (cookie/header) prior to launching sqlmap
async function prepareAuthContext(rawOptions = {}, __targetUrl = '', userId = 'system') {
  const options = { ...(rawOptions || {}) };
  const auth = options.auth || {};
  const meta = { mode: 'none' };

  // If user supplied direct cookie/headers without auth block, respect them
  if (!auth || auth.type === 'none' || (!auth.type && !auth.mode)) {
    if (options.cookie || (options.headers && Object.keys(options.headers).length)) {
      meta.mode = 'cookie';
    }
    return { preparedOptions: options, authMeta: meta };
  }

  const type = auth.type || auth.mode;
  if (type === 'cookie') {
    // Simple pass-through
    options.cookie = auth.cookie || options.cookie;
    options.headers = { ...(options.headers || {}), ...(auth.headers || {}) };
    meta.mode = 'cookie';
    return { preparedOptions: options, authMeta: meta };
  }

  if (type === 'login') {
    meta.mode = 'login';
    try {
      const loginUrl = auth.loginUrl;
      if (!loginUrl) return { preparedOptions: options, authMeta: meta };

      const method = String(auth.method || 'POST').toUpperCase();
      const usernameField = auth.usernameField || 'username';
      const passwordField = auth.passwordField || 'password';
      const username = auth.username || '';
      const password = auth.password || '';
      const extraFields = auth.extraFields || {};
      const csrf = auth.csrf || {};

      // Basic cookie jar using header parsing
      const cookieMap = new Map();
      const mergeSetCookie = (setCookie) => {
        if (!setCookie) return;
        const arr = Array.isArray(setCookie) ? setCookie : [setCookie];
        for (const c of arr) {
          const pair = String(c).split(';')[0];
          const eq = pair.indexOf('=');
          if (eq > 0) {
            const name = pair.slice(0, eq).trim();
            const val = pair.slice(eq + 1).trim();
            if (name) cookieMap.set(name, val);
          }
        }
      };
      const cookieHeader = () => Array.from(cookieMap.entries()).map(([k, v]) => `${k}=${v}`).join('; ');

      const baseHeaders = {
        'User-Agent': options.userAgent || 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) CyberSecScanner/1.0',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
      };

      // Optional CSRF fetch
      let csrfToken = null;
      const tokenUrl = csrf.tokenUrl || loginUrl;
      try {
        const resp = await axios.get(tokenUrl, { headers: baseHeaders, maxRedirects: 5, validateStatus: () => true });
        mergeSetCookie(resp.headers['set-cookie']);
        if (csrf.regex && typeof csrf.regex === 'string') {
          const re = new RegExp(csrf.regex);
          const m = (resp.data || '').match(re);
          if (m && m[1]) csrfToken = m[1];
        }
      } catch (e) {
        // Proceed without CSRF token if fetch fails
      }

      // Build form
      const params = new URLSearchParams();
      params.set(usernameField, username);
      params.set(passwordField, password);
      for (const [k, v] of Object.entries(extraFields)) params.set(String(k), String(v));
      if (csrfToken) {
        if (csrf.fieldName) params.set(csrf.fieldName, csrfToken);
      }

      const headers = { ...baseHeaders, 'Content-Type': 'application/x-www-form-urlencoded' };
      if (cookieMap.size) headers['Cookie'] = cookieHeader();
      if (csrf.headerName && csrfToken) headers[csrf.headerName] = csrfToken;

      const resp = await axios.request({ url: loginUrl, method, data: params.toString(), headers, maxRedirects: 5, validateStatus: () => true });
      mergeSetCookie(resp.headers['set-cookie']);
      const finalCookie = cookieHeader();
      if (finalCookie) {
        options.cookie = finalCookie;
      }
      // Propagate CSRF header if applicable for subsequent requests
      if (csrf.headerName && csrfToken) {
        options.headers = { ...(options.headers || {}), [csrf.headerName]: csrfToken };
      }

      return { preparedOptions: options, authMeta: meta };
    } catch (e) {
      // If login fails, continue unauthenticated
      Logger.warn('Login auth flow failed; proceeding without session', { error: e.message, userId });
      return { preparedOptions: rawOptions || {}, authMeta: meta };
    }
  }

  return { preparedOptions: options, authMeta: meta };
}

module.exports = {
  sanitizeOptionsForStorage,
  prepareAuthContext,
};
