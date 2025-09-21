const express = require('express');
const { v4: uuidv4 } = require('uuid');
const dns = require('dns').promises;
const axios = require('axios');
const Logger = require('../utils/logger');
const { requireAuth } = require('../middleware/auth');

function createTargetsRouter(database) {
  const router = express.Router();

  // List verified targets for user/org
  router.get('/', requireAuth, async (req, res) => {
    try {
      const items = await database.listVerifiedTargets(req.user.id, req.user.orgId, req.user.role === 'admin');
      res.json(items);
    } catch (e) {
      Logger.error('List targets failed', e);
      res.status(500).json({ error: 'Failed to list targets' });
    }
  });

  // Create verification request (generates token)
  router.post('/', requireAuth, async (req, res) => {
    try {
      const { hostname, method } = req.body;
      if (!hostname || !method || !['http-file', 'dns-txt'].includes(method)) {
        return res.status(400).json({ error: 'hostname and method (http-file|dns-txt) are required' });
      }
      const token = `cybersec-verify-${uuidv4()}`;
      const id = await database.upsertVerifiedTarget({
        id: uuidv4(),
        user_id: req.user.id,
        org_id: req.user.orgId || null,
        hostname: hostname.toLowerCase(),
        method,
        token
      });
      res.status(201).json({ id, hostname, method, token });
    } catch (e) {
      Logger.error('Create target failed', e);
      res.status(500).json({ error: 'Failed to create verification request' });
    }
  });

  // Verify target
  router.post('/:id/verify', requireAuth, async (req, res) => {
    try {
      const { id } = req.params;
      // Load record
      const items = await database.listVerifiedTargets(req.user.id, req.user.orgId, req.user.role === 'admin');
      const item = items.find(i => i.id === id);
      if (!item) return res.status(404).json({ error: 'Verification request not found' });

      const now = new Date().toISOString();
      if (item.method === 'http-file') {
        // Expect a reachable URL: http(s)://hostname/.well-known/cybersec-verify.txt containing the token
        const url = `https://${item.hostname}/.well-known/cybersec-verify.txt`;
        try {
          const resp = await axios.get(url, { timeout: 8000, maxRedirects: 2, validateStatus: () => true });
          const body = (resp.data || '').toString();
          if (resp.status >= 200 && resp.status < 400 && body.includes(item.token)) {
            await database.markVerifiedTarget(item.id, now);
            return res.json({ id: item.id, verified_at: now });
          }
          return res.status(400).json({ error: 'Verification file missing or token not found' });
        } catch (e) {
          return res.status(400).json({ error: 'Failed to fetch verification file' });
        }
      } else if (item.method === 'dns-txt') {
        try {
          const records = await dns.resolveTxt(item.hostname);
          const flat = records.flat().map(s => s.toString());
          const match = flat.some(txt => txt.includes(item.token));
          if (match) {
            await database.markVerifiedTarget(item.id, now);
            return res.json({ id: item.id, verified_at: now });
          }
          return res.status(400).json({ error: 'DNS TXT record with token not found' });
        } catch (e) {
          return res.status(400).json({ error: 'Failed to resolve DNS TXT records' });
        }
      }
      return res.status(400).json({ error: 'Unsupported verification method' });
    } catch (e) {
      Logger.error('Verify target failed', e);
      res.status(500).json({ error: 'Verification failed' });
    }
  });

  // Delete request
  router.delete('/:id', requireAuth, async (req, res) => {
    try {
      const items = await database.listVerifiedTargets(req.user.id, req.user.orgId, req.user.role === 'admin');
      const item = items.find(i => i.id === req.params.id);
      if (!item) return res.status(404).json({ error: 'Not found' });
      const isAdmin = req.user.role === 'admin';
      const sameUser = item.user_id === req.user.id;
      const sameOrg = req.user.orgId && item.org_id && req.user.orgId === item.org_id;
      if (!(isAdmin || sameUser || sameOrg)) {
        return res.status(403).json({ error: 'Forbidden' });
      }
      const ok = await database.deleteVerifiedTarget(req.params.id);
      res.json({ success: ok });
    } catch (e) {
      Logger.error('Delete target failed', e);
      res.status(500).json({ error: 'Failed to delete target' });
    }
  });

  return router;
}

module.exports = createTargetsRouter;
