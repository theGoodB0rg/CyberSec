const express = require('express');
const bcrypt = require('bcrypt');
const Logger = require('../utils/logger');
const { signToken, requireAuth } = require('../middleware/auth');

function createAuthRouter(database) {
  const router = express.Router();

  router.post('/register', async (req, res) => {
    try {
      const { email, password } = req.body;
      if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
      const existing = await database.getUserByEmail(email);
      if (existing) return res.status(409).json({ error: 'Email already registered' });
      const password_hash = await bcrypt.hash(password, 12);
      const id = await database.createUser({ email, password_hash });
      const user = { id, email, role: 'user' };
      const token = signToken(user);
      res.status(201).json({ token, user });
    } catch (e) {
      Logger.error('Register failed', e);
      res.status(500).json({ error: 'Registration failed' });
    }
  });

  router.post('/login', async (req, res) => {
    try {
      const { email, password } = req.body;
      if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
      const user = await database.getUserByEmail(email);
      if (!user) return res.status(401).json({ error: 'Invalid credentials' });
      const ok = await bcrypt.compare(password, user.password_hash);
      if (!ok) return res.status(401).json({ error: 'Invalid credentials' });
      await database.setUserLastLogin(user.id);
      const token = signToken(user);
      res.json({ token, user: { id: user.id, email: user.email, role: user.role } });
    } catch (e) {
      Logger.error('Login failed', e);
      res.status(500).json({ error: 'Login failed' });
    }
  });

  router.get('/me', requireAuth, async (req, res) => {
    try {
      const user = await database.getUserById(req.user.id);
      if (!user) return res.status(404).json({ error: 'User not found' });
      res.json({ id: user.id, email: user.email, role: user.role });
    } catch (e) {
      Logger.error('Get me failed', e);
      res.status(500).json({ error: 'Failed to fetch profile' });
    }
  });

  return router;
}

module.exports = createAuthRouter;
