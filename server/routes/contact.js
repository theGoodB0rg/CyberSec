const express = require('express')
const rateLimit = require('express-rate-limit')
const validator = require('validator')
const Logger = require('../utils/logger')

const limiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  limit: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: 'Too many contact requests. Please try again later.',
})

const normalizeString = (input, maxLength) =>
  String(input || '')
    .replace(/[\r\t]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, maxLength)

const normalizeMessage = input =>
  validator
    .stripLow(String(input || ''), true)
    .replace(/\r\n/g, '\n')
    .replace(/\r/g, '\n')
    .trim()

const MIN_MESSAGE_LENGTH = 40
const MAX_MESSAGE_LENGTH = 4000

module.exports = function createContactRouter(mailer, database) {
  const router = express.Router()

  if (!mailer || typeof mailer.send !== 'function') {
    throw new Error('Contact router requires a mailer with a send(payload, meta) method')
  }

  router.post('/', limiter, async (req, res) => {
    try {
      const { name, email, organisation, message, consent } = req.body || {}
      const cleanedName = normalizeString(name, 160)
      const cleanedEmail = normalizeString(email, 190).toLowerCase()
      const cleanedOrganisation = organisation ? normalizeString(organisation, 200) : undefined
      const cleanedMessage = normalizeMessage(message)

      if (!consent) {
        return res.status(400).json({ error: 'consent-required' })
      }

      if (!cleanedName) {
        return res.status(400).json({ error: 'name-required' })
      }

      if (!cleanedEmail || !validator.isEmail(cleanedEmail)) {
        return res.status(400).json({ error: 'email-invalid' })
      }

      if (cleanedMessage.length < MIN_MESSAGE_LENGTH) {
        return res.status(400).json({ error: 'message-too-short', minLength: MIN_MESSAGE_LENGTH })
      }

      if (cleanedMessage.length > MAX_MESSAGE_LENGTH) {
        return res.status(400).json({ error: 'message-too-long', maxLength: MAX_MESSAGE_LENGTH })
      }

      const meta = {
        ip: req.ip,
        userAgent: req.get('user-agent'),
        referer: req.get('referer') || req.get('referrer'),
      }

      const result = await mailer.send(
        {
          name: cleanedName,
          email: cleanedEmail,
          organisation: cleanedOrganisation,
          message: cleanedMessage,
          consent: Boolean(consent),
        },
        meta
      )

      try {
        Logger.info('Contact submission received', {
          email: cleanedEmail,
          delivered: result.delivered,
          storedFallback: result.stored,
          ip: meta.ip,
        })
      } catch (_) {}

      if (database && typeof database.logTelemetry === 'function') {
        database
          .logTelemetry({
            event_type: 'feedback-submitted',
            metadata: {
              delivered: Boolean(result.delivered),
              stored: Boolean(result.stored),
              organisation: cleanedOrganisation || null,
              consent: Boolean(consent),
              approximateLength: cleanedMessage.length,
            },
          })
          .catch((error) => {
            try {
              Logger.warn('Failed to record feedback telemetry', { error: error.message })
            } catch (_) {}
          })
      }

      const statusCode = result.delivered ? 200 : 202
      return res.status(statusCode).json({ ok: true, delivered: result.delivered, fallback: result.stored })
    } catch (error) {
      Logger.error('Contact submission failed', { error: error.message })
      return res.status(500).json({ error: 'contact-send-failed' })
    }
  })

  return router
}
