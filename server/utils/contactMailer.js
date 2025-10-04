const fs = require('fs')
const path = require('path')
const nodemailer = require('nodemailer')
const Logger = require('./logger')

const FALLBACK_FILENAME = 'contact-submissions.log'
const LOG_DIR = path.join(__dirname, '..', 'logs')

const truthy = value => ['true', '1', 'yes', 'on'].includes(String(value).toLowerCase())

const resolveTransportConfig = () => {
  const service = process.env.CONTACT_SMTP_SERVICE
  const host = process.env.CONTACT_SMTP_HOST
  const user = process.env.CONTACT_SMTP_USER
  const pass = process.env.CONTACT_SMTP_PASSWORD

  if (!service && !host) return null
  if (!user || !pass) {
    Logger.warn('Contact mailer missing credentials; falling back to file logging')
    return null
  }

  const base = service
    ? { service }
    : {
        host,
        port: Number(process.env.CONTACT_SMTP_PORT || '587'),
        secure: truthy(process.env.CONTACT_SMTP_SECURE),
      }

  return {
    ...base,
    auth: {
      user,
      pass,
    },
  }
}

const ensureLogDir = async () => {
  await fs.promises.mkdir(LOG_DIR, { recursive: true })
}

const writeFallbackEntry = async (payload, meta) => {
  try {
    await ensureLogDir()
    const filePath = path.join(LOG_DIR, FALLBACK_FILENAME)
    const entry = {
      receivedAt: new Date().toISOString(),
      payload,
      meta,
    }
    await fs.promises.appendFile(filePath, JSON.stringify(entry) + '\n', { encoding: 'utf8' })
  } catch (error) {
    Logger.error('Failed to persist contact submission fallback', { error: error.message })
  }
}

const buildMessage = (payload, meta, toAddress, fromAddress) => {
  const safeOrg = payload.organisation ? `Organisation: ${payload.organisation}\n` : ''
  const consentLine = payload.consent ? 'Consent: affirmative' : 'Consent: declined'
  const metadata = [
    `IP: ${meta.ip || 'unknown'}`,
    `User-Agent: ${meta.userAgent || 'unknown'}`,
    meta.referer ? `Referer: ${meta.referer}` : null,
  ]
    .filter(Boolean)
    .join('\n')

  return {
    to: toAddress,
    from: fromAddress,
    subject: `[CyberSec Contact] ${payload.name || 'New submission'}`,
    text: `Name: ${payload.name}\nEmail: ${payload.email}\n${safeOrg}Message:\n${payload.message}\n\n${consentLine}\n---\n${metadata}`,
  }
}

const sanitizePayload = payload => ({
  name: String(payload.name || '').trim().slice(0, 160),
  email: String(payload.email || '').trim().toLowerCase(),
  organisation: payload.organisation ? String(payload.organisation).trim().slice(0, 200) : undefined,
  message: String(payload.message || '').trim().slice(0, 4000),
  consent: Boolean(payload.consent),
})

function createContactMailer() {
  const toAddress = process.env.CONTACT_EMAIL_TO || 'theregalstarlite@gmail.com'
  const fromAddress = process.env.CONTACT_EMAIL_FROM || toAddress
  const transportConfig = resolveTransportConfig()
  const transporter = transportConfig ? nodemailer.createTransport(transportConfig) : null

  if (transporter) {
    transporter.verify().then(() => {
      Logger.info('Contact mailer SMTP transport verified', { service: transportConfig.service || transportConfig.host })
    }).catch(error => {
      Logger.warn('Contact mailer SMTP transport verification failed; messages may fallback to file logging', { error: error.message })
    })
  } else {
    Logger.warn('Contact mailer not fully configured; submissions will be logged to file only')
  }

  const send = async (data, meta = {}) => {
    const payload = sanitizePayload(data)
    const mail = buildMessage(payload, meta, toAddress, fromAddress)

    if (!transporter) {
      await writeFallbackEntry(payload, meta)
      return { delivered: false, stored: true }
    }

    try {
      await transporter.sendMail(mail)
      return { delivered: true, stored: false }
    } catch (error) {
      Logger.error('Contact mail send failed; falling back to file logging', { error: error.message })
      await writeFallbackEntry(payload, meta)
      return { delivered: false, stored: true }
    }
  }

  return {
    send,
    toAddress,
    isConfigured: Boolean(transporter),
  }
}

module.exports = {
  createContactMailer,
}
