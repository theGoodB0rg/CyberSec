import { FormEvent, useId, useMemo, useState } from 'react'
import { EnvelopeIcon, AcademicCapIcon } from '@heroicons/react/24/outline'

export type ContactFormPayload = {
  name: string
  email: string
  organisation?: string
  message: string
  consent: boolean
}

interface ContactSectionProps {
  onSubmit?: (payload: ContactFormPayload) => Promise<void>
}

type SubmitStatus =
  | { state: 'idle' }
  | { state: 'success'; message: string }
  | { state: 'error'; message: string }

const defaultStatus: SubmitStatus = { state: 'idle' }

const initialPayload: ContactFormPayload = {
  name: '',
  email: '',
  organisation: '',
  message: '',
  consent: false,
}

export function ContactSection({ onSubmit }: ContactSectionProps) {
  const [form, setForm] = useState<ContactFormPayload>(initialPayload)
  const [status, setStatus] = useState<SubmitStatus>(defaultStatus)
  const [isSubmitting, setSubmitting] = useState(false)
  const nameId = useId()
  const emailId = useId()
  const organisationId = useId()
  const messageId = useId()
  const consentId = useId()

  const isDisabled = useMemo(() => {
    if (isSubmitting) return true
    if (!form.name.trim()) return true
    if (!form.email.trim()) return true
    if (!form.message.trim()) return true
    if (!form.consent) return true
    return false
  }, [form, isSubmitting])

  const onInputChange = (key: keyof ContactFormPayload) =>
    (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => {
      const value = key === 'consent' ? (e.target as HTMLInputElement).checked : e.target.value
      setForm(prev => ({ ...prev, [key]: value }))
      if (status.state !== 'idle') {
        setStatus(defaultStatus)
      }
    }

  const buildMailtoUrl = (payload: ContactFormPayload) => {
    const to = 'theregalstarlite@gmail.com'
    const subject = encodeURIComponent(`CyberSec cohort enquiry – ${payload.name}`)
    const lines = [
      `Name: ${payload.name}`,
      `Email: ${payload.email}`,
      payload.organisation ? `Institution/Department: ${payload.organisation}` : null,
      '',
      'Objectives / Context:',
      payload.message,
      '',
      'Consent: I confirm I am authorised to request a supervised pilot.',
    ].filter(Boolean)
    const body = encodeURIComponent(lines.join('\n'))
    return `mailto:${to}?subject=${subject}&body=${body}`
  }

  const handleSubmit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (isDisabled) return

    const payload: ContactFormPayload = {
      ...form,
      organisation: form.organisation?.trim() || undefined,
      message: form.message.trim(),
      name: form.name.trim(),
      email: form.email.trim(),
    }

    if (onSubmit) {
      setSubmitting(true)
      try {
        await onSubmit(payload)
        setStatus({ state: 'success', message: 'Thanks! We will be in touch within two working days.' })
        setForm(initialPayload)
      } catch (error: any) {
        const message = error?.message || 'Unable to send message right now. Please try again later.'
        setStatus({ state: 'error', message })
      } finally {
        setSubmitting(false)
      }
      return
    }

    try {
      setSubmitting(true)
      const mailto = buildMailtoUrl(payload)
      if (typeof window !== 'undefined') {
        window.location.href = mailto
      } else {
        throw new Error('mail-client-unavailable')
      }
      setStatus({ state: 'success', message: 'We opened a draft email in your default mail client. Please review and send it to finish your request.' })
      setForm(initialPayload)
    } catch {
      setStatus({ state: 'error', message: 'Unable to start your mail client automatically. Email theregalstarlite@gmail.com and include your cohort details.' })
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <section className="bg-gray-950 py-16 sm:py-20" aria-labelledby="contact-heading">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
        <div className="grid gap-10 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)]">
          <div className="space-y-6">
            <span className="inline-flex items-center gap-2 rounded-full border border-blue-500/40 bg-blue-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-blue-200">
              <AcademicCapIcon className="h-4 w-4" aria-hidden /> Cohort partnerships
            </span>
            <h2 id="contact-heading" className="text-3xl font-semibold text-white sm:text-4xl">
              Coordinate supervised pilots or request an ethics briefing.
            </h2>
            <p className="text-sm text-gray-300 sm:text-base">
              Outline your intended use case, institutional requirements, and timeframe. We&apos;ll share consent templates,
              demo target playbooks, and facilitation support tailored to academic cohorts.
            </p>
            <div className="rounded-2xl border border-blue-500/30 bg-blue-500/5 p-6 text-sm text-blue-100">
              <p className="font-semibold uppercase tracking-wide text-[0.65rem]">What to include</p>
              <ul className="mt-3 space-y-2 text-blue-50">
                <li className="flex gap-3"><span className="mt-2 h-1.5 w-1.5 rounded-full bg-blue-200" aria-hidden /><span>Programme or research context and key learning outcomes.</span></li>
                <li className="flex gap-3"><span className="mt-2 h-1.5 w-1.5 rounded-full bg-blue-200" aria-hidden /><span>Preferred pilot window plus cohort size expectations.</span></li>
                <li className="flex gap-3"><span className="mt-2 h-1.5 w-1.5 rounded-full bg-blue-200" aria-hidden /><span>Any institutional review processes or policies we should align with.</span></li>
              </ul>
            </div>
          </div>
          <div className="rounded-3xl border border-gray-800 bg-gray-900/80 p-6 shadow-2xl shadow-blue-900/20">
            <form onSubmit={handleSubmit} className="space-y-4" noValidate>
              <div>
                <label htmlFor={nameId} className="mb-1 block text-sm text-gray-300">Full name</label>
                <input
                  id={nameId}
                  name="name"
                  type="text"
                  value={form.name}
                  onChange={onInputChange('name')}
                  className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Dr Samira Patel"
                  required
                  autoComplete="name"
                />
              </div>
              <div>
                <label htmlFor={emailId} className="mb-1 block text-sm text-gray-300">Academic email</label>
                <div className="relative">
                  <div className="pointer-events-none absolute inset-y-0 left-3 flex items-center text-gray-500">
                    <EnvelopeIcon className="h-5 w-5" aria-hidden />
                  </div>
                  <input
                    id={emailId}
                    name="email"
                    type="email"
                    value={form.email}
                    onChange={onInputChange('email')}
                    className="w-full rounded-lg border border-gray-700 bg-gray-950 py-2 pl-10 pr-3 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    placeholder="samira.patel@university.edu"
                    required
                    autoComplete="email"
                  />
                </div>
              </div>
              <div>
                <label htmlFor={organisationId} className="mb-1 block text-sm text-gray-300">Institution / Department (optional)</label>
                <input
                  id={organisationId}
                  name="organisation"
                  type="text"
                  value={form.organisation}
                  onChange={onInputChange('organisation')}
                  className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="University of Cybersecurity – MSc Programme"
                  autoComplete="organization"
                />
              </div>
              <div>
                <label htmlFor={messageId} className="mb-1 block text-sm text-gray-300">How can we support you?</label>
                <textarea
                  id={messageId}
                  name="message"
                  rows={5}
                  value={form.message}
                  onChange={onInputChange('message')}
                  className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                  placeholder="Share cohort objectives, desired dates, and any ethics checkpoints."
                  required
                />
              </div>
              <div className="rounded-lg border border-blue-500/30 bg-blue-500/10 p-4 text-xs text-blue-100">
                <div className="flex items-start gap-3">
                  <input
                    id={consentId}
                    name="consent"
                    type="checkbox"
                    checked={form.consent}
                    onChange={onInputChange('consent')}
                    className="mt-0.5 h-4 w-4 rounded border-blue-400 bg-gray-950 text-blue-500 focus:ring-blue-500"
                    required
                  />
                  <label htmlFor={consentId} className="text-left">
                    I confirm I&apos;m authorized to initiate an academic pilot and consent to being contacted at the supplied email.
                  </label>
                </div>
              </div>
              <button
                type="submit"
                disabled={isDisabled}
                className="w-full rounded-lg bg-blue-600 py-2 text-sm font-semibold text-white transition hover:bg-blue-500 disabled:cursor-not-allowed disabled:opacity-60"
              >
                {isSubmitting ? 'Sending…' : 'Share cohort brief'}
              </button>

              {status.state === 'success' && (
                <p className="rounded-lg border border-green-500/40 bg-green-500/10 px-3 py-2 text-xs text-green-200">
                  {status.message}
                </p>
              )}
              {status.state === 'error' && (
                <p className="rounded-lg border border-red-500/40 bg-red-500/10 px-3 py-2 text-xs text-red-200">
                  {status.message}
                </p>
              )}
            </form>
          </div>
        </div>
      </div>
    </section>
  )
}
