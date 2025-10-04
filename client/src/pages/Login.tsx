import { useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAppStore } from '@/store/appStore'
import toast from 'react-hot-toast'
import { LandingHero } from '@/components/landing/LandingHero'
import { MethodologyTimeline } from '@/components/landing/MethodologyTimeline'
import { LegalDisclaimer } from '@/components/landing/LegalDisclaimer'
import { LandingFAQ } from '@/components/landing/LandingFAQ'
import { ResearcherProfileDrawer } from '@/components/landing/ResearcherProfileDrawer'
import { ContactSection } from '@/components/landing/ContactSection'
import { AcademicCapIcon, ScaleIcon, BanknotesIcon } from '@heroicons/react/24/outline'

export default function Login() {
  const navigate = useNavigate()
  const { login, register } = useAppStore()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [profileOpen, setProfileOpen] = useState(false)
  const authCardRef = useRef<HTMLDivElement | null>(null)

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      if (mode === 'login') {
        await login(email, password)
        toast.success('Logged in')
      } else {
        await register(email, password)
        toast.success('Account created')
      }
      navigate('/dashboard', { replace: true })
    } catch (err: any) {
      toast.error(err?.message || 'Authentication failed')
    } finally {
      setLoading(false)
    }
  }

  const scrollToAuthCard = () => {
    authCardRef.current?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }

  const scrollToMethodology = () => {
    const section = document.getElementById('methodology')
    if (section) {
      section.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }

  const evidenceHighlights = [
    {
      icon: AcademicCapIcon,
      title: 'SQL injection curriculum ready',
      description: 'Slides, lab briefs, and assessment rubrics align SQLi exploitation and defence exercises with postgraduate cyber modules.',
    },
    {
      icon: ScaleIcon,
      title: 'Ethics defensible',
      description: 'Consent logging, legal disclaimers, and IRB language are shipped as defaults so SQL injection drills stay fully accountable.',
    },
    {
      icon: BanknotesIcon,
      title: 'Budget friendly',
      description: 'No per-seat surprises—scale SQLi lab access across capstone cohorts and research sprints alike.',
    },
  ]

  return (
    <div className="min-h-screen bg-gray-950 text-gray-100">
      <div className="relative overflow-hidden pb-16">
        <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-blue-500 via-cyan-400 to-indigo-500" aria-hidden />
        <div className="relative z-10 mx-auto flex max-w-7xl flex-col gap-16 px-4 pt-16 sm:px-6 lg:px-8 lg:pt-20">
          <div className="grid items-start gap-14 lg:grid-cols-[minmax(0,1.15fr)_minmax(0,0.85fr)]">
            <LandingHero
              onLaunchDemo={scrollToAuthCard}
              onViewMethodology={scrollToMethodology}
              onOpenProfile={() => setProfileOpen(true)}
            />
            <div
              ref={authCardRef}
              id="auth-card"
              className="w-full rounded-2xl border border-blue-500/40 bg-gray-900/80 p-8 shadow-2xl shadow-blue-900/40 backdrop-blur"
            >
              <div className="mb-6 space-y-2 text-center">
                <p className="text-xs uppercase tracking-wide text-blue-300/80">Secure faculty console</p>
                <h1 className="text-2xl font-semibold text-white">
                  {mode === 'login' ? 'Sign in to CyberSec' : 'Create your researcher account'}
                </h1>
                <p className="text-sm text-gray-400">
                  {mode === 'login'
                    ? 'Access analytics, terminal tooling, and ethical guardrails tailored to your institution.'
                    : 'Provisioned accounts receive guidance on consent capture and demo target etiquette.'}
                </p>
              </div>
              <form onSubmit={onSubmit} className="space-y-4">
                <div>
                  <label className="mb-1 block text-sm text-gray-300" htmlFor="email">Academic email</label>
                  <input
                    type="email"
                    className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    required
                    id="email"
                    name="email"
                    placeholder="you@university.edu"
                    aria-label="Email"
                  />
                </div>
                <div>
                  <label className="mb-1 block text-sm text-gray-300" htmlFor="password">Password</label>
                  <input
                    type="password"
                    className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                    minLength={6}
                    id="password"
                    name="password"
                    placeholder="••••••••"
                    aria-label="Password"
                  />
                </div>
                <button
                  type="submit"
                  disabled={loading}
                  className="w-full rounded-lg bg-blue-600 py-2 text-sm font-semibold text-white transition hover:bg-blue-500 disabled:opacity-50"
                >
                  {loading ? 'Please wait…' : mode === 'login' ? 'Secure sign in' : 'Create researcher seat'}
                </button>
              </form>
              <div className="mt-4 text-center text-sm text-gray-400">
                {mode === 'login' ? (
                  <button className="text-blue-300 hover:text-blue-200" onClick={() => setMode('register')}>
                    Need an account? Register a cohort lead
                  </button>
                ) : (
                  <button className="text-blue-300 hover:text-blue-200" onClick={() => setMode('login')}>
                    Already provisioned? Sign in
                  </button>
                )}
              </div>
              <div className="mt-6 rounded-lg border border-blue-500/30 bg-blue-500/10 p-4 text-xs text-blue-100">
                <p className="font-semibold uppercase tracking-wide text-[0.65rem]">Responsible use notice</p>
                <p className="mt-1">
                  This environment is restricted to authorized academic demonstrations. Production systems
                  must never be targeted without written consent from the asset owner.
                </p>
              </div>
            </div>
          </div>

          <div className="grid gap-6 lg:grid-cols-3">
            {evidenceHighlights.map(({ icon: Icon, title, description }) => (
              <div key={title} className="rounded-2xl border border-gray-800 bg-gray-900/70 p-6 shadow-inner shadow-black/20">
                <div className="mb-3 inline-flex items-center justify-center rounded-full border border-blue-400/30 bg-blue-500/10 p-3 text-blue-200">
                  <Icon className="h-6 w-6" aria-hidden />
                </div>
                <h3 className="text-lg font-semibold text-white">{title}</h3>
                <p className="mt-2 text-sm text-gray-400">{description}</p>
              </div>
            ))}
          </div>
        </div>
        <div className="absolute inset-x-0 bottom-0 h-48 bg-gradient-to-t from-gray-950 via-gray-950/80 to-transparent" aria-hidden />
      </div>

      <LegalDisclaimer />

      <MethodologyTimeline />

      <LandingFAQ />

  <ContactSection />

      <ResearcherProfileDrawer open={profileOpen} onClose={() => setProfileOpen(false)} />

      <section className="bg-gray-950 pb-20">
        <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
          <div className="rounded-3xl border border-gray-800 bg-gray-900/80 p-8 sm:p-12">
            <div className="grid gap-8 lg:grid-cols-[minmax(0,1.1fr)_minmax(0,0.9fr)] lg:items-center">
              <div className="space-y-4">
                <h2 className="text-2xl font-semibold text-white sm:text-3xl">Structured for ethics boards, ready for classrooms</h2>
                <p className="text-sm text-gray-300 sm:text-base">
                  Every SQLi scan action is logged, every demo host is vetted, and every flag bundle ships with explanatory
                  prose. Export audit packs before assessments or research write-ups to demonstrate full compliance to supervisors and accreditation teams.
                </p>
              </div>
              <ul className="space-y-3 rounded-2xl border border-blue-400/30 bg-blue-500/5 p-6 text-sm text-blue-100">
                {[
                  'Download ethics briefing templates for professors and teaching assistants.',
                  'Share quick reference cards mapping SQLMap toggles and SQLi payload types to academic learning outcomes.',
                  'Bundle anonymised evidence for moderation and second-marking in minutes.',
                ].map(point => (
                  <li key={point} className="flex items-start gap-3">
                    <span className="mt-1 h-2 w-2 rounded-full bg-blue-300" aria-hidden />
                    <span>{point}</span>
                  </li>
                ))}
              </ul>
            </div>
            <div className="mt-8 flex flex-wrap justify-between gap-4 text-xs text-gray-500">
              <span>IRB-aligned | GDPR mindful | Safe SQLi demo targets only</span>
              <span>Version 1.0.0 &middot; Autumn semester pilot</span>
            </div>
          </div>
        </div>
      </section>
    </div>
  )
}
