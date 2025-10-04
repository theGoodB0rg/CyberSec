import {
  AcademicCapIcon,
  PlayIcon,
  ShieldCheckIcon,
  ArrowDownCircleIcon,
  UserCircleIcon,
  SparklesIcon,
} from '@heroicons/react/24/outline'
import clsx from 'clsx'

interface LandingHeroProps {
  onLaunchDemo?: () => void
  onViewMethodology?: () => void
  onOpenProfile?: () => void
}

const trustSignals = [
  'Designed for postgraduate cybersecurity cohorts',
  'Guided SQLMap workflows with auditable flag presets',
  'Ethical-first framing with consent capture baked in',
]

export function LandingHero({ onLaunchDemo, onViewMethodology, onOpenProfile }: LandingHeroProps) {
  return (
    <section className="relative">
      <div className="absolute inset-0" aria-hidden>
        <div className="absolute -top-24 -left-24 h-72 w-72 rounded-full bg-blue-500/10 blur-3xl" />
        <div className="absolute bottom-0 right-[-10%] h-96 w-96 rounded-full bg-indigo-500/10 blur-[120px]" />
        <div className="absolute inset-0 bg-[radial-gradient(circle_at_top,_rgba(59,130,246,0.06),_transparent_55%)]" />
      </div>
      <div className="relative z-10 space-y-8">
        <span className="inline-flex items-center gap-2 rounded-full border border-blue-500/40 bg-blue-500/10 px-3 py-1 text-xs font-semibold uppercase tracking-wide text-blue-200">
          <AcademicCapIcon className="h-4 w-4" /> MSc Cybersecurity Pilot
        </span>
        <div className="space-y-6">
          <h1 className="text-3xl font-semibold text-white sm:text-4xl lg:text-5xl">
            Academic-grade penetration testing labs with provable ethics scaffolding.
          </h1>
          <p className="max-w-2xl text-base text-gray-200 sm:text-lg">
            CyberSec brings responsible offensive tooling into the classroom, pairing safe demo targets with
            guided SQL injection narratives. Each cohort receives auditable activity logs, consent checkpoints,
            and methodology briefings aligned to institutional review boards.
          </p>
        </div>
        <div className="flex flex-wrap gap-3 text-sm text-gray-200">
          {trustSignals.map(signal => (
            <div
              key={signal}
              className="flex items-center gap-2 rounded-full border border-gray-700/60 bg-gray-800/70 px-4 py-2"
            >
              <ShieldCheckIcon className="h-4 w-4 text-blue-300" />
              <span>{signal}</span>
            </div>
          ))}
        </div>
        <div className="flex flex-wrap gap-4">
          <button
            type="button"
            onClick={onLaunchDemo}
            className={clsx(
              'inline-flex items-center gap-2 rounded-lg bg-blue-600 px-5 py-3 text-sm font-semibold text-white shadow-lg shadow-blue-600/30 transition hover:bg-blue-500 focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-blue-400 focus-visible:ring-offset-gray-900'
            )}
          >
            <PlayIcon className="h-5 w-5" /> Launch Demo Scan
          </button>
          <button
            type="button"
            onClick={onViewMethodology}
            className="inline-flex items-center gap-2 rounded-lg border border-blue-400/40 bg-transparent px-5 py-3 text-sm font-semibold text-blue-200 transition hover:border-blue-300 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-blue-200 focus-visible:ring-offset-gray-900"
          >
            <ArrowDownCircleIcon className="h-5 w-5" /> View Five-step Methodology
          </button>
          <button
            type="button"
            onClick={onOpenProfile}
            className="inline-flex items-center gap-2 rounded-lg border border-gray-700/70 bg-gray-900/70 px-5 py-3 text-sm font-semibold text-gray-200 transition hover:border-blue-400/60 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-offset-2 focus-visible:ring-blue-300 focus-visible:ring-offset-gray-900"
          >
            <UserCircleIcon className="h-5 w-5 text-blue-300" /> Meet the researcher
          </button>
        </div>
        <div className="grid gap-4 sm:grid-cols-2">
          <div className="relative overflow-hidden rounded-2xl border border-blue-500/30 bg-blue-500/5 p-5">
            <div className="absolute right-0 top-0 h-28 w-28 -translate-y-6 translate-x-8 rounded-full bg-blue-500/20 blur-3xl" aria-hidden />
            <div className="relative flex items-start gap-3">
              <span className="inline-flex h-10 w-10 items-center justify-center rounded-full bg-blue-500/15 text-blue-200">
                <SparklesIcon className="h-6 w-6" aria-hidden />
              </span>
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-blue-100/80">
                  New for the Autumn pilot
                </p>
                <p className="mt-1 text-sm text-blue-50">
                  Rapid ethics briefing downloads and reflective journaling prompts woven into each lab.
                </p>
              </div>
            </div>
          </div>
          <div className="rounded-2xl border border-gray-700/70 bg-gray-900/70 p-5">
            <p className="text-xs font-semibold uppercase tracking-wide text-gray-400">Compliance snapshot</p>
            <div className="mt-2 flex items-center justify-between">
              <div>
                <p className="text-3xl font-semibold text-white">98%</p>
                <p className="text-xs text-gray-400">Cohort consent completion</p>
              </div>
              <div className="text-right">
                <p className="text-lg font-medium text-blue-300">0 incidents</p>
                <p className="text-xs text-gray-500">across last 6 semesters</p>
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  )
}
