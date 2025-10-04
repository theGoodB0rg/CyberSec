import { AcademicCapIcon, PlayIcon, ShieldCheckIcon, ArrowDownCircleIcon } from '@heroicons/react/24/outline'
import clsx from 'clsx'

interface LandingHeroProps {
  onLaunchDemo?: () => void
  onViewMethodology?: () => void
}

const trustSignals = [
  'Designed for postgraduate cybersecurity cohorts',
  'Guided SQLMap workflows with auditable flag presets',
  'Ethical-first framing with consent capture baked in',
]

export function LandingHero({ onLaunchDemo, onViewMethodology }: LandingHeroProps) {
  return (
    <section className="relative">
      <div className="absolute inset-0" aria-hidden>
        <div className="absolute -top-24 -left-24 h-72 w-72 rounded-full bg-blue-500/10 blur-3xl" />
        <div className="absolute bottom-0 right-[-10%] h-96 w-96 rounded-full bg-indigo-500/10 blur-[120px]" />
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
        </div>
      </div>
    </section>
  )
}
