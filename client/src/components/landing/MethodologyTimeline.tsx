import { AcademicCapIcon, ClipboardDocumentCheckIcon, CommandLineIcon, ShieldCheckIcon, SparklesIcon } from '@heroicons/react/24/outline'

const steps = [
  {
    id: 'Stage 01',
    title: 'Research framing & consent capture',
    description:
      'Students review the ethical use statement, confirm supervisory approval, and log consent artefacts before interacting with any targets.',
    icon: AcademicCapIcon,
  },
  {
    id: 'Stage 02',
    title: 'Baseline reconnaissance walkthrough',
    description:
      'We guide cohorts through passive fingerprinting, asset scoping, and identification of safe demo targets seeded by the platform.',
    icon: SparklesIcon,
  },
  {
    id: 'Stage 03',
    title: 'Guided SQLMap execution & tuning',
    description:
      'Pre-curated flag presets illustrate injection classes while preventing destructive operations. Learners justify each toggle they apply.',
    icon: CommandLineIcon,
  },
  {
    id: 'Stage 04',
    title: 'Evidence curation & peer review',
    description:
      'Generated findings are annotated with academic context. Students tag impact narratives, mitigation strategies, and confidence levels.',
    icon: ClipboardDocumentCheckIcon,
  },
  {
    id: 'Stage 05',
    title: 'Responsible disclosure simulation',
    description:
      'Teams publish structured reports, map to institutional risk rubrics, and rehearse communication protocols aligned with disclosure policies.',
    icon: ShieldCheckIcon,
  },
]

export function MethodologyTimeline() {
  return (
    <section id="methodology" className="relative overflow-hidden bg-gray-950 py-16 sm:py-20">
      <div className="absolute inset-x-0 top-0 h-1 bg-gradient-to-r from-blue-400 via-indigo-400 to-cyan-400" aria-hidden />
      <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
        <div className="mb-10 max-w-2xl">
          <h2 className="text-2xl font-semibold text-white sm:text-3xl">Five-step methodology designed for academic defensibility</h2>
          <p className="mt-3 text-sm text-gray-300 sm:text-base">
            Each cohort journey couples offensive experimentation with institutional safeguards. Every step is documented,
            reviewable, and auditable—ready for ethics committees and accreditation reviews.
          </p>
        </div>
        <div className="space-y-6 border-l border-gray-800 pl-8 sm:space-y-8">
          {steps.map(({ id, title, description, icon: Icon }, index) => (
            <div key={id} className="relative flex gap-6">
              <div className="absolute -left-14 flex h-12 w-12 items-center justify-center rounded-xl border border-indigo-500/30 bg-indigo-500/10 text-indigo-100 shadow-lg shadow-indigo-900/40">
                <Icon className="h-6 w-6" aria-hidden />
              </div>
              <div className="space-y-1">
                <p className="text-xs font-semibold uppercase tracking-wider text-indigo-300/90">{id}</p>
                <h3 className="text-lg font-semibold text-white sm:text-xl">{title}</h3>
                <p className="text-sm text-gray-300 sm:text-base">{description}</p>
              </div>
              <div className="absolute -left-[1.4rem] top-[1.4rem] h-4 w-4 rounded-full border border-indigo-400/40 bg-gray-950" aria-hidden />
              {index < steps.length - 1 && (
                <div className="absolute -left-[0.85rem] top-[3.4rem] h-full w-px bg-gradient-to-b from-indigo-500/40 via-blue-400/20 to-transparent" aria-hidden />
              )}
            </div>
          ))}
        </div>
      </div>
    </section>
  )
}
