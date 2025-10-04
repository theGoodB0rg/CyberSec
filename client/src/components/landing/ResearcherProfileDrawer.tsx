import { Dialog, Transition } from '@headlessui/react'
import {
  AcademicCapIcon,
  EnvelopeIcon,
  BuildingLibraryIcon,
  UsersIcon,
  ShieldCheckIcon,
} from '@heroicons/react/24/outline'
import { Fragment } from 'react'

interface ResearcherProfileDrawerProps {
  open: boolean
  onClose: () => void
}

const highlights = [
  {
    label: 'Programmes advised',
    value: '14 postgraduate cohorts',
    icon: AcademicCapIcon,
  },
  {
    label: 'Ethics approvals guided',
    value: '22 IRB submissions',
    icon: BuildingLibraryIcon,
  },
  {
    label: 'Learner impact',
    value: '180+ supervised researchers',
    icon: UsersIcon,
  },
]

const focusAreas = [
  'Offensive security education & lab design',
  'SQL injection detection & mitigation strategies',
  'Responsible disclosure process coaching',
  'Ethics-first penetration testing methodology',
]

export function ResearcherProfileDrawer({ open, onClose }: ResearcherProfileDrawerProps) {
  return (
    <Transition show={open} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={() => onClose()}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-150"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-100"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-black/60" aria-hidden />
        </Transition.Child>

        <div className="fixed inset-0 overflow-hidden">
          <div className="absolute inset-y-0 right-0 flex max-w-full pl-10">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-200"
              enterFrom="translate-x-full"
              enterTo="translate-x-0"
              leave="ease-in duration-150"
              leaveFrom="translate-x-0"
              leaveTo="translate-x-full"
            >
              <Dialog.Panel className="w-screen max-w-md bg-gray-950 shadow-xl">
                <div className="flex h-full flex-col border-l border-blue-500/30 bg-gradient-to-b from-gray-950 via-gray-950/95 to-gray-950/90">
                  <div className="px-6 py-6 sm:px-8">
                    <div className="flex items-start justify-between">
                      <div>
                        <Dialog.Title className="text-lg font-semibold text-white">
                          Dr. Maya Addison
                        </Dialog.Title>
                        <p className="text-sm text-blue-200/90">
                          Lead Researcher & Programme Architect
                        </p>
                      </div>
                      <span className="inline-flex h-10 w-10 items-center justify-center rounded-full border border-blue-500/40 bg-blue-500/10 text-blue-200">
                        <ShieldCheckIcon className="h-5 w-5" aria-hidden />
                      </span>
                    </div>
                    <p className="mt-4 text-sm text-gray-300">
                      Maya drives the academic framing of CyberSec. She has spent the last decade building
                      postgraduate security curricula that balance offensive experimentation with rigorous compliance
                      controls.
                    </p>
                  </div>

                  <div className="flex-1 space-y-6 overflow-y-auto px-6 pb-6 sm:px-8">
                    <section>
                      <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">Highlights</h3>
                      <dl className="mt-3 grid grid-cols-1 gap-3">
                        {highlights.map(({ label, value, icon: Icon }) => (
                          <div
                            key={label}
                            className="grid grid-cols-[auto_1fr] items-center gap-3 rounded-xl border border-gray-800 bg-gray-900/60 px-4 py-3"
                          >
                            <dt className="flex items-center gap-3 text-xs font-medium text-gray-300">
                              <span className="inline-flex h-9 w-9 items-center justify-center rounded-full bg-blue-500/10 text-blue-300">
                                <Icon className="h-5 w-5" aria-hidden />
                              </span>
                              <span>{label}</span>
                            </dt>
                            <dd className="justify-self-end text-sm font-semibold text-white">{value}</dd>
                          </div>
                        ))}
                      </dl>
                    </section>

                    <section>
                      <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">
                        Cohort focus areas
                      </h3>
                      <ul className="mt-3 space-y-2 text-sm text-gray-300">
                        {focusAreas.map(item => (
                          <li key={item} className="flex items-start gap-2">
                            <span className="mt-1 h-1.5 w-1.5 rounded-full bg-blue-400" aria-hidden />
                            <span>{item}</span>
                          </li>
                        ))}
                      </ul>
                    </section>

                    <section>
                      <h3 className="text-xs font-semibold uppercase tracking-wide text-gray-400">
                        Recent contributions
                      </h3>
                      <div className="mt-3 space-y-3 text-sm text-gray-300">
                        <p>
                          • Authored the responsible-use charter and consent checklist embedded in CyberSec&apos;s terminal
                          workflow.
                        </p>
                        <p>
                          • Facilitated cross-discipline research sprints aligning SQL injection techniques with business
                          risk narratives.
                        </p>
                        <p>
                          • Led collaborations with legal teams to streamline IRB submissions for offensive security
                          coursework.
                        </p>
                      </div>
                    </section>
                  </div>

                  <div className="border-t border-gray-800 bg-gray-900/70 px-6 py-4 sm:px-8">
                    <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
                      <div className="flex items-center gap-2 text-gray-300">
                        <EnvelopeIcon className="h-5 w-5 text-blue-300" aria-hidden />
                        <a
                          className="hover:text-blue-200"
                          href="mailto:theregalstarlite@gmail.com?subject=CyberSec%20Programme%20Enquiry"
                        >
                          theregalstarlite@gmail.com
                        </a>
                      </div>
                      <button
                        type="button"
                        onClick={() => onClose()}
                        className="rounded-md bg-blue-500 px-4 py-2 text-sm font-semibold text-gray-900 transition hover:bg-blue-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-200 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-950"
                      >
                        Close
                      </button>
                    </div>
                  </div>
                </div>
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition>
  )
}
