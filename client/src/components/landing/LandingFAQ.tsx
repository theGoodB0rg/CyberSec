import { Disclosure, Transition } from '@headlessui/react'
import { MinusSmallIcon, PlusSmallIcon } from '@heroicons/react/24/outline'

const faqEntries = [
  {
    question: 'What ethical guardrails are enforced during teaching labs?',
    answer:
      'Every scan is tied to an authenticated cohort member, logged with ISO 8601 timestamps, and scoped to pre-approved demo environments. Consent prompts and researcher attestations fire before any offensive command is executed.',
  },
  {
    question: 'How is student or target data handled?',
    answer:
      'Captured evidence stays within the encrypted course workspace. Personally identifiable information is scrubbed from terminal transcripts, and administrators can purge artefacts on demand once assessments conclude.',
  },
  {
    question: 'Do learners need supervisor approval before running scans?',
    answer:
      'Yes. The platform ships with a supervisor sign-off template and locks the terminal until the supervising academic has granted explicit authorization inside the consent workflow.',
  },
  {
    question: 'What is the recommended workflow for SQLMap experiments?',
    answer:
      'Learners start with the baseline preset, justify flag adjustments in reflective notes, and submit peer reviews of findings before exporting final reports. Faculty can inject feedback at each checkpoint.',
  },
  {
    question: 'How can students request feedback or raise concerns?',
    answer:
      'The feedback banner routes to a monitored academic inbox. Submissions capture cohort metadata, consent state, and optional attachments so teaching staff can respond quickly and maintain audit logs.',
  },
]

export function LandingFAQ() {
  return (
    <section className="bg-gray-950 py-16 sm:py-20" aria-labelledby="landing-faq-heading">
      <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
        <div className="mb-10 text-center">
          <h2 id="landing-faq-heading" className="text-2xl font-semibold text-white sm:text-3xl">
            Frequently asked questions
          </h2>
          <p className="mt-3 text-sm text-gray-300 sm:text-base">
            Clear guidance for ethics boards, supervisors, and learners exploring responsible offensive security.
          </p>
        </div>
        <div className="divide-y divide-gray-800 overflow-hidden rounded-2xl border border-gray-800 bg-gray-900/50 backdrop-blur">
          {faqEntries.map((item, index) => (
            <Disclosure as="div" className="px-6" key={item.question} defaultOpen={index === 0}>
              {({ open }) => (
                <>
                  <Disclosure.Button className="flex w-full items-center justify-between py-5 text-left">
                    <span className="text-base font-medium text-white sm:text-lg">{item.question}</span>
                    <span className="ml-4 flex h-7 w-7 items-center justify-center rounded-full border border-gray-700 text-gray-300">
                      {open ? (
                        <MinusSmallIcon className="h-4 w-4" aria-hidden />
                      ) : (
                        <PlusSmallIcon className="h-4 w-4" aria-hidden />
                      )}
                    </span>
                  </Disclosure.Button>
                  <Transition
                    enter="transition duration-150 ease-out"
                    enterFrom="transform scale-95 opacity-0"
                    enterTo="transform scale-100 opacity-100"
                    leave="transition duration-100 ease-in"
                    leaveFrom="transform scale-100 opacity-100"
                    leaveTo="transform scale-95 opacity-0"
                  >
                    <Disclosure.Panel className="pb-6 text-sm text-gray-300 sm:text-base">
                      {item.answer}
                    </Disclosure.Panel>
                  </Transition>
                </>
              )}
            </Disclosure>
          ))}
        </div>
      </div>
    </section>
  )
}
