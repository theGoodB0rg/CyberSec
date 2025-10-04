import { Dialog, Transition } from '@headlessui/react'
import { ExclamationTriangleIcon } from '@heroicons/react/24/outline'
import { Fragment, useState } from 'react'

export function LegalDisclaimer() {
  const [open, setOpen] = useState(false)

  return (
    <section className="bg-gray-950" aria-labelledby="legal-disclaimer-heading">
      <div className="mx-auto max-w-6xl px-4 sm:px-6 lg:px-8">
        <div className="rounded-3xl border border-amber-500/40 bg-amber-500/5 p-6 sm:p-8">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
            <div className="flex items-start gap-3">
              <span className="flex h-10 w-10 items-center justify-center rounded-full bg-amber-500/20 text-amber-200">
                <ExclamationTriangleIcon className="h-6 w-6" aria-hidden />
              </span>
              <div>
                <h2 id="legal-disclaimer-heading" className="text-lg font-semibold text-amber-100">
                  Educational-use only environment
                </h2>
                <p className="mt-2 text-sm text-amber-200/80 sm:text-base">
                  Access is restricted to sanctioned academic cohorts. Running scans against any system outside the
                  curated demo catalogue without explicit written permission is prohibited and logged.
                </p>
              </div>
            </div>
            <div className="shrink-0">
              <button
                type="button"
                onClick={() => setOpen(true)}
                className="inline-flex items-center justify-center rounded-lg border border-amber-400/40 bg-transparent px-4 py-2 text-sm font-semibold text-amber-100 transition hover:border-amber-200 hover:text-white focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-400 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-950"
              >
                Read full legal disclaimer
              </button>
            </div>
          </div>
        </div>
      </div>

      <Transition show={open} as={Fragment}>
        <Dialog as="div" className="relative z-50" onClose={setOpen}>
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

          <div className="fixed inset-0 overflow-y-auto">
            <div className="flex min-h-full items-center justify-center px-4 py-10">
              <Transition.Child
                as={Fragment}
                enter="ease-out duration-200"
                enterFrom="opacity-0 translate-y-1"
                enterTo="opacity-100 translate-y-0"
                leave="ease-in duration-150"
                leaveFrom="opacity-100 translate-y-0"
                leaveTo="opacity-0 translate-y-1"
              >
                <Dialog.Panel className="w-full max-w-2xl transform overflow-hidden rounded-2xl border border-amber-500/40 bg-gray-950 p-6 shadow-2xl">
                  <div className="flex items-start gap-3">
                    <span className="flex h-10 w-10 items-center justify-center rounded-full bg-amber-500/15 text-amber-200">
                      <ExclamationTriangleIcon className="h-6 w-6" aria-hidden />
                    </span>
                    <div className="space-y-3 text-sm text-gray-200 sm:text-base">
                      <Dialog.Title className="text-lg font-semibold text-white">
                        Legal disclaimer & responsible-use charter
                      </Dialog.Title>
                      <p>
                        CyberSec is provided exclusively for accredited academic programmes and supervised research. By
                        using the platform you affirm that you have obtained the necessary institutional approvals and
                        that all testing will target assets explicitly designated as safe demo systems or owned by your
                        organisation with written authorization.
                      </p>
                      <p>
                        Any attempt to scan or interfere with third-party infrastructure without consent violates this
                        agreement, may breach local laws and regulations, and will result in immediate suspension of
                        access. The team maintains detailed telemetry to assist with compliance reviews and incident
                        response.
                      </p>
                      <p>
                        Do not store personal data or regulated information within the environment. Generated evidence
                        and reports are intended for educational assessment purposes and must be handled in line with
                        your institution&apos;s privacy and retention policies.
                      </p>
                      <p>
                        Questions about permitted use, reporting obligations, or data handling should be directed to the
                        programme lead at <a className="text-amber-200 underline hover:text-amber-100" href="mailto:theregalstarlite@gmail.com">theregalstarlite@gmail.com</a> prior to executing scans.
                      </p>
                    </div>
                  </div>
                  <div className="mt-6 flex justify-end">
                    <button
                      type="button"
                      onClick={() => setOpen(false)}
                      className="rounded-md bg-amber-500 px-4 py-2 text-sm font-semibold text-gray-900 transition hover:bg-amber-400 focus:outline-none focus-visible:ring-2 focus-visible:ring-amber-200 focus-visible:ring-offset-2 focus-visible:ring-offset-gray-950"
                    >
                      I acknowledge the policy
                    </button>
                  </div>
                </Dialog.Panel>
              </Transition.Child>
            </div>
          </div>
        </Dialog>
      </Transition>
    </section>
  )
}
