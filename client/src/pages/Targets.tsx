import React, { useEffect, useMemo, useState } from 'react'
import {
  ShieldCheckIcon,
  PlusIcon,
  TrashIcon,
  CheckCircleIcon,
  ArrowPathIcon,
  BookmarkIcon,
  ClockIcon,
  SparklesIcon,
} from '@heroicons/react/24/outline'
import { apiFetch } from '@/utils/api'
import toast from 'react-hot-toast'
import { useAppStore } from '@/store/appStore'

type SafeTarget = {
  name: string
  hostname: string
  description: string
  focus: 'SQLi' | 'OWASP Top 10' | 'Mixed'
  docsUrl?: string
  optional?: boolean
  notes?: string
}

type RecentTarget = {
  hostname: string
  addedAt: string
}

const SAFE_TARGETS: SafeTarget[] = [
  {
    name: 'Acunetix Test (Vulnweb)',
    hostname: 'testphp.vulnweb.com',
    description: 'Classic DVWA-style target maintained for safe SQL injection training.',
    focus: 'SQLi',
    docsUrl: 'https://vulnweb.com',
    notes: 'Recommended starting point for walkthrough demos.',
  },
  {
    name: 'OWASP Juice Shop',
    hostname: 'juice-shop.herokuapp.com',
    description: 'Purposefully vulnerable single-page app maintained by OWASP.',
    focus: 'OWASP Top 10',
    docsUrl: 'https://owasp.org/www-project-juice-shop/',
    notes: 'Requires patience with rate limits; keep scans polite.',
  },
  {
    name: 'Hackazon (Demo Testfire)',
    hostname: 'demo.testfire.net',
    description: 'Deprecated e-commerce app by IBM; still reliable for SQLi demos.',
    focus: 'SQLi',
    docsUrl: 'https://github.com/rapid7/hackazon',
  },
  {
    name: 'Zero WebApp Security',
    hostname: 'zero.webappsecurity.com',
    description: 'Banking-style application with multiple injection surfaces.',
    focus: 'Mixed',
    docsUrl: 'https://github.com/snoopysecurity/ZeroTest',
  },
  {
    name: 'WebScanTest Playground',
    hostname: 'www.webscantest.com',
    description: 'Multiple interactive labs for injection and auth flaws.',
    focus: 'Mixed',
    docsUrl: 'https://www.webscantest.com',
  },
  {
    name: 'Alt Vulnweb Mirror',
    hostname: 'testasp.vulnweb.com',
    description: 'ASP variant of Vulnweb with similar injection payloads.',
    focus: 'SQLi',
    optional: true,
    docsUrl: 'https://vulnweb.com',
  },
  {
    name: 'bWAPP Docker Demo',
    hostname: 'bwapp.honeybot.io',
    description: 'Hosted Bee-Box instance—verify availability before live demos.',
    focus: 'OWASP Top 10',
    optional: true,
    docsUrl: 'https://github.com/raesene/bwapp-docker',
    notes: 'Community-hosted; mirrors may rotate.',
  },
]

type TargetRecord = {
  id: string
  user_id: string
  org_id?: string | null
  hostname: string
  method: 'http-file' | 'dns-txt'
  token: string
  verified_at?: string | null
  created_at: string
}

export default function Targets() {
  const currentUser = useAppStore(s => s.currentUser)
  const [items, setItems] = useState<TargetRecord[]>([])
  const [loading, setLoading] = useState(false)
  const [creating, setCreating] = useState(false)
  const [hostname, setHostname] = useState('')
  const [method, setMethod] = useState<'http-file' | 'dns-txt'>('http-file')
  const [showOptionalMirrors, setShowOptionalMirrors] = useState(false)
  const [recentTargets, setRecentTargets] = useState<RecentTarget[]>([])

  const historyKey = useMemo(
    () => `targetHistory:${currentUser?.id ?? 'anonymous'}`,
    [currentUser?.id]
  )

  const safeTargets = useMemo(
    () => SAFE_TARGETS.filter(target => showOptionalMirrors || !target.optional),
    [showOptionalMirrors]
  )

  useEffect(() => {
    if (typeof window === 'undefined') return
    try {
      const stored = window.localStorage.getItem(historyKey)
      if (stored) {
        const parsed = JSON.parse(stored) as RecentTarget[]
        setRecentTargets(parsed)
      } else {
        setRecentTargets([])
      }
    } catch (error) {
      console.warn('Unable to load target history', error)
      setRecentTargets([])
    }
  }, [historyKey])

  const saveHistory = (targetHostname: string) => {
    if (typeof window === 'undefined' || !targetHostname) return
    setRecentTargets(prev => {
      const existing = prev.filter(entry => entry.hostname !== targetHostname)
      const next = [
        { hostname: targetHostname, addedAt: new Date().toISOString() },
        ...existing,
      ].slice(0, 5)
      try {
        window.localStorage.setItem(historyKey, JSON.stringify(next))
      } catch (error) {
        console.warn('Unable to persist target history', error)
      }
      return next
    })
  }

  const clearHistory = () => {
    if (typeof window === 'undefined') return
    window.localStorage.removeItem(historyKey)
    setRecentTargets([])
  }

  const handleSelectSafeTarget = (targetHostname: string) => {
    setHostname(targetHostname)
    setMethod('http-file')
    saveHistory(targetHostname)
    toast.success('Hostname populated from curated demo list')
  }

  const load = async () => {
    setLoading(true)
    try {
      const data = await apiFetch<TargetRecord[]>('/api/targets')
      setItems(data)
    } catch (e: any) {
      toast.error(e.message || 'Failed to load targets')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const onCreate = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!hostname) return
    setCreating(true)
    try {
      await apiFetch<{ id: string; hostname: string; method: string; token: string }>(
        '/api/targets',
        { method: 'POST', body: JSON.stringify({ hostname, method }) }
      )
      toast.success('Verification request created')
      saveHistory(hostname)
      setHostname('')
      await load()
    } catch (e: any) {
      toast.error(e.message || 'Failed to create request')
    } finally {
      setCreating(false)
    }
  }

  const onVerify = async (id: string) => {
    try {
      await apiFetch(`/api/targets/${id}/verify`, { method: 'POST' })
      toast.success('Target verified')
      await load()
    } catch (e: any) {
      toast.error(e.message || 'Verification failed')
    }
  }

  const onDelete = async (id: string) => {
    try {
      await apiFetch(`/api/targets/${id}`, { method: 'DELETE' })
      toast('Removed')
      setItems(prev => prev.filter(i => i.id !== id))
    } catch (e: any) {
      toast.error(e.message || 'Failed to delete')
    }
  }

  const instructions = useMemo(() => {
    if (!hostname) return null
    if (method === 'http-file') {
      return (
        <div className="text-sm text-gray-300">
          <p className="mb-1">Create the following file on your site:</p>
          <code className="bg-gray-800 px-2 py-1 rounded">/.well-known/cybersec-verify.txt</code>
          <p className="mt-2">Then click Verify. The file must contain the token we generated for this hostname.</p>
        </div>
      )
    }
    return (
      <div className="text-sm text-gray-300">
        <p>Add a DNS TXT record for your domain containing the provided token, then click Verify.</p>
      </div>
    )
  }, [hostname, method])

  return (
    <div className="h-full overflow-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white flex items-center">
            <ShieldCheckIcon className="h-8 w-8 mr-3 text-blue-400" />
            Verify Target Ownership
          </h1>
          <p className="mt-2 text-gray-400">Verify domains you’re allowed to test. Non-admins must verify before scanning.</p>
        </div>

        <div className="grid gap-6 lg:grid-cols-2 mb-8">
          <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
            <div className="flex items-start justify-between">
              <div>
                <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                  <BookmarkIcon className="w-6 h-6 text-blue-400" />
                  Curated Demo Targets
                </h2>
                <p className="text-sm text-gray-400 mt-1">
                  Safe-to-scan environments for workshops, labs, and academic demonstrations.
                </p>
              </div>
              <button
                type="button"
                onClick={() => setShowOptionalMirrors(prev => !prev)}
                className="text-xs px-3 py-1.5 rounded border border-gray-600 text-gray-200 hover:bg-gray-700"
              >
                {showOptionalMirrors ? 'Hide optional mirrors' : 'Show optional mirrors'}
              </button>
            </div>

            <div className="mt-4 space-y-4">
              {safeTargets.map(target => (
                <div key={target.hostname} className="border border-gray-700 rounded-lg p-4 bg-gray-900/60">
                  <div className="flex items-start justify-between gap-3">
                    <div>
                      <div className="text-white font-medium flex items-center gap-2">
                        <span>{target.name}</span>
                        <span className="text-[0.65rem] uppercase tracking-wide bg-gray-800 text-gray-300 px-2 py-0.5 rounded">
                          {target.focus}
                        </span>
                      </div>
                      <p className="text-sm text-gray-400 mt-1">{target.description}</p>
                      <div className="text-xs text-gray-500 mt-2">
                        Hostname:{' '}
                        <code className="bg-gray-800 px-1.5 py-0.5 rounded">{target.hostname}</code>
                      </div>
                      {target.notes && (
                        <p className="text-xs text-gray-500 mt-1">{target.notes}</p>
                      )}
                      {target.docsUrl && (
                        <a
                          href={target.docsUrl}
                          target="_blank"
                          rel="noreferrer"
                          className="text-xs text-blue-400 hover:text-blue-300 inline-flex items-center gap-1 mt-2"
                        >
                          Learn more ↗
                        </a>
                      )}
                    </div>
                    <div className="flex flex-col items-end gap-2 shrink-0">
                      {target.optional && (
                        <span className="text-[0.65rem] uppercase tracking-wide text-amber-300 bg-amber-900/30 px-2 py-0.5 rounded">
                          Optional
                        </span>
                      )}
                      <button
                        type="button"
                        onClick={() => handleSelectSafeTarget(target.hostname)}
                        className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded text-sm"
                      >
                        Use host
                      </button>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-lg font-semibold text-white flex items-center gap-2">
                  <ClockIcon className="w-6 h-6 text-blue-400" />
                  Recent Targets
                </h2>
                <p className="text-sm text-gray-400 mt-1">
                  Last five verification requests tied to your account.
                </p>
              </div>
              <button
                type="button"
                onClick={clearHistory}
                className="text-xs px-3 py-1.5 rounded border border-gray-600 text-gray-200 hover:bg-gray-700 disabled:opacity-40"
                disabled={recentTargets.length === 0}
              >
                Clear history
              </button>
            </div>

            <div className="mt-4 space-y-3">
              {recentTargets.length === 0 && (
                <div className="text-sm text-gray-500 bg-gray-900/60 border border-dashed border-gray-700 rounded-lg p-4">
                  No recent targets yet. Create a verification request or choose a curated host to seed history.
                </div>
              )}
              {recentTargets.map(entry => (
                <button
                  key={`${entry.hostname}-${entry.addedAt}`}
                  type="button"
                  onClick={() => {
                    setHostname(entry.hostname)
                    setMethod('http-file')
                    toast.success('Hostname populated from recent history')
                  }}
                  className="w-full text-left bg-gray-900/60 border border-gray-700 hover:border-blue-500 hover:bg-gray-900 rounded-lg px-4 py-3 transition"
                >
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <SparklesIcon className="w-5 h-5 text-blue-400" />
                      <span className="text-sm text-white font-medium">{entry.hostname}</span>
                    </div>
                    <span className="text-xs text-gray-400">
                      {new Date(entry.addedAt).toLocaleString()}
                    </span>
                  </div>
                </button>
              ))}
            </div>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg border border-gray-700 p-6 mb-8">
          <form onSubmit={onCreate} className="grid grid-cols-1 md:grid-cols-3 gap-4 items-end">
            <div>
              <label className="block text-sm text-gray-300 mb-1">Hostname</label>
              <input value={hostname} onChange={(e) => setHostname(e.target.value)} placeholder="example.com" className="w-full bg-gray-900 text-gray-100 border border-gray-700 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500" />
            </div>
            <div>
              <label className="block text-sm text-gray-300 mb-1">Method</label>
              <select aria-label="Verification Method" title="Verification Method" value={method} onChange={(e) => setMethod(e.target.value as any)} className="w-full bg-gray-900 text-gray-100 border border-gray-700 rounded px-3 py-2 focus:outline-none focus:ring-2 focus:ring-blue-500">
                <option value="http-file">HTTP File</option>
                <option value="dns-txt">DNS TXT</option>
              </select>
            </div>
            <div className="flex gap-2">
              <button disabled={creating} aria-label="Create verification request" className="inline-flex items-center px-4 py-2 bg-blue-600 hover:bg-blue-700 rounded text-white disabled:opacity-50">
                <PlusIcon className="w-5 h-5 mr-2" /> Create Request
              </button>
              <button type="button" onClick={load} aria-label="Refresh" title="Refresh" className="inline-flex items-center px-3 py-2 bg-gray-700 hover:bg-gray-600 rounded text-gray-100">
                <ArrowPathIcon className="w-5 h-5" /> Refresh
              </button>
            </div>
          </form>
          {instructions && <div className="mt-4">{instructions}</div>}
        </div>

        <div className="bg-gray-800 rounded-lg border border-gray-700 p-0 overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
            <h2 className="text-white font-semibold">Your Targets</h2>
            {loading && <span className="text-xs text-gray-400">Loading…</span>}
          </div>
          <div className="divide-y divide-gray-700">
            {items.length === 0 && (
              <div className="p-6 text-gray-400">No targets yet. Create one above.</div>
            )}
            {items.map(item => (
              <div key={item.id} className="p-6 flex items-center justify-between gap-4">
                <div className="min-w-0">
                  <div className="text-white font-medium truncate">{item.hostname}</div>
                  <div className="text-xs text-gray-400 mt-1">Method: {item.method}</div>
                  <div className="text-xs text-gray-400 mt-1 break-words">
                    Token: <code className="bg-gray-900 px-1 py-0.5 rounded">{item.token}</code>
                  </div>
                  <div className="text-xs mt-1">
                    {item.verified_at ? (
                      <span className="text-green-400 inline-flex items-center"><CheckCircleIcon className="w-4 h-4 mr-1" /> Verified {new Date(item.verified_at).toLocaleString()}</span>
                    ) : (
                      <span className="text-yellow-400">Not verified</span>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {!item.verified_at && (
                    <button onClick={() => onVerify(item.id)} className="px-3 py-1.5 bg-green-600 hover:bg-green-700 rounded text-white">Verify</button>
                  )}
                  <button onClick={() => onDelete(item.id)} className="px-3 py-1.5 bg-gray-700 hover:bg-gray-600 rounded text-gray-100 inline-flex items-center">
                    <TrashIcon className="w-4 h-4 mr-1" /> Remove
                  </button>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
