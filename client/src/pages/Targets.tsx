import React, { useEffect, useMemo, useState } from 'react'
import { ShieldCheckIcon, PlusIcon, TrashIcon, CheckCircleIcon, ArrowPathIcon } from '@heroicons/react/24/outline'
import { apiFetch } from '@/utils/api'
import toast from 'react-hot-toast'

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
  const [items, setItems] = useState<TargetRecord[]>([])
  const [loading, setLoading] = useState(false)
  const [creating, setCreating] = useState(false)
  const [hostname, setHostname] = useState('')
  const [method, setMethod] = useState<'http-file' | 'dns-txt'>('http-file')

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
