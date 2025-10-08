import { useCallback, useEffect, useState } from 'react'
import { toast } from 'react-hot-toast'
import { useAppStore } from '@/store/appStore'
import { apiFetch } from '@/utils/api'
import RunningScansPanel, { RunningScan } from '@/components/admin/RunningScansPanel'

interface Metrics {
  users: { total: number; admins: number }
  scans: { last7d: { started: number; completed: number }; last30d: { started: number; completed: number } }
  timeToFirstReportMsAvg7d: number | null
  verifications7d: number
  falsePositives7d: number
  visits: { series: Array<{ day: string; visits: number }>; topPages: Array<{ path: string; c: number }> }
}

export default function Admin() {
  const currentUser = useAppStore(s => s.currentUser)
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [settings, setSettings] = useState<{
    require_proxy: { effective: boolean; env: string | null; db: string | null }
    trust_proxy: { effective: string; env: string | null; db: string | null }
  } | null>(null)
  const [saving, setSaving] = useState(false)

  const handleTerminateScan = useCallback(async (scan: RunningScan) => {
    if (typeof window !== 'undefined') {
      const confirmed = window.confirm(`Terminate scan ${scan.scanId}?`)
      if (!confirmed) return
    }

    let reason: string | undefined
    if (typeof window !== 'undefined') {
      const input = window.prompt('Reason for termination (optional)', 'Terminated by administrator')
      if (input && input.trim().length > 0) {
        reason = input.trim()
      }
    }

    try {
      await apiFetch(`/api/admin/scans/${encodeURIComponent(scan.scanId)}/terminate`, {
        method: 'POST',
        body: JSON.stringify(reason ? { reason } : {})
      })
      toast.success(`Termination requested for ${scan.scanId}`)
    } catch (e: any) {
      toast.error(e?.message || 'Failed to terminate scan')
      throw e
    }
  }, [])

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true)
        const [m, s] = await Promise.all([
          apiFetch<Metrics>('/api/admin/metrics'),
          apiFetch<{ settings: any }>('/api/admin/settings')
        ])
        setMetrics(m)
        setSettings(s.settings)
      } catch (e: any) {
        setError(e.message || 'Failed to fetch metrics')
        toast.error(e.message || 'Failed to fetch metrics')
      } finally {
        setLoading(false)
      }
    }
    load()
  }, [])

  if (currentUser?.role !== 'admin') {
    return (
      <div className="p-6">
        <h1 className="text-2xl font-bold text-red-400">Forbidden</h1>
        <p className="text-gray-300">You need admin privileges to access this page.</p>
      </div>
    )
  }

  if (loading) {
    return <div className="p-6">Loading metrics…</div>
  }
  if (error) {
    return <div className="p-6 text-red-400">{error}</div>
  }
  if (!metrics) {
    return <div className="p-6">No metrics available.</div>
  }

  const avgTtfr = metrics.timeToFirstReportMsAvg7d != null ? `${Math.round(metrics.timeToFirstReportMsAvg7d/1000)}s` : '—'
  const requireProxyEffective = settings?.require_proxy.effective ? 'Enabled' : 'Disabled'
  const trustProxyEffective = settings?.trust_proxy.effective || 'auto'
  // Map visits count to a fixed set of height classes to avoid inline styles
  const heightClassForVisits = (v: number) => {
    const capped = Math.min(100, Math.max(0, v * 10))
    // Choose nearest step of 10 between 0 and 100
    const step = Math.round(capped / 10) * 10
    const map: Record<number, string> = {
      0: 'h-0',
      10: 'h-[10px]',
      20: 'h-[20px]',
      30: 'h-[30px]',
      40: 'h-[40px]',
      50: 'h-[50px]',
      60: 'h-[60px]',
      70: 'h-[70px]',
      80: 'h-[80px]',
      90: 'h-[90px]',
      100: 'h-[100px]'
    }
    return map[step as 0|10|20|30|40|50|60|70|80|90|100] || 'h-0'
  }

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold text-blue-300">Admin Dashboard</h1>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
          <div className="text-gray-400 text-sm">Users</div>
          <div className="text-3xl font-bold">{metrics.users.total}</div>
          <div className="text-xs text-gray-400">Admins: {metrics.users.admins}</div>
        </div>
        <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
          <div className="text-gray-400 text-sm">Scans last 7d</div>
          <div className="text-3xl font-bold">{metrics.scans.last7d.started}</div>
          <div className="text-xs text-gray-400">Completed: {metrics.scans.last7d.completed}</div>
        </div>
        <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
          <div className="text-gray-400 text-sm">Avg time to first report (7d)</div>
          <div className="text-3xl font-bold">{avgTtfr}</div>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
          <div className="text-gray-400 text-sm">Verifications (7d)</div>
          <div className="text-3xl font-bold">{metrics.verifications7d}</div>
        </div>
        <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
          <div className="text-gray-400 text-sm">False positives (7d)</div>
          <div className="text-3xl font-bold">{metrics.falsePositives7d}</div>
        </div>
        <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
          <div className="text-gray-400 text-sm">Scans last 30d</div>
          <div className="text-3xl font-bold">{metrics.scans.last30d.started}</div>
          <div className="text-xs text-gray-400">Completed: {metrics.scans.last30d.completed}</div>
        </div>
      </div>

      <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
        <div className="flex items-center justify-between mb-2">
          <div className="text-gray-400 text-sm">Visits (last 14 days)</div>
          <div className="text-[10px] text-gray-400">
            <span className="inline-block w-3 h-3 bg-blue-600 rounded-sm mr-1 align-middle" />
            Visits per day
          </div>
        </div>
        <div className="grid grid-cols-14 gap-2">
          {metrics.visits.series.map((d) => (
            <div key={d.day} className="flex flex-col items-center group" title={`${d.day}: ${d.visits} visits`}>
              <div className={`w-6 bg-blue-600 ${heightClassForVisits(d.visits)} group-hover:bg-blue-500 transition-colors`} />
              <div className="text-[10px] text-gray-400 mt-1">{d.day.slice(5)}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="bg-gray-800 p-4 rounded-lg border border-gray-700">
        <div className="text-gray-400 text-sm mb-2">Top Pages (14 days)</div>
        <div className="space-y-1">
          {metrics.visits.topPages.map((p) => (
            <div key={p.path} className="flex justify-between text-sm">
              <span className="text-gray-300">{p.path || '(unknown)'}</span>
              <span className="text-gray-400">{p.c}</span>
            </div>
          ))}
        </div>
      </div>

  <RunningScansPanel onTerminate={handleTerminateScan} />

      {/* Settings Panel */}
      <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-semibold text-blue-200">Site Settings</h2>
          <div className="text-xs text-gray-400">Admin-only</div>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <div className="text-gray-300 font-medium">Require Proxy</div>
            <div className="text-sm text-gray-400">Effective: {requireProxyEffective} {settings?.require_proxy.env ? '(ENV override)' : settings?.require_proxy.db ? '(Admin override)' : ''}</div>
            <div className="flex items-center gap-2">
              <button
                disabled={saving}
                className={`px-3 py-1 rounded border ${settings?.require_proxy.effective ? 'bg-green-700 border-green-600' : 'bg-gray-700 border-gray-600'} text-white text-sm`}
                onClick={async () => {
                  try {
                    setSaving(true)
                    const next = !(settings?.require_proxy.effective)
                    await apiFetch('/api/admin/settings', {
                      method: 'PUT',
                      body: JSON.stringify({ require_proxy: String(next) })
                    })
                    toast.success(`Require Proxy ${next ? 'enabled' : 'disabled'}`)
                    const s = await apiFetch<{ settings: any }>('/api/admin/settings')
                    setSettings(s.settings)
                  } catch (e: any) {
                    toast.error(e.message || 'Failed to update setting')
                  } finally {
                    setSaving(false)
                  }
                }}
              >
                Toggle
              </button>
            </div>
          </div>

          <div className="space-y-2">
            <div className="text-gray-300 font-medium">Trust Proxy</div>
            <div className="text-sm text-gray-400">Effective: {trustProxyEffective} {settings?.trust_proxy.env ? '(ENV override)' : settings?.trust_proxy.db ? '(Admin override)' : ''}</div>
            <div className="flex items-center gap-2">
              <select
                disabled={saving}
                className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm text-gray-200"
                aria-label="Trust Proxy mode"
                value={(settings?.trust_proxy.db ?? settings?.trust_proxy.env ?? 'auto').toString()}
                onChange={e => setSettings(s => s ? { ...s, trust_proxy: { ...s.trust_proxy, db: e.target.value } } : s)}
              >
                <option value="auto">auto (loopback, linklocal, uniquelocal)</option>
                <option value="true">true (trust all)</option>
                <option value="false">false (trust none)</option>
              </select>
              <button
                disabled={saving}
                className="px-3 py-1 rounded border bg-blue-700 border-blue-600 text-white text-sm"
                onClick={async () => {
                  try {
                    setSaving(true)
                    const val = (settings?.trust_proxy.db ?? 'auto').toString()
                    await apiFetch('/api/admin/settings', {
                      method: 'PUT',
                      body: JSON.stringify({ trust_proxy: val })
                    })
                    toast.success('Trust Proxy updated')
                    const s = await apiFetch<{ settings: any }>('/api/admin/settings')
                    setSettings(s.settings)
                  } catch (e: any) {
                    toast.error(e.message || 'Failed to update trust proxy')
                  } finally {
                    setSaving(false)
                  }
                }}
              >
                Save
              </button>
            </div>
            <div className="text-xs text-gray-500">Tip: When behind a dev proxy (like Vite), set this to auto or true to avoid rate-limit IP warnings.</div>
          </div>
        </div>
      </div>
    </div>
  )
}
