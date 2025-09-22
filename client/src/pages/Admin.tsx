import { useEffect, useState } from 'react'
import { toast } from 'react-hot-toast'
import { useAppStore } from '@/store/appStore'
import { apiFetch } from '@/utils/api'

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

  useEffect(() => {
    const load = async () => {
      try {
        setLoading(true)
        const data = await apiFetch<Metrics>('/api/admin/metrics')
        setMetrics(data)
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
    </div>
  )
}
