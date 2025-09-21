import { useEffect, useState } from 'react'
import { ChartBarIcon } from '@heroicons/react/24/outline'
import { apiFetch } from '@/utils/api'
import toast from 'react-hot-toast'

type UsageResponse = {
  period: string
  usage: { user_id: string; period: string; scans_started: number; scans_completed: number; total_runtime_ms: number }
  limits: { concurrent: number; monthly: number }
}

function msToHms(ms: number) {
  const totalSeconds = Math.floor(ms / 1000)
  const h = Math.floor(totalSeconds / 3600)
  const m = Math.floor((totalSeconds % 3600) / 60)
  const s = totalSeconds % 60
  return `${h}h ${m}m ${s}s`
}

export default function Usage() {
  const [data, setData] = useState<UsageResponse | null>(null)
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const res = await apiFetch<UsageResponse>('/api/usage')
      setData(res)
    } catch (e: any) {
      toast.error(e.message || 'Failed to load usage')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  return (
    <div className="h-full overflow-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white flex items-center">
            <ChartBarIcon className="h-8 w-8 mr-3 text-blue-400" />
            Usage & Quotas
          </h1>
          <p className="mt-2 text-gray-400">Your current month usage and plan limits.</p>
        </div>

        <div className="bg-gray-800 rounded-lg border border-gray-700 p-6">
          {loading && <div className="text-gray-400">Loading…</div>}
          {!loading && data && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-gray-900 border border-gray-700 rounded p-4">
                <div className="text-sm text-gray-400">Period</div>
                <div className="text-xl text-white font-semibold">{data.period}</div>
              </div>
              <div className="bg-gray-900 border border-gray-700 rounded p-4">
                <div className="text-sm text-gray-400">Scans Started</div>
                <div className="text-xl text-white font-semibold">{data.usage.scans_started} / {data.limits.monthly}</div>
              </div>
              <div className="bg-gray-900 border border-gray-700 rounded p-4">
                <div className="text-sm text-gray-400">Concurrent Limit</div>
                <div className="text-xl text-white font-semibold">{data.limits.concurrent}</div>
              </div>

              <div className="bg-gray-900 border border-gray-700 rounded p-4">
                <div className="text-sm text-gray-400">Scans Completed</div>
                <div className="text-xl text-white font-semibold">{data.usage.scans_completed}</div>
              </div>
              <div className="bg-gray-900 border border-gray-700 rounded p-4">
                <div className="text-sm text-gray-400">Total Runtime</div>
                <div className="text-xl text-white font-semibold">{msToHms(data.usage.total_runtime_ms)}</div>
              </div>
            </div>
          )}
          {!loading && !data && (
            <div className="text-gray-400">No usage data.</div>
          )}
        </div>
      </div>
    </div>
  )
}
