import { useCallback, useEffect, useMemo, useState } from 'react'
import { toast } from 'react-hot-toast'
import { apiFetch } from '@/utils/api'

export type RunningScan = {
  scanId: string
  target: string | null
  status: string
  scanProfile: string | null
  sessionId: string | null
  userId: string | null
  userEmail: string | null
  userRole: string | null
  orgId: string | null
  startTime: string | null
  pid: number | null
  processInfo?: {
    pid: number | null
    startTime?: string | null
    target?: string | null
    scanProfile?: string | null
  } | null
  sqlmapContext?: {
    pid?: number | null
    context?: Record<string, unknown>
    userId?: string | null
    scanProfile?: string | null
    startTime?: string | null
  } | null
}

export type RunningScansSnapshot = {
  items: RunningScan[]
  totals: {
    database: number
    processes: number
    sqlmap: number
  }
}

const PAGE_SIZE_OPTIONS = [10, 20, 50]
const REFRESH_INTERVAL_MS = 15000

type TerminateHandler = (scan: RunningScan) => Promise<void>

type RunningScansPanelProps = {
  onTerminate?: TerminateHandler
}

const formatDateTime = (iso: string | null | undefined) => {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  return d.toLocaleString()
}

const formatDuration = (iso: string | null | undefined) => {
  if (!iso) return '—'
  const start = new Date(iso).getTime()
  if (!Number.isFinite(start)) return '—'
  const diffSeconds = Math.max(0, Math.round((Date.now() - start) / 1000))
  const hours = Math.floor(diffSeconds / 3600)
  const minutes = Math.floor((diffSeconds % 3600) / 60)
  const seconds = diffSeconds % 60
  const parts = []
  if (hours > 0) parts.push(`${hours}h`)
  if (minutes > 0 || hours > 0) parts.push(`${minutes}m`)
  parts.push(`${seconds}s`)
  return parts.join(' ')
}

const matchSearch = (scan: RunningScan, query: string) => {
  if (!query) return true
  const q = query.toLowerCase()
  return [
    scan.scanId,
    scan.target,
    scan.sessionId,
    scan.userId,
    scan.userEmail,
    scan.orgId,
    scan.status,
    scan.scanProfile
  ]
    .filter(Boolean)
    .some(value => value!.toLowerCase().includes(q))
}

export function RunningScansPanel({ onTerminate }: RunningScansPanelProps) {
  const [snapshot, setSnapshot] = useState<RunningScansSnapshot | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [page, setPage] = useState(1)
  const [pageSize, setPageSize] = useState(PAGE_SIZE_OPTIONS[0])
  const [terminatingScanId, setTerminatingScanId] = useState<string | null>(null)

  const fetchSnapshot = useCallback(async () => {
    try {
      setLoading(true)
      setError(null)
      const data = await apiFetch<RunningScansSnapshot>('/api/admin/scans/running')
      setSnapshot(data)
      return true
    } catch (err: any) {
      const message = err?.message || 'Failed to load running scans'
      setError(message)
      toast.error(message)
      return false
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchSnapshot()
    const timer = setInterval(fetchSnapshot, REFRESH_INTERVAL_MS)
    return () => clearInterval(timer)
  }, [fetchSnapshot])

  useEffect(() => {
    setPage(1)
  }, [search, pageSize])

  const filteredItems = useMemo(() => {
    if (!snapshot) return []
    const items = snapshot.items.filter(item => matchSearch(item, search))
    return items.sort((a, b) => {
      const timeA = a.startTime ? new Date(a.startTime).getTime() : 0
      const timeB = b.startTime ? new Date(b.startTime).getTime() : 0
      return timeB - timeA
    })
  }, [snapshot, search])

  const pageCount = Math.max(1, Math.ceil(filteredItems.length / pageSize))
  const currentPage = Math.min(page, pageCount)
  const pagedItems = filteredItems.slice((currentPage - 1) * pageSize, currentPage * pageSize)

  const handleManualRefresh = async () => {
    const ok = await fetchSnapshot()
    if (ok) toast.success('Running scans refreshed')
  }

  const handleTerminate = async (scan: RunningScan) => {
    if (!onTerminate) return
    try {
      setTerminatingScanId(scan.scanId)
      await onTerminate(scan)
      await fetchSnapshot()
    } catch (err: any) {
      const message = err?.message || 'Failed to terminate scan'
      toast.error(message)
    } finally {
      setTerminatingScanId(null)
    }
  }

  return (
    <div className="bg-gray-800 p-4 rounded-lg border border-gray-700 space-y-4">
      <div className="flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
        <div>
          <h2 className="text-xl font-semibold text-blue-200">Active Scans</h2>
          <p className="text-sm text-gray-400">Live view of running scans across the platform.</p>
        </div>
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <input
            type="search"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search target, user, session…"
            className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm text-gray-200 focus:border-blue-500 focus:outline-none"
          />
          <div className="flex items-center gap-2">
            <label className="text-xs text-gray-400" htmlFor="running-scans-page-size">Page size</label>
            <select
              id="running-scans-page-size"
              value={pageSize}
              onChange={e => setPageSize(Number(e.target.value))}
              className="bg-gray-900 border border-gray-700 rounded px-2 py-1 text-sm text-gray-200"
            >
              {PAGE_SIZE_OPTIONS.map(size => (
                <option key={size} value={size}>{size}</option>
              ))}
            </select>
          </div>
          <button
            onClick={handleManualRefresh}
            disabled={loading}
            className="px-3 py-2 rounded border border-blue-600 bg-blue-700 text-sm text-white disabled:opacity-60 disabled:cursor-not-allowed"
          >
            {loading ? 'Refreshing…' : 'Refresh'}
          </button>
        </div>
      </div>

      {error && (
        <div className="text-sm text-red-400">{error}</div>
      )}

      {snapshot && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <StatCard label="DB active" value={snapshot.totals.database} subtitle="Rows flagged as running" />
          <StatCard label="Processes tracked" value={snapshot.totals.processes} subtitle="In-memory workers" />
          <StatCard label="SQLMap sessions" value={snapshot.totals.sqlmap} subtitle="Sessions reporting active" />
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="min-w-full text-sm text-gray-200">
          <thead>
            <tr className="bg-gray-900 text-left">
              <th className="px-3 py-2 font-semibold">Target</th>
              <th className="px-3 py-2 font-semibold">User</th>
              <th className="px-3 py-2 font-semibold">Session</th>
              <th className="px-3 py-2 font-semibold">Started</th>
              <th className="px-3 py-2 font-semibold">Duration</th>
              <th className="px-3 py-2 font-semibold">Status</th>
              <th className="px-3 py-2 font-semibold text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading && (!snapshot || snapshot.items.length === 0) && (
              <tr>
                <td colSpan={7} className="px-3 py-4 text-center text-gray-400">Loading…</td>
              </tr>
            )}

            {!loading && pagedItems.length === 0 && (
              <tr>
                <td colSpan={7} className="px-3 py-4 text-center text-gray-500">No running scans found.</td>
              </tr>
            )}

            {pagedItems.map(scan => (
              <tr key={scan.scanId} className="border-b border-gray-700/60 last:border-none hover:bg-gray-900/60">
                <td className="px-3 py-2">
                  <div className="font-medium text-gray-100 truncate max-w-[220px]" title={scan.target || '—'}>
                    {scan.target || '—'}
                  </div>
                  <div className="text-xs text-gray-500">Profile: {scan.scanProfile || 'default'}</div>
                </td>
                <td className="px-3 py-2">
                  <div className="text-gray-100">{scan.userEmail || scan.userId || '—'}</div>
                  <div className="text-xs text-gray-500">Org: {scan.orgId || 'n/a'}</div>
                </td>
                <td className="px-3 py-2">
                  <div className="text-xs text-gray-400 break-all max-w-[220px]" title={scan.sessionId || '—'}>{scan.sessionId || '—'}</div>
                  {scan.pid != null && (
                    <div className="text-[11px] text-gray-500">PID: {scan.pid}</div>
                  )}
                </td>
                <td className="px-3 py-2">
                  <div>{formatDateTime(scan.startTime)}</div>
                </td>
                <td className="px-3 py-2">
                  <div>{formatDuration(scan.startTime)}</div>
                </td>
                <td className="px-3 py-2">
                  <span className={`inline-flex items-center px-2 py-1 rounded text-xs font-semibold ${scan.status === 'running' ? 'bg-green-900 text-green-200' : 'bg-yellow-900 text-yellow-200'}`}>
                    {scan.status}
                  </span>
                </td>
                <td className="px-3 py-2 text-right">
                  <div className="flex justify-end gap-2">
                    <button
                      className="px-3 py-1 rounded border border-red-600 text-red-200 hover:bg-red-600/20 text-xs disabled:opacity-50 disabled:cursor-not-allowed"
                      onClick={() => handleTerminate(scan)}
                      disabled={!onTerminate || loading || terminatingScanId === scan.scanId}
                    >
                      {terminatingScanId === scan.scanId ? 'Terminating…' : 'Terminate'}
                    </button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between text-sm text-gray-400">
        <div>
          Showing {pagedItems.length} of {filteredItems.length} matching scans
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setPage(p => Math.max(1, p - 1))}
            disabled={currentPage <= 1}
            className="px-2 py-1 rounded border border-gray-700 disabled:opacity-50"
          >
            Prev
          </button>
          <span>Page {currentPage} of {pageCount}</span>
          <button
            onClick={() => setPage(p => Math.min(pageCount, p + 1))}
            disabled={currentPage >= pageCount}
            className="px-2 py-1 rounded border border-gray-700 disabled:opacity-50"
          >
            Next
          </button>
        </div>
      </div>
    </div>
  )
}

function StatCard({ label, value, subtitle }: { label: string; value: number; subtitle: string }) {
  return (
    <div className="bg-gray-900 p-4 rounded-lg border border-gray-700">
      <div className="text-xs uppercase tracking-wide text-gray-400">{label}</div>
      <div className="text-3xl font-bold text-blue-300">{value}</div>
      <div className="text-xs text-gray-500">{subtitle}</div>
    </div>
  )
}

export default RunningScansPanel
