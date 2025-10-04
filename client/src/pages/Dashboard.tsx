import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { 
  PlayIcon, 
  DocumentTextIcon, 
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  ShieldCheckIcon,
  ComputerDesktopIcon,
  ArrowTrendingUpIcon,
  CheckBadgeIcon,
  EnvelopeOpenIcon,
  BookmarkIcon
} from '@heroicons/react/24/outline'
import { useAppStore, selectRunningScans, selectQueuedScans } from '../store/appStore'
import { shallow } from 'zustand/shallow'
import clsx from 'clsx'
import { apiFetch } from '@/utils/api'
import { parseServerDate } from '@/utils/dates'

type TrendPoint = {
  day: string
  count: number
}

type AnalyticsSummary = {
  dailyScans: {
    total: number
    trend: TrendPoint[]
    windowDays: number
  }
  successErrorRatio: {
    success: number
    error: number
    pending: number
    successRate: number
    errorRate: number
    windowDays: number
  }
  demoUsage: {
    total: number
    breakdown: Array<{ host: string; count: number }>
    windowDays: number
  }
  feedbackSubmissions: {
    total: number
    trend: TrendPoint[]
    windowDays: number
  }
  updatedAt: string
}

const numberFormatter = new Intl.NumberFormat()
const formatNumber = (value: number) => numberFormatter.format(value)

interface SparklineProps {
  data: TrendPoint[]
  color?: string
}

function Sparkline({ data, color = '#22d3ee' }: SparklineProps) {
  if (!data || data.length === 0) {
    return <div className="h-10 text-xs text-gray-500 flex items-center">No data</div>
  }

  const counts = data.map(point => point.count)
  const max = Math.max(...counts, 0)
  const min = Math.min(...counts, 0)
  const range = Math.max(1, max - min)

  const coordinates = data.map((point, index) => {
    const x = data.length === 1 ? 50 : (index / (data.length - 1)) * 100
    const y = 100 - ((point.count - min) / range) * 100
    return { x, y }
  })

  let linePoints: string
  if (coordinates.length === 1) {
    const { y } = coordinates[0]
    linePoints = `0,${y.toFixed(2)} 100,${y.toFixed(2)}`
  } else {
    linePoints = coordinates.map(({ x, y }) => `${x.toFixed(2)},${y.toFixed(2)}`).join(' ')
  }

  const last = coordinates[coordinates.length - 1]

  return (
    <svg viewBox="0 0 100 100" preserveAspectRatio="none" className="w-full h-10">
      <polyline
        points={linePoints}
        fill="none"
        stroke={color}
        strokeWidth={2.5}
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      {last && (
        <circle
          cx={last.x.toFixed(2)}
          cy={last.y.toFixed(2)}
          r={2.7}
          stroke={color}
          strokeWidth={1.5}
          fill="#111827"
        />
      )}
    </svg>
  )
}

export default function Dashboard() {
  const runningScans = useAppStore(selectRunningScans)
  const queuedScans = useAppStore(selectQueuedScans)
  const {
    reports,
    scans,
    isConnected,
    initialize,
    isLoading
  } = useAppStore(state => ({
    reports: state.reports,
    scans: state.scans,
    isConnected: state.isConnected,
    initialize: state.initialize,
    isLoading: state.isLoading,
  }), shallow)
  const runningScanCount = runningScans.length
  const queuedScanCount = queuedScans.length

  const [usage, setUsage] = useState<null | {
    period: string;
    usage: { scans_started: number; scans_completed: number; total_runtime_ms: number };
    limits: { concurrent: number; monthly: number };
  }>(null)
  const [analytics, setAnalytics] = useState<AnalyticsSummary | null>(null)
  const [analyticsLoading, setAnalyticsLoading] = useState(false)
  const [analyticsError, setAnalyticsError] = useState<string | null>(null)

  useEffect(() => {
    const loadUsage = async () => {
      try {
        const data = await apiFetch('/api/usage')
        setUsage(data as any)
      } catch {
        // Non-blocking: ignore errors
      }
    }
    loadUsage()
  }, [])

  useEffect(() => {
    let cancelled = false

    const loadAnalytics = async () => {
      setAnalyticsLoading(true)
      try {
        const data = await apiFetch<AnalyticsSummary>('/api/analytics/summary')
        if (!cancelled) {
          setAnalytics(data)
          setAnalyticsError(null)
        }
      } catch (error) {
        if (!cancelled) {
          const message = error instanceof Error ? error.message : 'Failed to load analytics insights'
          setAnalyticsError(message)
        }
      } finally {
        if (!cancelled) {
          setAnalyticsLoading(false)
        }
      }
    }

    loadAnalytics()

    return () => {
      cancelled = true
    }
  }, [])

  useEffect(() => {
    // Initialize the store to load data
    initialize()
  }, [initialize])

  // Calculate stats from real data
  const totalVulnerabilities = reports.reduce((total, report) => {
    return total + (report.vulnerabilities?.total || 0)
  }, 0)

  const stats = [
    { name: 'Total Scans', stat: scans.length.toString(), icon: ChartBarIcon, color: 'text-blue-400', href: '/reports' },
    {
      name: 'Running Scans',
      stat: runningScanCount.toString(),
      icon: PlayIcon,
      color: 'text-green-400',
      href: '/terminal',
      description: queuedScanCount > 0 ? `${queuedScanCount} ${queuedScanCount === 1 ? 'queued scan' : 'queued scans'}` : undefined,
    },
    { name: 'Vulnerabilities Found', stat: totalVulnerabilities.toString(), icon: ExclamationTriangleIcon, color: 'text-red-400', href: '/reports' },
    { name: 'Reports Generated', stat: reports.length.toString(), icon: DocumentTextIcon, color: 'text-purple-400', href: '/reports' },
  ]

  const usageProgress = (() => {
    if (!usage) return 0
    const used = usage.usage.scans_started || 0
    const cap = usage.limits.monthly || 1
    return Math.min(100, Math.round((used / cap) * 100))
  })()

  const dailyTrend = analytics?.dailyScans.trend ?? []
  const latestDailyCount = dailyTrend.length > 0 ? dailyTrend[dailyTrend.length - 1].count : 0
  const previousDailyCount = dailyTrend.length > 1 ? dailyTrend[dailyTrend.length - 2].count : 0
  const dailyDelta = latestDailyCount - previousDailyCount

  const feedbackTrend = analytics?.feedbackSubmissions.trend ?? []
  const latestFeedbackCount = feedbackTrend.length > 0 ? feedbackTrend[feedbackTrend.length - 1].count : 0
  const previousFeedbackCount = feedbackTrend.length > 1 ? feedbackTrend[feedbackTrend.length - 2].count : 0
  const feedbackDelta = latestFeedbackCount - previousFeedbackCount

  const ratio = analytics?.successErrorRatio
  const successDenominator = ratio ? ratio.success + ratio.error : 0
  const successProgress = successDenominator === 0 || !ratio ? 0 : ratio.success / successDenominator
  const errorProgress = successDenominator === 0 || !ratio ? 0 : ratio.error / successDenominator

  const demoBreakdown = analytics?.demoUsage.breakdown ? analytics.demoUsage.breakdown.slice(0, 2) : []
  const demoTopSum = demoBreakdown.reduce((sum, item) => sum + item.count, 0)
  const demoOther = Math.max(0, (analytics?.demoUsage.total ?? 0) - demoTopSum)

  // Format time ago
  const formatTimeAgo = (input: string | Date | null | undefined) => {
    const date = input instanceof Date ? input : parseServerDate(input ?? undefined)
    if (!date) return 'Unknown'

    const now = new Date()
    const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000)
    
    if (diffInSeconds < 0) return 'just now'
    if (diffInSeconds < 60) return 'just now'
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`
    return `${Math.floor(diffInSeconds / 86400)} days ago`
  }

  // Get recent scans (last 5)
  const getScanTimestamp = (scan: typeof scans[number]) => {
    const time = scan.endTime || scan.updatedAt || scan.createdAt
    return parseServerDate(time)
  }

  const recentScans = scans
    .slice()
    .sort((a, b) => (getScanTimestamp(b)?.getTime() || 0) - (getScanTimestamp(a)?.getTime() || 0))
    .slice(0, 5)
    .map(scan => {
      // Find corresponding report for vulnerability count
      const report = reports.find(r => r.scanId === scan.id)
      const timestamp = getScanTimestamp(scan)
      return {
        id: scan.id,
        target: scan.target,
        status: scan.status,
        vulnerabilities: report?.vulnerabilities?.total || 0,
        time: formatTimeAgo(timestamp),
        timestamp
      }
    })

  const getStatusIcon = (status: string) => {
    switch (status) {
      case 'completed':
        return <CheckCircleIcon className="h-5 w-5 text-green-400" />
      case 'running':
        return <ClockIcon className="h-5 w-5 text-yellow-400 animate-spin" />
      case 'failed':
        return <ExclamationTriangleIcon className="h-5 w-5 text-red-400" />
      default:
        return <ClockIcon className="h-5 w-5 text-gray-400" />
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed':
        return 'text-green-400 bg-green-400/10'
      case 'running':
        return 'text-yellow-400 bg-yellow-400/10'
      case 'failed':
        return 'text-red-400 bg-red-400/10'
      default:
        return 'text-gray-400 bg-gray-400/10'
    }
  }

  return (
    <div className="h-full overflow-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-white flex items-center">
            <ShieldCheckIcon className="h-8 w-8 mr-3 text-blue-400" />
            Security Dashboard
          </h1>
          <p className="mt-2 text-gray-400">
            Monitor your security scans and vulnerability assessments
          </p>
        </div>

        {/* Connection Status Alert */}
        {!isConnected && (
          <div className="mb-6 rounded-md bg-red-900/50 p-4 border border-red-800">
            <div className="flex">
              <div className="flex-shrink-0">
                <ExclamationTriangleIcon className="h-5 w-5 text-red-400" aria-hidden="true" />
              </div>
              <div className="ml-3">
                <h3 className="text-sm font-medium text-red-200">
                  Connection Issue
                </h3>
                <div className="mt-2 text-sm text-red-300">
                  <p>Unable to connect to the backend server. Some features may be unavailable.</p>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* Analytics Insights */}
        <div className="mb-8">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-2">
              <ChartBarIcon className="h-6 w-6 text-cyan-400" />
              <h2 className="text-lg font-semibold text-white">Insights</h2>
            </div>
            {analytics?.updatedAt && (
              <span className="text-xs text-gray-500">
                Updated {formatTimeAgo(analytics.updatedAt)}
              </span>
            )}
          </div>

          {analyticsError && (
            <div className="mb-4 rounded border border-red-800 bg-red-900/40 px-4 py-3 text-sm text-red-300">
              {analyticsError}
            </div>
          )}

          <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4">
            {analytics ? (
              <>
                <div className="bg-gray-800 border border-gray-700 rounded-lg p-5 flex flex-col">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-xs uppercase tracking-wide text-gray-400">Daily Scans</p>
                      <p className="mt-2 text-2xl font-semibold text-white">{formatNumber(analytics.dailyScans.total)}</p>
                      <p className="mt-1 text-xs text-gray-500">
                        Last {analytics.dailyScans.windowDays} days · Today {formatNumber(latestDailyCount)}
                      </p>
                      {dailyTrend.length > 1 && (
                        <p
                          className={clsx(
                            'mt-1 text-xs font-medium',
                            dailyDelta >= 0 ? 'text-emerald-400' : 'text-amber-300'
                          )}
                        >
                          {dailyDelta >= 0 ? '+' : ''}{formatNumber(Math.abs(dailyDelta))} vs prev day
                        </p>
                      )}
                    </div>
                    <span className="bg-cyan-900/40 text-cyan-300 rounded-md p-2">
                      <ArrowTrendingUpIcon className="h-6 w-6" />
                    </span>
                  </div>
                  <div className="mt-4 flex-1 flex items-end">
                    <Sparkline data={dailyTrend} color="#22d3ee" />
                  </div>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-lg p-5 flex flex-col">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-xs uppercase tracking-wide text-gray-400">Success Rate</p>
                      <p className="mt-2 text-2xl font-semibold text-white">
                        {ratio && Number.isFinite(ratio.successRate) ? `${ratio.successRate.toFixed(1)}%` : '0.0%'}
                      </p>
                      <p className="mt-1 text-xs text-gray-500">
                        {formatNumber(ratio?.success ?? 0)} success · {formatNumber(ratio?.error ?? 0)} errors
                      </p>
                    </div>
                    <span className="bg-emerald-900/40 text-emerald-300 rounded-md p-2">
                      <CheckBadgeIcon className="h-6 w-6" />
                    </span>
                  </div>
                  <div className="mt-4 space-y-2 text-xs text-gray-400">
                    <div className="flex items-center justify-between">
                      <span className="text-emerald-300 font-medium">Success share</span>
                      <span>{Math.round((successProgress || 0) * 100)}%</span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-amber-300 font-medium">Error share</span>
                      <span>{Math.round((errorProgress || 0) * 100)}%</span>
                    </div>
                    {ratio && ratio.pending > 0 && (
                      <div className="flex items-center justify-between">
                        <span className="text-gray-500">Pending scans</span>
                        <span>{formatNumber(ratio.pending)}</span>
                      </div>
                    )}
                  </div>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-lg p-5 flex flex-col">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-xs uppercase tracking-wide text-gray-400">Demo Usage</p>
                      <p className="mt-2 text-2xl font-semibold text-white">{formatNumber(analytics.demoUsage.total)}</p>
                      <p className="mt-1 text-xs text-gray-500">Last {analytics.demoUsage.windowDays} days</p>
                    </div>
                    <span className="bg-blue-900/40 text-blue-300 rounded-md p-2">
                      <BookmarkIcon className="h-6 w-6" />
                    </span>
                  </div>
                  <div className="mt-4 space-y-2 text-xs text-gray-300">
                    {demoBreakdown.length > 0 ? (
                      <>
                        {demoBreakdown.map(({ host, count }) => (
                          <div key={host} className="flex items-center justify-between gap-2">
                            <span className="truncate">{host}</span>
                            <span className="text-gray-400">{formatNumber(count)}</span>
                          </div>
                        ))}
                        {demoOther > 0 && (
                          <div className="flex items-center justify-between text-gray-500">
                            <span>Other demo hosts</span>
                            <span>{formatNumber(demoOther)}</span>
                          </div>
                        )}
                      </>
                    ) : (
                      <p className="text-gray-500">Run a curated demo scan to populate this metric.</p>
                    )}
                  </div>
                </div>

                <div className="bg-gray-800 border border-gray-700 rounded-lg p-5 flex flex-col">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-xs uppercase tracking-wide text-gray-400">Feedback Received</p>
                      <p className="mt-2 text-2xl font-semibold text-white">{formatNumber(analytics.feedbackSubmissions.total)}</p>
                      <p className="mt-1 text-xs text-gray-500">Last {analytics.feedbackSubmissions.windowDays} days</p>
                      {feedbackTrend.length > 1 && (
                        <p
                          className={clsx(
                            'mt-1 text-xs font-medium',
                            feedbackDelta >= 0 ? 'text-emerald-400' : 'text-amber-300'
                          )}
                        >
                          {feedbackDelta >= 0 ? '+' : ''}{formatNumber(Math.abs(feedbackDelta))} vs prev day
                        </p>
                      )}
                    </div>
                    <span className="bg-purple-900/40 text-purple-300 rounded-md p-2">
                      <EnvelopeOpenIcon className="h-6 w-6" />
                    </span>
                  </div>
                  <div className="mt-4 flex-1 flex items-end">
                    <Sparkline data={feedbackTrend} color="#c084fc" />
                  </div>
                </div>
              </>
            ) : analyticsLoading ? (
              [0, 1, 2, 3].map((idx) => (
                <div
                  key={idx}
                  className="bg-gray-800 border border-gray-700 rounded-lg h-36 animate-pulse"
                ></div>
              ))
            ) : (
              <div className="bg-gray-800 border border-gray-700 rounded-lg p-5 text-sm text-gray-500 sm:col-span-2 lg:col-span-4">
                Analytics tiles will populate after scans and feedback activity start flowing.
              </div>
            )}
          </div>
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4 mb-8">
          {stats.map((item) => (
            <div
              key={item.name}
              className="relative bg-gray-800 pt-5 px-4 pb-12 sm:pt-6 sm:px-6 shadow rounded-lg overflow-hidden border border-gray-700"
            >
              <div>
                <div className="absolute bg-gray-700 rounded-md p-3">
                  <item.icon className={clsx("h-6 w-6", item.color)} aria-hidden="true" />
                </div>
                <p className="ml-16 text-sm font-medium text-gray-400 truncate">{item.name}</p>
              </div>
              <div className="ml-16 pb-6 sm:pb-7">
                <p className="text-2xl font-semibold text-white">{item.stat}</p>
                {item.description && (
                  <p className="mt-1 text-sm text-gray-400">{item.description}</p>
                )}
                <div className="absolute bottom-0 inset-x-0 bg-gray-700 px-4 py-4 sm:px-6">
                  <div className="text-sm">
                    <Link
                      to={item.href ?? '/reports'}
                      className="font-medium text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      View all
                    </Link>
                  </div>
                </div>
              </div>
            </div>
          ))}
          {/* Usage Widget */}
          <div className="relative bg-gray-800 pt-5 px-4 pb-12 sm:pt-6 sm:px-6 shadow rounded-lg overflow-hidden border border-gray-700">
            <div>
              <div className="absolute bg-gray-700 rounded-md p-3">
                <ChartBarIcon className="h-6 w-6 text-cyan-400" aria-hidden="true" />
              </div>
              <p className="ml-16 text-sm font-medium text-gray-400 truncate">Monthly Usage</p>
            </div>
            <div className="ml-16 pb-6 sm:pb-7">
              <div className="text-sm text-gray-300 mb-2">
                {usage ? (
                  <>
                    <span className="font-semibold text-white">{usage.usage.scans_started}</span> / {usage.limits.monthly} scans
                    <span className="ml-2 text-gray-500">({usage.period})</span>
                  </>
                ) : (
                  <span className="text-gray-500">Loading…</span>
                )}
              </div>
              <div className="w-full bg-gray-700 rounded h-2 overflow-hidden">
                <div className="grid grid-cols-10 h-2">
                  {Array.from({ length: 10 }).map((_, i) => (
                    <div key={i} className={clsx('h-2', usageProgress > i * 10 ? 'bg-cyan-500' : 'bg-gray-700')} />
                  ))}
                </div>
              </div>
              <div className="mt-3 text-xs text-gray-400">
                Concurrent limit: {usage?.limits.concurrent ?? '—'}
              </div>
              <div className="absolute bottom-0 inset-x-0 bg-gray-700 px-4 py-4 sm:px-6">
                <div className="text-sm">
                  <Link to="/usage" className="font-medium text-cyan-400 hover:text-cyan-300 transition-colors">
                    View usage
                  </Link>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Recent Scans */}
          <div className="bg-gray-800 shadow rounded-lg border border-gray-700">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-lg leading-6 font-medium text-white mb-4">Recent Scans</h3>
              
              {isLoading ? (
                <div className="flex justify-center items-center py-8">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div>
                </div>
              ) : recentScans.length > 0 ? (
                <div className="flow-root">
                  <ul role="list" className="-mb-8">
                    {recentScans.map((scan, scanIdx) => (
                      <li key={scan.id}>
                        <div className="relative pb-8">
                          {scanIdx !== recentScans.length - 1 && (
                            <span
                              className="absolute top-4 left-4 -ml-px h-full w-0.5 bg-gray-600"
                              aria-hidden="true"
                            />
                          )}
                          <div className="relative flex space-x-3">
                            <div>
                              <span className="bg-gray-700 h-8 w-8 rounded-full flex items-center justify-center ring-8 ring-gray-800">
                                {getStatusIcon(scan.status)}
                              </span>
                            </div>
                            <div className="min-w-0 flex-1 pt-1.5 flex justify-between space-x-4">
                              <div>
                                <p className="text-sm text-gray-300">
                                  Scan of{' '}
                                  <Link 
                                    to={`/reports?scanId=${scan.id}`}
                                    className="font-medium text-blue-400 hover:text-blue-300 transition-colors"
                                  >
                                    {scan.target}
                                  </Link>
                                </p>
                                <div className="mt-1 flex items-center space-x-2">
                                  <span
                                    className={clsx(
                                      'inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                                      getStatusColor(scan.status)
                                    )}
                                  >
                                    {scan.status}
                                  </span>
                                  {scan.status === 'completed' && scan.vulnerabilities > 0 && (
                                    <span className="text-xs text-red-400">
                                      {scan.vulnerabilities} vulnerabilities found
                                    </span>
                                  )}
                                </div>
                              </div>
                              <div className="text-right text-sm whitespace-nowrap text-gray-400">
                                <time>{scan.time}</time>
                              </div>
                            </div>
                          </div>
                        </div>
                      </li>
                    ))}
                  </ul>
                </div>
              ) : (
                <div className="text-center py-8">
                  <ChartBarIcon className="mx-auto h-12 w-12 text-gray-500" />
                  <h3 className="mt-2 text-sm font-medium text-gray-300">No scans yet</h3>
                  <p className="mt-1 text-sm text-gray-500">Get started by running your first security scan.</p>
                </div>
              )}
              <div className="mt-6">
                <Link
                  to="/terminal"
                  className="w-full flex justify-center items-center px-4 py-2 border border-transparent rounded-md shadow-sm text-sm font-medium text-white bg-blue-600 hover:bg-blue-700 transition-colors"
                >
                  <PlayIcon className="h-4 w-4 mr-2" />
                  Start New Scan
                </Link>
              </div>
            </div>
          </div>

          {/* Quick Actions */}
          <div className="bg-gray-800 shadow rounded-lg border border-gray-700">
            <div className="px-4 py-5 sm:p-6">
              <h3 className="text-lg leading-6 font-medium text-white mb-4">Quick Actions</h3>
              <div className="space-y-4">
                <Link
                  to="/terminal"
                  className="flex items-center p-4 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors group"
                >
                  <ComputerDesktopIcon className="h-8 w-8 text-blue-400 group-hover:text-blue-300" />
                  <div className="ml-4">
                    <p className="text-sm font-medium text-white">Open Terminal</p>
                    <p className="text-sm text-gray-400">Execute SQLMap commands directly</p>
                  </div>
                </Link>

                <Link
                  to="/reports"
                  className="flex items-center p-4 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors group"
                >
                  <DocumentTextIcon className="h-8 w-8 text-green-400 group-hover:text-green-300" />
                  <div className="ml-4">
                    <p className="text-sm font-medium text-white">View Reports</p>
                    <p className="text-sm text-gray-400">Browse scan results and analysis</p>
                  </div>
                </Link>

                <Link
                  to="/settings"
                  className="flex items-center p-4 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors group"
                >
                  <ShieldCheckIcon className="h-8 w-8 text-purple-400 group-hover:text-purple-300" />
                  <div className="ml-4">
                    <p className="text-sm font-medium text-white">Configure Settings</p>
                    <p className="text-sm text-gray-400">Customize scan profiles and preferences</p>
                  </div>
                </Link>
              </div>
            </div>
          </div>
        </div>

        {/* System Status */}
        <div className="mt-8 bg-gray-800 shadow rounded-lg border border-gray-700">
          <div className="px-4 py-5 sm:p-6">
            <h3 className="text-lg leading-6 font-medium text-white mb-4">System Status</h3>
            <dl className="grid grid-cols-1 gap-x-4 gap-y-6 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <dt className="text-sm font-medium text-gray-400">Backend Connection</dt>
                <dd className="mt-1 flex items-center">
                  <div className={clsx(
                    'w-2 h-2 rounded-full mr-2',
                    isConnected ? 'bg-green-400' : 'bg-red-400'
                  )}></div>
                  <span className={clsx(
                    'text-sm font-medium',
                    isConnected ? 'text-green-400' : 'text-red-400'
                  )}>
                    {isConnected ? 'Connected' : 'Disconnected'}
                  </span>
                </dd>
              </div>
              
              <div>
                <dt className="text-sm font-medium text-gray-400">SQLMap Status</dt>
                <dd className="mt-1 flex items-center">
                  <div className="w-2 h-2 bg-green-400 rounded-full mr-2"></div>
                  <span className="text-sm font-medium text-green-400">Available</span>
                </dd>
              </div>
              
              <div>
                <dt className="text-sm font-medium text-gray-400">Running Scans</dt>
                <dd className="mt-1 text-sm font-medium text-white">
                  {runningScanCount}
                </dd>
              </div>

              <div>
                <dt className="text-sm font-medium text-gray-400">Queued Scans</dt>
                <dd className="mt-1 text-sm font-medium text-white">
                  {queuedScanCount}
                </dd>
              </div>

              <div>
                <dt className="text-sm font-medium text-gray-400">Total Reports</dt>
                <dd className="mt-1 text-sm font-medium text-white">
                  {reports.length}
                </dd>
              </div>
            </dl>
          </div>
        </div>
      </div>
    </div>
  )
} 