import { useEffect } from 'react'
import { Link } from 'react-router-dom'
import { 
  PlayIcon, 
  DocumentTextIcon, 
  ChartBarIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  ShieldCheckIcon,
  ComputerDesktopIcon
} from '@heroicons/react/24/outline'
import { useAppStore } from '../store/appStore'
import clsx from 'clsx'

export default function Dashboard() {
  const { 
    runningScans, 
    reports, 
    scans, 
    isConnected, 
    initialize,
    isLoading
  } = useAppStore()

  useEffect(() => {
    // Initialize the store to load data
    initialize()
  }, [initialize])

  // Calculate stats from real data
  const totalVulnerabilities = reports.reduce((total, report) => {
    return total + (report.vulnerabilities?.total || 0)
  }, 0)

  const stats = [
    { name: 'Total Scans', stat: scans.length.toString(), icon: ChartBarIcon, color: 'text-blue-400' },
    { name: 'Active Scans', stat: runningScans.length.toString(), icon: PlayIcon, color: 'text-green-400' },
    { name: 'Vulnerabilities Found', stat: totalVulnerabilities.toString(), icon: ExclamationTriangleIcon, color: 'text-red-400' },
    { name: 'Reports Generated', stat: reports.length.toString(), icon: DocumentTextIcon, color: 'text-purple-400' },
  ]

  // Format time ago
  const formatTimeAgo = (dateString: string) => {
    if (!dateString) return 'Unknown'
    
    const date = new Date(dateString)
    if (isNaN(date.getTime())) return 'Unknown'
    
    const now = new Date()
    const diffInSeconds = Math.floor((now.getTime() - date.getTime()) / 1000)
    
    if (diffInSeconds < 0) return 'just now'
    if (diffInSeconds < 60) return 'just now'
    if (diffInSeconds < 3600) return `${Math.floor(diffInSeconds / 60)} minutes ago`
    if (diffInSeconds < 86400) return `${Math.floor(diffInSeconds / 3600)} hours ago`
    return `${Math.floor(diffInSeconds / 86400)} days ago`
  }

  // Get recent scans (last 5)
  const recentScans = scans
    .slice()
    .sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime())
    .slice(0, 5)
    .map(scan => {
      // Find corresponding report for vulnerability count
      const report = reports.find(r => r.scanId === scan.id)
      return {
        id: scan.id,
        target: scan.target,
        status: scan.status,
        vulnerabilities: report?.vulnerabilities?.total || 0,
        time: formatTimeAgo(scan.createdAt)
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

        {/* Stats Overview */}
        <div className="grid grid-cols-1 gap-5 sm:grid-cols-2 lg:grid-cols-4 mb-8">
          {stats.map((item) => (
            <div
              key={item.name}
              className="relative bg-gray-800 pt-5 px-4 pb-12 sm:pt-6 sm:px-6 shadow rounded-lg overflow-hidden border border-gray-700"
            >
              <dt>
                <div className="absolute bg-gray-700 rounded-md p-3">
                  <item.icon className={clsx("h-6 w-6", item.color)} aria-hidden="true" />
                </div>
                <p className="ml-16 text-sm font-medium text-gray-400 truncate">{item.name}</p>
              </dt>
              <dd className="ml-16 pb-6 flex items-baseline sm:pb-7">
                <p className="text-2xl font-semibold text-white">{item.stat}</p>
                <div className="absolute bottom-0 inset-x-0 bg-gray-700 px-4 py-4 sm:px-6">
                  <div className="text-sm">
                    <Link
                      to={item.name === 'Reports Generated' ? '/reports' : 
                          item.name === 'Active Scans' ? '/terminal' : 
                          '/reports'}
                      className="font-medium text-blue-400 hover:text-blue-300 transition-colors"
                    >
                      View all
                    </Link>
                  </div>
                </div>
              </dd>
            </div>
          ))}
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
                <dt className="text-sm font-medium text-gray-400">Active Scans</dt>
                <dd className="mt-1 text-sm font-medium text-white">
                  {runningScans.length}
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