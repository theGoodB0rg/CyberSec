import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import { 
  DocumentTextIcon,
  EyeIcon,
  ArrowDownTrayIcon,
  MagnifyingGlassIcon,
  ExclamationTriangleIcon,
  CheckCircleIcon,
  ClockIcon,
  CalendarIcon
} from '@heroicons/react/24/outline'
import { useAppStore } from '../store/appStore'
import clsx from 'clsx'
import { format } from 'date-fns'
import toast from 'react-hot-toast'

const FILTER_OPTIONS = [
  { value: 'all', label: 'All Reports' },
  { value: 'completed', label: 'Completed' },
  { value: 'running', label: 'Running' },
  { value: 'failed', label: 'Failed' },
]

interface ReportItem {
  id: string
  scanId: string
  title: string
  target: string
  status: string
  vulnerabilities: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
    riskLevel: string
  }
  scanDuration: number
  created_at: string
  metadata?: {
    scanProfile: string
  }
}

export default function Reports() {
  const [searchTerm, setSearchTerm] = useState('')
  const [statusFilter, setStatusFilter] = useState('all')
  const [reports, setReports] = useState<ReportItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    loadReports()
  }, [])

  const loadReports = async () => {
    try {
      setLoading(true)
      setError(null)
      
      const response = await fetch('/api/reports')
      if (!response.ok) {
        throw new Error('Failed to fetch reports')
      }
      
      const data = await response.json()
      setReports(data)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load reports'
      setError(errorMessage)
      toast.error(errorMessage)
    } finally {
      setLoading(false)
    }
  }

  const downloadReport = async (reportId: string, format: string = 'json') => {
    try {
      const response = await fetch(`/api/reports/${reportId}/export/${format}`)
      if (!response.ok) {
        throw new Error('Failed to download report')
      }
      
      const blob = await response.blob()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `report-${reportId}.${format}`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
      
      toast.success(`Report downloaded as ${format.toUpperCase()}`)
    } catch (err) {
      toast.error('Failed to download report')
    }
  }

  const filteredReports = reports.filter(report => {
    const matchesSearch = report.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         report.title.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesStatus = statusFilter === 'all' || report.status === statusFilter
    return matchesSearch && matchesStatus
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

  const getSeverityColor = (riskLevel: string) => {
    switch (riskLevel?.toLowerCase()) {
      case 'critical':
      case 'high':
        return 'text-red-400 bg-red-400/10'
      case 'medium':
        return 'text-yellow-400 bg-yellow-400/10'
      case 'low':
        return 'text-blue-400 bg-blue-400/10'
      default:
        return 'text-gray-400 bg-gray-400/10'
    }
  }

  if (loading) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-32 w-32 border-b-2 border-blue-500"></div>
          <p className="mt-4 text-gray-400">Loading reports...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="h-full flex items-center justify-center">
        <div className="text-center">
          <ExclamationTriangleIcon className="h-16 w-16 text-red-500 mx-auto mb-4" />
          <h2 className="text-xl font-semibold text-white mb-2">Error Loading Reports</h2>
          <p className="text-gray-400 mb-4">{error}</p>
          <button
            onClick={loadReports}
            className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
          >
            Try Again
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="h-full overflow-auto">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <div className="flex items-center justify-between">
            <div>
              <h1 className="text-3xl font-bold text-white flex items-center">
                <DocumentTextIcon className="h-8 w-8 mr-3 text-blue-400" />
                Scan Reports
              </h1>
              <p className="mt-2 text-gray-400">
                View and manage your security scan reports ({reports.length} total)
              </p>
            </div>
            <button
              onClick={loadReports}
              className="px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors"
            >
              Refresh
            </button>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg border border-gray-700 p-6 mb-6">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <div className="lg:col-span-2">
              <div className="relative">
                <MagnifyingGlassIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 h-5 w-5 text-gray-400" />
                <input
                  type="text"
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  placeholder="Search by target URL or title..."
                  className="w-full pl-10 pr-4 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                />
              </div>
            </div>

            <div>
              <select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
                className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              >
                {FILTER_OPTIONS.map((option) => (
                  <option key={option.value} value={option.value}>
                    {option.label}
                  </option>
                ))}
              </select>
            </div>
          </div>
        </div>

        <div className="bg-gray-800 rounded-lg border border-gray-700">
          <div className="px-6 py-4 border-b border-gray-700">
            <h3 className="text-lg font-medium text-white">
              {filteredReports.length === 0 && reports.length > 0 ? 'No reports match your filters' : 'Recent Reports'}
            </h3>
          </div>
          
          {filteredReports.length === 0 ? (
            <div className="px-6 py-12 text-center">
              <DocumentTextIcon className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <p className="text-gray-400 text-lg">
                {reports.length === 0 ? 'No reports available yet' : 'No reports match your search criteria'}
              </p>
              <p className="text-gray-500 text-sm mt-2">
                {reports.length === 0 ? 'Run some scans to generate reports' : 'Try adjusting your search or filters'}
              </p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-gray-700">
                <thead className="bg-gray-900">
                  <tr>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Target
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Status
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Vulnerabilities
                    </th>
                    <th className="px-6 py-3 text-left text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Created
                    </th>
                    <th className="px-6 py-3 text-right text-xs font-medium text-gray-400 uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-gray-800 divide-y divide-gray-700">
                  {filteredReports.map((report) => (
                    <tr key={report.id} className="hover:bg-gray-700">
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div>
                          <div className="text-sm font-medium text-white truncate max-w-xs">
                            {report.target}
                          </div>
                          <div className="text-xs text-gray-400 truncate max-w-xs">
                            {report.title}
                          </div>
                        </div>
                      </td>
                      
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          {getStatusIcon(report.status)}
                          <span className={clsx(
                            'ml-2 inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium',
                            getStatusColor(report.status)
                          )}>
                            {report.status}
                          </span>
                        </div>
                      </td>
                      
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex items-center">
                          <span className="text-sm font-medium text-white mr-2">
                            {report.vulnerabilities?.total || 0}
                          </span>
                          {report.vulnerabilities?.riskLevel && (
                            <span className={clsx(
                              'inline-flex items-center px-2 py-1 rounded text-xs font-medium',
                              getSeverityColor(report.vulnerabilities.riskLevel)
                            )}>
                              {report.vulnerabilities.riskLevel}
                            </span>
                          )}
                        </div>
                      </td>
                      
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-gray-400">
                        <div className="flex items-center">
                          <CalendarIcon className="h-4 w-4 mr-1 text-gray-400" />
                          {report.created_at && !isNaN(new Date(report.created_at).getTime())
                            ? format(new Date(report.created_at), 'MMM dd, HH:mm')
                            : 'Unknown'}
                        </div>
                      </td>
                      
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div className="flex items-center justify-end space-x-2">
                          <Link
                            to={`/reports/${report.id}`}
                            className="text-blue-400 hover:text-blue-300 transition-colors"
                            title="View Report"
                          >
                            <EyeIcon className="h-4 w-4" />
                          </Link>
                          
                          <div className="relative group">
                            <button 
                              className="text-green-400 hover:text-green-300 transition-colors"
                              title="Download Report"
                            >
                              <ArrowDownTrayIcon className="h-4 w-4" />
                            </button>
                            
                            <div className="absolute right-0 mt-2 w-32 bg-gray-700 border border-gray-600 rounded-md shadow-lg opacity-0 invisible group-hover:opacity-100 group-hover:visible transition-all duration-200 z-10">
                              <div className="py-1">
                                <button
                                  onClick={() => downloadReport(report.id, 'pdf')}
                                  className="block w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-600 hover:text-white"
                                >
                                  Download PDF
                                </button>
                                <button
                                  onClick={() => downloadReport(report.id, 'html')}
                                  className="block w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-600 hover:text-white"
                                >
                                  Download HTML
                                </button>
                                <button
                                  onClick={() => downloadReport(report.id, 'json')}
                                  className="block w-full text-left px-4 py-2 text-sm text-gray-300 hover:bg-gray-600 hover:text-white"
                                >
                                  Download JSON
                                </button>
                              </div>
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
} 