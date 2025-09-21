import { create } from 'zustand'
import { devtools, persist } from 'zustand/middleware'
import { immer } from 'zustand/middleware/immer'
import { apiFetch } from '@/utils/api'

// Types
export interface Vulnerability {
  id: string
  type: string
  severity: 'Critical' | 'High' | 'Medium' | 'Low'
  cvss: number
  description: string
  impact: string
  remediation: string[]
  evidence: Array<{
    line: number
    content: string
  }>
  discoveredAt: string
}

export interface Report {
  id: string
  scanId: string
  title: string
  target: string
  command: string
  vulnerabilities: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
    riskScore: number
    riskLevel: string
    findings: Vulnerability[]
  }
  extractedData: {
    databases: string[]
    tables: string[]
    columns: string[]
    users: string[]
    systemInfo: Record<string, string>
  }
  recommendations: Array<{
    category: string
    priority: string
    title: string
    description: string
    implementation: string[]
    effort: string
    impact: string
  }>
  scanDuration: number
  status: string
  metadata: {
    generatedAt: string
    scanProfile: string
    reportVersion: string
    scanner: string
  }
}

export interface Scan {
  id: string
  target: string
  options: Record<string, any>
  scanProfile: string
  status: 'pending' | 'running' | 'completed' | 'failed' | 'terminated'
  startTime: string
  endTime?: string
  exitCode?: number
  error?: string
  output: string
  createdAt: string
  updatedAt: string
}

export interface ScanProfile {
  id: string
  name: string
  description: string
  flags: string[]
}

export interface Settings {
  theme: 'dark' | 'light' | 'auto'
  terminalFontSize: number
  terminalTheme: string
  notifications: boolean
  autoSave: boolean
  maxConcurrentScans: number
  defaultScanProfile: string
  apiTimeout: number
}

interface AppState {
  // Connection state
  isConnected: boolean
  connectionError: string | null
  // Auth
  authToken: string | null
  currentUser: { id: string; email: string; role: string } | null
  isAuthenticated: boolean
  
  // Application state
  isLoading: boolean
  
  // Scans
  scans: Scan[]
  currentScan: Scan | null
  scanProfiles: ScanProfile[]
  
  // Reports
  reports: Report[]
  currentReport: Report | null
  
  // Settings
  settings: Settings
  
  // Terminal
  terminalHistory: string[]
  terminalOutput: string
  
  // UI state
  sidebarCollapsed: boolean
  activeTerminalSession: string | null
  
  // Computed properties
  runningScans: Scan[]
}

interface AppActions {
  // Initialization
  initialize: () => Promise<void>
  // Auth
  setAuthToken: (token: string | null) => void
  fetchMe: () => Promise<void>
  login: (email: string, password: string) => Promise<void>
  register: (email: string, password: string) => Promise<void>
  logout: () => void
  
  // Connection management
  setConnected: (connected: boolean) => void
  setConnectionError: (error: string | null) => void
  
  // Scan management
  addScan: (scan: Scan) => void
  updateScan: (scanId: string, updates: Partial<Scan>) => void
  removeScan: (scanId: string) => void
  setCurrentScan: (scan: Scan | null) => void
  loadScans: () => Promise<void>
  
  // Report management
  addReport: (report: Report) => void
  updateReport: (reportId: string, updates: Partial<Report>) => void
  removeReport: (reportId: string) => void
  setCurrentReport: (report: Report | null) => void
  loadReports: () => Promise<void>
  
  // Settings management
  updateSettings: (updates: Partial<Settings>) => void
  resetSettings: () => void
  
  // Terminal management
  addTerminalOutput: (output: string) => void
  clearTerminalOutput: () => void
  addToHistory: (command: string) => void
  clearHistory: () => void
  
  // UI state management
  toggleSidebar: () => void
  setSidebarCollapsed: (collapsed: boolean) => void
  setActiveTerminalSession: (sessionId: string | null) => void
  
  // Loading state
  setLoading: (loading: boolean) => void
}

const defaultSettings: Settings = {
  theme: 'dark',
  terminalFontSize: 14,
  terminalTheme: 'default',
  notifications: true,
  autoSave: true,
  maxConcurrentScans: 3,
  defaultScanProfile: 'basic',
  apiTimeout: 30000,
}

const defaultScanProfiles: ScanProfile[] = [
  {
    id: 'basic',
    name: 'Basic SQL Injection Scan',
    description: 'Quick scan for common SQL injection vulnerabilities',
    flags: ['--batch', '--random-agent', '--level=1', '--risk=1'],
  },
  {
    id: 'deep',
    name: 'Deep Scan',
    description: 'Comprehensive scan with higher risk and level',
    flags: ['--batch', '--random-agent', '--level=3', '--risk=2', '--threads=2'],
  },
  {
    id: 'aggressive',
    name: 'Aggressive Scan',
    description: 'Maximum detection with highest risk and level settings',
    flags: ['--batch', '--random-agent', '--level=5', '--risk=3', '--threads=1', '--forms', '--crawl=2', '--tamper=space2comment,charencode'],
  },
  {
    id: 'enumeration',
    name: 'Database Enumeration',
    description: 'Enumerate database structure and contents',
    flags: ['--batch', '--random-agent', '--dbs', '--tables', '--columns'],
  },
  {
    id: 'dump',
    name: 'Data Extraction',
    description: 'Extract data from vulnerable parameters',
    flags: ['--batch', '--random-agent', '--dump', '--exclude-sysdbs'],
  },
  {
    id: 'custom',
    name: 'Custom Scan',
    description: 'User-defined custom parameters',
    flags: [],
  },
]

export const useAppStore = create<AppState & AppActions>()(
  devtools(
    persist(
      immer((set, get) => ({
        // Initial state
        isConnected: false,
        connectionError: null,
  authToken: null,
  currentUser: null,
  isAuthenticated: false,
        isLoading: false,
        scans: [],
        currentScan: null,
        scanProfiles: defaultScanProfiles,
        reports: [],
        currentReport: null,
        settings: defaultSettings,
        terminalHistory: [],
        terminalOutput: '',
        sidebarCollapsed: false,
        activeTerminalSession: null,

        // Computed properties
        get runningScans() {
          return get().scans.filter(scan => scan.status === 'running')
        },

        // Actions
        initialize: async () => {
          set((state) => {
            state.isLoading = true
          })

          try {
            // Check server health
            const response = await fetch('/api/health')
            if (response.ok) {
              set((state) => {
                state.isConnected = true
                state.connectionError = null
              })
            } else {
              throw new Error('Server health check failed')
            }

            // Restore token from localStorage if present
            const token = localStorage.getItem('authToken')
            if (token) {
              set((state) => {
                state.authToken = token
                state.isAuthenticated = true
              })
              await get().fetchMe().catch(() => set((s) => { s.isAuthenticated = false; s.authToken = null; s.currentUser = null }))
            }

            // Load initial data
            await get().loadReports()
            await get().loadScans()

          } catch (error) {
            set((state) => {
              state.isConnected = false
              state.connectionError = error instanceof Error ? error.message : 'Unknown error'
            })
          } finally {
            set((state) => {
              state.isLoading = false
            })
          }
        },

        setConnected: (connected) => {
          set((state) => {
            state.isConnected = connected
            if (connected) {
              state.connectionError = null
            }
          })
        },

        setConnectionError: (error) => {
          set((state) => {
            state.connectionError = error
            if (error) {
              state.isConnected = false
            }
          })
        },

        setAuthToken: (token) => {
          set((state) => {
            state.authToken = token
            state.isAuthenticated = !!token
            if (token) localStorage.setItem('authToken', token)
            else localStorage.removeItem('authToken')
          })
        },

        fetchMe: async () => {
          const me = await apiFetch<{ id: string; email: string; role: string }>('/api/auth/me')
          set((state) => {
            state.currentUser = me
            state.isAuthenticated = true
          })
        },

        login: async (email, password) => {
          const res = await apiFetch<{ token: string; user: { id: string; email: string; role: string } }>(
            '/api/auth/login',
            { method: 'POST', body: JSON.stringify({ email, password }) }
          )
          set((state) => {
            state.authToken = res.token
            state.currentUser = res.user
            state.isAuthenticated = true
          })
          localStorage.setItem('authToken', res.token)
        },

        register: async (email, password) => {
          const res = await apiFetch<{ token: string; user: { id: string; email: string; role: string } }>(
            '/api/auth/register',
            { method: 'POST', body: JSON.stringify({ email, password }) }
          )
          set((state) => {
            state.authToken = res.token
            state.currentUser = res.user
            state.isAuthenticated = true
          })
          localStorage.setItem('authToken', res.token)
        },

        logout: () => {
          set((state) => {
            state.authToken = null
            state.currentUser = null
            state.isAuthenticated = false
          })
          localStorage.removeItem('authToken')
        },

        addScan: (scan) => {
          set((state) => {
            state.scans.unshift(scan)
          })
        },

        updateScan: (scanId, updates) => {
          set((state) => {
            const index = state.scans.findIndex(s => s.id === scanId)
            if (index !== -1) {
              Object.assign(state.scans[index], updates)
            }
            if (state.currentScan?.id === scanId) {
              Object.assign(state.currentScan, updates)
            }
          })
        },

        removeScan: (scanId) => {
          set((state) => {
            state.scans = state.scans.filter(s => s.id !== scanId)
            if (state.currentScan?.id === scanId) {
              state.currentScan = null
            }
          })
        },

        setCurrentScan: (scan) => {
          set((state) => {
            state.currentScan = scan
          })
        },

        loadScans: async () => {
          try {
            const scans = await apiFetch<Scan[]>('/api/scans')
            set((state) => { state.scans = scans })
          } catch (error) {
            console.error('Failed to load scans:', error)
          }
        },

        addReport: (report) => {
          set((state) => {
            state.reports.unshift(report)
          })
        },

        updateReport: (reportId, updates) => {
          set((state) => {
            const index = state.reports.findIndex(r => r.id === reportId)
            if (index !== -1) {
              Object.assign(state.reports[index], updates)
            }
            if (state.currentReport?.id === reportId) {
              Object.assign(state.currentReport, updates)
            }
          })
        },

        removeReport: (reportId) => {
          set((state) => {
            state.reports = state.reports.filter(r => r.id !== reportId)
            if (state.currentReport?.id === reportId) {
              state.currentReport = null
            }
          })
        },

        setCurrentReport: (report) => {
          set((state) => {
            state.currentReport = report
          })
        },

        loadReports: async () => {
          try {
            const reports = await apiFetch<Report[]>('/api/reports')
            set((state) => { state.reports = reports })
          } catch (error) {
            console.error('Failed to load reports:', error)
          }
        },

        updateSettings: (updates) => {
          set((state) => {
            Object.assign(state.settings, updates)
          })
        },

        resetSettings: () => {
          set((state) => {
            state.settings = { ...defaultSettings }
          })
        },

        addTerminalOutput: (output) => {
          set((state) => {
            state.terminalOutput += output
          })
        },

        clearTerminalOutput: () => {
          set((state) => {
            state.terminalOutput = ''
          })
        },

        addToHistory: (command) => {
          set((state) => {
            state.terminalHistory.push(command)
            // Keep only last 100 commands
            if (state.terminalHistory.length > 100) {
              state.terminalHistory = state.terminalHistory.slice(-100)
            }
          })
        },

        clearHistory: () => {
          set((state) => {
            state.terminalHistory = []
          })
        },

        toggleSidebar: () => {
          set((state) => {
            state.sidebarCollapsed = !state.sidebarCollapsed
          })
        },

        setSidebarCollapsed: (collapsed) => {
          set((state) => {
            state.sidebarCollapsed = collapsed
          })
        },

        setActiveTerminalSession: (sessionId) => {
          set((state) => {
            state.activeTerminalSession = sessionId
          })
        },

        setLoading: (loading) => {
          set((state) => {
            state.isLoading = loading
          })
        },
      })),
      {
        name: 'cybersecurity-app-store',
        partialize: (state) => ({
          settings: state.settings,
          terminalHistory: state.terminalHistory,
          sidebarCollapsed: state.sidebarCollapsed,
          authToken: state.authToken,
          currentUser: state.currentUser,
        }),
      }
    ),
    {
      name: 'cybersecurity-app',
    }
  )
) 