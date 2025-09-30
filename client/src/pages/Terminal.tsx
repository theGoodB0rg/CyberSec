import { useEffect, useRef, useState } from 'react'
import { Terminal as XTerm } from 'xterm'
import { FitAddon } from 'xterm-addon-fit'
import { PlayIcon, StopIcon, ArrowPathIcon } from '@heroicons/react/24/outline'
import { useScanSocket } from '../hooks/useSocket'
import { useAppStore } from '../store/appStore'
import { validateFlagsString, wafPreset } from '../utils/sqlmapFlags'
import toast from 'react-hot-toast'
import 'xterm/css/xterm.css'
import { apiFetch, getUserScanSettings } from '../utils/api'

const SCAN_PROFILES = [
  { value: 'basic', label: 'Basic Scan', description: 'Quick vulnerability detection' },
  { value: 'deep', label: 'Deep Scan', description: 'Comprehensive analysis' },
  { value: 'enumeration', label: 'Database Enumeration', description: 'Extract database structure' },
  { value: 'dump', label: 'Data Extraction', description: 'Dump vulnerable data' },
  { value: 'custom', label: 'Custom Scan', description: 'Advanced user options' },
]

export default function Terminal() {
  const terminalRef = useRef<HTMLDivElement>(null)
  const { clearTerminalOutput } = useAppStore()
  const xtermRef = useRef<XTerm | null>(null)
  const fitAddonRef = useRef<FitAddon | null>(null)
  
  const [targetUrl, setTargetUrl] = useState('')
  const selectedProfile = useAppStore(s => s.terminalSelectedProfile)
  const customFlags = useAppStore(s => s.terminalCustomFlags)
  const setTerminalProfile = useAppStore(s => s.setTerminalProfile)
  const setTerminalCustomFlags = useAppStore(s => s.setTerminalCustomFlags)
  const [isScanning, setIsScanning] = useState(false)
  // Auth fields (Phase 1)
  const [authType, setAuthType] = useState<'none'|'cookie'|'login'>('none')
  const [authCookie, setAuthCookie] = useState('')
  const [authHeaderName, setAuthHeaderName] = useState('')
  const [authHeaderValue, setAuthHeaderValue] = useState('')
  const [loginUrl, setLoginUrl] = useState('')
  const [loginUsername, setLoginUsername] = useState('')
  const [loginPassword, setLoginPassword] = useState('')
  const [loginUsernameField, setLoginUsernameField] = useState('username')
  const [loginPasswordField, setLoginPasswordField] = useState('password')
  const [csrfRegex, setCsrfRegex] = useState('')
  const [csrfFieldName, setCsrfFieldName] = useState('')
  const [csrfHeaderName, setCsrfHeaderName] = useState('')
  // Scheduling UI
  const [scheduleAt, setScheduleAt] = useState<string>('')
  const [jobs, setJobs] = useState<any[]>([])
  const [loadingJobs, setLoadingJobs] = useState(false)
  
  const { on, off, startScan: sendStartScan, terminateScan, restartScan: emitRestart } = useScanSocket()
  const { addScan, updateScan, isConnected, upsertScanFromEvent } = useAppStore()

  // Initialize terminal
  const lastStartedTargetRef = useRef<string>('')
  const lastStartedOptionsRef = useRef<any>({})
  const lastStartedProfileRef = useRef<string>('basic')
  const lastScanIdRef = useRef<string>('')

  useEffect(() => {
    if (terminalRef.current && !xtermRef.current) {
      const term = new XTerm({
        cursorBlink: true,
        convertEol: true,
        fontFamily: `'Fira Code', monospace`,
        fontSize: 14,
        theme: {
          background: '#1f2937', // gray-800
          foreground: '#d1d5db', // gray-300
          cursor: '#60a5fa', // blue-400
        },
      })
      const fitAddon = new FitAddon()
      
      xtermRef.current = term
      fitAddonRef.current = fitAddon

      term.loadAddon(fitAddon)
      term.open(terminalRef.current)
      
      // Use a small timeout to ensure the container is sized before fitting
      setTimeout(() => {
        fitAddon.fit()
      }, 1)
      
      term.write('Welcome to the CyberSec SQLMap Terminal!\\r\\n')
      term.write('Use the form above to start a scan.\\r\\n')
    }

    const handleResize = () => {
      fitAddonRef.current?.fit()
    }

    window.addEventListener('resize', handleResize)

    return () => {
      window.removeEventListener('resize', handleResize)
      // Do not dispose of the terminal on unmount to preserve state
    }
  }, [])

  // On mount, preload user's last used or default profile
  useEffect(() => {
    (async () => {
      try {
        const settings = await getUserScanSettings().catch(() => null)
        if (settings) {
          const next = settings.last_used_profile || settings.default_profile || 'basic'
          if (next && next !== selectedProfile) {
            setTerminalProfile(next)
          }
        }
      } catch (_) {}
    })()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  // Socket event handlers
  useEffect(() => {
    if (!on) return

    const handleScanOutput = (data: { scanId: string; output: string }) => {
      if (xtermRef.current) {
        xtermRef.current.write(data.output.replace(/\\n/g, '\\r\\n'))
      }
    }

    const handleScanStarted = (data: { scanId: string }) => {
      lastScanIdRef.current = data.scanId
      const now = new Date().toISOString()
      addScan({
        id: data.scanId,
        target: lastStartedTargetRef.current,
        options: lastStartedOptionsRef.current,
        scanProfile: lastStartedProfileRef.current,
        status: 'running',
        startTime: now,
        output: '',
        createdAt: now,
        updatedAt: now,
      } as any)
    }

  // Server emits 'scan-completed'; keep backward compatibility if older event name was used
  const handleScanComplete = (data: { scanId: string; status?: string; reportId?: string; exit_code?: number }) => {
      setIsScanning(false)

      if (xtermRef.current) {
        xtermRef.current.writeln('')
        if (data.status === 'failed') {
          xtermRef.current.writeln('\x1b[1;31m✗ Scan finished with a failure status. Review the report or logs for details.\x1b[0m')
        } else {
          xtermRef.current.writeln('\x1b[1;32m✓ Scan completed successfully!\x1b[0m')
        }
        if (data.reportId) {
          xtermRef.current.writeln(`\x1b[36mReport ID: ${data.reportId}\x1b[0m`)
        }
        xtermRef.current.writeln('')
      }

      if (data.scanId) {
        updateScan(data.scanId, { status: (data.status as any) || 'completed' })
      }
    }

    const handleScanError = (data: { scanId?: string; message?: string; error?: string }) => {
      setIsScanning(false)

      const msg = (data?.message || data?.error || 'Unknown error').toString()
      if (xtermRef.current) {
        xtermRef.current.writeln('')
        xtermRef.current.writeln(`\\x1b[1;31m✗ Scan failed: ${msg}\\x1b[0m`)
        xtermRef.current.writeln('')
      }

      if (data?.scanId) {
        updateScan(data.scanId, { status: 'failed', error: msg })
      }

      const lower = msg.toLowerCase()
      if (lower.includes('similar scan was just started')) {
        toast('Duplicate prevented: an identical scan is already running.', { icon: 'ℹ️' })
      } else if (lower.includes('another scan is being started')) {
        toast('Please wait a moment, your previous start request is still processing.', { icon: '⏳' })
      } else if (lower.includes('concurrent scan limit reached')) {
        toast.error(msg)
      } else {
        toast.error(`Scan failed: ${msg}`)
      }
    }

    on('scan-output', handleScanOutput)
    on('scan-started', handleScanStarted)
    on('scan-completed', handleScanComplete)
    on('scan-error', handleScanError)
    on('scan-terminated', () => {
      setIsScanning(false)
      if (xtermRef.current) {
        xtermRef.current.writeln('')
        xtermRef.current.writeln('\x1b[1;33m! Scan was terminated by user or server\x1b[0m')
        xtermRef.current.writeln('')
      }
      toast('Scan terminated', { icon: '🛑' })
    })

    // Rehydrate any active scans if the server reports them on reconnect
    on('scan-still-running', (running: Array<{ scanId: string; target: string; scanProfile?: string; startTime?: string }>) => {
      try {
        if (Array.isArray(running) && running.length > 0) {
          running.forEach((r) => {
            upsertScanFromEvent({
              id: r.scanId,
              target: r.target,
              scanProfile: r.scanProfile || 'basic',
              startTime: r.startTime || new Date().toISOString(),
              status: 'running',
            } as any)
          })
          const count = running.length
          if (xtermRef.current) {
            xtermRef.current.writeln('')
            xtermRef.current.writeln(`\\x1b[1;36m↻ Restored ${count} running scan${count > 1 ? 's' : ''} after reconnect\\x1b[0m`)
            xtermRef.current.writeln('')
          }
          toast(`Restored ${count} running scan${count > 1 ? 's' : ''}`, { icon: '🔄' })
        }
      } catch (e) {
        console.warn('Failed to handle scan-still-running:', e)
      }
    })

    return () => {
    off('scan-output', handleScanOutput)
    off('scan-started', handleScanStarted)
    off('scan-completed', handleScanComplete)
    off('scan-error', handleScanError)
    off('scan-terminated')
    off('scan-still-running')
    }
  }, [on, off, updateScan, addScan, upsertScanFromEvent])

  const startScan = async () => {
    if (!targetUrl.trim()) {
      toast.error('Please enter a target URL')
      return
    }

    if (!isConnected) {
      toast.error('Not connected to server')
      return
    }

    const scanOptions: any = {
      target: targetUrl.trim(),
      profile: selectedProfile,
      ...(selectedProfile === 'custom' && customFlags.trim() && {
        customFlags: customFlags.trim()
      })
    }

    // Attach auth block
    if (authType === 'cookie') {
      const headers: Record<string,string> = {}
      if (authHeaderName && authHeaderValue) headers[authHeaderName] = authHeaderValue
      scanOptions.auth = { type: 'cookie', cookie: authCookie || undefined, headers }
      // Also pass direct fields for convenience
      if (authCookie) scanOptions.cookie = authCookie
      if (authHeaderName && authHeaderValue) scanOptions.headers = headers
    } else if (authType === 'login') {
      scanOptions.auth = {
        type: 'login',
        loginUrl,
        method: 'POST',
        username: loginUsername,
        password: loginPassword,
        usernameField: loginUsernameField || 'username',
        passwordField: loginPasswordField || 'password',
        csrf: {
          regex: csrfRegex || undefined,
          fieldName: csrfFieldName || undefined,
          headerName: csrfHeaderName || undefined,
          tokenUrl: loginUrl || undefined
        }
      }
    }

    try {
      setIsScanning(true)
      lastStartedTargetRef.current = targetUrl.trim()
      lastStartedProfileRef.current = selectedProfile
      lastStartedOptionsRef.current = scanOptions
      if (xtermRef.current) {
        xtermRef.current.writeln('')
        xtermRef.current.writeln(`\\x1b[1;36m→ Starting ${selectedProfile} scan for: ${targetUrl}\\x1b[0m`)
        xtermRef.current.writeln('')
      }

      // Emit scan start event via socket
      sendStartScan(targetUrl, scanOptions, selectedProfile)
      
    } catch (error) {
      setIsScanning(false)
      toast.error('Failed to start scan')
      console.error('Scan start error:', error)
    }
  }

  const scheduleScan = async () => {
    if (!targetUrl.trim()) { toast.error('Please enter a target URL'); return }
    try {
      const payload: any = { target: targetUrl.trim(), scanProfile: selectedProfile }
      // Reuse auth block from startScan
      if (authType === 'cookie') {
        const headers: Record<string,string> = {}
        if (authHeaderName && authHeaderValue) headers[authHeaderName] = authHeaderValue
        payload.options = { auth: { type: 'cookie', cookie: authCookie || undefined, headers }, cookie: authCookie || undefined, headers: headers }
      } else if (authType === 'login') {
        payload.options = { auth: { type: 'login', loginUrl, method: 'POST', username: loginUsername, password: loginPassword, usernameField: loginUsernameField || 'username', passwordField: loginPasswordField || 'password', csrf: { regex: csrfRegex || undefined, fieldName: csrfFieldName || undefined, headerName: csrfHeaderName || undefined, tokenUrl: loginUrl || undefined } } }
      }
      if (scheduleAt) payload.runAt = new Date(scheduleAt).toISOString()
      const res = await apiFetch<{ jobId: string, status: string, runAt: string }>(`/api/scans/schedule`, { method: 'POST', body: JSON.stringify(payload) })
      toast.success(`Scheduled (job ${res.jobId}) for ${new Date(res.runAt).toLocaleString()}`)
      setScheduleAt('')
      await refreshJobs()
    } catch (e:any) {
      toast.error(e.message || 'Failed to schedule scan')
    }
  }

  const refreshJobs = async () => {
    try {
      setLoadingJobs(true)
      const data = await apiFetch<any[]>(`/api/queue`)
      setJobs(data)
    } catch (e:any) {
      toast.error(e.message || 'Failed to load queue')
    } finally {
      setLoadingJobs(false)
    }
  }

  const cancelJob = async (id: string) => {
    try {
      await apiFetch(`/api/jobs/${encodeURIComponent(id)}`, { method: 'DELETE' })
      toast('Job canceled', { icon: '🗑️' })
      await refreshJobs()
    } catch (e:any) {
      toast.error(e.message || 'Failed to cancel job')
    }
  }

  const stopScan = () => {
    if (isScanning) {
      terminateScan(lastScanIdRef.current)
      toast('Scan termination signal sent.', {
        icon: '🛑',
      })
      setIsScanning(false)
    } else {
      toast.error('No active scan to stop.')
    }
  }

  const restartScan = () => {
    const lastTarget = lastStartedTargetRef.current?.trim()
    const lastProfile = lastStartedProfileRef.current
    const lastOptions = lastStartedOptionsRef.current

    if (!lastTarget) {
      toast.error('No previous scan parameters to restart')
      return
    }

    // If a scan is currently running, send terminate first
    if (isScanning) {
      terminateScan(lastScanIdRef.current)
      if (xtermRef.current) {
        xtermRef.current.writeln('')
        xtermRef.current.writeln('\x1b[1;33m! Terminating current scan before restart...\x1b[0m')
      }
      // Small delay to allow server to process termination
      setTimeout(() => {
        setIsScanning(true)
        if (xtermRef.current) {
          xtermRef.current.writeln('')
          xtermRef.current.writeln(`\x1b[1;36m↻ Restarting ${lastProfile} scan for: ${lastTarget}\x1b[0m`)
          xtermRef.current.writeln('')
        }
        sendStartScan(lastTarget, lastOptions, lastProfile)
      }, 600)
      return
    }

    // No active scan; just start again with last params
    setIsScanning(true)
    if (xtermRef.current) {
      xtermRef.current.writeln('')
      xtermRef.current.writeln(`\x1b[1;36m↻ Restarting ${lastProfile} scan for: ${lastTarget}\x1b[0m`)
      xtermRef.current.writeln('')
    }
    // Prefer server-side restart endpoint if we had a prior scanId
    if (lastScanIdRef.current) {
      emitRestart(lastScanIdRef.current, { target: lastTarget, options: lastOptions, scanProfile: lastProfile })
    } else {
      sendStartScan(lastTarget, lastOptions, lastProfile)
    }
  }

  const clearTerminal = () => {
    if (xtermRef.current) {
      xtermRef.current.clear()
      xtermRef.current.writeln('\x1b[90m[terminal cleared]\x1b[0m')
    }
    clearTerminalOutput()
  }

  return (
    <div className="h-full flex flex-col bg-gray-900">
      {/* Header */}
      <div className="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <h1 className="text-2xl font-bold text-white flex items-center">
          <PlayIcon className="h-6 w-6 mr-3 text-green-400" />
          SQLMap Terminal
        </h1>
        <p className="mt-1 text-gray-400">
          Interactive terminal for SQL injection testing
        </p>
          {/* Target URL */}
          <div className="lg:col-span-2">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Target URL
            </label>
            <input
              type="url"
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com/vulnerable.php?id=1"
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              disabled={isScanning}
            />
          </div>

          {/* Scan Profile */}
          <div>
            <label htmlFor="scanProfile" className="block text-sm font-medium text-gray-300 mb-2">
              Scan Profile
            </label>
            <select
              id="scanProfile"
              aria-label="Scan Profile"
              value={selectedProfile}
              onChange={(e) => setTerminalProfile(e.target.value)}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              disabled={isScanning}
            >
              {SCAN_PROFILES.map((profile) => (
                <option key={profile.value} value={profile.value}>
                  {profile.label}
                </option>
              ))}
            </select>
          </div>

          {/* Actions */}
          <div className="flex items-end space-x-2">
            {!isScanning ? (
              <button
                onClick={startScan}
                disabled={!isConnected || !targetUrl.trim()}
                className="flex items-center px-4 py-2 bg-green-600 text-white rounded-md hover:bg-green-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
              >
                <PlayIcon className="h-4 w-4 mr-2" />
                Start Scan
              </button>
            ) : (
              <button
                onClick={stopScan}
                className="flex items-center px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
              >
                <StopIcon className="h-4 w-4 mr-2" />
                Stop Scan
              </button>
            )}
            <button
              onClick={restartScan}
              className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              disabled={!isConnected || !lastStartedTargetRef.current}
              title={lastStartedTargetRef.current ? `Restart last scan for ${lastStartedTargetRef.current}` : 'Start a scan first to enable restart'}
            >
              <ArrowPathIcon className="h-4 w-4 mr-2" />
              Restart
            </button>
            
            <button
              onClick={clearTerminal}
              className="flex items-center px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 transition-colors"
              disabled={isScanning}
            >
              <ArrowPathIcon className="h-4 w-4 mr-2" />
              Clear
            </button>
            {/* Schedule */}
            <div className="flex items-center space-x-2 ml-4">
              <label htmlFor="scheduleAt" className="sr-only">Schedule At</label>
              <input
                id="scheduleAt"
                type="datetime-local"
                value={scheduleAt}
                onChange={(e)=>setScheduleAt(e.target.value)}
                className="px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500"
                aria-label="Schedule At"
              />
              <button onClick={scheduleScan} className="px-3 py-2 bg-blue-600 text-white rounded-md hover:bg-blue-700">Schedule</button>
              <button onClick={refreshJobs} className="px-3 py-2 bg-gray-700 text-white rounded-md hover:bg-gray-600">Queue</button>
            </div>
          </div>
        </div>

        {/* Auth Section */}
        <div className="mt-4 grid grid-cols-1 lg:grid-cols-4 gap-4">
          <div>
            <label htmlFor="authMode" className="block text-sm font-medium text-gray-300 mb-2">Auth Mode</label>
            <select
              id="authMode"
              value={authType}
              onChange={(e) => setAuthType(e.target.value as any)}
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              disabled={isScanning}
            >
              <option value="none">None</option>
              <option value="cookie">Cookie/Header</option>
              <option value="login">Login Flow</option>
            </select>
          </div>
          {authType === 'cookie' && (
            <>
              <div className="lg:col-span-1">
                <label className="block text-sm font-medium text-gray-300 mb-2">Cookie</label>
                <input type="text" value={authCookie} onChange={(e)=>setAuthCookie(e.target.value)} placeholder="sessionid=abc; other=..."
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Header Name</label>
                <input type="text" value={authHeaderName} onChange={(e)=>setAuthHeaderName(e.target.value)} placeholder="X-Auth-Token"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Header Value</label>
                <input type="text" value={authHeaderValue} onChange={(e)=>setAuthHeaderValue(e.target.value)} placeholder="..."
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
            </>
          )}
          {authType === 'login' && (
            <>
              <div className="lg:col-span-2">
                <label className="block text-sm font-medium text-gray-300 mb-2">Login URL</label>
                <input type="url" value={loginUrl} onChange={(e)=>setLoginUrl(e.target.value)} placeholder="https://example.com/login"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
              <div>
                <label htmlFor="loginUsername" className="block text-sm font-medium text-gray-300 mb-2">Username</label>
                <input id="loginUsername" type="text" value={loginUsername} onChange={(e)=>setLoginUsername(e.target.value)} placeholder="username"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
              <div>
                <label htmlFor="loginPassword" className="block text-sm font-medium text-gray-300 mb-2">Password</label>
                <input id="loginPassword" type="password" value={loginPassword} onChange={(e)=>setLoginPassword(e.target.value)} placeholder="password"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Username Field</label>
                <input type="text" value={loginUsernameField} onChange={(e)=>setLoginUsernameField(e.target.value)} placeholder="username"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">Password Field</label>
                <input type="text" value={loginPasswordField} onChange={(e)=>setLoginPasswordField(e.target.value)} placeholder="password"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">CSRF Regex (group 1)</label>
                <input type="text" value={csrfRegex} onChange={(e)=>setCsrfRegex(e.target.value)} placeholder='name="_token" value="([^"]+)"'
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">CSRF Field Name</label>
                <input type="text" value={csrfFieldName} onChange={(e)=>setCsrfFieldName(e.target.value)} placeholder="_token"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">CSRF Header Name (optional)</label>
                <input type="text" value={csrfHeaderName} onChange={(e)=>setCsrfHeaderName(e.target.value)} placeholder="X-CSRF-Token"
                  className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent" />
              </div>
            </>
          )}
        </div>

        {/* Queue Panel */}
        <div className="mt-4 px-6">
          <div className="flex items-center justify-between">
            <h2 className="text-white font-semibold">Queue</h2>
            <button onClick={refreshJobs} className="text-sm px-2 py-1 bg-gray-700 text-white rounded">Refresh</button>
          </div>
          {loadingJobs ? (
            <p className="text-gray-400 mt-2">Loading…</p>
          ) : (
            <div className="mt-2 overflow-x-auto">
              <table className="min-w-full text-sm text-gray-300">
                <thead>
                  <tr className="text-left">
                    <th className="py-2 pr-4">Job</th>
                    <th className="py-2 pr-4">Status</th>
                    <th className="py-2 pr-4">Error</th>
                    <th className="py-2 pr-4">Run At</th>
                    <th className="py-2 pr-4">Retries</th>
                    <th className="py-2 pr-4">Target</th>
                    <th className="py-2 pr-4">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.map(j => (
                    <tr key={j.id} className="border-t border-gray-700">
                      <td className="py-2 pr-4 font-mono text-xs">{j.id}</td>
                      <td className="py-2 pr-4">
                        <div className="flex items-center gap-2">
                          <span>{j.status}</span>
                          {j.created_by_admin ? <span className="text-[10px] px-1 py-0.5 bg-blue-800 text-blue-100 rounded">admin</span> : null}
                        </div>
                      </td>
                      <td className="py-2 pr-4 max-w-[260px] truncate" title={j.last_error || ''}>{j.last_error || ''}</td>
                      <td className="py-2 pr-4">{new Date(j.run_at).toLocaleString()}</td>
                      <td className="py-2 pr-4">{j.retries}/{j.max_retries}</td>
                      <td className="py-2 pr-4 break-all">{j.target}</td>
                      <td className="py-2 pr-4">
                        {(j.status === 'scheduled' || j.status === 'retrying') && (
                          <button onClick={()=>cancelJob(j.id)} className="px-2 py-1 bg-red-700 text-white rounded">Cancel</button>
                        )}
                      </td>
                    </tr>
                  ))}
                  {jobs.length === 0 && (
                    <tr><td colSpan={7} className="py-3 text-gray-500">No queued jobs</td></tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Custom Flags (only for custom profile) */}
        {selectedProfile === 'custom' && (
          <div className="mt-4">
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Custom SQLMap Flags
            </label>
            <input
              type="text"
              value={customFlags}
              onChange={(e) => setTerminalCustomFlags(e.target.value)}
              placeholder="--level=3 --risk=2 --tamper=space2comment"
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              disabled={isScanning}
            />
            <p className="mt-1 text-xs text-gray-400">
              Enter additional SQLMap flags for advanced customization
            </p>
            <div className="flex gap-2 items-center">
              <details className="relative">
                <summary className="px-2 py-2 bg-gray-700 border border-gray-600 rounded-md text-white cursor-pointer select-none text-xs">WAF presets</summary>
                <div className="absolute right-0 mt-1 w-56 bg-gray-800 border border-gray-700 rounded shadow-lg z-10">
                  <button type="button" className="block w-full text-left px-3 py-2 text-sm hover:bg-gray-700" onClick={() => { setTerminalProfile('custom'); setTerminalCustomFlags(wafPreset('light')) }}>Light</button>
                  <button type="button" className="block w-full text-left px-3 py-2 text-sm hover:bg-gray-700" onClick={() => { setTerminalProfile('custom'); setTerminalCustomFlags(wafPreset('standard')) }}>Standard</button>
                  <button type="button" className="block w-full text-left px-3 py-2 text-sm hover:bg-gray-700" onClick={() => { setTerminalProfile('custom'); setTerminalCustomFlags(wafPreset('strict')) }}>Strict</button>
                </div>
              </details>
            </div>
            {!validateFlagsString(customFlags).ok && (
              <p className="mt-1 text-xs text-yellow-400">
                Warning: disallowed flags detected: {validateFlagsString(customFlags).disallowed.join(', ')}
              </p>
            )}
          </div>
        )}

        {/* Profile Description */}
        <div className="mt-3">
          <p className="text-sm text-gray-400">
            <span className="font-medium">
              {SCAN_PROFILES.find(p => p.value === selectedProfile)?.label}:
            </span>{' '}
            {SCAN_PROFILES.find(p => p.value === selectedProfile)?.description}
          </p>
        </div>

      {/* Terminal */}
      <div className="flex-1 bg-gray-900 p-4">
        <div className="h-full bg-[#0d1117] rounded-lg border border-gray-700 overflow-hidden">
          <div ref={terminalRef} className="h-full w-full p-4" />
        </div>
      </div>

      {/* Status Bar */}
      <div className="bg-gray-800 border-t border-gray-700 px-6 py-2">
        <div className="flex justify-between items-center text-sm">
          <div className="flex items-center space-x-4">
            <div className="flex items-center">
              <div className={`w-2 h-2 rounded-full mr-2 ${
                isConnected ? 'bg-green-400' : 'bg-red-400'
              }`}></div>
              <span className="text-gray-400">
                {isConnected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
            
            {isScanning && (
              <div className="flex items-center">
                <div className="w-2 h-2 bg-yellow-400 rounded-full mr-2 animate-pulse"></div>
                <span className="text-yellow-400">Scanning...</span>
              </div>
            )}
          </div>
          
          <div className="text-gray-400">
            Press Ctrl+C to interrupt • Use the controls above to manage scans
          </div>
        </div>
      </div>
    </div>
  )
} 