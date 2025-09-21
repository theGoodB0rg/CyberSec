import React, { useEffect, useRef, useState } from 'react'
import { Terminal as XTerm } from 'xterm'
import { FitAddon } from 'xterm-addon-fit'
import { PlayIcon, StopIcon, ArrowPathIcon } from '@heroicons/react/24/outline'
import { useScanSocket } from '../hooks/useSocket'
import { useAppStore } from '../store/appStore'
import toast from 'react-hot-toast'
import 'xterm/css/xterm.css'

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
  const [selectedProfile, setSelectedProfile] = useState('basic')
  const [customFlags, setCustomFlags] = useState('')
  const [isScanning, setIsScanning] = useState(false)
  
  const { on, off, startScan: sendStartScan, terminateScan } = useScanSocket()
  const { addScan, updateScan, isConnected } = useAppStore()

  // Initialize terminal
  const lastStartedTargetRef = useRef<string>('')
  const lastStartedOptionsRef = useRef<any>({})
  const lastStartedProfileRef = useRef<string>('basic')

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

  // Socket event handlers
  useEffect(() => {
    if (!on) return

    const handleScanOutput = (data: { scanId: string; output: string }) => {
      if (xtermRef.current) {
        xtermRef.current.write(data.output.replace(/\\n/g, '\\r\\n'))
      }
    }

    const handleScanStarted = (data: { scanId: string }) => {
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
  const handleScanComplete = (data: { scanId: string; result: any }) => {
      setIsScanning(false)
      
      if (xtermRef.current) {
        xtermRef.current.writeln('')
        xtermRef.current.writeln('\\x1b[1;32m✓ Scan completed successfully!\\x1b[0m')
        xtermRef.current.writeln('')
      }

      updateScan(data.scanId, { status: 'completed' })
      toast.success('Scan completed successfully!')
    }

    const handleScanError = (data: { scanId: string; error: string }) => {
      setIsScanning(false)
      
      if (xtermRef.current) {
        xtermRef.current.writeln('')
        xtermRef.current.writeln(`\\x1b[1;31m✗ Scan failed: ${data.error}\\x1b[0m`)
        xtermRef.current.writeln('')
      }

      updateScan(data.scanId, { status: 'failed', error: data.error })
      toast.error(`Scan failed: ${data.error}`)
    }

    on('scan-output', handleScanOutput)
    on('scan-started', handleScanStarted)
    on('scan-completed', handleScanComplete)
    on('scan-error', handleScanError)

    return () => {
    off('scan-output', handleScanOutput)
    off('scan-started', handleScanStarted)
    off('scan-completed', handleScanComplete)
    off('scan-error', handleScanError)
    }
  }, [on, off, updateScan, addScan])

  const startScan = async () => {
    if (!targetUrl.trim()) {
      toast.error('Please enter a target URL')
      return
    }

    if (!isConnected) {
      toast.error('Not connected to server')
      return
    }

    const scanOptions = {
      target: targetUrl.trim(),
      profile: selectedProfile,
      ...(selectedProfile === 'custom' && customFlags.trim() && {
        customFlags: customFlags.trim()
      })
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

  const stopScan = () => {
    if (isScanning) {
      terminateScan()
      toast('Scan termination signal sent.', {
        icon: '🛑',
      })
      setIsScanning(false)
    } else {
      toast.error('No active scan to stop.')
    }
  }

  const clearTerminal = () => {
    if (xtermRef.current) {
      xtermRef.current.clear()
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
      </div>

      {/* Scan Configuration */}
      <div className="bg-gray-800 border-b border-gray-700 px-6 py-4">
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
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
              onChange={(e) => setSelectedProfile(e.target.value)}
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
              onClick={clearTerminal}
              className="flex items-center px-4 py-2 bg-gray-600 text-white rounded-md hover:bg-gray-700 transition-colors"
              disabled={isScanning}
            >
              <ArrowPathIcon className="h-4 w-4 mr-2" />
              Clear
            </button>
          </div>
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
              onChange={(e) => setCustomFlags(e.target.value)}
              placeholder="--level=3 --risk=2 --tamper=space2comment"
              className="w-full px-3 py-2 bg-gray-700 border border-gray-600 rounded-md text-white placeholder-gray-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
              disabled={isScanning}
            />
            <p className="mt-1 text-xs text-gray-400">
              Enter additional SQLMap flags for advanced customization
            </p>
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