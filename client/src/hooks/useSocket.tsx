import React, { createContext, useContext, useEffect, useMemo, useState } from 'react'
import { io, Socket } from 'socket.io-client'
import { useAppStore } from '../store/appStore'
import toast from 'react-hot-toast'

interface SocketContextType {
  socket: Socket | null
  isConnected: boolean
  emit: (event: string, data?: any) => void
  on: (event: string, handler: (...args: any[]) => void) => void
  off: (event: string, handler?: (...args: any[]) => void) => void
}

const SocketContext = createContext<SocketContextType | null>(null)

export const useSocket = (): SocketContextType => {
  const context = useContext(SocketContext)
  if (!context) {
    throw new Error('useSocket must be used within a SocketProvider')
  }
  return context
}

interface SocketProviderProps {
  children: React.ReactNode
}

export const SocketProvider: React.FC<SocketProviderProps> = ({ children }) => {
  const [socket, setSocket] = useState<Socket | null>(null)
  const [isConnected, setIsConnected] = useState(false)
  const { setConnected, upsertScanFromEvent, loadRunningScans, updateScan, addReport, addTerminalOutput, authToken, isAuthenticated } = useAppStore()

  // Derive WS host once
  const WS_HOST = useMemo(() => (
    import.meta.env.VITE_WS_URL || `${window.location.protocol}//${window.location.hostname}:3001`
  ), [])

  useEffect(() => {
    // Build the websocket URL dynamically so it works regardless of which port
    // the Vite dev-server happens to use (5173, 5174, etc.). In production you
    // can still override this via VITE_WS_URL.
    const token = authToken || localStorage.getItem('authToken') || undefined
    const socketInstance = io(WS_HOST, {
      transports: ['websocket', 'polling'],
      timeout: 20000,
      reconnectionAttempts: 5, // try a few times before surfacing an error
      reconnectionDelay: 2000,
      // Let socket.io manage the single instance internally – this avoids the
      // flood of "transport close" errors produced when forceNew continually
      // spins up fresh connections.
      forceNew: false,
      auth: token ? { token } : undefined,
    })

    setSocket(socketInstance)

    // Connection event handlers
    socketInstance.on('connect', () => {
      console.log('Socket connected:', socketInstance.id)
      setIsConnected(true)
      setConnected(true)
      toast.success('Connected to server')
    })

    socketInstance.on('auth-ok', (data) => {
      console.log('Socket auth ok:', data)
      // Optional user feedback
      if (data?.userId) {
        toast.success('Authenticated')
      }
    })

    socketInstance.on('disconnect', (reason) => {
      console.log('Socket disconnected:', reason)
      setIsConnected(false)
      setConnected(false)
      
      if (reason !== 'io client disconnect') {
        toast.error('Disconnected from server')
      }
    })

    socketInstance.on('connect_error', (error) => {
      console.error('Socket connection error:', error)
      setIsConnected(false)
      setConnected(false)
      toast.error('Failed to connect to server')
    })

    // Scan event handlers
    socketInstance.on('scan-started', (data) => {
      console.log('Scan started:', data)
      // Insert/merge into store
      upsertScanFromEvent({ id: data.scanId, target: data.target, scanProfile: data.scanProfile, startTime: data.startTime, status: 'running' })
      // Optionally refresh running scans list shortly after start
      setTimeout(() => { loadRunningScans().catch(()=>{}) }, 500)
      toast.success('Scan started successfully')
    })

    socketInstance.on('scan-output', (data) => {
      const { scanId, output } = data
      addTerminalOutput(output)
      updateScan(scanId, { output: output })
    })

    socketInstance.on('scan-completed', (data) => {
      const { scanId, status } = data
      console.log('Scan completed:', data)
      
      updateScan(scanId, { 
        status: status,
        endTime: new Date().toISOString()
      })
      
      if (status === 'completed') {
        toast.success('Scan completed successfully')
      } else {
        toast.error('Scan failed')
      }
    })

    socketInstance.on('scan-terminated', (data) => {
      const { scanId } = data
      console.log('Scan terminated:', data)
      
      updateScan(scanId, { 
        status: 'terminated',
        endTime: new Date().toISOString()
      })
      
      toast('Scan terminated')
    })

    socketInstance.on('scan-error', (data) => {
      const { scanId } = data || {}
      const msg: string = (data?.message || data?.error || 'Unknown error').toString()
      console.error('Scan error:', data)

      if (scanId) {
        updateScan(scanId, {
          status: 'failed',
          error: msg,
          endTime: new Date().toISOString(),
        })
      }

      // Friendly messages for common race/limit scenarios
      const lower = msg.toLowerCase()
      if (lower.includes('similar scan was just started')) {
        toast('Already running: we prevented a duplicate. Your existing scan is still in progress.', { icon: 'ℹ️' })
      } else if (lower.includes('another scan is being started')) {
        toast('Please wait a moment, a previous start request is still processing.', { icon: '⏳' })
      } else if (lower.includes('concurrent scan limit reached')) {
        toast.error(msg)
      } else {
        toast.error(`Scan error: ${msg}`)
      }
    })

    // Rehydrate running scans on reconnect
    socketInstance.on('scan-still-running', (running: Array<{ scanId: string; target: string; scanProfile?: string; startTime?: string }>) => {
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
          toast(`Restored ${count} running scan${count > 1 ? 's' : ''} after reconnect`, { icon: '🔄' })
        }
      } catch (e) {
        console.warn('Failed to rehydrate running scans:', e)
      }
    })

    // Command execution handlers
    socketInstance.on('command-output', (data) => {
      const { output } = data
      addTerminalOutput(output)
    })

    socketInstance.on('command-error', (data) => {
      const { message } = data
      addTerminalOutput(`Error: ${message}\n`)
      toast.error(`Command error: ${message}`)
    })

    // Cleanup on unmount
    return () => {
      socketInstance.removeAllListeners()
      socketInstance.disconnect()
    }
  // Recreate socket when authToken changes (login/logout) so the server sees
  // updated credentials without a full page refresh.
  }, [WS_HOST, authToken, isAuthenticated, setConnected, upsertScanFromEvent, loadRunningScans, updateScan, addReport, addTerminalOutput])

  const emit = (event: string, data?: any) => {
    if (socket && isConnected) {
      socket.emit(event, data)
    } else {
      console.warn('Socket not connected, cannot emit event:', event)
      toast.error('Not connected to server')
    }
  }

  const on = (event: string, handler: (...args: any[]) => void) => {
    if (socket) {
      socket.on(event, handler)
    }
  }

  const off = (event: string, handler?: (...args: any[]) => void) => {
    if (socket) {
      socket.off(event, handler)
    }
  }

  const contextValue: SocketContextType = {
    socket,
    isConnected,
    emit,
    on,
    off,
  }

  return (
    <SocketContext.Provider value={contextValue}>
      {children}
    </SocketContext.Provider>
  )
}

// Custom hooks for specific socket events
export const useScanSocket = () => {
  const { emit, on, off } = useSocket()

  const startScan = (target: string, options: any, scanProfile: string) => {
    emit('start-sqlmap-scan', { target, options, scanProfile })
  }

  const terminateScan = (scanId?: string) => {
    if (scanId) emit('terminate-scan', { scanId })
    else emit('terminate-scan')
  }

  // Optional: server may handle restart specifically; client can also just call startScan again
  const restartScan = (scanId?: string, payload?: { target?: string; options?: any; scanProfile?: string }) => {
    emit('restart-scan', { scanId, ...payload })
  }

  const executeCommand = (command: string, args: string[] = []) => {
    emit('execute-command', { command, args })
  }

  return {
    startScan,
    terminateScan,
    restartScan,
    executeCommand,
    on,
    off,
  }
}

export const useTerminalSocket = () => {
  const { emit, on, off } = useSocket()
  const { addTerminalOutput, addToHistory } = useAppStore()

  const executeCommand = (command: string, args: string[] = []) => {
    // Add command to history
    addToHistory(command + (args.length > 0 ? ' ' + args.join(' ') : ''))
    
    // Add command to terminal output
    addTerminalOutput(`$ ${command}${args.length > 0 ? ' ' + args.join(' ') : ''}\n`)
    
    // Emit command to server
    emit('execute-command', { command, args })
  }

  const clearTerminal = () => {
    useAppStore.getState().clearTerminalOutput()
  }

  return {
    executeCommand,
    clearTerminal,
    on,
    off,
  }
} 