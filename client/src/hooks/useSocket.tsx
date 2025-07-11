import React, { createContext, useContext, useEffect, useState } from 'react'
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
  const { setConnected, addScan, updateScan, addReport, addTerminalOutput } = useAppStore()

  useEffect(() => {
    // Build the websocket URL dynamically so it works regardless of which port
    // the Vite dev-server happens to use (5173, 5174, etc.). In production you
    // can still override this via VITE_WS_URL.
    const WS_HOST = import.meta.env.VITE_WS_URL || `${window.location.protocol}//${window.location.hostname}:3001`

    const socketInstance = io(WS_HOST, {
      transports: ['websocket', 'polling'],
      timeout: 20000,
      reconnectionAttempts: 5, // try a few times before surfacing an error
      reconnectionDelay: 2000,
      // Let socket.io manage the single instance internally – this avoids the
      // flood of "transport close" errors produced when forceNew continually
      // spins up fresh connections.
      forceNew: false,
    })

    setSocket(socketInstance)

    // Connection event handlers
    socketInstance.on('connect', () => {
      console.log('Socket connected:', socketInstance.id)
      setIsConnected(true)
      setConnected(true)
      toast.success('Connected to server')
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
      toast.success('Scan started successfully')
    })

    socketInstance.on('scan-output', (data) => {
      const { scanId, output, type } = data
      addTerminalOutput(output)
      updateScan(scanId, { output: output })
    })

    socketInstance.on('scan-completed', (data) => {
      const { scanId, status, reportId } = data
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
      
      toast.warning('Scan terminated')
    })

    socketInstance.on('scan-error', (data) => {
      const { scanId, message } = data
      console.error('Scan error:', data)
      
      if (scanId) {
        updateScan(scanId, { 
          status: 'failed',
          error: message,
          endTime: new Date().toISOString()
        })
      }
      
      toast.error(`Scan error: ${message}`)
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
  }, [setConnected, addScan, updateScan, addReport, addTerminalOutput])

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

  const terminateScan = () => {
    emit('terminate-scan')
  }

  const executeCommand = (command: string, args: string[] = []) => {
    emit('execute-command', { command, args })
  }

  return {
    startScan,
    terminateScan,
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