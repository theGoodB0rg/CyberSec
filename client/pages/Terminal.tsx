import React, { useEffect, useCallback } from 'react'
import io from 'socket.io-client'
import { toast } from 'react-hot-toast'

const socket = io.connect('http://localhost:3001')

const Terminal: React.FC = () => {
  const handleScanOutput = (data: any) => {
    console.log('Scan output:', data)
  }

  const handleScanComplete = (data: any) => {
    console.log('Scan complete:', data)
  }

  const handleScanError = (data: any) => {
    console.error('Scan error:', data)
    toast.error(`Scan failed: ${data.error}`)
  }

  useEffect(() => {
    socket.on('scan-output', handleScanOutput)
  socket.on('scan-completed', handleScanComplete)
    socket.on('scan-error', handleScanError)

    return () => {
      socket.off('scan-output', handleScanOutput)
  socket.off('scan-completed', handleScanComplete)
      socket.off('scan-error', handleScanError)
    }
  }, [socket])

  const startScan = async () => {
    // ... existing code ...
  }

  return (
    <div>
      {/* ... existing JSX ... */}
    </div>
  )
}

export default Terminal 