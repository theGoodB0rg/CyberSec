import { useEffect, useState } from 'react'
import { Routes, Route, Navigate, useNavigate } from 'react-router-dom'
import { Toaster, toast } from 'react-hot-toast'
import { useAppStore } from './store/appStore'
import { SocketProvider } from './hooks/useSocket'

// Components
import Layout from './components/Layout'
import Dashboard from './pages/Dashboard'
import Terminal from './pages/Terminal'
import Reports from './pages/Reports'
import Settings from './pages/Settings'
import ReportDetails from './pages/ReportDetails'
import LoadingScreen from './components/LoadingScreen'
import Login from './pages/Login'
import Targets from './pages/Targets'
import Usage from './pages/Usage'

function RequireAuth({ children }: { children: JSX.Element }) {
  const { isAuthenticated } = useAppStore()
  if (!isAuthenticated) {
    return <Navigate to="/login" replace />
  }
  return children
}

function App() {
  const { isConnected, connectionError, initialize } = useAppStore()
  const [isLoading, setIsLoading] = useState(true)
  const navigate = useNavigate()
  const logout = useAppStore(s => s.logout)

  useEffect(() => {
    // Initialize the application
    const initApp = async () => {
      try {
        await initialize()
      } catch (error) {
        console.error('Failed to initialize app:', error)
      } finally {
        setIsLoading(false)
      }
    }

    initApp()
  }, [initialize])

  // Global unauthorized handler: on 401/403, log the user out and send them to login
  useEffect(() => {
    const onUnauthorized = () => {
      logout()
      toast.error('Your session has expired. Please sign in again.')
      navigate('/login', { replace: true })
    }
    window.addEventListener('app:unauthorized', onUnauthorized)
    return () => window.removeEventListener('app:unauthorized', onUnauthorized)
  }, [logout, navigate])

  if (isLoading) {
    return <LoadingScreen />
  }

  if (connectionError) {
    return (
      <div className="min-h-screen bg-gray-900 flex items-center justify-center">
        <div className="text-center max-w-md mx-auto p-6">
          <div className="text-red-500 text-6xl mb-4">🔌</div>
          <h1 className="text-2xl font-bold text-white mb-4">
            Connection Error
          </h1>
          <p className="text-gray-400 mb-6">
            Unable to connect to the server. Please check your connection and try again.
          </p>
          <button
            onClick={() => window.location.reload()}
            className="btn-primary"
          >
            Retry Connection
          </button>
          <div className="mt-4 text-sm text-gray-500">
            Error: {connectionError}
          </div>
        </div>
      </div>
    )
  }

  return (
    <SocketProvider>
      <div className="min-h-screen bg-gray-900 text-gray-100">
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/" element={<RequireAuth><Layout /></RequireAuth>}>
            <Route index element={<Navigate to="/dashboard" replace />} />
            <Route path="dashboard" element={<Dashboard />} />
            <Route path="terminal" element={<Terminal />} />
            <Route path="reports" element={<Reports />} />
            <Route path="reports/:reportId" element={<ReportDetails />} />
            <Route path="settings" element={<Settings />} />
            <Route path="targets" element={<Targets />} />
            <Route path="usage" element={<Usage />} />
            <Route path="*" element={<Navigate to="/dashboard" replace />} />
          </Route>
        </Routes>
        
        {/* Global notifications */}
        <Toaster
          position="top-right"
          toastOptions={{
            duration: 4000,
            style: {
              background: '#1f2937',
              color: '#f9fafb',
              border: '1px solid #374151',
            },
            success: {
              iconTheme: {
                primary: '#10b981',
                secondary: '#f9fafb',
              },
            },
            error: {
              iconTheme: {
                primary: '#ef4444',
                secondary: '#f9fafb',
              },
            },
          }}
        />
        
        {/* Connection status indicator */}
        {!isConnected && (
          <div className="fixed bottom-4 left-4 z-50">
            <div className="bg-red-600 text-white px-4 py-2 rounded-lg shadow-lg flex items-center space-x-2">
              <div className="w-2 h-2 bg-white rounded-full animate-pulse"></div>
              <span className="text-sm font-medium">Disconnected</span>
            </div>
          </div>
        )}
        
        {/* Development tools (only in dev mode) */}
        {import.meta.env.DEV && (
          <div className="fixed bottom-4 right-4 z-50">
            <details className="bg-gray-800 border border-gray-600 rounded-lg p-2 text-xs">
              <summary className="cursor-pointer text-gray-400">
                Dev Tools
              </summary>
              <div className="mt-2 space-y-1 text-gray-300">
                <div>Connected: {isConnected ? '✅' : '❌'}</div>
                <div>Environment: {import.meta.env.MODE}</div>
                <div>Version: 1.0.0</div>
              </div>
            </details>
          </div>
        )}
      </div>
    </SocketProvider>
  )
}

export default App 