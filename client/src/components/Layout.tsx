import { useEffect, useState } from 'react'
import { Outlet, NavLink, useLocation } from 'react-router-dom'
import {
  HomeIcon,
  ComputerDesktopIcon,
  DocumentTextIcon,
  CogIcon,
  ShieldCheckIcon as VerifyIcon,
  ChartBarIcon as UsageIcon,
  ChevronLeftIcon,
  ChevronRightIcon,
  ShieldCheckIcon,
  Bars3Icon,
  XMarkIcon,
} from '@heroicons/react/24/outline'
import { useAppStore } from '../store/appStore'
import clsx from 'clsx'
import toast from 'react-hot-toast'
import { apiFetch } from '@/utils/api'

const navigation = [
  { name: 'Dashboard', href: '/dashboard', icon: HomeIcon },
  { name: 'Terminal', href: '/terminal', icon: ComputerDesktopIcon },
  { name: 'Reports', href: '/reports', icon: DocumentTextIcon },
  { name: 'Targets', href: '/targets', icon: VerifyIcon },
  { name: 'Usage', href: '/usage', icon: UsageIcon },
  { name: 'Settings', href: '/settings', icon: CogIcon },
]

export default function Layout() {
  const [sidebarExpanded, setSidebarExpanded] = useState(true)
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false)
  const { isConnected, runningScans, currentUser, logout } = useAppStore()
  const location = useLocation()

  // Minimal telemetry: send a visit event on route change (privacy-respecting)
  useEffect(() => {
    const controller = new AbortController()
    apiFetch('/api/telemetry/visit', {
      method: 'POST',
      body: JSON.stringify({ path: location.pathname }),
      signal: controller.signal as any
    }).catch(() => {})
    return () => controller.abort()
  }, [location.pathname])

  const toggleSidebar = () => setSidebarExpanded(!sidebarExpanded)
  const toggleMobileMenu = () => setMobileMenuOpen(!mobileMenuOpen)

  return (
    <div className="h-screen flex overflow-hidden bg-gray-900">
      {/* Mobile menu overlay */}
      {mobileMenuOpen && (
        <div className="fixed inset-0 flex z-40 md:hidden" role="dialog" aria-modal="true">
          <div
            className="fixed inset-0 bg-gray-600 bg-opacity-75"
            aria-hidden="true"
            onClick={toggleMobileMenu}
          />

          <div className="relative flex-1 flex flex-col max-w-xs w-full bg-gray-800">
            <div className="absolute top-0 right-0 -mr-12 pt-2">
              <button
                type="button"
                className="ml-1 flex items-center justify-center h-10 w-10 rounded-full focus:outline-none focus:ring-2 focus:ring-inset focus:ring-white"
                onClick={toggleMobileMenu}
                aria-label="Close menu"
                title="Close menu"
              >
                <XMarkIcon className="h-6 w-6 text-white" aria-hidden="true" />
              </button>
            </div>

            <div className="flex-1 h-0 pt-5 pb-4 overflow-y-auto">
              <div className="flex-shrink-0 flex items-center px-4">
                <ShieldCheckIcon className="h-8 w-8 text-blue-400" />
                <span className="ml-2 text-xl font-bold text-white">CyberSec</span>
              </div>

              {/* Mobile user area */}
              <div className="px-4 mt-2 flex items-center justify-between">
                {currentUser && (
                  <div className="flex items-center space-x-2">
                    <div className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs flex items-center justify-center">
                      {currentUser.email?.charAt(0).toUpperCase()}
                    </div>
                    <span className="text-gray-300 text-sm">{currentUser.email}</span>
                  </div>
                )}
                <button
                  onClick={() => {
                    logout()
                    toast('Logged out')
                    toggleMobileMenu()
                  }}
                  className="px-3 py-1 bg-gray-700 hover:bg-gray-600 rounded text-gray-100 text-sm"
                >
                  Logout
                </button>
              </div>

              <nav className="mt-5 px-2 space-y-1">
                {navigation.map((item) => {
                  const isActive = location.pathname === item.href
                  return (
                    <NavLink
                      key={item.name}
                      to={item.href}
                      onClick={toggleMobileMenu}
                      className={clsx(
                        isActive
                          ? 'bg-gray-900 text-white'
                          : 'text-gray-300 hover:bg-gray-700 hover:text-white',
                        'group flex items-center px-2 py-2 text-base font-medium rounded-md'
                      )}
                    >
                      <item.icon
                        className={clsx(
                          isActive ? 'text-gray-300' : 'text-gray-400 group-hover:text-gray-300',
                          'mr-4 flex-shrink-0 h-6 w-6'
                        )}
                        aria-hidden="true"
                      />
                      {item.name}
                    </NavLink>
                  )
                })}
                {currentUser?.role === 'admin' && (
                  <NavLink
                    key="Admin"
                    to="/admin"
                    onClick={toggleMobileMenu}
                    className={clsx(
                      location.pathname === '/admin' ? 'bg-gray-900 text-white' : 'text-gray-300 hover:bg-gray-700 hover:text-white',
                      'group flex items-center px-2 py-2 text-base font-medium rounded-md'
                    )}
                  >
                    <ShieldCheckIcon className="mr-4 flex-shrink-0 h-6 w-6 text-gray-400 group-hover:text-gray-300" />
                    Admin
                  </NavLink>
                )}
              </nav>
            </div>

            <div className="flex-shrink-0 flex border-t border-gray-700 p-4">
              <div className="flex items-center">
                <div
                  className={clsx('w-3 h-3 rounded-full mr-3', isConnected ? 'bg-green-500' : 'bg-red-500')}
                />
                <div className="text-sm">
                  <p className="text-white font-medium">{isConnected ? 'Connected' : 'Disconnected'}</p>
                  <p className="text-gray-400">{runningScans.length} active scans</p>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Desktop sidebar */}
      <div
        className={clsx(
          'hidden md:flex md:flex-shrink-0 transition-all duration-300',
          sidebarExpanded ? 'md:w-64' : 'md:w-16'
        )}
      >
        <div className="flex flex-col w-full">
          <div className="flex flex-col h-0 flex-1 bg-gray-800">
            <div className="flex-1 flex flex-col pt-5 pb-4 overflow-y-auto">
              <div className="flex items-center flex-shrink-0 px-4">
                <ShieldCheckIcon className="h-8 w-8 text-blue-400" />
                {sidebarExpanded && <span className="ml-2 text-xl font-bold text-white">CyberSec</span>}
              </div>

              <nav className="mt-5 flex-1 px-2 space-y-1">
                {navigation.map((item) => {
                  const isActive = location.pathname === item.href
                  return (
                    <NavLink
                      key={item.name}
                      to={item.href}
                      className={clsx(
                        isActive
                          ? 'bg-gray-900 text-white'
                          : 'text-gray-300 hover:bg-gray-700 hover:text-white',
                        'group flex items-center px-2 py-2 text-sm font-medium rounded-md transition-colors'
                      )}
                      title={!sidebarExpanded ? item.name : undefined}
                    >
                      <item.icon
                        className={clsx(
                          isActive ? 'text-gray-300' : 'text-gray-400 group-hover:text-gray-300',
                          'flex-shrink-0 h-6 w-6',
                          sidebarExpanded ? 'mr-3' : 'mx-auto'
                        )}
                        aria-hidden="true"
                      />
                      {sidebarExpanded && item.name}
                    </NavLink>
                  )
                })}
                {currentUser?.role === 'admin' && (
                  <NavLink
                    key="Admin"
                    to="/admin"
                    className={clsx(
                      location.pathname === '/admin'
                        ? 'bg-gray-900 text-white'
                        : 'text-gray-300 hover:bg-gray-700 hover:text-white',
                      'group flex items-center px-2 py-2 text-sm font-medium rounded-md transition-colors'
                    )}
                    title={!sidebarExpanded ? 'Admin' : undefined}
                  >
                    <ShieldCheckIcon
                      className={clsx(
                        location.pathname === '/admin' ? 'text-gray-300' : 'text-gray-400 group-hover:text-gray-300',
                        'flex-shrink-0 h-6 w-6',
                        sidebarExpanded ? 'mr-3' : 'mx-auto'
                      )}
                      aria-hidden="true"
                    />
                    {sidebarExpanded && 'Admin'}
                  </NavLink>
                )}
              </nav>

              {/* Sidebar toggle button */}
              <div className="px-2 mt-4">
                <button
                  onClick={toggleSidebar}
                  className="w-full flex items-center justify-center px-2 py-2 text-gray-400 hover:text-white hover:bg-gray-700 rounded-md transition-colors"
                  title={sidebarExpanded ? 'Collapse sidebar' : 'Expand sidebar'}
                >
                  {sidebarExpanded ? (
                    <ChevronLeftIcon className="h-5 w-5" />
                  ) : (
                    <ChevronRightIcon className="h-5 w-5" />
                  )}
                </button>
              </div>
            </div>

            {/* Connection status and user */}
            <div className="flex-shrink-0 flex border-t border-gray-700 p-4">
              {sidebarExpanded ? (
                <div className="flex items-center w-full justify-between">
                  <div
                    className={clsx(
                      'w-3 h-3 rounded-full mr-3',
                      isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'
                    )}
                  />
                  <div className="text-sm flex-1">
                    <p className="text-white font-medium">{isConnected ? 'Connected' : 'Disconnected'}</p>
                    <p className="text-gray-400">{runningScans.length} active scans</p>
                  </div>
                  <div className="text-right">
                    {currentUser && (
                      <div className="text-xs text-gray-300 mb-1 flex items-center justify-end space-x-2">
                        <div className="w-6 h-6 rounded-full bg-blue-600 text-white text-xs flex items-center justify-center">
                          {currentUser.email?.charAt(0).toUpperCase()}
                        </div>
                        <span>{currentUser.email}</span>
                      </div>
                    )}
                    <button
                      onClick={() => {
                        logout()
                        toast('Logged out')
                      }}
                      className="px-2 py-1 bg-gray-700 hover:bg-gray-600 rounded text-xs"
                      title="Logout"
                    >
                      Logout
                    </button>
                  </div>
                </div>
              ) : (
                <div
                  className={clsx(
                    'w-3 h-3 rounded-full mx-auto',
                    isConnected ? 'bg-green-500 animate-pulse' : 'bg-red-500'
                  )}
                  title={`${isConnected ? 'Connected' : 'Disconnected'} - ${runningScans.length} active scans`}
                />
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Main content */}
      <div className="flex flex-col w-0 flex-1 overflow-hidden">
        {/* Mobile header */}
        <div className="md:hidden">
          <div className="relative z-10 flex-shrink-0 flex h-16 bg-white shadow">
            <button
              type="button"
              className="px-4 border-r border-gray-200 text-gray-500 focus:outline-none focus:ring-2 focus:ring-inset focus:ring-indigo-500 md:hidden"
              onClick={toggleMobileMenu}
              aria-label="Open menu"
              title="Open menu"
            >
              <Bars3Icon className="h-6 w-6" aria-hidden="true" />
            </button>
            <div className="flex-1 px-4 flex justify-between">
              <div className="flex-1 flex items-center">
                <ShieldCheckIcon className="h-8 w-8 text-blue-600" />
                <span className="ml-2 text-xl font-bold text-gray-900">CyberSec</span>
              </div>
            </div>
          </div>
        </div>

        {/* Page content */}
        <main className="flex-1 relative overflow-y-auto focus:outline-none bg-gray-900">
          <div className="h-full">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}