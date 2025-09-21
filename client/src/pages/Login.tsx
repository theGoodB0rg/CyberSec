import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAppStore } from '@/store/appStore'
import toast from 'react-hot-toast'

export default function Login() {
  const navigate = useNavigate()
  const { login, register } = useAppStore()
  const [mode, setMode] = useState<'login' | 'register'>('login')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [loading, setLoading] = useState(false)

  const onSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      if (mode === 'login') {
        await login(email, password)
        toast.success('Logged in')
      } else {
        await register(email, password)
        toast.success('Account created')
      }
      navigate('/dashboard', { replace: true })
    } catch (err: any) {
      toast.error(err?.message || 'Authentication failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-900 px-4">
      <div className="w-full max-w-md bg-gray-800 p-8 rounded-lg shadow-lg border border-gray-700">
        <h1 className="text-2xl font-bold text-white mb-6 text-center">
          {mode === 'login' ? 'Sign in to CyberSec' : 'Create your account'}
        </h1>
        <form onSubmit={onSubmit} className="space-y-4">
          <div>
            <label className="block text-sm text-gray-300 mb-1">Email</label>
            <input
              type="email"
              className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              required
              id="email"
              name="email"
              placeholder="you@example.com"
              aria-label="Email"
            />
          </div>
          <div>
            <label className="block text-sm text-gray-300 mb-1">Password</label>
            <input
              type="password"
              className="w-full px-3 py-2 rounded bg-gray-900 border border-gray-700 text-white focus:outline-none focus:ring-2 focus:ring-blue-600"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
              minLength={6}
              id="password"
              name="password"
              placeholder="••••••••"
              aria-label="Password"
            />
          </div>
          <button
            type="submit"
            disabled={loading}
            className="w-full py-2 bg-blue-600 hover:bg-blue-700 text-white rounded font-medium disabled:opacity-50"
          >
            {loading ? 'Please wait...' : (mode === 'login' ? 'Sign In' : 'Create Account')}
          </button>
        </form>
        <div className="mt-4 text-center text-sm text-gray-400">
          {mode === 'login' ? (
            <button className="text-blue-400 hover:underline" onClick={() => setMode('register')}>Need an account? Register</button>
          ) : (
            <button className="text-blue-400 hover:underline" onClick={() => setMode('login')}>Already have an account? Sign in</button>
          )}
        </div>
      </div>
    </div>
  )
}
