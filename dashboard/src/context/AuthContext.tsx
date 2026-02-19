import { createContext, useContext, useState, useCallback, useEffect, type ReactNode } from 'react'

interface AuthState {
  accessToken: string | null
  isAuthenticated: boolean
}

interface AuthContextValue extends AuthState {
  login: (username: string, password: string) => Promise<void>
  logout: () => Promise<void>
  authFetch: (url: string, init?: RequestInit) => Promise<Response>
}

const AuthContext = createContext<AuthContextValue | null>(null)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [accessToken, setAccessToken] = useState<string | null>(null)

  // On mount: try to refresh (in case we have a valid httpOnly refresh cookie)
  useEffect(() => {
    fetch('/api/v1/auth/refresh', { method: 'POST', credentials: 'include' })
      .then(r => r.ok ? r.json() : null)
      .then(data => { if (data?.access_token) setAccessToken(data.access_token) })
      .catch(() => {})
  }, [])

  const login = useCallback(async (username: string, password: string) => {
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password }),
    })
    if (!res.ok) {
      const err = await res.json().catch(() => ({}))
      throw new Error(err.detail || `Login failed (${res.status})`)
    }
    const data = await res.json()
    setAccessToken(data.access_token)
  }, [])

  const logout = useCallback(async () => {
    await fetch('/api/v1/auth/logout', { method: 'POST', credentials: 'include' }).catch(() => {})
    setAccessToken(null)
  }, [])

  // Auth-aware fetch — auto-refreshes on 401
  const authFetch = useCallback(async (url: string, init: RequestInit = {}): Promise<Response> => {
    const headers = { ...(init.headers ?? {}), Authorization: `Bearer ${accessToken}` }
    const res = await fetch(url, { ...init, headers, credentials: 'include' })
    if (res.status === 401 && accessToken) {
      // Try silent refresh
      const refreshRes = await fetch('/api/v1/auth/refresh', { method: 'POST', credentials: 'include' })
      if (refreshRes.ok) {
        const data = await refreshRes.json()
        setAccessToken(data.access_token)
        return fetch(url, { ...init, headers: { ...headers, Authorization: `Bearer ${data.access_token}` }, credentials: 'include' })
      }
      setAccessToken(null)
    }
    return res
  }, [accessToken])

  return (
    <AuthContext.Provider value={{ accessToken, isAuthenticated: !!accessToken, login, logout, authFetch }}>
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
