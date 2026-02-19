import { useState } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../context/AuthContext'

const NAV = [
  { to: '/dashboard/', label: 'Overview', end: true },
  { to: '/dashboard/killswitch', label: 'KillSwitch', end: false },
  { to: '/dashboard/integrity', label: 'Integrity', end: false },
]

export default function Layout() {
  const { logout } = useAuth()
  const [menuOpen, setMenuOpen] = useState(false)

  return (
    <div className="min-h-screen bg-zinc-900 flex flex-col lg:flex-row">

      {/* Mobile top bar */}
      <div className="lg:hidden flex items-center justify-between px-4 py-3 bg-zinc-950 border-b border-zinc-800">
        <div>
          <span className="text-white font-bold">Moltr</span>
          <span className="text-zinc-500 text-xs ml-2">Security Dashboard</span>
        </div>
        <button
          onClick={() => setMenuOpen(v => !v)}
          className="text-zinc-400 hover:text-white p-1"
          aria-label="Menu"
        >
          {menuOpen ? '✕' : '☰'}
        </button>
      </div>

      {/* Sidebar — hidden on mobile unless open */}
      <aside className={`
        lg:flex lg:flex-col lg:w-56 lg:min-h-screen
        bg-zinc-950 border-r border-zinc-800
        ${menuOpen ? 'flex flex-col' : 'hidden lg:flex'}
      `}>
        <div className="hidden lg:block p-4 border-b border-zinc-800">
          <p className="text-white font-bold text-lg">Moltr</p>
          <p className="text-zinc-500 text-xs">Security Dashboard</p>
        </div>
        <nav className="flex-1 p-3 flex flex-col gap-1">
          {NAV.map(({ to, label, end }) => (
            <NavLink
              key={to}
              to={to}
              end={end}
              onClick={() => setMenuOpen(false)}
              className={({ isActive }) =>
                `px-3 py-2 rounded text-sm transition-colors ${
                  isActive
                    ? 'bg-zinc-800 text-white'
                    : 'text-zinc-400 hover:text-white hover:bg-zinc-800/50'
                }`
              }
            >
              {label}
            </NavLink>
          ))}
        </nav>
        <div className="p-3 border-t border-zinc-800 flex flex-col gap-2">
          <button
            onClick={logout}
            className="w-full text-left px-3 py-2 rounded text-sm text-zinc-500 hover:text-red-400 hover:bg-zinc-800/50 transition-colors"
          >
            Abmelden
          </button>
          <p className="text-zinc-600 text-xs px-3">v0.1.0 — Free Tier</p>
        </div>
      </aside>

      {/* Main */}
      <main className="flex-1 p-4 lg:p-8 overflow-auto">
        <Outlet />
      </main>
    </div>
  )
}
