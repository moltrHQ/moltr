import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '../context/AuthContext'

type Level = 'pause' | 'network_cut' | 'lockdown' | 'wipe' | 'emergency'

interface KillSwitchStatus {
  is_locked_down: boolean
  active_levels: string[]
  highest_level: string | null
}

interface KillSwitchLog {
  events: { timestamp: string; action: string; level: string; reason: string }[]
  total: number
  status: KillSwitchStatus
}

const LEVEL_META: Record<Level, { label: string; color: string; danger: boolean }> = {
  pause:       { label: 'PAUSE',       color: 'yellow', danger: false },
  network_cut: { label: 'NETWORK CUT', color: 'orange', danger: false },
  lockdown:    { label: 'LOCKDOWN',    color: 'red',    danger: false },
  wipe:        { label: 'WIPE',        color: 'red',    danger: true  },
  emergency:   { label: 'EMERGENCY',   color: 'red',    danger: true  },
}

const COLOR_CLASS: Record<string, string> = {
  yellow: 'border-yellow-700 text-yellow-400 hover:bg-yellow-900/30',
  orange: 'border-orange-700 text-orange-400 hover:bg-orange-900/30',
  red:    'border-red-700 text-red-400 hover:bg-red-900/30',
}

export default function KillSwitch() {
  const { authFetch } = useAuth()
  const [status, setStatus] = useState<KillSwitchStatus | null>(null)
  const [log, setLog] = useState<KillSwitchLog['events']>([])
  const [error, setError] = useState<string | null>(null)

  // Confirm-modal state
  const [modal, setModal] = useState<{ mode: 'trigger' | 'reset'; level: Level } | null>(null)
  const [reason, setReason] = useState('')
  const [codephrase, setCodephrase] = useState('')
  const [actionLoading, setActionLoading] = useState(false)
  const [actionResult, setActionResult] = useState<string | null>(null)

  const fetchStatus = useCallback(async () => {
    try {
      const [logRes] = await Promise.all([
        authFetch('/api/v1/dashboard/killswitch/log?limit=10'),
      ])
      if (logRes.ok) {
        const data: KillSwitchLog = await logRes.json()
        setStatus(data.status)
        setLog(data.events)
      }
      setError(null)
    } catch {
      setError('Verbindungsfehler')
    }
  }, [authFetch])

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 10000)
    return () => clearInterval(interval)
  }, [fetchStatus])

  const openTrigger = (level: Level) => {
    setModal({ mode: 'trigger', level })
    setReason('')
    setActionResult(null)
  }

  const openReset = (level: Level) => {
    setModal({ mode: 'reset', level })
    setCodephrase('')
    setReason('')
    setActionResult(null)
  }

  const confirmAction = async () => {
    if (!modal) return
    setActionLoading(true)
    setActionResult(null)
    try {
      if (modal.mode === 'trigger') {
        const finalReason = LEVEL_META[modal.level].danger
          ? `CONFIRM: ${reason}`
          : reason
        const res = await authFetch('/api/v1/dashboard/killswitch/trigger', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ level: modal.level, reason: finalReason }),
        })
        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`)
        setActionResult(`Ausgelöst: ${data.level}${data.already_active ? ' (bereits aktiv)' : ''}`)
      } else {
        const res = await authFetch('/api/v1/dashboard/killswitch/reset', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ level: modal.level, codephrase }),
        })
        const data = await res.json()
        if (!res.ok) throw new Error(data.detail || `HTTP ${res.status}`)
        setActionResult(`Reset erfolgreich: ${data.level}`)
      }
      await fetchStatus()
      setTimeout(() => setModal(null), 1500)
    } catch (err) {
      setActionResult(`Fehler: ${err instanceof Error ? err.message : 'Unbekannt'}`)
    } finally {
      setActionLoading(false)
    }
  }

  const activeLevels = status?.active_levels ?? []
  const isActive = (level: Level) => activeLevels.map(l => l.toLowerCase()).includes(level)

  const exportLog = async () => {
    const res = await authFetch('/api/v1/dashboard/killswitch/export')
    if (!res.ok) return
    const blob = await res.blob()
    const cd = res.headers.get('Content-Disposition') ?? ''
    const name = cd.match(/filename="([^"]+)"/)?.[1] ?? 'audit-log.json'
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url; a.download = name; a.click()
    URL.revokeObjectURL(url)
  }

  const formatTs = (ts: string) => {
    try { return new Date(ts).toLocaleString('de-DE', { day:'2-digit', month:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit' }) }
    catch { return ts }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-white mb-2">KillSwitch Control</h1>
      <p className="text-zinc-500 text-sm mb-6">
        Status: {status ? (status.is_locked_down ? '🔴 LOCKDOWN' : activeLevels.length ? `⚠️ ${activeLevels.join(', ')}` : '✅ Inaktiv') : '…'}
      </p>

      {error && <div className="bg-red-900/50 border border-red-700 text-red-200 px-4 py-3 rounded-lg mb-4">{error}</div>}

      {/* Trigger Buttons */}
      <div className="bg-zinc-800 rounded-lg p-5 border border-zinc-700 mb-4">
        <h2 className="text-zinc-300 font-semibold mb-3">Eskalation auslösen</h2>
        <div className="flex flex-wrap gap-2">
          {(Object.entries(LEVEL_META) as [Level, typeof LEVEL_META[Level]][]).map(([level, meta]) => (
            <button
              key={level}
              onClick={() => openTrigger(level)}
              className={`px-4 py-2 text-sm rounded border bg-zinc-900 transition-colors ${COLOR_CLASS[meta.color]} ${isActive(level) ? 'opacity-50' : ''}`}
            >
              {meta.label}{isActive(level) ? ' ●' : ''}
            </button>
          ))}
        </div>
      </div>

      {/* Reset Buttons */}
      <div className="bg-zinc-800 rounded-lg p-5 border border-zinc-700 mb-6">
        <h2 className="text-zinc-300 font-semibold mb-3">Level zurücksetzen</h2>
        <div className="flex flex-wrap gap-2">
          {(Object.keys(LEVEL_META) as Level[]).map(level => (
            <button
              key={level}
              onClick={() => openReset(level)}
              disabled={!isActive(level)}
              className="px-4 py-2 text-sm rounded border border-zinc-600 bg-zinc-900 text-zinc-400 hover:text-white hover:border-zinc-500 transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
            >
              Reset {LEVEL_META[level].label}
            </button>
          ))}
        </div>
      </div>

      {/* Event Log */}
      <div className="bg-zinc-800 rounded-lg p-5 border border-zinc-700">
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-zinc-300 font-semibold">Event Log</h2>
          <button
            onClick={exportLog}
            className="text-xs px-3 py-1.5 rounded border border-zinc-600 text-zinc-400 hover:text-white hover:border-zinc-500 transition-colors"
          >
            Export JSON
          </button>
        </div>
        {log.length === 0
          ? <p className="text-zinc-500 text-sm">Noch keine Events</p>
          : <div className="space-y-2">
              {log.map((e, i) => (
                <div key={i} className="flex items-start gap-3 text-sm">
                  <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${e.action === 'trigger' ? 'bg-red-500' : 'bg-green-500'}`} />
                  <div>
                    <span className={e.action === 'trigger' ? 'text-red-400 font-medium' : 'text-green-400 font-medium'}>
                      {e.action.toUpperCase()}
                    </span>
                    <span className="text-zinc-400 ml-2">Level: <span className="text-yellow-400">{e.level}</span></span>
                    {e.reason && <p className="text-zinc-500 text-xs mt-0.5">{e.reason}</p>}
                    <p className="text-zinc-600 text-xs">{formatTs(e.timestamp)}</p>
                  </div>
                </div>
              ))}
            </div>
        }
      </div>

      {/* Confirm Modal */}
      {modal && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50">
          <div className="bg-zinc-800 border border-zinc-700 rounded-lg p-6 w-full max-w-md mx-4">
            <h3 className="text-white font-bold text-lg mb-1">
              {modal.mode === 'trigger' ? `KillSwitch: ${LEVEL_META[modal.level].label}` : `Reset: ${LEVEL_META[modal.level].label}`}
            </h3>
            {LEVEL_META[modal.level].danger && modal.mode === 'trigger' && (
              <p className="text-red-400 text-sm mb-3">⚠️ Gefährliche Operation — Begründung wird automatisch mit CONFIRM: prefixiert</p>
            )}

            {modal.mode === 'trigger' && (
              <div className="mb-4">
                <label className="block text-zinc-400 text-sm mb-1">Begründung</label>
                <input
                  type="text"
                  value={reason}
                  onChange={e => setReason(e.target.value)}
                  placeholder="Begründung eingeben…"
                  className="w-full bg-zinc-900 border border-zinc-700 rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-zinc-500"
                />
              </div>
            )}

            {modal.mode === 'reset' && (
              <div className="mb-4">
                <label className="block text-zinc-400 text-sm mb-1">Codephrase</label>
                <input
                  type="password"
                  value={codephrase}
                  onChange={e => setCodephrase(e.target.value)}
                  placeholder="Codephrase eingeben…"
                  className="w-full bg-zinc-900 border border-zinc-700 rounded px-3 py-2 text-white text-sm focus:outline-none focus:border-zinc-500"
                />
              </div>
            )}

            {actionResult && (
              <p className={`text-sm mb-3 ${actionResult.startsWith('Fehler') ? 'text-red-400' : 'text-green-400'}`}>
                {actionResult}
              </p>
            )}

            <div className="flex gap-2 justify-end">
              <button
                onClick={() => setModal(null)}
                className="px-4 py-2 text-sm text-zinc-400 hover:text-white rounded border border-zinc-600 transition-colors"
              >
                Abbrechen
              </button>
              <button
                onClick={confirmAction}
                disabled={actionLoading}
                className="px-4 py-2 text-sm text-white rounded border border-red-700 bg-red-900/40 hover:bg-red-900/70 transition-colors disabled:opacity-50"
              >
                {actionLoading ? 'Wird ausgeführt…' : 'Bestätigen'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
