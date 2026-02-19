import { useState, useEffect, useCallback } from 'react'
import { useAuth } from '../context/AuthContext'

interface IntegrityReport {
  baseline_created_at: number | null
  last_check: number | null
  files_monitored: number
  watched_paths: string[]
  total_violations: number
  recent_violations: Violation[]
}

interface Violation {
  filepath: string
  expected_hash: string
  actual_hash: string
  violation_type: 'modified' | 'deleted' | 'added'
  detected_at: number
}

interface CheckResult {
  violations: Violation[]
  violations_count: number
  clean: boolean
}

const VIOLATION_COLOR: Record<string, string> = {
  modified: 'text-yellow-400 border-yellow-700 bg-yellow-900/20',
  deleted:  'text-red-400   border-red-700   bg-red-900/20',
  added:    'text-blue-400  border-blue-700  bg-blue-900/20',
}

export default function Integrity() {
  const { authFetch } = useAuth()
  const [report, setReport]         = useState<IntegrityReport | null>(null)
  const [checking, setChecking]     = useState(false)
  const [lastCheck, setLastCheck]   = useState<CheckResult | null>(null)
  const [error, setError]           = useState<string | null>(null)

  const fetchReport = useCallback(async () => {
    try {
      const res = await authFetch('/api/v1/dashboard/integrity/report')
      if (res.ok) setReport(await res.json())
      setError(null)
    } catch {
      setError('Verbindungsfehler')
    }
  }, [authFetch])

  useEffect(() => {
    fetchReport()
    const interval = setInterval(fetchReport, 30000)
    return () => clearInterval(interval)
  }, [fetchReport])

  const runCheck = async () => {
    setChecking(true)
    setError(null)
    try {
      const res = await authFetch('/api/v1/dashboard/integrity/check')
      if (res.ok) {
        const data: CheckResult = await res.json()
        setLastCheck(data)
        await fetchReport()
      }
    } catch {
      setError('Check fehlgeschlagen')
    } finally {
      setChecking(false)
    }
  }

  const formatTs = (ts: number | null) => {
    if (!ts) return '—'
    return new Date(ts * 1000).toLocaleString('de-DE', {
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
    })
  }

  const shortPath = (p: string) => p.replace(/.*moltr-security[\\/]/, '')

  const violations = report?.recent_violations ?? []
  const isClean = report ? report.total_violations === 0 : null

  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white">Integrity Check</h1>
          <p className="text-zinc-500 text-sm mt-1">
            SHA-256 Baseline — {report?.files_monitored ?? '…'} Dateien überwacht
          </p>
        </div>
        <button
          onClick={runCheck}
          disabled={checking}
          className="px-4 py-2 text-sm rounded border border-zinc-600 bg-zinc-800 text-zinc-300 hover:text-white hover:border-zinc-500 transition-colors disabled:opacity-50"
        >
          {checking ? 'Prüfung läuft…' : 'Jetzt prüfen'}
        </button>
      </div>

      {error && (
        <div className="bg-red-900/50 border border-red-700 text-red-200 px-4 py-3 rounded-lg mb-4">
          {error}
        </div>
      )}

      {/* Status Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        <div className={`rounded-lg p-4 border ${
          isClean === null ? 'border-zinc-700 bg-zinc-800'
          : isClean       ? 'border-green-700 bg-zinc-800'
                          : 'border-red-700 bg-zinc-800'
        }`}>
          <p className="text-zinc-400 text-sm">Status</p>
          <p className={`text-xl font-semibold mt-1 ${
            isClean === null ? 'text-zinc-400'
            : isClean        ? 'text-green-400'
                             : 'text-red-400'
          }`}>
            {isClean === null ? '…' : isClean ? 'Sauber' : `${report!.total_violations} Verletzung(en)`}
          </p>
        </div>

        <div className="rounded-lg p-4 border border-zinc-700 bg-zinc-800">
          <p className="text-zinc-400 text-sm">Letzte Prüfung</p>
          <p className="text-zinc-200 text-sm font-medium mt-1">
            {formatTs(report?.last_check ?? null)}
          </p>
        </div>

        <div className="rounded-lg p-4 border border-zinc-700 bg-zinc-800">
          <p className="text-zinc-400 text-sm">Baseline erstellt</p>
          <p className="text-zinc-200 text-sm font-medium mt-1">
            {formatTs(report?.baseline_created_at ?? null)}
          </p>
        </div>
      </div>

      {/* Last manual check result */}
      {lastCheck && (
        <div className={`rounded-lg p-4 border mb-6 ${
          lastCheck.clean ? 'border-green-700 bg-green-900/20' : 'border-red-700 bg-red-900/20'
        }`}>
          <p className={`text-sm font-medium ${lastCheck.clean ? 'text-green-400' : 'text-red-400'}`}>
            Manuelle Prüfung: {lastCheck.clean
              ? 'Alle Dateien intakt ✓'
              : `${lastCheck.violations_count} Verletzung(en) gefunden`}
          </p>
        </div>
      )}

      {/* Violations List */}
      <div className="bg-zinc-800 rounded-lg p-5 border border-zinc-700">
        <h2 className="text-zinc-300 font-semibold mb-4">
          Letzte Verletzungen {violations.length > 0 && <span className="text-red-400">({violations.length})</span>}
        </h2>
        {violations.length === 0 ? (
          <p className="text-zinc-500 text-sm">Keine Verletzungen registriert</p>
        ) : (
          <div className="space-y-2">
            {violations.map((v, i) => (
              <div key={i} className={`rounded border px-3 py-2 text-sm ${VIOLATION_COLOR[v.violation_type] ?? 'text-zinc-400 border-zinc-700'}`}>
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-medium uppercase text-xs">{v.violation_type}</span>
                  <span className="text-zinc-500 text-xs">{formatTs(v.detected_at)}</span>
                </div>
                <p className="text-zinc-300 font-mono text-xs break-all">{shortPath(v.filepath)}</p>
                {v.violation_type === 'modified' && (
                  <p className="text-zinc-500 text-xs mt-1">
                    Erwartet: <span className="font-mono">{v.expected_hash.slice(0, 16)}…</span>
                    {' | '}Gefunden: <span className="font-mono">{v.actual_hash.slice(0, 16)}…</span>
                  </p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      <p className="text-zinc-600 text-xs mt-4">Auto-Refresh alle 30 Sekunden · Watchdog-Intervall: 60s</p>
    </div>
  )
}
