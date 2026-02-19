import { useState, useEffect } from 'react'

interface HealthStatus {
  status: string
  timestamp: string
}

interface MoltrStatus {
  is_running: boolean
  killswitch: {
    is_locked_down: boolean
    active_levels: string[]
    highest_level: string | null
  }
}

interface KillSwitchEvent {
  timestamp: string
  action: string
  level: string
  reason: string
}

interface KillSwitchLogResponse {
  events: KillSwitchEvent[]
  total: number
  status: {
    is_locked_down: boolean
    active_levels: string[]
  }
}

export default function Overview() {
  const [health, setHealth] = useState<HealthStatus | null>(null)
  const [moltrStatus, setMoltrStatus] = useState<MoltrStatus | null>(null)
  const [killSwitchLog, setKillSwitchLog] = useState<KillSwitchEvent[]>([])
  const [error, setError] = useState<string | null>(null)

  const fetchData = async () => {
    try {
      // Fetch health
      const healthRes = await fetch('/health')
      if (healthRes.ok) {
        setHealth(await healthRes.json())
      }

      // Fetch moltr status
      const statusRes = await fetch('/status')
      if (statusRes.ok) {
        const statusData = await statusRes.json()
        setMoltrStatus(statusData)
      }

      // Fetch kill switch log (last 5 events)
      const logRes = await fetch('/killswitch/log?limit=5')
      if (logRes.ok) {
        const logData: KillSwitchLogResponse = await logRes.json()
        setKillSwitchLog(logData.events)
      }

      setError(null)
    } catch (err) {
      setError('Failed to fetch data')
      console.error(err)
    }
  }

  useEffect(() => {
    fetchData()
    const interval = setInterval(fetchData, 10000)
    return () => clearInterval(interval)
  }, [])

  const isSystemOnline = health?.status === 'ok'
  const isLockdown = moltrStatus?.killswitch?.is_locked_down ?? false
  const activeLevels = moltrStatus?.killswitch?.active_levels ?? []
  const hasActiveKillSwitch = activeLevels.length > 0

  const formatTimestamp = (ts: string) => {
    try {
      return new Date(ts).toLocaleString('de-DE', {
        day: '2-digit',
        month: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      })
    } catch {
      return ts
    }
  }

  return (
    <div>
      <h1 className="text-2xl font-bold text-white mb-6">System Overview</h1>
      
      {error && (
        <div className="bg-red-900/50 border border-red-700 text-red-200 px-4 py-3 rounded-lg mb-6">
          {error}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
        {/* System Status Card */}
        <div className={`rounded-lg p-4 border ${
          isSystemOnline 
            ? 'bg-zinc-800 border-green-700' 
            : 'bg-zinc-800 border-red-700'
        }`}>
          <p className="text-zinc-400 text-sm">System Status</p>
          <p className={`text-xl font-semibold mt-1 ${
            isSystemOnline ? 'text-green-400' : 'text-red-400'
          }`}>
            {isSystemOnline ? 'Online' : 'Offline'}
          </p>
          {health?.timestamp && (
            <p className="text-zinc-500 text-xs mt-2">
              {formatTimestamp(health.timestamp)}
            </p>
          )}
        </div>

        {/* KillSwitch Status Card */}
        <div className={`rounded-lg p-4 border ${
          isLockdown 
            ? 'bg-zinc-800 border-red-700' 
            : hasActiveKillSwitch
              ? 'bg-zinc-800 border-yellow-700'
              : 'bg-zinc-800 border-zinc-700'
        }`}>
          <p className="text-zinc-400 text-sm">KillSwitch</p>
          <p className={`text-xl font-semibold mt-1 ${
            isLockdown 
              ? 'text-red-400' 
              : hasActiveKillSwitch
                ? 'text-yellow-400'
                : 'text-green-400'
          }`}>
            {isLockdown 
              ? 'LOCKDOWN' 
              : hasActiveKillSwitch 
                ? activeLevels.join(', ')
                : 'Inactive'}
          </p>
          {moltrStatus?.killswitch?.highest_level && (
            <p className="text-zinc-500 text-xs mt-2">
              Highest: {moltrStatus.killswitch.highest_level}
            </p>
          )}
        </div>

        {/* Integrity Status Card (Placeholder) */}
        <div className="bg-zinc-800 rounded-lg p-4 border border-zinc-700">
          <p className="text-zinc-400 text-sm">Integrity</p>
          <p className="text-zinc-200 text-xl font-semibold mt-1">Unknown</p>
          <p className="text-zinc-500 text-xs mt-2">Coming in Tag 5</p>
        </div>
      </div>

      {/* KillSwitch Event Timeline */}
      <div className="bg-zinc-800 rounded-lg p-4 border border-zinc-700">
        <h2 className="text-lg font-semibold text-white mb-4">Letzte KillSwitch Events</h2>
        
        {killSwitchLog.length === 0 ? (
          <p className="text-zinc-500 text-sm">Noch keine Events</p>
        ) : (
          <div className="space-y-3">
            {killSwitchLog.map((event, index) => (
              <div key={index} className="flex items-start gap-3">
                <div className={`w-2 h-2 rounded-full mt-2 ${
                  event.action === 'trigger' ? 'bg-red-500' : 'bg-green-500'
                }`} />
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <span className={`text-sm font-medium ${
                      event.action === 'trigger' ? 'text-red-400' : 'text-green-400'
                    }`}>
                      {event.action.toUpperCase()}
                    </span>
                    <span className="text-sm text-zinc-300">
                      Level: <span className="text-yellow-400">{event.level}</span>
                    </span>
                  </div>
                  <p className="text-zinc-400 text-sm">{event.reason || '—'}</p>
                  <p className="text-zinc-500 text-xs">{formatTimestamp(event.timestamp)}</p>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      <p className="text-zinc-600 text-xs mt-6">
        Auto-Refresh alle 10 Sekunden
      </p>
    </div>
  )
}
