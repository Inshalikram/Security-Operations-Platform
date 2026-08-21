"use client"

import { useEffect, useState, useRef } from "react"
import { useSession } from "next-auth/react"
import { signOut } from "next-auth/react"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Bell, Loader2, Radio } from "lucide-react"

const BASE_URL = "http://127.0.0.1:8000"
const WS_URL = "ws://127.0.0.1:8000/ws/alerts"

const VERDICT_STYLES: Record<string, string> = {
  malicious: "bg-rose-500/20 text-rose-300 border-rose-500/30",
  suspicious: "bg-amber-500/20 text-amber-300 border-amber-500/30",
  clean: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
}

export default function AlertsPage() {
  const { data: session } = useSession()
  const [alerts, setAlerts] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [connected, setConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!session?.accessToken) return

    // Load history
    fetch(`${BASE_URL}/threat-intel/history`, {
      headers: { Authorization: `Bearer ${session.accessToken}` },
    })
      .then((res) => res.json())
      .then((data) => setAlerts(Array.isArray(data) ? data : []))
      .finally(() => setLoading(false))

    // Live updates over WebSocket
    const ws = new WebSocket(`${WS_URL}?token=${session.accessToken}`)
    ws.onopen = () => setConnected(true)
    ws.onclose = () => setConnected(false)
    ws.onmessage = (event) => {
      const data = JSON.parse(event.data)
      if (data.type === "new_alert") {
        setAlerts((prev) => [
          { ip_address: data.ip, verdict: data.verdict, malicious_signals: data.malicious_signals, checked_at: new Date().toISOString() },
          ...prev,
        ])
      }
    }
    wsRef.current = ws
    return () => ws.close()
  }, [session])

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-slate-100">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 h-96 w-96 rounded-full bg-violet-600/10 blur-3xl" />
        <div className="absolute top-40 right-0 h-96 w-96 rounded-full bg-rose-600/10 blur-3xl" />
      </div>

      <header className="relative border-b border-white/5 bg-white/[0.02] px-8 py-5 backdrop-blur-xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-rose-500 shadow-lg shadow-violet-500/20">
              <Bell className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight text-white">Alerts</h1>
              <p className="text-xs text-slate-500 flex items-center gap-1.5">
                <Radio className={`h-3 w-3 ${connected ? "text-emerald-400" : "text-slate-600"}`} />
                {connected ? "Live" : "Disconnected"}
              </p>
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="border-white/10 text-slate-300 hover:bg-white/5"
            onClick={() => signOut({ callbackUrl: "/" })}
          >
            Sign Out
          </Button>
        </div>
      </header>

      <main className="relative p-8 max-w-4xl mx-auto space-y-3">
        {loading && (
          <div className="flex items-center gap-2 text-slate-400 py-12 justify-center">
            <Loader2 className="h-5 w-5 animate-spin" />
            Loading alerts...
          </div>
        )}

        {!loading && alerts.length === 0 && (
          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="pt-6 text-center text-slate-400 py-12">
              No alerts yet.
            </CardContent>
          </Card>
        )}

        {alerts.map((a, i) => (
          <Card key={i} className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="pt-6 flex items-center justify-between">
              <div>
                <p className="text-white font-mono text-sm">{a.ip_address || a.ip}</p>
                <p className="text-xs text-slate-500 mt-1">
                  {a.malicious_signals} signal(s) · {a.checked_at ? new Date(a.checked_at).toLocaleString() : ""}
                </p>
              </div>
              <span className={`text-xs px-3 py-1 rounded-full border ${VERDICT_STYLES[a.verdict] || "bg-slate-500/20 text-slate-300 border-slate-500/30"}`}>
                {a.verdict}
              </span>
            </CardContent>
          </Card>
        ))}
      </main>
    </div>
  )
}