"use client"

import { useEffect, useState, useRef } from "react"
import { signOut } from "next-auth/react"
import { useSessionGuard } from "@/lib/use-session-guard"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { Bell, Loader2, Radio } from "lucide-react"
import FormattedTime from "@/components/formatted-time"

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://169.58.221.49:8000"
const WS_URL = process.env.NEXT_PUBLIC_API_URL
  ? process.env.NEXT_PUBLIC_API_URL.replace("https://", "wss://").replace("http://", "ws://") + "/ws/alerts"
  : "ws://169.58.221.49:8000/ws/alerts"

const VERDICT_STYLES: Record<string, string> = {
  malicious: "bg-rose-500/20 text-rose-300 border-rose-500/30",
  suspicious: "bg-amber-500/20 text-amber-300 border-amber-500/30",
  clean: "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
}

const SOURCE_STYLES: Record<string, string> = {
  suricata: "text-cyan-400",
  zeek: "text-blue-400",
  falco: "text-orange-400",
  wazuh: "text-rose-400",
  "laptop-network": "text-emerald-400",
  laptop: "text-emerald-400",
  "threat-intel": "text-slate-500",
}

// ── Normalizes a raw alert (from /alerts/unified OR the WebSocket) into a
// consistent { source, verdict } shape. Backend sends Wazuh/tool-health
// system alerts with source="monitoring" and severity="critical"/"warning"
// (not "malicious"/"suspicious"/"clean"), and the real tool name is buried
// in the title ("wazuh alert" or "laptop-network alert"). This pulls the tool name out and maps the
// severity so filtering + badge colors work the same as the other sources. ──
function normalizeAlert(source: string, verdict: string, title?: string) {
  if (source === "monitoring") {
    const toolMatch = title?.match(/^([\w-]+)\s+alert$/i)
    const resolvedSource = toolMatch ? toolMatch[1].toLowerCase() : source
    const resolvedVerdict = verdict === "critical" ? "malicious" : "suspicious"
    return { source: resolvedSource, verdict: resolvedVerdict }
  }
  return { source, verdict }
}

export default function AlertsPage() {
  const session = useSessionGuard()
  const [alerts, setAlerts] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [connected, setConnected] = useState(false)
  const wsRef = useRef<WebSocket | null>(null)

  useEffect(() => {
    if (!session?.accessToken) return

    const MONITORING_SOURCES = ["suricata", "zeek", "falco", "wazuh", "laptop-network", "laptop"]

    function shouldShow(source: string, verdict: string) {
      // Threat-intel: sab verdicts dikhao (clean bhi)
      if (source === "threat-intel") return true
      // Monitoring tools (Suricata/Zeek/Falco/Wazuh): sirf suspicious/malicious
      if (MONITORING_SOURCES.includes(source)) {
        return verdict === "suspicious" || verdict === "malicious"
      }
      // Baaki sources — dikhao by default
      return true
    }

    // Load history
    fetch(`${BASE_URL}/alerts/unified`, {
      headers: { Authorization: `Bearer ${session.accessToken}` },
    })
      .then((res) => res.json())
      .then((data) => {
        const normalized = (data.alerts || []).map((a: any) => {
          const { source, verdict } = normalizeAlert(a.source, a.severity, a.title)
          return { ...a, source, verdict }
        })
        const filtered = normalized.filter((a: any) => shouldShow(a.source, a.verdict))
        const mapped = filtered.map((a: any) => ({
          ip_address: a.title,
          verdict: a.verdict,
          source: a.source,
          signature: a.detail && a.detail !== a.title ? a.detail : a.title,
          checked_at: a.timestamp,
        }))
        setAlerts(mapped)
      })
      .finally(() => setLoading(false))

    // Live updates over WebSocket with auto-reconnect
    let reconnectTimeout: any = null
    let active = true

    function connectWs() {
      if (!active || !session?.accessToken) return
      const ws = new WebSocket(`${WS_URL}?token=${session.accessToken}`)
      wsRef.current = ws

      ws.onopen = () => setConnected(true)
      ws.onclose = () => {
        setConnected(false)
        if (active) {
          reconnectTimeout = setTimeout(connectWs, 3000)
        }
      }
      ws.onerror = () => ws.close()

      ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data)
          if (data.type === "new_alert") {
            const rawSource = data.source || "threat-intel"
            const { source, verdict } = normalizeAlert(rawSource, data.verdict, data.signature)
            if (shouldShow(source, verdict)) {
              setAlerts((prev) => [
                {
                  ip_address: data.ip,
                  verdict,
                  source,
                  signature: data.signature,
                  malicious_signals: data.malicious_signals,
                  checked_at: data.checked_at || new Date().toISOString(),
                },
                ...prev,
              ])
            }
          }
        } catch {}
      }
    }

    connectWs()

    return () => {
      active = false
      if (reconnectTimeout) clearTimeout(reconnectTimeout)
      if (wsRef.current) wsRef.current.close()
    }
  }, [session])

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-slate-100">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 h-96 w-96 rounded-full bg-[#1c2e4a]/40 blur-3xl" />
        <div className="absolute top-40 right-0 h-96 w-96 rounded-full bg-[#1c2e4a]/30 blur-3xl" />
      </div>

      <header className="sticky top-0 z-40 border-b border-white/5 bg-[#0a0a0f]/95 pl-16 sm:pl-20 pr-4 sm:pr-8 py-2.5 backdrop-blur-xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[#1c2e4a] border border-[#1c2e4a] shadow-md shadow-[#1c2e4a]/40">
              <Bell className="h-4 w-4 text-white" />
            </div>
            <div>
              <h1 className="text-sm font-semibold leading-tight text-white">Alerts</h1>
              <p className="text-[10px] text-slate-500 flex items-center gap-1.5">
                <Radio className={`h-2.5 w-2.5 ${connected ? "text-emerald-400" : "text-slate-600"}`} />
                {connected ? "Live" : "Disconnected"}
              </p>
            </div>
          </div>
          <Button
            variant="outline"
            size="xs"
            className="border-white/10 text-slate-300 hover:bg-white/5 text-xs h-7 px-2.5"
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
                <p className="text-white font-mono text-sm">
                  {a.source && a.source !== "threat-intel" && (
                    <span className={`text-xs uppercase mr-2 ${SOURCE_STYLES[a.source] || "text-slate-500"}`}>
                      [{a.source}]
                    </span>
                  )}
                  {a.ip_address || a.ip || a.signature || "Security Alert"}
                </p>
                <p className="text-xs text-slate-500 mt-1">
                  {(a.ip_address || a.ip) && a.signature && <>{a.signature} · </>}
                  {a.malicious_signals !== undefined && <>{a.malicious_signals} signal(s) · </>}
                  {a.checked_at ? <FormattedTime date={a.checked_at} /> : ""}
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