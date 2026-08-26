"use client"

import { useEffect, useState } from "react"
import { signOut } from "next-auth/react"
import { useSessionGuard } from "@/lib/use-session-guard"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Radio, Loader2, CheckCircle2, XCircle } from "lucide-react"

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://169.58.221.49:8000"

export default function NetworkStatusPage() {
  const session = useSessionGuard()
  const [status, setStatus] = useState<Record<string, any> | null>(null)
  const [loading, setLoading] = useState(true)

  async function fetchStatus() {
    if (!session?.accessToken) return
    try {
      const res = await fetch(`${BASE_URL}/security-monitoring/status`, {
        headers: { Authorization: `Bearer ${session.accessToken}` },
      })
      setStatus(await res.json())
    } catch (e) {
      setStatus(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchStatus()
    const interval = setInterval(fetchStatus, 15000)
    return () => clearInterval(interval)
  }, [session])

  const TOOL_KEYS = ["suricata", "zeek", "wazuh", "falco"]

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-slate-100">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 h-96 w-96 rounded-full bg-violet-600/10 blur-3xl" />
        <div className="absolute top-40 right-0 h-96 w-96 rounded-full bg-rose-600/10 blur-3xl" />
      </div>

      <header className="relative border-b border-white/5 bg-white/[0.02] pl-20 pr-8 py-5 backdrop-blur-xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-rose-500 shadow-lg shadow-violet-500/20">
              <Radio className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight text-white">Network Monitoring Status</h1>
              <p className="text-xs text-slate-500">Suricata · Zeek · Wazuh · Falco</p>
            </div>
          </div>
          <Button variant="outline" size="sm" className="border-white/10 text-slate-300 hover:bg-white/5" onClick={() => signOut({ callbackUrl: "/" })}>
            Sign Out
          </Button>
        </div>
      </header>

      <main className="relative p-8 max-w-5xl mx-auto space-y-6">
        {loading && (
          <div className="flex items-center gap-2 text-slate-400 py-12 justify-center">
            <Loader2 className="h-5 w-5 animate-spin" />
            Checking monitoring tools...
          </div>
        )}

        {!loading && !status && (
          <Card className="border-rose-500/20 bg-rose-500/5 backdrop-blur-xl">
            <CardContent className="pt-6 text-rose-300">Failed to load status. Check backend is running.</CardContent>
          </Card>
        )}

        {status && (
          <>
            <Card className={`border-white/5 backdrop-blur-xl ${status.overall_healthy ? "bg-teal-500/5" : "bg-orange-500/5"}`}>
              <CardContent className="pt-6 flex items-center gap-3">
                {status.overall_healthy ? <CheckCircle2 className="h-6 w-6 text-teal-400" /> : <XCircle className="h-6 w-6 text-orange-400" />}
                <div>
                  <p className="text-base font-semibold text-white">
                    {status.overall_healthy ? "All monitoring tools active" : "One or more tools not reporting"}
                  </p>
                  <p className="text-xs text-slate-500">Auto-refreshes every 15 seconds</p>
                </div>
              </CardContent>
            </Card>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {TOOL_KEYS.map((key) => {
                const data = status[key]
                if (!data) return null
                return (
                  <Card key={key} className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
                    <CardHeader>
                      <CardTitle className="text-base text-white flex items-center justify-between">
                        {data.label}
                        {data.healthy ? (
                          <span className="flex items-center gap-1 text-xs text-teal-400">
                            <span className="h-2 w-2 rounded-full bg-teal-400 animate-pulse" />
                            Active
                          </span>
                        ) : (
                          <span className="flex items-center gap-1 text-xs text-rose-400">
                            <span className="h-2 w-2 rounded-full bg-rose-400" />
                            Inactive
                          </span>
                        )}
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-2 text-sm">
                      <p className="text-slate-500">{data.monitors}</p>
                      {data.total_alerts_ingested !== undefined && (
                        <p className="text-slate-300">Alerts ingested: <span className="text-white font-medium">{data.total_alerts_ingested}</span></p>
                      )}
                      {data.total_notices_ingested !== undefined && (
                        <p className="text-slate-300">Notices ingested: <span className="text-white font-medium">{data.total_notices_ingested}</span></p>
                      )}
                      {data.core_processes_running !== undefined && (
                        <p className="text-slate-300">Core processes running: <span className="text-white font-medium">{data.core_processes_running}</span></p>
                      )}
                      {data.last_alert_at && <p className="text-slate-500 text-xs">Last alert: {new Date(data.last_alert_at).toLocaleString()}</p>}
                      {data.last_notice_at && <p className="text-slate-500 text-xs">Last notice: {new Date(data.last_notice_at).toLocaleString()}</p>}
                      {data.detail && <p className="text-slate-500 text-xs">{data.detail}</p>}
                      {data.error && <p className="text-rose-400 text-xs">{data.error}</p>}
                    </CardContent>
                  </Card>
                )
              })}
            </div>
          </>
        )}
      </main>
    </div>
  )
}