"use client"

import { useState } from "react"
import { signOut } from "next-auth/react"
import { useSessionGuard } from "@/lib/use-session-guard"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Shield, Loader2, Sparkles, Bug, FileBarChart } from "lucide-react"

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://169.58.221.49:8000"

const ACTIONS = [
  { key: "explain", label: "Explain IOC", endpoint: (ip: string) => `/ai/explain/${ip}` },
  { key: "rag", label: "RAG Explain", endpoint: (ip: string) => `/ai/rag-explain/${ip}` },
  { key: "recommend", label: "Recommendations", endpoint: (ip: string) => `/ai/recommend/${ip}` },
  { key: "hunt", label: "Threat Hunt Agent", endpoint: (ip: string) => `/agents/threat-hunt/${ip}` },
  { key: "triage", label: "Triage Agent", endpoint: (ip: string) => `/agents/triage/${ip}` },
]

const PERIODS = ["weekly", "monthly", "quarterly"] as const

export default function AIChat() {
  const session = useSessionGuard()
  const [ip, setIp] = useState("")
  const [loadingKey, setLoadingKey] = useState<string | null>(null)
  const [result, setResult] = useState<any>(null)
  const [activeLabel, setActiveLabel] = useState("")

  // Malware Investigation Agent inputs
  const [hash, setHash] = useState("")
  const [filename, setFilename] = useState("")
  const [malwareUrl, setMalwareUrl] = useState("")

  async function runAction(key: string, endpointFn: (ip: string) => string, label: string) {
    if (!ip) return
    setLoadingKey(key)
    setActiveLabel(label)
    setResult(null)
    try {
      const res = await fetch(`${BASE_URL}${endpointFn(ip)}`, {
        headers: { Authorization: `Bearer ${session?.accessToken}` },
      })
      const data = await res.json()
      setResult(data)
    } catch (e) {
      setResult({ error: "Request failed. Check backend is running." })
    } finally {
      setLoadingKey(null)
    }
  }

  async function runMalwareInvestigate() {
    if (!hash && !filename && !malwareUrl) return
    setLoadingKey("malware")
    setActiveLabel("Malware Investigation Agent")
    setResult(null)
    try {
      const res = await fetch(`${BASE_URL}/agents/malware-investigate`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${session?.accessToken}`,
        },
        body: JSON.stringify({
          hash: hash || null,
          filename: filename || null,
          url: malwareUrl || null,
        }),
      })
      const data = await res.json()
      setResult(data)
    } catch (e) {
      setResult({ error: "Request failed. Check backend is running." })
    } finally {
      setLoadingKey(null)
    }
  }

  async function runExecReport(period: string) {
    setLoadingKey(`exec-${period}`)
    setActiveLabel(`Executive Report (${period})`)
    setResult(null)
    try {
      const res = await fetch(`${BASE_URL}/agents/exec-report/${period}`, {
        headers: { Authorization: `Bearer ${session?.accessToken}` },
      })
      const data = await res.json()
      setResult(data)
    } catch (e) {
      setResult({ error: "Request failed. Check backend is running." })
    } finally {
      setLoadingKey(null)
    }
  }

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
              <Sparkles className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight text-white">AI Analyst Console</h1>
              <p className="text-xs text-slate-500">IOC Lookup &amp; Agentic Investigation</p>
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

      <main className="relative p-8 max-w-4xl mx-auto space-y-6">
        {/* IP-based actions */}
        <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
          <CardContent className="pt-6">
            <div className="flex gap-3">
              <Input
                placeholder="Enter an IP address (e.g. 1.1.1.1)"
                value={ip}
                onChange={(e) => setIp(e.target.value)}
                className="bg-white/5 border-white/10 text-white placeholder:text-slate-500"
              />
            </div>
            <div className="mt-4 flex flex-wrap gap-2">
              {ACTIONS.map((action) => (
                <Button
                  key={action.key}
                  onClick={() => runAction(action.key, action.endpoint, action.label)}
                  disabled={!ip || loadingKey !== null}
                  className="bg-gradient-to-br from-violet-600 to-rose-600 hover:opacity-90 text-white"
                >
                  {loadingKey === action.key ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  ) : null}
                  {action.label}
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Malware Investigation Agent */}
        <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
          <CardHeader>
            <CardTitle className="text-base text-white flex items-center gap-2">
              <Bug className="h-4 w-4 text-violet-400" />
              Malware Investigation Agent
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <Input
                placeholder="File hash (optional)"
                value={hash}
                onChange={(e) => setHash(e.target.value)}
                className="bg-white/5 border-white/10 text-white placeholder:text-slate-500"
              />
              <Input
                placeholder="Filename (optional)"
                value={filename}
                onChange={(e) => setFilename(e.target.value)}
                className="bg-white/5 border-white/10 text-white placeholder:text-slate-500"
              />
              <Input
                placeholder="URL (optional)"
                value={malwareUrl}
                onChange={(e) => setMalwareUrl(e.target.value)}
                className="bg-white/5 border-white/10 text-white placeholder:text-slate-500"
              />
            </div>
            <Button
              onClick={runMalwareInvestigate}
              disabled={(!hash && !filename && !malwareUrl) || loadingKey !== null}
              className="mt-4 bg-gradient-to-br from-violet-600 to-rose-600 hover:opacity-90 text-white"
            >
              {loadingKey === "malware" ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
              Investigate
            </Button>
          </CardContent>
        </Card>

        {/* Executive Reporting Agent */}
        <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
          <CardHeader>
            <CardTitle className="text-base text-white flex items-center gap-2">
              <FileBarChart className="h-4 w-4 text-violet-400" />
              Executive Reporting Agent
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-2">
              {PERIODS.map((period) => (
                <Button
                  key={period}
                  onClick={() => runExecReport(period)}
                  disabled={loadingKey !== null}
                  className="bg-gradient-to-br from-violet-600 to-rose-600 hover:opacity-90 text-white capitalize"
                >
                  {loadingKey === `exec-${period}` ? (
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  ) : null}
                  {period} Report
                </Button>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Result */}
        {(result || loadingKey) && (
          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardHeader>
              <CardTitle className="text-base text-white flex items-center gap-2">
                <Shield className="h-4 w-4 text-violet-400" />
                {activeLabel || "Result"}
              </CardTitle>
            </CardHeader>
            <CardContent>
              {loadingKey ? (
                <div className="flex items-center gap-2 text-slate-400 py-8 justify-center">
                  <Loader2 className="h-5 w-5 animate-spin" />
                  Running {activeLabel}...
                </div>
              ) : (
                <pre className="whitespace-pre-wrap text-sm text-slate-300 leading-relaxed font-sans">
                  {JSON.stringify(result, null, 2)}
                </pre>
              )}
            </CardContent>
          </Card>
        )}
      </main>
    </div>
  )
}