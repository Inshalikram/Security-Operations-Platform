"use client"

import { useState } from "react"
import { signOut } from "next-auth/react"
import { useSessionGuard } from "@/lib/use-session-guard"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Shield, Loader2, Sparkles, Bug, FileBarChart, ShieldAlert, Check, X, Terminal, ChevronDown, ChevronUp, Activity, Target, AlertCircle } from "lucide-react"

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://169.58.221.49:8000"

const ACTIONS = [
  { key: "explain", label: "Explain IOC", endpoint: (ip: string) => `/ai/explain/${ip}` },
  { key: "rag", label: "RAG Explain", endpoint: (ip: string) => `/ai/rag-explain/${ip}` },
  { key: "recommend", label: "Recommendations", endpoint: (ip: string) => `/ai/recommend/${ip}` },
  { key: "hunt", label: "Threat Hunt Agent", endpoint: (ip: string) => `/agents/threat-hunt/${ip}` },
  { key: "triage", label: "Triage Agent", endpoint: (ip: string) => `/agents/triage/${ip}` },
]

const PERIODS = ["weekly", "monthly", "quarterly"] as const

function parseInline(text: string): React.ReactNode {
  if (!text) return null
  const regex = /(`[^`]+`|\*\*\*[^*]+\*\*\*|\*\*[^*]+\*\*|\*[^*]+\*)/g
  const parts = text.split(regex)

  return parts.map((part, index) => {
    if (part.startsWith("`") && part.endsWith("`")) {
      return (
        <code
          key={index}
          className="px-1.5 py-0.5 mx-0.5 rounded bg-violet-500/15 border border-violet-500/25 text-violet-300 font-mono text-xs"
        >
          {part.slice(1, -1)}
        </code>
      )
    }
    if (part.startsWith("***") && part.endsWith("***")) {
      return (
        <strong key={index} className="font-bold italic text-white">
          {part.slice(3, -3)}
        </strong>
      )
    }
    if (part.startsWith("**") && part.endsWith("**")) {
      return (
        <strong key={index} className="font-semibold text-white">
          {part.slice(2, -2)}
        </strong>
      )
    }
    if (part.startsWith("*") && part.endsWith("*")) {
      return (
        <em key={index} className="italic text-slate-200">
          {part.slice(1, -1)}
        </em>
      )
    }
    return part
  })
}

function FormattedReportView({ content }: { content: string }) {
  if (!content) return null

  const normalized = content.replace(/\\n/g, "\n").replace(/\r\n/g, "\n")
  const lines = normalized.split("\n")

  const elements: React.ReactNode[] = []
  let currentList: { type: "bullet" | "number"; items: { text: string; num?: string; indent: number }[] } | null = null

  function flushList() {
    if (!currentList) return
    const key = `list-${elements.length}`
    if (currentList.type === "number") {
      elements.push(
        <div key={key} className="space-y-3 my-3">
          {currentList.items.map((item, idx) => (
            <div key={idx} className="flex items-start gap-3 pl-0.5">
              <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-lg bg-violet-500/20 border border-violet-500/30 text-xs font-semibold text-violet-300">
                {item.num || idx + 1}
              </span>
              <div className="text-slate-300 leading-relaxed pt-0.5">{parseInline(item.text)}</div>
            </div>
          ))}
        </div>
      )
    } else {
      elements.push(
        <ul key={key} className="space-y-2 my-2.5">
          {currentList.items.map((item, idx) => (
            <li
              key={idx}
              className={`flex items-start gap-2.5 text-slate-300 leading-relaxed ${
                item.indent > 0 ? "ml-6" : "ml-2"
              }`}
            >
              <span className="text-violet-400 mt-1.5 text-xs select-none">•</span>
              <div className="flex-1">{parseInline(item.text)}</div>
            </li>
          ))}
        </ul>
      )
    }
    currentList = null
  }

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i]
    const trimmed = rawLine.trim()

    if (!trimmed) {
      flushList()
      continue
    }

    if (trimmed === "---" || trimmed === "***" || trimmed === "___") {
      flushList()
      elements.push(<hr key={`hr-${i}`} className="border-white/10 my-4" />)
      continue
    }

    if (trimmed.startsWith("#")) {
      flushList()
      const level = trimmed.match(/^#+/)?.[0].length || 1
      const title = trimmed.replace(/^#+\s*/, "")
      elements.push(
        <div key={`h-${i}`} className="mt-4 mb-2 pt-1 flex items-center gap-2">
          <div className="h-2 w-2 rounded-full bg-violet-400 shadow-sm shadow-violet-400/50" />
          <h4
            className={`font-semibold text-white tracking-tight ${
              level <= 2 ? "text-base" : "text-sm"
            }`}
          >
            {parseInline(title)}
          </h4>
        </div>
      )
      continue
    }

    const numMatch = trimmed.match(/^(\d+)\.\s+(.*)$/)
    if (numMatch) {
      if (!currentList || currentList.type !== "number") {
        flushList()
        currentList = { type: "number", items: [] }
      }
      currentList.items.push({ text: numMatch[2], num: numMatch[1], indent: 0 })
      continue
    }

    const bulletMatch = rawLine.match(/^(\s*)[*•-]\s+(.*)$/)
    if (bulletMatch) {
      const indent = bulletMatch[1].length
      if (!currentList || currentList.type !== "bullet") {
        flushList()
        currentList = { type: "bullet", items: [] }
      }
      currentList.items.push({ text: bulletMatch[2], indent })
      continue
    }

    flushList()
    elements.push(
      <p key={`p-${i}`} className="text-slate-300 leading-relaxed my-2 text-sm">
        {parseInline(trimmed)}
      </p>
    )
  }

  flushList()
  return <div className="space-y-1">{elements}</div>
}

export default function AIChat() {
  const session = useSessionGuard()
  const [ip, setIp] = useState("")
  const [loadingKey, setLoadingKey] = useState<string | null>(null)
  const [result, setResult] = useState<any>(null)
  const [activeLabel, setActiveLabel] = useState("")

  const [showRaw, setShowRaw] = useState(false)

  // Malware Investigation Agent inputs
  const [hash, setHash] = useState("")
  const [filename, setFilename] = useState("")
  const [malwareUrl, setMalwareUrl] = useState("")

  // Governance — pending action shown inline after Triage Agent runs
  const [pendingActionId, setPendingActionId] = useState<number | null>(null)
  const [decisionStatus, setDecisionStatus] = useState<string | null>(null) // "executed" | "rejected" | null
  const [decidingAction, setDecidingAction] = useState(false)

  const authHeaders = { Authorization: `Bearer ${session?.accessToken}` }

  async function runAction(key: string, endpointFn: (ip: string) => string, label: string) {
    if (!ip) return
    setLoadingKey(key)
    setActiveLabel(label)
    setResult(null)
    setShowRaw(false)
    setPendingActionId(null)
    setDecisionStatus(null)
    try {
      const res = await fetch(`${BASE_URL}${endpointFn(ip)}`, { headers: authHeaders })
      const data = await res.json()
      setResult(data)
      if (data?.proposed_action?.status === "pending_approval") {
        setPendingActionId(data.proposed_action.action_id)
      }
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
    setShowRaw(false)
    setPendingActionId(null)
    setDecisionStatus(null)
    try {
      const res = await fetch(`${BASE_URL}/agents/malware-investigate`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...authHeaders },
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
    setShowRaw(false)
    setPendingActionId(null)
    setDecisionStatus(null)
    try {
      const res = await fetch(`${BASE_URL}/agents/exec-report/${period}`, { headers: authHeaders })
      const data = await res.json()
      setResult(data)
    } catch (e) {
      setResult({ error: "Request failed. Check backend is running." })
    } finally {
      setLoadingKey(null)
    }
  }

  async function handleApproveAction() {
    if (!pendingActionId) return
    setDecidingAction(true)
    try {
      const res = await fetch(`${BASE_URL}/agents/approve/${pendingActionId}`, {
        method: "POST",
        headers: authHeaders,
      })
      const data = await res.json()
      setDecisionStatus(data?.status || "executed")
    } catch (e) {
      setDecisionStatus("error")
    } finally {
      setDecidingAction(false)
    }
  }

  async function handleRejectAction() {
    if (!pendingActionId) return
    const reason = window.prompt("Reason for rejecting this action (optional):") || ""
    setDecidingAction(true)
    try {
      const res = await fetch(
        `${BASE_URL}/agents/reject/${pendingActionId}?reason=${encodeURIComponent(reason)}`,
        { method: "POST", headers: authHeaders }
      )
      const data = await res.json()
      setDecisionStatus(data?.status || "rejected")
    } catch (e) {
      setDecisionStatus("error")
    } finally {
      setDecidingAction(false)
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
              ) : result?.error ? (
                <div className="flex items-start gap-3 p-4 rounded-xl border border-rose-500/30 bg-rose-500/10 text-rose-300">
                  <AlertCircle className="h-5 w-5 shrink-0 mt-0.5" />
                  <div>
                    <p className="font-semibold text-sm">Execution Notice</p>
                    <p className="text-xs text-rose-200/90 mt-1 leading-relaxed">{result.error}</p>
                  </div>
                </div>
              ) : (
                <div className="space-y-4">
                  {/* Meta Badges Header */}
                  <div className="flex flex-wrap items-center gap-2 pb-3 border-b border-white/5">
                    {(result.ip || ip) && (
                      <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-white/5 border border-white/10 text-xs font-mono text-slate-300">
                        <Target className="h-3 w-3 text-violet-400" />
                        {result.ip || ip}
                      </span>
                    )}
                    {(result.verdict || result.findings?.threat_intel?.overall_verdict) && (
                      <span
                        className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold uppercase tracking-wider border ${
                          (result.verdict || result.findings?.threat_intel?.overall_verdict) === "malicious"
                            ? "bg-rose-500/20 text-rose-300 border-rose-500/30 shadow-sm shadow-rose-500/10"
                            : (result.verdict || result.findings?.threat_intel?.overall_verdict) === "suspicious"
                            ? "bg-amber-500/20 text-amber-300 border-amber-500/30"
                            : "bg-emerald-500/20 text-emerald-300 border-emerald-500/30"
                        }`}
                      >
                        Verdict: {result.verdict || result.findings?.threat_intel?.overall_verdict}
                      </span>
                    )}
                    {(result.severity || result.risk_level) && (
                      <span
                        className={`inline-flex items-center px-2.5 py-1 rounded-full text-xs font-semibold border ${
                          ["Critical", "High"].includes(result.severity || result.risk_level)
                            ? "bg-red-500/20 text-red-300 border-red-500/30"
                            : ["Medium"].includes(result.severity || result.risk_level)
                            ? "bg-amber-500/20 text-amber-300 border-amber-500/30"
                            : "bg-blue-500/20 text-blue-300 border-blue-500/30"
                        }`}
                      >
                        Severity: {result.severity || result.risk_level}
                      </span>
                    )}
                    {result.assigned_to && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-violet-500/10 border border-violet-500/20 text-xs text-violet-300">
                        Assigned: {result.assigned_to}
                      </span>
                    )}
                    {result.period && (
                      <span className="inline-flex items-center gap-1 px-2.5 py-1 rounded-full bg-violet-500/10 border border-violet-500/20 text-xs text-violet-300 capitalize">
                        Period: {result.period}
                      </span>
                    )}
                  </div>

                  {/* Threat Intel Telemetry Quick Stats (If Available) */}
                  {(() => {
                    const ti = result.findings?.threat_intel?.details || result.details || result.vt_findings
                    if (!ti || (!ti.abuseipdb && !ti.virustotal && !ti.otx && !ti.malicious_votes && !ti.malicious)) return null
                    return (
                      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2.5 my-3">
                        {ti.abuseipdb && (
                          <div className="p-2.5 rounded-lg bg-white/[0.02] border border-white/5">
                            <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">AbuseIPDB</div>
                            <div className="text-sm font-bold text-rose-300 mt-0.5">
                              {ti.abuseipdb.abuse_confidence_score ?? 0}% Score
                            </div>
                            <div className="text-[11px] text-slate-500">
                              {ti.abuseipdb.total_reports ?? 0} Reports
                            </div>
                          </div>
                        )}
                        {(ti.virustotal || ti.malicious !== undefined) && (
                          <div className="p-2.5 rounded-lg bg-white/[0.02] border border-white/5">
                            <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">VirusTotal</div>
                            <div className="text-sm font-bold text-white mt-0.5">
                              {ti.virustotal?.malicious_votes ?? ti.malicious ?? 0} Detections
                            </div>
                            <div className="text-[11px] text-slate-500">
                              Country: {ti.virustotal?.country || "Scanned"}
                            </div>
                          </div>
                        )}
                        {ti.otx && (
                          <div className="p-2.5 rounded-lg bg-white/[0.02] border border-white/5">
                            <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">AlienVault OTX</div>
                            <div className="text-sm font-bold text-amber-300 mt-0.5">
                              {ti.otx.pulse_count ?? 0} Pulses
                            </div>
                            <div className="text-[11px] text-slate-500">
                              Threat Feeds
                            </div>
                          </div>
                        )}
                        {ti.shodan && (
                          <div className="p-2.5 rounded-lg bg-white/[0.02] border border-white/5">
                            <div className="text-[10px] font-semibold text-slate-400 uppercase tracking-wider">Shodan</div>
                            <div className="text-sm font-bold text-white mt-0.5">
                              {Array.isArray(ti.shodan.vulns) ? ti.shodan.vulns.length : 0} CVEs
                            </div>
                            <div className="text-[11px] text-slate-500">
                              {Array.isArray(ti.shodan.open_ports) ? `${ti.shodan.open_ports.length} Open Ports` : "Scanned"}
                            </div>
                          </div>
                        )}
                      </div>
                    )
                  })()}

                  {/* Agent Execution Trace Stepper */}
                  {Array.isArray(result.steps_taken) && result.steps_taken.length > 0 && (
                    <div className="rounded-xl border border-white/5 bg-white/[0.02] p-3.5 my-3">
                      <div className="text-xs font-semibold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                        <Activity className="h-3.5 w-3.5 text-violet-400" />
                        Agent Execution Trace
                      </div>
                      <div className="space-y-1.5">
                        {result.steps_taken.map((step: string, sIdx: number) => (
                          <div key={sIdx} className="text-xs text-slate-300 flex items-center gap-2">
                            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 shadow-sm shadow-emerald-400/50" />
                            <span>{step}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Main AI Report / Explanation Content (Clean Formatted Markdown, NO RAW QUOTES) */}
                  {(() => {
                    const mainText =
                      result.investigation_report ||
                      result.recommendations ||
                      result.ai_explanation ||
                      result.rag_explanation ||
                      result.report ||
                      result.reasoning ||
                      result.containment_recommendation ||
                      result.explanation ||
                      result.mitre_mapping ||
                      result.executive_summary

                    if (mainText && typeof mainText === "string") {
                      return <FormattedReportView content={mainText} />
                    }

                    // Fallback to clean key-value presentation if non-string
                    return (
                      <div className="space-y-2 py-2">
                        {Object.entries(result).map(([k, v]) => {
                          if (["ip", "verdict", "severity", "assigned_to", "steps_taken", "details", "findings", "proposed_action"].includes(k)) return null
                          return (
                            <div key={k} className="text-sm">
                              <span className="text-violet-400 font-semibold uppercase text-xs tracking-wider mr-2">{k}:</span>
                              <span className="text-slate-300">{typeof v === "object" ? JSON.stringify(v) : String(v)}</span>
                            </div>
                          )
                        })}
                      </div>
                    )
                  })()}

                  {/* Technical JSON Toggle for Debugging/Advanced Analysis */}
                  <div className="mt-6 pt-3 border-t border-white/5 flex items-center justify-between">
                    <button
                      type="button"
                      onClick={() => setShowRaw(!showRaw)}
                      className="inline-flex items-center gap-1.5 text-xs text-slate-500 hover:text-slate-300 transition-colors"
                    >
                      <Terminal className="h-3.5 w-3.5" />
                      {showRaw ? "Hide Raw Technical JSON" : "View Raw Technical JSON"}
                      {showRaw ? <ChevronUp className="h-3 w-3 ml-0.5" /> : <ChevronDown className="h-3 w-3 ml-0.5" />}
                    </button>
                  </div>

                  {showRaw && (
                    <pre className="mt-3 p-3 rounded-lg bg-black/50 border border-white/5 text-xs font-mono text-slate-400 overflow-x-auto leading-relaxed">
                      {JSON.stringify(result, null, 2)}
                    </pre>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Governance — appears automatically when the agent proposed a destructive action */}
        {pendingActionId && !decisionStatus && (
          <Card className="border-amber-500/30 bg-amber-500/[0.06] backdrop-blur-xl">
            <CardHeader>
              <CardTitle className="text-base text-amber-300 flex items-center gap-2">
                <ShieldAlert className="h-4 w-4" />
                Action Pending Approval
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-slate-300">
                The Triage Agent proposed a <span className="font-medium text-amber-300">block_ip</span> action
                on <span className="font-medium text-white">{ip}</span>. This is a destructive action and
                requires human approval before it executes.
              </p>
              <div className="flex gap-2">
                <Button
                  onClick={handleApproveAction}
                  disabled={decidingAction}
                  className="bg-emerald-600 hover:bg-emerald-700 text-white"
                >
                  {decidingAction ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Check className="h-4 w-4 mr-2" />}
                  Approve
                </Button>
                <Button
                  onClick={handleRejectAction}
                  disabled={decidingAction}
                  variant="outline"
                  className="border-rose-500/30 text-rose-300 hover:bg-rose-500/10"
                >
                  <X className="h-4 w-4 mr-2" />
                  Reject
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {decisionStatus && (
          <Card
            className={`backdrop-blur-xl ${
              decisionStatus === "executed"
                ? "border-emerald-500/30 bg-emerald-500/[0.06]"
                : decisionStatus === "rejected"
                ? "border-rose-500/30 bg-rose-500/[0.06]"
                : "border-white/5 bg-white/[0.03]"
            }`}
          >
            <CardContent className="pt-6">
              <p
                className={`text-sm font-medium ${
                  decisionStatus === "executed"
                    ? "text-emerald-300"
                    : decisionStatus === "rejected"
                    ? "text-rose-300"
                    : "text-slate-300"
                }`}
              >
                {decisionStatus === "executed" && `Action approved and executed — ${ip} has been blocked.`}
                {decisionStatus === "rejected" && `Action rejected — ${ip} was not blocked.`}
                {decisionStatus === "error" && "Something went wrong recording your decision. Try again."}
              </p>
            </CardContent>
          </Card>
        )}
      </main>
    </div>
  )
}