"use client"

import { useEffect, useState } from "react"
import { signOut } from "next-auth/react"
import { useSessionGuard } from "@/lib/use-session-guard"
import { Button } from "@/components/ui/button"
import { Card, CardContent } from "@/components/ui/card"
import { ShieldAlert, Loader2, Check, X, History } from "lucide-react"

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://169.58.221.49:8000"

const STATUS_COLORS: Record<string, string> = {
  pending: "bg-amber-500/20 text-amber-300",
  approved: "bg-emerald-500/20 text-emerald-300",
  executed: "bg-emerald-500/20 text-emerald-300",
  rejected: "bg-rose-500/20 text-rose-300",
  denied: "bg-rose-500/20 text-rose-300",
  failed: "bg-rose-500/20 text-rose-300",
}

export default function PendingApprovalsPage() {
  const session = useSessionGuard()
  const [pending, setPending] = useState<any[]>([])
  const [auditLog, setAuditLog] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [actingOn, setActingOn] = useState<number | null>(null)
  const [showAudit, setShowAudit] = useState(false)

  const headers = { Authorization: `Bearer ${session?.accessToken}`, "Content-Type": "application/json" }

  function loadPending() {
    fetch(`${BASE_URL}/agents/pending-approvals`, { headers })
      .then((res) => res.json())
      .then((data) => setPending(Array.isArray(data) ? data : []))
      .finally(() => setLoading(false))
  }

  function loadAuditLog() {
    fetch(`${BASE_URL}/agents/audit-log`, { headers })
      .then((res) => res.json())
      .then((data) => setAuditLog(Array.isArray(data) ? data : []))
  }

  useEffect(() => {
    if (session?.accessToken) {
      loadPending()
      loadAuditLog()
    }
  }, [session])

  async function handleApprove(id: number) {
    setActingOn(id)
    await fetch(`${BASE_URL}/agents/approve/${id}`, { method: "POST", headers })
    setActingOn(null)
    loadPending()
    loadAuditLog()
  }

  async function handleReject(id: number) {
    const reason = window.prompt("Reason for rejecting this action (optional):") || ""
    setActingOn(id)
    await fetch(`${BASE_URL}/agents/reject/${id}?reason=${encodeURIComponent(reason)}`, { method: "POST", headers })
    setActingOn(null)
    loadPending()
    loadAuditLog()
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
              <ShieldAlert className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight text-white">Pending Approvals</h1>
              <p className="text-xs text-slate-500">Agent-proposed actions awaiting human review</p>
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

      <main className="relative p-8 max-w-4xl mx-auto space-y-4">
        {loading && (
          <div className="flex items-center gap-2 text-slate-400 py-12 justify-center">
            <Loader2 className="h-5 w-5 animate-spin" />
            Loading pending approvals...
          </div>
        )}

        {!loading && pending.length === 0 && (
          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="pt-6 text-center text-slate-400 py-12">
              No actions awaiting approval. Agent-proposed destructive actions will show up here.
            </CardContent>
          </Card>
        )}

        {pending.map((a) => (
          <Card key={a.id} className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="pt-6 space-y-3">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-white font-medium">
                    {a.agent_name} → {a.action_name}
                  </p>
                  <p className="text-xs text-slate-500 mt-1">
                    Target: {a.target} · Requested: {new Date(a.requested_at).toLocaleString()}
                  </p>
                </div>
                <span className={`text-xs px-2 py-1 rounded-full ${STATUS_COLORS.pending}`}>pending</span>
              </div>
              {a.reasoning && (
                <p className="text-sm text-slate-400 border-l-2 border-white/10 pl-3">{a.reasoning}</p>
              )}
              <div className="flex gap-2 pt-1">
                <Button
                  onClick={() => handleApprove(a.id)}
                  disabled={actingOn === a.id}
                  size="sm"
                  className="bg-emerald-600 hover:bg-emerald-700 text-white"
                >
                  {actingOn === a.id ? <Loader2 className="h-4 w-4 animate-spin" /> : <Check className="h-4 w-4 mr-1" />}
                  Approve
                </Button>
                <Button
                  onClick={() => handleReject(a.id)}
                  disabled={actingOn === a.id}
                  size="sm"
                  variant="outline"
                  className="border-rose-500/30 text-rose-300 hover:bg-rose-500/10"
                >
                  <X className="h-4 w-4 mr-1" />
                  Reject
                </Button>
              </div>
            </CardContent>
          </Card>
        ))}

        <div className="pt-6">
          <Button
            variant="outline"
            size="sm"
            className="border-white/10 text-slate-300 hover:bg-white/5"
            onClick={() => setShowAudit(!showAudit)}
          >
            <History className="h-4 w-4 mr-2" />
            {showAudit ? "Hide" : "Show"} Audit Log
          </Button>
        </div>

        {showAudit && (
          <div className="space-y-3">
            {auditLog.length === 0 && (
              <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
                <CardContent className="pt-6 text-center text-slate-400 py-8">
                  No agent actions logged yet.
                </CardContent>
              </Card>
            )}
            {auditLog.map((a) => (
              <Card key={a.id} className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
                <CardContent className="pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-white font-medium">
                        {a.agent_name} → {a.action_name}
                      </p>
                      <p className="text-xs text-slate-500 mt-1">
                        Target: {a.target} · {new Date(a.requested_at).toLocaleString()}
                        {a.decided_by && ` · Decided by: ${a.decided_by}`}
                      </p>
                    </div>
                    <span className={`text-xs px-2 py-1 rounded-full ${STATUS_COLORS[a.status] || STATUS_COLORS.pending}`}>
                      {a.status}
                    </span>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </main>
    </div>
  )
}