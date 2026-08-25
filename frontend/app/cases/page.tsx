"use client"

import { useEffect, useState } from "react"
import { signOut } from "next-auth/react"
import { useSessionGuard } from "@/lib/use-session-guard"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { FolderOpen, Loader2, AlertTriangle } from "lucide-react"

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://169.58.221.49:8000"

const SEVERITY_COLORS: Record<number, string> = {
  1: "bg-slate-500/20 text-slate-300",
  2: "bg-amber-500/20 text-amber-300",
  3: "bg-rose-500/20 text-rose-300",
}

export default function CasesPage() {
  const session= useSessionGuard()
  const [cases, setCases] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!session?.accessToken) return
    fetch(`${BASE_URL}/cases`, {
      headers: { Authorization: `Bearer ${session.accessToken}` },
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.error) setError(data.error)
        else setCases(data.cases || [])
      })
      .catch(() => setError("Failed to load cases. Check backend is running."))
      .finally(() => setLoading(false))
  }, [session])

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
              <FolderOpen className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight text-white">Cases</h1>
              <p className="text-xs text-slate-500">TheHive incident tracking</p>
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

      <main className="relative p-8 max-w-5xl mx-auto space-y-4">
        {loading && (
          <div className="flex items-center gap-2 text-slate-400 py-12 justify-center">
            <Loader2 className="h-5 w-5 animate-spin" />
            Loading cases...
          </div>
        )}

        {error && (
          <Card className="border-rose-500/20 bg-rose-500/5 backdrop-blur-xl">
            <CardContent className="pt-6 flex items-center gap-2 text-rose-300">
              <AlertTriangle className="h-4 w-4" />
              {error}
            </CardContent>
          </Card>
        )}

        {!loading && !error && cases.length === 0 && (
          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="pt-6 text-center text-slate-400 py-12">
              No cases yet. Cases are auto-created when a threat check finds a suspicious or malicious verdict.
            </CardContent>
          </Card>
        )}

        {cases.map((c) => (
          <Card key={c.id} className="border-white/5 bg-white/[0.03] backdrop-blur-xl hover:bg-white/[0.05] transition-colors">
            <CardHeader className="flex flex-row items-center justify-between space-y-0">
              <CardTitle className="text-base text-white">{c.title}</CardTitle>
              <span className={`text-xs px-2 py-1 rounded-full ${SEVERITY_COLORS[c.severity] || "bg-slate-500/20 text-slate-300"}`}>
                Severity {c.severity}
              </span>
            </CardHeader>
            <CardContent>
              <p className="text-sm text-slate-400 mb-3">{c.description}</p>
              <div className="flex flex-wrap gap-2 mb-2">
                {(c.tags || []).map((tag: string) => (
                  <span key={tag} className="text-xs px-2 py-0.5 rounded-full bg-violet-500/10 text-violet-300 border border-violet-500/20">
                    {tag}
                  </span>
                ))}
              </div>
              <div className="flex items-center justify-between text-xs text-slate-500">
                <span>Status: {c.status || "Open"}</span>
                <span>{c.created_at ? new Date(c.created_at).toLocaleString() : ""}</span>
              </div>
            </CardContent>
          </Card>
        ))}
      </main>
    </div>
  )
}