"use client"

import { useState } from "react"
import { signOut } from "next-auth/react"
import { useSessionGuard } from "@/lib/use-session-guard"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Search, Loader2 } from "lucide-react"

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://169.58.221.49:8000"

const INDEX_LABELS: Record<string, string> = {
  threat_indicators: "Threat Indicator",
  suricata_alerts: "Suricata Alert",
  zeek_notices: "Zeek Notice",
  cases: "Case",
}

export default function LogSearch() {
  const session = useSessionGuard()
  const [query, setQuery] = useState("")
  const [loading, setLoading] = useState(false)
  const [results, setResults] = useState<any[]>([])
  const [searched, setSearched] = useState(false)

  async function handleSearch() {
    if (!query) return
    setLoading(true)
    setSearched(true)
    try {
      const res = await fetch(`${BASE_URL}/search?q=${encodeURIComponent(query)}`, {
        headers: { Authorization: `Bearer ${session?.accessToken}` },
      })
      const data = await res.json()
      setResults(data.results || [])
    } catch (e) {
      setResults([])
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-slate-100">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 h-96 w-96 rounded-full bg-[#1c2e4a]/40 blur-3xl" />
        <div className="absolute top-40 right-0 h-96 w-96 rounded-full bg-[#1c2e4a]/30 blur-3xl" />
      </div>

      <header className="sticky top-0 z-40 border-b border-white/5 bg-[#0a0a0f]/95 pl-16 sm:pl-20 pr-4 sm:pr-8 py-2.5 backdrop-blur-xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[#1c2e4a] shadow-md shadow-[#1c2e4a]/40 border border-[#1c2e4a]">
              <Search className="h-4 w-4 text-white" />
            </div>
            <div>
              <h1 className="text-sm font-semibold leading-tight text-white">Log Search</h1>
              <p className="text-[10px] text-slate-500">Unified search across alerts, notices &amp; indicators</p>
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

      <main className="relative p-8 max-w-4xl mx-auto space-y-6">
        <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
          <CardContent className="pt-6">
            <div className="flex gap-3">
              <Input
                placeholder="Search by IP, signature, message..."
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                className="bg-white/5 border-white/10 text-white placeholder:text-slate-500"
              />
              <Button
                onClick={handleSearch}
                disabled={!query || loading}
                className="bg-[#1c2e4a] hover:bg-[#243b61] text-white shadow-sm shadow-[#1c2e4a]/30 border border-[#1c2e4a]"
              >
                {loading ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : null}
                Search
              </Button>
            </div>
          </CardContent>
        </Card>

        {searched && !loading && results.length === 0 && (
          <p className="text-slate-500 text-sm">No results found.</p>
        )}

        {results.length > 0 && (
          <div className="space-y-3">
            {results.map((r, i) => (
              <Card key={i} className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm text-white flex items-center justify-between">
                    <span className="text-blue-400">{INDEX_LABELS[r.index] || r.index}</span>
                    <span className="text-xs text-slate-500 font-normal">
                      score: {r.score?.toFixed(2)}
                    </span>
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <pre className="whitespace-pre-wrap text-sm text-slate-300 leading-relaxed font-sans">
                    {JSON.stringify(
                      Object.fromEntries(
                        Object.entries(r).filter(([k]) => k !== "index" && k !== "score")
                      ),
                      null,
                      2
                    )}
                  </pre>
                </CardContent>
              </Card>
            ))}
          </div>
        )}
      </main>
    </div>
  )
}