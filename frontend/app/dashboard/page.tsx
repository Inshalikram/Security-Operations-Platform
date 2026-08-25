import { auth, signOut } from "@/auth"
import { redirect } from "next/navigation"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Shield, AlertTriangle, ShieldAlert, Activity } from "lucide-react"
import DashboardChart from "@/components/dashboard-chart"

type ThreatRecord = {
  ip: string
  verdict: string
  malicious_signals: number
  sources_checked: string[]
  checked_at: string
}

async function getHistory(token: string): Promise<ThreatRecord[]> {
  const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/threat-intel/history`, {
    headers: { Authorization: `Bearer ${token}` },
    cache: "no-store",
  })
  if (!res.ok) return []
  return res.json()
}

function verdictBadgeClass(verdict: string) {
  if (verdict === "malicious") return "bg-rose-500/10 text-rose-400 border-rose-500/30"
  if (verdict === "suspicious") return "bg-orange-500/10 text-orange-400 border-orange-500/30"
  return "bg-teal-500/10 text-teal-400 border-teal-500/30"
}

export default async function Dashboard() {
  const session = await auth()
  if (!session) redirect("/")
  if (session.error === "RefreshAccessTokenError") redirect("/api/auth/signin")

  const history = await getHistory(session.accessToken as string)
  const malicious = history.filter((h) => h.verdict === "malicious").length
  const suspicious = history.filter((h) => h.verdict === "suspicious").length
  const clean = history.filter((h) => h.verdict === "clean").length

  const chartData = [
    { name: "Malicious", value: malicious, color: "#fb7185" },
    { name: "Suspicious", value: suspicious, color: "#fb923c" },
    { name: "Clean", value: clean, color: "#2dd4bf" },
  ]

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-slate-100">
      {/* Ambient glow background */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 h-96 w-96 rounded-full bg-violet-600/10 blur-3xl" />
        <div className="absolute top-40 right-0 h-96 w-96 rounded-full bg-rose-600/10 blur-3xl" />
      </div>

      {/* Header */}
      <header className="relative border-b border-white/5 bg-white/[0.02] pl-20 pr-8 py-5 backdrop-blur-xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-rose-500 shadow-lg shadow-violet-500/20">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight text-white">SOC Dashboard</h1>
              <p className="text-xs text-slate-500">Security Operations Platform</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <div className="text-right">
              <p className="text-sm font-medium leading-tight text-white">
                {session.user?.name || session.user?.email}
              </p>
              <p className="text-xs text-slate-500">Analyst</p>
            </div>
            <div className="flex h-9 w-9 items-center justify-center rounded-full bg-gradient-to-br from-violet-500 to-rose-500 text-sm font-medium text-white">
              {(session.user?.name || "U").charAt(0)}
            </div>
            <form
              action={async () => {
                "use server"
                await signOut({ redirectTo: "/" })
              }}
            >
              <Button type="submit" variant="outline" size="sm" className="border-white/10 text-slate-300 hover:bg-white/5">
                Sign Out
              </Button>
            </form>
          </div>
        </div>
      </header>

      <main className="relative p-8 space-y-6">
        {/* Stat cards */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="flex items-center justify-between pt-6">
              <div>
                <p className="text-sm text-slate-500">Total Checked</p>
                <p className="text-3xl font-bold text-white">{history.length}</p>
              </div>
              <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-violet-500/10">
                <Activity className="h-5 w-5 text-violet-400" />
              </div>
            </CardContent>
          </Card>

          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="flex items-center justify-between pt-6">
              <div>
                <p className="text-sm text-slate-500">Malicious</p>
                <p className="text-3xl font-bold text-rose-400">{malicious}</p>
              </div>
              <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-rose-500/10">
                <ShieldAlert className="h-5 w-5 text-rose-400" />
              </div>
            </CardContent>
          </Card>

          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="flex items-center justify-between pt-6">
              <div>
                <p className="text-sm text-slate-500">Suspicious</p>
                <p className="text-3xl font-bold text-orange-400">{suspicious}</p>
              </div>
              <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-orange-500/10">
                <AlertTriangle className="h-5 w-5 text-orange-400" />
              </div>
            </CardContent>
          </Card>

          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="flex items-center justify-between pt-6">
              <div>
                <p className="text-sm text-slate-500">Clean</p>
                <p className="text-3xl font-bold text-teal-400">{clean}</p>
              </div>
              <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-teal-500/10">
                <Shield className="h-5 w-5 text-teal-400" />
              </div>
            </CardContent>
          </Card>
        </div>

        <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
          {/* Chart */}
          <Card className="lg:col-span-1 border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardHeader>
              <CardTitle className="text-base text-white">Verdict Breakdown</CardTitle>
            </CardHeader>
            <CardContent>
              <DashboardChart data={chartData} />
            </CardContent>
          </Card>

          {/* Table */}
          <Card className="lg:col-span-2 border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardHeader>
              <CardTitle className="text-base text-white">Recent Threat Checks</CardTitle>
            </CardHeader>
            <CardContent>
              <Table>
                <TableHeader>
                  <TableRow className="border-white/5 hover:bg-transparent">
                    <TableHead className="text-slate-500">IP Address</TableHead>
                    <TableHead className="text-slate-500">Verdict</TableHead>
                    <TableHead className="text-slate-500">Signals</TableHead>
                    <TableHead className="text-slate-500">Checked At</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {history.length === 0 ? (
                    <TableRow className="border-white/5">
                      <TableCell colSpan={4} className="text-center text-slate-600 py-8">
                        No records yet
                      </TableCell>
                    </TableRow>
                  ) : (
                    history.slice(0, 10).map((record, i) => (
                      <TableRow key={i} className="border-white/5 hover:bg-white/[0.03]">
                        <TableCell className="font-mono text-sm text-slate-300">{record.ip}</TableCell>
                        <TableCell>
                          <Badge className={verdictBadgeClass(record.verdict)} variant="outline">
                            {record.verdict}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-slate-400">{record.malicious_signals}</TableCell>
                        <TableCell className="text-sm text-slate-600">
                          {new Date(record.checked_at).toLocaleString()}
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  )
}