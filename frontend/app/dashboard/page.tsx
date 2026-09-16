import { auth, signOut } from "@/auth"
import { redirect } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Shield } from "lucide-react"
import DashboardView, { ThreatStats } from "@/components/dashboard-view"
import { ThreatRecord } from "@/components/dashboard-table"

async function getStats(token: string): Promise<ThreatStats | null> {
  try {
    const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/threat-intel/stats`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    })
    if (!res.ok) return null
    return res.json()
  } catch {
    return null
  }
}

async function getHistory(token: string): Promise<ThreatRecord[]> {
  try {
    const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/threat-intel/history?limit=100`, {
      headers: { Authorization: `Bearer ${token}` },
      cache: "no-store",
    })
    if (!res.ok) return []
    return res.json()
  } catch {
    return []
  }
}

export default async function Dashboard() {
  const session = await auth()
  if (!session) redirect("/")
  if (session.error === "RefreshAccessTokenError") redirect("/api/auth/signin")

  const token = session.accessToken as string
  const [statsData, history] = await Promise.all([
    getStats(token),
    getHistory(token),
  ])

  const initialStats: ThreatStats = statsData || {
    total: history.length,
    malicious: history.filter((h) => h.verdict === "malicious").length,
    suspicious: history.filter((h) => h.verdict === "suspicious").length,
    clean: history.filter((h) => h.verdict === "clean").length,
  }

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

      <main className="relative p-8">
        <DashboardView
          initialStats={initialStats}
          initialHistory={history}
          token={token}
        />
      </main>
    </div>
  )
}