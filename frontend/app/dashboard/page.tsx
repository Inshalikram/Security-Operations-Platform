import { auth } from "@/auth"
import { redirect } from "next/navigation"
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
    <DashboardView
      initialStats={initialStats}
      initialHistory={history}
      token={token}
      user={session.user}
    />
  )
}