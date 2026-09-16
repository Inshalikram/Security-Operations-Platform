"use client"

import React, { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Shield, AlertTriangle, ShieldAlert, Activity, Clock, Loader2 } from "lucide-react"
import { Button } from "@/components/ui/button"
import { signOut } from "next-auth/react"
import DashboardChart from "@/components/dashboard-chart"
import DashboardTable, { ThreatRecord } from "@/components/dashboard-table"

export type ThreatStats = {
  time_range?: string
  total: number
  malicious: number
  suspicious: number
  clean: number
}

interface DashboardViewProps {
  initialStats: ThreatStats
  initialHistory: ThreatRecord[]
  token: string
  user?: {
    name?: string | null
    email?: string | null
  }
}

const TIME_RANGES = [
  { id: "24h", label: "24h", fullLabel: "Past 24 hours" },
  { id: "7d", label: "7d", fullLabel: "Past 7 days" },
  { id: "30d", label: "30d", fullLabel: "Past 30 days" },
  { id: "all", label: "All Time", fullLabel: "Lifetime total" },
] as const

type TimeRangeId = (typeof TIME_RANGES)[number]["id"]

export default function DashboardView({
  initialStats,
  initialHistory,
  token,
  user,
}: DashboardViewProps) {
  const [selectedRange, setSelectedRange] = useState<TimeRangeId>("all")
  const [stats, setStats] = useState<ThreatStats>(initialStats)
  const [history, setHistory] = useState<ThreatRecord[]>(initialHistory)
  const [isLoading, setIsLoading] = useState(false)

  const handleRangeChange = async (range: TimeRangeId) => {
    if (range === selectedRange || isLoading) return
    setSelectedRange(range)
    setIsLoading(true)

    try {
      let statsUpdated = false
      let historyUpdated = false

      // 1. Try Next.js internal API proxy route (same-origin, automatic auth session)
      try {
        const [statsRes, historyRes] = await Promise.all([
          fetch(`/api/threat-intel/stats?time_range=${range}`, { cache: "no-store" }),
          fetch(`/api/threat-intel/history?time_range=${range}&limit=100`, { cache: "no-store" }),
        ])

        if (statsRes.ok) {
          const statsData = await statsRes.json()
          if (statsData && typeof statsData.total === "number") {
            setStats(statsData)
            statsUpdated = true
          }
        }
        if (historyRes.ok) {
          const historyData = await historyRes.json()
          if (Array.isArray(historyData)) {
            setHistory(historyData)
            historyUpdated = true
          }
        }
      } catch (proxyErr) {
        console.warn("Proxy route fetch failed, trying direct endpoint:", proxyErr)
      }

      // 2. Direct fallback to backend API if proxy was not used
      if (!statsUpdated || !historyUpdated) {
        const directBase =
          process.env.NEXT_PUBLIC_API_URL ||
          (typeof window !== "undefined" && window.location.hostname.includes("169-58-221-49.nip.io")
            ? "https://api.169-58-221-49.nip.io"
            : "http://169.58.221.49:8000")

        const headers: Record<string, string> = {}
        if (token) headers["Authorization"] = `Bearer ${token}`

        const [directStatsRes, directHistoryRes] = await Promise.all([
          !statsUpdated ? fetch(`${directBase}/threat-intel/stats?time_range=${range}`, { headers }) : null,
          !historyUpdated ? fetch(`${directBase}/threat-intel/history?time_range=${range}&limit=100`, { headers }) : null,
        ])

        if (directStatsRes && directStatsRes.ok) {
          const statsData = await directStatsRes.json()
          setStats(statsData)
        }
        if (directHistoryRes && directHistoryRes.ok) {
          const historyData = await directHistoryRes.json()
          setHistory(historyData)
        }
      }
    } catch (err) {
      console.error("Failed to load stats for time range:", err)
    } finally {
      setIsLoading(false)
    }
  }

  const currentRangeObj = TIME_RANGES.find((r) => r.id === selectedRange) || TIME_RANGES[3]

  const chartData = [
    { name: "Malicious", value: stats.malicious, color: "#fb7185" },
    { name: "Suspicious", value: stats.suspicious, color: "#fb923c" },
    { name: "Clean", value: stats.clean, color: "#2dd4bf" },
  ]

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-slate-100 flex flex-col">
      {/* Ambient glow background */}
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 h-96 w-96 rounded-full bg-[#1c2e4a]/40 blur-3xl" />
        <div className="absolute top-40 right-0 h-96 w-96 rounded-full bg-[#1c2e4a]/30 blur-3xl" />
      </div>

      {/* Slim Header with Narrow Integrated Time Range Selector */}
      <header className="relative border-b border-white/5 bg-white/[0.02] pl-16 sm:pl-20 pr-4 sm:pr-8 py-2.5 backdrop-blur-xl">
        <div className="flex flex-wrap items-center justify-between gap-3">
          {/* Left Title */}
          <div className="flex items-center gap-2.5">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[#1c2e4a] border border-[#1c2e4a] shadow-md shadow-[#1c2e4a]/40">
              <Shield className="h-4 w-4 text-white" />
            </div>
            <div>
              <h1 className="text-sm font-semibold leading-tight text-white">SOC Dashboard</h1>
              <p className="text-[10px] text-slate-500">Security Operations Platform</p>
            </div>
          </div>

          {/* Center: Narrow Time Range Filter */}
          <div className="flex items-center gap-1 p-0.5 rounded-lg bg-black/40 border border-white/10 shadow-inner">
            <Clock className="h-3 w-3 text-blue-400 ml-1.5 mr-0.5" />
            {TIME_RANGES.map((r) => {
              const isActive = selectedRange === r.id
              return (
                <button
                  key={r.id}
                  type="button"
                  onClick={() => handleRangeChange(r.id)}
                  disabled={isLoading}
                  className={`px-2.5 py-0.5 text-[11px] rounded font-medium transition-all ${
                    isActive
                      ? "bg-[#1c2e4a] text-white border border-[#1c2e4a] shadow-sm shadow-[#1c2e4a]/50 font-semibold"
                      : "text-slate-400 hover:text-slate-200 hover:bg-white/5"
                  } disabled:opacity-50`}
                >
                  {r.label}
                </button>
              )
            })}
            {isLoading && <Loader2 className="h-3 w-3 animate-spin text-blue-400 ml-0.5 mr-1.5" />}
          </div>

          {/* Right: User info & Sign Out */}
          <div className="flex items-center gap-2.5">
            <div className="text-right hidden sm:block">
              <p className="text-xs font-medium leading-tight text-white">
                {user?.name || user?.email}
              </p>
              <p className="text-[10px] text-slate-500">Analyst</p>
            </div>
            <div className="flex h-7 w-7 items-center justify-center rounded-full bg-[#1c2e4a] border border-[#1c2e4a] text-xs font-medium text-white shadow-sm">
              {(user?.name || "U").charAt(0)}
            </div>
            <Button
              variant="outline"
              size="xs"
              onClick={() => signOut({ callbackUrl: "/" })}
              className="border-white/10 text-slate-300 hover:bg-white/5 text-xs h-7 px-2.5"
            >
              Sign Out
            </Button>
          </div>
        </div>
      </header>

      {/* Main Dashboard Body */}
      <main className="relative flex-1 px-4 sm:px-6 py-3.5 space-y-3.5">
        {/* Stat cards */}
        <div className={`grid grid-cols-2 lg:grid-cols-4 gap-3 transition-opacity duration-200 ${isLoading ? "opacity-60" : "opacity-100"}`}>
          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="flex items-center justify-between p-3">
              <div>
                <p className="text-xs text-slate-400 font-medium">Total Checked</p>
                <p className="text-2xl font-bold text-white mt-0.5">{stats.total}</p>
                <p className="text-[10px] text-slate-500 mt-0.5 font-mono">{currentRangeObj.fullLabel}</p>
              </div>
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-[#1c2e4a]/50 border border-[#1c2e4a]">
                <Activity className="h-4 w-4 text-blue-300" />
              </div>
            </CardContent>
          </Card>

          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="flex items-center justify-between p-3">
              <div>
                <p className="text-xs text-slate-400 font-medium">Malicious</p>
                <p className="text-2xl font-bold text-rose-400 mt-0.5">{stats.malicious}</p>
                <p className="text-[10px] text-slate-500 mt-0.5 font-mono">{currentRangeObj.fullLabel}</p>
              </div>
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-rose-500/10">
                <ShieldAlert className="h-4 w-4 text-rose-400" />
              </div>
            </CardContent>
          </Card>

          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="flex items-center justify-between p-3">
              <div>
                <p className="text-xs text-slate-400 font-medium">Suspicious</p>
                <p className="text-2xl font-bold text-orange-400 mt-0.5">{stats.suspicious}</p>
                <p className="text-[10px] text-slate-500 mt-0.5 font-mono">{currentRangeObj.fullLabel}</p>
              </div>
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-orange-500/10">
                <AlertTriangle className="h-4 w-4 text-orange-400" />
              </div>
            </CardContent>
          </Card>

          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="flex items-center justify-between p-3">
              <div>
                <p className="text-xs text-slate-400 font-medium">Clean</p>
                <p className="text-2xl font-bold text-teal-400 mt-0.5">{stats.clean}</p>
                <p className="text-[10px] text-slate-500 mt-0.5 font-mono">{currentRangeObj.fullLabel}</p>
              </div>
              <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-teal-500/10">
                <Shield className="h-4 w-4 text-teal-400" />
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Charts and Tables */}
        <div className={`grid grid-cols-1 gap-3 lg:grid-cols-3 transition-opacity duration-200 ${isLoading ? "opacity-60" : "opacity-100"}`}>
          {/* Chart */}
          <Card className="lg:col-span-1 border-white/5 bg-white/[0.03] backdrop-blur-xl flex flex-col">
            <CardHeader className="py-2.5 px-4 border-b border-white/5">
              <CardTitle className="text-xs font-semibold text-white flex items-center justify-between">
                <span>Verdict Breakdown</span>
                <span className="text-[10px] font-normal text-slate-500 font-mono">{currentRangeObj.fullLabel}</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="flex-1 flex flex-col items-center justify-center p-3 sm:p-4">
              <DashboardChart data={chartData} />
            </CardContent>
          </Card>

          {/* Table */}
          <Card className="lg:col-span-2 border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardHeader className="py-2.5 px-4 border-b border-white/5">
              <CardTitle className="text-xs font-semibold text-white flex items-center justify-between">
                <span>Recent Threat Checks</span>
                <span className="text-[10px] font-normal text-slate-500 font-mono">{currentRangeObj.fullLabel}</span>
              </CardTitle>
            </CardHeader>
            <CardContent className="p-3">
              <DashboardTable key={selectedRange} initialRecords={history} />
            </CardContent>
          </Card>
        </div>
      </main>
    </div>
  )
}
