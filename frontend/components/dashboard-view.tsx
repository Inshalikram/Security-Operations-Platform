"use client"

import React, { useState } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Shield, AlertTriangle, ShieldAlert, Activity, Clock, Loader2 } from "lucide-react"
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
}

const TIME_RANGES = [
  { id: "24h", label: "24 Hours", sub: "Past 24 hours" },
  { id: "7d", label: "7 Days", sub: "Past 7 days" },
  { id: "30d", label: "30 Days", sub: "Past 30 days" },
  { id: "all", label: "All Time", sub: "Lifetime total" },
] as const

type TimeRangeId = (typeof TIME_RANGES)[number]["id"]

export default function DashboardView({ initialStats, initialHistory, token }: DashboardViewProps) {
  const [selectedRange, setSelectedRange] = useState<TimeRangeId>("all")
  const [stats, setStats] = useState<ThreatStats>(initialStats)
  const [history, setHistory] = useState<ThreatRecord[]>(initialHistory)
  const [isLoading, setIsLoading] = useState(false)

  const handleRangeChange = async (range: TimeRangeId) => {
    if (range === selectedRange || isLoading) return
    setSelectedRange(range)
    setIsLoading(true)

    try {
      const baseUrl = process.env.NEXT_PUBLIC_API_URL || ""
      const headers = { Authorization: `Bearer ${token}` }

      const [statsRes, historyRes] = await Promise.all([
        fetch(`${baseUrl}/threat-intel/stats?time_range=${range}`, { headers }),
        fetch(`${baseUrl}/threat-intel/history?time_range=${range}&limit=100`, { headers }),
      ])

      if (statsRes.ok) {
        const statsData = await statsRes.json()
        setStats(statsData)
      }
      if (historyRes.ok) {
        const historyData = await historyRes.json()
        setHistory(historyData)
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
    <div className="space-y-6">
      {/* Time Range Filter Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 p-4 rounded-xl bg-white/[0.02] border border-white/5 backdrop-blur-xl">
        <div className="flex items-center gap-2">
          <Clock className="h-4 w-4 text-blue-400" />
          <span className="text-sm font-medium text-slate-200">Time Range:</span>
          <span className="text-xs text-slate-500 font-mono">({currentRangeObj.sub})</span>
          {isLoading && <Loader2 className="h-3.5 w-3.5 animate-spin text-blue-400 ml-1" />}
        </div>

        <div className="flex items-center gap-1.5 p-1 rounded-lg bg-black/40 border border-white/10 self-stretch sm:self-auto overflow-x-auto">
          {TIME_RANGES.map((r) => {
            const isActive = selectedRange === r.id
            return (
              <button
                key={r.id}
                type="button"
                onClick={() => handleRangeChange(r.id)}
                disabled={isLoading}
                className={`px-3 py-1 text-xs rounded-md font-medium transition-all ${
                  isActive
                    ? "bg-blue-600 text-white shadow-md shadow-blue-600/30"
                    : "text-slate-400 hover:text-slate-200 hover:bg-white/5"
                } disabled:opacity-50`}
              >
                {r.label}
              </button>
            )
          })}
        </div>
      </div>

      {/* Stat cards */}
      <div className={`grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4 transition-opacity duration-200 ${isLoading ? "opacity-60" : "opacity-100"}`}>
        <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
          <CardContent className="flex items-center justify-between pt-6">
            <div>
              <p className="text-sm text-slate-500">Total Checked</p>
              <p className="text-3xl font-bold text-white">{stats.total}</p>
              <p className="text-[11px] text-slate-500 mt-1">{currentRangeObj.sub}</p>
            </div>
            <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-blue-500/10">
              <Activity className="h-5 w-5 text-blue-400" />
            </div>
          </CardContent>
        </Card>

        <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
          <CardContent className="flex items-center justify-between pt-6">
            <div>
              <p className="text-sm text-slate-500">Malicious</p>
              <p className="text-3xl font-bold text-rose-400">{stats.malicious}</p>
              <p className="text-[11px] text-slate-500 mt-1">{currentRangeObj.sub}</p>
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
              <p className="text-3xl font-bold text-orange-400">{stats.suspicious}</p>
              <p className="text-[11px] text-slate-500 mt-1">{currentRangeObj.sub}</p>
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
              <p className="text-3xl font-bold text-teal-400">{stats.clean}</p>
              <p className="text-[11px] text-slate-500 mt-1">{currentRangeObj.sub}</p>
            </div>
            <div className="flex h-11 w-11 items-center justify-center rounded-lg bg-teal-500/10">
              <Shield className="h-5 w-5 text-teal-400" />
            </div>
          </CardContent>
        </Card>
      </div>

      <div className={`grid grid-cols-1 gap-6 lg:grid-cols-3 transition-opacity duration-200 ${isLoading ? "opacity-60" : "opacity-100"}`}>
        {/* Chart */}
        <Card className="lg:col-span-1 border-white/5 bg-white/[0.03] backdrop-blur-xl">
          <CardHeader>
            <CardTitle className="text-base text-white flex items-center justify-between">
              <span>Verdict Breakdown</span>
              <span className="text-xs font-normal text-slate-500">{currentRangeObj.label}</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <DashboardChart data={chartData} />
          </CardContent>
        </Card>

        {/* Table */}
        <Card className="lg:col-span-2 border-white/5 bg-white/[0.03] backdrop-blur-xl">
          <CardHeader>
            <CardTitle className="text-base text-white flex items-center justify-between">
              <span>Recent Threat Checks</span>
              <span className="text-xs font-normal text-slate-500">{currentRangeObj.label}</span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <DashboardTable key={selectedRange} initialRecords={history} />
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
