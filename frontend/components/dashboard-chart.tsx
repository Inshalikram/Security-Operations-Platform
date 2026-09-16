"use client"

import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip, Legend } from "recharts"

type ChartData = { name: string; value: number; color: string }

export default function DashboardChart({ data }: { data: ChartData[] }) {
  const total = data.reduce((acc, curr) => acc + (curr.value || 0), 0)
  const malicious = data.find((d) => d.name === "Malicious")?.value || 0
  const suspicious = data.find((d) => d.name === "Suspicious")?.value || 0
  const clean = data.find((d) => d.name === "Clean")?.value || 0

  if (total === 0) {
    return (
      <div className="flex h-48 flex-col items-center justify-center text-slate-500 text-xs text-center px-4">
        <p>No threat checks found in this time range.</p>
      </div>
    )
  }

  return (
    <div className="w-full flex flex-col items-center justify-center py-1">
      {/* Donut Chart with Center Counter */}
      <div className="relative w-full h-[170px] flex items-center justify-center">
        <ResponsiveContainer width="100%" height={170}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              nameKey="name"
              innerRadius={48}
              outerRadius={74}
              paddingAngle={3}
              stroke="none"
            >
              {data.map((entry, i) => (
                <Cell key={i} fill={entry.color} />
              ))}
            </Pie>
            <Tooltip
              contentStyle={{
                backgroundColor: "#0d1117",
                borderColor: "rgba(255,255,255,0.1)",
                borderRadius: "8px",
                color: "#fff",
                fontSize: "12px",
                boxShadow: "0 4px 12px rgba(0,0,0,0.5)",
              }}
              itemStyle={{ color: "#fff" }}
            />
          </PieChart>
        </ResponsiveContainer>

        {/* Center Total Counter */}
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-xl font-bold tracking-tight text-white leading-none">
            {total.toLocaleString()}
          </span>
          <span className="text-[10px] uppercase tracking-wider text-slate-400 font-medium mt-1">
            Total
          </span>
        </div>
      </div>

      {/* Structured Verdict Breakdown Badges below Donut */}
      <div className="w-full grid grid-cols-3 gap-2 mt-3 pt-3 border-t border-white/5 text-center">
        <div className="rounded-lg bg-rose-500/10 border border-rose-500/20 py-1.5 px-1">
          <p className="text-[10px] font-semibold text-rose-400">Malicious</p>
          <p className="text-sm font-bold text-white mt-0.5">{malicious.toLocaleString()}</p>
          <p className="text-[9px] text-slate-400 font-mono">
            {total > 0 ? Math.round((malicious / total) * 100) : 0}%
          </p>
        </div>

        <div className="rounded-lg bg-orange-500/10 border border-orange-500/20 py-1.5 px-1">
          <p className="text-[10px] font-semibold text-orange-400">Suspicious</p>
          <p className="text-sm font-bold text-white mt-0.5">{suspicious.toLocaleString()}</p>
          <p className="text-[9px] text-slate-400 font-mono">
            {total > 0 ? Math.round((suspicious / total) * 100) : 0}%
          </p>
        </div>

        <div className="rounded-lg bg-teal-500/10 border border-teal-500/20 py-1.5 px-1">
          <p className="text-[10px] font-semibold text-teal-400">Clean</p>
          <p className="text-sm font-bold text-white mt-0.5">{clean.toLocaleString()}</p>
          <p className="text-[9px] text-slate-400 font-mono">
            {total > 0 ? Math.round((clean / total) * 100) : 0}%
          </p>
        </div>
      </div>
    </div>
  )
}
