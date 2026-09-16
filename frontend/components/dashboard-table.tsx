"use client"

import React, { useState, useMemo } from "react"
import Link from "next/link"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import FormattedTime from "@/components/formatted-time"
import { Search, ChevronLeft, ChevronRight, ArrowUpRight } from "lucide-react"

export type ThreatRecord = {
  ip: string
  verdict: string
  malicious_signals: number
  sources_checked: string[]
  checked_at: string
}

export function verdictBadgeClass(verdict: string) {
  if (verdict === "malicious") return "bg-rose-500/10 text-rose-400 border-rose-500/30"
  if (verdict === "suspicious") return "bg-orange-500/10 text-orange-400 border-orange-500/30"
  return "bg-teal-500/10 text-teal-400 border-teal-500/30"
}

interface DashboardTableProps {
  initialRecords: ThreatRecord[]
}

export default function DashboardTable({ initialRecords }: DashboardTableProps) {
  const [searchTerm, setSearchTerm] = useState("")
  const [verdictFilter, setVerdictFilter] = useState<string>("all")
  const [currentPage, setCurrentPage] = useState(1)
  const pageSize = 10

  const filteredRecords = useMemo(() => {
    return initialRecords.filter((record) => {
      const matchesSearch = record.ip.toLowerCase().includes(searchTerm.trim().toLowerCase())
      const matchesVerdict = verdictFilter === "all" || record.verdict.toLowerCase() === verdictFilter.toLowerCase()
      return matchesSearch && matchesVerdict
    })
  }, [initialRecords, searchTerm, verdictFilter])

  const totalPages = Math.max(1, Math.ceil(filteredRecords.length / pageSize))
  const safePage = Math.min(currentPage, totalPages)

  const paginatedRecords = useMemo(() => {
    const startIndex = (safePage - 1) * pageSize
    return filteredRecords.slice(startIndex, startIndex + pageSize)
  }, [filteredRecords, safePage, pageSize])

  const handleSearchChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchTerm(e.target.value)
    setCurrentPage(1)
  }

  const handleVerdictChange = (verdict: string) => {
    setVerdictFilter(verdict)
    setCurrentPage(1)
  }

  const startRecord = filteredRecords.length === 0 ? 0 : (safePage - 1) * pageSize + 1
  const endRecord = Math.min(safePage * pageSize, filteredRecords.length)

  return (
    <div className="space-y-3">
      {/* Search and Filters Bar */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-2">
        <div className="relative w-full sm:w-64">
          <Search className="absolute left-2 top-2 h-3.5 w-3.5 text-slate-500" />
          <Input
            type="text"
            placeholder="Search IP address..."
            value={searchTerm}
            onChange={handleSearchChange}
            className="pl-8 h-7 text-xs bg-white/[0.03] border-white/10 text-slate-200 placeholder:text-slate-500 focus:border-[#03045E]"
          />
        </div>

        <div className="flex items-center gap-1 p-0.5 rounded-lg bg-white/[0.03] border border-white/10 self-stretch sm:self-auto overflow-x-auto">
          {(["all", "malicious", "suspicious", "clean"] as const).map((filter) => {
            const isActive = verdictFilter === filter
            return (
              <button
                key={filter}
                type="button"
                onClick={() => handleVerdictChange(filter)}
                className={`px-2 py-0.5 text-[11px] rounded font-medium capitalize transition-colors ${
                  isActive
                    ? "bg-[#03045E] text-white border border-blue-400/50 shadow-sm shadow-[#03045E]/50 font-semibold"
                    : "text-slate-400 hover:text-slate-200 hover:bg-white/5"
                }`}
              >
                {filter}
              </button>
            )
          })}
        </div>
      </div>

      {/* Table */}
      <div className="rounded-lg border border-white/5 overflow-hidden">
        <Table>
          <TableHeader>
            <TableRow className="border-white/5 bg-white/[0.02] hover:bg-transparent [&_th]:h-8 [&_th]:py-1.5 [&_th]:px-2.5 [&_th]:text-xs">
              <TableHead className="text-slate-400">IP Address</TableHead>
              <TableHead className="text-slate-400">Verdict</TableHead>
              <TableHead className="text-slate-400">Signals</TableHead>
              <TableHead className="text-slate-400">Checked At (PKT)</TableHead>
              <TableHead className="text-right text-slate-400">Action</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {paginatedRecords.length === 0 ? (
              <TableRow className="border-white/5">
                <TableCell colSpan={5} className="text-center text-slate-500 py-6 text-xs">
                  {initialRecords.length === 0 ? "No records found in database" : "No matching IPs found"}
                </TableCell>
              </TableRow>
            ) : (
              paginatedRecords.map((record, i) => (
                <TableRow key={`${record.ip}-${record.checked_at}-${i}`} className="border-white/5 hover:bg-white/[0.03] transition-colors [&_td]:py-1.5 [&_td]:px-2.5">
                  <TableCell className="font-mono text-xs text-slate-200 font-medium">
                    {record.ip}
                  </TableCell>
                  <TableCell>
                    <Badge className={`${verdictBadgeClass(record.verdict)} text-[10px] px-1.5 py-0`} variant="outline">
                      {record.verdict}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-slate-400 font-mono text-[11px]">
                    {record.malicious_signals}
                  </TableCell>
                  <TableCell className="text-[11px] text-slate-400 font-mono">
                    <FormattedTime date={record.checked_at} />
                  </TableCell>
                  <TableCell className="text-right">
                    <Link
                      href={`/ai-chat?ip=${record.ip}`}
                      className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition-colors group"
                      title="Investigate in AI Chat"
                    >
                      <span>Analyze</span>
                      <ArrowUpRight className="h-3 w-3 group-hover:translate-x-0.5 group-hover:-translate-y-0.5 transition-transform" />
                    </Link>
                  </TableCell>
                </TableRow>
              ))
            )}
          </TableBody>
        </Table>
      </div>

      {/* Pagination Controls */}
      {filteredRecords.length > 0 && (
        <div className="flex flex-col sm:flex-row items-center justify-between gap-2 text-xs text-slate-400 pt-0.5">
          <div className="text-[11px]">
            Showing <span className="text-slate-200 font-medium">{startRecord}</span> to{" "}
            <span className="text-slate-200 font-medium">{endRecord}</span> of{" "}
            <span className="text-slate-200 font-medium">{filteredRecords.length}</span> threat checks
          </div>

          <div className="flex items-center gap-1.5">
            <Button
              variant="outline"
              size="xs"
              onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
              disabled={safePage <= 1}
              className="border-white/10 bg-white/[0.02] text-slate-300 hover:bg-white/10 hover:text-white disabled:opacity-40 h-6 px-2 text-xs"
            >
              <ChevronLeft className="h-3.5 w-3.5 mr-0.5" />
              Prev
            </Button>
            <span className="px-1.5 font-mono text-[11px] text-slate-400">
              <span className="text-slate-200 font-medium">{safePage}</span> /{" "}
              <span className="text-slate-200 font-medium">{totalPages}</span>
            </span>
            <Button
              variant="outline"
              size="xs"
              onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
              disabled={safePage >= totalPages}
              className="border-white/10 bg-white/[0.02] text-slate-300 hover:bg-white/10 hover:text-white disabled:opacity-40 h-6 px-2 text-xs"
            >
              Next
              <ChevronRight className="h-3.5 w-3.5 ml-0.5" />
            </Button>
          </div>
        </div>
      )}
    </div>
  )
}
