"use client"

import React, { useEffect, useState } from "react"

export function formatToPKT(
  date: string | number | Date | null | undefined,
  includeSeconds: boolean = true
): { display: string; utc: string } {
  if (!date) return { display: "", utc: "" }
  let s = String(date).trim()
  if (!s.endsWith("Z") && !s.includes("+") && s.includes("T")) {
    s += "Z"
  }
  const d = new Date(s)
  if (isNaN(d.getTime())) return { display: String(date), utc: "" }

  const display =
    d.toLocaleString("en-US", {
      timeZone: "Asia/Karachi",
      year: "numeric",
      month: "numeric",
      day: "numeric",
      hour: "numeric",
      minute: "2-digit",
      second: includeSeconds ? "2-digit" : undefined,
      hour12: true,
    }) + " PKT"

  const utc = d.toISOString().replace("T", " ").replace(/\.\d+Z$/, " UTC")

  return { display, utc }
}

interface FormattedTimeProps {
  date: string | number | Date | null | undefined
  includeSeconds?: boolean
  className?: string
  fallback?: string
}

export function FormattedTime({
  date,
  includeSeconds = true,
  className = "",
  fallback = "",
}: FormattedTimeProps) {
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  const { display, utc } = formatToPKT(date, includeSeconds)

  if (!display) {
    return <span className={className}>{fallback}</span>
  }

  return (
    <span
      className={className}
      title={`UTC: ${utc}`}
      suppressHydrationWarning
    >
      {display}
    </span>
  )
}

export default FormattedTime
