"use client"

import { useState, useEffect } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { useSession } from "next-auth/react"
import { Menu } from "lucide-react"

const NAV_ITEMS = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/alerts", label: "Alerts" },
  { href: "/cases", label: "Cases" },
  { href: "/assests", label: "Assets" },
  { href: "/organizations", label: "Organizations" },
  { href: "/search", label: "Search" },
  { href: "/log-search", label: "Log Search" },
  { href: "/threat-map", label: "Threat Map" },
  { href: "/network-status", label: "Network Status" },
  { href: "/ai-chat", label: "AI Chat" },
  { href: "/pending-approvals", label: "Pending Approvals" },
  { href: "/settings", label: "Settings" },
]

export default function Sidebar() {
  const [open, setOpen] = useState(false)
  const [mounted, setMounted] = useState(false)
  const pathname = usePathname()
  const { status } = useSession()

  useEffect(() => {
    setMounted(true)
  }, [])

  // Root/login page never shows the sidebar, regardless of session state
  if (pathname === "/") return null
  if (!mounted || status !== "authenticated") return null

  return (
    <>
      {/* Hamburger button ... */}
      {/* Hamburger button — perfectly aligned with header logo */}
      <button
        onClick={() => setOpen(true)}
        aria-label="Open menu"
        className="fixed top-2.5 left-3.5 z-50 flex h-8 w-8 items-center justify-center rounded-lg bg-[#03045E] hover:bg-[#023e8a] border border-blue-400/30 text-white shadow-md shadow-[#03045E]/40 transition-colors cursor-pointer"
      >
        <Menu className="h-4 w-4 text-white" />
      </button>

      {/* Dark overlay when sidebar is open — stays fixed so it covers the full viewport while open */}
      {open && (
        <div
          onClick={() => setOpen(false)}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.6)",
            zIndex: 40,
          }}
        />
      )}

      {/* Sliding sidebar panel — stays fixed so it doesn't get cut off mid-scroll while open */}
      <nav
        style={{
          position: "fixed",
          top: 0,
          left: open ? 0 : -260,
          width: 240,
          height: "100%",
          background: "#0d0d14",
          borderRight: "1px solid rgba(255,255,255,0.08)",
          zIndex: 45,
          transition: "left 0.2s ease",
          padding: "80px 16px 16px",
        }}
      >
        {NAV_ITEMS.map((item) => {
          const active = pathname === item.href
          return (
            <Link
              key={item.href}
              href={item.href}
              onClick={() => setOpen(false)}
              style={{
                display: "block",
                padding: "10px 14px",
                marginBottom: 4,
                borderRadius: 8,
                color: active ? "#ffffff" : "rgba(255,255,255,0.65)",
                background: active ? "#03045E" : "transparent",
                borderLeft: active ? "3px solid #0096c7" : "3px solid transparent",
                textDecoration: "none",
                fontSize: 14,
                fontWeight: active ? 600 : 400,
              }}
            >
              {item.label}
            </Link>
          )
        })}
      </nav>
    </>
  )
}