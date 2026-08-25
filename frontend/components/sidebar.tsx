"use client"

import { useState } from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"

const NAV_ITEMS = [
  { href: "/dashboard", label: "Dashboard" },
  { href: "/alerts", label: "Alerts" },
  { href: "/cases", label: "Cases" },
  { href: "/assests", label: "Assets" },
  { href: "/organizations", label: "Organizations" },
  { href: "/search", label: "Search" },
  { href: "/log-search", label: "Log Search" },
  { href: "/threat-map", label: "Threat Map" },
  { href: "/ai-chat", label: "AI Chat" },
  { href: "/settings", label: "Settings" },
]

export default function Sidebar() {
  const [open, setOpen] = useState(false)
  const pathname = usePathname()

  return (
    <>
      {/* Hamburger button — now scrolls away with the page instead of staying pinned */}
      <button
        onClick={() => setOpen(true)}
        aria-label="Open menu"
        style={{
          position: "absolute",
          top: 21,
          left: 14,
          zIndex: 50,
          background: "linear-gradient(135deg, #ec4899, #a855f7)",
          border: "none",
          borderRadius: 12,
          width: 38,
          height: 40,
          display: "flex",
          alignItems: "center",
          justifyContent: "center",
          color: "white",
          fontSize: 20,
          cursor: "pointer",
        }}
      >
        ☰
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
                color: active ? "white" : "rgba(255,255,255,0.65)",
                background: active
                  ? "linear-gradient(135deg, rgba(236,72,153,0.25), rgba(168,85,247,0.25))"
                  : "transparent",
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