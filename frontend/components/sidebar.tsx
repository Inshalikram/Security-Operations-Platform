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
  { href: "/threat-map", label: "Threat Map" },
  { href: "/ai-chat", label: "AI Chat" },
  { href: "/settings", label: "Settings" },
]

export default function Sidebar() {
  const [open, setOpen] = useState(false)
  const pathname = usePathname()

  return (
    <>
      {/* Hamburger button — always visible, top-left */}
      <button
        onClick={() => setOpen(true)}
        aria-label="Open menu"
        style={{
          position: "fixed",
          top: 16,
          left: 16,
          zIndex: 50,
          background: "rgba(20,20,30,0.9)",
          border: "1px solid rgba(255,255,255,0.15)",
          borderRadius: 8,
          padding: "8px 10px",
          color: "white",
          cursor: "pointer",
        }}
      >
        ☰
      </button>

      {/* Dark overlay when sidebar is open */}
      {open && (
        <div
          onClick={() => setOpen(false)}
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.5)",
            zIndex: 40,
          }}
        />
      )}

      {/* Sliding sidebar panel */}
      <nav
        style={{
          position: "fixed",
          top: 0,
          left: open ? 0 : -260,
          width: 240,
          height: "100%",
          background: "#111117",
          borderRight: "1px solid rgba(255,255,255,0.1)",
          zIndex: 45,
          transition: "left 0.2s ease",
          padding: "70px 16px 16px",
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
                padding: "10px 12px",
                marginBottom: 4,
                borderRadius: 6,
                color: active ? "white" : "rgba(255,255,255,0.7)",
                background: active ? "rgba(236,72,153,0.2)" : "transparent",
                textDecoration: "none",
                fontSize: 14,
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