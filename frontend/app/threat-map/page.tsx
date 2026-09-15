"use client"

import { useEffect, useState } from "react"
import { useRouter } from "next/navigation"
import { signOut } from "next-auth/react"
import { useSessionGuard } from "@/lib/use-session-guard"
import { ComposableMap, Geographies, Geography } from "react-simple-maps"
import countries from "i18n-iso-countries"
import enLocale from "i18n-iso-countries/langs/en.json"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Globe, Loader2, AlertTriangle, ShieldAlert, Crosshair, ArrowUpRight, X, Activity } from "lucide-react"

countries.registerLocale(enLocale)

const BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://169.58.221.49:8000"
const GEO_URL = "https://cdn.jsdelivr.net/npm/world-atlas@2/countries-110m.json"

// Normalizes whatever the backend gives us (2-letter code OR full name) into a full country name.
function normalizeCountryName(raw: string): string {
  if (!raw) return "Unknown"
  if (raw.length === 2) {
    const name = countries.getName(raw.toUpperCase(), "en")
    return name || raw
  }
  return raw
}

export default function ThreatMapPage() {
  const session = useSessionGuard()
  const router = useRouter()
  const [countryData, setCountryData] = useState<Record<string, any>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [hovered, setHovered] = useState<{ name: string; stats: any } | null>(null)
  const [selectedCountry, setSelectedCountry] = useState<{ name: string; stats: any } | null>(null)

  useEffect(() => {
    if (!session?.accessToken) return
    fetch(`${BASE_URL}/threat-map`, {
      headers: { Authorization: `Bearer ${session.accessToken}` },
    })
      .then((res) => res.json())
      .then((data) => {
        if (data.error) {
          setError(data.error)
          return
        }
        // Re-key the backend's country map by normalized full name
        const normalized: Record<string, any> = {}
        Object.entries(data.countries || {}).forEach(([raw, stats]: [string, any]) => {
          const name = normalizeCountryName(raw)
          normalized[name] = stats
        })
        setCountryData(normalized)
      })
      .catch(() => setError("Failed to load threat map. Check backend is running."))
      .finally(() => setLoading(false))
  }, [session])

  const maxTotal = Math.max(1, ...Object.values(countryData).map((s: any) => s.total))

  function fillFor(name: string) {
    const stats = countryData[name]
    if (!stats) return "#1e1e2e"           // no data — dark neutral
    const intensity = stats.total / maxTotal
    // interpolate between violet (#7c3aed) and rose (#e11d48) by intensity
    const r = Math.round(124 + (225 - 124) * intensity)
    const g = Math.round(58 + (29 - 58) * intensity)
    const b = Math.round(237 + (72 - 237) * intensity)
    return `rgb(${r},${g},${b})`
  }

  // Top origin countries sorted by total detections
  const topCountries = Object.entries(countryData)
    .filter(([name]) => name !== "Unknown")
    .sort((a, b) => (b[1]?.total || 0) - (a[1]?.total || 0))
    .slice(0, 8)

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-slate-100">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 h-96 w-96 rounded-full bg-violet-600/10 blur-3xl" />
        <div className="absolute top-40 right-0 h-96 w-96 rounded-full bg-rose-600/10 blur-3xl" />
      </div>

      <header className="relative border-b border-white/5 bg-white/[0.02] pl-20 pr-8 py-5 backdrop-blur-xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-rose-500 shadow-lg shadow-violet-500/20">
              <Globe className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight text-white">Threat Map</h1>
              <p className="text-xs text-slate-500">Live global intrusions & attacker intent by country</p>
            </div>
          </div>
          <Button
            variant="outline"
            size="sm"
            className="border-white/10 text-slate-300 hover:bg-white/5"
            onClick={() => signOut({ callbackUrl: "/" })}
          >
            Sign Out
          </Button>
        </div>
      </header>

      <main className="relative p-8 max-w-5xl mx-auto space-y-6">
        {loading && (
          <div className="flex items-center gap-2 text-slate-400 py-12 justify-center">
            <Loader2 className="h-5 w-5 animate-spin" />
            Loading threat map telemetry...
          </div>
        )}

        {error && (
          <Card className="border-rose-500/20 bg-rose-500/5 backdrop-blur-xl">
            <CardContent className="pt-6 flex items-center gap-2 text-rose-300">
              <AlertTriangle className="h-4 w-4" />
              {error}
            </CardContent>
          </Card>
        )}

        {!loading && !error && (
          <>
            {/* Interactive World Map */}
            <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl overflow-hidden">
              <CardHeader className="flex flex-row items-center justify-between">
                <div>
                  <CardTitle className="text-base text-white">Global Attack Origins</CardTitle>
                  <p className="text-xs text-slate-400 mt-0.5">
                    Click any highlighted country to inspect its exact IPs and attack intent
                  </p>
                </div>
                {hovered && (
                  <span className="text-sm text-slate-300">
                    {hovered.name}: <span className="text-white font-medium">{hovered.stats.total}</span> detection(s)
                    {hovered.stats.malicious > 0 && (
                      <span className="text-rose-400 ml-2">{hovered.stats.malicious} malicious</span>
                    )}
                  </span>
                )}
              </CardHeader>
              <CardContent>
                <ComposableMap
                  projectionConfig={{ scale: 140 }}
                  style={{ width: "100%", height: "auto" }}
                >
                  <Geographies geography={GEO_URL}>
                    {({ geographies }) =>
                      geographies.map((geo) => {
                        const name = geo.properties.name
                        const stats = countryData[name]
                        const isSelected = selectedCountry?.name === name
                        return (
                          <Geography
                            key={geo.rsmKey}
                            geography={geo}
                            onMouseEnter={() => stats && setHovered({ name, stats })}
                            onMouseLeave={() => setHovered(null)}
                            onClick={() => {
                              if (stats) {
                                setSelectedCountry({ name, stats })
                              }
                            }}
                            style={{
                              default: {
                                fill: isSelected ? "#f43f5e" : fillFor(name),
                                stroke: isSelected ? "#ffffff" : "#0a0a0f",
                                strokeWidth: isSelected ? 1.2 : 0.5,
                                outline: "none",
                              },
                              hover: {
                                fill: stats ? "#f472b6" : "#2a2a3e",
                                stroke: "#0a0a0f",
                                strokeWidth: 0.5,
                                outline: "none",
                                cursor: stats ? "pointer" : "default",
                              },
                              pressed: { outline: "none" },
                            }}
                          />
                        )
                      })
                    }
                  </Geographies>
                </ComposableMap>

                {/* Legend & Quick-Select Origin Countries */}
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-4 border-t border-white/5 mt-4">
                  <div className="flex items-center gap-2 text-xs text-slate-500">
                    <span>Low activity</span>
                    <div className="h-2 w-24 rounded-full bg-gradient-to-r from-violet-600 to-rose-600" />
                    <span>High activity</span>
                  </div>

                  {topCountries.length > 0 && (
                    <div className="flex flex-wrap items-center gap-1.5">
                      <span className="text-xs text-slate-400 mr-1">Quick Select:</span>
                      {topCountries.map(([name, stats]) => (
                        <button
                          key={name}
                          onClick={() => setSelectedCountry({ name, stats })}
                          className={`text-xs px-2.5 py-1 rounded-lg border transition-all ${
                            selectedCountry?.name === name
                              ? "bg-rose-500/20 border-rose-500/50 text-rose-300"
                              : "bg-white/[0.03] border-white/10 text-slate-300 hover:bg-white/[0.08]"
                          }`}
                        >
                          {name} <span className="text-slate-400 font-mono text-[11px]">({stats.total})</span>
                        </button>
                      ))}
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Selected Country Active Threats & Intent Inspection Panel */}
            {selectedCountry && (
              <Card className="border-white/10 bg-white/[0.03] backdrop-blur-xl animate-in fade-in slide-in-from-bottom-3 duration-200">
                <CardHeader className="flex flex-row items-center justify-between pb-3 border-b border-white/5">
                  <div className="flex items-center gap-3">
                    <div className="h-9 w-9 rounded-xl bg-rose-500/10 border border-rose-500/20 flex items-center justify-center text-rose-400">
                      <ShieldAlert className="h-5 w-5" />
                    </div>
                    <div>
                      <CardTitle className="text-base text-white flex items-center gap-2">
                        {selectedCountry.name}
                        <span className="text-xs px-2 py-0.5 rounded-full bg-white/10 text-slate-300 font-normal">
                          {selectedCountry.stats.total} total detection(s)
                        </span>
                      </CardTitle>
                      <p className="text-xs text-slate-400 mt-0.5">
                        {selectedCountry.stats.malicious || 0} malicious · {selectedCountry.stats.suspicious || 0} suspicious · {selectedCountry.stats.clean || 0} clean
                      </p>
                    </div>
                  </div>

                  <button
                    onClick={() => setSelectedCountry(null)}
                    className="h-8 w-8 rounded-lg bg-white/5 hover:bg-white/10 text-slate-400 hover:text-white flex items-center justify-center transition-colors"
                  >
                    <X className="h-4 w-4" />
                  </button>
                </CardHeader>

                <CardContent className="pt-4 space-y-3">
                  <div className="text-xs font-semibold uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                    <Crosshair className="h-3.5 w-3.5 text-rose-400" />
                    Detected IPs & Attacker Intent
                  </div>

                  {Array.isArray(selectedCountry.stats.threats) && selectedCountry.stats.threats.length > 0 ? (
                    <div className="divide-y divide-white/5">
                      {selectedCountry.stats.threats.map((threat: any, idx: number) => (
                        <div
                          key={idx}
                          className="py-3 flex flex-col sm:flex-row sm:items-center justify-between gap-3 hover:bg-white/[0.01] px-2 rounded-lg transition-colors"
                        >
                          <div className="space-y-1">
                            <div className="flex items-center gap-2.5">
                              <span className="font-mono text-sm font-semibold text-white">
                                {threat.ip}
                              </span>
                              <span
                                className={`text-[11px] px-2 py-0.5 rounded-full border ${
                                  threat.verdict === "malicious"
                                    ? "bg-rose-500/20 text-rose-300 border-rose-500/30"
                                    : threat.verdict === "suspicious"
                                    ? "bg-amber-500/20 text-amber-300 border-amber-500/30"
                                    : "bg-emerald-500/20 text-emerald-300 border-emerald-500/30"
                                }`}
                              >
                                {threat.verdict}
                              </span>
                              {threat.malicious_signals > 0 && (
                                <span className="text-[11px] text-slate-400">
                                  ({threat.malicious_signals} signal{threat.malicious_signals > 1 ? "s" : ""})
                                </span>
                              )}
                            </div>

                            {/* Attacker Intent / Action */}
                            <div className="flex items-center gap-1.5 text-xs text-slate-300">
                              <Activity className="h-3 w-3 text-cyan-400 shrink-0" />
                              <span className="text-slate-400">Intent:</span>
                              <span className="text-slate-200 font-medium">{threat.intent}</span>
                            </div>
                          </div>

                          {/* Quick Action: Open directly in AI Chat */}
                          <Button
                            size="sm"
                            variant="outline"
                            className="shrink-0 border-white/10 hover:border-cyan-500/30 text-slate-300 hover:text-cyan-300 bg-white/[0.02] hover:bg-cyan-500/10 text-xs flex items-center gap-1.5"
                            onClick={() => router.push(`/ai-chat?ip=${encodeURIComponent(threat.ip)}`)}
                          >
                            Investigate in AI Chat
                            <ArrowUpRight className="h-3.5 w-3.5" />
                          </Button>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-sm text-slate-400 py-4 text-center bg-white/[0.01] rounded-lg border border-white/5">
                      No granular IP threats recorded for {selectedCountry.name} yet.
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
          </>
        )}
      </main>
    </div>
  )
}