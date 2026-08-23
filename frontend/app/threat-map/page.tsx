"use client"

import { useEffect, useState } from "react"
import { useSession } from "next-auth/react"
import { signOut } from "next-auth/react"
import { ComposableMap, Geographies, Geography } from "react-simple-maps"
import countries from "i18n-iso-countries"
import enLocale from "i18n-iso-countries/langs/en.json"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Globe, Loader2, AlertTriangle } from "lucide-react"

countries.registerLocale(enLocale)

const BASE_URL = "http://127.0.0.1:8000"
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
  const { data: session } = useSession()
  const [countryData, setCountryData] = useState<Record<string, any>>({})
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [hovered, setHovered] = useState<{ name: string; stats: any } | null>(null)

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

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-slate-100">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 h-96 w-96 rounded-full bg-violet-600/10 blur-3xl" />
        <div className="absolute top-40 right-0 h-96 w-96 rounded-full bg-rose-600/10 blur-3xl" />
      </div>

      <header className="relative border-b border-white/5 bg-white/[0.02] pl-17 pr-8 py-5 backdrop-blur-xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-rose-500 shadow-lg shadow-violet-500/20">
              <Globe className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight text-white">Threat Map</h1>
              <p className="text-xs text-slate-500">Detections by country of origin</p>
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
            Loading threat map...
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
          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl overflow-hidden">
            <CardHeader className="flex flex-row items-center justify-between">
              <CardTitle className="text-base text-white">Global Detections</CardTitle>
              {hovered && (
                <span className="text-sm text-slate-300">
                  {hovered.name}: <span className="text-white font-medium">{hovered.stats.total}</span> detection(s)
                  {hovered.stats.malicious > 0 && <span className="text-rose-400 ml-2">{hovered.stats.malicious} malicious</span>}
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
                      return (
                        <Geography
                          key={geo.rsmKey}
                          geography={geo}
                          onMouseEnter={() => stats && setHovered({ name, stats })}
                          onMouseLeave={() => setHovered(null)}
                          style={{
                            default: {
                              fill: fillFor(name),
                              stroke: "#0a0a0f",
                              strokeWidth: 0.5,
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

              <div className="flex items-center justify-center gap-2 mt-4 text-xs text-slate-500">
                <span>Low activity</span>
                <div className="h-2 w-24 rounded-full bg-gradient-to-r from-violet-600 to-rose-600" />
                <span>High activity</span>
              </div>
            </CardContent>
          </Card>
        )}
      </main>
    </div>
  )
}