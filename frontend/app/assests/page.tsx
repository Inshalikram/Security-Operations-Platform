"use client"

import { useEffect, useState } from "react"
import { useSession } from "next-auth/react"
import { signOut } from "next-auth/react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Server, Loader2, Plus, Trash2 } from "lucide-react"

const BASE_URL = "http://127.0.0.1:8000"

const CRITICALITY_COLORS: Record<string, string> = {
  low: "bg-slate-500/20 text-slate-300",
  medium: "bg-amber-500/20 text-amber-300",
  high: "bg-orange-500/20 text-orange-300",
  critical: "bg-rose-500/20 text-rose-300",
}

export default function AssetsPage() {
  const { data: session } = useSession()
  const [assets, setAssets] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: "", ip_address: "", asset_type: "server", owner: "", criticality: "medium" })

  const headers = { Authorization: `Bearer ${session?.accessToken}`, "Content-Type": "application/json" }

  function loadAssets() {
    fetch(`${BASE_URL}/assets`, { headers })
      .then((res) => res.json())
      .then((data) => setAssets(Array.isArray(data) ? data : []))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    if (session?.accessToken) loadAssets()
  }, [session])

  async function handleCreate() {
    if (!form.name) return
    await fetch(`${BASE_URL}/assets`, { method: "POST", headers, body: JSON.stringify(form) })
    setForm({ name: "", ip_address: "", asset_type: "server", owner: "", criticality: "medium" })
    setShowForm(false)
    loadAssets()
  }

  async function handleDelete(id: number) {
    await fetch(`${BASE_URL}/assets/${id}`, { method: "DELETE", headers })
    loadAssets()
  }

  return (
    <div className="min-h-screen bg-[#0a0a0f] text-slate-100">
      <div className="pointer-events-none fixed inset-0 overflow-hidden">
        <div className="absolute -top-40 -left-40 h-96 w-96 rounded-full bg-violet-600/10 blur-3xl" />
        <div className="absolute top-40 right-0 h-96 w-96 rounded-full bg-rose-600/10 blur-3xl" />
      </div>

      <header className="relative border-b border-white/5 bg-white/[0.02] px-8 py-5 backdrop-blur-xl">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-violet-500 to-rose-500 shadow-lg shadow-violet-500/20">
              <Server className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight text-white">Assets</h1>
              <p className="text-xs text-slate-500">Organization asset inventory</p>
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

      <main className="relative p-8 max-w-4xl mx-auto space-y-4">
        <div className="flex justify-end">
          <Button
            onClick={() => setShowForm(!showForm)}
            className="bg-gradient-to-br from-violet-600 to-rose-600 hover:opacity-90 text-white"
          >
            <Plus className="h-4 w-4 mr-2" />
            Add Asset
          </Button>
        </div>

        {showForm && (
          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="pt-6 space-y-3">
              <Input placeholder="Asset name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="bg-white/5 border-white/10 text-white" />
              <Input placeholder="IP address" value={form.ip_address} onChange={(e) => setForm({ ...form, ip_address: e.target.value })} className="bg-white/5 border-white/10 text-white" />
              <Input placeholder="Owner" value={form.owner} onChange={(e) => setForm({ ...form, owner: e.target.value })} className="bg-white/5 border-white/10 text-white" />
              <div className="flex gap-2">
                <select
                  value={form.asset_type}
                  onChange={(e) => setForm({ ...form, asset_type: e.target.value })}
                  className="flex-1 bg-white/5 border border-white/10 text-white rounded-md px-3 py-2 text-sm"
                >
                  <option value="server">Server</option>
                  <option value="workstation">Workstation</option>
                  <option value="network-device">Network Device</option>
                  <option value="cloud-resource">Cloud Resource</option>
                </select>
                <select
                  value={form.criticality}
                  onChange={(e) => setForm({ ...form, criticality: e.target.value })}
                  className="flex-1 bg-white/5 border border-white/10 text-white rounded-md px-3 py-2 text-sm"
                >
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <Button onClick={handleCreate} className="w-full bg-gradient-to-br from-violet-600 to-rose-600 text-white">
                Save Asset
              </Button>
            </CardContent>
          </Card>
        )}

        {loading && (
          <div className="flex items-center gap-2 text-slate-400 py-12 justify-center">
            <Loader2 className="h-5 w-5 animate-spin" />
            Loading assets...
          </div>
        )}

        {!loading && assets.length === 0 && (
          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="pt-6 text-center text-slate-400 py-12">
              No assets yet. Add your first one above.
            </CardContent>
          </Card>
        )}

        {assets.map((a) => (
          <Card key={a.id} className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="pt-6 flex items-center justify-between">
              <div>
                <p className="text-white font-medium">{a.name}</p>
                <p className="text-xs text-slate-500 mt-1">
                  {a.ip_address || "no IP"} · {a.asset_type} · Owner: {a.owner || "unassigned"}
                </p>
              </div>
              <div className="flex items-center gap-3">
                <span className={`text-xs px-2 py-1 rounded-full ${CRITICALITY_COLORS[a.criticality] || CRITICALITY_COLORS.medium}`}>
                  {a.criticality}
                </span>
                <button onClick={() => handleDelete(a.id)} className="text-slate-500 hover:text-rose-400">
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </CardContent>
          </Card>
        ))}
      </main>
    </div>
  )
}