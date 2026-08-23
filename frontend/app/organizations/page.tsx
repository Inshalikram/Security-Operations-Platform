"use client"

import { useEffect, useState } from "react"
import { useSession } from "next-auth/react"
import { signOut } from "next-auth/react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Card, CardContent } from "@/components/ui/card"
import { Building2, Loader2, Plus, Trash2 } from "lucide-react"

const BASE_URL = "http://169.58.221.49:8000"

export default function OrganizationsPage() {
  const { data: session } = useSession()
  const [orgs, setOrgs] = useState<any[]>([])
  const [loading, setLoading] = useState(true)
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ name: "", description: "" })

  const headers = { Authorization: `Bearer ${session?.accessToken}`, "Content-Type": "application/json" }

  function loadOrgs() {
    fetch(`${BASE_URL}/organizations`, { headers })
      .then((res) => res.json())
      .then((data) => setOrgs(Array.isArray(data) ? data : []))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    if (session?.accessToken) loadOrgs()
  }, [session])

  async function handleCreate() {
    if (!form.name) return
    await fetch(`${BASE_URL}/organizations`, { method: "POST", headers, body: JSON.stringify(form) })
    setForm({ name: "", description: "" })
    setShowForm(false)
    loadOrgs()
  }

  async function handleDelete(id: number) {
    await fetch(`${BASE_URL}/organizations/${id}`, { method: "DELETE", headers })
    loadOrgs()
  }

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
              <Building2 className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight text-white">Organizations</h1>
              <p className="text-xs text-slate-500">Tenants managed on this platform</p>
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
            Add Organization
          </Button>
        </div>

        {showForm && (
          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="pt-6 space-y-3">
              <Input placeholder="Organization name" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="bg-white/5 border-white/10 text-white" />
              <Input placeholder="Description (optional)" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className="bg-white/5 border-white/10 text-white" />
              <Button onClick={handleCreate} className="w-full bg-gradient-to-br from-violet-600 to-rose-600 text-white">
                Save Organization
              </Button>
            </CardContent>
          </Card>
        )}

        {loading && (
          <div className="flex items-center gap-2 text-slate-400 py-12 justify-center">
            <Loader2 className="h-5 w-5 animate-spin" />
            Loading organizations...
          </div>
        )}

        {!loading && orgs.length === 0 && (
          <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="pt-6 text-center text-slate-400 py-12">
              No organizations yet.
            </CardContent>
          </Card>
        )}

        {orgs.map((o) => (
          <Card key={o.id} className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
            <CardContent className="pt-6 flex items-center justify-between">
              <div>
                <p className="text-white font-medium">{o.name}</p>
                {o.description && <p className="text-xs text-slate-500 mt-1">{o.description}</p>}
              </div>
              <button onClick={() => handleDelete(o.id)} className="text-slate-500 hover:text-rose-400">
                <Trash2 className="h-4 w-4" />
              </button>
            </CardContent>
          </Card>
        ))}
      </main>
    </div>
  )
}