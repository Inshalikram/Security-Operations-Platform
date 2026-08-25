"use client"

import { useState } from "react"
import { signOut } from "next-auth/react"
import { useSessionGuard } from "@/lib/use-session-guard"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Settings as SettingsIcon, User, Cpu } from "lucide-react"

const PROVIDERS = ["ollama", "openai", "gemini", "deepseek", "qwen"]

export default function SettingsPage() {
  const session= useSessionGuard()
  const [provider, setProvider] = useState("ollama")

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
              <SettingsIcon className="h-5 w-5 text-white" />
            </div>
            <div>
              <h1 className="text-lg font-semibold leading-tight text-white">Settings</h1>
              <p className="text-xs text-slate-500">Account &amp; platform preferences</p>
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

      <main className="relative p-8 max-w-2xl mx-auto space-y-6">
        <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
          <CardHeader>
            <CardTitle className="text-base text-white flex items-center gap-2">
              <User className="h-4 w-4 text-violet-400" />
              Account
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-2 text-sm">
            <div className="flex justify-between">
              <span className="text-slate-500">Username</span>
              <span className="text-white">{session?.user?.name || "—"}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-500">Email</span>
              <span className="text-white">{session?.user?.email || "—"}</span>
            </div>
          </CardContent>
        </Card>

        <Card className="border-white/5 bg-white/[0.03] backdrop-blur-xl">
          <CardHeader>
            <CardTitle className="text-base text-white flex items-center gap-2">
              <Cpu className="h-4 w-4 text-violet-400" />
              Default AI Provider
            </CardTitle>
          </CardHeader>
          <CardContent>
            <p className="text-xs text-slate-500 mb-3">
              Used as the default provider for AI Chat actions unless you pick a different one per-request.
            </p>
            <div className="flex flex-wrap gap-2">
              {PROVIDERS.map((p) => (
                <button
                  key={p}
                  onClick={() => setProvider(p)}
                  className={`text-sm px-4 py-2 rounded-lg border transition-colors ${
                    provider === p
                      ? "bg-gradient-to-br from-violet-600 to-rose-600 border-transparent text-white"
                      : "border-white/10 text-slate-300 hover:bg-white/5"
                  }`}
                >
                  {p}
                </button>
              ))}
            </div>
          </CardContent>
        </Card>
      </main>
    </div>
  )
}