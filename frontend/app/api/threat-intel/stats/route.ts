import { auth } from "@/auth"
import { NextRequest, NextResponse } from "next/server"

export async function GET(request: NextRequest) {
  const session = await auth()
  const { searchParams } = new URL(request.url)
  const timeRange = searchParams.get("time_range") || "all"

  const backendCandidates = [
    process.env.BACKEND_INTERNAL_URL,
    process.env.NEXT_PUBLIC_API_URL,
    "http://backend:8000",
    "https://api.169-58-221-49.nip.io",
    "http://169.58.221.49:8000",
  ].filter(Boolean) as string[]

  let lastError: any = null
  for (const baseUrl of backendCandidates) {
    try {
      const headers: Record<string, string> = { "Content-Type": "application/json" }
      if (session?.accessToken) {
        headers["Authorization"] = `Bearer ${session.accessToken}`
      }
      const res = await fetch(`${baseUrl}/threat-intel/stats?time_range=${timeRange}`, {
        headers,
        cache: "no-store",
      })
      if (res.ok) {
        const data = await res.json()
        return NextResponse.json(data)
      }
    } catch (e) {
      lastError = e
    }
  }

  return NextResponse.json(
    { error: "Failed to fetch threat intel stats", detail: String(lastError) },
    { status: 502 }
  )
}
