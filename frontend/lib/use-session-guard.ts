"use client"
import { useEffect } from "react"
import { useSession, signOut } from "next-auth/react"

export function useSessionGuard() {
  const { data: session } = useSession()
  useEffect(() => {
    if (session?.error === "RefreshAccessTokenError") {
      signOut({ callbackUrl: "/" })
    }
  }, [session])
  return session
}