import NextAuth from "next-auth"
import Keycloak from "next-auth/providers/keycloak"

async function refreshAccessToken(token: any) {
  try {
    const url = `${process.env.AUTH_KEYCLOAK_INTERNAL_ISSUER}/protocol/openid-connect/token`
    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        client_id: process.env.AUTH_KEYCLOAK_ID as string,
        client_secret: process.env.AUTH_KEYCLOAK_SECRET || "",
        grant_type: "refresh_token",
        refresh_token: token.refreshToken,
      }),
    })
    const refreshed = await response.json()
    if (!response.ok) throw refreshed

    return {
      ...token,
      accessToken: refreshed.access_token,
      // same fallback here — refresh response can also come back with expires_at
      // instead of expires_in depending on the Keycloak version
      accessTokenExpires: refreshed.expires_at
        ? refreshed.expires_at * 1000
        : Date.now() + (refreshed.expires_in ?? 300) * 1000,
      refreshToken: refreshed.refresh_token ?? token.refreshToken,
      error: undefined,
    }
  } catch (error) {
    console.error("Error refreshing access token", error)
    return { ...token, error: "RefreshAccessTokenError" }
  }
}

export const { handlers, signIn, signOut, auth } = NextAuth({
  providers: [
    Keycloak({
      clientId: process.env.AUTH_KEYCLOAK_ID,
      clientSecret: process.env.AUTH_KEYCLOAK_SECRET || "",
      issuer: process.env.AUTH_KEYCLOAK_ISSUER,
      authorization: {
       url: `${process.env.AUTH_KEYCLOAK_ISSUER}/protocol/openid-connect/auth`,
       params: { scope: "openid email profile offline_access" },
      },
      token: `${process.env.AUTH_KEYCLOAK_INTERNAL_ISSUER}/protocol/openid-connect/token`,
      userinfo: `${process.env.AUTH_KEYCLOAK_INTERNAL_ISSUER}/protocol/openid-connect/userinfo`,
      jwks_endpoint: `${process.env.AUTH_KEYCLOAK_INTERNAL_ISSUER}/protocol/openid-connect/certs`,
    }),
  ],
  callbacks: {
    async jwt({ token, account }) {
      // Initial sign-in — save the tokens Keycloak gave us
      if (account) {
        // Auth.js providers sometimes return expires_at (absolute, seconds)
        // instead of expires_in (relative, seconds) — handle both so this
        // never silently becomes NaN and breaks the expiry check below.
        const accessTokenExpires = account.expires_at
          ? (account.expires_at as number) * 1000
          : Date.now() + ((account.expires_in as number) ?? 300) * 1000

        return {
          ...token,
          accessToken: account.access_token,
          refreshToken: account.refresh_token,
          idToken: account.id_token,
          accessTokenExpires,
        }
      }

      // Access token still valid (30s buffer so a request in-flight right at
      // expiry doesn't get sent with a token that dies before it lands)
      if (Date.now() < (token.accessTokenExpires as number) - 30_000) {
        return token
      }

      // Access token expired (or about to) — refresh it
      return refreshAccessToken(token)
    },
    async session({ session, token }) {
      session.accessToken = token.accessToken as string
      // Surface refresh failures to the client so the UI can force a re-login
      // instead of silently sending requests with a dead token.
      session.error = token.error as string | undefined
      return session
    },
  },
  events: {
    // NextAuth's own signOut only clears its local session — without this,
    // the user stays logged into Keycloak's SSO session and a fresh login
    // silently re-authenticates them with no login prompt.
    async signOut(message) {
      const token = "token" in message ? message.token : undefined
      if (!token?.idToken) return
      try {
        const logOutUrl = `${process.env.AUTH_KEYCLOAK_INTERNAL_ISSUER}/protocol/openid-connect/logout`
        await fetch(logOutUrl, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: process.env.AUTH_KEYCLOAK_ID as string,
            client_secret: process.env.AUTH_KEYCLOAK_SECRET || "",
            refresh_token: (token.refreshToken as string) || "",
          }),
        })
      } catch (error) {
        console.error("Error logging out from Keycloak", error)
      }
    },
  },
})