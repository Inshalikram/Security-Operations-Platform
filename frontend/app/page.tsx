import { auth, signIn, signOut } from "@/auth"
import { Button } from "@/components/ui/button"

export default async function Home() {
  const session = await auth()

  if (!session) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <form
         action={async () => {
             "use server"
              await signIn("keycloak", { redirectTo: "/dashboard" })
            }}
        >
          <Button type="submit">Login with Keycloak</Button>
        </form>
      </div>
    )
  }

  return (
    <div className="flex min-h-screen flex-col items-center justify-center gap-4">
      <p>Logged in as {session.user?.name || session.user?.email}</p>
      <form
        action={async () => {
          "use server"
          await signOut()
        }}
      >
        <Button type="submit" variant="outline">Sign Out</Button>
      </form>
    </div>
  )
}