import { useEffect, useState } from "react"
import { Loader2, ShieldCheck } from "lucide-react"
import { useSecGoController } from "./useSecGoController"
import { LoginScreen } from "./components/LoginScreen"
import { ProductHeader } from "./components/ProductHeader"
import { ProductWorkspace } from "./components/ProductWorkspace"
import { TaskCreateDialog } from "./components/TaskCreateDialog"

const THEME_KEY = "secgo_theme"

function initialTheme(): "light" | "dark" {
  try {
    const stored = localStorage.getItem(THEME_KEY)
    if (stored === "light" || stored === "dark") return stored
  } catch {
    // Fall back to system preference.
  }
  return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light"
}

export function SecGoApp() {
  const controller = useSecGoController()
  const [theme, setTheme] = useState<"light" | "dark">(initialTheme)
  const [createOpen, setCreateOpen] = useState(false)

  useEffect(() => {
    document.documentElement.classList.toggle("dark", theme === "dark")
    try { localStorage.setItem(THEME_KEY, theme) } catch { /* theme persistence is optional */ }
  }, [theme])

  if (controller.authPhase === "checking") {
    return (
      <main className="flex min-h-screen items-center justify-center">
        <div className="surface-card flex items-center gap-3 rounded-3xl px-6 py-5 text-sm text-slate-600 dark:text-slate-300">
          <div className="flex h-10 w-10 items-center justify-center rounded-2xl bg-cyan-100 text-cyan-700 dark:bg-cyan-950/50 dark:text-cyan-300"><ShieldCheck className="h-5 w-5" /></div>
          <Loader2 className="h-4 w-4 animate-spin text-cyan-500" />正在验证安全会话...
        </div>
      </main>
    )
  }

  if (controller.authPhase === "anonymous" || !controller.user) {
    return <LoginScreen busy={controller.authBusy} error={controller.authError} onLogin={controller.login} />
  }

  return (
    <div className="app-shell min-h-screen text-slate-900 transition-colors dark:text-slate-100">
      <ProductHeader
        user={controller.user}
        theme={theme}
        onToggleTheme={() => setTheme(current => current === "dark" ? "light" : "dark")}
        onLogout={controller.logout}
      />
      <ProductWorkspace controller={controller} onCreate={() => setCreateOpen(true)} />
      <TaskCreateDialog
        open={createOpen}
        busy={controller.operationBusy}
        onClose={() => setCreateOpen(false)}
        onCreate={async input => Boolean(await controller.createTask(input))}
      />
    </div>
  )
}

