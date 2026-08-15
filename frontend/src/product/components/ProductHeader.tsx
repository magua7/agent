import { LogOut, Moon, ShieldCheck, Sun } from "lucide-react"
import type { SecGoUser } from "../types"

interface Props {
  user: SecGoUser
  theme: "light" | "dark"
  onToggleTheme: () => void
  onLogout: () => void
}

export function ProductHeader({ user, theme, onToggleTheme, onLogout }: Props) {
  return (
    <header className="sticky top-0 z-30 border-b border-slate-200/70 bg-white/78 backdrop-blur-2xl dark:border-slate-800/70 dark:bg-slate-950/86">
      <div className="flex h-[4.5rem] items-center justify-between px-4 sm:px-6">
        <div className="flex min-w-0 items-center gap-3">
          <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-slate-950 text-cyan-300 shadow-sm dark:bg-cyan-400 dark:text-slate-950">
            <ShieldCheck className="h-6 w-6" />
          </div>
          <div className="min-w-0">
            <div className="brand-wordmark truncate text-lg text-slate-950 dark:text-white">SEC-GO</div>
            <div className="hidden text-[0.68rem] uppercase tracking-[0.16em] text-slate-500 dark:text-slate-400 sm:block">Evidence-driven Security Agent</div>
          </div>
        </div>

        <div className="flex items-center gap-2 sm:gap-3">
          <div className="hidden rounded-full border border-slate-200 bg-white/80 px-3 py-2 text-xs text-slate-600 shadow-sm dark:border-slate-800 dark:bg-slate-900/80 dark:text-slate-300 md:block">
            {user.displayName || user.username}
          </div>
          <button onClick={onToggleTheme} className="flex h-9 w-9 items-center justify-center rounded-full border border-slate-200 bg-white/80 text-slate-500 shadow-sm transition hover:border-cyan-300 hover:text-cyan-700 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-400 dark:hover:text-cyan-300" aria-label="切换主题">
            {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
          </button>
          <button onClick={onLogout} className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white/80 px-3.5 py-2 text-xs text-slate-600 shadow-sm transition hover:border-red-200 hover:text-red-600 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-red-900 dark:hover:text-red-300">
            <LogOut className="h-4 w-4" />
            <span className="hidden sm:inline">退出</span>
          </button>
        </div>
      </div>
    </header>
  )
}

