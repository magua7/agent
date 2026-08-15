import { Moon, Sun } from "lucide-react"
import brandLogo from "../assets/brand-logo.png"

interface Props {
  title: string
  subtitle?: string
  currentView: "home" | "workspace" | "settings"
  onGoHome: () => void
  onGoWorkspace: () => void
  onGoSettings: () => void
  theme: "dark" | "light"
  onToggleTheme: () => void
}

export function AppHeader({
  title,
  subtitle,
  currentView,
  onGoHome,
  onGoWorkspace,
  onGoSettings,
  theme,
  onToggleTheme,
}: Props) {
  return (
    <header className="sticky top-0 z-30 border-b border-slate-200/70 bg-white/72 backdrop-blur-2xl dark:border-slate-800/70 dark:bg-slate-950/82">
      <div className="flex h-[4.5rem] items-center justify-between px-6">
        <div className="flex min-w-0 items-center gap-5">
          <button
            type="button"
            onClick={onGoHome}
            className="group flex min-w-0 items-center gap-3 rounded-2xl px-1 py-1 text-left transition"
          >
            <div className="flex h-11 w-11 shrink-0 items-center justify-center overflow-hidden rounded-2xl bg-slate-950/5 ring-1 ring-black/5 transition group-hover:ring-cyan-300/70 dark:bg-white/5 dark:ring-white/10 dark:group-hover:ring-cyan-500/50">
              <img src={brandLogo} alt="智御Go安全智能体品牌Logo" className="h-10 w-10 object-contain" />
            </div>
            <div className="min-w-0">
              <div className="brand-wordmark truncate text-[1.05rem] text-slate-950 dark:text-slate-50 md:text-[1.12rem]">
                {title}
              </div>
            </div>
          </button>

          <nav className="hidden items-center gap-1 rounded-full border border-slate-200/80 bg-white/72 p-1 shadow-sm dark:border-slate-800/80 dark:bg-slate-900/70 md:flex">
            <HeaderNavButton active={currentView === "home"} onClick={onGoHome}>
              首页
            </HeaderNavButton>
            <HeaderNavButton active={currentView === "workspace"} onClick={onGoWorkspace}>
              工作台
            </HeaderNavButton>
            <HeaderNavButton active={currentView === "settings"} onClick={onGoSettings}>
              设置
            </HeaderNavButton>
          </nav>
        </div>

        <div className="flex items-center gap-3">
          <div className="hidden items-center gap-2 rounded-full border border-emerald-200/80 bg-emerald-50/80 px-3 py-1.5 text-sm text-emerald-700 shadow-sm dark:border-emerald-900/60 dark:bg-emerald-950/40 dark:text-emerald-300 md:flex">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-500 shadow-[0_0_0_3px_rgba(16,185,129,0.14)]" />
            Online
          </div>

          <button
            type="button"
            onClick={onToggleTheme}
            className="inline-flex items-center gap-2 rounded-full border border-slate-200/80 bg-white/78 px-3.5 py-2 text-sm text-slate-600 shadow-sm transition hover:border-cyan-300 hover:text-cyan-700 dark:border-slate-800 dark:bg-slate-900/74 dark:text-slate-300 dark:hover:border-cyan-700 dark:hover:text-cyan-300"
            aria-label="切换主题"
          >
            {theme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
            <span className="hidden sm:inline">{theme === "dark" ? "亮色" : "夜间"}</span>
          </button>
        </div>
      </div>
    </header>
  )
}

function HeaderNavButton({
  active,
  onClick,
  children,
}: {
  active: boolean
  onClick: () => void
  children: React.ReactNode
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className={[
        "rounded-full px-4 py-2 text-sm font-medium transition",
        active
          ? "bg-white text-cyan-700 shadow-sm dark:bg-slate-800 dark:text-cyan-300"
          : "text-slate-500 hover:text-slate-900 dark:text-slate-400 dark:hover:text-slate-100",
      ].join(" ")}
    >
      {children}
    </button>
  )
}
