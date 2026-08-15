import { FormEvent, useState } from "react"
import { Eye, EyeOff, LockKeyhole, ShieldCheck } from "lucide-react"

interface Props {
  busy: boolean
  error: string | null
  onLogin: (username: string, password: string) => Promise<void>
}

export function LoginScreen({ busy, error, onLogin }: Props) {
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [showPassword, setShowPassword] = useState(false)

  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (!username.trim() || !password || busy) return
    void onLogin(username.trim(), password)
  }

  return (
    <main className="relative flex min-h-screen items-center justify-center overflow-hidden px-5 py-12">
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute left-[8%] top-[14%] h-72 w-72 rounded-full bg-cyan-300/20 blur-3xl dark:bg-cyan-500/10" />
        <div className="absolute bottom-[8%] right-[10%] h-80 w-80 rounded-full bg-indigo-300/20 blur-3xl dark:bg-indigo-500/10" />
        <div className="secgo-grid absolute inset-0 opacity-35 dark:opacity-20" />
      </div>

      <div className="surface-card-strong relative z-10 grid w-full max-w-5xl overflow-hidden rounded-[36px] lg:grid-cols-[1.05fr_0.95fr]">
        <section className="hidden min-h-[610px] flex-col justify-between bg-slate-950 p-10 text-white lg:flex">
          <div>
            <div className="mb-12 flex items-center gap-3">
              <div className="flex h-12 w-12 items-center justify-center rounded-2xl bg-cyan-400 text-slate-950 shadow-lg shadow-cyan-400/20">
                <ShieldCheck className="h-7 w-7" />
              </div>
              <div>
                <div className="brand-wordmark text-xl">SEC-GO</div>
                <div className="text-xs uppercase tracking-[0.2em] text-cyan-300">Evidence-driven runtime</div>
              </div>
            </div>
            <h1 className="max-w-lg text-4xl font-bold leading-tight">
              让每个安全结论，<br />都能回到真实证据。
            </h1>
            <p className="mt-6 max-w-md text-sm leading-7 text-slate-300">
              结构化任务、可审计计划、受控工具执行与独立验证，共同组成轻量且可扩展的安全智能体工作台。
            </p>
          </div>
          <div className="grid grid-cols-3 gap-3 text-xs text-slate-300">
            {[["01", "明确授权范围"], ["02", "保存原始证据"], ["03", "验证后再完成"]].map(([step, label]) => (
              <div key={step} className="rounded-2xl border border-slate-800 bg-slate-900/70 p-4">
                <div className="mb-2 font-mono text-cyan-300">{step}</div>
                <div>{label}</div>
              </div>
            ))}
          </div>
        </section>

        <section className="flex min-h-[560px] flex-col justify-center p-7 sm:p-10 lg:p-12">
          <div className="mb-8 lg:hidden">
            <div className="flex items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-2xl bg-cyan-600 text-white"><ShieldCheck className="h-6 w-6" /></div>
              <div className="brand-wordmark text-xl text-slate-950 dark:text-white">SEC-GO</div>
            </div>
          </div>
          <span className="section-eyebrow">Secure workspace</span>
          <h2 className="mt-3 text-3xl font-bold text-slate-950 dark:text-white">登录安全工作台</h2>
          <p className="mt-3 text-sm leading-6 text-slate-500 dark:text-slate-400">身份验证成功后才能查看任务、证据与报告。</p>

          <form className="mt-9 space-y-5" onSubmit={submit}>
            <label className="block">
              <span className="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-300">用户名</span>
              <input
                value={username}
                onChange={event => setUsername(event.target.value)}
                autoComplete="username"
                autoFocus
                className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3.5 text-sm text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-4 focus:ring-cyan-500/10 dark:border-slate-700 dark:bg-slate-900 dark:text-white"
                placeholder="请输入用户名"
              />
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-300">密码</span>
              <div className="relative">
                <input
                  type={showPassword ? "text" : "password"}
                  value={password}
                  onChange={event => setPassword(event.target.value)}
                  autoComplete="current-password"
                  className="w-full rounded-2xl border border-slate-200 bg-white px-4 py-3.5 pr-12 text-sm text-slate-900 outline-none transition focus:border-cyan-500 focus:ring-4 focus:ring-cyan-500/10 dark:border-slate-700 dark:bg-slate-900 dark:text-white"
                  placeholder="请输入密码"
                />
                <button type="button" onClick={() => setShowPassword(value => !value)} className="absolute right-3 top-1/2 -translate-y-1/2 rounded-xl p-2 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-800">
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </label>

            {error && <div role="alert" className="rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300">{error}</div>}

            <button disabled={busy || !username.trim() || !password} className="flex w-full items-center justify-center gap-2 rounded-2xl bg-cyan-600 px-5 py-3.5 text-sm font-semibold text-white shadow-lg shadow-cyan-600/15 transition hover:bg-cyan-700 disabled:cursor-not-allowed disabled:bg-slate-300 disabled:shadow-none dark:disabled:bg-slate-700">
              <LockKeyhole className="h-4 w-4" />
              {busy ? "正在验证..." : "安全登录"}
            </button>
          </form>

          <div className="mt-7 rounded-2xl border border-amber-200/80 bg-amber-50/80 px-4 py-3 text-xs leading-5 text-amber-800 dark:border-amber-900/50 dark:bg-amber-950/25 dark:text-amber-300">
            本地开发初始凭据为 <code>admin / secgo</code>。正式部署请在首次初始化数据库前通过
            <code> SEC_GO_ADMIN_PASSWORD </code>设置强密码，切勿继续使用默认凭据。
          </div>
        </section>
      </div>
    </main>
  )
}
