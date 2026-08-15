import { ChatInput } from "./ChatInput"

interface Props {
  disabled: boolean
  onSubmit: (query: string) => void
}

const EXAMPLES = [
  "扫描 127.0.0.1 的 80,443 端口",
  "用 Google 搜索 testphp.vulnweb.com 的漏洞信息",
  "检查本机 ipconfig",
]

export function DashboardWelcome({ disabled, onSubmit }: Props) {
  return (
    <div className="mx-auto flex min-h-[62vh] w-full max-w-chat-column items-center justify-center px-1 pb-8 pt-10">
      <div className="surface-card-strong w-full rounded-[32px] px-6 py-8 md:px-8 md:py-10">
        <div className="mx-auto max-w-3xl space-y-8 text-center">
          <div className="space-y-3">
            <span className="section-eyebrow">Workspace Ready</span>
            <h1 className="dashboard-hero-title text-3xl font-bold tracking-tight text-slate-950 dark:text-white md:text-4xl">
              开始你的下一次安全研判
            </h1>
            <p className="mx-auto max-w-2xl text-sm leading-7 text-slate-600 dark:text-slate-400 md:text-base">
              输入安全任务、验证目标或日志线索，智能体会自动拆解步骤、执行验证并整理结果。
            </p>
          </div>
          <ChatInput onSubmit={onSubmit} disabled={disabled} variant="light" />
          <div className="space-y-3 text-left">
            <p className="text-xs font-semibold uppercase tracking-[0.14em] text-slate-500 dark:text-slate-400">示例任务</p>
            <div className="flex flex-wrap gap-2.5">
              {EXAMPLES.map(example => (
                <button
                  key={example}
                  onClick={() => onSubmit(example)}
                  disabled={disabled}
                  className="rounded-full border border-slate-200/90 bg-white/88 px-3.5 py-2 text-xs text-slate-600 transition-colors hover:bg-slate-100 hover:text-slate-900 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-400 dark:hover:bg-slate-800 dark:hover:text-slate-200"
                >
                  {example}
                </button>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
