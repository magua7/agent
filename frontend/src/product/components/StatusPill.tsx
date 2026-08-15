import { Circle, Loader2 } from "lucide-react"

const STATUS_LABELS: Record<string, string> = {
  created: "已创建",
  draft: "草稿",
  pending: "等待中",
  queued: "排队中",
  planning: "规划中",
  running: "执行中",
  verifying: "验证中",
  cancelling: "取消中",
  completed: "已完成",
  failed: "失败",
  cancelled: "已取消",
  canceled: "已取消",
  timed_out: "已超时",
  active: "活动",
  ready: "就绪",
  blocked: "阻塞",
  succeeded: "成功",
  superseded: "已替代",
}

const STATUS_COLORS: Record<string, string> = {
  created: "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300",
  draft: "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300",
  pending: "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300",
  queued: "bg-sky-100 text-sky-700 dark:bg-sky-950/60 dark:text-sky-300",
  planning: "bg-violet-100 text-violet-700 dark:bg-violet-950/60 dark:text-violet-300",
  running: "bg-cyan-100 text-cyan-700 dark:bg-cyan-950/60 dark:text-cyan-300",
  verifying: "bg-blue-100 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300",
  cancelling: "bg-amber-100 text-amber-700 dark:bg-amber-950/60 dark:text-amber-300",
  completed: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300",
  succeeded: "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/60 dark:text-emerald-300",
  failed: "bg-red-100 text-red-700 dark:bg-red-950/60 dark:text-red-300",
  blocked: "bg-orange-100 text-orange-700 dark:bg-orange-950/60 dark:text-orange-300",
  cancelled: "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300",
  canceled: "bg-slate-100 text-slate-600 dark:bg-slate-800 dark:text-slate-300",
  timed_out: "bg-amber-100 text-amber-700 dark:bg-amber-950/60 dark:text-amber-300",
}

export function StatusPill({ status, compact = false }: { status: string; compact?: boolean }) {
  const normalized = status.toLowerCase()
  const active = ["planning", "running", "verifying", "cancelling"].includes(normalized)
  return (
    <span className={`inline-flex shrink-0 items-center gap-1.5 rounded-full font-medium ${compact ? "px-2 py-0.5 text-[0.68rem]" : "px-2.5 py-1 text-xs"} ${STATUS_COLORS[normalized] || STATUS_COLORS.created}`}>
      {active ? <Loader2 className="h-3 w-3 animate-spin" /> : <Circle className="h-2.5 w-2.5 fill-current" />}
      {STATUS_LABELS[normalized] || status}
    </span>
  )
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-600 text-white dark:bg-red-500 dark:text-slate-950",
  high: "bg-orange-100 text-orange-800 dark:bg-orange-950/60 dark:text-orange-300",
  medium: "bg-amber-100 text-amber-800 dark:bg-amber-950/60 dark:text-amber-300",
  low: "bg-sky-100 text-sky-800 dark:bg-sky-950/60 dark:text-sky-300",
  informational: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
  info: "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300",
}

export function SeverityPill({ severity }: { severity: string }) {
  const normalized = severity.toLowerCase()
  return (
    <span className={`rounded-full px-2.5 py-1 text-[0.7rem] font-bold uppercase tracking-wider ${SEVERITY_COLORS[normalized] || SEVERITY_COLORS.informational}`}>
      {normalized}
    </span>
  )
}
