import { cn } from "../lib/utils"

const statusConfig: Record<string, { bg: string; text: string; label: string }> = {
  success:             { bg: "bg-emerald-100 dark:bg-emerald-900/40", text: "text-emerald-700 dark:text-emerald-300", label: "成功" },
  success_after_retry: { bg: "bg-emerald-100 dark:bg-emerald-900/40", text: "text-emerald-700 dark:text-emerald-300", label: "重试成功" },
  timeout:             { bg: "bg-amber-100 dark:bg-amber-900/40", text: "text-amber-700 dark:text-amber-300", label: "超时" },
  skipped:             { bg: "bg-slate-100 dark:bg-slate-800", text: "text-slate-600 dark:text-slate-300", label: "跳过" },
  unreachable:         { bg: "bg-red-100 dark:bg-red-900/40", text: "text-red-700 dark:text-red-300", label: "不可达" },
  error:               { bg: "bg-red-100 dark:bg-red-900/40", text: "text-red-700 dark:text-red-300", label: "错误" },
  running:             { bg: "bg-cyan-100 dark:bg-cyan-900/40", text: "text-cyan-700 dark:text-cyan-300", label: "执行中" },
  done:                { bg: "bg-emerald-100 dark:bg-emerald-900/40", text: "text-emerald-700 dark:text-emerald-300", label: "完成" },
}

const riskConfig: Record<string, { bg: string; text: string; label: string }> = {
  level0: { bg: "bg-emerald-100 dark:bg-emerald-900/40", text: "text-emerald-700 dark:text-emerald-300", label: "L0" },
  level1: { bg: "bg-sky-100 dark:bg-sky-900/40", text: "text-sky-700 dark:text-sky-300", label: "L1" },
  level2: { bg: "bg-amber-100 dark:bg-amber-900/40", text: "text-amber-700 dark:text-amber-300", label: "L2" },
  level3: { bg: "bg-red-100 dark:bg-red-900/40", text: "text-red-700 dark:text-red-300", label: "L3" },
}

export function StatusBadge({ status }: { status: string }) {
  const config = statusConfig[status] || { bg: "bg-slate-100 dark:bg-slate-800", text: "text-slate-600 dark:text-slate-300", label: status }
  return (
    <span className={cn("rounded-full px-2 py-0.5 text-xs font-medium", config.bg, config.text)}>
      {config.label}
    </span>
  )
}

export function RiskBadge({ risk }: { risk: string }) {
  const config = riskConfig[risk] || { bg: "bg-slate-100 dark:bg-slate-800", text: "text-slate-600 dark:text-slate-300", label: risk }
  return (
    <span className={cn("rounded-full px-2 py-0.5 text-xs font-mono font-semibold", config.bg, config.text)}>
      {config.label}
    </span>
  )
}

export function TaskStatusBadge({ status }: { status: string }) {
  const config: Record<string, { bg: string; text: string; label: string }> = {
    pending:          { bg: "bg-slate-100 dark:bg-slate-800", text: "text-slate-600 dark:text-slate-300", label: "等待中" },
    running:          { bg: "bg-cyan-100 dark:bg-cyan-900/40", text: "text-cyan-700 dark:text-cyan-300", label: "执行中" },
    waiting_approval: { bg: "bg-amber-100 dark:bg-amber-900/40", text: "text-amber-700 dark:text-amber-300", label: "待确认" },
    completed:        { bg: "bg-emerald-100 dark:bg-emerald-900/40", text: "text-emerald-700 dark:text-emerald-300", label: "已完成" },
    failed:           { bg: "bg-red-100 dark:bg-red-900/40", text: "text-red-700 dark:text-red-300", label: "失败" },
    cancelled:        { bg: "bg-slate-100 dark:bg-slate-800", text: "text-slate-600 dark:text-slate-300", label: "已取消" },
    timed_out:        { bg: "bg-amber-100 dark:bg-amber-900/40", text: "text-amber-700 dark:text-amber-300", label: "已超时" },
  }
  const resolved = config[status] || config.pending
  return (
    <span className={cn("rounded-full px-2 py-0.5 text-xs font-medium", resolved.bg, resolved.text)}>
      {resolved.label}
    </span>
  )
}
