import { Loader2, XCircle } from "lucide-react"
import type { CurrentTaskStatus, TaskDetail } from "../types/events"
import { TaskStatusBadge } from "./StatusBadge"

interface Props {
  status: CurrentTaskStatus
  report: string | null
  stats: TaskDetail["stats"]
  onCancel?: () => void
}

export function DashboardTopBar({ status, report, stats, onCancel }: Props) {
  const isRunning = status === "running" || status === "waiting_approval"

  return (
    <div className="flex items-center justify-between border-b border-slate-200 bg-white/80 px-6 py-3 backdrop-blur shrink-0 dark:border-slate-800 dark:bg-slate-950/70">
      <div className="flex items-center gap-3 min-w-0">
        {isRunning && <Loader2 className="w-4 h-4 text-cyan-500 animate-spin shrink-0" />}
        {status === "completed" && <div className="w-4 h-4 rounded-full bg-emerald-500 shrink-0" />}
        {status === "failed" && <XCircle className="w-4 h-4 text-red-500 shrink-0" />}
        {status === "cancelled" && <div className="w-4 h-4 rounded-full bg-amber-500 shrink-0" />}
        {status === "timed_out" && <XCircle className="w-4 h-4 text-amber-500 shrink-0" />}
        <span className="text-sm text-slate-600 dark:text-slate-300 truncate">
          {report ? `${report.slice(0, 60)}${report.length > 60 ? "..." : ""}` : "执行中..."}
        </span>
        <TaskStatusBadge status={status} />
      </div>
      <div className="flex items-center gap-3 shrink-0">
        {stats && (
          <span className="text-xs text-slate-500 dark:text-slate-400">
            {stats.success_count}/{stats.step_count} 成功 · {stats.elapsed_sec}s
          </span>
        )}
        {isRunning && onCancel && (
          <button onClick={onCancel} className="text-xs text-slate-500 hover:text-red-500 transition-colors dark:text-slate-400 dark:hover:text-red-400">
            取消
          </button>
        )}
      </div>
    </div>
  )
}
