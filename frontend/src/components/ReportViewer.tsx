import { Shield, Clock, CheckCircle2, XCircle } from "lucide-react"
import type { TaskDetail } from "../types/events"
import { MarkdownRenderer } from "./MarkdownRenderer"

interface Props {
  report: string
  stats: TaskDetail["stats"]
}

export function ReportViewer({ report, stats }: Props) {
  return (
    <div className="space-y-4 p-5">
      {stats && (
        <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
          <StatCard icon={<TerminalIcon />} label="总步骤" value={stats.step_count} color="text-blue-500" />
          <StatCard icon={<CheckCircle2 className="w-4 h-4" />} label="成功" value={stats.success_count} color="text-emerald-500" />
          <StatCard icon={<XCircle className="w-4 h-4" />} label="跳过" value={stats.skipped_count} color="text-amber-500" />
          <StatCard icon={<Clock className="w-4 h-4" />} label="耗时" value={`${stats.elapsed_sec}s`} color="text-slate-500" />
        </div>
      )}

      <div className="rounded-2xl border border-slate-200 bg-slate-50/80 p-5 dark:border-slate-800 dark:bg-slate-950/40">
        <div className="mb-4 flex items-center gap-2">
          <Shield className="w-5 h-5 text-cyan-500 dark:text-cyan-300" />
          <h2 className="text-lg font-semibold text-slate-900 dark:text-slate-100">安全报告</h2>
        </div>
        <MarkdownRenderer content={report} />
      </div>
    </div>
  )
}

function TerminalIcon() {
  return (
    <svg className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
      <polyline points="4 17 10 11 4 5" /><line x1="12" y1="19" x2="20" y2="19" />
    </svg>
  )
}

function StatCard({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: string | number; color: string }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white p-3 text-center shadow-sm dark:border-slate-800 dark:bg-slate-900/80">
      <div className={`mb-1 flex justify-center ${color}`}>{icon}</div>
      <div className={`text-lg font-bold ${color}`}>{value}</div>
      <div className="text-xs text-slate-500 dark:text-slate-400">{label}</div>
    </div>
  )
}
