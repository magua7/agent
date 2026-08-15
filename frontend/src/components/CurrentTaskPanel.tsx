import { Bot, Loader2, User, XCircle } from "lucide-react"
import type { CurrentTaskStatus, TaskDetail, TimelineEntry } from "../types/events"
import { ExecutionTimeline } from "./ExecutionTimeline"
import { ReportViewer } from "./ReportViewer"

function UserBubble({ content }: { content: string }) {
  return (
    <div className="flex items-start gap-3 justify-end">
      <div className="max-w-[75%] rounded-2xl rounded-tr-sm border border-cyan-200 bg-cyan-50 px-4 py-2.5 dark:border-cyan-800/50 dark:bg-cyan-900/30">
        <p className="text-sm whitespace-pre-wrap text-slate-800 dark:text-slate-100">{content}</p>
      </div>
      <div className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-cyan-600 text-white shadow-sm">
        <User className="w-4 h-4" />
      </div>
    </div>
  )
}

function AssistantShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3">
      <div className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-slate-100 text-cyan-600 shadow-sm dark:bg-slate-800 dark:text-cyan-300">
        <Bot className="w-4 h-4" />
      </div>
      <div className="flex-1 min-w-0">{children}</div>
    </div>
  )
}

interface Props {
  currentQuery: string
  timeline: TimelineEntry[]
  report: string | null
  stats: TaskDetail["stats"]
  error: string | null
  status: CurrentTaskStatus
  showUserQuery: boolean
}

export function CurrentTaskPanel({ currentQuery, timeline, report, stats, error, status, showUserQuery }: Props) {
  const isRunning = status === "running" || status === "waiting_approval"
  const isFinal = status === "completed" || status === "failed" || status === "cancelled" || status === "timed_out"

  return (
    <div className="space-y-3">
      {showUserQuery && currentQuery && <UserBubble content={currentQuery} />}

      <AssistantShell>
        {isRunning && (
          <>
            <div className="mb-3 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950/60">
            <div className="mb-3 flex items-center gap-2 text-sm text-slate-500 dark:text-slate-400">
              <Loader2 className="w-4 h-4 animate-spin" />
              执行中...
            </div>
              <ExecutionTimeline timeline={timeline} />
            </div>
            {report && (
              <div className="mb-3 overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950/60">
                <ReportViewer report={report} stats={null} />
              </div>
            )}
          </>
        )}

        {isFinal && (
          <>
            {timeline.length > 0 && (
              <div className="mb-3 rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950/60">
                <ExecutionTimeline timeline={timeline} />
              </div>
            )}
            {report && (
              <div className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-sm dark:border-slate-800 dark:bg-slate-950/60">
                <ReportViewer report={report} stats={stats} />
              </div>
            )}
            {status === "failed" && (
              <div className="py-8 text-center text-slate-500 dark:text-slate-400">
                <XCircle className="mx-auto mb-3 h-12 w-12 text-red-400" />
                <p className="text-lg">任务执行失败</p>
                {error && <p className="mt-1 text-sm text-red-500 dark:text-red-400">{error}</p>}
              </div>
            )}
            {status === "cancelled" && (
              <div className="py-8 text-center text-slate-500 dark:text-slate-400">
                <XCircle className="mx-auto mb-3 h-12 w-12 text-amber-400" />
                <p className="text-lg">任务已取消</p>
              </div>
            )}
            {status === "timed_out" && (
              <div className="py-8 text-center text-slate-500 dark:text-slate-400">
                <XCircle className="mx-auto mb-3 h-12 w-12 text-amber-400" />
                <p className="text-lg">任务执行超时</p>
                {error && <p className="mt-1 text-sm text-amber-600 dark:text-amber-400">{error}</p>}
              </div>
            )}
          </>
        )}
      </AssistantShell>
    </div>
  )
}
