import { Clock3, Plus, RefreshCw, Shield, Target } from "lucide-react"
import { formatDate } from "../model"
import type { TaskSummary } from "../types"
import { StatusPill } from "./StatusPill"

interface Props {
  tasks: TaskSummary[]
  selectedTaskId: string | null
  loading: boolean
  onSelect: (taskId: string) => void
  onCreate: () => void
  onRefresh: () => void
}

export function TaskSidebar({ tasks, selectedTaskId, loading, onSelect, onCreate, onRefresh }: Props) {
  return (
    <aside className="surface-card flex min-h-0 flex-col overflow-hidden rounded-[28px] lg:h-[calc(100vh-6.5rem)]">
      <div className="border-b border-slate-200/80 p-4 dark:border-slate-800">
        <button onClick={onCreate} className="flex w-full items-center justify-center gap-2 rounded-2xl bg-cyan-600 px-4 py-3 text-sm font-semibold text-white shadow-sm transition hover:bg-cyan-700">
          <Plus className="h-4 w-4" />新建安全任务
        </button>
        <div className="mt-4 flex items-center justify-between px-1">
          <div>
            <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">任务历史</div>
            <div className="mt-0.5 text-xs text-slate-500 dark:text-slate-400">{tasks.length} 个独立 Run</div>
          </div>
          <button onClick={onRefresh} disabled={loading} className="rounded-xl p-2 text-slate-400 transition hover:bg-slate-100 hover:text-cyan-600 disabled:opacity-50 dark:hover:bg-slate-800 dark:hover:text-cyan-300" aria-label="刷新任务">
            <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-3">
        {tasks.length === 0 ? (
          <div className="flex min-h-52 flex-col items-center justify-center px-5 text-center">
            <div className="mb-3 flex h-12 w-12 items-center justify-center rounded-2xl bg-slate-100 text-slate-400 dark:bg-slate-800"><Shield className="h-6 w-6" /></div>
            <div className="text-sm font-medium text-slate-700 dark:text-slate-300">暂无任务</div>
            <p className="mt-1 text-xs leading-5 text-slate-500 dark:text-slate-400">创建一个明确授权的 localhost 检查任务开始。</p>
          </div>
        ) : (
          <div className="space-y-2">
            {tasks.map(task => {
              const selected = task.id === selectedTaskId
              return (
                <button
                  key={task.id}
                  onClick={() => onSelect(task.id)}
                  className={`w-full rounded-[22px] border p-3.5 text-left transition ${selected
                    ? "border-cyan-300 bg-cyan-50/90 shadow-sm dark:border-cyan-800 dark:bg-cyan-950/30"
                    : "border-transparent bg-white/55 hover:border-slate-200 hover:bg-white dark:bg-slate-900/35 dark:hover:border-slate-800 dark:hover:bg-slate-900/70"}`}
                >
                  <div className="mb-2 flex items-start justify-between gap-2">
                    <div className="min-w-0 flex-1 truncate text-sm font-semibold text-slate-900 dark:text-slate-100">{task.title}</div>
                    <StatusPill status={task.status} compact />
                  </div>
                  <p className="line-clamp-2 text-xs leading-5 text-slate-500 dark:text-slate-400">{task.description || "等待任务解释器生成 TaskSpec"}</p>
                  <div className="mt-3 flex flex-wrap items-center gap-x-3 gap-y-1 text-[0.68rem] text-slate-400 dark:text-slate-500">
                    {task.target && <span className="inline-flex items-center gap-1"><Target className="h-3 w-3" />{task.target}</span>}
                    <span className="inline-flex items-center gap-1"><Clock3 className="h-3 w-3" />{formatDate(task.updatedAt || task.createdAt)}</span>
                  </div>
                </button>
              )
            })}
          </div>
        )}
      </div>
    </aside>
  )
}

