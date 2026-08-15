import { useEffect, useMemo, useRef } from "react"
import { AlertTriangle, Bot, CheckCircle2, CircleDot, Database, FileCheck2, GitBranch, Loader2, SearchCheck, ShieldCheck, Wrench, XCircle } from "lucide-react"
import { formatDate } from "../model"
import type { JsonValue, TaskEvent } from "../types"

type StreamState = "connecting" | "live" | "reconnecting" | "closed"

interface EventPresentation {
  label: string
  icon: React.ReactNode
  accent: string
}

function presentation(event: TaskEvent): EventPresentation {
  const type = event.type
  if (type.includes("plan")) return { label: type === "plan_created" ? "计划已生成" : "计划已更新", icon: <GitBranch className="h-4 w-4" />, accent: "text-violet-600 dark:text-violet-300" }
  if (type.includes("skill")) return { label: "能力策略已选择", icon: <SearchCheck className="h-4 w-4" />, accent: "text-sky-600 dark:text-sky-300" }
  if (type.includes("tool")) return { label: type === "tool_started" ? "工具开始" : type === "tool_failed" ? "工具失败" : "工具完成", icon: <Wrench className="h-4 w-4" />, accent: type === "tool_failed" ? "text-red-600 dark:text-red-300" : "text-cyan-600 dark:text-cyan-300" }
  if (type.includes("evidence")) return { label: "证据已保存", icon: <Database className="h-4 w-4" />, accent: "text-blue-600 dark:text-blue-300" }
  if (type.includes("finding")) return { label: "发现已记录", icon: <FileCheck2 className="h-4 w-4" />, accent: "text-amber-600 dark:text-amber-300" }
  if (type.includes("verification")) {
    const finishedSuccess = type === "verification_finished" ? event.payload.success === true : type.endsWith("passed")
    const finishedFailure = type === "verification_finished" ? event.payload.success === false : type.endsWith("failed")
    return {
      label: finishedSuccess ? "验证通过" : finishedFailure ? "验证未通过" : "开始验证",
      icon: <ShieldCheck className="h-4 w-4" />,
      accent: finishedFailure ? "text-red-600 dark:text-red-300" : "text-emerald-600 dark:text-emerald-300",
    }
  }
  if (type.includes("node")) return { label: type === "node_started" ? "节点开始" : type === "node_failed" ? "节点失败" : "节点完成", icon: <CircleDot className="h-4 w-4" />, accent: type === "node_failed" ? "text-red-600 dark:text-red-300" : "text-indigo-600 dark:text-indigo-300" }
  if (type === "agent_thinking") return { label: "策略摘要", icon: <Bot className="h-4 w-4" />, accent: "text-fuchsia-600 dark:text-fuchsia-300" }
  if (type.endsWith("failed")) return { label: "任务失败", icon: <XCircle className="h-4 w-4" />, accent: "text-red-600 dark:text-red-300" }
  if (type.endsWith("completed")) return { label: "任务完成", icon: <CheckCircle2 className="h-4 w-4" />, accent: "text-emerald-600 dark:text-emerald-300" }
  if (type.endsWith("started")) return { label: "任务开始", icon: <Loader2 className="h-4 w-4 animate-spin" />, accent: "text-cyan-600 dark:text-cyan-300" }
  return { label: type.replace(/_/g, " "), icon: <CircleDot className="h-4 w-4" />, accent: "text-slate-500 dark:text-slate-400" }
}

function scalarText(value: JsonValue | undefined): string {
  if (typeof value === "string") return value
  if (typeof value === "number" || typeof value === "boolean") return String(value)
  if (Array.isArray(value)) return value.filter(item => typeof item === "string" || typeof item === "number").slice(0, 4).join("、")
  return ""
}

function eventSummary(event: TaskEvent): string {
  const payload = event.payload
  const keys = event.type === "agent_thinking"
    ? ["summary", "message", "reason"]
    : ["summary", "reason", "goal", "tool_name", "tool", "title", "skill_name", "node_id", "evidence_id", "finding_id"]
  for (const key of keys) {
    const result = scalarText(payload[key])
    if (result) return result.slice(0, 260)
  }
  return "事件已写入审计日志"
}

function StreamBadge({ state }: { state: StreamState }) {
  const config = state === "live"
    ? ["实时", "bg-emerald-500"]
    : state === "connecting"
      ? ["连接中", "bg-cyan-500"]
      : state === "reconnecting"
        ? ["重连中", "bg-amber-500"]
        : ["已关闭", "bg-slate-400"]
  return <span className="inline-flex items-center gap-1.5 text-[0.68rem] text-slate-500 dark:text-slate-400"><span className={`h-2 w-2 rounded-full ${config[1]} ${state !== "closed" ? "animate-pulse" : ""}`} />{config[0]}</span>
}

export function TimelinePanel({ events, streamState }: { events: TaskEvent[]; streamState: StreamState }) {
  const scrollRef = useRef<HTMLDivElement>(null)
  const ordered = useMemo(() => [...events].sort((a, b) => a.sequence && b.sequence ? a.sequence - b.sequence : a.timestamp.localeCompare(b.timestamp)), [events])

  useEffect(() => {
    if (scrollRef.current) scrollRef.current.scrollTop = scrollRef.current.scrollHeight
  }, [ordered.length])

  return (
    <aside className="surface-card flex min-h-[420px] min-w-0 flex-col overflow-hidden rounded-[28px] xl:h-[calc(100vh-6.5rem)]">
      <div className="flex items-start justify-between border-b border-slate-200/80 px-4 py-4 dark:border-slate-800">
        <div>
          <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">审计时间线</div>
          <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">SSE 历史重放与实时事件</div>
        </div>
        <StreamBadge state={streamState} />
      </div>

      <div ref={scrollRef} className="flex-1 overflow-y-auto px-4 py-4">
        {ordered.length === 0 ? (
          <div className="flex min-h-60 flex-col items-center justify-center text-center">
            <AlertTriangle className="mb-3 h-7 w-7 text-slate-400" />
            <div className="text-sm text-slate-600 dark:text-slate-300">暂无审计事件</div>
            <p className="mt-1 max-w-xs text-xs leading-5 text-slate-400">任务启动后，计划、工具、证据、发现和验证事件会按 sequence 展示。</p>
          </div>
        ) : (
          <div className="relative space-y-3 before:absolute before:bottom-3 before:left-[0.72rem] before:top-3 before:w-px before:bg-slate-200 dark:before:bg-slate-800">
            {ordered.map(event => {
              const item = presentation(event)
              return (
                <article key={eventKeyForView(event)} className="relative flex gap-3">
                  <div className={`relative z-10 mt-1 flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-white ring-4 ring-white dark:bg-slate-900 dark:ring-slate-900 ${item.accent}`}>{item.icon}</div>
                  <div className="min-w-0 flex-1 rounded-2xl border border-slate-200/80 bg-white/75 p-3 dark:border-slate-800 dark:bg-slate-900/55">
                    <div className="flex items-start justify-between gap-2">
                      <div className={`text-xs font-semibold ${item.accent}`}>{item.label}</div>
                      <span className="shrink-0 font-mono text-[0.62rem] text-slate-400">#{event.sequence || "—"}</span>
                    </div>
                    <p className="mt-1 break-words text-xs leading-5 text-slate-600 dark:text-slate-300">{eventSummary(event)}</p>
                    <div className="mt-2 text-[0.62rem] text-slate-400">{formatDate(event.timestamp)}</div>
                  </div>
                </article>
              )
            })}
          </div>
        )}
      </div>
    </aside>
  )
}

function eventKeyForView(event: TaskEvent): string {
  return event.event_id || `${event.sequence}:${event.type}:${event.timestamp}`
}
