import { Activity, BarChart3, Brain, ChevronDown, ChevronRight, Database, ListChecks, Network, Wrench } from "lucide-react"
import { useMemo, useState } from "react"
import type { CurrentTaskStatus, KnowledgeDetails, TimelineEntry } from "../types/events"
import { getTimelineSummary, isComplexityEntry, isKnowledgeEntry, isPlanEntry, isIntentEntry, selectTimelineEntries } from "../lib/timeline"
import { RiskBadge, StatusBadge } from "./StatusBadge"
import { AttackPathGraph } from "./AttackPathGraph"
import { useAttackGraph } from "../hooks/useAttackGraph"

interface Props {
  timeline: TimelineEntry[]
  status: CurrentTaskStatus
  width?: number
}

type Tab = "flow" | "graph"

export function ExecutionFlowPanel({ timeline, status, width }: Props) {
  const [expanded, setExpanded] = useState(true)
  const [tab, setTab] = useState<Tab>("flow")

  const summary = useMemo(() => getTimelineSummary(timeline), [timeline])
  const entries = useMemo(() => selectTimelineEntries(timeline), [timeline])
  const { nodes, edges } = useAttackGraph(timeline)

  return (
    <aside style={{ width }} className="hidden shrink-0 border-l border-slate-200 bg-white/80 backdrop-blur dark:border-slate-800 dark:bg-slate-950/70 xl:flex xl:flex-col">
      <div className="shrink-0 px-4 pb-3 pt-5">
        <div className="mb-4 flex items-start justify-between gap-3">
          <div>
            <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">执行流程</div>
            <div className="mt-1 text-xs leading-5 text-slate-500 dark:text-slate-400">
              展示智能体工作过程与攻击路径
            </div>
          </div>
          <StatusBadge status={status} />
        </div>

        <div className="mb-4 grid grid-cols-2 gap-3 text-left">
          <MetricCard label="阶段" value={summary.phaseCount} icon={<Activity className="h-4 w-4" />} />
          <MetricCard label="工具调用" value={summary.toolCount} icon={<Wrench className="h-4 w-4" />} />
          <MetricCard label="思考链" value={summary.thinkingCount} icon={<Brain className="h-4 w-4" />} />
          <MetricCard label="知识检索" value={summary.knowledgeCount} icon={<Database className="h-4 w-4" />} />
        </div>

        <div className="flex gap-1 rounded-2xl border border-slate-200 bg-slate-100 p-1 dark:border-slate-800 dark:bg-slate-900">
          <button
            type="button"
            onClick={() => setTab("flow")}
            className={`flex flex-1 items-center justify-center gap-2 rounded-xl px-3 py-2 text-xs font-medium transition-all ${
              tab === "flow"
                ? "bg-white text-slate-900 shadow-sm dark:bg-slate-800 dark:text-slate-100"
                : "text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-300"
            }`}
          >
            <ListChecks className="h-4 w-4" />
            执行时间线
          </button>
          <button
            type="button"
            onClick={() => setTab("graph")}
            className={`flex flex-1 items-center justify-center gap-2 rounded-xl px-3 py-2 text-xs font-medium transition-all ${
              tab === "graph"
                ? "bg-white text-slate-900 shadow-sm dark:bg-slate-800 dark:text-slate-100"
                : "text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-300"
            }`}
          >
            <Network className="h-4 w-4" />
            攻击路径图
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-hidden px-4 pb-5">
        {tab === "flow" ? (
          <div className="flex h-full flex-col overflow-hidden rounded-3xl border border-slate-200 bg-slate-50/80 dark:border-slate-800 dark:bg-slate-900/60">
            <button
              type="button"
              onClick={() => setExpanded(prev => !prev)}
              className="flex w-full shrink-0 items-center justify-between px-4 pb-3 pt-4 text-left"
            >
              <div>
                <div className="text-sm font-semibold text-slate-900 dark:text-slate-100">智能体执行时间线</div>
                <div className="text-xs text-slate-500 dark:text-slate-400">按事件顺序折叠展示</div>
              </div>
              {expanded ? <ChevronDown className="h-4 w-4 text-slate-500" /> : <ChevronRight className="h-4 w-4 text-slate-500" />}
            </button>

            <div className="flex-1 overflow-y-auto px-4 pb-4">
              {expanded && (
                <div className="space-y-3">
                  {entries.length === 0 ? (
                    <div className="rounded-2xl border border-dashed border-slate-300 bg-white/70 px-4 py-6 text-sm text-slate-500 dark:border-slate-700 dark:bg-slate-950/40 dark:text-slate-400">
                      当前还没有执行步骤，任务开始后会在这里展示规划、知识检索、工具调用与状态变化。
                    </div>
                  ) : (
                    entries.map((entry, index) => <FlowEntry key={index} entry={entry} />)
                  )}
                </div>
              )}
            </div>
          </div>
        ) : (
          <div className="h-full min-h-[320px] overflow-hidden rounded-3xl border border-slate-200 bg-slate-50/80 dark:border-slate-800 dark:bg-slate-900/60">
            <AttackPathGraph nodes={nodes} edges={edges} />
          </div>
        )}
      </div>
    </aside>
  )
}

function MetricCard({ label, value, icon }: { label: string; value: number; icon: React.ReactNode }) {
  return (
    <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 shadow-sm dark:border-slate-800 dark:bg-slate-900">
      <div className="mb-2 flex items-center gap-2 text-cyan-600 dark:text-cyan-300">{icon}</div>
      <div className="text-lg font-semibold text-slate-900 dark:text-slate-100">{value}</div>
      <div className="text-xs text-slate-500 dark:text-slate-400">{label}</div>
    </div>
  )
}

function KnowledgeCard({ details }: { details: KnowledgeDetails }) {
  const [expanded, setExpanded] = useState(false)
  const titles = details.top_titles || []
  const paths = details.top_paths || []
  return (
    <div className="rounded-2xl border border-sky-200 bg-sky-50 px-4 py-3 dark:border-sky-900/60 dark:bg-sky-950/25">
      <button type="button" onClick={() => setExpanded(prev => !prev)} className="flex w-full items-center justify-between gap-3 text-left">
        <div>
          <div className="text-sm font-medium text-sky-800 dark:text-sky-300">知识库检索</div>
          <div className="mt-1 text-xs text-slate-600 dark:text-slate-300">
            检索词：{details.used_query || details.query || "未记录"}
          </div>
        </div>
        {expanded ? <ChevronDown className="h-4 w-4 text-slate-500" /> : <ChevronRight className="h-4 w-4 text-slate-500" />}
      </button>
      <div className="mt-2 space-y-1 text-xs text-slate-600 dark:text-slate-300">
        <div>命中：{details.hits ?? 0} 条{details.fallback_used ? " · 已使用备用检索词" : ""}</div>
        {titles.length > 0 && (
          <div className="space-y-1">
            {titles.slice(0, 3).map((title, index) => (
              <div key={`${title}-${index}`}>- {title}</div>
            ))}
          </div>
        )}
        {expanded && paths.length > 0 && (
          <div className="space-y-1 break-all pt-1 text-slate-500 dark:text-slate-400">
            {paths.slice(0, 3).map((path, index) => (
              <div key={`${path}-${index}`}>- {path}</div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

function FlowEntry({ entry }: { entry: TimelineEntry }) {
  if (isComplexityEntry(entry)) {
    return (
      <div className="rounded-2xl border border-sky-200 bg-sky-50 px-4 py-3 dark:border-sky-900/60 dark:bg-sky-950/25">
        <div className="mb-1 text-sm font-medium text-sky-800 dark:text-sky-300">复杂度判断</div>
        <div className="text-xs text-slate-600 dark:text-slate-300">模式：{(entry.details as Record<string, any>).mode} · score={(entry.details as Record<string, any>).score}</div>
        {Array.isArray((entry.details as Record<string, any>).reasons) && (entry.details as Record<string, any>).reasons.length > 0 && (
          <div className="mt-2 space-y-1 text-xs text-slate-600 dark:text-slate-300">
            {((entry.details as Record<string, any>).reasons as string[]).map((reason: string, index: number) => (
              <div key={index}>- {reason}</div>
            ))}
          </div>
        )}
      </div>
    )
  }

  if (isKnowledgeEntry(entry)) {
    return <KnowledgeCard details={entry.details as KnowledgeDetails} />
  }

  if (entry.kind === "thinking") {
    return (
      <div className={`rounded-2xl border px-4 py-3 ${entry.stage === "conclusion"
        ? "border-emerald-200 bg-emerald-50 dark:border-emerald-900/60 dark:bg-emerald-950/25"
        : "border-cyan-200 bg-cyan-50 dark:border-cyan-900/60 dark:bg-cyan-950/25"}`}>
        <div className={`mb-1 text-sm font-medium ${entry.stage === "conclusion"
          ? "text-emerald-800 dark:text-emerald-300"
          : "text-cyan-800 dark:text-cyan-300"}`}>
          {entry.stage === "conclusion" ? "思考结论" : "思考中"}
          {entry.iteration != null && <span className="ml-2 text-xs opacity-70">#{entry.iteration}</span>}
        </div>
        <div className="text-xs leading-5 text-slate-600 dark:text-slate-300">{entry.text}</div>
      </div>
    )
  }

  if (entry.kind === "retrospective") {
    return (
      <div className="rounded-2xl border border-fuchsia-200 bg-fuchsia-50 px-4 py-3 dark:border-fuchsia-900/60 dark:bg-fuchsia-950/25">
        <div className="mb-1 text-sm font-medium text-fuchsia-800 dark:text-fuchsia-300">任务复盘</div>
        <div className="text-xs leading-5 text-slate-600 dark:text-slate-300">{entry.summary}</div>
      </div>
    )
  }

  if (entry.kind === "phase") {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 dark:border-slate-800 dark:bg-slate-950/50">
        <div className="mb-1 flex items-center justify-between gap-3">
          <div className="text-sm font-medium text-slate-900 dark:text-slate-100">{entry.phase || "阶段"}</div>
          <StatusBadge status={entry.status || "done"} />
        </div>
        <div className="text-xs text-slate-500 dark:text-slate-400">
          第 {entry.num ?? "-"} 步 / 共 {entry.total ?? "-"} 步
        </div>
      </div>
    )
  }

  if (entry.kind === "tool") {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 dark:border-slate-800 dark:bg-slate-950/50">
        <div className="mb-2 flex items-center justify-between gap-3">
          <div className="truncate text-sm font-mono text-slate-900 dark:text-slate-100">{entry.tool}</div>
          <div className="flex items-center gap-2">
            {entry.risk && <RiskBadge risk={entry.risk} />}
            <StatusBadge status={entry.status || "running"} />
          </div>
        </div>
        <div className="text-xs text-slate-500 dark:text-slate-400">
          Step {entry.stepNum ?? "-"}
          {entry.elapsed != null ? ` · ${entry.elapsed}s` : ""}
        </div>
        {entry.outputPreview && (
          <div className="mt-2 rounded-xl bg-slate-50 px-3 py-2 text-xs leading-5 text-slate-600 dark:bg-slate-900 dark:text-slate-400">
            {entry.outputPreview}
          </div>
        )}
      </div>
    )
  }

  if (entry.kind === "warning" || entry.kind === "error") {
    return (
      <div className="rounded-2xl border border-yellow-200 bg-yellow-50 px-4 py-3 text-sm text-yellow-700 dark:border-yellow-900/60 dark:bg-yellow-950/30 dark:text-yellow-300">
        {entry.message}
      </div>
    )
  }

  if (entry.kind === "approval") {
    const resolvedText = entry.resolved ? (entry.approved ? "已批准" : "已跳过") : "等待确认"
    return (
      <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 dark:border-slate-800 dark:bg-slate-950/50">
        <div className="mb-1 flex items-center justify-between gap-3">
          <div className="text-sm font-medium text-slate-900 dark:text-slate-100">风险确认</div>
          <span className="text-xs text-slate-500 dark:text-slate-400">{resolvedText}</span>
        </div>
        <div className="text-xs text-slate-500 dark:text-slate-400">
          {entry.step?.tool || "待确认操作"}
        </div>
      </div>
    )
  }

  if (isIntentEntry(entry)) {
    return (
      <div className="rounded-2xl border border-cyan-200 bg-cyan-50 px-4 py-3 dark:border-cyan-900/60 dark:bg-cyan-950/25">
        <div className="mb-1 text-sm font-medium text-cyan-800 dark:text-cyan-300">任务理解</div>
        <div className="space-y-1 text-xs text-cyan-700 dark:text-cyan-200">
          <div>目标：{(entry.details as Record<string, any>)?.target || "未指定"}</div>
          <div>类型：{(entry.details as Record<string, any>)?.task_type || "general"}</div>
          <div>描述：{(entry.details as Record<string, any>)?.goal || "无"}</div>
        </div>
      </div>
    )
  }

  if (isPlanEntry(entry)) {
    const steps = (entry.details as Record<string, any>)?.steps || []
    return (
      <div className="rounded-2xl border border-purple-200 bg-purple-50 px-4 py-3 dark:border-purple-900/60 dark:bg-purple-950/25">
        <div className="mb-2 flex items-center gap-2 text-sm font-medium text-purple-800 dark:text-purple-300">
          <ListChecks className="h-4 w-4" />
          执行计划
        </div>
        <div className="space-y-2 text-xs text-purple-700 dark:text-purple-200">
          {steps.map((step: { step: number; tool: string; reason: string; risk: string }) => (
            <div key={`${step.step}-${step.tool}`} className="rounded-xl bg-white/70 px-3 py-2 dark:bg-slate-950/40">
              <div className="mb-1 flex items-center justify-between gap-2">
                <span className="font-medium">{step.step}. {step.tool}</span>
                <RiskBadge risk={step.risk} />
              </div>
              <div>{step.reason}</div>
            </div>
          ))}
        </div>
      </div>
    )
  }

  if (entry.kind === "debug") {
    return (
      <div className="rounded-2xl border border-slate-200 bg-white px-4 py-3 text-xs text-slate-500 dark:border-slate-800 dark:bg-slate-950/50 dark:text-slate-400">
        {entry.message}
      </div>
    )
  }

  return null
}
