import { useState } from "react"
import { CheckCircle2, Circle, Loader2, AlertTriangle, XCircle, ChevronDown, ChevronRight, Terminal, Globe, Wrench, Brain, ListChecks, Database, Lightbulb, Sparkles } from "lucide-react"
import type { KnowledgeDetails, TimelineEntry } from "../types/events"
import { isComplexityEntry, isIntentEntry, isKnowledgeEntry, isPlanEntry, selectTimelineEntries } from "../lib/timeline"
import { StatusBadge, RiskBadge } from "./StatusBadge"

function ToolIcon({ tool }: { tool: string }) {
  if (tool.includes("nmap") || tool.includes("scan")) return <Terminal className="w-3.5 h-3.5" />
  if (tool.includes("browser") || tool.includes("navigate") || tool.includes("click") || tool.includes("fill") || tool.includes("screenshot") || tool.includes("snapshot")) {
    return <Globe className="w-3.5 h-3.5" />
  }
  return <Wrench className="w-3.5 h-3.5" />
}

function PhaseRow({ phase, status }: { phase: string; status: string }) {
  return (
    <div className="flex items-center gap-3 py-2">
      {status === "running" ? (
        <Loader2 className="w-4 h-4 shrink-0 animate-spin text-cyan-500 dark:text-cyan-300" />
      ) : (
        <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-500 dark:text-emerald-300" />
      )}
      <span className="text-sm text-slate-700 dark:text-slate-200">{phase}</span>
    </div>
  )
}

function ToolRow({ entry }: { entry: TimelineEntry }) {
  const [expanded, setExpanded] = useState(false)
  const tool = entry.tool || ""
  const risk = entry.risk || "level0"
  const status = entry.status || ""
  const output = entry.outputPreview || ""
  const sourceLabel = entry.toolSource === "mcp"
    ? `MCP · ${entry.toolSourceId || "unknown"}`
    : "Builtin"
  const hasDetails = Boolean(
    output
    || entry.callId
    || entry.resultId
    || entry.evidenceId
    || entry.errorCode,
  )

  const statusIcon = () => {
    switch (status) {
      case "running": return <Loader2 className="w-3.5 h-3.5 animate-spin text-cyan-500 dark:text-cyan-300" />
      case "success":
      case "success_after_retry": return <CheckCircle2 className="w-3.5 h-3.5 text-emerald-500 dark:text-emerald-300" />
      case "timeout": return <AlertTriangle className="w-3.5 h-3.5 text-amber-500 dark:text-amber-300" />
      case "error":
      case "unreachable": return <XCircle className="w-3.5 h-3.5 text-red-500 dark:text-red-300" />
      case "skipped": return <Circle className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />
      default: return <Circle className="w-3.5 h-3.5 text-slate-400 dark:text-slate-500" />
    }
  }

  return (
    <div className="ml-2 border-l-2 border-slate-200 pl-4 dark:border-slate-700">
      <button
        onClick={() => hasDetails && setExpanded(!expanded)}
        className="group flex w-full items-center gap-2 rounded-xl px-2 py-1.5 text-left transition hover:bg-slate-100 dark:hover:bg-slate-800/60"
      >
        {statusIcon()}
        <ToolIcon tool={tool} />
        <span className="font-mono text-sm text-slate-700 dark:text-slate-200">{tool}</span>
        <span className="rounded-md border border-slate-200 px-1.5 py-0.5 text-[10px] text-slate-500 dark:border-slate-700 dark:text-slate-400">
          {sourceLabel}
        </span>
        <RiskBadge risk={risk} />
        <StatusBadge status={status} />
        {entry.elapsed != null && (
          <span className="ml-auto text-xs text-slate-500 dark:text-slate-400">{entry.elapsed}s</span>
        )}
        {hasDetails && (
          <span className="text-slate-400 dark:text-slate-500">
            {expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}
          </span>
        )}
      </button>
      {expanded && hasDetails && (
        <div className="mb-2 ml-8 space-y-2 rounded-xl border border-slate-200 bg-slate-50 p-3 text-xs dark:border-slate-800 dark:bg-slate-950/50">
          <dl className="grid grid-cols-[90px_1fr] gap-x-2 gap-y-1 text-slate-500 dark:text-slate-400">
            <dt>Call</dt>
            <dd className="break-all font-mono">{entry.callId || "-"}</dd>
            <dt>Result</dt>
            <dd className="break-all font-mono">{entry.resultId || "-"}</dd>
            <dt>Evidence</dt>
            <dd className="break-all font-mono">{entry.evidenceId || "-"}</dd>
            <dt>Snapshot</dt>
            <dd className="break-all font-mono">{entry.snapshotVersion || "-"}</dd>
            <dt>Runtime</dt>
            <dd>{entry.runtimeStatus || entry.status || "-"}</dd>
            {entry.errorCode && (
              <>
                <dt>Error</dt>
                <dd className="font-mono text-red-600 dark:text-red-300">{entry.errorCode}</dd>
              </>
            )}
          </dl>
          {output && <pre className="output-pre">{output}</pre>}
        </div>
      )}
    </div>
  )
}

function SystemRow({ kind, message }: { kind: string; message: string }) {
  const colors = {
    warning: "border-amber-200 bg-amber-50 text-amber-700 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-300",
    error: "border-red-200 bg-red-50 text-red-700 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300",
    debug: "border-slate-200 bg-white text-slate-500 dark:border-slate-800 dark:bg-slate-900/70 dark:text-slate-400",
  }
  const color = colors[kind as keyof typeof colors] || colors.debug

  return (
    <div className="ml-2 border-l-2 border-slate-200 py-1 pl-4 dark:border-slate-700">
      <span className={`inline-block rounded-xl border px-2 py-1 text-xs ${color}`}>{message}</span>
    </div>
  )
}

function ThinkingRow({ entry }: { entry: TimelineEntry }) {
  const [expanded, setExpanded] = useState(true)
  const text = entry.text || ""
  const stage = entry.stage || "reasoning"
  const isConclusion = stage === "conclusion"
  const borderColor = isConclusion
    ? "border-emerald-200 dark:border-emerald-900/60"
    : "border-cyan-200 dark:border-cyan-900/60"
  const bgColor = isConclusion
    ? "bg-emerald-50 dark:bg-emerald-950/25"
    : "bg-cyan-50 dark:bg-cyan-950/25"
  const iconColor = isConclusion
    ? "text-emerald-500 dark:text-emerald-300"
    : "text-cyan-500 dark:text-cyan-300"

  return (
    <div className={`ml-2 border-l-2 ${borderColor} pl-4 dark:border-cyan-900/60`}>
      <button
        onClick={() => setExpanded(!expanded)}
        className="group flex w-full items-center gap-2 rounded-xl px-2 py-1.5 text-left transition hover:bg-slate-100 dark:hover:bg-slate-800/60"
      >
        <Lightbulb className={`h-4 w-4 shrink-0 ${iconColor}`} />
        <span className="text-sm text-slate-700 dark:text-slate-200">
          {isConclusion ? "思考结论" : "思考中"}
        </span>
        {entry.iteration != null && (
          <span className="text-xs text-slate-400 dark:text-slate-500"># {entry.iteration}</span>
        )}
        <span className="text-xs text-slate-400 dark:text-slate-500">{expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}</span>
      </button>
      {expanded && text && (
        <div className={`mb-2 ml-8 rounded-2xl border ${borderColor} ${bgColor} p-3 text-xs leading-5 text-slate-600 dark:text-slate-300`}>
          {text}
        </div>
      )}
    </div>
  )
}

function RetrospectiveCard({ summary }: { summary: string }) {
  const [expanded, setExpanded] = useState(true)
  return (
    <div className="ml-2 border-l-2 border-fuchsia-200 pl-4 dark:border-fuchsia-900/60">
      <button
        onClick={() => setExpanded(!expanded)}
        className="group flex w-full items-center gap-2 rounded-xl px-2 py-1.5 text-left transition hover:bg-slate-100 dark:hover:bg-slate-800/60"
      >
        <Sparkles className="h-4 w-4 shrink-0 text-fuchsia-500 dark:text-fuchsia-300" />
        <span className="text-sm text-slate-700 dark:text-slate-200">任务复盘</span>
        <span className="text-xs text-slate-400 dark:text-slate-500">{expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}</span>
      </button>
      {expanded && summary && (
        <div className="mb-2 ml-8 rounded-2xl border border-fuchsia-100 bg-fuchsia-50 p-3 text-xs leading-5 text-slate-600 dark:border-fuchsia-900/60 dark:bg-fuchsia-950/20 dark:text-slate-300">
          {summary}
        </div>
      )}
    </div>
  )
}

function IntentRow({ details }: { details: Record<string, any> }) {
  const [expanded, setExpanded] = useState(true)
  return (
    <div className="ml-2 border-l-2 border-cyan-200 pl-4 dark:border-cyan-900/60">
      <button
        onClick={() => setExpanded(!expanded)}
        className="group flex w-full items-center gap-2 rounded-xl px-2 py-1.5 text-left transition hover:bg-slate-100 dark:hover:bg-slate-800/60"
      >
        <Brain className="w-4 h-4 shrink-0 text-cyan-500 dark:text-cyan-300" />
        <span className="text-sm text-slate-700 dark:text-slate-200">意图解析</span>
        <span className="text-xs text-slate-400 dark:text-slate-500">{expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}</span>
      </button>
      {expanded && (
        <div className="mb-2 ml-8 space-y-1 rounded-2xl border border-cyan-100 bg-cyan-50 p-3 text-xs dark:border-cyan-900/60 dark:bg-cyan-950/25">
          <div className="text-slate-600 dark:text-slate-300">
            <span className="text-slate-500 dark:text-slate-400">目标:</span> {details.target || "未指定"}
          </div>
          <div className="text-slate-600 dark:text-slate-300">
            <span className="text-slate-500 dark:text-slate-400">任务类型:</span> {details.task_type || "general"}
          </div>
          <div className="text-slate-600 dark:text-slate-300">
            <span className="text-slate-500 dark:text-slate-400">目标描述:</span> {details.goal || "无"}
          </div>
        </div>
      )}
    </div>
  )
}

function PlanRow({ details }: { details: Record<string, any> }) {
  const [expanded, setExpanded] = useState(true)
  const steps: Array<{ step: number; tool: string; reason: string; risk: string }> = details.steps || []
  return (
    <div className="ml-2 border-l-2 border-purple-200 pl-4 dark:border-purple-900/60">
      <button
        onClick={() => setExpanded(!expanded)}
        className="group flex w-full items-center gap-2 rounded-xl px-2 py-1.5 text-left transition hover:bg-slate-100 dark:hover:bg-slate-800/60"
      >
        <ListChecks className="w-4 h-4 shrink-0 text-purple-500 dark:text-purple-300" />
        <span className="text-sm text-slate-700 dark:text-slate-200">执行计划 ({steps.length}步)</span>
        <span className="text-xs text-slate-400 dark:text-slate-500">{expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}</span>
      </button>
      {expanded && steps.length > 0 && (
        <div className="mb-2 ml-8 space-y-1">
          {steps.map((step, index) => (
            <div key={index} className="flex items-center gap-2 py-1 text-xs text-slate-600 dark:text-slate-300">
              <span className="w-4 shrink-0 text-slate-400 dark:text-slate-500">{step.step}.</span>
              <span className="font-mono text-slate-700 dark:text-slate-200">{step.tool}</span>
              <span className="max-w-[200px] truncate text-slate-500 dark:text-slate-400">{step.reason}</span>
              <RiskBadge risk={step.risk} />
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ComplexityRow({ details }: { details: Record<string, any> }) {
  const [expanded, setExpanded] = useState(true)
  const reasons: string[] = details.reasons || []
  return (
    <div className="ml-2 border-l-2 border-sky-200 pl-4 dark:border-sky-900/60">
      <button
        onClick={() => setExpanded(!expanded)}
        className="group flex w-full items-center gap-2 rounded-xl px-2 py-1.5 text-left transition hover:bg-slate-100 dark:hover:bg-slate-800/60"
      >
        <Brain className="w-4 h-4 shrink-0 text-sky-500 dark:text-sky-300" />
        <span className="text-sm text-slate-700 dark:text-slate-200">复杂度判断</span>
        <span className="text-xs text-slate-400 dark:text-slate-500">{expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}</span>
      </button>
      {expanded && (
        <div className="mb-2 ml-8 rounded-2xl border border-sky-100 bg-sky-50 p-3 text-xs dark:border-sky-900/60 dark:bg-sky-950/20">
          <div className="mb-2 flex items-center gap-2 text-slate-700 dark:text-slate-200">
            <span className="font-medium">模式:</span>
            <StatusBadge status={details.mode || 'unknown'} />
            <span className="text-slate-500 dark:text-slate-400">score={details.score ?? 0}</span>
          </div>
          <div className="space-y-1 text-slate-600 dark:text-slate-300">
            {reasons.map((reason, index) => (
              <div key={index}>- {reason}</div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

function KnowledgeRow({ details }: { details: KnowledgeDetails }) {
  const [expanded, setExpanded] = useState(false)
  const titles = details.top_titles || []
  const paths = details.top_paths || []
  return (
    <div className="ml-2 border-l-2 border-sky-200 pl-4 dark:border-sky-900/60">
      <button
        onClick={() => setExpanded(!expanded)}
        className="group flex w-full items-center gap-2 rounded-xl px-2 py-1.5 text-left transition hover:bg-slate-100 dark:hover:bg-slate-800/60"
      >
        <Database className="w-4 h-4 shrink-0 text-sky-500 dark:text-sky-300" />
        <span className="text-sm text-slate-700 dark:text-slate-200">知识库检索</span>
        <span className="text-xs text-slate-400 dark:text-slate-500">{expanded ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />}</span>
      </button>
      <div className="mb-2 ml-8 rounded-2xl border border-sky-100 bg-sky-50 p-3 text-xs dark:border-sky-900/60 dark:bg-sky-950/20">
        <div className="space-y-1 text-slate-600 dark:text-slate-300">
          <div><span className="text-slate-500 dark:text-slate-400">检索词:</span> {details.used_query || details.query || "未记录"}</div>
          <div><span className="text-slate-500 dark:text-slate-400">命中:</span> {details.hits ?? 0} 条{details.fallback_used ? " · 已使用备用检索词" : ""}</div>
          {titles.length > 0 && (
            <div>
              <span className="text-slate-500 dark:text-slate-400">命中文档:</span>
              <div className="mt-1 space-y-1">
                {titles.slice(0, 3).map((title, index) => (
                  <div key={`${title}-${index}`}>- {title}</div>
                ))}
              </div>
            </div>
          )}
          {expanded && paths.length > 0 && (
            <div>
              <span className="text-slate-500 dark:text-slate-400">路径:</span>
              <div className="mt-1 space-y-1 break-all">
                {paths.slice(0, 3).map((path, index) => (
                  <div key={`${path}-${index}`}>- {path}</div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

interface Props {
  timeline: TimelineEntry[]
}

export function ExecutionTimeline({ timeline }: Props) {
  const entries = selectTimelineEntries(timeline)
  if (entries.length === 0) return null

  return (
    <div className="space-y-0.5 py-4">
      {entries.map((entry, index) => {
        if (entry.kind === "phase") return <PhaseRow key={index} phase={entry.phase || ""} status={entry.status || ""} />
        if (entry.kind === "tool") return <ToolRow key={index} entry={entry} />
        if (entry.kind === "warning") return <SystemRow key={index} kind="warning" message={entry.message || ""} />
        if (entry.kind === "error") return <SystemRow key={index} kind="error" message={entry.message || ""} />
        if (isIntentEntry(entry)) {
          return <IntentRow key={index} details={entry.details} />
        }
        if (isPlanEntry(entry)) {
          return <PlanRow key={index} details={entry.details} />
        }
        if (isComplexityEntry(entry)) {
          return <ComplexityRow key={index} details={entry.details} />
        }
        if (isKnowledgeEntry(entry)) {
          return <KnowledgeRow key={index} details={entry.details as KnowledgeDetails} />
        }
        if (entry.kind === "thinking") {
          return <ThinkingRow key={index} entry={entry} />
        }
        if (entry.kind === "retrospective") {
          return <RetrospectiveCard key={index} summary={entry.summary || ""} />
        }
        if (entry.kind === "approval") {
          if (!entry.resolved) return null
          return (
            <div key={index} className="ml-2 border-l-2 border-slate-200 py-1 pl-4 dark:border-slate-700">
              <span className={`text-xs ${entry.approved ? "text-emerald-600 dark:text-emerald-300" : "text-amber-600 dark:text-amber-300"}`}>
                {entry.approved ? "[已批准]" : "[已跳过]"} {entry.decision || ""}
              </span>
            </div>
          )
        }
        return null
      })}
    </div>
  )
}
