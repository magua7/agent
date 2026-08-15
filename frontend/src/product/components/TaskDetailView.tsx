import { useEffect, useMemo, useState } from "react"
import { AlertTriangle, Ban, CheckCircle2, ClipboardCheck, Clock3, Database, FileSearch, Flag, GitBranch, Loader2, RefreshCw, ShieldAlert, ShieldCheck, Target, XCircle } from "lucide-react"
import { formatDate, isTerminalStatus } from "../model"
import type { EvidenceRecord, JsonObject, JsonValue, TaskDetail, TaskSummary, VerificationRecord } from "../types"
import { PlanGraph } from "./PlanGraph"
import { SafeMarkdown } from "./SafeMarkdown"
import { SeverityPill, StatusPill } from "./StatusPill"

type Tab = "overview" | "plan" | "evidence" | "findings" | "report"

interface Props {
  summary: TaskSummary | null
  detail: TaskDetail | null
  loading: boolean
  busy: boolean
  onCancel: (taskId: string) => void
  onRefresh: () => void
  onCreate: () => void
  evidenceDetails: Record<string, EvidenceRecord>
  evidenceLoading: Record<string, boolean>
  onLoadEvidence: (taskId: string, evidenceId: string) => void
}

const TABS: { id: Tab; label: string; icon: React.ReactNode }[] = [
  { id: "overview", label: "概览", icon: <ClipboardCheck className="h-4 w-4" /> },
  { id: "plan", label: "计划", icon: <GitBranch className="h-4 w-4" /> },
  { id: "evidence", label: "证据", icon: <Database className="h-4 w-4" /> },
  { id: "findings", label: "发现", icon: <Flag className="h-4 w-4" /> },
  { id: "report", label: "报告", icon: <FileSearch className="h-4 w-4" /> },
]

export function TaskDetailView({ summary, detail, loading, busy, onCancel, onRefresh, onCreate, evidenceDetails, evidenceLoading, onLoadEvidence }: Props) {
  const [tab, setTab] = useState<Tab>("overview")
  useEffect(() => setTab("overview"), [summary?.id])

  if (!summary) return <WelcomePanel onCreate={onCreate} />

  const task = detail?.task || summary
  const active = !isTerminalStatus(task.status) && task.status !== "draft"

  return (
    <section className="surface-card-strong flex min-h-[600px] min-w-0 flex-col overflow-hidden rounded-[28px] lg:h-[calc(100vh-6.5rem)]">
      <div className="shrink-0 border-b border-slate-200/80 px-5 py-4 dark:border-slate-800 md:px-6">
        <div className="flex flex-col justify-between gap-4 sm:flex-row sm:items-start">
          <div className="min-w-0">
            <div className="mb-2 flex flex-wrap items-center gap-2">
              <StatusPill status={task.status} />
              {task.runId && <span className="rounded-full bg-slate-100 px-2.5 py-1 font-mono text-[0.68rem] text-slate-500 dark:bg-slate-800 dark:text-slate-400">{task.runId}</span>}
            </div>
            <h1 className="truncate text-xl font-bold text-slate-950 dark:text-white md:text-2xl">{task.title}</h1>
            <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500 dark:text-slate-400">
              {task.target && <span className="inline-flex items-center gap-1.5"><Target className="h-3.5 w-3.5" />{task.target}{task.ports.length > 0 ? ` · ${task.ports.join(", ")}` : ""}</span>}
              <span className="inline-flex items-center gap-1.5"><Clock3 className="h-3.5 w-3.5" />{formatDate(task.updatedAt || task.createdAt)}</span>
            </div>
          </div>
          <div className="flex shrink-0 items-center gap-2">
            <button onClick={onRefresh} disabled={loading} className="inline-flex items-center gap-2 rounded-2xl border border-slate-200 bg-white px-3.5 py-2.5 text-xs font-medium text-slate-600 transition hover:border-cyan-300 hover:text-cyan-700 disabled:opacity-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:border-cyan-700 dark:hover:text-cyan-300">
              <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} />刷新
            </button>
            {active && (
              <button onClick={() => onCancel(task.id)} disabled={busy} className="inline-flex items-center gap-2 rounded-2xl border border-red-200 bg-red-50 px-3.5 py-2.5 text-xs font-medium text-red-700 transition hover:bg-red-100 disabled:opacity-50 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300 dark:hover:bg-red-950/50">
                <Ban className="h-4 w-4" />取消 Run
              </button>
            )}
          </div>
        </div>

        <nav className="mt-5 flex gap-1 overflow-x-auto rounded-2xl bg-slate-100 p-1 dark:bg-slate-900">
          {TABS.map(item => {
            const count = item.id === "evidence" ? detail?.evidence.length : item.id === "findings" ? detail?.findings.length : undefined
            return (
              <button key={item.id} onClick={() => setTab(item.id)} className={`inline-flex min-w-max flex-1 items-center justify-center gap-2 rounded-xl px-3 py-2 text-xs font-medium transition ${tab === item.id ? "bg-white text-cyan-700 shadow-sm dark:bg-slate-800 dark:text-cyan-300" : "text-slate-500 hover:text-slate-800 dark:text-slate-400 dark:hover:text-slate-200"}`}>
                {item.icon}{item.label}{count !== undefined && <span className="rounded-full bg-slate-100 px-1.5 text-[0.62rem] dark:bg-slate-700">{count}</span>}
              </button>
            )
          })}
        </nav>
      </div>

      <div className="flex-1 overflow-y-auto px-5 py-5 md:px-6">
        {loading && !detail ? <LoadingDetail /> : !detail ? <MissingDetail /> : (
          <>
            {tab === "overview" && <Overview detail={detail} />}
            {tab === "plan" && <PlanView detail={detail} />}
            {tab === "evidence" && <EvidenceView taskId={detail.task.id} evidence={detail.evidence} details={evidenceDetails} loading={evidenceLoading} onLoad={onLoadEvidence} />}
            {tab === "findings" && <FindingsView detail={detail} />}
            {tab === "report" && <ReportView detail={detail} />}
          </>
        )}
      </div>
    </section>
  )
}

function WelcomePanel({ onCreate }: { onCreate: () => void }) {
  return (
    <section className="surface-card-strong flex min-h-[600px] items-center justify-center rounded-[28px] px-6 py-12 lg:h-[calc(100vh-6.5rem)]">
      <div className="max-w-xl text-center">
        <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-[24px] bg-cyan-100 text-cyan-700 dark:bg-cyan-950/50 dark:text-cyan-300"><ShieldCheck className="h-8 w-8" /></div>
        <span className="section-eyebrow">Workspace ready</span>
        <h1 className="dashboard-hero-title mt-3 text-3xl font-bold text-slate-950 dark:text-white">从明确授权的本机任务开始</h1>
        <p className="mx-auto mt-4 max-w-lg text-sm leading-7 text-slate-600 dark:text-slate-400">SEC-GO 会生成 TaskSpec 和计划，调用受控工具保存原始证据，再由独立 Verifier 判断能否完成。</p>
        <button onClick={onCreate} className="mt-7 rounded-2xl bg-cyan-600 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-cyan-600/15 transition hover:bg-cyan-700">创建 localhost 检查任务</button>
      </div>
    </section>
  )
}

function LoadingDetail() {
  return <div className="flex min-h-80 items-center justify-center gap-2 text-sm text-slate-500"><Loader2 className="h-5 w-5 animate-spin text-cyan-500" />正在加载结构化任务详情...</div>
}

function MissingDetail() {
  return <div className="rounded-3xl border border-dashed border-slate-300 bg-slate-50/60 p-8 text-center text-sm text-slate-500 dark:border-slate-700 dark:bg-slate-950/30">暂时无法读取任务详情，请稍后刷新。</div>
}

function Overview({ detail }: { detail: TaskDetail }) {
  const stats = detail.stats
  return (
    <div className="space-y-5">
      <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <Metric icon={<GitBranch className="h-4 w-4" />} label="执行步骤" value={stats.stepCount} color="text-violet-600 dark:text-violet-300" />
        <Metric icon={<Database className="h-4 w-4" />} label="真实证据" value={stats.evidenceCount} color="text-blue-600 dark:text-blue-300" />
        <Metric icon={<Flag className="h-4 w-4" />} label="安全发现" value={stats.findingCount} color="text-amber-600 dark:text-amber-300" />
        <Metric icon={<Clock3 className="h-4 w-4" />} label="运行耗时" value={formatDuration(stats.elapsedMs)} color="text-cyan-600 dark:text-cyan-300" />
      </div>

      <div className="grid gap-5 2xl:grid-cols-[1.2fr_0.8fr]">
        <div className="rounded-3xl border border-slate-200 bg-white/70 p-5 dark:border-slate-800 dark:bg-slate-900/50">
          <div className="mb-4 flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-slate-100"><Target className="h-4 w-4 text-cyan-600 dark:text-cyan-300" />TaskSpec</div>
          {detail.taskSpec ? (
            <div className="space-y-4 text-sm">
              <Field label="目标" value={detail.taskSpec.objective} />
              <div className="grid gap-4 sm:grid-cols-2">
                <Field label="任务类型" value={detail.taskSpec.taskType} mono />
                <Field label="网络范围" value={detail.taskSpec.networkTargets.join(", ") || "—"} mono />
              </div>
              <ListField label="成功标准" values={detail.taskSpec.successCriteria} />
              <ListField label="约束" values={detail.taskSpec.constraints} />
            </div>
          ) : (
            <p className="text-sm text-slate-500 dark:text-slate-400">Task Interpreter 正在生成结构化任务说明。</p>
          )}
        </div>
        <VerificationCard verification={detail.verification} status={detail.task.status} />
      </div>

      {detail.task.description && (
        <div className="rounded-3xl border border-slate-200 bg-white/70 p-5 dark:border-slate-800 dark:bg-slate-900/50">
          <div className="mb-2 text-sm font-semibold text-slate-900 dark:text-slate-100">任务描述</div>
          <p className="whitespace-pre-wrap text-sm leading-7 text-slate-600 dark:text-slate-300">{detail.task.description}</p>
        </div>
      )}
    </div>
  )
}

function Metric({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: string | number; color: string }) {
  return (
    <div className="rounded-3xl border border-slate-200 bg-white/75 p-4 dark:border-slate-800 dark:bg-slate-900/55">
      <div className={`mb-3 ${color}`}>{icon}</div>
      <div className="text-xl font-bold text-slate-950 dark:text-white">{value}</div>
      <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">{label}</div>
    </div>
  )
}

function Field({ label, value, mono = false }: { label: string; value: string; mono?: boolean }) {
  return <div><div className="mb-1 text-xs text-slate-400">{label}</div><div className={`break-words text-sm text-slate-700 dark:text-slate-200 ${mono ? "font-mono" : ""}`}>{value || "—"}</div></div>
}

function ListField({ label, values }: { label: string; values: string[] }) {
  return <div><div className="mb-1.5 text-xs text-slate-400">{label}</div>{values.length > 0 ? <ul className="space-y-1 text-sm text-slate-700 dark:text-slate-200">{values.map((value, index) => <li key={`${value}-${index}`} className="flex gap-2"><span className="text-cyan-500">•</span><span>{value}</span></li>)}</ul> : <div className="text-sm text-slate-400">—</div>}</div>
}

function VerificationCard({ verification, status }: { verification: VerificationRecord | null; status: string }) {
  const waiting = !verification
  const passed = verification?.success === true
  return (
    <div className={`rounded-3xl border p-5 ${waiting ? "border-slate-200 bg-white/70 dark:border-slate-800 dark:bg-slate-900/50" : passed ? "border-emerald-200 bg-emerald-50/70 dark:border-emerald-900/60 dark:bg-emerald-950/25" : "border-red-200 bg-red-50/70 dark:border-red-900/60 dark:bg-red-950/25"}`}>
      <div className="mb-4 flex items-center justify-between gap-3">
        <div className="flex items-center gap-2 text-sm font-semibold text-slate-900 dark:text-slate-100">
          {waiting ? <ShieldAlert className="h-4 w-4 text-slate-400" /> : passed ? <CheckCircle2 className="h-4 w-4 text-emerald-600" /> : <XCircle className="h-4 w-4 text-red-600" />}
          独立验证
        </div>
        <span className="text-xs text-slate-500">{waiting ? (status === "verifying" ? "验证中" : "等待验证") : passed ? "通过" : "未通过"}</span>
      </div>
      {verification ? (
        <div className="space-y-3 text-sm text-slate-600 dark:text-slate-300">
          <p className="leading-6">{verification.reason || "未提供验证说明"}</p>
          <ListField label="缺失要求" values={verification.missingRequirements} />
          <ListField label="冲突" values={verification.conflicts} />
          <div className="text-xs text-slate-400">引用证据：{verification.evidenceIds.length}</div>
        </div>
      ) : <p className="text-sm leading-6 text-slate-500 dark:text-slate-400">只有真实 Evidence、关键节点与成功标准通过检查后，Run 才能进入 completed。</p>}
    </div>
  )
}

function PlanView({ detail }: { detail: TaskDetail }) {
  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div><div className="text-sm font-semibold text-slate-900 dark:text-slate-100">Plan DAG</div><div className="mt-1 text-xs text-slate-500 dark:text-slate-400">完全根据 PlanNode.dependencies 构图，不解析工具输出文本。</div></div>
        {detail.plan && <div className="flex items-center gap-2"><span className="font-mono text-xs text-slate-400">v{detail.plan.version}</span><StatusPill status={detail.plan.status} compact /></div>}
      </div>
      <PlanGraph plan={detail.plan} />
      {detail.plan && detail.plan.nodes.length > 0 && (
        <div className="space-y-3">
          {detail.plan.nodes.map(node => (
            <article key={node.id} className="rounded-3xl border border-slate-200 bg-white/70 p-4 dark:border-slate-800 dark:bg-slate-900/50">
              <div className="flex items-start justify-between gap-3"><div><div className="text-sm font-semibold text-slate-900 dark:text-slate-100">{node.goal}</div>{node.description && <p className="mt-1 text-xs leading-5 text-slate-500 dark:text-slate-400">{node.description}</p>}</div><StatusPill status={node.status} compact /></div>
              <div className="mt-3 flex flex-wrap gap-2 text-[0.68rem] text-slate-500 dark:text-slate-400">
                <span>依赖 {node.dependencies.length}</span><span>证据 {node.evidenceIds.length}</span><span>发现 {node.findingIds.length}</span>
                {node.requiredCapabilities.map(capability => <span key={capability} className="rounded-full bg-slate-100 px-2 py-0.5 font-mono dark:bg-slate-800">{capability}</span>)}
              </div>
            </article>
          ))}
        </div>
      )}
    </div>
  )
}

function EvidenceView({ taskId, evidence, details, loading, onLoad }: { taskId: string; evidence: EvidenceRecord[]; details: Record<string, EvidenceRecord>; loading: Record<string, boolean>; onLoad: (taskId: string, evidenceId: string) => void }) {
  if (evidence.length === 0) return <EmptyCollection icon={<Database className="h-8 w-8" />} title="尚无证据" description="工具产生真实结果后，Evidence Store 会保存摘要、来源与内容哈希。" />
  return (
    <div className="space-y-3">
      {evidence.map(summary => {
        const item = details[summary.id] || summary
        return <details key={item.id} onToggle={event => event.currentTarget.open && !details[item.id] && onLoad(taskId, item.id)} className="group rounded-3xl border border-slate-200 bg-white/70 dark:border-slate-800 dark:bg-slate-900/50">
          <summary className="cursor-pointer list-none p-4 sm:p-5">
            <div className="flex items-start gap-3">
              <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-2xl bg-blue-100 text-blue-700 dark:bg-blue-950/60 dark:text-blue-300"><Database className="h-5 w-5" /></div>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-xs font-semibold text-blue-700 dark:text-blue-300">{item.type}</span><span className="text-xs text-slate-400">{item.source}</span></div>
                <p className="mt-2 break-words text-sm leading-6 text-slate-700 dark:text-slate-200">{item.summary}</p>
                <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[0.65rem] text-slate-400"><span>{item.id}</span>{item.contentHash && <span>sha256:{item.contentHash.slice(0, 16)}…</span>}<span>{formatDate(item.createdAt)}</span></div>
              </div>
            </div>
          </summary>
          <div className="border-t border-slate-200/80 px-4 py-4 dark:border-slate-800 sm:px-5">
            {loading[item.id] ? <div className="flex items-center gap-2 text-xs text-slate-500"><Loader2 className="h-4 w-4 animate-spin text-cyan-500" />正在按需读取原始 Evidence...</div> : item.rawContent ? <pre className="output-pre">{item.rawContent}</pre> : <p className="text-xs text-slate-500">原始 Evidence 暂不可用。</p>}
            {item.integrityValid !== undefined && <div className={`mt-3 inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs ${item.integrityValid ? "bg-emerald-100 text-emerald-700 dark:bg-emerald-950/50 dark:text-emerald-300" : "bg-red-100 text-red-700 dark:bg-red-950/50 dark:text-red-300"}`}>{item.integrityValid ? <CheckCircle2 className="h-3.5 w-3.5" /> : <XCircle className="h-3.5 w-3.5" />}哈希完整性{item.integrityValid ? "有效" : "异常"}</div>}
            {Object.keys(item.metadata).length > 0 && <pre className="output-pre mt-3">{JSON.stringify(redactForDisplay(item.metadata), null, 2)}</pre>}
          </div>
        </details>
      })}
    </div>
  )
}

function FindingsView({ detail }: { detail: TaskDetail }) {
  if (detail.findings.length === 0) return <EmptyCollection icon={<Flag className="h-8 w-8" />} title="尚无安全发现" description="Finding 必须引用 Evidence；没有证据的推测不会被显示为已验证发现。" />
  return (
    <div className="space-y-3">
      {detail.findings.map(finding => (
        <article key={finding.id} className="rounded-3xl border border-slate-200 bg-white/70 p-5 dark:border-slate-800 dark:bg-slate-900/50">
          <div className="flex flex-col justify-between gap-3 sm:flex-row sm:items-start">
            <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><SeverityPill severity={finding.severity} /><StatusPill status={finding.status} compact />{finding.subject && <span className="font-mono text-xs text-slate-400">{finding.subject}</span>}</div><h3 className="mt-3 text-base font-semibold text-slate-950 dark:text-white">{finding.title}</h3></div>
            <div className="shrink-0 text-xs text-slate-500">置信度 {(finding.confidence * 100).toFixed(0)}%</div>
          </div>
          <p className="mt-3 whitespace-pre-wrap text-sm leading-7 text-slate-600 dark:text-slate-300">{finding.description}</p>
          <div className="mt-4 flex flex-wrap gap-2">
            {finding.evidenceIds.length > 0 ? finding.evidenceIds.map(id => <span key={id} className="rounded-full bg-blue-50 px-2.5 py-1 font-mono text-[0.65rem] text-blue-700 dark:bg-blue-950/40 dark:text-blue-300">Evidence · {id}</span>) : <span className="inline-flex items-center gap-1 text-xs text-red-600 dark:text-red-300"><AlertTriangle className="h-3.5 w-3.5" />未引用证据</span>}
          </div>
        </article>
      ))}
    </div>
  )
}

function ReportView({ detail }: { detail: TaskDetail }) {
  if (!detail.report) return <EmptyCollection icon={<FileSearch className="h-8 w-8" />} title="报告尚未生成" description="Run 完成并经过 Verifier 后，结构化结论会在这里呈现。" />
  return (
    <article className="rounded-3xl border border-slate-200 bg-white/75 p-5 dark:border-slate-800 dark:bg-slate-900/55 md:p-7">
      <div className="mb-5 flex items-center gap-2 border-b border-slate-200 pb-4 text-base font-semibold text-slate-950 dark:border-slate-800 dark:text-white"><ShieldCheck className="h-5 w-5 text-cyan-600 dark:text-cyan-300" />安全任务报告</div>
      <SafeMarkdown content={detail.report} />
    </article>
  )
}

function EmptyCollection({ icon, title, description }: { icon: React.ReactNode; title: string; description: string }) {
  return <div className="flex min-h-80 flex-col items-center justify-center rounded-3xl border border-dashed border-slate-300 bg-slate-50/60 px-6 text-center dark:border-slate-700 dark:bg-slate-950/30"><div className="mb-3 text-slate-400">{icon}</div><div className="text-sm font-medium text-slate-700 dark:text-slate-300">{title}</div><p className="mt-1 max-w-md text-xs leading-5 text-slate-500 dark:text-slate-400">{description}</p></div>
}

function formatDuration(elapsedMs?: number): string {
  if (elapsedMs == null) return "—"
  if (elapsedMs < 1_000) return `${elapsedMs}ms`
  return `${(elapsedMs / 1_000).toFixed(elapsedMs < 10_000 ? 1 : 0)}s`
}

function redactForDisplay(value: JsonValue): JsonValue {
  if (Array.isArray(value)) return value.map(redactForDisplay)
  if (value && typeof value === "object") {
    const result: JsonObject = {}
    for (const [key, item] of Object.entries(value)) {
      result[key] = /token|secret|password|api[_-]?key|authorization|cookie/i.test(key) ? "[REDACTED]" : redactForDisplay(item)
    }
    return result
  }
  return value
}
