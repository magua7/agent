import type {
  EvidenceRecord,
  FindingRecord,
  JsonObject,
  JsonValue,
  PlanNodeRecord,
  PlanRecord,
  RunRecord,
  SecGoUser,
  TaskDetail,
  TaskSpecRecord,
  TaskStats,
  TaskSummary,
  VerificationRecord,
} from "./types"

export function asObject(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {}
}

export function unwrapApiData(value: unknown): unknown {
  const record = asObject(value)
  if (record.success === true && "data" in record) return record.data
  return value
}

function text(value: unknown, fallback = ""): string {
  return typeof value === "string" ? value : fallback
}

function number(value: unknown, fallback = 0): number {
  return typeof value === "number" && Number.isFinite(value) ? value : fallback
}

function strings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : []
}

function ports(value: unknown): number[] {
  if (Array.isArray(value)) {
    return value
      .filter((item): item is number => Number.isInteger(item) && item >= 1 && item <= 65_535)
      .sort((a, b) => a - b)
  }
  if (typeof value === "string") {
    try {
      return parsePorts(value)
    } catch {
      return []
    }
  }
  return []
}

function jsonObject(value: unknown): JsonObject {
  const source = asObject(value)
  const result: JsonObject = {}
  for (const [key, item] of Object.entries(source)) {
    if (isJsonValue(item)) result[key] = item
  }
  return result
}

function isJsonValue(value: unknown): value is JsonValue {
  if (value === null || typeof value === "string" || typeof value === "number" || typeof value === "boolean") return true
  if (Array.isArray(value)) return value.every(isJsonValue)
  if (typeof value !== "object") return false
  return Object.values(value as Record<string, unknown>).every(isJsonValue)
}

export function normalizeUser(value: unknown): SecGoUser {
  const user = asObject(value)
  const username = text(user.username, text(user.name, "user"))
  return {
    id: text(user.id, text(user.user_id, username)),
    username,
    displayName: text(user.display_name, text(user.displayName)) || undefined,
  }
}

export function normalizeTaskSummary(value: unknown): TaskSummary {
  const root = asObject(unwrapApiData(value))
  const task = Object.keys(asObject(root.task)).length > 0 ? asObject(root.task) : root
  const run = asObject(root.run)
  const taskSpec = asObject(task.task_spec)
  const inputs = Object.keys(asObject(taskSpec.inputs)).length > 0 ? asObject(taskSpec.inputs) : asObject(task.inputs)
  const scope = asObject(taskSpec.scope)
  const id = text(task.id, text(task.task_id, text(root.task_id)))
  const description = text(task.description, text(task.objective, text(task.query)))
  const title = text(task.title, description.slice(0, 72) || (id ? `任务 ${id.slice(-8)}` : "未命名任务"))
  const scopeTargets = strings(scope.network_targets)
  const target = text(task.target, text(inputs.target, scopeTargets[0] || "")) || undefined
  const taskPorts = ports(task.ports).length > 0 ? ports(task.ports) : ports(inputs.ports)
  return {
    id,
    title,
    description,
    target,
    ports: taskPorts,
    status: text(run.status, text(task.status, text(root.status, "created"))).toLowerCase(),
    runId: text(run.id, text(run.run_id, text(task.run_id, text(root.run_id)))) || undefined,
    createdAt: text(task.created_at, text(root.created_at)) || undefined,
    updatedAt: text(run.updated_at, text(task.updated_at, text(root.updated_at))) || undefined,
  }
}

export function normalizeTaskList(value: unknown): TaskSummary[] {
  const payload = unwrapApiData(value)
  const root = asObject(payload)
  const rows = Array.isArray(payload)
    ? payload
    : Array.isArray(root.tasks)
      ? root.tasks
      : Array.isArray(root.items)
        ? root.items
        : []
  return rows.map(normalizeTaskSummary).filter(task => Boolean(task.id))
}

function normalizeRun(value: unknown, fallbackStatus: string): RunRecord | null {
  const run = asObject(value)
  if (Object.keys(run).length === 0) return null
  return {
    id: text(run.id, text(run.run_id)),
    status: text(run.status, fallbackStatus).toLowerCase(),
    startedAt: text(run.started_at) || undefined,
    updatedAt: text(run.updated_at) || undefined,
    finishedAt: text(run.finished_at) || undefined,
    stepCount: number(run.step_count),
    replanCount: number(run.replan_count),
    lastError: text(run.last_error, text(run.error)) || undefined,
  }
}

function normalizeTaskSpec(value: unknown): TaskSpecRecord | null {
  const spec = asObject(value)
  if (Object.keys(spec).length === 0) return null
  const scope = asObject(spec.scope)
  return {
    objective: text(spec.objective),
    taskType: text(spec.task_type, "generic"),
    networkTargets: strings(scope.network_targets),
    fileRoots: strings(scope.file_roots),
    constraints: strings(spec.constraints),
    inputs: jsonObject(spec.inputs),
    successCriteria: strings(spec.success_criteria),
  }
}

function normalizeNode(value: unknown): PlanNodeRecord {
  const node = asObject(value)
  return {
    id: text(node.id, text(node.node_id)),
    goal: text(node.goal, text(node.title, "未命名计划节点")),
    description: text(node.description),
    status: text(node.status, "pending").toLowerCase(),
    assignedAgent: text(node.assigned_agent, text(node.assignedAgent)) || undefined,
    requiredCapabilities: strings(node.required_capabilities).length > 0
      ? strings(node.required_capabilities)
      : strings(node.requiredCapabilities),
    dependencies: strings(node.dependencies).length > 0 ? strings(node.dependencies) : strings(node.depends_on),
    successCriteria: strings(node.success_criteria).length > 0
      ? strings(node.success_criteria)
      : strings(node.successCriteria),
    attemptCount: number(node.attempt_count),
    maxAttempts: number(node.max_attempts, 1),
    evidenceIds: strings(node.evidence_ids),
    findingIds: strings(node.finding_ids),
  }
}

function normalizePlan(value: unknown): PlanRecord | null {
  const plan = asObject(value)
  if (Object.keys(plan).length === 0) return null
  const nodes = Array.isArray(plan.nodes) ? plan.nodes.map(normalizeNode).filter(node => Boolean(node.id)) : []
  return {
    id: text(plan.id, text(plan.plan_id)),
    version: number(plan.version, 1),
    status: text(plan.status, "draft").toLowerCase(),
    nodes,
    createdAt: text(plan.created_at) || undefined,
    updatedAt: text(plan.updated_at) || undefined,
  }
}

export function normalizeEvidenceRecord(value: unknown): EvidenceRecord {
  const evidence = asObject(value)
  return {
    id: text(evidence.id, text(evidence.evidence_id)),
    type: text(evidence.type, "other"),
    source: text(evidence.source, "unknown"),
    summary: text(evidence.summary, text(evidence.preview, "无摘要")),
    rawContent: text(evidence.raw_content, text(evidence.content)) || undefined,
    contentHash: text(evidence.content_hash) || undefined,
    actionId: text(evidence.action_id) || undefined,
    createdAt: text(evidence.created_at) || undefined,
    metadata: jsonObject(evidence.metadata),
    integrityValid: typeof evidence.integrity_valid === "boolean" ? evidence.integrity_valid : undefined,
  }
}

function normalizeFinding(value: unknown): FindingRecord {
  const finding = asObject(value)
  return {
    id: text(finding.id, text(finding.finding_id)),
    title: text(finding.title, "未命名发现"),
    description: text(finding.description),
    severity: text(finding.severity, "informational").toLowerCase(),
    confidence: number(finding.confidence),
    status: text(finding.status, "draft").toLowerCase(),
    subject: text(finding.subject) || undefined,
    evidenceIds: strings(finding.evidence_ids),
    createdAt: text(finding.created_at) || undefined,
  }
}

function normalizeReport(value: unknown): string | null {
  if (typeof value === "string") return value || null
  const report = asObject(value)
  return text(report.markdown, text(report.content, text(report.report))) || null
}

function normalizeStats(value: unknown, run: RunRecord | null, evidenceCount: number, findingCount: number): TaskStats {
  const stats = asObject(value)
  return {
    stepCount: number(stats.step_count, number(stats.stepCount, run?.stepCount ?? 0)),
    replanCount: number(stats.replan_count, number(stats.replanCount, run?.replanCount ?? 0)),
    evidenceCount: number(stats.evidence_count, number(stats.evidenceCount, evidenceCount)),
    findingCount: number(stats.finding_count, number(stats.findingCount, findingCount)),
    elapsedMs: number(stats.elapsed_ms, number(stats.elapsedMs, number(stats.elapsed_sec) * 1_000)) || undefined,
  }
}

function normalizeVerification(value: unknown): VerificationRecord | null {
  const verification = asObject(value)
  if (Object.keys(verification).length === 0) return null
  return {
    success: verification.success === true,
    reason: text(verification.reason),
    evidenceIds: strings(verification.evidence_ids),
    missingRequirements: strings(verification.missing_requirements),
    conflicts: strings(verification.conflicts),
  }
}

export function normalizeTaskDetail(value: unknown): TaskDetail {
  const root = asObject(unwrapApiData(value))
  const task = normalizeTaskSummary(root)
  const runSource = Object.keys(asObject(root.run)).length > 0
    ? root.run
    : root.run_id
      ? { run_id: root.run_id, status: root.status, started_at: root.created_at, updated_at: root.updated_at }
      : null
  const run = normalizeRun(runSource, task.status)
  const plan = normalizePlan(root.plan)
  const evidence = (Array.isArray(root.evidence) ? root.evidence : []).map(normalizeEvidenceRecord).filter(item => Boolean(item.id))
  const findings = (Array.isArray(root.findings) ? root.findings : []).map(normalizeFinding).filter(item => Boolean(item.id))
  const effectiveTask = run ? { ...task, status: run.status, runId: run.id || task.runId } : task
  return {
    task: effectiveTask,
    taskSpec: normalizeTaskSpec(root.task_spec),
    run,
    plan,
    evidence,
    findings,
    verification: normalizeVerification(root.verification),
    report: normalizeReport(root.report),
    stats: normalizeStats(root.stats, run, evidence.length, findings.length),
  }
}

export function parsePorts(input: string): number[] {
  const parts = input.split(",").map(item => item.trim()).filter(Boolean)
  if (parts.length === 0) throw new Error("请至少填写一个端口")
  if (parts.length > 128) throw new Error("一次最多检查 128 个端口")
  const values = parts.map(item => {
    if (!/^\d+$/.test(item)) throw new Error(`端口格式无效：${item}`)
    const value = Number(item)
    if (!Number.isInteger(value) || value < 1 || value > 65_535) throw new Error(`端口超出范围：${item}`)
    return value
  })
  return [...new Set(values)].sort((a, b) => a - b)
}

export function isLoopbackTarget(input: string): boolean {
  const target = input.trim().toLowerCase().replace(/^\[|\]$/g, "")
  if (target === "localhost" || target === "::1") return true
  const octets = target.split(".")
  if (octets.length !== 4 || !octets.every(item => /^\d{1,3}$/.test(item))) return false
  const values = octets.map(Number)
  return values[0] === 127 && values.every(value => value >= 0 && value <= 255)
}

export function isTerminalStatus(status: string): boolean {
  return ["completed", "failed", "cancelled", "canceled", "timed_out"].includes(status.toLowerCase())
}

export function statusFromEvent(type: string): string | null {
  const normalized = type.toLowerCase()
  if (["run_started", "task_started", "plan_created", "node_started", "tool_started"].includes(normalized)) return "running"
  if (normalized === "verification_started") return "verifying"
  if (["run_completed", "task_completed"].includes(normalized)) return "completed"
  if (["run_failed", "task_failed"].includes(normalized)) return "failed"
  if (["run_timed_out", "task_timed_out"].includes(normalized)) return "timed_out"
  if (["run_cancelled", "task_cancelled", "run_canceled", "task_canceled"].includes(normalized)) return "cancelled"
  return null
}

export function formatDate(value?: string): string {
  if (!value) return "—"
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString("zh-CN", { hour12: false })
}
