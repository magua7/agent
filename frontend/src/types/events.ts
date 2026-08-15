// ── 与后端 EventType 保持同步 ──
export type EventType =
  | "TASK_CREATED" | "TASK_STARTED" | "TASK_FINISHED" | "TASK_FAILED" | "TASK_CANCELLED" | "TASK_TIMED_OUT"
  | "STEP_STARTED" | "STEP_FINISHED"
  | "THINKING" | "RETROSPECTIVE"
  | "TOOL_STARTED" | "TOOL_FINISHED"
  | "APPROVAL_REQUIRED" | "APPROVAL_APPROVED" | "APPROVAL_DENIED"
  | "WARNING" | "ERROR" | "DEBUG" | "ANSWER_CHUNK"

export interface ToolProvenance {
  canonical_tool?: string | null
  tool_source: string
  tool_source_id: string
  snapshot_version: string
}

export interface ToolStartedPayload extends ToolProvenance {
  step_num: number
  tool: string
  args: Record<string, unknown>
  risk: "level0" | "level1" | "level2" | "level3"
  call_id: string
}

export interface ToolFinishedPayload extends ToolProvenance {
  step_num: number
  tool: string
  status: string
  runtime_status: "succeeded" | "no_data" | "failed" | "denied" | "cancelled" | "timed_out"
  error_code?: string | null
  elapsed: number
  output_preview: string
  call_id: string
  result_id: string
  evidence_id?: string | null
  termination_guaranteed?: boolean
  execution_may_continue?: boolean
  remote_termination_unknown?: boolean
  cleanup_error?: string | null
}

export interface AnswerChunkPayload {
  delta: string
  source?: string
}

interface EventBase {
  event_id: string
  task_id: string
  time: string
}

type EventPayload<T extends EventType> =
  T extends "TOOL_STARTED" ? ToolStartedPayload
  : T extends "TOOL_FINISHED" ? ToolFinishedPayload
  : T extends "ANSWER_CHUNK" ? AnswerChunkPayload
  : Record<string, any>

export type AgentEvent = {
  [T in EventType]: EventBase & {
    type: T
    payload: EventPayload<T>
  }
}[EventType]

// ── Task types ──
export type TaskStatus = "pending" | "running" | "waiting_approval" | "completed" | "failed" | "cancelled" | "timed_out"
export type CurrentTaskStatus = "idle" | TaskStatus

export interface TaskSummary {
  task_id: string
  status: TaskStatus
  query: string
  title?: string | null
  stats: { step_count: number; success_count: number; skipped_count: number; elapsed_sec: number } | null
  created_at: string
}

export interface TaskDetail {
  task_id: string
  status: TaskStatus
  query: string
  title?: string | null
  report: string | null
  plan: { goal: string; steps: PlanStep[] } | null
  stats: { step_count: number; success_count: number; skipped_count: number; elapsed_sec: number } | null
  timeline: TimelineEntry[] | null
  created_at: string
  completed_at: string | null
}

export interface PlanStep {
  step: number
  tool: string
  args: Record<string, any>
  reason: string
  risk: "level0" | "level1" | "level2" | "level3"
}

// ── Session types ──
export interface SessionInfo {
  session_id: string
  conversation_count: number
  question_count: number
  created_at: string
  last_active: string
  first_query: string
  tasks: TaskSummary[]
}

export interface ConversationEntry {
  id: number
  role: "user" | "assistant"
  content: string
  task_type?: string | null
  target?: string | null
  task_id?: string | null
  created_at: string
  optimistic?: boolean
}

export interface KnowledgeDetails {
  query?: string
  used_query?: string
  hits?: number
  fallback_used?: boolean
  top_titles?: string[]
  top_paths?: string[]
}

// ── Timeline entries (flat interface, narrow-by-kind) ──
export interface TimelineEntry {
  kind: "phase" | "tool" | "approval" | "warning" | "error" | "debug" | "thinking" | "retrospective"
  // phase
  phase?: string
  num?: number
  total?: number
  // thinking
  text?: string
  stage?: string
  iteration?: number
  // retrospective
  summary?: string
  // tool
  stepNum?: number
  tool?: string
  args?: Record<string, any>
  risk?: string
  // tool result
  status?: string
  elapsed?: number
  outputPreview?: string
  callId?: string
  resultId?: string
  evidenceId?: string
  canonicalTool?: string | null
  toolSource?: string
  toolSourceId?: string
  snapshotVersion?: string
  runtimeStatus?: string
  errorCode?: string | null
  terminationGuaranteed?: boolean
  executionMayContinue?: boolean
  remoteTerminationUnknown?: boolean
  cleanupError?: string | null
  // approval
  step?: PlanStep
  resolved?: boolean
  approved?: boolean
  decision?: string
  // system
  message?: string
  // debug with structured details (intent/plan/knowledge)
  debugType?: string
  details?: Record<string, any> | KnowledgeDetails
}
