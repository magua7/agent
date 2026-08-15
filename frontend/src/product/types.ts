export type JsonPrimitive = string | number | boolean | null
export type JsonValue = JsonPrimitive | JsonObject | JsonValue[]
export interface JsonObject {
  [key: string]: JsonValue
}

export interface SecGoUser {
  id: string
  username: string
  displayName?: string
}

export interface AuthResponse {
  access_token: string
  token_type: string
  expires_in: number
  user: SecGoUser
}

export interface TaskCreateInput {
  title: string
  description: string
  target: string
  ports: number[]
}

export interface TaskSummary {
  id: string
  title: string
  description: string
  target?: string
  ports: number[]
  status: string
  runId?: string
  createdAt?: string
  updatedAt?: string
}

export interface RunRecord {
  id: string
  status: string
  startedAt?: string
  updatedAt?: string
  finishedAt?: string
  stepCount: number
  replanCount: number
  lastError?: string
}

export interface PlanNodeRecord {
  id: string
  goal: string
  description: string
  status: string
  assignedAgent?: string
  requiredCapabilities: string[]
  dependencies: string[]
  successCriteria: string[]
  attemptCount: number
  maxAttempts: number
  evidenceIds: string[]
  findingIds: string[]
}

export interface PlanRecord {
  id: string
  version: number
  status: string
  nodes: PlanNodeRecord[]
  createdAt?: string
  updatedAt?: string
}

export interface EvidenceRecord {
  id: string
  type: string
  source: string
  summary: string
  rawContent?: string
  contentHash?: string
  actionId?: string
  createdAt?: string
  metadata: JsonObject
  integrityValid?: boolean
}

export interface FindingRecord {
  id: string
  title: string
  description: string
  severity: string
  confidence: number
  status: string
  subject?: string
  evidenceIds: string[]
  createdAt?: string
}

export interface TaskStats {
  stepCount: number
  replanCount: number
  evidenceCount: number
  findingCount: number
  elapsedMs?: number
}

export interface TaskSpecRecord {
  objective: string
  taskType: string
  networkTargets: string[]
  fileRoots: string[]
  constraints: string[]
  inputs: JsonObject
  successCriteria: string[]
}

export interface VerificationRecord {
  success: boolean
  reason: string
  evidenceIds: string[]
  missingRequirements: string[]
  conflicts: string[]
}

export interface TaskDetail {
  task: TaskSummary
  taskSpec: TaskSpecRecord | null
  run: RunRecord | null
  plan: PlanRecord | null
  evidence: EvidenceRecord[]
  findings: FindingRecord[]
  verification: VerificationRecord | null
  report: string | null
  stats: TaskStats
}

export interface TaskEvent {
  event_id: string
  sequence: number
  task_id: string
  run_id: string
  type: string
  timestamp: string
  payload: JsonObject
}

export type AuthPhase = "checking" | "anonymous" | "authenticated"
