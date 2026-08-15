import { normalizeEvidenceRecord, normalizeTaskDetail, normalizeTaskList, normalizeTaskSummary, normalizeUser, unwrapApiData } from "./model"
import type { AuthResponse, EvidenceRecord, SecGoUser, TaskCreateInput, TaskDetail, TaskSummary } from "./types"

const configuredBase = (import.meta.env.VITE_API_BASE_URL || "").trim()
export const API_BASE_URL = configuredBase.replace(/\/$/, "")

export function apiUrl(path: string): string {
  return `${API_BASE_URL}${path}`
}

export class ApiError extends Error {
  readonly status: number
  readonly code?: string

  constructor(message: string, status: number, code?: string) {
    super(message)
    this.name = "ApiError"
    this.status = status
    this.code = code
  }
}

interface RequestOptions extends RequestInit {
  token?: string | null
  onUnauthorized?: () => void
}

async function readPayload(response: Response): Promise<unknown> {
  const text = await response.text()
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    return text
  }
}

function errorMessage(payload: unknown, fallback: string): string {
  if (typeof payload === "string" && payload.trim()) return payload
  if (payload && typeof payload === "object") {
    const record = payload as Record<string, unknown>
    for (const key of ["message", "detail", "error", "code"]) {
      if (typeof record[key] === "string" && record[key]) return record[key] as string
    }
  }
  return fallback
}

export async function apiRequest(path: string, options: RequestOptions = {}): Promise<unknown> {
  const headers = new Headers(options.headers)
  headers.set("Accept", "application/json")
  if (options.body && !headers.has("Content-Type")) headers.set("Content-Type", "application/json")
  if (options.token) headers.set("Authorization", `Bearer ${options.token}`)

  const response = await fetch(apiUrl(path), { ...options, headers })
  const payload = await readPayload(response)
  if (response.status === 401) options.onUnauthorized?.()
  if (!response.ok) {
    const record = payload && typeof payload === "object" ? payload as Record<string, unknown> : {}
    throw new ApiError(
      errorMessage(payload, `请求失败（HTTP ${response.status}）`),
      response.status,
      typeof record.code === "string" ? record.code : undefined,
    )
  }
  const record = payload && typeof payload === "object" ? payload as Record<string, unknown> : {}
  if (record.success === false) {
    throw new ApiError(errorMessage(payload, "请求失败"), response.status, typeof record.code === "string" ? record.code : undefined)
  }
  return payload
}

export async function login(username: string, password: string): Promise<AuthResponse> {
  const payload = unwrapApiData(await apiRequest("/api/auth/login", {
    method: "POST",
    body: JSON.stringify({ username, password }),
  }))
  const record = payload && typeof payload === "object" ? payload as Record<string, unknown> : {}
  const accessToken = typeof record.access_token === "string" ? record.access_token : ""
  if (!accessToken) throw new ApiError("登录响应缺少 access_token", 500)
  return {
    access_token: accessToken,
    token_type: typeof record.token_type === "string" ? record.token_type : "bearer",
    expires_in: typeof record.expires_in === "number" ? record.expires_in : 0,
    user: normalizeUser(record.user),
  }
}

export async function getCurrentUser(token: string, onUnauthorized: () => void): Promise<SecGoUser> {
  const payload = unwrapApiData(await apiRequest("/api/auth/me", { token, onUnauthorized }))
  return normalizeUser(payload)
}

export async function listTasks(token: string, onUnauthorized: () => void): Promise<TaskSummary[]> {
  return normalizeTaskList(await apiRequest("/api/tasks", { token, onUnauthorized }))
}

export async function createTask(token: string, input: TaskCreateInput, onUnauthorized: () => void): Promise<TaskSummary> {
  const payload = await apiRequest("/api/tasks", {
    method: "POST",
    token,
    onUnauthorized,
    body: JSON.stringify(input),
  })
  return normalizeTaskSummary(payload)
}

export async function getTask(token: string, taskId: string, onUnauthorized: () => void): Promise<TaskDetail> {
  return normalizeTaskDetail(await apiRequest(`/api/tasks/${encodeURIComponent(taskId)}`, { token, onUnauthorized }))
}

export async function cancelTask(token: string, taskId: string, onUnauthorized: () => void): Promise<void> {
  await apiRequest(`/api/tasks/${encodeURIComponent(taskId)}/cancel`, {
    method: "POST",
    token,
    onUnauthorized,
  })
}

export async function getEvidence(token: string, taskId: string, evidenceId: string, onUnauthorized: () => void): Promise<EvidenceRecord> {
  const payload = unwrapApiData(await apiRequest(
    `/api/tasks/${encodeURIComponent(taskId)}/evidence/${encodeURIComponent(evidenceId)}`,
    { token, onUnauthorized },
  ))
  return normalizeEvidenceRecord(payload)
}
