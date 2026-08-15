import type { TaskDetail } from "../types/events"
import { requestJson } from "./client"

export function createTask(params: { query: string; debug: boolean; session_id: string }) {
  return requestJson<{ task_id: string; status: string; created_at: string | null }>("/api/tasks", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(params),
  })
}

export function getTaskDetail(taskId: string) {
  return requestJson<TaskDetail>(`/api/tasks/${taskId}`)
}

export function renameTaskRequest(taskId: string, title: string) {
  return requestJson<{ task_id: string; title: string }>(`/api/tasks/${taskId}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ title }),
  })
}

export function deleteTaskRequest(taskId: string) {
  return requestJson<{ task_id: string; status: string }>(`/api/tasks/${taskId}`, {
    method: "DELETE",
  })
}

export function cancelTaskRequest(taskId: string) {
  return requestJson<{ task_id: string; status: string }>(`/api/tasks/${taskId}/cancel`, {
    method: "POST",
  })
}

export function submitTaskApproval(taskId: string, decision: string) {
  return requestJson<{ task_id: string; status: string; decision: string }>(`/api/tasks/${taskId}/approval`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ decision }),
  })
}
