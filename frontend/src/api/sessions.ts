import type { ConversationEntry, SessionInfo } from "../types/events"
import { requestJson } from "./client"

export function listSessions() {
  return requestJson<SessionInfo[]>("/api/sessions")
}

export function getSessionConversations(sessionId: string) {
  return requestJson<ConversationEntry[]>(`/api/sessions/${sessionId}/conversations`)
}
