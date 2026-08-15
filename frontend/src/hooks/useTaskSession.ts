import { useCallback, useRef, useState } from "react"
import type { ConversationEntry, SessionInfo } from "../types/events"
import { getSessionConversations, listSessions } from "../api/sessions"

function normalizeMessageTime(createdAt: string | undefined) {
  const value = createdAt ? Date.parse(createdAt) : NaN
  return Number.isNaN(value) ? 0 : value
}

function sameConversation(serverMessage: ConversationEntry, localMessage: ConversationEntry) {
  if (serverMessage.id === localMessage.id) return true
  if (serverMessage.role !== localMessage.role) return false

  if (serverMessage.task_id && localMessage.task_id) {
    return serverMessage.task_id === localMessage.task_id && serverMessage.content === localMessage.content
  }

  if (serverMessage.content !== localMessage.content) return false

  const delta = Math.abs(normalizeMessageTime(serverMessage.created_at) - normalizeMessageTime(localMessage.created_at))
  return delta <= 60_000
}

function mergeConversationMessages(serverMessages: ConversationEntry[], localMessages: ConversationEntry[]) {
  const merged = [...serverMessages]
  const optimisticMessages = localMessages.filter(message => message.optimistic)

  for (const localMessage of optimisticMessages) {
    const exists = serverMessages.some(serverMessage => sameConversation(serverMessage, localMessage))
    if (!exists) {
      merged.push(localMessage)
    }
  }

  return merged.sort((a, b) => normalizeMessageTime(a.created_at) - normalizeMessageTime(b.created_at))
}

export function useTaskSession(initialSessionId: string) {
  const [sessions, setSessions] = useState<SessionInfo[]>([])
  const [sessionsError, setSessionsError] = useState<string | null>(null)
  const [currentSessionId, setCurrentSessionId] = useState<string>(initialSessionId)
  const [sessionMessages, setSessionMessages] = useState<ConversationEntry[]>([])
  const [sessionMessagesError, setSessionMessagesError] = useState<string | null>(null)
  const [scrollToIndex, setScrollToIndex] = useState<number | undefined>(undefined)
  const [scrollTargetTaskId, setScrollTargetTaskId] = useState<string | null>(null)
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null)
  const currentSessionIdRef = useRef<string>(initialSessionId)

  const refreshSessions = useCallback(async () => {
    try {
      const data = await listSessions()
      setSessions(data || [])
      setSessionsError(null)
    } catch (error: any) {
      setSessionsError(error?.message || "历史记录加载失败")
    }
  }, [])

  const refreshSessionMessages = useCallback(async (sid: string) => {
    try {
      const serverMessages = await getSessionConversations(sid)
      setSessionMessages(prev => mergeConversationMessages(serverMessages || [], prev))
      setSessionMessagesError(null)
    } catch (error: any) {
      setSessionMessagesError(error?.message || "会话记录加载失败")
    }
  }, [])

  const appendOptimisticUserMessage = useCallback((query: string) => {
    const optimisticId = -Date.now()
    const optimisticMessage: ConversationEntry = {
      id: optimisticId,
      role: "user",
      content: query,
      task_id: null,
      created_at: new Date().toISOString(),
      optimistic: true,
    }

    setSessionMessages(prev => [...prev, optimisticMessage])
    setSessionMessagesError(null)
    return optimisticId
  }, [])

  const attachTaskIdToMessage = useCallback((messageId: number, taskId: string) => {
    setSessionMessages(prev => prev.map(message => (
      message.id === messageId
        ? { ...message, task_id: taskId }
        : message
    )))
  }, [])

  const removeMessage = useCallback((messageId: number) => {
    setSessionMessages(prev => prev.filter(message => message.id !== messageId))
  }, [])

  const setSession = useCallback((sid: string) => {
    setCurrentSessionId(sid)
    currentSessionIdRef.current = sid
    localStorage.setItem("security_agent_session", sid)
  }, [])

  const clearScrollTargetTaskId = useCallback(() => {
    setScrollTargetTaskId(null)
  }, [])

  const resetSessionView = useCallback(() => {
    setSessionMessages([])
    setSessionMessagesError(null)
    setScrollToIndex(undefined)
    setScrollTargetTaskId(null)
    setSelectedTaskId(null)
  }, [])

  return {
    sessions,
    setSessions,
    currentSessionId,
    setCurrentSessionId: setSession,
    currentSessionIdRef,
    sessionMessages,
    setSessionMessages,
    sessionsError,
    sessionMessagesError,
    scrollToIndex,
    setScrollToIndex,
    scrollTargetTaskId,
    setScrollTargetTaskId,
    clearScrollTargetTaskId,
    selectedTaskId,
    setSelectedTaskId,
    refreshSessions,
    refreshSessionMessages,
    appendOptimisticUserMessage,
    attachTaskIdToMessage,
    removeMessage,
    resetSessionView,
  }
}
