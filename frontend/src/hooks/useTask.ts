import { useCallback, useMemo, useRef, useState } from "react"
import type { AgentEvent, TaskDetail, ConversationEntry } from "../types/events"
import { cancelTaskRequest, createTask as createTaskRequest, deleteTaskRequest, getTaskDetail, renameTaskRequest, submitTaskApproval } from "../api/tasks"
import { getSessionConversations } from "../api/sessions"
import { useTaskCurrent } from "./useTaskCurrent"
import { useTaskSession } from "./useTaskSession"

export function useTask(sessionId: string) {
  const current = useTaskCurrent()
  const session = useTaskSession(sessionId)
  const [selectedTaskDetail, setSelectedTaskDetail] = useState<TaskDetail | null>(null)
  const [selectedTaskLoading, setSelectedTaskLoading] = useState(false)
  const selectTaskRequestRef = useRef(0)
  // SSE 重连/重放可能导致同一事件被多次应用，按 event_id 去重，防止时间线重复
  const processedEventIdsRef = useRef<Set<string>>(new Set())

  const selectSession = useCallback(async (sid: string) => {
    session.setCurrentSessionId(sid)
    session.setSelectedTaskId(null)
    setSelectedTaskDetail(null)
    setSelectedTaskLoading(false)
    current.resetCurrentTask()
    session.setScrollToIndex(undefined)
    session.setScrollTargetTaskId(null)
    await session.refreshSessionMessages(sid)
  }, [current, session])

  const createNewSession = useCallback(() => {
    const newId = `session-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    localStorage.setItem("security_agent_session", newId)
    session.setCurrentSessionId(newId)
    session.setSelectedTaskId(null)
    setSelectedTaskDetail(null)
    setSelectedTaskLoading(false)
    current.resetCurrentTask()
    session.resetSessionView()
    session.refreshSessions()
  }, [current, session])

  const handleEvent = useCallback((event: AgentEvent) => {
    if (event.event_id) {
      if (processedEventIdsRef.current.has(event.event_id)) return
      processedEventIdsRef.current.add(event.event_id)
    }
    current.applyTimelineEvent(event)

    switch (event.type) {
      case "TASK_FINISHED": {
        const payload = event.payload
        const finalStats = payload.stats || null
        const finalReport = payload.report || null
        current.setStats(finalStats)
        current.setReport(finalReport)
        current.setStatus("completed")

        const sid = session.currentSessionIdRef.current
        if (sid) {
          session.refreshSessionMessages(sid)
        }
        session.refreshSessions()
        break
      }

      case "TASK_FAILED": {
        const payload = event.payload
        current.setError(payload.reason || "未知错误")
        current.setStatus("failed")
        const sid = session.currentSessionIdRef.current
        if (sid) {
          session.refreshSessionMessages(sid)
        }
        session.refreshSessions()
        break
      }

      case "TASK_CANCELLED": {
        current.setError(null)
        current.setStatus("cancelled")
        const sid = session.currentSessionIdRef.current
        if (sid) {
          session.refreshSessionMessages(sid)
        }
        session.refreshSessions()
        break
      }

      case "TASK_TIMED_OUT": {
        current.setError(event.payload.reason || "任务超过总执行期限")
        current.setStatus("timed_out")
        const sid = session.currentSessionIdRef.current
        if (sid) {
          session.refreshSessionMessages(sid)
        }
        session.refreshSessions()
        break
      }
    }

    if (event.type === "APPROVAL_REQUIRED") {
      current.setStatus("waiting_approval")
    }
  }, [current, session])

  const createTask = useCallback(async (query: string, debug: boolean = false): Promise<string | null> => {
    processedEventIdsRef.current = new Set()
    current.setError(null)
    current.setTimeline([])
    current.timelineRef.current = []
    current.setReport(null)
    current.setStats(null)
    current.setPlan(null)
    current.setCurrentQuery(query)
    setSelectedTaskDetail(null)
    setSelectedTaskLoading(false)
    session.setScrollToIndex(undefined)
    session.setScrollTargetTaskId(null)
    session.setSelectedTaskId(null)
    current.setStatus("running")

    const optimisticMessageId = session.appendOptimisticUserMessage(query)

    try {
      const data = await createTaskRequest({ query, debug, session_id: session.currentSessionId })
      const id = data.task_id
      current.setTaskId(id)
      current.taskIdRef.current = id
      session.attachTaskIdToMessage(optimisticMessageId, id)
      return id
    } catch (e: any) {
      session.removeMessage(optimisticMessageId)
      current.setError(e.message)
      current.setStatus("failed")
      return null
    }
  }, [current, session])

  const submitApproval = useCallback(async (decision: string) => {
    if (!current.taskId) return
    try {
      await submitTaskApproval(current.taskId, decision)
      current.setStatus("running")
    } catch (e: any) {
      current.setError(e.message)
    }
  }, [current])

  const cancelTask = useCallback(async () => {
    if (!current.taskId) return
    try {
      await cancelTaskRequest(current.taskId)
      current.setStatus("cancelled")
    } catch (e: any) {
      current.setError(e.message)
    }
  }, [current])

  const selectTask = useCallback(async (id: string, sessionId?: string) => {
    const sid = sessionId || session.currentSessionId
    if (!sid) return

    session.setSelectedTaskId(id)
    setSelectedTaskDetail(null)
    setSelectedTaskLoading(true)

    if (sid !== session.currentSessionId) {
      session.setCurrentSessionId(sid)
      current.resetCurrentTask()
    }

    const requestId = ++selectTaskRequestRef.current

    try {
      const [messages, detail] = await Promise.all([
        getSessionConversations(sid),
        getTaskDetail(id),
      ])

      if (requestId !== selectTaskRequestRef.current) return

      const sessionMessages: ConversationEntry[] = messages || []
      session.setSessionMessages(sessionMessages)
      const targetIdx = sessionMessages.findIndex(message => message.task_id === id)
      session.setScrollToIndex(targetIdx >= 0 ? targetIdx : undefined)
      session.setScrollTargetTaskId(id)
      setSelectedTaskDetail(detail as TaskDetail)
    } catch {
      if (requestId !== selectTaskRequestRef.current) return
      setSelectedTaskDetail(null)
    } finally {
      if (requestId === selectTaskRequestRef.current) {
        setSelectedTaskLoading(false)
      }
    }
  }, [current, session])

  const deleteTask = useCallback(async (tid: string) => {
    try {
      await deleteTaskRequest(tid)
      session.refreshSessions()
      if (session.selectedTaskId === tid) {
        session.setSelectedTaskId(null)
        session.setScrollTargetTaskId(null)
        setSelectedTaskDetail(null)
        setSelectedTaskLoading(false)
      }
      return true
    } catch {
      /* ignore */
    }
    return false
  }, [session])

  const renameTask = useCallback(async (tid: string, title: string) => {
    try {
      await renameTaskRequest(tid, title)
      session.refreshSessions()
      if (selectedTaskDetail?.task_id === tid) {
        setSelectedTaskDetail(prev => prev ? { ...prev, title } : prev)
      }
      return true
    } catch {
      /* ignore */
    }
    return false
  }, [selectedTaskDetail?.task_id, session])

  const syncFromBackend = useCallback(async (id?: string) => {
    const tid = id || current.taskId
    if (!tid) return

    try {
      const detail = await getTaskDetail(tid)
      if (detail.status !== "running" && detail.status !== "waiting_approval") {
        current.setStatus(detail.status)
        current.setReport(detail.report || null)
        current.setStats(detail.stats || null)
        current.setPlan(detail.plan || null)

        if (session.selectedTaskId === tid) {
          setSelectedTaskDetail(detail)
        }

        const sid = session.currentSessionIdRef.current
        if (sid) {
          session.refreshSessionMessages(sid)
        }
        session.refreshSessions()
      }
    } catch {
      /* ignore */
    }
  }, [current, session])

  const displayTask = useMemo(() => {
    if (session.selectedTaskId) {
      if (selectedTaskLoading || !selectedTaskDetail) return null
      return {
        taskId: selectedTaskDetail.task_id,
        status: selectedTaskDetail.status,
        query: selectedTaskDetail.query,
        title: selectedTaskDetail.title || null,
        report: selectedTaskDetail.report || null,
        stats: selectedTaskDetail.stats || null,
        plan: selectedTaskDetail.plan || null,
        timeline: selectedTaskDetail.timeline || [],
      }
    }

    return {
      taskId: current.taskId,
      status: current.status,
      query: current.currentQuery,
      title: null,
      report: current.report,
      stats: current.stats,
      plan: current.plan,
      timeline: current.timeline,
    }
  }, [current.currentQuery, current.plan, current.report, current.stats, current.status, current.taskId, current.timeline, selectedTaskDetail, selectedTaskLoading, session.selectedTaskId])

  const showWelcome = session.sessionMessages.length === 0 && !current.taskId && current.status === "idle" && !session.selectedTaskId
  const hasCurrentTaskContent = Boolean(current.currentQuery || current.timeline.length > 0 || current.report || current.error || current.taskId)
  const hasCurrentUserMessageInSession = Boolean(
    current.currentQuery && session.sessionMessages.some(message => message.role === "user" && message.content === current.currentQuery),
  )
  const hasArchivedCurrentTask = Boolean(
    current.taskId && session.sessionMessages.some(message => message.task_id === current.taskId && message.role === "assistant"),
  )
  const showCurrentTask = hasCurrentTaskContent && (
    current.status === "running"
    || current.status === "waiting_approval"
    || ((current.status === "completed" || current.status === "failed" || current.status === "cancelled" || current.status === "timed_out") && !hasArchivedCurrentTask)
  )
  const showCurrentUserQuery = !hasCurrentUserMessageInSession

  return {
    taskId: current.taskId,
    status: current.status,
    timeline: current.timeline,
    report: current.report,
    stats: current.stats,
    plan: current.plan,
    error: current.error,
    currentQuery: current.currentQuery,
    displayTask,
    selectedTaskLoading,
    showWelcome,
    showCurrentTask,
    showCurrentUserQuery,
    createTask,
    submitApproval,
    cancelTask,
    selectTask,
    deleteTask,
    renameTask,
    handleEvent,
    syncFromBackend,
    clearError: () => current.setError(null),
    sessions: session.sessions,
    currentSessionId: session.currentSessionId,
    selectedTaskId: session.selectedTaskId,
    sessionMessages: session.sessionMessages,
    sessionsError: session.sessionsError,
    sessionMessagesError: session.sessionMessagesError,
    scrollToIndex: session.scrollToIndex,
    scrollTargetTaskId: session.scrollTargetTaskId,
    clearScrollTargetTaskId: session.clearScrollTargetTaskId,
    loadSessions: session.refreshSessions,
    selectSession,
    createNewSession,
  }
}
