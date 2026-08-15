import { useCallback, useRef, useState } from "react"
import type { AgentEvent, CurrentTaskStatus, TaskDetail, TimelineEntry } from "../types/events"
import { reduceTaskEvent } from "../state/taskEventReducer"

export function useTaskCurrent() {
  const [taskId, setTaskId] = useState<string | null>(null)
  const [status, setStatus] = useState<CurrentTaskStatus>("idle")
  const [timeline, setTimelineState] = useState<TimelineEntry[]>([])
  const [storedReport, setStoredReport] = useState<string | null>(null)
  const [answerDraft, setAnswerDraft] = useState("")
  const [stats, setStats] = useState<TaskDetail["stats"]>(null)
  const [plan, setPlan] = useState<TaskDetail["plan"]>(null)
  const [error, setError] = useState<string | null>(null)
  const [currentQuery, setCurrentQuery] = useState<string>("")

  const timelineRef = useRef<TimelineEntry[]>([])
  const answerDraftRef = useRef("")
  const taskIdRef = useRef<string | null>(null)

  const setTimeline = useCallback((value: TimelineEntry[]) => {
    timelineRef.current = value
    setTimelineState(value)
  }, [])

  const setReport = useCallback((value: string | null) => {
    setStoredReport(value)
    answerDraftRef.current = ""
    setAnswerDraft("")
  }, [])

  const resetCurrentTask = useCallback(() => {
    setTaskId(null)
    taskIdRef.current = null
    setStatus("idle")
    setTimeline([])
    setReport(null)
    setStats(null)
    setPlan(null)
    setError(null)
    setCurrentQuery("")
  }, [setReport, setTimeline])

  const applyTimelineEvent = useCallback((event: AgentEvent) => {
    if (taskIdRef.current && event.task_id && event.task_id !== taskIdRef.current) {
      return
    }
    const next = reduceTaskEvent({
      timeline: timelineRef.current,
      answerDraft: answerDraftRef.current,
    }, event)
    timelineRef.current = next.timeline
    answerDraftRef.current = next.answerDraft
    setTimelineState(next.timeline)
    setAnswerDraft(next.answerDraft)
  }, [])

  return {
    taskId,
    setTaskId,
    taskIdRef,
    status,
    setStatus,
    timeline,
    setTimeline,
    timelineRef,
    report: storedReport ?? (answerDraft || null),
    setReport,
    answerDraft,
    stats,
    setStats,
    plan,
    setPlan,
    error,
    setError,
    currentQuery,
    setCurrentQuery,
    resetCurrentTask,
    applyTimelineEvent,
  }
}
