import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { ApiError, cancelTask as cancelTaskRequest, createTask as createTaskRequest, getCurrentUser, getEvidence, getTask, listTasks, login as loginRequest } from "./api"
import { isTerminalStatus, statusFromEvent } from "./model"
import { consumeTaskEvents } from "./sse"
import type { AuthPhase, EvidenceRecord, SecGoUser, TaskCreateInput, TaskDetail, TaskEvent, TaskSummary } from "./types"

const TOKEN_KEY = "secgo_access_token"
const MAX_EVENTS_PER_TASK = 1_000

type StreamState = "connecting" | "live" | "reconnecting" | "closed"

function initialToken(): string | null {
  try {
    return sessionStorage.getItem(TOKEN_KEY)
  } catch {
    return null
  }
}

function waitFor(delay: number, signal: AbortSignal): Promise<void> {
  return new Promise(resolve => {
    if (signal.aborted) {
      resolve()
      return
    }
    const timer = window.setTimeout(resolve, delay)
    signal.addEventListener("abort", () => {
      window.clearTimeout(timer)
      resolve()
    }, { once: true })
  })
}

function eventKey(event: TaskEvent): string {
  return event.event_id || (event.sequence ? String(event.sequence) : `${event.type}:${event.timestamp}`)
}

function mergeTaskLists(server: TaskSummary[], current: TaskSummary[]): TaskSummary[] {
  const currentById = new Map(current.map(task => [task.id, task]))
  const merged = server.map(task => {
    const previous = currentById.get(task.id)
    if (!previous) return task
    if (!isTerminalStatus(previous.status) && isTerminalStatus(task.status)) return task
    return {
      ...previous,
      ...task,
      target: task.target || previous.target,
      ports: task.ports.length > 0 ? task.ports : previous.ports,
      runId: task.runId || previous.runId,
    }
  })
  const serverIds = new Set(server.map(task => task.id))
  return [...merged, ...current.filter(task => !serverIds.has(task.id))]
}

export function useSecGoController() {
  const [token, setToken] = useState<string | null>(initialToken)
  const [authPhase, setAuthPhase] = useState<AuthPhase>(() => token ? "checking" : "anonymous")
  const [user, setUser] = useState<SecGoUser | null>(null)
  const [authError, setAuthError] = useState<string | null>(null)
  const [authBusy, setAuthBusy] = useState(false)

  const [tasks, setTasks] = useState<TaskSummary[]>([])
  const [tasksLoading, setTasksLoading] = useState(false)
  const [selectedTaskId, setSelectedTaskId] = useState<string | null>(null)
  const [detailsByTask, setDetailsByTask] = useState<Record<string, TaskDetail>>({})
  const [detailLoading, setDetailLoading] = useState<Record<string, boolean>>({})
  const [eventsByTask, setEventsByTask] = useState<Record<string, TaskEvent[]>>({})
  const [evidenceDetails, setEvidenceDetails] = useState<Record<string, EvidenceRecord>>({})
  const [evidenceLoading, setEvidenceLoading] = useState<Record<string, boolean>>({})
  const [streamStateByTask, setStreamStateByTask] = useState<Record<string, StreamState>>({})
  const [operationBusy, setOperationBusy] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const streamControllers = useRef(new Map<string, AbortController>())
  const streamCursors = useRef(new Map<string, string>())
  const processedEvents = useRef(new Map<string, Set<string>>())
  const hydratedEventTasks = useRef(new Set<string>())
  const detailRefreshTimers = useRef(new Map<string, number>())
  const refreshDetailRef = useRef<(taskId: string, quiet?: boolean) => Promise<void>>(async () => {})
  const tokenRef = useRef(token)
  tokenRef.current = token

  const stopAllStreams = useCallback(() => {
    for (const controller of streamControllers.current.values()) controller.abort()
    streamControllers.current.clear()
    for (const timer of detailRefreshTimers.current.values()) window.clearTimeout(timer)
    detailRefreshTimers.current.clear()
  }, [])

  const logout = useCallback(() => {
    stopAllStreams()
    try { sessionStorage.removeItem(TOKEN_KEY) } catch { /* storage can be unavailable */ }
    tokenRef.current = null
    setToken(null)
    setUser(null)
    setAuthPhase("anonymous")
    setTasks([])
    setSelectedTaskId(null)
    setDetailsByTask({})
    setEventsByTask({})
    setEvidenceDetails({})
    setEvidenceLoading({})
    hydratedEventTasks.current.clear()
    setStreamStateByTask({})
    setError(null)
  }, [stopAllStreams])

  useEffect(() => {
    if (!token) {
      setAuthPhase("anonymous")
      return
    }
    let active = true
    setAuthPhase("checking")
    getCurrentUser(token, logout)
      .then(currentUser => {
        if (!active) return
        setUser(currentUser)
        setAuthPhase("authenticated")
      })
      .catch(err => {
        if (!active) return
        if (!(err instanceof ApiError && err.status === 401)) {
          setAuthError(err instanceof Error ? err.message : "无法验证登录状态")
          logout()
        }
      })
    return () => { active = false }
  }, [logout, token])

  useEffect(() => () => stopAllStreams(), [stopAllStreams])

  const login = useCallback(async (username: string, password: string) => {
    setAuthBusy(true)
    setAuthError(null)
    try {
      const response = await loginRequest(username, password)
      try { sessionStorage.setItem(TOKEN_KEY, response.access_token) } catch { /* session-only fallback */ }
      tokenRef.current = response.access_token
      setToken(response.access_token)
      setUser(response.user)
      setAuthPhase("authenticated")
    } catch (err) {
      setAuthError(err instanceof Error ? err.message : "登录失败")
    } finally {
      setAuthBusy(false)
    }
  }, [])

  const loadTasks = useCallback(async (quiet = false) => {
    const accessToken = tokenRef.current
    if (!accessToken) return
    if (!quiet) setTasksLoading(true)
    try {
      const rows = await listTasks(accessToken, logout)
      setTasks(current => mergeTaskLists(rows, current))
      setSelectedTaskId(current => current || rows[0]?.id || null)
      setError(null)
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 401)) {
        setError(err instanceof Error ? err.message : "任务列表加载失败")
      }
    } finally {
      if (!quiet) setTasksLoading(false)
    }
  }, [logout])

  useEffect(() => {
    if (authPhase !== "authenticated" || !token) return
    void loadTasks()
    const timer = window.setInterval(() => void loadTasks(true), 10_000)
    return () => window.clearInterval(timer)
  }, [authPhase, loadTasks, token])

  const refreshDetail = useCallback(async (taskId: string, quiet = false) => {
    const accessToken = tokenRef.current
    if (!accessToken || !taskId) return
    if (!quiet) setDetailLoading(current => ({ ...current, [taskId]: true }))
    try {
      const detail = await getTask(accessToken, taskId, logout)
      setDetailsByTask(current => ({ ...current, [taskId]: detail }))
      setTasks(current => current.map(task => task.id === taskId ? { ...task, ...detail.task } : task))
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 401) && !quiet) {
        setError(err instanceof Error ? err.message : "任务详情加载失败")
      }
    } finally {
      if (!quiet) setDetailLoading(current => ({ ...current, [taskId]: false }))
    }
  }, [logout])
  refreshDetailRef.current = refreshDetail

  useEffect(() => {
    if (selectedTaskId && !detailsByTask[selectedTaskId]) void refreshDetail(selectedTaskId)
  }, [detailsByTask, refreshDetail, selectedTaskId])

  const scheduleDetailRefresh = useCallback((taskId: string, immediate = false) => {
    const previous = detailRefreshTimers.current.get(taskId)
    if (previous) window.clearTimeout(previous)
    const timer = window.setTimeout(() => {
      detailRefreshTimers.current.delete(taskId)
      void refreshDetailRef.current(taskId, true)
    }, immediate ? 0 : 280)
    detailRefreshTimers.current.set(taskId, timer)
  }, [])

  const applyEvent = useCallback((taskId: string, event: TaskEvent) => {
    const seen = processedEvents.current.get(taskId) || new Set<string>()
    const key = eventKey(event)
    if (seen.has(key)) return
    seen.add(key)
    if (seen.size > MAX_EVENTS_PER_TASK * 2) seen.clear()
    processedEvents.current.set(taskId, seen)

    setEventsByTask(current => {
      const next = [...(current[taskId] || []), event]
      next.sort((a, b) => {
        if (a.sequence && b.sequence) return a.sequence - b.sequence
        return a.timestamp.localeCompare(b.timestamp)
      })
      return { ...current, [taskId]: next.slice(-MAX_EVENTS_PER_TASK) }
    })

    const status = statusFromEvent(event.type)
    if (status) {
      setTasks(current => current.map(task => task.id === taskId ? { ...task, status } : task))
    }
    const refreshTypes = new Set([
      "plan_created", "plan_updated", "node_completed", "node_failed",
      "evidence_created", "finding_created", "verification_failed",
      "verification_passed", "verification_finished", "run_completed", "run_failed", "run_cancelled",
      "task_completed", "task_failed", "task_cancelled",
    ])
    if (refreshTypes.has(event.type)) scheduleDetailRefresh(taskId, Boolean(status && isTerminalStatus(status)))
  }, [scheduleDetailRefresh])

  const startStream = useCallback((taskId: string) => {
    const accessToken = tokenRef.current
    if (!accessToken || streamControllers.current.has(taskId)) return
    const controller = new AbortController()
    streamControllers.current.set(taskId, controller)
    setStreamStateByTask(current => ({ ...current, [taskId]: "connecting" }))

    void (async () => {
      let retries = 0
      while (!controller.signal.aborted && tokenRef.current) {
        try {
          const result = await consumeTaskEvents({
            taskId,
            token: tokenRef.current,
            lastEventId: streamCursors.current.get(taskId) || null,
            signal: controller.signal,
            onEvent: event => {
              setStreamStateByTask(current => ({ ...current, [taskId]: "live" }))
              if (event.sequence) streamCursors.current.set(taskId, String(event.sequence))
              else if (event.event_id) streamCursors.current.set(taskId, event.event_id)
              applyEvent(taskId, event)
            },
            onUnauthorized: logout,
          })
          if (result.lastEventId) streamCursors.current.set(taskId, result.lastEventId)
          if (result.terminal) {
            hydratedEventTasks.current.add(taskId)
            break
          }
          if (controller.signal.aborted) break
          retries = 0
        } catch (err) {
          if (controller.signal.aborted) break
          if (err instanceof ApiError && err.status === 401) break
          if (err instanceof ApiError && (err.status === 404 || err.status === 409) && retries >= 3) break
        }
        if (controller.signal.aborted) break
        const delay = Math.min(1_000 * (2 ** retries), 16_000)
        retries = Math.min(retries + 1, 5)
        setStreamStateByTask(current => ({ ...current, [taskId]: "reconnecting" }))
        await waitFor(delay, controller.signal)
      }
      if (streamControllers.current.get(taskId) === controller) streamControllers.current.delete(taskId)
      setStreamStateByTask(current => ({ ...current, [taskId]: "closed" }))
      if (!controller.signal.aborted) scheduleDetailRefresh(taskId, true)
    })()
  }, [applyEvent, logout, scheduleDetailRefresh])

  useEffect(() => {
    if (authPhase !== "authenticated") return
    const activeIds = new Set(tasks.filter(task => !isTerminalStatus(task.status) && task.status !== "draft").map(task => task.id))
    if (selectedTaskId && !hydratedEventTasks.current.has(selectedTaskId)) activeIds.add(selectedTaskId)
    for (const id of activeIds) startStream(id)
    for (const [id, controller] of streamControllers.current) {
      if (!activeIds.has(id)) {
        controller.abort()
        streamControllers.current.delete(id)
      }
    }
  }, [authPhase, selectedTaskId, startStream, tasks])

  const createTask = useCallback(async (input: TaskCreateInput): Promise<string | null> => {
    const accessToken = tokenRef.current
    if (!accessToken) return null
    setOperationBusy(true)
    setError(null)
    try {
      const created = await createTaskRequest(accessToken, input, logout)
      if (created.id) {
        setTasks(current => [created, ...current.filter(task => task.id !== created.id)])
        setSelectedTaskId(created.id)
        startStream(created.id)
        void refreshDetail(created.id, true)
      }
      await loadTasks(true)
      return created.id || null
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 401)) setError(err instanceof Error ? err.message : "任务创建失败")
      return null
    } finally {
      setOperationBusy(false)
    }
  }, [loadTasks, logout, refreshDetail, startStream])

  const cancelTask = useCallback(async (taskId: string) => {
    const accessToken = tokenRef.current
    if (!accessToken) return
    setOperationBusy(true)
    setError(null)
    try {
      await cancelTaskRequest(accessToken, taskId, logout)
      setTasks(current => current.map(task => task.id === taskId ? { ...task, status: "cancelling" } : task))
      scheduleDetailRefresh(taskId, true)
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 401)) setError(err instanceof Error ? err.message : "取消任务失败")
    } finally {
      setOperationBusy(false)
    }
  }, [logout, scheduleDetailRefresh])

  const loadEvidence = useCallback(async (taskId: string, evidenceId: string) => {
    const accessToken = tokenRef.current
    if (!accessToken || !taskId || !evidenceId || evidenceDetails[evidenceId] || evidenceLoading[evidenceId]) return
    setEvidenceLoading(current => ({ ...current, [evidenceId]: true }))
    try {
      const evidence = await getEvidence(accessToken, taskId, evidenceId, logout)
      setEvidenceDetails(current => ({ ...current, [evidenceId]: evidence }))
    } catch (err) {
      if (!(err instanceof ApiError && err.status === 401)) setError(err instanceof Error ? err.message : "证据原文加载失败")
    } finally {
      setEvidenceLoading(current => ({ ...current, [evidenceId]: false }))
    }
  }, [evidenceDetails, evidenceLoading, logout])

  const selectedTask = useMemo(
    () => tasks.find(task => task.id === selectedTaskId) || null,
    [selectedTaskId, tasks],
  )

  return {
    authPhase,
    user,
    authError,
    authBusy,
    login,
    logout,
    tasks,
    tasksLoading,
    loadTasks,
    selectedTaskId,
    selectedTask,
    selectTask: setSelectedTaskId,
    selectedDetail: selectedTaskId ? detailsByTask[selectedTaskId] || null : null,
    selectedDetailLoading: selectedTaskId ? Boolean(detailLoading[selectedTaskId]) : false,
    selectedEvents: selectedTaskId ? eventsByTask[selectedTaskId] || [] : [],
    selectedStreamState: selectedTaskId ? streamStateByTask[selectedTaskId] || "closed" : "closed",
    createTask,
    cancelTask,
    evidenceDetails,
    evidenceLoading,
    loadEvidence,
    operationBusy,
    error,
    clearError: () => setError(null),
    refreshSelected: () => selectedTaskId ? refreshDetail(selectedTaskId) : Promise.resolve(),
  }
}

export type SecGoController = ReturnType<typeof useSecGoController>
