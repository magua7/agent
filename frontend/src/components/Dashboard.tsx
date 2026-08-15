import { useCallback, useEffect, useRef, useState } from "react"
import { useSSE } from "../hooks/useSSE"
import { ChatInput } from "./ChatInput"
import { CurrentTaskPanel } from "./CurrentTaskPanel"
import { DashboardErrorBanner } from "./DashboardErrorBanner"
import { DashboardTopBar } from "./DashboardTopBar"
import { DashboardWelcome } from "./DashboardWelcome"
import { RiskConfirmationModal } from "./RiskConfirmationModal"
import { SessionMessageList } from "./SessionMessageList"
import { useToast } from "./Toast"

interface Props {
  task: ReturnType<typeof import("../hooks/useTask").useTask>
}

export function Dashboard({ task }: Props) {
  const {
    taskId,
    status,
    timeline,
    report,
    stats,
    error,
    createTask,
    submitApproval,
    cancelTask,
    handleEvent,
    clearError,
    currentQuery,
    sessionMessages,
    scrollToIndex,
    scrollTargetTaskId,
    clearScrollTargetTaskId,
    selectedTaskId,
    selectedTaskLoading,
    displayTask,
    showWelcome,
    showCurrentTask,
    showCurrentUserQuery,
  } = task

  const { toast } = useToast()
  const toastedRef = useRef<Set<string>>(new Set())
  const scrollRef = useRef<HTMLDivElement>(null)
  const [sseError, setSseError] = useState<string | null>(null)

  const isRunning = status === "running" || status === "waiting_approval"
  const isFinal = status === "completed" || status === "failed" || status === "cancelled" || status === "timed_out"
  const displayTimeline = displayTask?.timeline || []
  const displayReport = displayTask?.report || null
  const displayStats = displayTask?.stats || null
  const displayQuery = displayTask?.query || ""
  const displayStatus = displayTask?.status || status

  useEffect(() => {
    if (!scrollRef.current) return
    if (selectedTaskId || selectedTaskLoading || scrollTargetTaskId) return
    if (!(isRunning || showCurrentTask)) return
    scrollRef.current.scrollTop = scrollRef.current.scrollHeight
  }, [isRunning, showCurrentTask, timeline, report, sessionMessages.length, selectedTaskId, selectedTaskLoading, scrollTargetTaskId])

  useEffect(() => {
    if (!scrollTargetTaskId) return

    let attempts = 0
    const tryScroll = () => {
      const element = document.getElementById(`task-msg-${scrollTargetTaskId}`)
      if (element) {
        element.scrollIntoView({ behavior: "smooth", block: "center" })
        element.classList.add("highlight-message")
        setTimeout(() => element.classList.remove("highlight-message"), 2000)
        clearScrollTargetTaskId()
        return
      }
      if (++attempts < 15) setTimeout(tryScroll, 100)
    }

    tryScroll()
  }, [clearScrollTargetTaskId, scrollTargetTaskId])

  const handleCreateTask = useCallback(async (query: string) => {
    await createTask(query, false)
  }, [createTask])

  useSSE({
    taskId: isRunning ? taskId : null,
    onEvent: (event) => {
      setSseError(null)
      handleEvent(event)
      if (
        event.type === "TASK_FINISHED"
        || event.type === "TASK_FAILED"
        || event.type === "TASK_CANCELLED"
        || event.type === "TASK_TIMED_OUT"
      ) {
        void task.syncFromBackend(event.task_id || taskId || undefined)
      }
    },
    onError: (message: string) => {
      setSseError(message)
    },
  })

  useEffect(() => {
    for (let i = timeline.length - 1; i >= 0; i--) {
      const entry = timeline[i]
      const key = `${entry.kind}:${entry.message || ""}`
      if (toastedRef.current.has(key)) continue
      if (entry.kind === "warning") {
        toastedRef.current.add(key)
        toast("warning", entry.message || "")
      } else if (entry.kind === "error") {
        toastedRef.current.add(key)
        toast("error", entry.message || "")
      }
    }
    if (toastedRef.current.size > 200) toastedRef.current.clear()
  }, [timeline, toast])

  const pendingApproval = timeline.find(
    entry => entry.kind === "approval" && !entry.resolved,
  ) as { kind: "approval"; step: any; resolved: boolean } | undefined
  const canCancelDisplayTask = !selectedTaskId && isRunning

  return (
    <div className="surface-card-strong flex min-w-0 flex-1 flex-col overflow-hidden rounded-[32px] xl:h-[calc(100vh-5.5rem)]">
      {displayStatus !== "idle" && (
        <DashboardTopBar
          status={displayStatus}
          report={displayReport}
          stats={displayStats}
          onCancel={canCancelDisplayTask ? cancelTask : undefined}
        />
      )}

      {(error || sseError) && (
        <DashboardErrorBanner
          error={error || sseError || "未知错误"}
          onDismiss={() => {
            clearError()
            setSseError(null)
          }}
        />
      )}

      <div ref={scrollRef} className="flex-1 overflow-y-auto px-6 py-5 md:px-8">
        {showWelcome ? (
          <DashboardWelcome disabled={isRunning} onSubmit={handleCreateTask} />
        ) : (
          <div className="mx-auto flex w-full max-w-chat-column flex-col gap-4">
            {selectedTaskLoading && (
              <div className="rounded-2xl border border-slate-200 bg-white p-4 text-sm text-slate-500 shadow-sm dark:border-slate-800 dark:bg-slate-950/60 dark:text-slate-400">
                正在定位历史任务...
              </div>
            )}

            <SessionMessageList
              sessionMessages={sessionMessages}
              selectedTaskId={selectedTaskId}
              selectedTaskDetail={selectedTaskId && displayTask ? {
                taskId: displayTask.taskId,
                status: displayStatus,
                query: displayQuery,
                report: displayReport,
                stats: displayStats,
                timeline: displayTimeline,
              } : null}
            />

            {selectedTaskId && displayTask && !displayReport && displayTimeline.length === 0 && (
              <div className="rounded-2xl border border-amber-200 bg-amber-50 p-4 text-sm text-amber-700 shadow-sm dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-300">
                该历史任务暂未恢复到可展示的链路或报告数据，请刷新后重试；如果这是旧任务，后端会优先用 execution_steps 做兜底恢复。
              </div>
            )}

            {showCurrentTask && (
              <CurrentTaskPanel
                currentQuery={currentQuery}
                timeline={timeline}
                report={report}
                stats={stats}
                error={error}
                status={status}
                showUserQuery={showCurrentUserQuery}
              />
            )}
          </div>
        )}
      </div>

      {!showWelcome && (
        <div className="input-dock shrink-0 px-6 pb-5 pt-4 md:px-8">
          <div className="mx-auto w-full max-w-chat-column">
            <ChatInput
              onSubmit={handleCreateTask}
              disabled={isRunning}
              placeholder={isRunning ? "等待当前任务完成..." : "继续提问..."}
              variant="light"
            />
          </div>
        </div>
      )}

      <RiskConfirmationModal
        step={pendingApproval?.step || null}
        open={!!pendingApproval}
        onApprove={() => submitApproval("approve")}
        onDeny={() => submitApproval("deny")}
        onSkipAll={() => submitApproval("skip_all")}
      />
    </div>
  )
}
