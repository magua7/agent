import { Bot, User } from "lucide-react"
import type { ConversationEntry, CurrentTaskStatus, TaskDetail } from "../types/events"
import { CurrentTaskPanel } from "./CurrentTaskPanel"
import { MarkdownRenderer } from "./MarkdownRenderer"

function UserBubble({ content }: { content: string }) {
  return (
    <div className="mb-3 flex items-start justify-end gap-3">
      <div className="max-w-[75%] rounded-2xl rounded-tr-sm border border-cyan-200 bg-cyan-50 px-4 py-2.5 dark:border-cyan-800/50 dark:bg-cyan-900/30">
        <p className="text-sm whitespace-pre-wrap text-slate-800 dark:text-slate-100">{content}</p>
      </div>
      <div className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-cyan-600 text-white shadow-sm">
        <User className="w-4 h-4" />
      </div>
    </div>
  )
}

function AssistantShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="mb-3 flex items-start gap-3">
      <div className="mt-1 flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-slate-100 text-cyan-600 shadow-sm dark:bg-slate-800 dark:text-cyan-300">
        <Bot className="w-4 h-4" />
      </div>
      <div className="flex-1 min-w-0">{children}</div>
    </div>
  )
}

interface Props {
  sessionMessages: ConversationEntry[]
  selectedTaskId?: string | null
  selectedTaskDetail?: {
    taskId: string | null
    status: CurrentTaskStatus
    query: string
    report: string | null
    stats: TaskDetail["stats"]
    timeline: TaskDetail["timeline"] | []
  } | null
}

export function SessionMessageList({ sessionMessages, selectedTaskId, selectedTaskDetail }: Props) {
  if (sessionMessages.length === 0) return null

  return (
    <div className="space-y-3">
      {sessionMessages.map((message, index) => {
        const showSelectedTaskDetail = Boolean(
          message.role === "assistant"
          && selectedTaskId
          && message.task_id === selectedTaskId
          && selectedTaskDetail
          && selectedTaskDetail.taskId === selectedTaskId,
        )

        const messageDomId = message.task_id ? `task-msg-${message.task_id}` : `msg-${index}`

        return (
          <div key={`${message.id}-${message.task_id || "local"}`} id={messageDomId}>
            {message.role === "user" && <UserBubble content={message.content} />}

            {message.role === "assistant" && (
              <AssistantMessage
                message={message}
                showSelectedTaskDetail={showSelectedTaskDetail}
                selectedTaskDetail={showSelectedTaskDetail ? selectedTaskDetail : null}
              />
            )}
          </div>
        )
      })}
    </div>
  )
}

function AssistantMessage({
  message,
  showSelectedTaskDetail,
  selectedTaskDetail,
}: {
  message: ConversationEntry
  showSelectedTaskDetail: boolean
  selectedTaskDetail: Props["selectedTaskDetail"]
}) {
  const shouldInlineTaskDetail = Boolean(
    showSelectedTaskDetail
    && selectedTaskDetail
    && ((selectedTaskDetail.timeline && selectedTaskDetail.timeline.length > 0) || selectedTaskDetail.report),
  )

  return (
    <AssistantShell>
      <div className="space-y-3">
        {!shouldInlineTaskDetail && (
          <div className="rounded-2xl border border-slate-200 bg-white p-4 shadow-sm dark:border-slate-800 dark:bg-slate-950/60">
            <MarkdownRenderer content={message.content} />
          </div>
        )}
        {showSelectedTaskDetail && selectedTaskDetail && (
          <CurrentTaskPanel
            currentQuery={selectedTaskDetail.query}
            timeline={selectedTaskDetail.timeline || []}
            report={selectedTaskDetail.report}
            stats={selectedTaskDetail.stats}
            error={null}
            status={selectedTaskDetail.status}
            showUserQuery={false}
          />
        )}
      </div>
    </AssistantShell>
  )
}
