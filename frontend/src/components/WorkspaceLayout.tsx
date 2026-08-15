import { useState } from "react"
import { Dashboard } from "./Dashboard"
import { ExecutionFlowPanel } from "./ExecutionFlowPanel"
import { ResizeHandle } from "./ResizeHandle"
import { Sidebar } from "./Sidebar"

interface Props {
  task: ReturnType<typeof import("../hooks/useTask").useTask>
  sidebarOpen: boolean
  onToggleSidebar: () => void
  onSelectSession: (sid: string) => void
  onSelectTask: (taskId: string, sessionId?: string) => void
  onNewSession: () => void
  onDeleteTask: (taskId: string) => void
  onRenameTask: (taskId: string, title: string) => void
  onCopyReport: (taskId: string) => void
}

const SIDEBAR_KEY = "security_agent_sidebar_width"
const RIGHT_KEY = "security_agent_right_panel_width"
const SIDEBAR_DEFAULT = 320
const SIDEBAR_MIN = 220
const SIDEBAR_MAX = 480
const RIGHT_DEFAULT = 360
const RIGHT_MIN = 280
const RIGHT_MAX = 560

function loadWidth(key: string, fallback: number, min: number, max: number): number {
  try {
    const raw = Number(localStorage.getItem(key))
    if (Number.isFinite(raw) && raw >= min && raw <= max) return raw
  } catch {
    /* ignore */
  }
  return fallback
}

function saveWidth(key: string, width: number) {
  try {
    localStorage.setItem(key, String(width))
  } catch {
    /* ignore */
  }
}

export function WorkspaceLayout({
  task,
  sidebarOpen,
  onToggleSidebar,
  onSelectSession,
  onSelectTask,
  onNewSession,
  onDeleteTask,
  onRenameTask,
  onCopyReport,
}: Props) {
  const [sidebarWidth, setSidebarWidth] = useState(() =>
    loadWidth(SIDEBAR_KEY, SIDEBAR_DEFAULT, SIDEBAR_MIN, SIDEBAR_MAX),
  )
  const [rightPanelWidth, setRightPanelWidth] = useState(() =>
    loadWidth(RIGHT_KEY, RIGHT_DEFAULT, RIGHT_MIN, RIGHT_MAX),
  )

  const handleSidebarResize = (w: number) => {
    setSidebarWidth(w)
    saveWidth(SIDEBAR_KEY, w)
  }
  const handleRightResize = (w: number) => {
    setRightPanelWidth(w)
    saveWidth(RIGHT_KEY, w)
  }

  return (
    <div className="flex h-[calc(100vh-4.5rem)] bg-transparent">
      <Sidebar
        sessions={task.sessions}
        sessionsError={task.sessionsError}
        activeSessionId={task.currentSessionId}
        activeTaskId={task.selectedTaskId || task.taskId}
        collapsed={!sidebarOpen}
        width={sidebarWidth}
        onToggle={onToggleSidebar}
        onSelectSession={onSelectSession}
        onSelectTask={onSelectTask}
        onNewSession={onNewSession}
        onDeleteTask={onDeleteTask}
        onRenameTask={onRenameTask}
        onCopyReport={onCopyReport}
      />
      <ResizeHandle
        currentWidth={sidebarOpen ? sidebarWidth : 64}
        onResize={handleSidebarResize}
        min={SIDEBAR_MIN}
        max={SIDEBAR_MAX}
        defaultWidth={SIDEBAR_DEFAULT}
      />
      <div className="flex min-w-0 flex-1 flex-col px-4 pb-4 pt-4 md:px-5">
        <Dashboard task={task} />
      </div>
      <ResizeHandle
        currentWidth={rightPanelWidth}
        onResize={handleRightResize}
        min={RIGHT_MIN}
        max={RIGHT_MAX}
        defaultWidth={RIGHT_DEFAULT}
        reverse
      />
      <ExecutionFlowPanel
        timeline={task.displayTask?.timeline || []}
        status={task.displayTask?.status || task.status}
        width={rightPanelWidth}
      />
    </div>
  )
}