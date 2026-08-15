import { useState, useRef, useEffect } from "react"
import { createPortal } from "react-dom"
import { Plus, Menu, X, MoreHorizontal, Pencil, Copy, Trash2, ChevronDown, ChevronRight, MessageSquare } from "lucide-react"
import type { SessionInfo, TaskSummary } from "../types/events"
import { TaskStatusBadge } from "./StatusBadge"

interface Props {
  sessions: SessionInfo[]
  sessionsError?: string | null
  activeSessionId: string | null
  activeTaskId: string | null
  collapsed: boolean
  width?: number
  onToggle: () => void
  onSelectSession: (id: string) => void
  onSelectTask: (id: string, sessionId?: string) => void
  onNewSession: () => void
  onDeleteTask: (id: string) => void
  onRenameTask: (id: string, title: string) => void
  onCopyReport: (id: string) => void
}

interface MenuState {
  taskId: string
  top: number
  left: number
}

const MENU_WIDTH = 160
const MENU_HEIGHT = 132
const MENU_GAP = 8
const VIEWPORT_PADDING = 8

export function Sidebar({
  sessions, sessionsError, activeSessionId, activeTaskId, collapsed, width,
  onToggle, onSelectSession, onSelectTask, onNewSession,
  onDeleteTask, onRenameTask, onCopyReport,
}: Props) {
  const [expandedSessions, setExpandedSessions] = useState<Set<string>>(new Set())
  const [menuState, setMenuState] = useState<MenuState | null>(null)
  const [renameId, setRenameId] = useState<string | null>(null)
  const [renameValue, setRenameValue] = useState("")
  const renameInputRef = useRef<HTMLInputElement>(null)
  const menuRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (activeSessionId) {
      setExpandedSessions(prev => new Set(prev).add(activeSessionId))
    }
  }, [activeSessionId])

  useEffect(() => {
    if (!menuState) return
    const handler = (e: MouseEvent) => {
      if (menuRef.current && !menuRef.current.contains(e.target as Node)) {
        setMenuState(null)
      }
    }
    const closeMenu = () => setMenuState(null)
    document.addEventListener("mousedown", handler)
    window.addEventListener("resize", closeMenu)
    return () => {
      document.removeEventListener("mousedown", handler)
      window.removeEventListener("resize", closeMenu)
    }
  }, [menuState])

  useEffect(() => {
    setMenuState(null)
  }, [activeSessionId, activeTaskId, collapsed])

  useEffect(() => {
    if (renameId) renameInputRef.current?.focus()
  }, [renameId])

  const toggleExpand = (sid: string) => {
    setExpandedSessions(prev => {
      const next = new Set(prev)
      if (next.has(sid)) next.delete(sid)
      else next.add(sid)
      return next
    })
  }

  const getMenuPosition = (triggerEl: HTMLElement) => {
    const rect = triggerEl.getBoundingClientRect()
    const maxLeft = window.innerWidth - MENU_WIDTH - VIEWPORT_PADDING
    const left = Math.max(
      VIEWPORT_PADDING,
      Math.min(rect.right - MENU_WIDTH, maxLeft),
    )
    const preferredTop = rect.bottom + MENU_GAP
    const maxTop = window.innerHeight - MENU_HEIGHT - VIEWPORT_PADDING
    const top = Math.max(
      VIEWPORT_PADDING,
      Math.min(preferredTop, maxTop),
    )
    return { top, left }
  }

  const toggleMenu = (taskId: string, triggerEl: HTMLElement) => {
    setRenameId(null)
    setMenuState(prev => {
      if (prev?.taskId === taskId) return null
      return { taskId, ...getMenuPosition(triggerEl) }
    })
  }

  const handleMenuClick = (e: React.MouseEvent<HTMLElement>, taskId: string) => {
    e.stopPropagation()
    e.preventDefault()
    toggleMenu(taskId, e.currentTarget)
  }

  const handleMenuKeyDown = (e: React.KeyboardEvent<HTMLElement>, taskId: string) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault()
      e.stopPropagation()
      toggleMenu(taskId, e.currentTarget)
    }
  }

  const handleRenameStart = (e: React.MouseEvent, task: TaskSummary) => {
    e.stopPropagation()
    setMenuState(null)
    setRenameId(task.task_id)
    setRenameValue(task.title || task.query)
  }

  const handleRenameSubmit = (taskId: string) => {
    const trimmed = renameValue.trim()
    if (trimmed) onRenameTask(taskId, trimmed)
    setRenameId(null)
  }

  const handleRenameKeyDown = (e: React.KeyboardEvent, taskId: string) => {
    if (e.key === "Enter") handleRenameSubmit(taskId)
    if (e.key === "Escape") setRenameId(null)
  }

  const handleDelete = (e: React.MouseEvent, task: TaskSummary) => {
    e.stopPropagation()
    setMenuState(null)
    if (confirm(`确定删除任务「${task.title || task.query}」？`)) {
      onDeleteTask(task.task_id)
    }
  }

  const handleCopyReport = (e: React.MouseEvent, taskId: string) => {
    e.stopPropagation()
    setMenuState(null)
    onCopyReport(taskId)
  }

  const sessionName = (s: SessionInfo) => s.first_query || `对话 ${s.session_id.slice(-8)}`

  const timeStr = (t: string) => {
    try { return new Date(t).toLocaleTimeString("zh-CN", { hour: "2-digit", minute: "2-digit" }) }
    catch { return "" }
  }

  const menu = menuState ? createPortal(
    <div
      ref={menuRef}
      className="fixed z-[140] w-40 rounded-2xl border border-slate-200 bg-white py-1 shadow-2xl dark:border-slate-800 dark:bg-slate-900"
      style={{ top: `${menuState.top}px`, left: `${menuState.left}px` }}
      onClick={(e) => e.stopPropagation()}
    >
      {(() => {
        const session = sessions.find(item => item.tasks.some(task => task.task_id === menuState.taskId))
        const task = session?.tasks.find(item => item.task_id === menuState.taskId)
        if (!task) return null
        return (
          <>
            <button
              onClick={(e) => handleRenameStart(e, task)}
              className="w-full flex items-center gap-2 px-3 py-2 text-left text-xs text-slate-600 transition hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              <Pencil className="w-3 h-3 text-slate-400" />
              重命名
            </button>
            <button
              onClick={(e) => handleCopyReport(e, task.task_id)}
              className="w-full flex items-center gap-2 px-3 py-2 text-left text-xs text-slate-600 transition hover:bg-slate-100 dark:text-slate-300 dark:hover:bg-slate-800"
            >
              <Copy className="w-3 h-3 text-slate-400" />
              复制报告
            </button>
            <div className="my-1 border-t border-slate-200 dark:border-slate-800" />
            <button
              onClick={(e) => handleDelete(e, task)}
              className="w-full flex items-center gap-2 px-3 py-2 text-left text-xs text-red-500 transition hover:bg-slate-100 dark:hover:bg-slate-800"
            >
              <Trash2 className="w-3 h-3" />
              删除
            </button>
          </>
        )
      })()}
    </div>,
    document.body,
  ) : null

  if (!collapsed) {
    return (
      <>
        <aside style={{ width }} className="shrink-0 border-r border-slate-200/80 bg-white/78 backdrop-blur-xl dark:border-slate-800/80 dark:bg-slate-950/84 max-sm:fixed max-sm:inset-y-0 max-sm:left-0 max-sm:z-40 max-sm:shadow-2xl">
          <div className="flex h-full flex-col">
            <div className="flex items-center justify-end px-4 pt-4 sm:hidden">
              <button onClick={onToggle} className="text-slate-400 hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300">
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="px-4 pb-4 pt-3">
              <button
                onClick={onNewSession}
                className="w-full flex items-center justify-center gap-2 rounded-2xl bg-cyan-600 px-4 py-3 text-sm font-medium text-white shadow-sm transition hover:bg-cyan-700"
              >
                <Plus className="w-4 h-4" />
                新建会话
              </button>
            </div>

            <div className="flex-1 overflow-y-auto px-3 pb-4 overflow-x-visible" onScroll={() => setMenuState(null)}>
              <div className="mb-3 flex items-center gap-2 px-2 text-xs font-semibold uppercase tracking-[0.14em] text-slate-500 dark:text-slate-400">
                <MessageSquare className="w-3.5 h-3.5" />
                对话历史
              </div>

              {sessionsError ? (
                <p className="py-8 text-center text-xs text-red-500 dark:text-red-400">{sessionsError}</p>
              ) : sessions.length === 0 ? (
                <p className="py-8 text-center text-xs text-slate-400 dark:text-slate-500">暂无对话历史</p>
              ) : (
                <div className="space-y-2.5">
                  {sessions.map((session) => {
                    const isActive = session.session_id === activeSessionId
                    const isExpanded = expandedSessions.has(session.session_id) || isActive

                    return (
                      <div key={session.session_id} className="surface-card rounded-[26px] p-1.5">
                        <div
                          onClick={() => {
                            if (isActive) toggleExpand(session.session_id)
                            else onSelectSession(session.session_id)
                          }}
                          role="button"
                          tabIndex={0}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" || e.key === " ") {
                              e.preventDefault()
                              if (isActive) toggleExpand(session.session_id)
                              else onSelectSession(session.session_id)
                            }
                          }}
                          className={[
                            "flex cursor-pointer items-start gap-3 rounded-[20px] px-3 py-3 transition",
                            isActive
                              ? "bg-cyan-50/90 text-slate-900 dark:bg-slate-800 dark:text-slate-100"
                              : "hover:bg-slate-100/80 dark:hover:bg-slate-800/70",
                          ].join(" ")}
                        >
                          <button
                            type="button"
                            onClick={(e) => { e.stopPropagation(); toggleExpand(session.session_id) }}
                            className="mt-0.5 shrink-0 text-slate-400 hover:text-slate-600 dark:text-slate-500 dark:hover:text-slate-300"
                          >
                            {isExpanded ? <ChevronDown className="w-3.5 h-3.5" /> : <ChevronRight className="w-3.5 h-3.5" />}
                          </button>
                          <div className="min-w-0 flex-1">
                            <div className="truncate text-sm font-semibold text-slate-800 dark:text-slate-100">{sessionName(session)}</div>
                            <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">{timeStr(session.last_active)}</div>
                          </div>
                        </div>

                        {isExpanded && session.tasks.length > 0 && (
                          <div className="ml-[1.15rem] mt-1 space-y-1 border-l border-slate-200/80 pl-4 dark:border-slate-700/80">
                            {session.tasks.map((task) => (
                              <div key={task.task_id} className="relative group">
                                {renameId === task.task_id ? (
                                  <div className="rounded-2xl border border-cyan-300 bg-cyan-50 p-2.5 dark:border-cyan-800 dark:bg-slate-800">
                                    <input
                                      ref={renameInputRef}
                                      type="text"
                                      value={renameValue}
                                      onChange={(e) => setRenameValue(e.target.value)}
                                      onBlur={() => handleRenameSubmit(task.task_id)}
                                      onKeyDown={(e) => handleRenameKeyDown(e, task.task_id)}
                                      className="w-full rounded-xl border border-slate-200 bg-white px-3 py-2 text-xs text-slate-800 outline-none focus:border-cyan-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100"
                                      placeholder="输入新标题..."
                                    />
                                  </div>
                                ) : (
                                  <button
                                    onClick={() => onSelectTask(task.task_id, session.session_id)}
                                    className={[
                                      "flex w-full items-center gap-3 rounded-2xl border px-3 py-2.5 text-left text-xs transition",
                                      task.task_id === activeTaskId
                                        ? "border-cyan-200 bg-cyan-50/90 dark:border-slate-700 dark:bg-slate-800"
                                        : "border-transparent hover:bg-slate-100/80 dark:hover:bg-slate-800/70",
                                    ].join(" ")}
                                  >
                                    <span className="min-w-0 flex-1 truncate text-[0.82rem] leading-6 text-slate-600 dark:text-slate-300">
                                      {task.title || task.query}
                                    </span>
                                    <TaskStatusBadge status={task.status} />
                                    <span
                                      role="button"
                                      tabIndex={0}
                                      onClick={(e) => handleMenuClick(e, task.task_id)}
                                      onKeyDown={(e) => handleMenuKeyDown(e, task.task_id)}
                                      className="inline-flex shrink-0 cursor-pointer rounded-full p-1 text-slate-400 opacity-0 transition-all hover:bg-slate-200 hover:text-slate-700 group-hover:opacity-100 dark:text-slate-500 dark:hover:bg-slate-700 dark:hover:text-slate-200"
                                    >
                                      <MoreHorizontal className="w-3.5 h-3.5" />
                                    </span>
                                  </button>
                                )}
                              </div>
                            ))}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          </div>
        </aside>
        {menu}
      </>
    )
  }

  return (
    <aside className="flex h-full w-16 shrink-0 flex-col items-center gap-3 border-r border-slate-200/80 bg-white/78 py-3 backdrop-blur-xl dark:border-slate-800/80 dark:bg-slate-950/84">
      <button onClick={onToggle} className="p-1.5 text-slate-400 hover:text-slate-700 dark:text-slate-500 dark:hover:text-slate-200">
        <Menu className="w-5 h-5" />
      </button>
      <button onClick={onNewSession} className="rounded-xl p-2 text-slate-400 hover:bg-slate-100 hover:text-cyan-600 dark:text-slate-500 dark:hover:bg-slate-800 dark:hover:text-cyan-300" title="新建会话">
        <Plus className="w-5 h-5" />
      </button>
      <div className="flex-1 overflow-y-auto space-y-2 w-full px-2">
        {sessions.map((session) => (
          <button
            key={session.session_id}
            onClick={() => onSelectSession(session.session_id)}
            title={sessionName(session)}
            className={[
              "mx-auto flex h-10 w-10 items-center justify-center rounded-xl text-xs transition-colors",
              session.session_id === activeSessionId
                ? "bg-cyan-50 text-cyan-700 dark:bg-slate-800 dark:text-cyan-300"
                : "text-slate-500 hover:bg-slate-100 hover:text-slate-700 dark:text-slate-500 dark:hover:bg-slate-800 dark:hover:text-slate-200",
            ].join(" ")}
          >
            <MessageSquare className="w-4 h-4" />
          </button>
        ))}
      </div>
      <div className="mt-auto mb-2 h-2.5 w-2.5 rounded-full bg-cyan-500 shadow-[0_0_0_3px_rgba(14,165,233,0.18)] dark:bg-cyan-300" />
    </aside>
  )
}
