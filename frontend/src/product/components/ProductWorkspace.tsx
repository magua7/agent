import { AlertTriangle, X } from "lucide-react"
import type { SecGoController } from "../useSecGoController"
import { TaskDetailView } from "./TaskDetailView"
import { TaskSidebar } from "./TaskSidebar"
import { TimelinePanel } from "./TimelinePanel"

interface Props {
  controller: SecGoController
  onCreate: () => void
}

export function ProductWorkspace({ controller, onCreate }: Props) {
  return (
    <main className="p-3 sm:p-4">
      {controller.error && (
        <div role="alert" className="mx-auto mb-3 flex max-w-[1800px] items-start justify-between gap-3 rounded-2xl border border-red-200 bg-red-50/95 px-4 py-3 text-sm text-red-700 shadow-sm dark:border-red-900/60 dark:bg-red-950/80 dark:text-red-300">
          <div className="flex items-start gap-2"><AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" /><span>{controller.error}</span></div>
          <button onClick={controller.clearError} className="rounded-lg p-1 hover:bg-red-100 dark:hover:bg-red-900/50" aria-label="关闭错误提示"><X className="h-4 w-4" /></button>
        </div>
      )}

      <div className="mx-auto grid max-w-[1800px] gap-3 lg:grid-cols-[280px_minmax(0,1fr)] xl:grid-cols-[280px_minmax(0,1fr)_360px]">
        <TaskSidebar
          tasks={controller.tasks}
          selectedTaskId={controller.selectedTaskId}
          loading={controller.tasksLoading}
          onSelect={controller.selectTask}
          onCreate={onCreate}
          onRefresh={() => void controller.loadTasks()}
        />
        <TaskDetailView
          summary={controller.selectedTask}
          detail={controller.selectedDetail}
          loading={controller.selectedDetailLoading}
          busy={controller.operationBusy}
          onCancel={taskId => void controller.cancelTask(taskId)}
          onRefresh={() => void controller.refreshSelected()}
          onCreate={onCreate}
          evidenceDetails={controller.evidenceDetails}
          evidenceLoading={controller.evidenceLoading}
          onLoadEvidence={(taskId, evidenceId) => void controller.loadEvidence(taskId, evidenceId)}
        />
        <TimelinePanel events={controller.selectedEvents} streamState={controller.selectedStreamState} />
      </div>
    </main>
  )
}
