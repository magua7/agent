import { Component, type ErrorInfo, type ReactNode } from "react"
import { AlertTriangle, RefreshCw } from "lucide-react"

interface State {
  failed: boolean
}

export class ProductErrorBoundary extends Component<{ children: ReactNode }, State> {
  state: State = { failed: false }

  static getDerivedStateFromError(): State {
    return { failed: true }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error("SEC-GO UI crashed", error, info.componentStack)
  }

  render() {
    if (!this.state.failed) return this.props.children
    return (
      <main className="flex min-h-screen items-center justify-center px-5">
        <div className="surface-card-strong max-w-lg rounded-[32px] p-8 text-center">
          <div className="mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-2xl bg-red-100 text-red-600 dark:bg-red-950/50 dark:text-red-300"><AlertTriangle className="h-7 w-7" /></div>
          <h1 className="text-xl font-bold text-slate-950 dark:text-white">工作台遇到未预期错误</h1>
          <p className="mt-3 text-sm leading-6 text-slate-500 dark:text-slate-400">页面状态已被隔离。刷新后将从后端重新读取任务与审计事件。</p>
          <button onClick={() => window.location.reload()} className="mt-6 inline-flex items-center gap-2 rounded-2xl bg-cyan-600 px-5 py-3 text-sm font-semibold text-white hover:bg-cyan-700"><RefreshCw className="h-4 w-4" />刷新页面</button>
        </div>
      </main>
    )
  }
}

