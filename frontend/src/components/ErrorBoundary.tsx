import { Component, type ReactNode } from "react"
import { AlertTriangle, RefreshCw } from "lucide-react"

interface Props {
  children: ReactNode
  fallback?: ReactNode
}

interface State {
  hasError: boolean
  error: string | null
}

export class ErrorBoundary extends Component<Props, State> {
  state: State = { hasError: false, error: null }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error: error.message }
  }

  componentDidCatch(error: Error, info: any) {
    console.error("[ErrorBoundary]", error, info)
  }

  handleReset = () => {
    this.setState({ hasError: false, error: null })
  }

  render() {
    if (this.state.hasError) {
      if (this.props.fallback) return this.props.fallback

      return (
        <div className="flex items-center justify-center h-full">
          <div className="text-center space-y-4 max-w-md">
            <AlertTriangle className="w-12 h-12 text-red-400 mx-auto" />
            <h2 className="text-lg font-semibold text-white">界面渲染错误</h2>
            <p className="text-sm text-gray-400 break-all">{this.state.error}</p>
            <button
              onClick={this.handleReset}
              className="inline-flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-200
                         rounded-lg px-4 py-2 text-sm transition-colors border border-gray-700"
            >
              <RefreshCw className="w-4 h-4" />
              重试
            </button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
