import { X, XCircle } from "lucide-react"

interface Props {
  error: string
  onDismiss: () => void
}

export function DashboardErrorBanner({ error, onDismiss }: Props) {
  return (
    <div className="mx-6 mt-4 flex items-center justify-between rounded-2xl border border-red-200 bg-red-50 p-3 shrink-0 dark:border-red-900/60 dark:bg-red-950/30">
      <div className="flex items-center gap-2 text-sm text-red-600 dark:text-red-300">
        <XCircle className="w-4 h-4" />
        {error}
      </div>
      <button onClick={onDismiss} className="text-red-500 hover:text-red-600 dark:text-red-300 dark:hover:text-red-200">
        <X className="w-4 h-4" />
      </button>
    </div>
  )
}
