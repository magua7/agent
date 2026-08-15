import { useEffect, useState, useCallback, createContext, useContext, type ReactNode } from "react"
import { X, AlertTriangle, XCircle, Info } from "lucide-react"

interface ToastItem {
  id: string
  level: "warning" | "error" | "info"
  message: string
}

// ── Toast Context ──

interface ToastCtx {
  toast: (level: ToastItem["level"], message: string) => void
}

const ToastContext = createContext<ToastCtx>({ toast: () => {} })

export function useToast() {
  return useContext(ToastContext)
}

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<ToastItem[]>([])

  const addToast = useCallback((level: ToastItem["level"], message: string) => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`
    setToasts(prev => [...prev.slice(-4), { id, level, message }])
  }, [])

  const removeToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  return (
    <ToastContext.Provider value={{ toast: addToast }}>
      {children}
      {/* Toast container — fixed bottom-right */}
      <div className="fixed bottom-4 right-4 z-50 space-y-2 max-w-sm">
        {toasts.map(t => (
          <ToastMessage key={t.id} item={t} onDismiss={() => removeToast(t.id)} />
        ))}
      </div>
    </ToastContext.Provider>
  )
}

// ── Single Toast ──

function ToastMessage({ item, onDismiss }: { item: ToastItem; onDismiss: () => void }) {
  useEffect(() => {
    const timer = setTimeout(onDismiss, 4000)
    return () => clearTimeout(timer)
  }, [onDismiss])

  const config = {
    warning: { bg: "bg-yellow-900/90 border-yellow-700", text: "text-yellow-200", icon: AlertTriangle },
    error:   { bg: "bg-red-900/90 border-red-700", text: "text-red-200", icon: XCircle },
    info:    { bg: "bg-blue-900/90 border-blue-700", text: "text-blue-200", icon: Info },
  }
  const c = config[item.level] || config.info
  const Icon = c.icon

  return (
    <div className={`${c.bg} ${c.text} border rounded-lg px-4 py-3 shadow-2xl
                     animate-[slideIn_0.2s_ease-out] flex items-start gap-3`}>
      <Icon className="w-4 h-4 mt-0.5 shrink-0" />
      <p className="text-sm flex-1">{item.message}</p>
      <button onClick={onDismiss} className="opacity-60 hover:opacity-100 transition-opacity shrink-0">
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}
