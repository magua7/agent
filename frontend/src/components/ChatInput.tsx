import { useState, useRef } from "react"
import { Send, Loader2 } from "lucide-react"

interface ChatInputProps {
  onSubmit: (query: string) => void
  disabled?: boolean
  placeholder?: string
  variant?: "light" | "dark"
}

export function ChatInput({ onSubmit, disabled, placeholder, variant = "dark" }: ChatInputProps) {
  const [query, setQuery] = useState("")
  const inputRef = useRef<HTMLInputElement>(null)

  const handleSubmit = () => {
    const trimmed = query.trim()
    if (!trimmed || disabled) return
    onSubmit(trimmed)
    setQuery("")
  }

  const light = variant === "light"

  return (
    <div className={[
      "flex items-center gap-3 rounded-[26px] border px-3 py-3 shadow-sm transition",
      light
        ? "border-slate-200/90 bg-white/92 dark:border-slate-800/80 dark:bg-slate-950/88"
        : "border-gray-700 bg-gray-800",
    ].join(" ")}>
      <input
        ref={inputRef}
        id="security-agent-chat-input"
        name="security-agent-chat-input"
        type="text"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
        placeholder={placeholder || "输入安全任务，例如：扫描 127.0.0.1 的端口..."}
        className={[
          "flex-1 rounded-[20px] px-4 py-3.5 text-sm leading-6 focus:outline-none focus:ring-0 disabled:opacity-50",
          light
            ? "border border-slate-200 bg-white text-slate-900 placeholder-slate-400 focus:border-cyan-500 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-100 dark:placeholder-slate-500 dark:focus:border-cyan-400"
            : "border border-gray-700 bg-gray-800 text-gray-100 placeholder-gray-500 focus:border-cyan-600",
        ].join(" ")}
        disabled={disabled}
        autoFocus
      />
      <button
        onClick={handleSubmit}
        disabled={disabled || !query.trim()}
        className={[
          "inline-flex shrink-0 items-center gap-2 rounded-[20px] px-5 py-3.5 text-sm font-medium transition-colors",
          light
            ? "bg-cyan-600 text-white hover:bg-cyan-700 disabled:bg-slate-200 disabled:text-slate-400 dark:disabled:bg-slate-800 dark:disabled:text-slate-500"
            : "bg-cyan-600 text-white hover:bg-cyan-700 disabled:bg-gray-700 disabled:text-gray-500",
        ].join(" ")}
      >
        {disabled ? <Loader2 className="w-4 h-4 animate-spin" /> : <Send className="w-4 h-4" />}
        执行
      </button>
    </div>
  )
}
