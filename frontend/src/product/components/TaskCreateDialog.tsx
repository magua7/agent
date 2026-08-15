import { FormEvent, useEffect, useState } from "react"
import { AlertTriangle, ShieldCheck, X } from "lucide-react"
import { isLoopbackTarget, parsePorts } from "../model"
import type { TaskCreateInput } from "../types"

interface Props {
  open: boolean
  busy: boolean
  onClose: () => void
  onCreate: (input: TaskCreateInput) => Promise<boolean>
}

export function TaskCreateDialog({ open, busy, onClose, onCreate }: Props) {
  const [title, setTitle] = useState("本机服务发现")
  const [description, setDescription] = useState("检查明确授权的本机 TCP 端口，保存真实扫描证据并形成验证结论。")
  const [target, setTarget] = useState("127.0.0.1")
  const [portsText, setPortsText] = useState("80,443,8000,8080")
  const [authorized, setAuthorized] = useState(false)
  const [validationError, setValidationError] = useState<string | null>(null)

  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape" && !busy) onClose()
    }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [busy, onClose, open])

  if (!open) return null

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setValidationError(null)
    if (!title.trim()) return setValidationError("请填写任务标题")
    if (!description.trim()) return setValidationError("请填写任务描述")
    if (!isLoopbackTarget(target)) return setValidationError("当前 MVP 仅允许 localhost、127.0.0.0/8 或 ::1")
    if (!authorized) return setValidationError("请确认你已明确授权此次本机检查")
    try {
      const created = await onCreate({
        title: title.trim(),
        description: description.trim(),
        target: target.trim(),
        ports: parsePorts(portsText),
      })
      if (created) {
        setAuthorized(false)
        onClose()
      }
    } catch (err) {
      setValidationError(err instanceof Error ? err.message : "输入无效")
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/45 px-4 py-8 backdrop-blur-sm" onMouseDown={event => event.target === event.currentTarget && !busy && onClose()}>
      <form onSubmit={submit} className="surface-card-strong max-h-full w-full max-w-2xl overflow-y-auto rounded-[32px]">
        <div className="flex items-start justify-between border-b border-slate-200/80 px-6 py-5 dark:border-slate-800">
          <div>
            <div className="flex items-center gap-2 text-lg font-bold text-slate-950 dark:text-white"><ShieldCheck className="h-5 w-5 text-cyan-600 dark:text-cyan-300" />创建授权任务</div>
            <p className="mt-1 text-sm text-slate-500 dark:text-slate-400">目标和端口会作为明确授权范围写入 TaskSpec。</p>
          </div>
          <button type="button" onClick={onClose} disabled={busy} className="rounded-xl p-2 text-slate-400 hover:bg-slate-100 hover:text-slate-700 dark:hover:bg-slate-800 dark:hover:text-slate-200"><X className="h-5 w-5" /></button>
        </div>

        <div className="space-y-5 px-6 py-6">
          <label className="block">
            <span className="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-300">任务标题</span>
            <input value={title} onChange={event => setTitle(event.target.value)} maxLength={160} className="secgo-input" />
          </label>
          <label className="block">
            <span className="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-300">任务描述</span>
            <textarea value={description} onChange={event => setDescription(event.target.value)} rows={3} maxLength={4000} className="secgo-input resize-none" />
          </label>
          <div className="grid gap-4 sm:grid-cols-2">
            <label className="block">
              <span className="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-300">Loopback 目标</span>
              <input value={target} onChange={event => setTarget(event.target.value)} className="secgo-input font-mono" placeholder="127.0.0.1" />
              <span className="mt-1.5 block text-xs text-slate-400">仅允许 localhost、127.0.0.0/8、::1</span>
            </label>
            <label className="block">
              <span className="mb-2 block text-sm font-medium text-slate-700 dark:text-slate-300">TCP 端口</span>
              <input value={portsText} onChange={event => setPortsText(event.target.value)} className="secgo-input font-mono" placeholder="80,443,8080" />
              <span className="mt-1.5 block text-xs text-slate-400">1–65535，逗号分隔，最多 128 个</span>
            </label>
          </div>

          <label className="flex cursor-pointer items-start gap-3 rounded-2xl border border-cyan-200 bg-cyan-50/80 p-4 dark:border-cyan-900/60 dark:bg-cyan-950/25">
            <input type="checkbox" checked={authorized} onChange={event => setAuthorized(event.target.checked)} className="mt-0.5 h-4 w-4 rounded border-slate-300 text-cyan-600 focus:ring-cyan-500" />
            <span className="text-sm leading-6 text-cyan-900 dark:text-cyan-200">
              我确认对上述 loopback 目标和端口拥有明确授权，并理解执行会产生真实本机网络连接。
            </span>
          </label>

          {validationError && (
            <div role="alert" className="flex items-start gap-2 rounded-2xl border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-700 dark:border-red-900/60 dark:bg-red-950/30 dark:text-red-300">
              <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />{validationError}
            </div>
          )}
        </div>

        <div className="flex justify-end gap-3 border-t border-slate-200/80 px-6 py-5 dark:border-slate-800">
          <button type="button" onClick={onClose} disabled={busy} className="rounded-2xl border border-slate-200 bg-white px-5 py-2.5 text-sm text-slate-600 transition hover:bg-slate-50 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300 dark:hover:bg-slate-800">取消</button>
          <button disabled={busy} className="rounded-2xl bg-cyan-600 px-5 py-2.5 text-sm font-semibold text-white shadow-sm transition hover:bg-cyan-700 disabled:cursor-not-allowed disabled:opacity-60">{busy ? "正在创建..." : "创建并执行"}</button>
        </div>
      </form>
    </div>
  )
}
