import { Shield, AlertTriangle } from "lucide-react"
import type { PlanStep } from "../types/events"

interface Props {
  step: PlanStep | null
  open: boolean
  onApprove: () => void
  onDeny: () => void
  onSkipAll: () => void
}

export function RiskConfirmationModal({ step, open, onApprove, onDeny, onSkipAll }: Props) {
  if (!open || !step) return null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-slate-950/40 px-4 backdrop-blur-sm dark:bg-black/70">
      <div className="mx-4 w-full max-w-md rounded-3xl border border-amber-200 bg-white shadow-2xl dark:border-amber-900/60 dark:bg-slate-950">
        <div className="flex items-center gap-3 border-b border-slate-200 p-5 dark:border-slate-800">
          <div className="rounded-2xl bg-amber-100 p-2 text-amber-600 dark:bg-amber-950/40 dark:text-amber-300">
            <AlertTriangle className="w-6 h-6" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-slate-900 dark:text-slate-100">需要确认操作</h3>
            <p className="text-sm text-amber-600 dark:text-amber-300">Level 2 — 主动探测</p>
          </div>
        </div>

        <div className="space-y-3 p-5">
          <div className="grid grid-cols-2 gap-3 text-sm">
            <div>
              <span className="text-slate-500 dark:text-slate-400">工具</span>
              <p className="font-mono text-slate-800 dark:text-slate-100">{step.tool}</p>
            </div>
            <div>
              <span className="text-slate-500 dark:text-slate-400">风险等级</span>
              <p className="font-bold text-amber-600 dark:text-amber-300">{step.risk}</p>
            </div>
          </div>
          <div>
            <span className="text-sm text-slate-500 dark:text-slate-400">参数</span>
            <pre className="output-pre mt-1">{JSON.stringify(step.args, null, 2)}</pre>
          </div>
          {step.reason && (
            <div>
              <span className="text-sm text-slate-500 dark:text-slate-400">理由</span>
              <p className="mt-0.5 text-sm text-slate-600 dark:text-slate-300">{step.reason}</p>
            </div>
          )}
          <div className="rounded-2xl border border-amber-200 bg-amber-50 p-3 text-xs text-amber-700 dark:border-amber-900/60 dark:bg-amber-950/30 dark:text-amber-300">
            可能产生网络请求，不会修改目标数据
          </div>
        </div>

        <div className="flex gap-3 border-t border-slate-200 p-5 dark:border-slate-800">
          <button
            onClick={onSkipAll}
            className="flex-1 rounded-2xl bg-slate-100 py-2.5 text-sm text-slate-600 transition hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700"
          >
            跳过全部
          </button>
          <button
            onClick={onDeny}
            className="flex-1 rounded-2xl bg-slate-100 py-2.5 text-sm text-slate-600 transition hover:bg-slate-200 dark:bg-slate-800 dark:text-slate-300 dark:hover:bg-slate-700"
          >
            跳过此步
          </button>
          <button
            onClick={onApprove}
            className="flex flex-1 items-center justify-center gap-1.5 rounded-2xl bg-cyan-600 py-2.5 text-sm font-medium text-white transition hover:bg-cyan-700"
          >
            <Shield className="w-4 h-4" />
            确认执行
          </button>
        </div>
      </div>
    </div>
  )
}
