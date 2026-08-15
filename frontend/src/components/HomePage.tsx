import { ArrowRight, FileSearch, Radar, ShieldCheck, Workflow } from "lucide-react"
import { ChatInput } from "./ChatInput"

interface Props {
  onSubmit: (query: string) => void
  onEnterWorkspace: () => void
}

const FEATURE_CARDS = [
  {
    icon: ShieldCheck,
    title: "漏洞分析",
    description: "围绕目标 URL、接口和系统行为，生成结构化分析与修复建议。",
  },
  {
    icon: Radar,
    title: "资产侦察",
    description: "从端口、服务、页面入口到公开情报，快速建立目标画像。",
  },
  {
    icon: Workflow,
    title: "执行流程可视化",
    description: "把任务理解、计划生成、工具调用和结果汇总完整展示出来。",
  },
  {
    icon: FileSearch,
    title: "报告生成",
    description: "自动整理发现、证据与建议，输出适合展示和汇报的安全报告。",
  },
]

export function HomePage({ onSubmit, onEnterWorkspace }: Props) {
  return (
    <main className="min-h-[calc(100vh-4.5rem)] px-6 py-16 md:py-20">
      <div className="app-content-shell flex flex-col items-center gap-14 text-center md:gap-16">
        <section className="mx-auto flex max-w-5xl flex-col items-center gap-5 md:gap-7">
          <div className="space-y-3 md:space-y-4">
            <h1 className="hero-highlight bg-gradient-to-r from-cyan-600 via-sky-600 to-indigo-700 bg-clip-text text-5xl font-black text-transparent md:text-7xl xl:text-[5.6rem]">
              智御Go安全智能体
            </h1>
            <div className="hero-kicker text-2xl font-bold text-slate-900 dark:text-slate-50 md:text-4xl xl:text-[3rem]">
              帮你完成研判、执行与报告
            </div>
          </div>

          <p className="hero-description text-base md:text-xl">
            从任务理解、执行路径规划，到工具调用、风险确认与最终报告输出，
            帮助你更高效地完成安全研判、验证分析与结论整理。
          </p>
        </section>

        <section className="surface-card-strong w-full max-w-4xl rounded-[30px] p-5 text-left md:p-6">
          <div className="mb-5 flex flex-col gap-4 md:flex-row md:items-start md:justify-between">
            <div className="space-y-1.5">
              <div className="panel-title text-slate-950 dark:text-slate-50">开始一次安全任务</div>
              <div className="panel-subtitle">
                直接输入问题，或进入工作台查看历史会话与执行流程。
              </div>
            </div>
            <button
              type="button"
              onClick={onEnterWorkspace}
              className="inline-flex items-center gap-2 self-start rounded-full border border-slate-200/90 bg-white/90 px-4 py-2 text-sm font-medium text-slate-700 shadow-sm transition hover:border-cyan-300 hover:text-cyan-700 dark:border-slate-700 dark:bg-slate-950/80 dark:text-slate-300 dark:hover:border-cyan-700 dark:hover:text-cyan-300"
            >
              进入工作台
              <ArrowRight className="h-4 w-4" />
            </button>
          </div>
          <ChatInput
            onSubmit={onSubmit}
            placeholder="输入域名、IP、漏洞问题或任何你想交给智能体分析的任务..."
            variant="light"
          />
        </section>

        <section className="grid w-full max-w-6xl gap-5 md:grid-cols-2 xl:grid-cols-4">
          {FEATURE_CARDS.map(card => {
            const Icon = card.icon
            return (
              <button
                key={card.title}
                type="button"
                onClick={onEnterWorkspace}
                className="surface-card group rounded-[28px] p-6 text-left transition duration-200 hover:-translate-y-1 hover:shadow-panel dark:hover:shadow-panel-dark"
              >
                <div className="mb-5 flex h-12 w-12 items-center justify-center rounded-2xl bg-cyan-50 text-cyan-600 transition group-hover:bg-cyan-600 group-hover:text-white dark:bg-slate-800 dark:text-cyan-300 dark:group-hover:bg-cyan-500 dark:group-hover:text-slate-950">
                  <Icon className="h-6 w-6" />
                </div>
                <h3 className="mb-3 text-lg font-semibold text-slate-900 dark:text-slate-100">{card.title}</h3>
                <p className="text-sm leading-7 text-slate-600 dark:text-slate-400">{card.description}</p>
              </button>
            )
          })}
        </section>

        <section className="grid w-full max-w-5xl gap-5 md:grid-cols-3">
          {[
            {
              step: "01",
              title: "输入任务 / 选择能力",
              description: "输入自然语言问题，或从能力卡片进入具体场景。",
            },
            {
              step: "02",
              title: "规划并执行验证",
              description: "智能体拆解任务，规划执行链，并按风险等级调用工具。",
            },
            {
              step: "03",
              title: "输出报告与执行过程",
              description: "除了结论，还能展示完整思路和证据路径。",
            },
          ].map(item => (
            <div
              key={item.step}
              className="surface-card rounded-[30px] p-6 text-left md:p-7"
            >
              <div className="mb-5 inline-flex h-11 w-11 items-center justify-center rounded-full bg-cyan-600 text-sm font-semibold text-white shadow-sm">
                {item.step}
              </div>
              <div className="mb-3 text-xl font-semibold text-slate-900 dark:text-slate-100">{item.title}</div>
              <p className="text-sm leading-7 text-slate-600 dark:text-slate-400">{item.description}</p>
            </div>
          ))}
        </section>

        <div className="text-sm text-slate-500 dark:text-slate-400">
          面向安全分析、验证执行与报告整理的一体化智能体工作入口。
        </div>
      </div>
    </main>
  )
}