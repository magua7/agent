import { useMemo } from "react"
import { Background, BackgroundVariant, Controls, Position, ReactFlow, type Edge, type Node } from "@xyflow/react"
import "@xyflow/react/dist/style.css"
import { GitBranch } from "lucide-react"
import type { PlanNodeRecord, PlanRecord } from "../types"
import { StatusPill } from "./StatusPill"

const NODE_WIDTH = 240
const COLUMN_GAP = 100
const ROW_GAP = 150

function nodeDepths(nodes: PlanNodeRecord[]): Map<string, number> {
  const ids = new Set(nodes.map(node => node.id))
  const depths = new Map(nodes.map(node => [node.id, 0]))
  for (let pass = 0; pass < nodes.length; pass++) {
    let changed = false
    for (const node of nodes) {
      const dependencies = node.dependencies.filter(id => ids.has(id))
      if (dependencies.length === 0) continue
      const next = Math.max(...dependencies.map(id => depths.get(id) || 0)) + 1
      if (next > (depths.get(node.id) || 0) && next < nodes.length) {
        depths.set(node.id, next)
        changed = true
      }
    }
    if (!changed) break
  }
  return depths
}

function nodeStyle(status: string): React.CSSProperties {
  const normalized = status.toLowerCase()
  const border = normalized === "succeeded" ? "#34d399"
    : normalized === "failed" ? "#f87171"
      : normalized === "running" ? "#22d3ee"
        : normalized === "blocked" ? "#fb923c"
          : "#94a3b8"
  return {
    width: NODE_WIDTH,
    border: `2px solid ${border}`,
    borderRadius: 18,
    padding: 0,
    background: "transparent",
    boxShadow: "0 14px 35px -24px rgba(15, 23, 42, .4)",
  }
}

export function PlanGraph({ plan }: { plan: PlanRecord | null }) {
  const graph = useMemo(() => {
    if (!plan) return { nodes: [] as Node[], edges: [] as Edge[] }
    const depths = nodeDepths(plan.nodes)
    const columns = new Map<number, PlanNodeRecord[]>()
    for (const node of plan.nodes) {
      const depth = depths.get(node.id) || 0
      columns.set(depth, [...(columns.get(depth) || []), node])
    }
    const graphNodes: Node[] = []
    for (const [depth, column] of columns) {
      column.forEach((node, row) => {
        graphNodes.push({
          id: node.id,
          position: { x: depth * (NODE_WIDTH + COLUMN_GAP), y: row * ROW_GAP },
          sourcePosition: Position.Right,
          targetPosition: Position.Left,
          style: nodeStyle(node.status),
          data: {
            label: (
              <div className="rounded-[16px] bg-white/95 p-4 text-left dark:bg-slate-900/95">
                <div className="mb-2 flex items-start justify-between gap-2">
                  <span className="line-clamp-2 text-sm font-semibold text-slate-900 dark:text-slate-100">{node.goal}</span>
                  <StatusPill status={node.status} compact />
                </div>
                {node.description && <p className="line-clamp-2 text-xs leading-5 text-slate-500 dark:text-slate-400">{node.description}</p>}
                {node.requiredCapabilities.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1">
                    {node.requiredCapabilities.slice(0, 3).map(capability => <span key={capability} className="rounded-full bg-slate-100 px-2 py-1 font-mono text-[0.62rem] text-slate-500 dark:bg-slate-800 dark:text-slate-400">{capability}</span>)}
                  </div>
                )}
              </div>
            ),
          },
        })
      })
    }
    const graphEdges: Edge[] = []
    const ids = new Set(plan.nodes.map(node => node.id))
    for (const node of plan.nodes) {
      for (const dependency of node.dependencies) {
        if (!ids.has(dependency)) continue
        graphEdges.push({
          id: `${dependency}->${node.id}`,
          source: dependency,
          target: node.id,
          type: "smoothstep",
          animated: node.status === "running",
          style: { stroke: node.status === "succeeded" ? "#34d399" : "#94a3b8", strokeWidth: 2 },
        })
      }
    }
    return { nodes: graphNodes, edges: graphEdges }
  }, [plan])

  if (!plan || plan.nodes.length === 0) {
    return (
      <div className="flex min-h-80 flex-col items-center justify-center rounded-3xl border border-dashed border-slate-300 bg-slate-50/60 px-6 text-center dark:border-slate-700 dark:bg-slate-950/30">
        <GitBranch className="mb-3 h-8 w-8 text-slate-400" />
        <div className="text-sm font-medium text-slate-700 dark:text-slate-300">计划尚未生成</div>
        <p className="mt-1 text-xs text-slate-500 dark:text-slate-400">Planner 生成结构化 Plan 后，这里会按真实依赖关系展示 DAG。</p>
      </div>
    )
  }

  return (
    <div className="h-[470px] overflow-hidden rounded-3xl border border-slate-200 bg-slate-50/70 dark:border-slate-800 dark:bg-slate-950/40">
      <ReactFlow nodes={graph.nodes} edges={graph.edges} fitView fitViewOptions={{ padding: 0.25 }} minZoom={0.3} maxZoom={1.8} proOptions={{ hideAttribution: true }}>
        <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="#94a3b8" />
        <Controls className="!rounded-xl !border !border-slate-200 !bg-white/90 !shadow-sm dark:!border-slate-700 dark:!bg-slate-900/90" />
      </ReactFlow>
    </div>
  )
}
