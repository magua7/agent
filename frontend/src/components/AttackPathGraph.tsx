import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { createPortal } from "react-dom"
import {
  Background,
  BackgroundVariant,
  Controls,
  Handle,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
  type OnInit,
  type ReactFlowInstance,
  useEdgesState,
  useNodesState,
} from "@xyflow/react"
import "@xyflow/react/dist/style.css"
import { AlertTriangle, Globe, Globe2, Loader2, Maximize2, Shield, Terminal, Wrench, X } from "lucide-react"
import type { AttackNodeData } from "../hooks/useAttackGraph"

type AttackNode = Node<AttackNodeData>

function TargetNode({ data }: NodeProps) {
  const d = data as unknown as AttackNodeData
  return (
    <div className="relative flex items-center gap-3 rounded-2xl border-2 border-cyan-400/60 bg-white/90 px-5 py-4 shadow-lg shadow-cyan-500/10 backdrop-blur dark:bg-slate-900/90 dark:shadow-cyan-500/5">
      <Handle type="source" position={Position.Bottom} className="!border-cyan-400 !bg-cyan-400" />
      <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-cyan-100 text-cyan-600 dark:bg-cyan-900/50 dark:text-cyan-300">
        <Shield className="h-5 w-5" />
      </div>
      <div className="min-w-0">
        <div className="truncate text-sm font-semibold text-slate-800 dark:text-slate-100">{d.label}</div>
        <div className="text-xs text-cyan-600 dark:text-cyan-400">攻击目标</div>
      </div>
    </div>
  )
}

function StepNode({ data }: NodeProps) {
  const d = data as unknown as AttackNodeData
  const isRunning = d.status === "running"
  const isFailed = d.status === "failed" || d.runtimeStatus === "failed" || d.runtimeStatus === "cancelled" || d.runtimeStatus === "timed_out"
  const isSkipped = d.runtimeStatus === "denied"

  const borderColor = isFailed ? "border-red-400/60" : isSkipped ? "border-amber-400/60" : isRunning ? "border-cyan-400/60" : "border-purple-400/60"
  const iconBg = isFailed ? "bg-red-100 text-red-600 dark:bg-red-900/50 dark:text-red-300" : isSkipped ? "bg-amber-100 text-amber-600 dark:bg-amber-900/50 dark:text-amber-300" : isRunning ? "bg-cyan-100 text-cyan-600 dark:bg-cyan-900/50 dark:text-cyan-300" : "bg-purple-100 text-purple-600 dark:bg-purple-900/50 dark:text-purple-300"
  const labelColor = isFailed ? "text-red-700 dark:text-red-300" : isSkipped ? "text-amber-700 dark:text-amber-300" : "text-slate-800 dark:text-slate-100"

  const riskDot = d.risk === "level3" ? "bg-red-500" : d.risk === "level2" ? "bg-amber-500" : d.risk === "level1" ? "bg-cyan-500" : "bg-green-500"

  const toolIcon = useMemo(() => {
    const t = (d.tool || "").toLowerCase()
    if (t.includes("port") || t.includes("scan")) return <Globe2 className="h-5 w-5" />
    if (t.includes("dir") || t.includes("enum")) return <Globe className="h-5 w-5" />
    if (t.includes("sql") || t.includes("xss") || t.includes("vuln")) return <AlertTriangle className="h-5 w-5" />
    if (t.includes("exec") || t.includes("command") || t.includes("shell")) return <Terminal className="h-5 w-5" />
    return <Wrench className="h-5 w-5" />
  }, [d.tool])

  return (
    <div className={`relative rounded-2xl border-2 ${borderColor} bg-white/90 px-4 py-3 shadow-lg backdrop-blur dark:bg-slate-900/90`}>
      <Handle type="target" position={Position.Top} className="!border-slate-400 !bg-slate-400" />
      <Handle type="source" position={Position.Bottom} className="!border-slate-400 !bg-slate-400" />
      <div className="flex items-center gap-3">
        <div className={`flex h-9 w-9 items-center justify-center rounded-xl ${iconBg}`}>
          {isRunning ? <Loader2 className="h-5 w-5 animate-spin" /> : toolIcon}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className={`truncate text-sm font-semibold ${labelColor}`}>{d.label}</span>
            <span className={`h-2 w-2 shrink-0 rounded-full ${riskDot}`} />
          </div>
          <div className="flex items-center gap-2 text-xs text-slate-500 dark:text-slate-400">
            <span>{d.subtitle}</span>
            {d.status === "running" && <span className="text-cyan-500">执行中...</span>}
            {d.runtimeStatus === "succeeded" && <span className="text-green-500">✓</span>}
            {isFailed && <span className="text-red-500">✗</span>}
            {isSkipped && <span className="text-amber-500">—</span>}
            {d.elapsed != null && <span>{d.elapsed}s</span>}
          </div>
        </div>
      </div>
    </div>
  )
}

function AssetNode({ data }: NodeProps) {
  const d = data as unknown as AttackNodeData
  return (
    <div className="relative rounded-2xl border-2 border-blue-400/50 bg-blue-50/90 px-4 py-3 shadow-lg backdrop-blur dark:bg-blue-950/50 dark:border-blue-700/50">
      <Handle type="target" position={Position.Top} className="!border-blue-400 !bg-blue-400" />
      <div className="flex items-center gap-2">
        <div className="flex h-7 w-7 items-center justify-center rounded-lg bg-blue-100 text-blue-600 dark:bg-blue-900/50 dark:text-blue-300">
          <Globe className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <div className="truncate text-sm font-medium text-blue-800 dark:text-blue-200">{d.label}</div>
          <div className="text-xs text-blue-500 dark:text-blue-400">资产</div>
        </div>
      </div>
    </div>
  )
}

function VulnNode({ data }: NodeProps) {
  const d = data as unknown as AttackNodeData
  const riskColor = d.risk === "level3" ? "border-red-400/60 bg-red-50/90 dark:bg-red-950/50 dark:border-red-700/60" : d.risk === "level2" ? "border-amber-400/60 bg-amber-50/90 dark:bg-amber-950/50 dark:border-amber-700/60" : "border-yellow-400/60 bg-yellow-50/90 dark:bg-yellow-950/50 dark:border-yellow-700/60"
  const iconBg = d.risk === "level3" ? "bg-red-100 text-red-600 dark:bg-red-900/50 dark:text-red-300" : d.risk === "level2" ? "bg-amber-100 text-amber-600 dark:bg-amber-900/50 dark:text-amber-300" : "bg-yellow-100 text-yellow-600 dark:bg-yellow-900/50 dark:text-yellow-300"
  const textColor = d.risk === "level3" ? "text-red-800 dark:text-red-200" : d.risk === "level2" ? "text-amber-800 dark:text-amber-200" : "text-yellow-800 dark:text-yellow-200"

  return (
    <div className={`relative rounded-2xl border-2 ${riskColor} px-4 py-3 shadow-lg backdrop-blur`}>
      <Handle type="target" position={Position.Top} className="!border-slate-400 !bg-slate-400" />
      <div className="flex items-center gap-2">
        <div className={`flex h-7 w-7 items-center justify-center rounded-lg ${iconBg}`}>
          <AlertTriangle className="h-4 w-4" />
        </div>
        <div className="min-w-0">
          <div className={`truncate text-sm font-semibold ${textColor}`}>{d.label}</div>
          <div className="text-xs text-slate-500 dark:text-slate-400">
            {d.risk === "level3" ? "高危" : d.risk === "level2" ? "中危" : "低危"}
          </div>
        </div>
      </div>
    </div>
  )
}

const nodeTypes = {
  target: TargetNode,
  step: StepNode,
  asset: AssetNode,
  vuln: VulnNode,
}

function SelectedNodePopup({ data }: { data: AttackNodeData }) {
  return (
    <div className="absolute bottom-4 left-4 right-4 z-10 rounded-2xl border border-slate-200 bg-white/95 px-4 py-3 shadow-lg backdrop-blur dark:border-slate-800 dark:bg-slate-900/95">
      <div className="mb-1 flex items-center gap-2">
        <span className="text-sm font-semibold text-slate-800 dark:text-slate-100">{data.label}</span>
        {data.risk && (
          <span className={`rounded-full px-2 py-0.5 text-xs font-medium ${
            data.risk === "level3" ? "bg-red-100 text-red-700 dark:bg-red-900/50 dark:text-red-300"
            : data.risk === "level2" ? "bg-amber-100 text-amber-700 dark:bg-amber-900/50 dark:text-amber-300"
            : "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/50 dark:text-yellow-300"
          }`}>
            {data.risk === "level3" ? "高危" : data.risk === "level2" ? "中危" : "低危"}
          </span>
        )}
      </div>
      {data.subtitle && <div className="text-xs text-slate-500 dark:text-slate-400">{data.subtitle}</div>}
      {data.outputPreview && (
        <pre className="mt-2 max-h-24 overflow-y-auto rounded-xl bg-slate-50 p-2 text-xs text-slate-600 dark:bg-slate-950 dark:text-slate-400">
          {data.outputPreview}
        </pre>
      )}
    </div>
  )
}

interface CanvasProps {
  nodes: AttackNode[]
  edges: Edge[]
  className?: string
}

function GraphCanvas({ nodes: initialNodes, edges: initialEdges, className }: CanvasProps) {
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes)
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges)
  const flowRef = useRef<ReactFlowInstance<AttackNode, Edge> | null>(null)

  // useNodesState/useEdgesState 只在挂载时初始化；时间线持续更新时需手动同步 props，
  // 否则攻击路径图会停留在挂载那一刻的状态（表现为"没反应"）。
  useEffect(() => {
    setNodes(initialNodes)
    setEdges(initialEdges)
  }, [initialNodes, initialEdges, setNodes, setEdges])

  // 数据变化后重新适配视口，保证纵向攻击链始终完整可见
  useEffect(() => {
    const instance = flowRef.current
    if (!instance || initialNodes.length === 0) return
    const t = setTimeout(() => instance.fitView({ padding: 0.25, duration: 200 }), 60)
    return () => clearTimeout(t)
  }, [initialNodes, initialEdges])

  const onInit: OnInit<AttackNode, Edge> = useCallback((instance) => {
    flowRef.current = instance
  }, [])

  const [selectedNode, setSelectedNode] = useState<AttackNodeData | null>(null)

  const onNodeClick = useCallback((_event: React.MouseEvent, node: Node) => {
    setSelectedNode(node.data as unknown as AttackNodeData)
  }, [])

  const onPaneClick = useCallback(() => {
    setSelectedNode(null)
  }, [])

  const defaultEdgeOptions = useMemo(() => ({
    style: { stroke: "#94a3b8", strokeWidth: 2 },
    type: "smoothstep",
    animated: true,
  }), [])

  return (
    <div className="relative h-full w-full">
      <ReactFlow
        onInit={onInit}
        nodes={nodes}
        edges={edges}
        onNodesChange={onNodesChange}
        onEdgesChange={onEdgesChange}
        nodeTypes={nodeTypes}
        defaultEdgeOptions={defaultEdgeOptions}
        fitView
        fitViewOptions={{ padding: 0.25 }}
        minZoom={0.3}
        maxZoom={2}
        onNodeClick={onNodeClick}
        onPaneClick={onPaneClick}
        proOptions={{ hideAttribution: true }}
        className={className}
      >
        <Background variant={BackgroundVariant.Dots} gap={16} size={1} color="#94a3b8" />
        <Controls className="!rounded-2xl !border !border-slate-200 !bg-white/80 !shadow-sm !backdrop-blur dark:!border-slate-800 dark:!bg-slate-900/80" />
      </ReactFlow>

      {selectedNode && <SelectedNodePopup data={selectedNode} />}
    </div>
  )
}

interface Props {
  nodes: AttackNode[]
  edges: Edge[]
}

export function AttackPathGraph({ nodes, edges }: Props) {
  const [expanded, setExpanded] = useState(false)

  useEffect(() => {
    if (!expanded) return
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setExpanded(false)
    }
    window.addEventListener("keydown", onKey)
    const prev = document.body.style.overflow
    document.body.style.overflow = "hidden"
    return () => {
      window.removeEventListener("keydown", onKey)
      document.body.style.overflow = prev
    }
  }, [expanded])

  if (nodes.length === 0) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 text-slate-400 dark:text-slate-500">
        <Wrench className="h-8 w-8" />
        <div className="text-sm">任务开始后，攻击路径图将在此展示</div>
      </div>
    )
  }

  return (
    <div className="relative h-full w-full">
      <GraphCanvas nodes={nodes} edges={edges} className="rounded-2xl" />

      <button
        type="button"
        onClick={() => setExpanded(true)}
        title="全屏查看攻击路径图"
        className="absolute right-3 top-3 z-10 flex h-9 w-9 items-center justify-center rounded-xl border border-slate-200 bg-white/90 text-slate-500 shadow-sm backdrop-blur transition hover:border-cyan-300 hover:text-cyan-600 dark:border-slate-700 dark:bg-slate-900/90 dark:text-slate-400 dark:hover:border-cyan-600 dark:hover:text-cyan-300"
      >
        <Maximize2 className="h-4 w-4" />
      </button>

      {expanded && createPortal(
        <div className="fixed inset-x-0 bottom-0 top-[4.5rem] z-50 flex flex-col bg-slate-950/85 p-4 backdrop-blur-sm md:p-6">
          <div className="mb-4 flex items-center justify-between px-1">
            <div className="flex items-center gap-2 text-sm font-semibold text-slate-100">
              <Shield className="h-4 w-4 text-cyan-400" />
              攻击路径图 · 全屏
            </div>
            <button
              type="button"
              onClick={() => setExpanded(false)}
              className="flex h-9 w-9 items-center justify-center rounded-xl border border-slate-700 bg-slate-900 text-slate-300 transition hover:border-cyan-600 hover:text-cyan-300"
              title="关闭"
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          <div className="min-h-0 flex-1 overflow-hidden rounded-2xl border border-slate-700/80 bg-slate-900/80">
            <GraphCanvas nodes={nodes} edges={edges} className="rounded-2xl" />
          </div>
        </div>,
        document.body,
      )}
    </div>
  )
}
