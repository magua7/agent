import { useMemo } from "react"
import type { Edge, Node } from "@xyflow/react"
import type { TimelineEntry } from "../types/events"

export interface AttackNodeData extends Record<string, unknown> {
  type: "target" | "step" | "vuln" | "asset"
  label: string
  subtitle?: string
  risk?: string
  status?: string
  tool?: string
  outputPreview?: string
  runtimeStatus?: string
  elapsed?: number
}

const STEP_W = 200
const FIND_W = 190
const SPINE_X = 0
const FIND_X = SPINE_X + STEP_W / 2 + 70
const V_STEP = 110
const V_FIND = 70
const ROOT_Y = 20
const TOP_GAP = 110

function parseDiscoveredItems(tool: string, output: string): { assets: string[]; vulns: { label: string; risk: string }[] } {
  const assets: string[] = []
  const vulns: { label: string; risk: string }[] = []
  const lower = output.toLowerCase()

  if (tool.includes("port_scan") || tool.includes("portscan")) {
    const ports = lower.match(/port\s+(\d+)/g)
    if (ports) ports.forEach(p => assets.push(p))
    const open = lower.match(/(\d+)\/(tcp|udp)\s+open/g)
    if (open) open.forEach(o => assets.push(o))
  }

  if (tool.includes("dir_enum") || tool.includes("dirsearch") || tool.includes("dir")) {
    const urls = output.match(/(https?:\/\/[^\s"'<>,]+)/gi)
    if (urls) urls.forEach(u => assets.push(u))
    const paths = output.match(/\/[\w\-./]+\.\w+/g)
    if (paths) paths.forEach(p => assets.push(p))
  }

  const vulnPatterns = [
    { pattern: /sql\s*injection/i, label: "SQL Injection", risk: "level3" },
    { pattern: /xss|cross.?site.?scripting/i, label: "XSS", risk: "level2" },
    { pattern: /ssrf/i, label: "SSRF", risk: "level2" },
    { pattern: /command\s*injection|cmdi/i, label: "Command Injection", risk: "level3" },
    { pattern: /path\s*traversal|lfi/i, label: "Path Traversal", risk: "level2" },
    { pattern: /open\s*redirect/i, label: "Open Redirect", risk: "level1" },
    { pattern: /csrf/i, label: "CSRF", risk: "level1" },
    { pattern: /xxe/i, label: "XXE", risk: "level3" },
    { pattern: /vulnerability/i, label: "Vulnerability", risk: "level2" },
  ]

  for (const vp of vulnPatterns) {
    if (vp.pattern.test(output)) {
      if (!vulns.find(v => v.label === vp.label)) {
        vulns.push({ label: vp.label, risk: vp.risk })
      }
    }
  }

  if (lower.includes("found") && assets.length === 0 && vulns.length === 0) {
    const foundMatch = output.match(/found\s+[:\s]*(.+?)(?:\.|$)/i)
    if (foundMatch) assets.push(foundMatch[1].trim())
  }

  return { assets, vulns }
}

export function useAttackGraph(timeline: TimelineEntry[]): { nodes: Node<AttackNodeData>[]; edges: Edge[] } {
  return useMemo(() => {
    const nodes: Node<AttackNodeData>[] = []
    const edges: Edge[] = []
    const nodeSet = new Set<string>()

    let target = ""
    for (const entry of timeline) {
      if (entry.kind === "debug" && entry.debugType === "intent" && entry.details) {
        target = (entry.details as Record<string, any>).target || ""
        break
      }
    }

    if (target) {
      nodes.push({
        id: "target",
        type: "target",
        position: { x: SPINE_X - STEP_W / 2, y: ROOT_Y },
        data: { type: "target", label: target },
      })
      nodeSet.add("target")
    }

    let stepIdx = 0
    let prevStepId: string | null = null

    for (const entry of timeline) {
      if (entry.kind !== "tool") continue
      stepIdx++
      const sid = `step-${stepIdx}`
      const stepY = ROOT_Y + TOP_GAP + (stepIdx - 1) * V_STEP

      nodes.push({
        id: sid,
        type: "step",
        position: { x: SPINE_X - STEP_W / 2, y: stepY },
        data: {
          type: "step",
          label: entry.tool || "unknown",
          subtitle: `Step ${entry.stepNum ?? stepIdx}`,
          risk: entry.risk,
          status: entry.status,
          tool: entry.tool,
          outputPreview: entry.outputPreview,
          runtimeStatus: entry.runtimeStatus,
          elapsed: entry.elapsed,
        },
      })
      nodeSet.add(sid)

      // 攻击主线：目标 → 步骤1 → 步骤2 → …
      if (stepIdx === 1) {
        if (target) edges.push({ id: `e-target-${sid}`, source: "target", target: sid, animated: true })
      } else if (prevStepId) {
        edges.push({ id: `e-step-${stepIdx - 1}-${sid}`, source: prevStepId, target: sid, animated: true })
      }
      prevStepId = sid

      // 每个步骤的发现物向右分支，多个时纵向错开；超过上限折叠成 "+N 更多"
      if (entry.outputPreview && entry.status === "done") {
        const { assets, vulns } = parseDiscoveredItems(entry.tool || "", entry.outputPreview)
        const findings: { id: string; type: "asset" | "vuln"; label: string; risk?: string }[] = []

        for (const a of assets) {
          const aid = `asset-${stepIdx}-${a.replace(/[^a-zA-Z0-9]/g, "-").slice(0, 40)}`
          if (nodeSet.has(aid)) continue
          nodeSet.add(aid)
          findings.push({ id: aid, type: "asset", label: a.length > 40 ? a.slice(0, 40) + "..." : a })
        }
        for (const v of vulns) {
          const vid = `vuln-${stepIdx}-${v.label.replace(/[^a-zA-Z0-9]/g, "-")}`
          if (nodeSet.has(vid)) continue
          nodeSet.add(vid)
          findings.push({ id: vid, type: "vuln", label: v.label, risk: v.risk })
        }

        const MAX_FINDINGS = 5
        const shown = findings.slice(0, MAX_FINDINGS)
        const hiddenCount = findings.length - shown.length
        const n = shown.length + (hiddenCount > 0 ? 1 : 0)
        shown.forEach((f, j) => {
          nodes.push({
            id: f.id,
            type: f.type,
            position: { x: FIND_X, y: stepY + j * V_FIND - ((n - 1) * V_FIND) / 2 },
            data: { type: f.type, label: f.label, risk: f.risk },
          })
          edges.push({ id: `e-${sid}-${f.id}`, source: sid, target: f.id })
        })
        if (hiddenCount > 0) {
          const moreId = `more-${stepIdx}`
          nodes.push({
            id: moreId,
            type: "asset",
            position: { x: FIND_X, y: stepY + (shown.length) * V_FIND - ((n - 1) * V_FIND) / 2 },
            data: { type: "asset", label: `… +${hiddenCount} 更多` },
          })
          edges.push({ id: `e-${sid}-${moreId}`, source: sid, target: moreId })
        }
      }
    }

    return { nodes, edges }
  }, [timeline])
}