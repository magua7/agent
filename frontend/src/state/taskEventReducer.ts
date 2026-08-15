import type { AgentEvent, TimelineEntry } from "../types/events"

export interface TaskEventState {
  timeline: TimelineEntry[]
  answerDraft: string
}

export const initialTaskEventState: TaskEventState = {
  timeline: [],
  answerDraft: "",
}

export function reduceTaskEvent(state: TaskEventState, event: AgentEvent): TaskEventState {
  if (event.type === "ANSWER_CHUNK") {
    return {
      ...state,
      answerDraft: state.answerDraft + String(event.payload.delta || ""),
    }
  }
  const timeline = [...state.timeline]
  switch (event.type) {
    case "STEP_STARTED":
      timeline.push({
        kind: "phase",
        phase: event.payload.phase,
        num: event.payload.num,
        total: event.payload.total,
        status: "running",
      })
      break
    case "STEP_FINISHED":
      for (let i = timeline.length - 1; i >= 0; i--) {
        const entry = timeline[i]
        if (entry.kind === "phase" && entry.phase === event.payload.phase && entry.status === "running") {
          timeline[i] = { ...entry, status: "done" }
          break
        }
      }
      break
    case "TOOL_STARTED":
      timeline.push({
        kind: "tool",
        stepNum: event.payload.step_num,
        tool: event.payload.tool,
        args: event.payload.args || {},
        risk: event.payload.risk || "level0",
        status: "running",
        callId: event.payload.call_id,
        canonicalTool: event.payload.canonical_tool,
        toolSource: event.payload.tool_source,
        toolSourceId: event.payload.tool_source_id,
        snapshotVersion: event.payload.snapshot_version,
      })
      break
    case "TOOL_FINISHED":
      for (let i = timeline.length - 1; i >= 0; i--) {
        const entry = timeline[i]
        if (entry.kind === "tool" && entry.status === "running" && (
          (event.payload.call_id && entry.callId === event.payload.call_id)
          || (!event.payload.call_id && entry.tool === event.payload.tool)
        )) {
          timeline[i] = {
            ...entry,
            status: event.payload.status,
            runtimeStatus: event.payload.runtime_status,
            errorCode: event.payload.error_code,
            terminationGuaranteed: event.payload.termination_guaranteed,
            executionMayContinue: event.payload.execution_may_continue,
            remoteTerminationUnknown: event.payload.remote_termination_unknown,
            cleanupError: event.payload.cleanup_error,
            elapsed: event.payload.elapsed,
            outputPreview: event.payload.output_preview,
            resultId: event.payload.result_id,
            evidenceId: event.payload.evidence_id || undefined,
            canonicalTool: event.payload.canonical_tool || entry.canonicalTool,
            toolSource: event.payload.tool_source || entry.toolSource,
            toolSourceId: event.payload.tool_source_id || entry.toolSourceId,
            snapshotVersion: event.payload.snapshot_version || entry.snapshotVersion,
          }
          break
        }
      }
      break
    case "APPROVAL_REQUIRED":
      timeline.push({ kind: "approval", step: event.payload.step, resolved: false })
      break
    case "APPROVAL_APPROVED":
    case "APPROVAL_DENIED":
      for (let i = timeline.length - 1; i >= 0; i--) {
        const entry = timeline[i]
        if (entry.kind === "approval" && !entry.resolved) {
          timeline[i] = {
            ...entry,
            resolved: true,
            approved: event.type === "APPROVAL_APPROVED",
            decision: event.payload.decision,
          }
          break
        }
      }
      break
    case "WARNING":
      timeline.push({ kind: "warning", message: event.payload.message })
      break
    case "THINKING":
      timeline.push({
        kind: "thinking",
        text: event.payload.text,
        stage: event.payload.stage,
        iteration: event.payload.iteration,
      })
      break
    case "RETROSPECTIVE":
      timeline.push({ kind: "retrospective", summary: event.payload.summary })
      break
    case "ERROR":
      timeline.push({ kind: "error", message: event.payload.message })
      break
    case "DEBUG":
      timeline.push({
        kind: "debug",
        message: event.payload.message,
        debugType: event.payload.type,
        details: event.payload.details,
      })
      break
  }
  return { ...state, timeline }
}
