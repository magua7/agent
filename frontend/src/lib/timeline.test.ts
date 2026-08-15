import assert from "node:assert/strict"
import test from "node:test"

import type { TimelineEntry } from "../types/events.ts"
import { getTimelineSummary, selectTimelineEntries } from "./timeline.ts"

test("selects the same supported timeline entries for every execution view", () => {
  const timeline: TimelineEntry[] = [
    { kind: "phase", phase: "plan", status: "done" },
    { kind: "debug", debugType: "intent", details: { target: "example.test" } },
    { kind: "debug", debugType: "internal-noise", details: { raw: true } },
    { kind: "approval", resolved: false },
    { kind: "thinking", text: "inspect evidence" },
  ]

  const selected = selectTimelineEntries(timeline)

  assert.deepEqual(selected, [timeline[0], timeline[1], timeline[3], timeline[4]])
  assert.equal(selected[2].kind, "approval")
})

test("summaries count only entries selected for display", () => {
  const timeline: TimelineEntry[] = [
    { kind: "tool", tool: "curl", status: "success" },
    { kind: "debug", debugType: "knowledge", details: { hits: 2 } },
    { kind: "debug", debugType: "internal-noise", details: {} },
  ]

  const summary = getTimelineSummary(timeline)

  assert.equal(summary.toolCount, 1)
  assert.equal(summary.knowledgeCount, 1)
})
