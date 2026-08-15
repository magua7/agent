import assert from "node:assert/strict"
import test from "node:test"

import { createSseState, parseSseChunk } from "./sseParser.ts"

test("parses fragmented SEC-GO SSE and keeps the numeric replay cursor", () => {
  const first = parseSseChunk(createSseState(), ": keep-alive\n\nid: 7\nevent: evidence_cre")
  assert.equal(first.events.length, 0)

  const second = parseSseChunk(first.state, "ated\ndata: {\"event_id\":\"event-uuid\",\"sequence\":7,\"task_id\":\"task-1\",\"run_id\":\"run-1\",\"type\":\"evidence_created\",\"timestamp\":\"2026-08-15T10:00:00Z\",\"payload\":{\"summary\":\"real output\"}}\n\n")
  assert.equal(second.events.length, 1)
  assert.equal(second.events[0].type, "evidence_created")
  assert.equal(second.events[0].sequence, 7)
  assert.equal(second.events[0].payload.summary, "real output")
  assert.equal(second.state.lastEventId, "7")
})

test("isolates malformed frames and continues parsing valid events", () => {
  const chunk = [
    "id: 8\ndata: {bad json}\n\n",
    "id: 9\ndata: {\"event_id\":\"e9\",\"sequence\":9,\"task_id\":\"task-1\",\"run_id\":\"run-1\",\"type\":\"verification_passed\",\"timestamp\":\"now\",\"payload\":{\"success\":true}}\n\n",
  ].join("")
  const parsed = parseSseChunk(createSseState(), chunk)
  assert.equal(parsed.events.length, 1)
  assert.equal(parsed.events[0].sequence, 9)
  assert.equal(parsed.state.lastEventId, "9")
})
