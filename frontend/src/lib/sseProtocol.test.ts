import assert from "node:assert/strict"
import test from "node:test"

import {
  buildSseRequestHeaders,
  createSseParserState,
  parseSseChunk,
} from "./sseProtocol.ts"

test("parses fragmented frames, tracks cursor, and ignores heartbeats", () => {
  let state = createSseParserState()
  const first = parseSseChunk(state, ": heartbeat\n\nid: evt-1\nevent: ANSWER_CH")
  state = first.state
  assert.deepEqual(first.events, [])

  const second = parseSseChunk(
    state,
    "UNK\ndata: {\"event_id\":\"evt-1\",\"task_id\":\"task-1\",\"time\":\"now\",\"type\":\"ANSWER_CHUNK\",\"payload\":{\"delta\":\"hi\"}}\n\n",
  )

  assert.equal(second.events.length, 1)
  assert.equal(second.events[0].type, "ANSWER_CHUNK")
  assert.equal(second.state.lastEventId, "evt-1")
  assert.equal(second.state.terminal, false)
})

test("marks terminal frames and builds the resume header", () => {
  const frame = "id: evt-final\nevent: TASK_FINISHED\ndata: {\"event_id\":\"evt-final\",\"task_id\":\"task-1\",\"time\":\"now\",\"type\":\"TASK_FINISHED\",\"payload\":{}}\n\n"
  const parsed = parseSseChunk(createSseParserState(), frame)

  assert.equal(parsed.state.terminal, true)
  assert.deepEqual(buildSseRequestHeaders(parsed.state.lastEventId), {
    "Last-Event-ID": "evt-final",
  })
  assert.deepEqual(buildSseRequestHeaders(null), {})
})

test("marks task timeout as a terminal frame", () => {
  const frame = "id: evt-timeout\nevent: TASK_TIMED_OUT\ndata: {\"event_id\":\"evt-timeout\",\"task_id\":\"task-1\",\"time\":\"now\",\"type\":\"TASK_TIMED_OUT\",\"payload\":{\"reason\":\"deadline\"}}\n\n"

  const parsed = parseSseChunk(createSseParserState(), frame)

  assert.equal(parsed.events[0].type, "TASK_TIMED_OUT")
  assert.equal(parsed.state.terminal, true)
})
