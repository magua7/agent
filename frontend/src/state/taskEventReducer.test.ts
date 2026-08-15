import assert from "node:assert/strict"
import test from "node:test"

import type { AgentEvent } from "../types/events.ts"
import { initialTaskEventState, reduceTaskEvent } from "./taskEventReducer.ts"

function event(type: AgentEvent["type"], payload: Record<string, unknown>): AgentEvent {
  return {
    event_id: `event-${type}`,
    task_id: "task-1",
    time: "now",
    type,
    payload,
  } as AgentEvent
}

test("accumulates answer chunks in arrival order", () => {
  const first = reduceTaskEvent(
    initialTaskEventState,
    event("ANSWER_CHUNK", { delta: "hello " }),
  )
  const second = reduceTaskEvent(
    first,
    event("ANSWER_CHUNK", { delta: "world" }),
  )

  assert.equal(second.answerDraft, "hello world")
})

test("keeps the draft through the terminal event until final report reconciliation", () => {
  const streaming = reduceTaskEvent(
    initialTaskEventState,
    event("ANSWER_CHUNK", { delta: "partial answer" }),
  )
  const terminal = reduceTaskEvent(
    streaming,
    event("TASK_FINISHED", { report: "final answer" }),
  )

  assert.equal(terminal.answerDraft, "partial answer")
})

test("keeps the draft when the task times out", () => {
  const streaming = reduceTaskEvent(
    initialTaskEventState,
    event("ANSWER_CHUNK", { delta: "partial answer" }),
  )

  const terminal = reduceTaskEvent(
    streaming,
    event("TASK_TIMED_OUT", { reason: "deadline" }),
  )

  assert.equal(terminal.answerDraft, "partial answer")
})
