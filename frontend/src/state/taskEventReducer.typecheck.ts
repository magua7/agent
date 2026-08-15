import type { AgentEvent } from "../types/events"
import { initialTaskEventState, reduceTaskEvent } from "./taskEventReducer"

const chunkEvent = {
  event_id: "event-1",
  task_id: "task-1",
  time: new Date(0).toISOString(),
  type: "ANSWER_CHUNK",
  payload: { delta: "hello", source: "agent" },
} as AgentEvent

const next = reduceTaskEvent(initialTaskEventState, chunkEvent)
const answerDraft: string = next.answerDraft

void answerDraft
