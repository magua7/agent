import { asObject } from "./model.ts"
import type { JsonObject, TaskEvent } from "./types.ts"

export interface SseParserState {
  buffer: string
  lastEventId: string | null
}

export interface SseParseResult {
  state: SseParserState
  events: TaskEvent[]
}

export function createSseState(lastEventId: string | null = null): SseParserState {
  return { buffer: "", lastEventId }
}

function normalizeEvent(value: unknown, frameId: string | null): TaskEvent | null {
  const event = asObject(value)
  const type = typeof event.type === "string" ? event.type.toLowerCase() : ""
  if (!type) return null
  const sequence = typeof event.sequence === "number" && Number.isFinite(event.sequence) ? event.sequence : 0
  const eventId = typeof event.event_id === "string" && event.event_id
    ? event.event_id
    : frameId || (sequence ? String(sequence) : "")
  return {
    event_id: eventId,
    sequence,
    task_id: typeof event.task_id === "string" ? event.task_id : "",
    run_id: typeof event.run_id === "string" ? event.run_id : "",
    type,
    timestamp: typeof event.timestamp === "string" ? event.timestamp : new Date().toISOString(),
    payload: asObject(event.payload) as JsonObject,
  }
}

export function parseSseChunk(state: SseParserState, chunk: string): SseParseResult {
  const normalized = (state.buffer + chunk).replace(/\r\n/g, "\n").replace(/\r/g, "\n")
  const frames = normalized.split("\n\n")
  const buffer = frames.pop() || ""
  const events: TaskEvent[] = []
  let lastEventId = state.lastEventId

  for (const frame of frames) {
    let frameId: string | null = null
    const dataLines: string[] = []
    for (const line of frame.split("\n")) {
      if (!line || line.startsWith(":")) continue
      const separator = line.indexOf(":")
      const field = separator >= 0 ? line.slice(0, separator) : line
      const rawValue = separator >= 0 ? line.slice(separator + 1) : ""
      const fieldValue = rawValue.startsWith(" ") ? rawValue.slice(1) : rawValue
      if (field === "id") frameId = fieldValue
      if (field === "data") dataLines.push(fieldValue)
    }
    if (dataLines.length === 0) continue
    try {
      const event = normalizeEvent(JSON.parse(dataLines.join("\n")), frameId)
      if (!event) continue
      events.push(event)
      lastEventId = frameId || event.event_id || (event.sequence ? String(event.sequence) : lastEventId)
    } catch {
      // A malformed frame is isolated; later valid frames remain consumable.
    }
  }

  return { state: { buffer, lastEventId }, events }
}

