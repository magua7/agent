import type { AgentEvent } from "../types/events"

export interface SseParserState {
  buffer: string
  lastEventId: string | null
  terminal: boolean
}

export function createSseParserState(lastEventId: string | null = null): SseParserState {
  return { buffer: "", lastEventId, terminal: false }
}

function isTerminalEvent(event: AgentEvent) {
  return event.type === "TASK_FINISHED"
    || event.type === "TASK_FAILED"
    || event.type === "TASK_CANCELLED"
    || event.type === "TASK_TIMED_OUT"
}

export function parseSseChunk(state: SseParserState, chunk: string) {
  const normalized = (state.buffer + chunk).replace(/\r\n/g, "\n")
  const frames = normalized.split("\n\n")
  const buffer = frames.pop() || ""
  const events: AgentEvent[] = []
  let lastEventId = state.lastEventId
  let terminal = state.terminal

  for (const frame of frames) {
    let frameId: string | null = null
    const dataLines: string[] = []
    for (const line of frame.split("\n")) {
      if (line.startsWith(":")) continue
      if (line.startsWith("id:")) frameId = line.slice(3).trim()
      if (line.startsWith("data:")) dataLines.push(line.slice(5).trimStart())
    }
    if (dataLines.length === 0) continue

    try {
      const event = JSON.parse(dataLines.join("\n")) as AgentEvent
      events.push(event)
      lastEventId = frameId || event.event_id || lastEventId
      terminal = terminal || isTerminalEvent(event)
    } catch {
      // Ignore malformed frames; a later valid frame can still advance the stream.
    }
  }

  return {
    state: { buffer, lastEventId, terminal },
    events,
  }
}

export function buildSseRequestHeaders(lastEventId: string | null): Record<string, string> {
  return lastEventId ? { "Last-Event-ID": lastEventId } : {}
}
