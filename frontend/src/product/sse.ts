import { ApiError, apiUrl } from "./api"
import { isTerminalStatus, statusFromEvent } from "./model"
import { createSseState, parseSseChunk } from "./sseParser"
import type { TaskEvent } from "./types"

export { createSseState, parseSseChunk } from "./sseParser"
export type { SseParserState, SseParseResult } from "./sseParser"

export interface ConsumeEventsOptions {
  taskId: string
  token: string
  lastEventId: string | null
  signal: AbortSignal
  onEvent: (event: TaskEvent) => void
  onUnauthorized: () => void
}

export interface ConsumeEventsResult {
  lastEventId: string | null
  terminal: boolean
}

export async function consumeTaskEvents(options: ConsumeEventsOptions): Promise<ConsumeEventsResult> {
  const headers = new Headers({
    Accept: "text/event-stream",
    Authorization: `Bearer ${options.token}`,
    "Cache-Control": "no-cache",
  })
  if (options.lastEventId) headers.set("Last-Event-ID", options.lastEventId)

  const response = await fetch(apiUrl(`/api/tasks/${encodeURIComponent(options.taskId)}/events`), {
    headers,
    signal: options.signal,
  })
  if (response.status === 401) options.onUnauthorized()
  if (!response.ok || !response.body) throw new ApiError(`事件流连接失败（HTTP ${response.status}）`, response.status)

  const reader = response.body.getReader()
  const decoder = new TextDecoder()
  let state = createSseState(options.lastEventId)
  let terminal = false

  while (!options.signal.aborted) {
    const { done, value } = await reader.read()
    if (done) break
    const parsed = parseSseChunk(state, decoder.decode(value, { stream: true }))
    state = parsed.state
    for (const event of parsed.events) {
      options.onEvent(event)
      const status = statusFromEvent(event.type)
      terminal = terminal || Boolean(status && isTerminalStatus(status))
    }
    if (terminal) {
      await reader.cancel()
      break
    }
  }
  return { lastEventId: state.lastEventId, terminal }
}
