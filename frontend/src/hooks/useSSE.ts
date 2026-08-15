import { useEffect, useRef, useCallback } from "react"
import type { AgentEvent } from "../types/events"
import { getTaskStreamUrl } from "../api/stream"
import { buildSseRequestHeaders, createSseParserState, parseSseChunk } from "../lib/sseProtocol"

interface UseSSEOptions {
  taskId: string | null
  onEvent: (event: AgentEvent) => void
  onError?: (error: string) => void
}

const MAX_BACKOFF = 16000   // 16s max
const BASE_DELAY = 1000     // start at 1s

export function useSSE({ taskId, onEvent, onError }: UseSSEOptions) {
  const abortRef = useRef<AbortController | null>(null)
  const doneRef = useRef(false)                    // task completed, stop reconnecting
  const retryRef = useRef(0)
  const onEventRef = useRef(onEvent)
  onEventRef.current = onEvent
  // Track task completion via ref so disconnect doesn't trigger reconnect
  const taskDoneRef = useRef(false)

  const disconnect = useCallback(() => {
    taskDoneRef.current = true
    if (abortRef.current) {
      abortRef.current.abort()
      abortRef.current = null
    }
  }, [])

  useEffect(() => {
    if (!taskId) return

    // Reset for new task
    disconnect()
    doneRef.current = false
    taskDoneRef.current = false
    retryRef.current = 0

    const controller = new AbortController()
    abortRef.current = controller
    let parserState = createSseParserState()

    async function connect() {
      const url = getTaskStreamUrl(taskId!)

      while (!taskDoneRef.current && !controller.signal.aborted) {
        try {
          const resp = await fetch(url, {
            signal: controller.signal,
            headers: buildSseRequestHeaders(parserState.lastEventId),
          })

          if (!resp.ok || !resp.body) {
            // 404/409 — task doesn't exist or already done, stop reconnecting
            if (resp.status === 404 || resp.status === 409) {
              onError?.(`SSE 连接失败: ${resp.status}`)
              return
            }
            throw new Error(`HTTP ${resp.status}`)
          }

          // Connection succeeded — reset backoff
          retryRef.current = 0

          const reader = resp.body.getReader()
          const decoder = new TextDecoder()

          while (true) {
            const { done, value } = await reader.read()

            if (done) {
              // Stream ended cleanly (server closed) — likely task complete
              // Don't reconnect if we've received TASK_FINISHED/TASK_FAILED
              if (doneRef.current) return
              break  // break inner loop → retry
            }

            const parsed = parseSseChunk(
              parserState,
              decoder.decode(value, { stream: true }),
            )
            parserState = parsed.state
            doneRef.current = parserState.terminal
            for (const event of parsed.events) {
              onEventRef.current(event)
            }

            if (doneRef.current) {
              reader.cancel()
              return  // task done, no retry
            }
          }
        } catch (err: any) {
          if (err.name === "AbortError") return
          if (taskDoneRef.current || doneRef.current) return
        }

        // — Exponential backoff before retry —
        if (taskDoneRef.current || doneRef.current || controller.signal.aborted) return

        const delay = Math.min(BASE_DELAY * Math.pow(2, retryRef.current), MAX_BACKOFF)
        retryRef.current = Math.min(retryRef.current + 1, 10)

        onError?.(`连接断开，${(delay / 1000).toFixed(0)}s 后重连...`)

        // Wait with abort-awareness
        await new Promise<void>((resolve) => {
          const t = setTimeout(resolve, delay)
          const onAbort = () => { clearTimeout(t); resolve() }
          controller.signal.addEventListener("abort", onAbort, { once: true })
        })
      }
    }

    connect()

    return () => disconnect()
  }, [taskId])

  return { disconnect }
}
