import { useCallback, useRef } from "react"

interface Props {
  currentWidth: number
  onResize: (newWidth: number) => void
  min?: number
  max?: number
  defaultWidth?: number
  /** 面板在把手右侧时传 true：拖向左 = 变宽，拖向右 = 变窄 */
  reverse?: boolean
}

export function ResizeHandle({ currentWidth, onResize, min = 200, max = 600, defaultWidth, reverse = false }: Props) {
  const startRef = useRef<{ x: number; width: number } | null>(null)

  const onPointerDown = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    e.preventDefault()
    const handle = e.currentTarget
    handle.setPointerCapture(e.pointerId)
    startRef.current = { x: e.clientX, width: currentWidth }
    document.body.style.userSelect = "none"
    document.body.style.cursor = "col-resize"
  }, [currentWidth])

  const onPointerMove = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    if (!startRef.current) return
    const delta = e.clientX - startRef.current.x
    const signed = reverse ? -delta : delta
    const next = Math.round(Math.min(max, Math.max(min, startRef.current.width + signed)))
    onResize(next)
  }, [max, min, onResize, reverse])

  const onPointerUp = useCallback((e: React.PointerEvent<HTMLDivElement>) => {
    if (startRef.current) {
      e.currentTarget.releasePointerCapture(e.pointerId)
      startRef.current = null
      document.body.style.userSelect = ""
      document.body.style.cursor = ""
    }
  }, [])

  const onDoubleClick = useCallback(() => {
    if (defaultWidth) onResize(defaultWidth)
  }, [defaultWidth, onResize])

  return (
    <div
      role="separator"
      aria-orientation="vertical"
      onPointerDown={onPointerDown}
      onPointerMove={onPointerMove}
      onPointerUp={onPointerUp}
      onDoubleClick={onDoubleClick}
      className="group relative z-10 hidden w-1.5 shrink-0 cursor-col-resize items-center justify-center bg-transparent transition-colors hover:bg-cyan-400/20 active:bg-cyan-400/30 xl:flex"
    >
      <span className="pointer-events-none h-12 w-[3px] rounded-full bg-slate-300/60 opacity-0 transition-opacity group-hover:opacity-100 dark:bg-slate-600/60" />
    </div>
  )
}