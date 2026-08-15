import type { KnowledgeDetails, TimelineEntry } from "../types/events"

type DetailedTimelineEntry = TimelineEntry & { details: Record<string, any> }
type KnowledgeTimelineEntry = TimelineEntry & { details: KnowledgeDetails }

export function isIntentEntry(entry: TimelineEntry): entry is DetailedTimelineEntry {
  return entry.kind === "debug" && entry.debugType === "intent" && Boolean(entry.details)
}

export function isPlanEntry(entry: TimelineEntry): entry is DetailedTimelineEntry {
  return entry.kind === "debug" && entry.debugType === "plan" && Boolean(entry.details)
}

export function isComplexityEntry(entry: TimelineEntry): entry is DetailedTimelineEntry {
  return entry.kind === "debug" && entry.debugType === "complexity" && Boolean(entry.details)
}

export function isKnowledgeEntry(entry: TimelineEntry): entry is KnowledgeTimelineEntry {
  return entry.kind === "debug" && entry.debugType === "knowledge" && Boolean(entry.details)
}

export function isThinkingEntry(entry: TimelineEntry): boolean {
  return entry.kind === "thinking" && Boolean(entry.text)
}

export function isRetrospectiveEntry(entry: TimelineEntry): boolean {
  return entry.kind === "retrospective" && Boolean(entry.summary)
}

export function selectTimelineEntries(timeline: TimelineEntry[]): TimelineEntry[] {
  return timeline.filter((entry) => {
    if (entry.kind !== "debug") return true
    return isIntentEntry(entry)
      || isPlanEntry(entry)
      || isComplexityEntry(entry)
      || isKnowledgeEntry(entry)
  })
}

export function getTimelineSummary(timeline: TimelineEntry[]) {
  const selected = selectTimelineEntries(timeline)
  return {
    phaseCount: selected.filter(entry => entry.kind === "phase").length,
    toolCount: selected.filter(entry => entry.kind === "tool").length,
    warningCount: selected.filter(entry => entry.kind === "warning").length,
    errorCount: selected.filter(entry => entry.kind === "error").length,
    complexityCount: selected.filter(entry => isComplexityEntry(entry)).length,
    knowledgeCount: selected.filter(entry => isKnowledgeEntry(entry)).length,
    thinkingCount: selected.filter(entry => entry.kind === "thinking").length,
    retrospectiveCount: selected.filter(entry => entry.kind === "retrospective").length,
  }
}
