import type {
  TimelineEntry,
  ToolFinishedPayload,
  ToolStartedPayload,
} from "./events"

const started = {} as ToolStartedPayload
const finished = {} as ToolFinishedPayload
const timeline = {} as TimelineEntry

void started.canonical_tool
void started.tool_source
void started.snapshot_version
void finished.result_id
void finished.evidence_id
void timeline.callId
void timeline.canonicalTool
void timeline.toolSourceId
void timeline.snapshotVersion
