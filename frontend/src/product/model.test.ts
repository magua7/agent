import assert from "node:assert/strict"
import test from "node:test"

import { isLoopbackTarget, normalizeTaskDetail, parsePorts, statusFromEvent } from "./model.ts"

test("accepts only explicit loopback targets", () => {
  assert.equal(isLoopbackTarget("localhost"), true)
  assert.equal(isLoopbackTarget("127.0.0.42"), true)
  assert.equal(isLoopbackTarget("[::1]"), true)
  assert.equal(isLoopbackTarget("192.168.1.1"), false)
  assert.equal(isLoopbackTarget("example.com"), false)
  assert.equal(isLoopbackTarget("127.0.0.999"), false)
})

test("normalizes and bounds the explicit port list", () => {
  assert.deepEqual(parsePorts("443, 80,443,8080"), [80, 443, 8080])
  assert.throws(() => parsePorts(""), /至少填写一个端口/)
  assert.throws(() => parsePorts("0"), /超出范围/)
  assert.throws(() => parsePorts("80-90"), /格式无效/)
  assert.throws(() => parsePorts(Array.from({ length: 129 }, (_, index) => index + 1).join(",")), /最多检查 128/)
})

test("normalizes the frozen SEC-GO task detail contract", () => {
  const detail = normalizeTaskDetail({
    id: "task-1",
    task_id: "task-1",
    title: "Loopback scan",
    description: "Inspect explicit ports",
    status: "completed",
    created_at: "2026-08-15T10:00:00Z",
    updated_at: "2026-08-15T10:00:02Z",
    run_id: "run-1",
    task_spec: {
      objective: "Inspect loopback",
      task_type: "pentest",
      scope: { network_targets: ["127.0.0.1"], file_roots: [] },
      constraints: ["loopback only"],
      inputs: { target: "127.0.0.1", ports: [80, 443] },
      success_criteria: ["real scan evidence exists"],
    },
    plan: {
      id: "plan-1",
      version: 2,
      status: "completed",
      nodes: [{
        id: "node-1",
        goal: "Scan",
        description: "Probe explicit ports",
        status: "succeeded",
        dependencies: [],
        required_capabilities: ["network.scan"],
        evidence_ids: ["ev-1"],
        finding_ids: ["finding-1"],
      }],
    },
    evidence: [{ id: "ev-1", type: "network_scan", source: "network_scan", summary: "port 80 open", content_hash: "abc", created_at: "2026-08-15T10:00:01Z", metadata: {} }],
    findings: [{ id: "finding-1", title: "Open port", severity: "informational", description: "TCP 80", confidence: 1, status: "verified", evidence_ids: ["ev-1"], created_at: "2026-08-15T10:00:01Z" }],
    verification: { success: true, reason: "evidence present", evidence_ids: ["ev-1"], missing_requirements: [], conflicts: [] },
    report: "# Result",
    stats: { step_count: 1, evidence_count: 1, finding_count: 1, replan_count: 0, elapsed_sec: 2 },
  })

  assert.equal(detail.task.id, "task-1")
  assert.equal(detail.task.target, "127.0.0.1")
  assert.deepEqual(detail.task.ports, [80, 443])
  assert.equal(detail.run?.id, "run-1")
  assert.equal(detail.plan?.nodes[0].requiredCapabilities[0], "network.scan")
  assert.equal(detail.evidence[0].contentHash, "abc")
  assert.equal(detail.findings[0].evidenceIds[0], "ev-1")
  assert.equal(detail.verification?.success, true)
  assert.equal(detail.stats.elapsedMs, 2_000)
})

test("maps terminal and verification event statuses", () => {
  assert.equal(statusFromEvent("task_started"), "running")
  assert.equal(statusFromEvent("verification_started"), "verifying")
  assert.equal(statusFromEvent("task_completed"), "completed")
  assert.equal(statusFromEvent("task_timed_out"), "timed_out")
})
