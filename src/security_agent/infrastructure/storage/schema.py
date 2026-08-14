"""SQLite schema for durable run and evidence state."""

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    task_id TEXT NOT NULL,
    task_json TEXT NOT NULL,
    plan_id TEXT,
    plan_version INTEGER,
    status TEXT NOT NULL,
    current_nodes_json TEXT NOT NULL,
    started_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    finished_at TEXT,
    step_count INTEGER NOT NULL CHECK (step_count >= 0),
    replan_count INTEGER NOT NULL CHECK (replan_count >= 0),
    last_error TEXT,
    CHECK ((plan_id IS NULL) = (plan_version IS NULL)),
    CHECK (plan_version IS NULL OR plan_version > 0)
);

CREATE TABLE IF NOT EXISTS plans (
    plan_id TEXT NOT NULL,
    version INTEGER NOT NULL CHECK (version > 0),
    run_id TEXT NOT NULL,
    task_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (plan_id, version),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS plan_nodes (
    plan_id TEXT NOT NULL,
    plan_version INTEGER NOT NULL,
    position INTEGER NOT NULL CHECK (position >= 0),
    node_id TEXT NOT NULL,
    goal TEXT NOT NULL,
    description TEXT NOT NULL,
    status TEXT NOT NULL,
    assigned_agent TEXT NOT NULL,
    required_capabilities_json TEXT NOT NULL,
    dependencies_json TEXT NOT NULL,
    success_criteria_json TEXT NOT NULL,
    attempt_count INTEGER NOT NULL CHECK (attempt_count >= 0),
    max_attempts INTEGER NOT NULL CHECK (max_attempts > 0),
    evidence_ids_json TEXT NOT NULL,
    finding_ids_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (plan_id, plan_version, node_id),
    UNIQUE (plan_id, plan_version, position),
    FOREIGN KEY (plan_id, plan_version)
        REFERENCES plans(plan_id, version) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    plan_node_id TEXT NOT NULL,
    agent_id TEXT NOT NULL,
    tool_name TEXT NOT NULL,
    arguments_json TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    duration_ms INTEGER CHECK (duration_ms IS NULL OR duration_ms >= 0),
    success INTEGER CHECK (success IS NULL OR success IN (0, 1)),
    exit_code INTEGER,
    error TEXT,
    evidence_ids_json TEXT NOT NULL,
    UNIQUE (id, run_id),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    action_id TEXT,
    type TEXT NOT NULL,
    source TEXT NOT NULL,
    summary TEXT NOT NULL,
    raw_content TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    created_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    UNIQUE (id, run_id),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE RESTRICT,
    FOREIGN KEY (action_id, run_id)
        REFERENCES actions(id, run_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence REAL NOT NULL CHECK (confidence >= 0.0 AND confidence <= 1.0),
    evidence_ids_json TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    subject TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    UNIQUE (id, run_id),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS events (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS idx_plans_run ON plans(run_id, version);
CREATE INDEX IF NOT EXISTS idx_actions_run ON actions(run_id, started_at);
CREATE INDEX IF NOT EXISTS idx_actions_run_node
    ON actions(run_id, plan_node_id, started_at);
CREATE INDEX IF NOT EXISTS idx_evidence_run ON evidence(run_id, created_at);
CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id, created_at);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, created_at);
"""
