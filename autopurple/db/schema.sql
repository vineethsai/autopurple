-- AutoPurple Database Schema
-- Compatible with Pacu's existing session schema
-- Do not modify Pacu tables; only add AutoPurple-specific tables

PRAGMA foreign_keys = ON;

-- AutoPurple runs table - tracks pipeline execution
CREATE TABLE IF NOT EXISTS ap_runs (
    id TEXT PRIMARY KEY,                 -- ULID/UUID
    started_at TIMESTAMP NOT NULL,
    ended_at TIMESTAMP,
    aws_account TEXT,
    aws_region TEXT,
    status TEXT CHECK(status IN ('started','validated','remediated','failed')) NOT NULL,
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- AutoPurple findings table - normalized findings from ScoutSuite
CREATE TABLE IF NOT EXISTS ap_findings (
    id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL REFERENCES ap_runs(id) ON DELETE CASCADE,
    source TEXT CHECK(source IN ('scoutsuite')) NOT NULL,
    service TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT CHECK(severity IN ('low','medium','high','critical')) NOT NULL,
    evidence JSON NOT NULL,              -- raw ScoutSuite snippet + links
    status TEXT CHECK(status IN ('new','validated','dismissed','remediated')) NOT NULL DEFAULT 'new',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- AutoPurple validations table - Pacu validation results
CREATE TABLE IF NOT EXISTS ap_validations (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES ap_findings(id) ON DELETE CASCADE,
    tool TEXT CHECK(tool IN ('pacu')) NOT NULL,
    module TEXT NOT NULL,                -- Pacu module used
    executed_at TIMESTAMP NOT NULL,
    result TEXT CHECK(result IN ('exploitable','not_exploitable','error')) NOT NULL,
    evidence JSON NOT NULL,              -- Pacu output excerpt / artifact refs
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- AutoPurple remediations table - MCP remediation actions
CREATE TABLE IF NOT EXISTS ap_remediations (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL REFERENCES ap_findings(id) ON DELETE CASCADE,
    planned_change JSON NOT NULL,        -- Claude plan (human-readable + machine)
    mcp_server TEXT NOT NULL,            -- ccapi | cfn
    mcp_call JSON NOT NULL,              -- exact payload sent to MCP
    executed_at TIMESTAMP,
    status TEXT CHECK(status IN ('planned','executed','rolled_back','failed')) NOT NULL,
    audit_ref TEXT,                      -- ARN/stack-id/tx-id
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- AutoPurple audit trail table - detailed action logging
CREATE TABLE IF NOT EXISTS ap_audit_trail (
    id TEXT PRIMARY KEY,
    run_id TEXT REFERENCES ap_runs(id) ON DELETE CASCADE,
    finding_id TEXT REFERENCES ap_findings(id) ON DELETE CASCADE,
    action TEXT NOT NULL,
    actor TEXT NOT NULL,
    resource TEXT NOT NULL,
    details JSON,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_ap_findings_run_id ON ap_findings(run_id);
CREATE INDEX IF NOT EXISTS idx_ap_findings_service ON ap_findings(service);
CREATE INDEX IF NOT EXISTS idx_ap_findings_severity ON ap_findings(severity);
CREATE INDEX IF NOT EXISTS idx_ap_findings_status ON ap_findings(status);
CREATE INDEX IF NOT EXISTS idx_ap_validations_finding_id ON ap_validations(finding_id);
CREATE INDEX IF NOT EXISTS idx_ap_remediations_finding_id ON ap_remediations(finding_id);
CREATE INDEX IF NOT EXISTS idx_ap_audit_trail_run_id ON ap_audit_trail(run_id);
CREATE INDEX IF NOT EXISTS idx_ap_audit_trail_timestamp ON ap_audit_trail(timestamp);

-- Triggers for updated_at timestamps
CREATE TRIGGER IF NOT EXISTS update_ap_runs_updated_at 
    AFTER UPDATE ON ap_runs
    BEGIN
        UPDATE ap_runs SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER IF NOT EXISTS update_ap_findings_updated_at 
    AFTER UPDATE ON ap_findings
    BEGIN
        UPDATE ap_findings SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

CREATE TRIGGER IF NOT EXISTS update_ap_remediations_updated_at 
    AFTER UPDATE ON ap_remediations
    BEGIN
        UPDATE ap_remediations SET updated_at = CURRENT_TIMESTAMP WHERE id = NEW.id;
    END;

