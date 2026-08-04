-- Deterministic enterprise systems of record used by AIP end-to-end tests.
-- Each domain has independent state, immutable audit records, and explicit
-- plan/commit/compensate transitions. The fixtures are local production-like
-- systems of record; agents never receive these facts through prompts.

CREATE SCHEMA IF NOT EXISTS enterprise;

CREATE TABLE IF NOT EXISTS enterprise.workflows (
    workflow_id text PRIMARY KEY,
    domain text NOT NULL CHECK (domain IN ('incident', 'procurement', 'access', 'travel')),
    tenant_id text NOT NULL,
    state text NOT NULL,
    version bigint NOT NULL DEFAULT 1,
    facts jsonb NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE TABLE IF NOT EXISTS enterprise.plans (
    plan_id text PRIMARY KEY,
    workflow_id text NOT NULL REFERENCES enterprise.workflows(workflow_id),
    capability_id text NOT NULL,
    idempotency_key text NOT NULL,
    input_hash text NOT NULL,
    status text NOT NULL CHECK (status IN ('planned', 'committed', 'failed', 'compensated')),
    plan jsonb NOT NULL,
    commit_result jsonb,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    UNIQUE (capability_id, idempotency_key)
);

CREATE TABLE IF NOT EXISTS enterprise.audit_events (
    event_id bigserial PRIMARY KEY,
    workflow_id text NOT NULL,
    plan_id text,
    event_type text NOT NULL,
    actor_principal text NOT NULL,
    tenant_id text NOT NULL,
    payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS enterprise_audit_workflow_idx
    ON enterprise.audit_events(workflow_id, event_id);

INSERT INTO enterprise.workflows (workflow_id, domain, tenant_id, state, facts)
VALUES
    (
        'inc_5001', 'incident', 'tenant-acme', 'open',
        '{"service":"checkout-api","severity":"sev1","error_rate":0.37,"baseline_error_rate":0.004,"deploy_id":"deploy-2026-07-10-42","previous_deploy_id":"deploy-2026-07-10-41","mitigation":"rollback","customer_impact":"checkout failures"}'::jsonb
    ),
    (
        'pr_7001', 'procurement', 'tenant-acme', 'requested',
        '{"requester":"human:engineering-director","vendor_id":"vendor-observability-1","vendor_status":"approved","amount_cents":4800000,"currency":"USD","budget_available_cents":6500000,"cost_center":"engineering-platform","required_approvals":["finance","procurement"]}'::jsonb
    ),
    (
        'ar_9001', 'access', 'tenant-acme', 'requested',
        '{"subject":"human:oncall-engineer","resource":"production-payments","role":"break_glass_operator","risk":"critical","max_ttl_seconds":900,"required_approver_role":"security-duty-manager"}'::jsonb
    ),
    (
        'trip_8001', 'travel', 'tenant-acme', 'disrupted',
        '{"traveler":"human:ava-stone","original_booking":"DXB-LHR-20260711-EK001","disruption":"cancelled","options":[{"option_id":"opt_1","flight":"EK003","price_delta_cents":22000,"currency":"USD"},{"option_id":"opt_2","flight":"BA106","price_delta_cents":41000,"currency":"USD"}],"selected_option":null,"reservation_id":null}'::jsonb
    )
ON CONFLICT (workflow_id) DO NOTHING;

INSERT INTO enterprise.audit_events (
    workflow_id, event_type, actor_principal, tenant_id, payload, created_at
)
SELECT workflow_id, 'fixture.seeded', 'system:enterprise-sandbox', tenant_id,
       jsonb_build_object('domain', domain), '2026-07-10T00:00:00Z'
FROM enterprise.workflows w
WHERE NOT EXISTS (
    SELECT 1 FROM enterprise.audit_events a
    WHERE a.workflow_id = w.workflow_id AND a.event_type = 'fixture.seeded'
);
