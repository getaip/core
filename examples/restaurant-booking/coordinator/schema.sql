CREATE SCHEMA IF NOT EXISTS restaurant_booking;

CREATE TABLE IF NOT EXISTS restaurant_booking.workflows (
    request_id UUID PRIMARY KEY,
    state TEXT NOT NULL CHECK (state IN (
        'collecting',
        'manager_checked',
        'planned',
        'approval_pending',
        'supervisor_checked',
        'approved',
        'committed',
        'completed'
    )),
    request JSONB NOT NULL DEFAULT '{}'::jsonb,
    manager_result JSONB,
    manager_delegation_id TEXT,
    plan_result JSONB,
    plan_id TEXT,
    commit_action_id TEXT,
    approval_id TEXT,
    supervisor_result JSONB,
    supervisor_delegation_id TEXT,
    approval_record JSONB,
    commit_result JSONB,
    booking_uid TEXT,
    booking_seat_uid TEXT,
    booking_snapshot JSONB,
    last_error JSONB,
    lease_owner UUID,
    lease_expires_at TIMESTAMPTZ,
    fencing_token BIGINT NOT NULL DEFAULT 0,
    version BIGINT NOT NULL DEFAULT 1,
    created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp()
);

CREATE INDEX IF NOT EXISTS workflows_state_updated_idx
    ON restaurant_booking.workflows (state, updated_at);

ALTER TABLE restaurant_booking.workflows
    ADD COLUMN IF NOT EXISTS booking_seat_uid TEXT;

DROP INDEX IF EXISTS restaurant_booking.workflows_booking_uid_idx;

CREATE UNIQUE INDEX IF NOT EXISTS workflows_booking_seat_uid_idx
    ON restaurant_booking.workflows (booking_seat_uid)
    WHERE booking_seat_uid IS NOT NULL;

REVOKE ALL ON SCHEMA restaurant_booking FROM PUBLIC;
REVOKE ALL ON ALL TABLES IN SCHEMA restaurant_booking FROM PUBLIC;
