BEGIN;
DELETE FROM enterprise.audit_events WHERE event_type <> 'fixture.seeded';
DELETE FROM enterprise.plans;
UPDATE enterprise.workflows
SET state = CASE domain
        WHEN 'incident' THEN 'open'
        WHEN 'procurement' THEN 'requested'
        WHEN 'access' THEN 'requested'
        WHEN 'travel' THEN 'disrupted'
    END,
    version = version + 1,
    facts = CASE domain
        WHEN 'incident' THEN facts - 'rollback_deploy_id' - 'resolved_at'
        WHEN 'procurement' THEN jsonb_set(
            facts - 'purchase_order_id' - 'reserved_cents',
            '{budget_available_cents}',
            '6500000'::jsonb
        )
        WHEN 'access' THEN facts - 'grant_id' - 'granted_until'
        WHEN 'travel' THEN jsonb_set(jsonb_set(facts, '{selected_option}', 'null'), '{reservation_id}', 'null')
    END,
    updated_at = clock_timestamp();
COMMIT;
