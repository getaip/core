-- Reset the deterministic duplicate-charge scenario without dropping the
-- database volume. This is test-fixture setup only; the business flow under
-- test must still use AIP capabilities instead of direct SQL.

BEGIN;

DELETE FROM billing.refunds
WHERE case_id = 'case_1001';

DELETE FROM approval.approval_requests
WHERE case_id = 'case_1001';

DELETE FROM audit.events
WHERE subject_ref IN (
    'case:case_1001',
    'refund:rf:refund:case_1001:ch_1001_b:e2e',
    'approval:appr:refund:case_1001:ch_1001_b:e2e'
)
AND event_type <> 'support_sandbox.seeded';

UPDATE billing.charges
SET status = 'succeeded'
WHERE charge_id IN ('ch_1001_a', 'ch_1001_b');

UPDATE billing.orders
SET status = 'fulfilled'
WHERE order_id = 'ord_1001';

UPDATE support.cases
SET
    status = 'open',
    priority = 'urgent',
    updated_at = '2026-07-09T09:12:00Z'
WHERE case_id = 'case_1001';

COMMIT;
