SELECT
    case_id,
    customer_id,
    full_name,
    priority,
    jsonb_array_length(charges) AS charge_count
FROM support.case_triage_context
ORDER BY case_id;

SELECT
    customer_id,
    order_id,
    amount_cents,
    currency,
    successful_charge_count,
    charge_ids
FROM billing.duplicate_charge_candidates
ORDER BY order_id;

SELECT
    policy_id,
    requires_human_approval,
    rollback_supported,
    active
FROM policy.refund_policies
ORDER BY policy_id;
