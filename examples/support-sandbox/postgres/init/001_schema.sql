-- AIP Support Sandbox
--
-- This database is a deterministic system of record for end-to-end
-- customer-support scenarios. It intentionally models real enterprise
-- boundaries: support cases, customer identity, billing facts, refund policy,
-- approval state, idempotent financial mutations, and audit evidence.

CREATE SCHEMA IF NOT EXISTS support;
CREATE SCHEMA IF NOT EXISTS billing;
CREATE SCHEMA IF NOT EXISTS policy;
CREATE SCHEMA IF NOT EXISTS approval;
CREATE SCHEMA IF NOT EXISTS audit;

CREATE TABLE support.customers (
    customer_id TEXT PRIMARY KEY,
    external_ref TEXT NOT NULL UNIQUE,
    email TEXT NOT NULL UNIQUE,
    full_name TEXT NOT NULL,
    locale TEXT NOT NULL DEFAULT 'en-US',
    risk_tier TEXT NOT NULL DEFAULT 'standard',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (customer_id <> ''),
    CHECK (email <> '')
);

CREATE TABLE support.cases (
    case_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES support.customers(customer_id),
    channel TEXT NOT NULL,
    external_conversation_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    priority TEXT NOT NULL DEFAULT 'normal',
    subject TEXT NOT NULL,
    opened_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    CHECK (status IN ('open', 'pending_approval', 'resolved', 'closed')),
    CHECK (priority IN ('low', 'normal', 'high', 'urgent'))
);

CREATE TABLE support.messages (
    message_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES support.cases(case_id),
    direction TEXT NOT NULL,
    sender_role TEXT NOT NULL,
    body TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    CHECK (direction IN ('inbound', 'outbound', 'internal')),
    CHECK (sender_role IN ('customer', 'agent', 'system'))
);

CREATE TABLE billing.orders (
    order_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES support.customers(customer_id),
    external_ref TEXT NOT NULL UNIQUE,
    total_amount_cents INTEGER NOT NULL,
    currency CHAR(3) NOT NULL,
    status TEXT NOT NULL,
    placed_at TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    CHECK (total_amount_cents > 0),
    CHECK (currency = upper(currency)),
    CHECK (status IN ('placed', 'fulfilled', 'cancelled', 'refunded'))
);

CREATE TABLE billing.charges (
    charge_id TEXT PRIMARY KEY,
    customer_id TEXT NOT NULL REFERENCES support.customers(customer_id),
    order_id TEXT NOT NULL REFERENCES billing.orders(order_id),
    provider TEXT NOT NULL,
    provider_charge_id TEXT NOT NULL UNIQUE,
    amount_cents INTEGER NOT NULL,
    currency CHAR(3) NOT NULL,
    status TEXT NOT NULL,
    card_fingerprint_last4 TEXT,
    idempotency_fingerprint TEXT NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    CHECK (amount_cents > 0),
    CHECK (currency = upper(currency)),
    CHECK (status IN ('pending', 'succeeded', 'failed', 'refunded', 'partially_refunded'))
);

CREATE INDEX billing_charges_customer_idx ON billing.charges(customer_id);
CREATE INDEX billing_charges_order_idx ON billing.charges(order_id);
CREATE INDEX billing_charges_duplicate_detection_idx
    ON billing.charges(order_id, amount_cents, currency, status, idempotency_fingerprint);

CREATE TABLE policy.refund_policies (
    policy_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    version INTEGER NOT NULL,
    applies_to JSONB NOT NULL,
    max_age_days INTEGER NOT NULL,
    auto_approve_limit_cents INTEGER NOT NULL,
    requires_human_approval BOOLEAN NOT NULL,
    rollback_supported BOOLEAN NOT NULL,
    compensation_capability_id TEXT,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (version > 0),
    CHECK (max_age_days > 0),
    CHECK (auto_approve_limit_cents >= 0)
);

CREATE TABLE approval.approval_requests (
    approval_request_id TEXT PRIMARY KEY,
    case_id TEXT NOT NULL REFERENCES support.cases(case_id),
    requested_by_principal TEXT NOT NULL,
    approver_principal TEXT,
    action_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'requested',
    reason TEXT NOT NULL,
    evidence JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    decided_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (status IN ('requested', 'granted', 'denied', 'expired', 'cancelled')),
    CHECK (expires_at > created_at)
);

CREATE TABLE billing.refunds (
    refund_id TEXT PRIMARY KEY,
    charge_id TEXT NOT NULL REFERENCES billing.charges(charge_id),
    customer_id TEXT NOT NULL REFERENCES support.customers(customer_id),
    case_id TEXT NOT NULL REFERENCES support.cases(case_id),
    amount_cents INTEGER NOT NULL,
    currency CHAR(3) NOT NULL,
    status TEXT NOT NULL DEFAULT 'planned',
    idempotency_key TEXT NOT NULL UNIQUE,
    approval_request_id TEXT REFERENCES approval.approval_requests(approval_request_id),
    reason TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    committed_at TIMESTAMPTZ,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    CHECK (amount_cents > 0),
    CHECK (currency = upper(currency)),
    CHECK (status IN ('planned', 'blocked_for_approval', 'approved', 'committed', 'failed', 'cancelled'))
);

CREATE INDEX billing_refunds_case_idx ON billing.refunds(case_id);
CREATE INDEX billing_refunds_customer_idx ON billing.refunds(customer_id);

CREATE TABLE audit.events (
    event_id BIGSERIAL PRIMARY KEY,
    event_type TEXT NOT NULL,
    actor_principal TEXT NOT NULL,
    subject_ref TEXT NOT NULL,
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE VIEW billing.duplicate_charge_candidates AS
SELECT
    customer_id,
    order_id,
    amount_cents,
    currency,
    idempotency_fingerprint,
    count(*) AS successful_charge_count,
    array_agg(charge_id ORDER BY captured_at) AS charge_ids,
    min(captured_at) AS first_captured_at,
    max(captured_at) AS last_captured_at
FROM billing.charges
WHERE status = 'succeeded'
GROUP BY customer_id, order_id, amount_cents, currency, idempotency_fingerprint
HAVING count(*) > 1;

CREATE VIEW support.case_triage_context AS
SELECT
    c.case_id,
    c.status AS case_status,
    c.priority,
    c.subject,
    c.external_conversation_id,
    cust.customer_id,
    cust.external_ref AS customer_external_ref,
    cust.email,
    cust.full_name,
    cust.risk_tier,
    coalesce(
        jsonb_agg(
            DISTINCT jsonb_build_object(
                'order_id', o.order_id,
                'external_ref', o.external_ref,
                'total_amount_cents', o.total_amount_cents,
                'currency', o.currency,
                'status', o.status,
                'placed_at', o.placed_at
            )
        ) FILTER (WHERE o.order_id IS NOT NULL),
        '[]'::jsonb
    ) AS orders,
    coalesce(
        jsonb_agg(
            DISTINCT jsonb_build_object(
                'charge_id', ch.charge_id,
                'order_id', ch.order_id,
                'provider', ch.provider,
                'provider_charge_id', ch.provider_charge_id,
                'amount_cents', ch.amount_cents,
                'currency', ch.currency,
                'status', ch.status,
                'captured_at', ch.captured_at,
                'idempotency_fingerprint', ch.idempotency_fingerprint
            )
        ) FILTER (WHERE ch.charge_id IS NOT NULL),
        '[]'::jsonb
    ) AS charges
FROM support.cases c
JOIN support.customers cust ON cust.customer_id = c.customer_id
LEFT JOIN billing.orders o ON o.customer_id = cust.customer_id
LEFT JOIN billing.charges ch ON ch.order_id = o.order_id
GROUP BY
    c.case_id,
    c.status,
    c.priority,
    c.subject,
    c.external_conversation_id,
    cust.customer_id,
    cust.external_ref,
    cust.email,
    cust.full_name,
    cust.risk_tier;

INSERT INTO support.customers (
    customer_id,
    external_ref,
    email,
    full_name,
    locale,
    risk_tier,
    created_at
) VALUES
    ('cust_001', 'chatwoot-contact-77', 'ava.thompson@example.com', 'Ava Thompson', 'en-US', 'standard', '2026-07-01T08:00:00Z'),
    ('cust_002', 'chatwoot-contact-88', 'miles.chen@example.com', 'Miles Chen', 'en-US', 'standard', '2026-07-02T08:00:00Z');

INSERT INTO support.cases (
    case_id,
    customer_id,
    channel,
    external_conversation_id,
    status,
    priority,
    subject,
    opened_at,
    updated_at
) VALUES
    ('case_1001', 'cust_001', 'chatwoot', 'conversation-1001', 'open', 'urgent', 'Duplicate charge refund request', '2026-07-09T09:10:00Z', '2026-07-09T09:12:00Z'),
    ('case_1002', 'cust_002', 'chatwoot', 'conversation-1002', 'open', 'normal', 'Shipping status question', '2026-07-09T10:00:00Z', '2026-07-09T10:02:00Z');

INSERT INTO support.messages (
    message_id,
    case_id,
    direction,
    sender_role,
    body,
    created_at,
    metadata
) VALUES
    (
        'msg_1001_in_001',
        'case_1001',
        'inbound',
        'customer',
        'I was charged twice for the same order. Refund the duplicate charge now. I am angry.',
        '2026-07-09T09:10:00Z',
        '{"source": "chatwoot", "delivery_id": "delivery-1001"}'::jsonb
    ),
    (
        'msg_1002_in_001',
        'case_1002',
        'inbound',
        'customer',
        'Can you tell me when my order will ship?',
        '2026-07-09T10:00:00Z',
        '{"source": "chatwoot", "delivery_id": "delivery-1002"}'::jsonb
    );

INSERT INTO billing.orders (
    order_id,
    customer_id,
    external_ref,
    total_amount_cents,
    currency,
    status,
    placed_at,
    metadata
) VALUES
    ('ord_1001', 'cust_001', 'shopify-order-7001', 12900, 'USD', 'fulfilled', '2026-07-08T13:00:00Z', '{"sku_count": 2}'::jsonb),
    ('ord_1002', 'cust_002', 'shopify-order-7002', 4500, 'USD', 'placed', '2026-07-08T15:00:00Z', '{"sku_count": 1}'::jsonb);

INSERT INTO billing.charges (
    charge_id,
    customer_id,
    order_id,
    provider,
    provider_charge_id,
    amount_cents,
    currency,
    status,
    card_fingerprint_last4,
    idempotency_fingerprint,
    captured_at,
    metadata
) VALUES
    (
        'ch_1001_a',
        'cust_001',
        'ord_1001',
        'stripe',
        'py_ch_ava_001',
        12900,
        'USD',
        'succeeded',
        '4242',
        'checkout-session-dup-7001',
        '2026-07-08T13:01:10Z',
        '{"payment_intent": "pi_ava_001"}'::jsonb
    ),
    (
        'ch_1001_b',
        'cust_001',
        'ord_1001',
        'stripe',
        'py_ch_ava_002',
        12900,
        'USD',
        'succeeded',
        '4242',
        'checkout-session-dup-7001',
        '2026-07-08T13:01:42Z',
        '{"payment_intent": "pi_ava_002", "suspected_duplicate": true}'::jsonb
    ),
    (
        'ch_1002_a',
        'cust_002',
        'ord_1002',
        'stripe',
        'py_ch_miles_001',
        4500,
        'USD',
        'succeeded',
        '1881',
        'checkout-session-7002',
        '2026-07-08T15:01:00Z',
        '{"payment_intent": "pi_miles_001"}'::jsonb
    );

INSERT INTO policy.refund_policies (
    policy_id,
    name,
    version,
    applies_to,
    max_age_days,
    auto_approve_limit_cents,
    requires_human_approval,
    rollback_supported,
    compensation_capability_id,
    active
) VALUES
    (
        'pol_duplicate_charge_refund_v1',
        'Duplicate charge refund policy',
        1,
        '{"reason": "duplicate_charge", "providers": ["stripe"], "currencies": ["USD"]}'::jsonb,
        30,
        0,
        true,
        false,
        NULL,
        true
    );

INSERT INTO audit.events (
    event_type,
    actor_principal,
    subject_ref,
    payload,
    created_at
) VALUES
    (
        'support_sandbox.seeded',
        'system:support-sandbox',
        'case:case_1001',
        '{"scenario": "sierra_like_duplicate_charge_triage"}'::jsonb,
        '2026-07-09T09:00:00Z'
    );
