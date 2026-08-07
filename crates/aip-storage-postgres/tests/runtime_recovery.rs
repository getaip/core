//! Live PostgreSQL recovery coverage for RFC 0003 read models.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::panic)]

use aip_auth::{AuthScheme, AuthenticatedPrincipal, AuthorityMembership};
use aip_core::{
    Action, ActionId, ActionMode, ActionResult, ActionResultStatus, ActionStatusRequest,
    ApprovalDecision, ApprovalDecisionKind, ApprovalId, ApprovalRequest, ApproverSelector,
    CapabilityId, Event, EventStreamRequest, MessageBody, PrincipalKind, ReceiptType, StreamChunk,
    StreamChunkKind,
};
use aip_runtime::{
    ActionHandler, EchoHandler, EventAppendOutcome, EventStore, LifecycleBackend,
    MAX_EVENT_PAGE_BYTES, MAX_EVENT_RECORD_BYTES, MessageContext, ProfileStateCasOutcome,
    QueueAttemptOutcome, QueueCompletion, QueuedActionRecord, QueuedActionStatus, Runtime,
    RuntimeRecoveryConfig, RuntimeResult, StreamChunkRecordOutcome, VerifiedApprovalDecision,
    validate_event_record_size,
};
use aip_storage_postgres::PostgresRuntimeStore;
use aip_testkit::{manifest, principal};
use serde_json::json;
use std::{
    collections::{BTreeSet, HashMap},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use time::OffsetDateTime;
use uuid::Uuid;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_stream_chunk_replay_is_atomic() -> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = postgres_test_url() else {
        eprintln!("AIP_POSTGRES_TEST_URL is not set; skipping atomic stream replay test");
        return Ok(());
    };
    let store = PostgresRuntimeStore::connect(&database_url).await?;
    let action_id = ActionId::new();
    let chunk = StreamChunk {
        action_id: action_id.clone(),
        sequence: 1,
        kind: StreamChunkKind::Progress,
        data: Some(json!({ "progress": 50 })),
        part: None,
    };
    let left_store = store.clone();
    let right_store = store.clone();
    let (left, right) = tokio::join!(
        left_store.record_stream_chunk(chunk.clone()),
        right_store.record_stream_chunk(chunk.clone()),
    );
    let outcomes = [left?, right?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == StreamChunkRecordOutcome::Inserted)
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| **outcome == StreamChunkRecordOutcome::Replayed)
            .count(),
        1
    );
    assert_eq!(store.stream_chunks(&action_id).await?, vec![chunk]);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn postgres_event_id_replay_reports_one_atomic_insert()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = postgres_test_url() else {
        eprintln!("AIP_POSTGRES_TEST_URL is not set; skipping atomic event replay test");
        return Ok(());
    };
    let store = PostgresRuntimeStore::connect(&database_url).await?;
    let action_id = ActionId::new();
    let mut event = Event::new("aip.test.atomic-event-replay");
    event.action_id = Some(action_id.clone());
    event.data = Some(json!({ "proof": "same-event-id" }));
    let event_id = event.id.clone();
    let left_store = store.clone();
    let right_store = store.clone();
    let (left, right) = tokio::join!(
        left_store.append_with_outcome(event.clone()),
        right_store.append_with_outcome(event),
    );
    let outcomes = [left?, right?];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, EventAppendOutcome::Inserted(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, EventAppendOutcome::Replayed(_)))
            .count(),
        1
    );
    assert!(
        outcomes
            .iter()
            .all(|outcome| outcome.event().id == event_id)
    );
    let stored = store
        .stream_action_checked(
            &action_id,
            &EventStreamRequest {
                cursor: None,
                limit: Some(10),
                kinds: vec!["aip.test.atomic-event-replay".to_owned()],
            },
        )
        .await?;
    assert_eq!(stored.events.len(), 1);
    assert_eq!(stored.events[0].id, event_id);
    Ok(())
}

#[tokio::test]
async fn postgres_event_stream_filters_tenant_before_decoding_page()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = postgres_test_url() else {
        eprintln!("AIP_POSTGRES_TEST_URL is not set; skipping tenant event stream test");
        return Ok(());
    };
    let store = PostgresRuntimeStore::connect(&database_url).await?;
    let run = Uuid::now_v7().simple().to_string();
    let tenant_a = format!("tenant-event-a-{run}");
    let tenant_b = format!("tenant-event-b-{run}");
    for (kind, tenant_id) in [
        (format!("aip.test.{run}.a.first"), tenant_a.as_str()),
        (format!("aip.test.{run}.b"), tenant_b.as_str()),
        (format!("aip.test.{run}.a.second"), tenant_a.as_str()),
    ] {
        let mut event = Event::new(kind);
        event.data = Some(json!({
            "identity": { "tenant": { "id": tenant_id } }
        }));
        store.append(event).await?;
    }
    let page = store
        .stream_tenant_checked(
            &tenant_a,
            &EventStreamRequest {
                cursor: None,
                limit: Some(10),
                kinds: Vec::new(),
            },
        )
        .await?;
    assert_eq!(page.events.len(), 2);
    assert!(page.events.iter().all(|event| {
        event
            .data
            .as_ref()
            .and_then(|data| data.pointer("/identity/tenant/id"))
            .and_then(serde_json::Value::as_str)
            == Some(tenant_a.as_str())
    }));

    let page_tenant = format!("tenant-event-page-{run}");
    let event_count = 40_usize;
    for sequence in 0..event_count {
        let mut event = Event::new(format!("aip.test.{run}.bounded.{sequence}"));
        event.data = Some(json!({
            "identity": { "tenant": { "id": page_tenant } },
            "sequence": sequence,
            "payload": "x".repeat(MAX_EVENT_RECORD_BYTES / 2)
        }));
        store.append(event).await?;
    }
    let first = store
        .stream_tenant_checked(
            &page_tenant,
            &EventStreamRequest {
                cursor: None,
                limit: Some(100),
                kinds: Vec::new(),
            },
        )
        .await?;
    assert!(!first.events.is_empty());
    assert!(first.events.len() < event_count);
    let first_bytes = first
        .events
        .iter()
        .map(validate_event_record_size)
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .sum::<usize>();
    assert!(first_bytes <= MAX_EVENT_PAGE_BYTES);
    let second = store
        .stream_tenant_checked(
            &page_tenant,
            &EventStreamRequest {
                cursor: first.next_cursor,
                limit: Some(100),
                kinds: Vec::new(),
            },
        )
        .await?;
    assert_eq!(first.events.len() + second.events.len(), event_count);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn postgres_event_replay_storm_is_bounded_and_slow_reader_isolated()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = postgres_test_url() else {
        eprintln!("AIP_POSTGRES_TEST_URL is not set; skipping event replay storm test");
        return Ok(());
    };
    let store = PostgresRuntimeStore::connect(&database_url).await?;
    let run = Uuid::now_v7().simple().to_string();
    let tenant_id = format!("tenant-event-replay-{run}");
    let event_count = 200_usize;
    let page_limit = 17_u32;
    let mut expected_ids = BTreeSet::new();
    for sequence in 0..event_count {
        let mut event = Event::new(format!("aip.test.{run}.replay.{sequence}"));
        event.data = Some(json!({
            "identity": { "tenant": { "id": tenant_id } },
            "sequence": sequence,
            "payload": "x".repeat(1_024)
        }));
        expected_ids.insert(event.id.clone());
        store.append(event).await?;
    }

    let slow_store = store.clone();
    let slow_tenant = tenant_id.clone();
    let (slow_loaded, slow_loaded_rx) = tokio::sync::oneshot::channel();
    let slow_reader = tokio::spawn(async move {
        let page = slow_store
            .stream_tenant_checked(
                &slow_tenant,
                &EventStreamRequest {
                    cursor: None,
                    limit: Some(page_limit),
                    kinds: Vec::new(),
                },
            )
            .await
            .expect("slow reader page");
        let _ = slow_loaded.send(page.events.len());
        std::future::pending::<()>().await;
    });
    assert_eq!(slow_loaded_rx.await?, usize::try_from(page_limit)?);

    let mut readers = tokio::task::JoinSet::new();
    for _ in 0..32 {
        let store = store.clone();
        let tenant_id = tenant_id.clone();
        readers.spawn(async move {
            let mut cursor = None;
            let mut seen = BTreeSet::new();
            loop {
                let page = store
                    .stream_tenant_checked(
                        &tenant_id,
                        &EventStreamRequest {
                            cursor,
                            limit: Some(page_limit),
                            kinds: Vec::new(),
                        },
                    )
                    .await?;
                assert!(page.events.len() <= usize::try_from(page_limit).expect("page limit"));
                let page_bytes = page
                    .events
                    .iter()
                    .map(validate_event_record_size)
                    .collect::<Result<Vec<_>, _>>()?
                    .into_iter()
                    .sum::<usize>();
                assert!(page_bytes <= MAX_EVENT_PAGE_BYTES);
                for event in &page.events {
                    assert!(
                        seen.insert(event.id.clone()),
                        "replay page repeated an event"
                    );
                }
                if page.events.len() < usize::try_from(page_limit).expect("page limit") {
                    break;
                }
                cursor = page.next_cursor;
            }
            Ok::<_, aip_runtime::RuntimeError>(seen)
        });
    }
    let completed = tokio::time::timeout(Duration::from_secs(20), async {
        let mut completed = Vec::new();
        while let Some(result) = readers.join_next().await {
            completed.push(
                result
                    .expect("replay reader task")
                    .expect("replay reader pages"),
            );
        }
        completed
    })
    .await
    .expect("fast replay readers must not wait for a slow consumer");
    assert_eq!(completed.len(), 32);
    assert!(completed.iter().all(|ids| ids == &expected_ids));
    assert!(
        !slow_reader.is_finished(),
        "the slow reader fixture must still be holding its page"
    );
    slow_reader.abort();
    let _ = slow_reader.await;
    Ok(())
}

fn authenticated_context(principal: &aip_core::Principal) -> MessageContext {
    MessageContext {
        actor: Some(principal.clone()),
        authenticated: Some(AuthenticatedPrincipal {
            principal: principal.clone(),
            scheme: AuthScheme::DidProof,
            issuer: "postgres-test".to_owned(),
            audience: Some("aip-runtime".to_owned()),
            scopes: BTreeSet::from(["*".to_owned()]),
            authenticated_at: OffsetDateTime::now_utc(),
            expires_at: None,
            credential_fingerprint: None,
        }),
        ..MessageContext::default()
    }
}

fn verified_decision(
    approval_id: ApprovalId,
    decision: ApprovalDecisionKind,
    approver: aip_core::Principal,
    label: &str,
) -> VerifiedApprovalDecision {
    let now = OffsetDateTime::now_utc();
    VerifiedApprovalDecision {
        decision: ApprovalDecision {
            approval_id,
            decision,
            approver: approver.clone(),
            decided_at: now,
            reason: Some(label.to_owned()),
            constraints: Vec::new(),
            evidence: Vec::new(),
            decision_id: Some(format!("decision:{label}")),
            policy_hash: None,
            authority_path: vec![format!("principal:{}", approver.id)],
            target_decision_id: None,
        },
        authority: AuthorityMembership {
            principal_id: approver.id,
            tenant_id: None,
            roles: BTreeSet::new(),
            groups: BTreeSet::new(),
            tenant_policies: BTreeSet::from(["postgres-test-policy".to_owned()]),
            external_systems: BTreeSet::new(),
            delegated_scopes: Vec::new(),
            revision: 1,
            expires_at: None,
            revoked: false,
        },
        evidence_hash: format!("sha256:test:{label}"),
        recorded_at: now,
    }
}

#[derive(Clone)]
struct ExternalEffectCounter(Arc<AtomicUsize>);

#[async_trait::async_trait]
impl ActionHandler for ExternalEffectCounter {
    async fn handle(&self, action: Action) -> RuntimeResult<ActionResult> {
        let count = self.0.fetch_add(1, Ordering::SeqCst) + 1;
        Ok(ActionResult {
            action_id: action.id,
            status: ActionResultStatus::Completed,
            output: Some(json!({ "external_effect_count": count })),
            message: Vec::new(),
            memory_update: None,
            usage: None,
            receipt: None,
            error: None,
        })
    }
}

fn queued_record(action: Action, principal: aip_core::Principal) -> QueuedActionRecord {
    let now = OffsetDateTime::now_utc();
    QueuedActionRecord {
        action,
        principal,
        context: MessageContext::default(),
        status: QueuedActionStatus::Queued,
        result: None,
        cancellation_reason: None,
        attempts: 0,
        retry_policy: None,
        first_attempted_at: None,
        last_attempted_at: None,
        next_attempt_at: None,
        last_error: None,
        dead_letter_reason: None,
        lease: None,
        idempotency_reservation: None,
        created_at: now,
        updated_at: now,
    }
}

async fn admit_handler<H>(
    runtime: &Runtime,
    key: impl Into<String>,
    manifest: aip_core::Manifest,
    capability_id: CapabilityId,
    handler: H,
) -> RuntimeResult<()>
where
    H: ActionHandler + 'static,
{
    runtime
        .admit_manifest_with_handlers(
            key,
            manifest,
            HashMap::from([(capability_id, Arc::new(handler) as Arc<dyn ActionHandler>)]),
        )
        .await
}

fn isolated_manifest(prefix: &str) -> (String, CapabilityId, aip_core::Manifest) {
    let suffix = aip_core::ActionId::new().to_string();
    let manifest_key = format!("{prefix}-{suffix}");
    let capability_id = CapabilityId::trusted(format!("cap:test:{prefix}:{suffix}"));
    let mut manifest = manifest();
    manifest.capabilities[0].id = capability_id.clone();
    (manifest_key, capability_id, manifest)
}

#[tokio::test]
async fn postgres_queue_rejects_action_id_contract_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = postgres_test_url() else {
        eprintln!("AIP_POSTGRES_TEST_URL is not set; skipping live queue collision test");
        return Ok(());
    };

    let store = PostgresRuntimeStore::connect(&database_url).await?;
    let runtime = Runtime::with_stores(store.runtime_stores());
    let owner = principal("agent:postgres-queue-owner", PrincipalKind::Agent);
    let attacker = principal("agent:postgres-queue-attacker", PrincipalKind::Agent);
    let original_action = Action::new(
        CapabilityId::trusted(format!(
            "cap:test:queue-owner:{}",
            aip_core::ActionId::new()
        )),
        json!({ "record": "original" }),
    );
    let original = queued_record(original_action.clone(), owner);
    runtime.action_queue.enqueue(original.clone()).await?;

    let mut replacement = queued_record(
        Action::new(
            CapabilityId::trusted("cap:test:queue-replacement"),
            json!({ "record": "replacement" }),
        ),
        attacker,
    );
    replacement.action.id = original_action.id.clone();
    let error = runtime
        .action_queue
        .enqueue(replacement)
        .await
        .expect_err("conflicting queue replacement must fail closed");
    assert!(matches!(
        error,
        aip_runtime::RuntimeError::Protocol(aip_core::ProtocolError { code, .. })
            if code == "action.id_conflict"
    ));
    assert_eq!(
        runtime.action_queue.get(&original_action.id).await?,
        Some(original)
    );
    Ok(())
}

#[tokio::test]
async fn postgres_runtime_read_models_survive_restart() -> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = postgres_test_url() else {
        eprintln!("AIP_POSTGRES_TEST_URL is not set; skipping live PostgreSQL recovery test");
        return Ok(());
    };

    let (key, capability_id, manifest) = isolated_manifest("postgres-recovery");
    let principal = principal("agent:postgres-recovery", PrincipalKind::Agent);
    let action = Action {
        mode: Some(ActionMode::Async),
        ..Action::new(capability_id.clone(), json!({ "case": key }))
    };
    let action_id = action.id.clone();
    let approval_id = ApprovalId::new();

    let first_store = PostgresRuntimeStore::connect(&database_url).await?;
    let first = Runtime::with_stores(first_store.runtime_stores());
    admit_handler(
        &first,
        key.clone(),
        manifest.clone(),
        capability_id.clone(),
        EchoHandler,
    )
    .await?;
    first
        .action_queue
        .enqueue(QueuedActionRecord {
            action: action.clone(),
            principal: principal.clone(),
            context: MessageContext::default(),
            status: QueuedActionStatus::Queued,
            result: None,
            cancellation_reason: None,
            attempts: 0,
            retry_policy: None,
            first_attempted_at: None,
            last_attempted_at: None,
            next_attempt_at: None,
            last_error: None,
            dead_letter_reason: None,
            lease: None,
            idempotency_reservation: None,
            created_at: OffsetDateTime::now_utc(),
            updated_at: OffsetDateTime::now_utc(),
        })
        .await?;
    first
        .record_approval_request(
            ApprovalRequest {
                id: approval_id.clone(),
                action_id: action_id.clone(),
                capability_id: capability_id.clone(),
                requester: principal.clone(),
                subject: principal.clone(),
                approver_selector: ApproverSelector::TenantPolicy,
                reason: "live PostgreSQL restart proof".to_owned(),
                evidence: Vec::new(),
                expires_at: None,
                policy_decision_id: Some(key.clone()),
                identity: None,
                policy_snapshot: None,
                policy_hash: None,
                operator: None,
                risk: None,
                governed_value: None,
            },
            authenticated_context(&principal),
        )
        .await?;
    drop(first);

    let second_store = PostgresRuntimeStore::connect(&database_url).await?;
    let second = Runtime::with_stores(second_store.runtime_stores());
    admit_handler(&second, key, manifest, capability_id.clone(), EchoHandler).await?;
    let report = second
        .recover_runtime_state(RuntimeRecoveryConfig {
            recover_running_delegations: false,
            recover_callback_deliveries: false,
            ..RuntimeRecoveryConfig::default()
        })
        .await?;

    assert!(
        report
            .pending_approvals
            .iter()
            .any(|record| record.request.id == approval_id),
        "pending approval must survive PostgreSQL-backed runtime restart"
    );
    assert!(
        report
            .queued_results
            .iter()
            .any(|result| result.action_id == action_id
                && result.status == ActionResultStatus::Completed),
        "queued async action must be recovered and settled after restart"
    );
    let status = match second
        .action_status_response_with_context(
            ActionStatusRequest {
                action_id: action_id.clone(),
                include_result: true,
                include_receipts: false,
                include_chunks: false,
                tenant_id: None,
                wait_ms: None,
            },
            &authenticated_context(&principal),
        )
        .await
    {
        MessageBody::ActionStatus(status) => status,
        other => {
            return Err(format!("expected action status response, got {other:?}").into());
        }
    };
    assert_eq!(status.action_id, action_id);
    assert_eq!(status.result_status, Some(ActionResultStatus::Completed));

    let stream = second
        .events
        .stream_action_checked(
            &action_id,
            &EventStreamRequest {
                cursor: None,
                limit: Some(100),
                kinds: vec!["aip.approval.requested".to_owned()],
            },
        )
        .await?;
    assert!(
        stream
            .events
            .iter()
            .any(|event| event.kind == "aip.approval.requested"
                && event.action_id.as_ref() == Some(&action_id)),
        "approval request event must be durable in PostgreSQL"
    );

    Ok(())
}

#[tokio::test]
async fn postgres_approval_outbox_recovers_after_crash_before_publication()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = postgres_test_url() else {
        eprintln!(
            "AIP_POSTGRES_TEST_URL is not set; skipping live PostgreSQL approval outbox test"
        );
        return Ok(());
    };

    let (manifest_key, capability_id, manifest) = isolated_manifest("approval-outbox");
    let requester = principal("agent:postgres-approval-requester", PrincipalKind::Agent);
    let approver = principal("human:postgres-approval-authority", PrincipalKind::Human);
    let action = Action {
        mode: Some(ActionMode::Async),
        ..Action::new(
            capability_id.clone(),
            json!({ "case": manifest_key.clone() }),
        )
    };
    let action_id = action.id.clone();
    let approval_id = ApprovalId::new();
    let now = OffsetDateTime::now_utc();

    let first_store = PostgresRuntimeStore::connect(&database_url).await?;
    let first = Runtime::with_stores(first_store.runtime_stores());
    admit_handler(
        &first,
        manifest_key.clone(),
        manifest.clone(),
        capability_id.clone(),
        EchoHandler,
    )
    .await?;
    first
        .action_queue
        .enqueue(QueuedActionRecord {
            action,
            principal: requester.clone(),
            context: MessageContext {
                actor: Some(requester.clone()),
                ..MessageContext::default()
            },
            status: QueuedActionStatus::RequiresHuman,
            result: None,
            cancellation_reason: None,
            attempts: 0,
            retry_policy: None,
            first_attempted_at: None,
            last_attempted_at: None,
            next_attempt_at: None,
            last_error: None,
            dead_letter_reason: None,
            lease: None,
            idempotency_reservation: None,
            created_at: now,
            updated_at: now,
        })
        .await?;
    first
        .record_approval_request(
            ApprovalRequest {
                id: approval_id.clone(),
                action_id: action_id.clone(),
                capability_id: capability_id.clone(),
                requester: requester.clone(),
                subject: requester.clone(),
                approver_selector: ApproverSelector::Principal {
                    id: approver.id.clone(),
                },
                reason: "prove transactional approval outbox recovery".to_owned(),
                evidence: Vec::new(),
                expires_at: None,
                policy_decision_id: Some(manifest_key.clone()),
                identity: None,
                policy_snapshot: None,
                policy_hash: None,
                operator: None,
                risk: None,
                governed_value: None,
            },
            authenticated_context(&requester),
        )
        .await?;
    first
        .approvals
        .record_verified_decision(verified_decision(
            approval_id.clone(),
            ApprovalDecisionKind::Approved,
            approver.clone(),
            "approved-before-crash",
        ))
        .await?;
    drop(first);

    let second_store = PostgresRuntimeStore::connect(&database_url).await?;
    let second = Runtime::with_stores(second_store.runtime_stores());
    admit_handler(
        &second,
        manifest_key,
        manifest,
        capability_id.clone(),
        EchoHandler,
    )
    .await?;
    let recovered = second
        .recover_approval_transitions("postgres-approval-recovery", 30_000)
        .await?;
    assert!(
        !recovered.is_empty(),
        "the durable outbox transition must be recoverable"
    );
    for transition in recovered {
        transition?;
    }
    assert_eq!(
        second
            .action_queue
            .get(&action_id)
            .await?
            .expect("queue record")
            .status,
        QueuedActionStatus::Completed
    );
    let chain = second
        .lifecycle
        .receipt_chain(&format!("approval:{approval_id}"))
        .await?
        .expect("approval receipt chain");
    assert!(
        chain
            .receipts
            .iter()
            .any(|receipt| receipt.receipt_type == ReceiptType::ApprovalGranted)
    );
    assert!(
        second
            .recover_approval_transitions("postgres-approval-recovery-2", 30_000)
            .await?
            .is_empty(),
        "completed outbox transitions must not replay"
    );

    Ok(())
}

#[tokio::test]
async fn postgres_approval_decision_compare_and_set_has_one_winner()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = postgres_test_url() else {
        eprintln!("AIP_POSTGRES_TEST_URL is not set; skipping live PostgreSQL approval CAS test");
        return Ok(());
    };
    let runtime = Runtime::with_stores(
        PostgresRuntimeStore::connect(&database_url)
            .await?
            .runtime_stores(),
    );
    let requester = principal("agent:postgres-cas-requester", PrincipalKind::Agent);
    let left_approver = principal("human:postgres-cas-left", PrincipalKind::Human);
    let right_approver = principal("human:postgres-cas-right", PrincipalKind::Human);
    let approval_id = ApprovalId::new();
    runtime
        .record_approval_request(
            ApprovalRequest {
                id: approval_id.clone(),
                action_id: aip_core::ActionId::new(),
                capability_id: CapabilityId::trusted("cap:test:echo"),
                requester: requester.clone(),
                subject: requester.clone(),
                approver_selector: ApproverSelector::TenantPolicy,
                reason: "concurrent PostgreSQL approval CAS".to_owned(),
                evidence: Vec::new(),
                expires_at: None,
                policy_decision_id: None,
                identity: None,
                policy_snapshot: None,
                policy_hash: None,
                operator: None,
                risk: None,
                governed_value: None,
            },
            authenticated_context(&requester),
        )
        .await?;
    let left_store = runtime.approvals.clone();
    let left_id = approval_id.clone();
    let left = tokio::spawn(async move {
        left_store
            .record_verified_decision(verified_decision(
                left_id,
                ApprovalDecisionKind::Approved,
                left_approver,
                "postgres-cas-left",
            ))
            .await
    });
    let right_store = runtime.approvals.clone();
    let right_id = approval_id.clone();
    let right = tokio::spawn(async move {
        right_store
            .record_verified_decision(verified_decision(
                right_id,
                ApprovalDecisionKind::Denied,
                right_approver,
                "postgres-cas-right",
            ))
            .await
    });
    let outcomes = [left.await?, right.await?];
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
        outcomes.iter().filter(|outcome| outcome.is_err()).count(),
        1
    );
    if let Some(claim) = runtime
        .approvals
        .claim_decision_transition(&approval_id, "postgres-cas-cleanup", 30_000)
        .await?
    {
        assert!(
            runtime
                .approvals
                .complete_decision_transition(&approval_id, &claim.lease_id)
                .await?
        );
    }

    Ok(())
}

#[tokio::test]
async fn postgres_profile_state_is_durable_and_compare_and_set_is_atomic()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = postgres_test_url() else {
        eprintln!("AIP_POSTGRES_TEST_URL is not set; skipping live profile-state CAS test");
        return Ok(());
    };
    let namespace = format!("test.a2a.{}", aip_core::ActionId::new());
    let key = "task-1";
    let first = Runtime::with_stores(
        PostgresRuntimeStore::connect(&database_url)
            .await?
            .runtime_stores(),
    );
    let created = first
        .profile_state
        .create(&namespace, key, json!({ "state": "created" }))
        .await?;
    let ProfileStateCasOutcome::Applied(created) = created else {
        panic!("fresh profile-state key must be created");
    };
    assert_eq!(created.revision, 1);
    drop(first);

    let second = Runtime::with_stores(
        PostgresRuntimeStore::connect(&database_url)
            .await?
            .runtime_stores(),
    );
    assert_eq!(
        second
            .profile_state
            .get(&namespace, key)
            .await?
            .expect("durable profile state")
            .value,
        json!({ "state": "created" })
    );
    let left_store = second.profile_state.clone();
    let left_namespace = namespace.clone();
    let left = tokio::spawn(async move {
        left_store
            .compare_and_set(&left_namespace, key, Some(1), json!({ "winner": "left" }))
            .await
    });
    let right_store = second.profile_state.clone();
    let right_namespace = namespace.clone();
    let right = tokio::spawn(async move {
        right_store
            .compare_and_set(&right_namespace, key, Some(1), json!({ "winner": "right" }))
            .await
    });
    let outcomes = [left.await??, right.await??];
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ProfileStateCasOutcome::Applied(_)))
            .count(),
        1
    );
    assert_eq!(
        outcomes
            .iter()
            .filter(|outcome| matches!(outcome, ProfileStateCasOutcome::Conflict(Some(_))))
            .count(),
        1
    );
    let final_entry = second
        .profile_state
        .get(&namespace, key)
        .await?
        .expect("final profile state");
    assert_eq!(final_entry.revision, 2);
    assert!(
        second
            .profile_state
            .delete(&namespace, key, final_entry.revision)
            .await?
    );
    Ok(())
}

#[tokio::test]
async fn postgres_two_workers_execute_once_and_reject_stale_settlement()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = postgres_test_url() else {
        eprintln!("AIP_POSTGRES_TEST_URL is not set; skipping live two-worker test");
        return Ok(());
    };
    let (manifest_key, capability_id, manifest) = isolated_manifest("two-worker");
    let principal = principal("agent:postgres-two-worker", PrincipalKind::Agent);
    let first_store = PostgresRuntimeStore::connect(&database_url).await?;
    let second_store = PostgresRuntimeStore::connect(&database_url).await?;
    let first = Runtime::with_stores(first_store.runtime_stores());
    let second = Runtime::with_stores(second_store.runtime_stores());
    let effects = Arc::new(AtomicUsize::new(0));
    admit_handler(
        &first,
        manifest_key.clone(),
        manifest.clone(),
        capability_id.clone(),
        ExternalEffectCounter(effects.clone()),
    )
    .await?;
    admit_handler(
        &second,
        manifest_key,
        manifest,
        capability_id.clone(),
        ExternalEffectCounter(effects.clone()),
    )
    .await?;
    let action = Action::new(capability_id.clone(), json!({ "race": true }));
    first
        .action_queue
        .enqueue(queued_record(action.clone(), principal.clone()))
        .await?;

    let left_runtime = first.clone();
    let right_runtime = second.clone();
    let left_action_id = action.id.clone();
    let right_action_id = action.id.clone();
    let left = tokio::spawn(async move {
        left_runtime
            .run_queued_action_by_id_once(&left_action_id, "postgres-worker-left", 30_000)
            .await
    });
    let right = tokio::spawn(async move {
        right_runtime
            .run_queued_action_by_id_once(&right_action_id, "postgres-worker-right", 30_000)
            .await
    });
    let outcomes = [left.await??, right.await??];
    assert_eq!(outcomes.iter().filter(|result| result.is_some()).count(), 1);
    assert_eq!(effects.load(Ordering::SeqCst), 1);
    assert_eq!(
        first
            .action_queue
            .get(&action.id)
            .await?
            .expect("settled queue action")
            .status,
        QueuedActionStatus::Completed
    );

    let stale_action = Action::new(capability_id, json!({ "stale": true }));
    first
        .action_queue
        .enqueue(queued_record(stale_action.clone(), principal))
        .await?;
    let stale_lease = first
        .action_queue
        .lease_action(&stale_action.id, "stale-worker", 1)
        .await?
        .expect("stale lease");
    let stale_lease_id = stale_lease
        .lease
        .as_ref()
        .expect("stale lease metadata")
        .lease_id
        .clone();
    tokio::time::sleep(Duration::from_millis(5)).await;
    let current_lease = second
        .action_queue
        .lease_action(&stale_action.id, "current-worker", 30_000)
        .await?
        .expect("take over expired lease");
    let current_lease_id = current_lease
        .lease
        .as_ref()
        .expect("current lease metadata")
        .lease_id
        .clone();
    let stale_result = ActionResult {
        action_id: stale_action.id.clone(),
        status: ActionResultStatus::Completed,
        output: Some(json!({ "winner": "stale" })),
        message: Vec::new(),
        memory_update: None,
        usage: None,
        receipt: None,
        error: None,
    };
    assert_eq!(
        first
            .action_queue
            .complete_attempt(
                &stale_action.id,
                &stale_lease_id,
                QueueAttemptOutcome::Settle(stale_result),
            )
            .await?,
        QueueCompletion::LeaseLost
    );
    let current_result = ActionResult {
        action_id: stale_action.id.clone(),
        status: ActionResultStatus::Completed,
        output: Some(json!({ "winner": "current" })),
        message: Vec::new(),
        memory_update: None,
        usage: None,
        receipt: None,
        error: None,
    };
    assert_eq!(
        second
            .action_queue
            .complete_attempt(
                &stale_action.id,
                &current_lease_id,
                QueueAttemptOutcome::Settle(current_result),
            )
            .await?,
        QueueCompletion::Applied
    );
    assert_eq!(
        second
            .action_queue
            .get(&stale_action.id)
            .await?
            .expect("current settlement")
            .result
            .as_ref()
            .and_then(|result| result.output.as_ref())
            .and_then(|output| output.get("winner"))
            .and_then(serde_json::Value::as_str),
        Some("current")
    );
    Ok(())
}

fn postgres_test_url() -> Option<String> {
    std::env::var("AIP_POSTGRES_TEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
}
