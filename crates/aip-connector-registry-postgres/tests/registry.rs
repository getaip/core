//! Live PostgreSQL checks for normalized catalog and durable route assignment.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::panic)]

use aip_connector_admission::{
    AdmissionJournal, AdmissionOperation, AdmissionOperationClaim, AdmissionOperationState,
};
use aip_connector_registry::{
    ActionTargetResolver, AdmissionPolicy, AdmissionScopeKind, ArtifactAttestation,
    ArtifactCheckStatus, CapabilityBinding, CapabilityCatalogProvider, CapabilityCatalogQuery,
    CatalogReadContext, ConnectorFleetStatusProvider, ConnectorInstance, ConnectorInstanceStatus,
    ConnectorRegistryAdmin, ConnectorRegistryReader, ConnectorReplica, ConnectorReplicaStatus,
    ConnectorType, ConnectorTypeId, ConnectorVersion, ConnectorVersionId, ConnectorVersionStatus,
    RegistryError, RouteResolutionRequest, RouteSettlement, digest_json, schema_bundle_digest,
};
use aip_connector_registry_postgres::{PostgresConnectorRegistry, RegistryPoolLimits};
use aip_core::{
    ActionId, Capability, CapabilityId, CapabilityKind, Manifest, MessageId, Principal,
    PrincipalId, PrincipalKind, ProfileId,
};
use aip_discovery::CapabilityImplementationSupport;
use serde_json::json;
use sqlx_core::{query::query, row::Row};
use sqlx_postgres::Postgres;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};
use tokio::sync::Barrier;
use uuid::Uuid;

#[tokio::test]
async fn admission_journal_serializes_concurrent_package_revisions()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = std::env::var("AIP_POSTGRES_TEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("AIP_POSTGRES_TEST_URL is not set; skipping admission fencing test");
        return Ok(());
    };
    let registry = PostgresConnectorRegistry::connect(&database_url).await?;
    let package_id = format!("package:concurrent:{}", Uuid::now_v7().simple());
    let connector_type_id = ConnectorTypeId::new();
    let operation = |revision: u64| AdmissionOperation {
        package_id: package_id.clone(),
        revision,
        package_digest: format!("sha256:{revision:064x}"),
        connector_type_id: connector_type_id.clone(),
        version_id: ConnectorVersionId::new(),
        signer_identity: "integration-test-release-authority".to_owned(),
        claim_id: format!("claim-{revision}-{}", Uuid::now_v7().simple()),
        claim_expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
        state: AdmissionOperationState::Applying,
        last_error: None,
        updated_at: OffsetDateTime::now_utc(),
    };
    let first = operation(1);
    let second = operation(2);
    let barrier = Arc::new(Barrier::new(3));
    let first_task = {
        let registry = registry.clone();
        let barrier = barrier.clone();
        let operation = first.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            registry.claim_admission_operation(operation).await
        })
    };
    let second_task = {
        let registry = registry.clone();
        let barrier = barrier.clone();
        let operation = second.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            registry.claim_admission_operation(operation).await
        })
    };
    barrier.wait().await;
    let first_result = first_task.await?;
    let second_result = second_task.await?;
    assert_eq!(
        usize::from(first_result.is_ok()) + usize::from(second_result.is_ok()),
        1,
        "exactly one concurrent package revision must own the durable claim"
    );
    let (winner, winner_result, loser_result) = if first_result.is_ok() {
        (first, first_result, second_result)
    } else {
        (second, second_result, first_result)
    };
    assert_eq!(winner_result?, AdmissionOperationClaim::New);
    assert!(matches!(
        loser_result,
        Err(aip_connector_admission::AdmissionError::Conflict(_))
    ));
    let mut competing = winner.clone();
    competing.claim_id = format!("competing-{}", Uuid::now_v7().simple());
    assert!(matches!(
        registry.claim_admission_operation(competing).await,
        Err(aip_connector_admission::AdmissionError::Conflict(message))
            if message.contains("live admission claim")
    ));
    registry
        .fail_admission_operation(
            &winner.package_id,
            winner.revision,
            &winner.package_digest,
            &winner.claim_id,
            "simulated operator interruption",
        )
        .await?;
    let mut recovery = winner;
    recovery.claim_id = format!("recovery-{}", Uuid::now_v7().simple());
    recovery.claim_expires_at = OffsetDateTime::now_utc() + Duration::minutes(5);
    assert_eq!(
        registry.claim_admission_operation(recovery).await?,
        AdmissionOperationClaim::Resume
    );
    Ok(())
}

#[tokio::test]
async fn data_plane_pool_has_no_catalog_control_credentials()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = std::env::var("AIP_POSTGRES_DATA_TEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("AIP_POSTGRES_DATA_TEST_URL is not set; skipping split-role registry test");
        return Ok(());
    };
    let registry =
        PostgresConnectorRegistry::connect_data_plane(&database_url, RegistryPoolLimits::default())
            .await?;
    let pools = registry.pool_snapshot();
    assert_eq!(pools.control_size, 0);
    assert_eq!(pools.control_max, 0);
    let _catalog_revision = registry.revision().await?;
    let page = registry
        .query(
            CapabilityCatalogQuery {
                limit: 1,
                ..CapabilityCatalogQuery::default()
            },
            &CatalogReadContext::internal(),
        )
        .await?;
    assert_eq!(page.catalog_revision, registry.revision().await?);

    let denied = registry
        .put_connector_type(ConnectorType {
            id: ConnectorTypeId::new(),
            name: "must be denied".to_owned(),
            owner: "data plane".to_owned(),
            enabled: true,
        })
        .await
        .expect_err("data-plane composition must not expose a control pool");
    assert!(matches!(denied, RegistryError::Storage(message) if message.contains("control-plane")));

    let direct_write = query::<Postgres>(
        r#"
        INSERT INTO aip_connector_types
            (type_id, name, owner, enabled, record, updated_at_ms)
        VALUES ($1, 'denied', 'data-plane-role', TRUE, '{}'::JSONB, 0)
        "#,
    )
    .bind(format!("ctype_denied_{}", Uuid::now_v7().simple()))
    .execute(registry.data_pool())
    .await;
    assert!(
        direct_write.is_err(),
        "the database data-plane role must not mutate catalog tables"
    );
    let current_user = query::<Postgres>("SELECT current_user AS current_user")
        .fetch_one(registry.data_pool())
        .await?
        .try_get::<String, _>("current_user")?;
    assert!(!current_user.trim().is_empty());
    Ok(())
}

#[tokio::test]
async fn catalog_and_route_survive_concurrent_resolve_and_reconnect()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = std::env::var("AIP_POSTGRES_TEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("AIP_POSTGRES_TEST_URL is not set; skipping live connector registry test");
        return Ok(());
    };
    let registry = PostgresConnectorRegistry::connect(&database_url).await?;
    let control_request_id = MessageId::new();
    let control_request_expiry = OffsetDateTime::now_utc() + Duration::minutes(5);
    assert!(
        registry
            .claim_control_request(control_request_id.as_str(), control_request_expiry)
            .await?
    );
    assert!(
        !registry
            .claim_control_request(control_request_id.as_str(), control_request_expiry)
            .await?
    );
    let replay_reopened = PostgresConnectorRegistry::connect(&database_url).await?;
    assert!(
        !replay_reopened
            .claim_control_request(control_request_id.as_str(), control_request_expiry)
            .await?
    );
    registry
        .put_admission_policy(AdmissionPolicy::conservative("quota:test"))
        .await?;
    registry
        .put_admission_policy(AdmissionPolicy::conservative("quota:fallback"))
        .await?;
    let connector_type_id = ConnectorTypeId::new();
    registry
        .put_connector_type(ConnectorType {
            id: connector_type_id.clone(),
            name: "PostgreSQL registry test".to_owned(),
            owner: "AIP conformance".to_owned(),
            enabled: true,
        })
        .await?;
    let capability_id = CapabilityId::trusted(format!("cap:test:postgres:{}", Uuid::now_v7()));
    let capability = Capability {
        id: capability_id.clone(),
        name: "PostgreSQL connector route".to_owned(),
        kind: CapabilityKind::Tool,
        input_schema: json!({ "type": "object" }),
        output_schema: Some(json!({ "type": "object" })),
        description: Some("Live normalized registry fixture".to_owned()),
        risk: None,
        stability: None,
        cost: None,
        auth: None,
        bindings: Vec::new(),
        requires_human_approval: None,
        contract: None,
    };
    let manifest = Manifest {
        manifest_version: "aip-manifest/v1".to_owned(),
        agent: Principal::new(
            PrincipalId::trusted(format!("service:test-host:{}", Uuid::now_v7())),
            PrincipalKind::Service,
        ),
        capabilities: vec![capability],
        profiles: vec![ProfileId::from("aip.native.http.v1")],
        resources: Vec::new(),
        channels: Vec::new(),
        security: None,
        governance: None,
        limits: None,
        compatibility: None,
        extensions: None,
    };
    let version_id = aip_connector_registry::ConnectorVersionId::new();
    registry
        .admit_version(ConnectorVersion {
            id: version_id.clone(),
            connector_type_id: connector_type_id.clone(),
            version: format!("1.0.0+{}", Uuid::now_v7().simple()),
            status: ConnectorVersionStatus::Active,
            manifest_digest: digest_json(&serde_json::to_value(&manifest)?)?,
            attestation: ArtifactAttestation {
                artifact_digest: unique_digest(),
                schema_bundle_digest: schema_bundle_digest(&manifest)?,
                sbom_digest: unique_digest(),
                provenance_digest: unique_digest(),
                conformance_report_digest: unique_digest(),
                vulnerability_report_digest: unique_digest(),
                license_report_digest: unique_digest(),
                signature_ref: "sigstore:test-bundle".to_owned(),
                signer_identity: "https://fulcio.example/identity/postgres-test".to_owned(),
                owner: "AIP conformance".to_owned(),
                supported_aip_versions: BTreeSet::from([aip_core::AIP_VERSION.to_owned()]),
                sdk_version_requirement: format!("^{}", env!("CARGO_PKG_VERSION")),
                conformance_status: ArtifactCheckStatus::Passed,
                vulnerability_policy_status: ArtifactCheckStatus::Passed,
                license_policy_status: ArtifactCheckStatus::Passed,
                revocation_status: ArtifactCheckStatus::Passed,
            },
            manifest,
            implementation_support: BTreeMap::from([(
                capability_id.clone(),
                CapabilityImplementationSupport {
                    invocation: true,
                    ..CapabilityImplementationSupport::default()
                },
            )]),
            admitted_at: OffsetDateTime::now_utc(),
        })
        .await?;
    let qualification_row = query::<Postgres>(
        "SELECT supply_chain_qualified FROM aip_connector_versions WHERE version_id = $1",
    )
    .bind(version_id.as_str())
    .fetch_one(registry.pool())
    .await?;
    assert!(qualification_row.try_get::<bool, _>("supply_chain_qualified")?);
    let tenant_id = format!("tenant-{}", Uuid::now_v7().simple());
    let instance_id = aip_connector_registry::ConnectorInstanceId::new();
    registry
        .put_instance(ConnectorInstance {
            id: instance_id.clone(),
            connector_type_id: connector_type_id.clone(),
            version_id: version_id.clone(),
            tenant_id: tenant_id.clone(),
            config_revision: 1,
            secret_provider_ref: format!("vault://{tenant_id}/fixture"),
            status: ConnectorInstanceStatus::Enabled,
        })
        .await?;
    let replica_id = aip_connector_registry::ConnectorReplicaId::new();
    registry
        .put_replica(ConnectorReplica {
            id: replica_id.clone(),
            instance_id: instance_id.clone(),
            version_id: version_id.clone(),
            endpoint: "https://connector.test/aip/v1/messages".to_owned(),
            peer_principal_id: PrincipalId::trusted("service:test-postgres-connector"),
            peer_principal_kind: PrincipalKind::Service,
            peer_did: "did:key:test-postgres-connector".to_owned(),
            trust_domain: "connectors.test".to_owned(),
            transport_profile: ProfileId::from("aip.native.http.v1"),
            topology: Default::default(),
            status: ConnectorReplicaStatus::Ready,
            lease_expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
            capacity: 2,
            active_assignments: 0,
            health_revision: 1,
            last_control_request_id: None,
            last_control_request_digest: None,
        })
        .await?;
    let lifecycle_request_id = MessageId::new();
    let lifecycle_request_digest = unique_digest();
    let mut lifecycle_replica = registry
        .connector_replica(&replica_id)
        .await?
        .ok_or_else(|| std::io::Error::other("registered replica disappeared"))?;
    lifecycle_replica.health_revision += 1;
    lifecycle_replica.last_control_request_id = Some(lifecycle_request_id.clone());
    lifecycle_replica.last_control_request_digest = Some(lifecycle_request_digest.clone());
    registry.put_replica(lifecycle_replica).await?;
    let lifecycle_reopened = PostgresConnectorRegistry::connect(&database_url).await?;
    let persisted_lifecycle = lifecycle_reopened
        .connector_replica(&replica_id)
        .await?
        .ok_or_else(|| std::io::Error::other("reconnected lifecycle replica disappeared"))?;
    assert_eq!(
        persisted_lifecycle.last_control_request_id.as_ref(),
        Some(&lifecycle_request_id)
    );
    assert_eq!(
        persisted_lifecycle.last_control_request_digest.as_deref(),
        Some(lifecycle_request_digest.as_str())
    );
    let mut stale_lifecycle_update = persisted_lifecycle;
    stale_lifecycle_update.status = ConnectorReplicaStatus::Draining;
    assert!(matches!(
        lifecycle_reopened.put_replica(stale_lifecycle_update).await,
        Err(RegistryError::Conflict(_))
    ));
    registry
        .put_binding(CapabilityBinding {
            tenant_id: tenant_id.clone(),
            capability_id: capability_id.clone(),
            instance_id: instance_id.clone(),
            priority: 0,
            policy_revision: 1,
            credential_revision_ref: Some("credential-revision-1".to_owned()),
            quota_policy_ref: Some("quota:test".to_owned()),
            enabled: true,
        })
        .await?;

    let page = registry
        .query(
            CapabilityCatalogQuery {
                profile: Some(ProfileId::from("aip.native.http.v1")),
                limit: 10,
                ..CapabilityCatalogQuery::default()
            },
            &CatalogReadContext::for_tenant(&tenant_id),
        )
        .await?;
    assert_eq!(page.total, 1);
    assert_eq!(page.capabilities[0].capability.id, capability_id);
    let action_id = ActionId::new();
    let request = RouteResolutionRequest {
        action_id: action_id.clone(),
        capability_id,
        tenant_id: tenant_id.clone(),
        topology: Default::default(),
    };
    let left = registry.clone();
    let right = registry.clone();
    let left_request = request.clone();
    let right_request = request.clone();
    let (left, right) = tokio::join!(left.resolve(left_request), right.resolve(right_request));
    let left = left?;
    let right = right?;
    assert_eq!(left, right);
    assert_eq!(left.replica_id, replica_id);
    registry
        .settle(&left, RouteSettlement::OutcomeUnknown)
        .await?;

    let requests = [ActionId::new(), ActionId::new(), ActionId::new()].map(|action_id| {
        registry.resolve(RouteResolutionRequest {
            action_id,
            capability_id: request.capability_id.clone(),
            tenant_id: request.tenant_id.clone(),
            topology: Default::default(),
        })
    });
    let [first, second, third] = requests;
    let (first, second, third) = tokio::join!(first, second, third);
    let outcomes = [first, second, third];
    let successful = outcomes.iter().filter(|outcome| outcome.is_ok()).count();
    assert_eq!(successful, 2, "capacity two must admit exactly two actions");
    for assignment in outcomes.into_iter().flatten() {
        registry
            .settle(&assignment, RouteSettlement::Completed)
            .await?;
    }

    let lease_request = RouteResolutionRequest {
        action_id: ActionId::new(),
        capability_id: request.capability_id.clone(),
        tenant_id: request.tenant_id.clone(),
        topology: Default::default(),
    };
    let lease_assignment = registry.resolve(lease_request.clone()).await?;
    let mut expiring_replica = registry
        .connector_replica(&replica_id)
        .await?
        .ok_or_else(|| std::io::Error::other("registered replica disappeared"))?;
    expiring_replica.health_revision += 1;
    expiring_replica.lease_expires_at = OffsetDateTime::now_utc() - Duration::seconds(1);
    registry.put_replica(expiring_replica).await?;
    let before_expiry = registry.fleet_status(OffsetDateTime::now_utc()).await?;
    assert_eq!(before_expiry.expired_leases, 1);
    assert_eq!(before_expiry.active_assignments, 1);
    assert_eq!(
        registry
            .expire_stale_replicas(OffsetDateTime::now_utc(), 10)
            .await?,
        1
    );
    let mut recovered_replica = registry
        .connector_replica(&replica_id)
        .await?
        .ok_or_else(|| std::io::Error::other("expired replica disappeared"))?;
    assert_eq!(recovered_replica.status, ConnectorReplicaStatus::Offline);
    assert_eq!(recovered_replica.active_assignments, 0);
    assert_eq!(recovered_replica.last_control_request_id, None);
    assert_eq!(recovered_replica.last_control_request_digest, None);
    assert!(matches!(
        registry.resolve(lease_request.clone()).await,
        Err(RegistryError::ReplicaUnavailable(_))
    ));
    recovered_replica.status = ConnectorReplicaStatus::Ready;
    recovered_replica.health_revision += 1;
    recovered_replica.lease_expires_at = OffsetDateTime::now_utc() + Duration::minutes(5);
    registry.put_replica(recovered_replica).await?;
    let pinned_after_recovery = registry.resolve(lease_request).await?;
    assert_eq!(pinned_after_recovery, lease_assignment);
    registry
        .settle(&pinned_after_recovery, RouteSettlement::Completed)
        .await?;
    exercise_bounded_retry_storm(&registry, &replica_id, &request).await?;

    let mut offline_replica = registry
        .connector_replica(&replica_id)
        .await?
        .ok_or_else(|| std::io::Error::other("recovered replica disappeared"))?;
    offline_replica.status = ConnectorReplicaStatus::Offline;
    offline_replica.health_revision += 1;
    registry.put_replica(offline_replica).await?;
    let fallback_instance_id = aip_connector_registry::ConnectorInstanceId::new();
    registry
        .put_instance(ConnectorInstance {
            id: fallback_instance_id.clone(),
            connector_type_id,
            version_id: version_id.clone(),
            tenant_id: tenant_id.clone(),
            config_revision: 1,
            secret_provider_ref: format!("vault://{tenant_id}/fallback"),
            status: ConnectorInstanceStatus::Enabled,
        })
        .await?;
    let fallback_replica_id = aip_connector_registry::ConnectorReplicaId::new();
    registry
        .put_replica(ConnectorReplica {
            id: fallback_replica_id.clone(),
            instance_id: fallback_instance_id.clone(),
            version_id: version_id.clone(),
            endpoint: "https://fallback.connector.test/aip/v1/messages".to_owned(),
            peer_principal_id: PrincipalId::trusted("service:test-postgres-fallback"),
            peer_principal_kind: PrincipalKind::Service,
            peer_did: "did:key:test-postgres-fallback".to_owned(),
            trust_domain: "connectors.test".to_owned(),
            transport_profile: ProfileId::from("aip.native.http.v1"),
            topology: Default::default(),
            status: ConnectorReplicaStatus::Ready,
            lease_expires_at: OffsetDateTime::now_utc() + Duration::minutes(5),
            capacity: 1,
            active_assignments: 0,
            health_revision: 1,
            last_control_request_id: None,
            last_control_request_digest: None,
        })
        .await?;
    registry
        .put_binding(CapabilityBinding {
            tenant_id: tenant_id.clone(),
            capability_id: request.capability_id.clone(),
            instance_id: fallback_instance_id,
            priority: 1,
            policy_revision: 1,
            credential_revision_ref: Some("credential-revision-fallback".to_owned()),
            quota_policy_ref: Some("quota:fallback".to_owned()),
            enabled: true,
        })
        .await?;
    let fallback_request = RouteResolutionRequest {
        action_id: ActionId::new(),
        capability_id: request.capability_id.clone(),
        tenant_id: request.tenant_id.clone(),
        topology: Default::default(),
    };
    let fallback = registry.resolve(fallback_request.clone()).await?;
    assert_eq!(fallback.replica_id, fallback_replica_id);
    assert_eq!(fallback.binding_policy_revision, 1);
    assert_eq!(fallback.quota_policy_ref.as_deref(), Some("quota:fallback"));
    registry
        .settle(&fallback, RouteSettlement::Completed)
        .await?;

    let reopened = PostgresConnectorRegistry::connect(&database_url).await?;
    assert_eq!(reopened.assignment(&action_id).await?, Some(left));
    for _ in 0..5 {
        let circuit_attempt = reopened.resolve(fallback_request.clone()).await?;
        reopened
            .settle(&circuit_attempt, RouteSettlement::OutcomeUnknown)
            .await?;
    }
    assert!(matches!(
        reopened.resolve(fallback_request.clone()).await,
        Err(RegistryError::ReplicaUnavailable(id)) if id == fallback.instance_id
    ));

    reopened
        .set_version_status(&version_id, ConnectorVersionStatus::Revoked)
        .await?;
    assert_eq!(
        reopened.assignment(&fallback.action_id).await?,
        Some(fallback.clone())
    );
    reopened
        .resolve(fallback_request.clone())
        .await
        .expect_err("revoked artifact cannot start another pinned attempt");
    let unavailable = reopened
        .resolve(RouteResolutionRequest {
            action_id: ActionId::new(),
            capability_id: request.capability_id,
            tenant_id: request.tenant_id,
            topology: Default::default(),
        })
        .await
        .expect_err("revoked versions cannot receive new routes");
    assert!(matches!(
        unavailable,
        RegistryError::BindingUnavailable { .. }
    ));
    Ok(())
}

async fn exercise_bounded_retry_storm(
    registry: &PostgresConnectorRegistry,
    replica_id: &aip_connector_registry::ConnectorReplicaId,
    request: &RouteResolutionRequest,
) -> Result<(), Box<dyn std::error::Error>> {
    const RETRY_BUDGET: usize = 4;
    const STORM_SIZE: usize = 32;

    let mut replica = registry
        .connector_replica(replica_id)
        .await?
        .ok_or_else(|| std::io::Error::other("retry-storm replica disappeared"))?;
    replica.capacity = u32::try_from(STORM_SIZE * 2)?;
    replica.health_revision += 1;
    replica.lease_expires_at = OffsetDateTime::now_utc() + Duration::minutes(5);
    registry.put_replica(replica).await?;

    let mut policy = AdmissionPolicy::conservative("quota:test");
    policy.revision = 2;
    policy.max_global_in_flight = 1_000;
    policy.max_tenant_in_flight = 1_000;
    policy.max_connector_type_in_flight = 1_000;
    policy.max_instance_in_flight = 1_000;
    policy.max_binding_in_flight = 1_000;
    policy.max_tenant_retry_in_flight = u32::try_from(RETRY_BUDGET)?;
    policy.circuit_failure_threshold = 1_000;
    registry.put_admission_policy(policy).await?;

    let mut retry_requests = Vec::with_capacity(STORM_SIZE);
    for _ in 0..STORM_SIZE {
        let retry_request = RouteResolutionRequest {
            action_id: ActionId::new(),
            capability_id: request.capability_id.clone(),
            tenant_id: request.tenant_id.clone(),
            topology: Default::default(),
        };
        let assignment = registry.resolve(retry_request.clone()).await?;
        registry
            .settle(&assignment, RouteSettlement::OutcomeUnknown)
            .await?;
        retry_requests.push(retry_request);
    }

    let mut retries = tokio::task::JoinSet::new();
    for retry_request in retry_requests {
        let registry = registry.clone();
        retries.spawn(async move { registry.resolve(retry_request).await });
    }
    let mut admitted = Vec::new();
    let mut rejected = 0_usize;
    while let Some(result) = retries.join_next().await {
        match result? {
            Ok(assignment) => admitted.push(assignment),
            Err(RegistryError::CapacityExceeded {
                scope: AdmissionScopeKind::TenantRetry,
                ..
            }) => rejected += 1,
            Err(error) => return Err(error.into()),
        }
    }
    assert_eq!(admitted.len(), RETRY_BUDGET);
    assert_eq!(rejected, STORM_SIZE - RETRY_BUDGET);
    for assignment in admitted {
        registry
            .settle(&assignment, RouteSettlement::Completed)
            .await?;
    }
    Ok(())
}

fn unique_digest() -> String {
    digest_json(&json!({ "nonce": Uuid::now_v7() })).expect("fixture digest")
}
