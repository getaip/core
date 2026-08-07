//! Opt-in fleet-scale qualification against a real PostgreSQL instance.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used, clippy::panic)]

use aip_connector_registry::{
    ActionTargetResolver, AdmissionPolicy, AdmissionScopeKind, ArtifactAttestation,
    ArtifactCheckStatus, CapabilityBinding, CapabilityCatalogProvider, CapabilityCatalogQuery,
    CapabilityDefinition, CatalogReadContext, ConnectorFleetStatusProvider, ConnectorInstance,
    ConnectorInstanceId, ConnectorInstanceStatus, ConnectorRegistryAdmin, ConnectorReplica,
    ConnectorReplicaId, ConnectorReplicaStatus, ConnectorTypeId, ConnectorVersion,
    ConnectorVersionId, ConnectorVersionStatus, RegistryError, RouteResolutionRequest,
    RouteSettlement, schema_bundle_digest,
};
use aip_connector_registry_postgres::PostgresConnectorRegistry;
use aip_core::{
    ActionId, Capability, CapabilityId, CapabilityKind, Manifest, Principal, PrincipalId,
    PrincipalKind, ProfileId,
};
use serde_json::{Value, json};
use sqlx_core::{query::query, row::Row};
use sqlx_postgres::Postgres;
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
    time::Instant,
};
use time::{Duration, OffsetDateTime};
use tokio::sync::Barrier;
use uuid::Uuid;

const TENANT_COUNT: i64 = 100;
const CAPABILITIES_PER_VERSION: i64 = 100;
const BINDINGS_PER_INSTANCE: i64 = 10;
const SCALE_SLO_PROFILE: &str = "aip-fleet-slo-v1";
const MAX_SEED_MILLIS: u128 = 60_000;
const MAX_CATALOG_P99_MICROS: u64 = 2_000_000;
const MAX_ROUTE_P99_MICROS: u64 = 3_000_000;
const MIN_ROUTE_THROUGHPUT_PER_SECOND: f64 = 100.0;
const MAX_PROCESS_RSS_KIB: u64 = 512 * 1024;
const MAX_DATABASE_GROWTH_BYTES: u64 = 1024 * 1024 * 1024;

#[tokio::test]
async fn indexed_catalog_and_routing_remain_bounded_at_fleet_scale()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = std::env::var("AIP_POSTGRES_SCALE_TEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("AIP_POSTGRES_SCALE_TEST_URL is not set; skipping fleet-scale qualification");
        return Ok(());
    };
    let type_count = positive_env_i64("AIP_SCALE_CONNECTOR_TYPES", 1_000)?;
    let capability_count = positive_env_i64("AIP_SCALE_CAPABILITIES", 1_000)?;
    let instance_count = positive_env_i64("AIP_SCALE_INSTANCES", 10_000)?;
    let route_count = positive_env_usize("AIP_SCALE_CONCURRENT_ROUTES", 500)?;
    let environment_label = bounded_environment_label()?;
    assert!(
        capability_count >= CAPABILITIES_PER_VERSION,
        "scale test needs at least {CAPABILITIES_PER_VERSION} capabilities"
    );
    assert!(
        instance_count >= type_count,
        "scale test needs at least one instance per connector type"
    );
    let run = Uuid::now_v7().simple().to_string();
    let scale_policy_ref = format!("quota:scale:{run}");
    let registry = PostgresConnectorRegistry::connect(&database_url).await?;
    let postgres_environment = postgres_environment(&registry).await?;
    let database_size_before = database_size_bytes(&registry).await?;
    let mut max_rss_kib = process_rss_kib().unwrap_or_default();
    let mut scale_policy = AdmissionPolicy::fleet(scale_policy_ref.clone());
    scale_policy.max_global_in_flight = u32::MAX;
    scale_policy.max_tenant_in_flight = u32::MAX;
    scale_policy.max_connector_type_in_flight = u32::MAX;
    scale_policy.max_instance_in_flight = u32::MAX;
    scale_policy.max_binding_in_flight = u32::MAX;
    scale_policy.max_tenant_retry_in_flight = u32::MAX;
    registry.put_admission_policy(scale_policy).await?;
    let seeded_at = Instant::now();
    seed_scale_fleet(
        &registry,
        &run,
        type_count,
        capability_count,
        instance_count,
        &scale_policy_ref,
    )
    .await?;
    exercise_version_rollout(&registry, &run, type_count).await?;
    exercise_noisy_tenant_isolation(
        &registry,
        &run,
        type_count,
        capability_count,
        &scale_policy_ref,
    )
    .await?;
    exercise_bounded_retry_storm_at_scale(
        &registry,
        &run,
        type_count,
        capability_count,
        &scale_policy_ref,
    )
    .await?;
    let seed_elapsed_ms = seeded_at.elapsed().as_millis();
    eprintln!(
        "seeded types={type_count} capabilities={capability_count} instances={instance_count} bindings={} elapsed_ms={}",
        instance_count * BINDINGS_PER_INSTANCE,
        seed_elapsed_ms
    );
    max_rss_kib = max_rss_kib.max(process_rss_kib().unwrap_or_default());

    let tenant_id = scale_tenant_id(&run, 1);
    let catalog_started = Instant::now();
    let mut cursor = None;
    let mut catalog_revision = None;
    let mut ids = BTreeSet::new();
    let mut total = None;
    loop {
        let page = registry
            .query(
                CapabilityCatalogQuery {
                    cursor,
                    limit: 50,
                    ..CapabilityCatalogQuery::default()
                },
                &CatalogReadContext::for_tenant(&tenant_id),
            )
            .await?;
        assert!(page.capabilities.len() <= 50);
        if let Some(revision) = catalog_revision {
            assert_eq!(page.catalog_revision, revision);
        } else {
            catalog_revision = Some(page.catalog_revision);
        }
        if let Some(expected_total) = total {
            assert_eq!(page.total, expected_total);
        } else {
            total = Some(page.total);
        }
        for definition in page.capabilities {
            assert!(ids.insert(definition.capability.id));
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(u64::try_from(ids.len())?, total.unwrap_or_default());
    eprintln!(
        "catalog tenant={} total={} page_limit=50 elapsed_ms={}",
        tenant_id,
        ids.len(),
        catalog_started.elapsed().as_millis()
    );
    max_rss_kib = max_rss_kib.max(process_rss_kib().unwrap_or_default());

    let parallel_catalog_started = Instant::now();
    let mut catalog_reads = tokio::task::JoinSet::new();
    for tenant_no in 1..=TENANT_COUNT.min(32) {
        let registry = registry.clone();
        let tenant_id = scale_tenant_id(&run, tenant_no);
        catalog_reads.spawn(async move {
            let started = Instant::now();
            let page = registry
                .query(
                    CapabilityCatalogQuery {
                        limit: 50,
                        ..CapabilityCatalogQuery::default()
                    },
                    &CatalogReadContext::for_tenant(tenant_id),
                )
                .await?;
            Ok::<_, aip_connector_registry::RegistryError>((
                page.capabilities.len(),
                elapsed_micros(started),
            ))
        });
    }
    let mut catalog_latencies_us = Vec::new();
    while let Some(result) = catalog_reads.join_next().await {
        let (page_size, latency_us) = result??;
        assert!(page_size <= 50);
        catalog_latencies_us.push(latency_us);
    }
    eprintln!(
        "parallel catalog reads={} elapsed_ms={}",
        catalog_latencies_us.len(),
        parallel_catalog_started.elapsed().as_millis()
    );

    let routed_capability = scale_capability_id(&run, 1);
    let eligible_replicas =
        eligible_replica_count(&registry, &tenant_id, &routed_capability).await?;
    let routing_started = Instant::now();
    let mut routes = tokio::task::JoinSet::new();
    for _ in 0..route_count {
        let registry = registry.clone();
        let tenant_id = tenant_id.clone();
        let capability_id = routed_capability.clone();
        routes.spawn(async move {
            let started = Instant::now();
            let assignment = registry
                .resolve(RouteResolutionRequest {
                    action_id: ActionId::new(),
                    capability_id,
                    tenant_id,
                    topology: Default::default(),
                })
                .await?;
            Ok::<_, aip_connector_registry::RegistryError>((assignment, elapsed_micros(started)))
        });
    }
    let mut assignments = Vec::with_capacity(route_count);
    let mut route_latencies_us = Vec::with_capacity(route_count);
    while let Some(outcome) = routes.join_next().await {
        let (assignment, latency_us) = outcome??;
        assignments.push(assignment);
        route_latencies_us.push(latency_us);
    }
    let routing_elapsed = routing_started.elapsed();
    assert_eq!(assignments.len(), route_count);
    let mut distribution = BTreeMap::<ConnectorReplicaId, usize>::new();
    for assignment in &assignments {
        *distribution
            .entry(assignment.replica_id.clone())
            .or_default() += 1;
    }
    if route_count >= eligible_replicas {
        assert_eq!(
            distribution.len(),
            eligible_replicas,
            "concurrent routing must cover every eligible replica"
        );
    }
    let minimum = distribution.values().min().copied().unwrap_or_default();
    let maximum = distribution.values().max().copied().unwrap_or_default();
    assert!(
        maximum.saturating_sub(minimum) <= 3,
        "least-loaded routing is imbalanced: {distribution:?}"
    );
    for assignment in &assignments {
        registry
            .settle(assignment, RouteSettlement::Completed)
            .await?;
    }
    let active_row = query::<Postgres>(
        "SELECT COALESCE(SUM(active_assignments), 0)::BIGINT AS active \
         FROM aip_connector_replicas WHERE replica_id LIKE $1",
    )
    .bind(format!("crepl_scale_{run}_%"))
    .fetch_one(registry.pool())
    .await?;
    let active: i64 = active_row.try_get("active")?;
    assert_eq!(active, 0, "every fenced reservation must be released");
    exercise_retry_and_credential_rotation(&registry, &assignments, &tenant_id, &routed_capability)
        .await?;
    eprintln!(
        "routing actions={} replicas={} elapsed_ms={} p50_us={} p95_us={} p99_us={}",
        route_count,
        distribution.len(),
        routing_elapsed.as_millis(),
        percentile(&route_latencies_us, 50),
        percentile(&route_latencies_us, 95),
        percentile(&route_latencies_us, 99)
    );
    max_rss_kib = max_rss_kib.max(process_rss_kib().unwrap_or_default());

    let plan = routing_plan(&registry, &tenant_id, &routed_capability).await?;
    assert!(
        !plan.contains("Seq Scan on aip_tenant_capability_bindings"),
        "binding lookup scanned the fleet:\n{plan}"
    );
    assert!(
        !plan.contains("Seq Scan on aip_connector_replicas"),
        "replica lookup scanned the fleet:\n{plan}"
    );
    assert!(
        plan.contains("aip_tenant_capability_bindings_pkey")
            || plan.contains("aip_tenant_capability_bindings_routing_idx")
            || plan.contains("aip_tenant_capability_bindings_capability_fk_idx"),
        "binding lookup did not use an indexed path:\n{plan}"
    );
    eprintln!("routing query plan:\n{plan}");

    let expired_replicas = exercise_lease_churn(&registry, &run, instance_count).await?;

    let database_size_after = database_size_bytes(&registry).await?;
    let elapsed_seconds = routing_elapsed.as_secs_f64().max(f64::EPSILON);
    let catalog_p99_us = percentile(&catalog_latencies_us, 99);
    let route_p99_us = percentile(&route_latencies_us, 99);
    let route_throughput_per_second = route_count as f64 / elapsed_seconds;
    let database_growth_bytes = database_size_after.saturating_sub(database_size_before);
    assert!(
        seed_elapsed_ms <= MAX_SEED_MILLIS,
        "{SCALE_SLO_PROFILE} seed time exceeded: {seed_elapsed_ms}ms > {MAX_SEED_MILLIS}ms"
    );
    assert!(
        catalog_p99_us <= MAX_CATALOG_P99_MICROS,
        "{SCALE_SLO_PROFILE} catalog p99 exceeded: {catalog_p99_us}us > {MAX_CATALOG_P99_MICROS}us"
    );
    assert!(
        route_p99_us <= MAX_ROUTE_P99_MICROS,
        "{SCALE_SLO_PROFILE} route p99 exceeded: {route_p99_us}us > {MAX_ROUTE_P99_MICROS}us"
    );
    assert!(
        route_throughput_per_second >= MIN_ROUTE_THROUGHPUT_PER_SECOND,
        "{SCALE_SLO_PROFILE} route throughput regressed: {route_throughput_per_second:.2}/s < {MIN_ROUTE_THROUGHPUT_PER_SECOND:.2}/s"
    );
    assert!(
        max_rss_kib <= MAX_PROCESS_RSS_KIB,
        "{SCALE_SLO_PROFILE} process RSS exceeded: {max_rss_kib}KiB > {MAX_PROCESS_RSS_KIB}KiB"
    );
    assert!(
        database_growth_bytes <= MAX_DATABASE_GROWTH_BYTES,
        "{SCALE_SLO_PROFILE} database growth exceeded: {database_growth_bytes}B > {MAX_DATABASE_GROWTH_BYTES}B"
    );
    let result = json!({
        "run": run,
        "qualification": {
            "environment_label": environment_label,
            "target_os": std::env::consts::OS,
            "target_arch": std::env::consts::ARCH,
            "postgres": postgres_environment,
            "measurement_scope": "repeatable CI regression gate; not a universal deployment SLO"
        },
        "slo": {
            "profile": SCALE_SLO_PROFILE,
            "passed": true,
            "thresholds": {
                "seed_max_ms": MAX_SEED_MILLIS,
                "catalog_p99_max_us": MAX_CATALOG_P99_MICROS,
                "route_p99_max_us": MAX_ROUTE_P99_MICROS,
                "route_throughput_min_per_second": MIN_ROUTE_THROUGHPUT_PER_SECOND,
                "process_rss_max_kib": MAX_PROCESS_RSS_KIB,
                "database_growth_max_bytes": MAX_DATABASE_GROWTH_BYTES
            }
        },
        "dataset": {
            "connector_types": type_count,
            "capabilities": capability_count,
            "instances": instance_count,
            "replicas": instance_count,
            "bindings": instance_count * BINDINGS_PER_INSTANCE,
            "version_capability_providers": type_count * CAPABILITIES_PER_VERSION
        },
        "catalog": {
            "parallel_reads": catalog_latencies_us.len(),
            "p50_us": percentile(&catalog_latencies_us, 50),
            "p95_us": percentile(&catalog_latencies_us, 95),
            "p99_us": catalog_p99_us
        },
        "routing": {
            "actions": route_count,
            "errors": 0,
            "eligible_replicas": eligible_replicas,
            "p50_us": percentile(&route_latencies_us, 50),
            "p95_us": percentile(&route_latencies_us, 95),
            "p99_us": route_p99_us,
            "throughput_per_second": route_throughput_per_second
        },
        "lifecycle": {
            "credential_rotation_pinned_existing_routes": true,
            "version_rollout": true,
            "noisy_tenant_isolated": true,
            "retry_storm_bounded": true,
            "expired_replicas": expired_replicas
        },
        "resources": {
            "process_rss_kib_observed_max": max_rss_kib,
            "database_size_before_bytes": database_size_before,
            "database_size_after_bytes": database_size_after,
            "database_growth_bytes": database_growth_bytes,
            "available_parallelism": std::thread::available_parallelism()
                .map(std::num::NonZeroUsize::get)
                .unwrap_or(1),
            "pool": registry.pool_snapshot()
        }
    });
    eprintln!("AIP_SCALE_RESULT={result}");
    cleanup_scale_fleet(&registry, &run, &scale_policy_ref).await?;
    Ok(())
}

async fn exercise_noisy_tenant_isolation(
    registry: &PostgresConnectorRegistry,
    run: &str,
    type_count: i64,
    capability_count: i64,
    policy_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    const TENANT_BUDGET: usize = 4;
    const NOISY_REQUESTS: usize = 64;
    const HEALTHY_REQUESTS: usize = 4;

    let mut policy = AdmissionPolicy::fleet(policy_ref);
    policy.revision = 2;
    policy.max_tenant_in_flight = u32::try_from(TENANT_BUDGET)?;
    policy.max_instance_in_flight = u32::MAX;
    policy.max_binding_in_flight = u32::MAX;
    policy.max_tenant_retry_in_flight = u32::MAX;
    registry.put_admission_policy(policy).await?;

    let noisy_tenant = scale_tenant_id(run, 1);
    let noisy_capability = tenant_primary_capability(run, 1, type_count, capability_count);
    let healthy_tenant = scale_tenant_id(run, 2);
    let healthy_capability = tenant_primary_capability(run, 2, type_count, capability_count);
    let barrier = Arc::new(Barrier::new(NOISY_REQUESTS + HEALTHY_REQUESTS + 1));
    let mut noisy = tokio::task::JoinSet::new();
    for _ in 0..NOISY_REQUESTS {
        let registry = registry.clone();
        let tenant_id = noisy_tenant.clone();
        let capability_id = noisy_capability.clone();
        let barrier = barrier.clone();
        noisy.spawn(async move {
            barrier.wait().await;
            registry
                .resolve(RouteResolutionRequest {
                    action_id: ActionId::new(),
                    capability_id,
                    tenant_id,
                    topology: Default::default(),
                })
                .await
        });
    }
    let mut healthy = tokio::task::JoinSet::new();
    for _ in 0..HEALTHY_REQUESTS {
        let registry = registry.clone();
        let tenant_id = healthy_tenant.clone();
        let capability_id = healthy_capability.clone();
        let barrier = barrier.clone();
        healthy.spawn(async move {
            barrier.wait().await;
            registry
                .resolve(RouteResolutionRequest {
                    action_id: ActionId::new(),
                    capability_id,
                    tenant_id,
                    topology: Default::default(),
                })
                .await
        });
    }
    barrier.wait().await;

    let mut noisy_admitted = Vec::new();
    let mut noisy_rejected = 0_usize;
    while let Some(result) = noisy.join_next().await {
        match result? {
            Ok(assignment) => noisy_admitted.push(assignment),
            Err(RegistryError::CapacityExceeded {
                scope: AdmissionScopeKind::Tenant,
                ..
            }) => noisy_rejected = noisy_rejected.saturating_add(1),
            Err(error) => return Err(error.into()),
        }
    }
    let mut healthy_admitted = Vec::new();
    while let Some(result) = healthy.join_next().await {
        healthy_admitted.push(result??);
    }
    assert_eq!(noisy_admitted.len(), TENANT_BUDGET);
    assert_eq!(noisy_rejected, NOISY_REQUESTS - TENANT_BUDGET);
    assert_eq!(healthy_admitted.len(), HEALTHY_REQUESTS);
    for assignment in noisy_admitted.iter().chain(&healthy_admitted) {
        registry
            .settle(assignment, RouteSettlement::Completed)
            .await?;
    }
    eprintln!(
        "tenant isolation noisy_admitted={} noisy_rejected={} healthy_admitted={}",
        noisy_admitted.len(),
        noisy_rejected,
        healthy_admitted.len()
    );
    Ok(())
}

async fn exercise_bounded_retry_storm_at_scale(
    registry: &PostgresConnectorRegistry,
    run: &str,
    type_count: i64,
    capability_count: i64,
    policy_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    const RETRY_BUDGET: usize = 8;
    const RETRY_REQUESTS: usize = 64;
    const HEALTHY_REQUESTS: usize = 8;

    let mut policy = AdmissionPolicy::fleet(policy_ref);
    policy.revision = 3;
    policy.max_tenant_in_flight = u32::MAX;
    policy.max_instance_in_flight = u32::MAX;
    policy.max_binding_in_flight = u32::MAX;
    policy.max_tenant_retry_in_flight = u32::try_from(RETRY_BUDGET)?;
    registry.put_admission_policy(policy).await?;

    let retry_tenant = scale_tenant_id(run, 1);
    let retry_capability = tenant_primary_capability(run, 1, type_count, capability_count);
    let healthy_tenant = scale_tenant_id(run, 2);
    let healthy_capability = tenant_primary_capability(run, 2, type_count, capability_count);
    let mut retry_requests = Vec::with_capacity(RETRY_REQUESTS);
    for _ in 0..RETRY_REQUESTS {
        let request = RouteResolutionRequest {
            action_id: ActionId::new(),
            capability_id: retry_capability.clone(),
            tenant_id: retry_tenant.clone(),
            topology: Default::default(),
        };
        let assignment = registry.resolve(request.clone()).await?;
        registry
            .settle(&assignment, RouteSettlement::OutcomeUnknown)
            .await?;
        retry_requests.push(request);
    }

    let barrier = Arc::new(Barrier::new(RETRY_REQUESTS + HEALTHY_REQUESTS + 1));
    let mut retries = tokio::task::JoinSet::new();
    for request in retry_requests {
        let registry = registry.clone();
        let barrier = barrier.clone();
        retries.spawn(async move {
            barrier.wait().await;
            registry.resolve(request).await
        });
    }
    let mut healthy = tokio::task::JoinSet::new();
    for _ in 0..HEALTHY_REQUESTS {
        let registry = registry.clone();
        let barrier = barrier.clone();
        let tenant_id = healthy_tenant.clone();
        let capability_id = healthy_capability.clone();
        healthy.spawn(async move {
            barrier.wait().await;
            registry
                .resolve(RouteResolutionRequest {
                    action_id: ActionId::new(),
                    capability_id,
                    tenant_id,
                    topology: Default::default(),
                })
                .await
        });
    }
    barrier.wait().await;

    let mut retry_admitted = Vec::new();
    let mut retry_rejected = 0_usize;
    while let Some(result) = retries.join_next().await {
        match result? {
            Ok(assignment) => retry_admitted.push(assignment),
            Err(RegistryError::CapacityExceeded {
                scope: AdmissionScopeKind::TenantRetry,
                ..
            }) => retry_rejected = retry_rejected.saturating_add(1),
            Err(error) => return Err(error.into()),
        }
    }
    let mut healthy_admitted = Vec::new();
    while let Some(result) = healthy.join_next().await {
        healthy_admitted.push(result??);
    }
    assert_eq!(retry_admitted.len(), RETRY_BUDGET);
    assert_eq!(retry_rejected, RETRY_REQUESTS - RETRY_BUDGET);
    assert_eq!(healthy_admitted.len(), HEALTHY_REQUESTS);
    for assignment in retry_admitted.iter().chain(&healthy_admitted) {
        registry
            .settle(assignment, RouteSettlement::Completed)
            .await?;
    }

    let mut restored = AdmissionPolicy::fleet(policy_ref);
    restored.revision = 4;
    restored.max_tenant_in_flight = u32::MAX;
    restored.max_instance_in_flight = u32::MAX;
    restored.max_binding_in_flight = u32::MAX;
    restored.max_tenant_retry_in_flight = u32::MAX;
    registry.put_admission_policy(restored).await?;
    eprintln!(
        "retry isolation retry_admitted={} retry_rejected={} healthy_admitted={}",
        retry_admitted.len(),
        retry_rejected,
        healthy_admitted.len()
    );
    Ok(())
}

fn tenant_primary_capability(
    run: &str,
    tenant_no: i64,
    type_count: i64,
    capability_count: i64,
) -> CapabilityId {
    let type_no = ((tenant_no - 1).rem_euclid(type_count)) + 1;
    let capability_no =
        (((type_no - 1) * CAPABILITIES_PER_VERSION).rem_euclid(capability_count)) + 1;
    scale_capability_id(run, capability_no)
}

async fn eligible_replica_count(
    registry: &PostgresConnectorRegistry,
    tenant_id: &str,
    capability_id: &CapabilityId,
) -> Result<usize, Box<dyn std::error::Error>> {
    let row = query::<Postgres>(
        r#"
        SELECT COUNT(*)::BIGINT AS total
        FROM aip_tenant_capability_bindings b
        JOIN aip_connector_instances i ON i.instance_id = b.instance_id
        JOIN aip_connector_versions v ON v.version_id = i.version_id
        JOIN aip_connector_types t ON t.type_id = i.type_id
        JOIN aip_connector_version_capabilities vc
          ON vc.version_id = v.version_id AND vc.capability_id = b.capability_id
        JOIN aip_connector_replicas r
          ON r.instance_id = i.instance_id AND r.version_id = v.version_id
        WHERE b.tenant_id = $1 AND b.capability_id = $2
          AND b.enabled = TRUE AND i.tenant_id = b.tenant_id
          AND i.status = 'enabled' AND v.status = 'active'
          AND v.supply_chain_qualified = TRUE AND t.enabled = TRUE
          AND r.status = 'ready' AND r.lease_expires_at_ms > $3
          AND r.active_assignments < r.capacity
        "#,
    )
    .bind(tenant_id)
    .bind(capability_id.as_str())
    .bind(unix_ms(OffsetDateTime::now_utc())?)
    .fetch_one(registry.pool())
    .await?;
    let total: i64 = row.try_get("total")?;
    Ok(usize::try_from(total)?)
}

async fn exercise_version_rollout(
    registry: &PostgresConnectorRegistry,
    run: &str,
    type_count: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    let type_id = format!("ctype_scale_{run}_{type_count:06}");
    let old_version_id = format!("cver_scale_{run}_{type_count:06}");
    let new_version_id = format!("cver_scale_{run}_rollout_{type_count:06}");
    let instance_id = format!("cinst_scale_{run}_{type_count:08}");
    let old_replica_id = format!("crepl_scale_{run}_{type_count:08}");
    let new_replica_id = format!("crepl_scale_{run}_rollout_{type_count:08}");
    let now_ms = unix_ms(OffsetDateTime::now_utc())?;
    let lease_ms = unix_ms(OffsetDateTime::now_utc() + Duration::hours(1))?;
    let artifact_digest = format!(
        "sha256:{}{}",
        md5_compatible_fragment(&format!("{run}:rollout:artifact")),
        md5_compatible_fragment(&format!("{run}:rollout:artifact:extra"))
    );
    let manifest_digest = format!(
        "sha256:{}{}",
        md5_compatible_fragment(&format!("{run}:rollout:manifest")),
        md5_compatible_fragment(&format!("{run}:rollout:manifest:extra"))
    );
    let inserted = query::<Postgres>(
        r#"
        INSERT INTO aip_connector_versions
            (version_id, type_id, version, status, artifact_digest, manifest_digest,
             supply_chain_qualified, record, admitted_at_ms)
        SELECT $2, type_id, '1.0.1', 'active', $3, $4, TRUE,
               record || jsonb_build_object(
                   'id', $2,
                   'version', '1.0.1',
                   'status', 'active',
                   'manifest_digest', $4,
                   'attestation', (record->'attestation') || jsonb_build_object(
                       'artifact_digest', $3,
                       'signature_ref', format('sigstore:scale:%s:rollout', $5)
                   )
               ),
               $6
        FROM aip_connector_versions
        WHERE version_id = $1 AND type_id = $7
        "#,
    )
    .bind(&old_version_id)
    .bind(&new_version_id)
    .bind(&artifact_digest)
    .bind(&manifest_digest)
    .bind(run)
    .bind(now_ms)
    .bind(&type_id)
    .execute(registry.pool())
    .await?;
    assert_eq!(inserted.rows_affected(), 1);
    query::<Postgres>(
        r#"
        INSERT INTO aip_connector_version_capabilities
            (version_id, capability_id, contract_digest)
        SELECT $2, capability_id, contract_digest
        FROM aip_connector_version_capabilities
        WHERE version_id = $1
        "#,
    )
    .bind(&old_version_id)
    .bind(&new_version_id)
    .execute(registry.pool())
    .await?;
    query::<Postgres>(
        r#"
        INSERT INTO aip_connector_version_profiles (version_id, profile_id)
        SELECT $2, profile_id
        FROM aip_connector_version_profiles
        WHERE version_id = $1
        "#,
    )
    .bind(&old_version_id)
    .bind(&new_version_id)
    .execute(registry.pool())
    .await?;
    let updated_instance = query::<Postgres>(
        r#"
        UPDATE aip_connector_instances
        SET version_id = $2,
            config_revision = config_revision + 1,
            record = jsonb_set(
                jsonb_set(record, '{version_id}', to_jsonb($2::TEXT)),
                '{config_revision}', to_jsonb(config_revision + 1)
            ),
            updated_at_ms = $3
        WHERE instance_id = $1 AND type_id = $4
        "#,
    )
    .bind(&instance_id)
    .bind(&new_version_id)
    .bind(now_ms)
    .bind(&type_id)
    .execute(registry.pool())
    .await?;
    assert_eq!(updated_instance.rows_affected(), 1);
    query::<Postgres>(
        r#"
        UPDATE aip_connector_replicas
        SET status = 'draining',
            record = jsonb_set(record, '{status}', '"draining"'::JSONB),
            updated_at_ms = $2
        WHERE replica_id = $1
        "#,
    )
    .bind(&old_replica_id)
    .bind(now_ms)
    .execute(registry.pool())
    .await?;
    let new_replica = query::<Postgres>(
        r#"
        INSERT INTO aip_connector_replicas
            (replica_id, instance_id, version_id, endpoint, status, lease_expires_at_ms,
             capacity, active_assignments, health_revision, record, updated_at_ms,
             consecutive_failures, circuit_open_until_ms)
        SELECT $2, instance_id, $3,
               format('https://%s.scale.invalid/aip/v1/messages', $2),
               'ready', $4, capacity, 0, health_revision + 1,
               record || jsonb_build_object(
                   'id', $2,
                   'version_id', $3,
                   'endpoint', format('https://%s.scale.invalid/aip/v1/messages', $2),
                   'status', 'ready',
                   'active_assignments', 0,
                   'health_revision', health_revision + 1,
                   'peer_principal_id', format('service:%s', $2),
                   'peer_did', format('did:key:%s', $2)
               ),
               $5, 0, 0
        FROM aip_connector_replicas
        WHERE replica_id = $1
        "#,
    )
    .bind(&old_replica_id)
    .bind(&new_replica_id)
    .bind(&new_version_id)
    .bind(lease_ms)
    .bind(now_ms)
    .execute(registry.pool())
    .await?;
    assert_eq!(new_replica.rows_affected(), 1);
    query::<Postgres>(
        "UPDATE aip_connector_catalog_revision SET revision = revision + 1, published_at_ms = $1 WHERE singleton = TRUE",
    )
    .bind(now_ms)
    .execute(registry.pool())
    .await?;
    let row = query::<Postgres>(
        r#"
        SELECT COUNT(*)::BIGINT AS ready_rollout
        FROM aip_connector_instances i
        JOIN aip_connector_replicas r
          ON r.instance_id = i.instance_id AND r.version_id = i.version_id
        WHERE i.instance_id = $1 AND i.version_id = $2
          AND r.replica_id = $3 AND r.status = 'ready'
        "#,
    )
    .bind(&instance_id)
    .bind(&new_version_id)
    .bind(&new_replica_id)
    .fetch_one(registry.pool())
    .await?;
    assert_eq!(row.try_get::<i64, _>("ready_rollout")?, 1);
    Ok(())
}

async fn exercise_retry_and_credential_rotation(
    registry: &PostgresConnectorRegistry,
    assignments: &[aip_connector_registry::RouteAssignment],
    tenant_id: &str,
    capability_id: &CapabilityId,
) -> Result<(), Box<dyn std::error::Error>> {
    let retry_count = assignments.len().min(100);
    let mut retries = tokio::task::JoinSet::new();
    for assignment in assignments.iter().take(retry_count).cloned() {
        let registry = registry.clone();
        retries.spawn(async move {
            let retried = registry
                .resolve(RouteResolutionRequest {
                    action_id: assignment.action_id.clone(),
                    capability_id: assignment.capability_id.clone(),
                    tenant_id: assignment.tenant_id.clone(),
                    topology: Default::default(),
                })
                .await?;
            if retried != assignment {
                return Err(aip_connector_registry::RegistryError::FenceLost);
            }
            registry.settle(&retried, RouteSettlement::Completed).await
        });
    }
    while let Some(result) = retries.join_next().await {
        result??;
    }

    let now_ms = unix_ms(OffsetDateTime::now_utc())?;
    let rotated = query::<Postgres>(
        r#"
        UPDATE aip_tenant_capability_bindings
        SET credential_revision_ref = 'credential-revision-2',
            policy_revision = policy_revision + 1,
            record = jsonb_set(
                jsonb_set(
                    record,
                    '{credential_revision_ref}',
                    '"credential-revision-2"'::JSONB
                ),
                '{policy_revision}',
                to_jsonb(policy_revision + 1)
            ),
            updated_at_ms = $3
        WHERE tenant_id = $1 AND capability_id = $2
        "#,
    )
    .bind(tenant_id)
    .bind(capability_id.as_str())
    .bind(now_ms)
    .execute(registry.pool())
    .await?;
    assert!(rotated.rows_affected() > 0);
    query::<Postgres>(
        "UPDATE aip_connector_catalog_revision SET revision = revision + 1, published_at_ms = $1 WHERE singleton = TRUE",
    )
    .bind(now_ms)
    .execute(registry.pool())
    .await?;

    let pinned = assignments
        .first()
        .ok_or_else(|| std::io::Error::other("scale routing produced no assignments"))?;
    let retried = registry
        .resolve(RouteResolutionRequest {
            action_id: pinned.action_id.clone(),
            capability_id: pinned.capability_id.clone(),
            tenant_id: pinned.tenant_id.clone(),
            topology: Default::default(),
        })
        .await?;
    assert_eq!(retried, *pinned);
    assert_eq!(
        retried.credential_revision_ref.as_deref(),
        Some("credential-revision-1")
    );
    registry
        .settle(&retried, RouteSettlement::Completed)
        .await?;
    let fresh = registry
        .resolve(RouteResolutionRequest {
            action_id: ActionId::new(),
            capability_id: capability_id.clone(),
            tenant_id: tenant_id.to_owned(),
            topology: Default::default(),
        })
        .await?;
    assert_eq!(
        fresh.credential_revision_ref.as_deref(),
        Some("credential-revision-2")
    );
    registry.settle(&fresh, RouteSettlement::Completed).await?;
    Ok(())
}

async fn exercise_lease_churn(
    registry: &PostgresConnectorRegistry,
    run: &str,
    instance_count: i64,
) -> Result<usize, Box<dyn std::error::Error>> {
    let target_count = instance_count.clamp(1, 1_000);
    let now_ms = unix_ms(OffsetDateTime::now_utc())?;
    let renewed = query::<Postgres>(
        r#"
        WITH targets AS (
            SELECT replica_id
            FROM aip_connector_replicas
            WHERE replica_id LIKE $1 AND status = 'ready'
            ORDER BY replica_id
            LIMIT $2
        )
        UPDATE aip_connector_replicas r
        SET lease_expires_at_ms = $3,
            health_revision = health_revision + 1,
            record = jsonb_set(
                record,
                '{health_revision}',
                to_jsonb(health_revision + 1)
            ),
            updated_at_ms = $4
        FROM targets
        WHERE r.replica_id = targets.replica_id
        "#,
    )
    .bind(format!("crepl_scale_{run}_%"))
    .bind(target_count)
    .bind(unix_ms(OffsetDateTime::now_utc() + Duration::hours(2))?)
    .bind(now_ms)
    .execute(registry.pool())
    .await?;
    assert_eq!(i64::try_from(renewed.rows_affected())?, target_count);
    let expired = query::<Postgres>(
        r#"
        WITH targets AS (
            SELECT replica_id
            FROM aip_connector_replicas
            WHERE replica_id LIKE $1 AND status = 'ready'
            ORDER BY replica_id
            LIMIT $2
        )
        UPDATE aip_connector_replicas r
        SET lease_expires_at_ms = $3, updated_at_ms = $3
        FROM targets
        WHERE r.replica_id = targets.replica_id
        "#,
    )
    .bind(format!("crepl_scale_{run}_%"))
    .bind(target_count)
    .bind(now_ms - 1)
    .execute(registry.pool())
    .await?;
    assert_eq!(i64::try_from(expired.rows_affected())?, target_count);
    let started = Instant::now();
    let mut transitioned = 0_usize;
    loop {
        let count = registry
            .expire_stale_replicas(OffsetDateTime::now_utc(), 200)
            .await?;
        transitioned = transitioned.saturating_add(count);
        if count < 200 {
            break;
        }
    }
    let scoped_expired: i64 = query::<Postgres>(
        r#"
        SELECT COUNT(*) AS expired
        FROM aip_connector_replicas
        WHERE replica_id LIKE $1 AND status = 'offline'
        "#,
    )
    .bind(format!("crepl_scale_{run}_%"))
    .fetch_one(registry.pool())
    .await?
    .try_get("expired")?;
    assert_eq!(scoped_expired, target_count);
    assert!(
        transitioned >= usize::try_from(scoped_expired)?,
        "global expiry count cannot be smaller than this run's expired replica count"
    );
    eprintln!(
        "lease churn renewed={} expired={} global_expired={} elapsed_ms={}",
        target_count,
        scoped_expired,
        transitioned,
        started.elapsed().as_millis()
    );
    Ok(usize::try_from(scoped_expired)?)
}

fn md5_compatible_fragment(value: &str) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(value.as_bytes());
    digest[..16]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

async fn seed_scale_fleet(
    registry: &PostgresConnectorRegistry,
    run: &str,
    type_count: i64,
    capability_count: i64,
    instance_count: i64,
    policy_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let now_ms = unix_ms(OffsetDateTime::now_utc())?;
    let type_rows = query::<Postgres>(
        r#"
        WITH generated AS (
            SELECT gs,
                   format('ctype_scale_%s_%s', $1, lpad(gs::TEXT, 6, '0')) AS type_id
            FROM generate_series(1, $2::BIGINT) AS gs
        )
        INSERT INTO aip_connector_types (type_id, name, owner, enabled, record, updated_at_ms)
        SELECT type_id,
               format('Scale connector type %s', gs),
               'AIP scale qualification',
               TRUE,
               jsonb_build_object(
                   'id', type_id,
                   'name', format('Scale connector type %s', gs),
                   'owner', 'AIP scale qualification',
                   'enabled', TRUE
               ),
               $3
        FROM generated
        "#,
    )
    .bind(run)
    .bind(type_count)
    .bind(now_ms)
    .execute(registry.pool())
    .await?;
    assert_eq!(i64::try_from(type_rows.rows_affected())?, type_count);

    let version_template = version_template();
    let version_rows = query::<Postgres>(
        r#"
        WITH generated AS (
            SELECT gs,
                   format('ctype_scale_%s_%s', $1, lpad(gs::TEXT, 6, '0')) AS type_id,
                   format('cver_scale_%s_%s', $1, lpad(gs::TEXT, 6, '0')) AS version_id,
                   'sha256:' || md5($1 || ':artifact:' || gs::TEXT) ||
                       md5($1 || ':artifact-extra:' || gs::TEXT) AS artifact_digest,
                   'sha256:' || md5($1 || ':manifest:' || gs::TEXT) ||
                       md5($1 || ':manifest-extra:' || gs::TEXT) AS manifest_digest,
                   'sha256:' || md5($1 || ':sbom:' || gs::TEXT) ||
                       md5($1 || ':sbom-extra:' || gs::TEXT) AS sbom_digest,
                   'sha256:' || md5($1 || ':provenance:' || gs::TEXT) ||
                       md5($1 || ':provenance-extra:' || gs::TEXT) AS provenance_digest
            FROM generate_series(1, $2::BIGINT) AS gs
        )
        INSERT INTO aip_connector_versions
            (version_id, type_id, version, status, artifact_digest, manifest_digest,
             supply_chain_qualified, record, admitted_at_ms)
        SELECT version_id,
               type_id,
               '1.0.0',
               'active',
               artifact_digest,
               manifest_digest,
               TRUE,
               $3::JSONB || jsonb_build_object(
                   'id', version_id,
                   'connector_type_id', type_id,
                   'version', '1.0.0',
                   'status', 'active',
                   'manifest_digest', manifest_digest,
                   'attestation', ($3::JSONB->'attestation') || jsonb_build_object(
                       'artifact_digest', artifact_digest,
                       'sbom_digest', sbom_digest,
                       'provenance_digest', provenance_digest,
                       'signature_ref', format('sigstore:scale:%s:%s', $1, gs)
                   )
               ),
               $4
        FROM generated
        "#,
    )
    .bind(run)
    .bind(type_count)
    .bind(version_template)
    .bind(now_ms)
    .execute(registry.pool())
    .await?;
    assert_eq!(i64::try_from(version_rows.rows_affected())?, type_count);

    let definition_template = capability_definition_template();
    let capability_rows = query::<Postgres>(
        r#"
        WITH generated AS (
            SELECT gs,
                   format('cap:scale:%s:%s', $1, lpad(gs::TEXT, 6, '0')) AS capability_id,
                   'sha256:' || md5($1 || ':contract:' || gs::TEXT) ||
                       md5($1 || ':contract-extra:' || gs::TEXT) AS contract_digest,
                   'sha256:' || md5($1 || ':schema:' || gs::TEXT) ||
                       md5($1 || ':schema-extra:' || gs::TEXT) AS schema_digest
            FROM generate_series(1, $2::BIGINT) AS gs
        )
        INSERT INTO aip_capability_definitions
            (capability_id, contract_digest, schema_digest, record)
        SELECT capability_id,
               contract_digest,
               schema_digest,
               $3::JSONB || jsonb_build_object(
                   'capability', ($3::JSONB->'capability') || jsonb_build_object(
                       'id', capability_id,
                       'name', format('Scale capability %s', gs),
                       'description', format('Fleet scale fixture %s', gs)
                   ),
                   'contract_digest', contract_digest,
                   'schema_digest', schema_digest
               )
        FROM generated
        "#,
    )
    .bind(run)
    .bind(capability_count)
    .bind(definition_template)
    .execute(registry.pool())
    .await?;
    assert_eq!(
        i64::try_from(capability_rows.rows_affected())?,
        capability_count
    );

    let provider_rows = query::<Postgres>(
        r#"
        WITH generated AS (
            SELECT type_no,
                   slot,
                   format('cver_scale_%s_%s', $1, lpad(type_no::TEXT, 6, '0')) AS version_id,
                   format(
                       'cap:scale:%s:%s',
                       $1,
                       lpad(((((type_no - 1) * $4 + slot - 1) % $3) + 1)::TEXT, 6, '0')
                   ) AS capability_id
            FROM generate_series(1, $2::BIGINT) AS type_no
            CROSS JOIN generate_series(1, $4::BIGINT) AS slot
        )
        INSERT INTO aip_connector_version_capabilities
            (version_id, capability_id, contract_digest)
        SELECT g.version_id, g.capability_id, d.contract_digest
        FROM generated g
        JOIN aip_capability_definitions d ON d.capability_id = g.capability_id
        "#,
    )
    .bind(run)
    .bind(type_count)
    .bind(capability_count)
    .bind(CAPABILITIES_PER_VERSION)
    .execute(registry.pool())
    .await?;
    assert_eq!(
        i64::try_from(provider_rows.rows_affected())?,
        type_count * CAPABILITIES_PER_VERSION
    );
    query::<Postgres>(
        r#"
        INSERT INTO aip_connector_version_profiles (version_id, profile_id)
        SELECT format('cver_scale_%s_%s', $1, lpad(gs::TEXT, 6, '0')),
               'aip.native.http.v1'
        FROM generate_series(1, $2::BIGINT) AS gs
        "#,
    )
    .bind(run)
    .bind(type_count)
    .execute(registry.pool())
    .await?;

    let instance_template = serde_json::to_value(ConnectorInstance {
        id: ConnectorInstanceId::trusted("cinst_scale_template"),
        connector_type_id: ConnectorTypeId::trusted("ctype_scale_template"),
        version_id: ConnectorVersionId::trusted("cver_scale_template"),
        tenant_id: "tenant-scale-template".to_owned(),
        config_revision: 1,
        secret_provider_ref: "vault://scale/template".to_owned(),
        status: ConnectorInstanceStatus::Enabled,
    })?;
    let instance_rows = query::<Postgres>(
        r#"
        WITH generated AS (
            SELECT gs,
                   (((gs - 1) % $3) + 1) AS type_no,
                   (((gs - 1) % $4) + 1) AS tenant_no
            FROM generate_series(1, $2::BIGINT) AS gs
        ), records AS (
            SELECT gs,
                   format('cinst_scale_%s_%s', $1, lpad(gs::TEXT, 8, '0')) AS instance_id,
                   format('ctype_scale_%s_%s', $1, lpad(type_no::TEXT, 6, '0')) AS type_id,
                   format('cver_scale_%s_%s', $1, lpad(type_no::TEXT, 6, '0')) AS version_id,
                   format('tenant-scale-%s-%s', $1, lpad(tenant_no::TEXT, 3, '0')) AS tenant_id
            FROM generated
        )
        INSERT INTO aip_connector_instances
            (instance_id, type_id, version_id, tenant_id, config_revision,
             secret_provider_ref, status, record, updated_at_ms)
        SELECT instance_id,
               type_id,
               version_id,
               tenant_id,
               1,
               format('vault://%s/%s', tenant_id, instance_id),
               'enabled',
               $5::JSONB || jsonb_build_object(
                   'id', instance_id,
                   'connector_type_id', type_id,
                   'version_id', version_id,
                   'tenant_id', tenant_id,
                   'secret_provider_ref', format('vault://%s/%s', tenant_id, instance_id)
               ),
               $6
        FROM records
        "#,
    )
    .bind(run)
    .bind(instance_count)
    .bind(type_count)
    .bind(TENANT_COUNT)
    .bind(instance_template)
    .bind(now_ms)
    .execute(registry.pool())
    .await?;
    assert_eq!(
        i64::try_from(instance_rows.rows_affected())?,
        instance_count
    );

    let replica_template = serde_json::to_value(ConnectorReplica {
        id: ConnectorReplicaId::trusted("crepl_scale_template"),
        instance_id: ConnectorInstanceId::trusted("cinst_scale_template"),
        version_id: ConnectorVersionId::trusted("cver_scale_template"),
        endpoint: "https://scale.invalid/aip/v1/messages".to_owned(),
        peer_principal_id: PrincipalId::trusted("service:scale-connector-host"),
        peer_principal_kind: PrincipalKind::Service,
        peer_did: "did:key:scale-template".to_owned(),
        trust_domain: "scale.test".to_owned(),
        transport_profile: ProfileId::from("aip.native.http.v1"),
        topology: Default::default(),
        status: ConnectorReplicaStatus::Ready,
        lease_expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
        capacity: 100,
        active_assignments: 0,
        health_revision: 1,
        last_control_request_id: None,
        last_control_request_digest: None,
    })?;
    let lease_ms = unix_ms(OffsetDateTime::now_utc() + Duration::hours(1))?;
    let replica_rows = query::<Postgres>(
        r#"
        WITH generated AS (
            SELECT gs, (((gs - 1) % $3) + 1) AS type_no
            FROM generate_series(1, $2::BIGINT) AS gs
        ), records AS (
            SELECT gs,
                   format('crepl_scale_%s_%s', $1, lpad(gs::TEXT, 8, '0')) AS replica_id,
                   format('cinst_scale_%s_%s', $1, lpad(gs::TEXT, 8, '0')) AS instance_id,
                   format('cver_scale_%s_%s', $1, lpad(type_no::TEXT, 6, '0')) AS version_id
            FROM generated
        )
        INSERT INTO aip_connector_replicas
            (replica_id, instance_id, version_id, endpoint, status, lease_expires_at_ms,
             capacity, active_assignments, health_revision, record, updated_at_ms)
        SELECT replica_id,
               instance_id,
               version_id,
               format('https://%s.scale.invalid/aip/v1/messages', replica_id),
               'ready',
               $5,
               100,
               0,
               1,
               $4::JSONB || jsonb_build_object(
                   'id', replica_id,
                   'instance_id', instance_id,
                   'version_id', version_id,
                   'endpoint', format('https://%s.scale.invalid/aip/v1/messages', replica_id),
                   'peer_principal_id', format('service:%s', replica_id),
                   'peer_did', format('did:key:%s', replica_id)
               ),
               $6
        FROM records
        "#,
    )
    .bind(run)
    .bind(instance_count)
    .bind(type_count)
    .bind(replica_template)
    .bind(lease_ms)
    .bind(now_ms)
    .execute(registry.pool())
    .await?;
    assert_eq!(i64::try_from(replica_rows.rows_affected())?, instance_count);

    let binding_template = serde_json::to_value(CapabilityBinding {
        tenant_id: "tenant-scale-template".to_owned(),
        capability_id: CapabilityId::trusted("cap:scale:template:000001"),
        instance_id: ConnectorInstanceId::trusted("cinst_scale_template"),
        priority: 0,
        policy_revision: 1,
        credential_revision_ref: Some("credential-revision-1".to_owned()),
        quota_policy_ref: Some(policy_ref.to_owned()),
        enabled: true,
    })?;
    let binding_rows = query::<Postgres>(
        r#"
        WITH generated AS (
            SELECT instance_no,
                   slot,
                   (((instance_no - 1) % $3) + 1) AS type_no,
                   (((instance_no - 1) % $4) + 1) AS tenant_no
            FROM generate_series(1, $2::BIGINT) AS instance_no
            CROSS JOIN generate_series(1, $6::BIGINT) AS slot
        ), records AS (
            SELECT instance_no,
                   format('cinst_scale_%s_%s', $1, lpad(instance_no::TEXT, 8, '0')) AS instance_id,
                   format('tenant-scale-%s-%s', $1, lpad(tenant_no::TEXT, 3, '0')) AS tenant_id,
                   format(
                       'cap:scale:%s:%s',
                       $1,
                       lpad(((((type_no - 1) * $7 + slot - 1) % $5) + 1)::TEXT, 6, '0')
                   ) AS capability_id
            FROM generated
        )
        INSERT INTO aip_tenant_capability_bindings
            (tenant_id, capability_id, instance_id, priority, policy_revision,
             credential_revision_ref, quota_policy_ref, enabled, record, updated_at_ms)
        SELECT tenant_id,
               capability_id,
               instance_id,
               0,
               1,
               'credential-revision-1',
               $10,
               TRUE,
               $8::JSONB || jsonb_build_object(
                   'tenant_id', tenant_id,
                   'capability_id', capability_id,
                   'instance_id', instance_id
               ),
               $9
        FROM records
        "#,
    )
    .bind(run)
    .bind(instance_count)
    .bind(type_count)
    .bind(TENANT_COUNT)
    .bind(capability_count)
    .bind(BINDINGS_PER_INSTANCE)
    .bind(CAPABILITIES_PER_VERSION)
    .bind(binding_template)
    .bind(now_ms)
    .bind(policy_ref)
    .execute(registry.pool())
    .await?;
    assert_eq!(
        i64::try_from(binding_rows.rows_affected())?,
        instance_count * BINDINGS_PER_INSTANCE
    );
    query::<Postgres>(
        "UPDATE aip_connector_catalog_revision \
         SET revision = revision + 1, published_at_ms = $1 WHERE singleton = TRUE",
    )
    .bind(now_ms)
    .execute(registry.pool())
    .await?;
    for table in [
        "aip_connector_types",
        "aip_connector_versions",
        "aip_capability_definitions",
        "aip_connector_version_capabilities",
        "aip_connector_instances",
        "aip_connector_replicas",
        "aip_tenant_capability_bindings",
    ] {
        query::<Postgres>(&format!("ANALYZE {table}"))
            .execute(registry.pool())
            .await?;
    }
    Ok(())
}

async fn routing_plan(
    registry: &PostgresConnectorRegistry,
    tenant_id: &str,
    capability_id: &CapabilityId,
) -> Result<String, Box<dyn std::error::Error>> {
    let rows = query::<Postgres>(
        r#"
        EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT)
        SELECT b.instance_id, r.replica_id
        FROM aip_tenant_capability_bindings b
        JOIN aip_connector_instances i ON i.instance_id = b.instance_id
        JOIN aip_connector_versions v ON v.version_id = i.version_id
        JOIN aip_connector_types t ON t.type_id = i.type_id
        JOIN aip_connector_version_capabilities vc
          ON vc.version_id = v.version_id AND vc.capability_id = b.capability_id
        JOIN aip_connector_replicas r
          ON r.instance_id = i.instance_id AND r.version_id = v.version_id
        WHERE b.tenant_id = $1 AND b.capability_id = $2
          AND b.enabled = TRUE AND i.tenant_id = b.tenant_id
          AND i.status = 'enabled' AND v.status = 'active'
          AND v.supply_chain_qualified = TRUE AND t.enabled = TRUE
          AND r.status = 'ready' AND r.lease_expires_at_ms > $3
          AND r.active_assignments < r.capacity
        ORDER BY b.priority,
                 r.active_assignments,
                 hashtextextended(r.replica_id || $4, 0),
                 b.instance_id,
                 r.replica_id
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .bind(capability_id.as_str())
    .bind(unix_ms(OffsetDateTime::now_utc())?)
    .bind("scale-plan")
    .fetch_all(registry.pool())
    .await?;
    rows.into_iter()
        .map(|row| row.try_get::<String, _>("QUERY PLAN"))
        .collect::<Result<Vec<_>, _>>()
        .map(|lines| lines.join("\n"))
        .map_err(Into::into)
}

async fn cleanup_scale_fleet(
    registry: &PostgresConnectorRegistry,
    run: &str,
    policy_ref: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    query::<Postgres>("DELETE FROM aip_route_assignments WHERE tenant_id LIKE $1")
        .bind(format!("tenant-scale-{run}-%"))
        .execute(registry.pool())
        .await?;
    query::<Postgres>("DELETE FROM aip_tenant_capability_bindings WHERE tenant_id LIKE $1")
        .bind(format!("tenant-scale-{run}-%"))
        .execute(registry.pool())
        .await?;
    query::<Postgres>("DELETE FROM aip_connector_replicas WHERE replica_id LIKE $1")
        .bind(format!("crepl_scale_{run}_%"))
        .execute(registry.pool())
        .await?;
    query::<Postgres>("DELETE FROM aip_connector_instances WHERE instance_id LIKE $1")
        .bind(format!("cinst_scale_{run}_%"))
        .execute(registry.pool())
        .await?;
    query::<Postgres>("DELETE FROM aip_connector_version_capabilities WHERE version_id LIKE $1")
        .bind(format!("cver_scale_{run}_%"))
        .execute(registry.pool())
        .await?;
    query::<Postgres>("DELETE FROM aip_connector_version_profiles WHERE version_id LIKE $1")
        .bind(format!("cver_scale_{run}_%"))
        .execute(registry.pool())
        .await?;
    query::<Postgres>("DELETE FROM aip_connector_versions WHERE version_id LIKE $1")
        .bind(format!("cver_scale_{run}_%"))
        .execute(registry.pool())
        .await?;
    query::<Postgres>("DELETE FROM aip_connector_types WHERE type_id LIKE $1")
        .bind(format!("ctype_scale_{run}_%"))
        .execute(registry.pool())
        .await?;
    query::<Postgres>("DELETE FROM aip_capability_definitions WHERE capability_id LIKE $1")
        .bind(format!("cap:scale:{run}:%"))
        .execute(registry.pool())
        .await?;
    query::<Postgres>(
        "DELETE FROM aip_connector_admission_counters \
         WHERE active = 0 AND scope_kind IN ('tenant', 'tenant_retry') AND scope_key LIKE $1",
    )
    .bind(format!("tenant-scale-{run}-%"))
    .execute(registry.pool())
    .await?;
    query::<Postgres>("DELETE FROM aip_connector_admission_policies WHERE policy_ref = $1")
        .bind(policy_ref)
        .execute(registry.pool())
        .await?;
    Ok(())
}

fn version_template() -> Value {
    let manifest = Manifest {
        manifest_version: "aip-manifest/v1".to_owned(),
        agent: Principal::new(
            PrincipalId::trusted("service:scale-connector-host"),
            PrincipalKind::Service,
        ),
        capabilities: Vec::new(),
        profiles: vec![ProfileId::from("aip.native.http.v1")],
        resources: Vec::new(),
        channels: Vec::new(),
        security: None,
        governance: None,
        limits: None,
        compatibility: None,
        extensions: None,
    };
    serde_json::to_value(ConnectorVersion {
        id: ConnectorVersionId::trusted("cver_scale_template"),
        connector_type_id: ConnectorTypeId::trusted("ctype_scale_template"),
        version: "1.0.0".to_owned(),
        status: ConnectorVersionStatus::Active,
        manifest: manifest.clone(),
        manifest_digest: format!("sha256:{}", "0".repeat(64)),
        attestation: ArtifactAttestation {
            artifact_digest: format!("sha256:{}", "1".repeat(64)),
            schema_bundle_digest: schema_bundle_digest(&manifest).expect("schema bundle digest"),
            sbom_digest: format!("sha256:{}", "2".repeat(64)),
            provenance_digest: format!("sha256:{}", "3".repeat(64)),
            conformance_report_digest: format!("sha256:{}", "4".repeat(64)),
            vulnerability_report_digest: format!("sha256:{}", "5".repeat(64)),
            license_report_digest: format!("sha256:{}", "6".repeat(64)),
            signature_ref: "sigstore:scale-template".to_owned(),
            signer_identity: "https://fulcio.example/identity/scale-test".to_owned(),
            owner: "AIP scale qualification".to_owned(),
            supported_aip_versions: BTreeSet::from([aip_core::AIP_VERSION.to_owned()]),
            sdk_version_requirement: format!("^{}", env!("CARGO_PKG_VERSION")),
            conformance_status: ArtifactCheckStatus::Passed,
            vulnerability_policy_status: ArtifactCheckStatus::Passed,
            license_policy_status: ArtifactCheckStatus::Passed,
            revocation_status: ArtifactCheckStatus::Passed,
        },
        implementation_support: BTreeMap::new(),
        admitted_at: OffsetDateTime::now_utc(),
    })
    .expect("version template")
}

fn capability_definition_template() -> Value {
    serde_json::to_value(CapabilityDefinition {
        capability: Capability {
            id: CapabilityId::trusted("cap:scale:template:000001"),
            name: "Scale capability".to_owned(),
            kind: CapabilityKind::Tool,
            input_schema: json!({ "type": "object" }),
            output_schema: Some(json!({ "type": "object" })),
            description: Some("Fleet scale qualification fixture".to_owned()),
            risk: None,
            stability: None,
            cost: None,
            auth: None,
            bindings: Vec::new(),
            requires_human_approval: None,
            contract: None,
        },
        contract_digest: format!("sha256:{}", "4".repeat(64)),
        schema_digest: format!("sha256:{}", "5".repeat(64)),
    })
    .expect("capability definition template")
}

fn scale_tenant_id(run: &str, tenant_no: i64) -> String {
    format!("tenant-scale-{run}-{tenant_no:03}")
}

fn scale_capability_id(run: &str, capability_no: i64) -> CapabilityId {
    CapabilityId::trusted(format!("cap:scale:{run}:{capability_no:06}"))
}

fn unix_ms(value: OffsetDateTime) -> Result<i64, Box<dyn std::error::Error>> {
    Ok(i64::try_from(value.unix_timestamp_nanos() / 1_000_000)?)
}

fn positive_env_i64(name: &str, default: i64) -> Result<i64, Box<dyn std::error::Error>> {
    let value = std::env::var(name)
        .ok()
        .map(|value| value.parse::<i64>())
        .transpose()?
        .unwrap_or(default);
    if value <= 0 {
        return Err(format!("{name} must be greater than zero").into());
    }
    Ok(value)
}

fn positive_env_usize(name: &str, default: usize) -> Result<usize, Box<dyn std::error::Error>> {
    let value = std::env::var(name)
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()?
        .unwrap_or(default);
    if value == 0 {
        return Err(format!("{name} must be greater than zero").into());
    }
    Ok(value)
}

fn bounded_environment_label() -> Result<String, Box<dyn std::error::Error>> {
    let label = std::env::var("AIP_SCALE_ENVIRONMENT_LABEL")
        .unwrap_or_else(|_| "local-unspecified".to_owned());
    if label.trim().is_empty()
        || label.len() > 128
        || !label
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
    {
        return Err(
            "AIP_SCALE_ENVIRONMENT_LABEL must contain 1 to 128 safe ASCII label bytes".into(),
        );
    }
    Ok(label)
}

fn elapsed_micros(started: Instant) -> u64 {
    u64::try_from(started.elapsed().as_micros()).unwrap_or(u64::MAX)
}

fn percentile(values: &[u64], percentile: usize) -> u64 {
    if values.is_empty() {
        return 0;
    }
    let mut values = values.to_vec();
    values.sort_unstable();
    let index = (values.len() - 1).saturating_mul(percentile.min(100)) / 100;
    values[index]
}

async fn database_size_bytes(
    registry: &PostgresConnectorRegistry,
) -> Result<u64, Box<dyn std::error::Error>> {
    let row = query::<Postgres>(
        "SELECT pg_database_size(current_database())::BIGINT AS database_size_bytes",
    )
    .fetch_one(registry.pool())
    .await?;
    let value: i64 = row.try_get("database_size_bytes")?;
    Ok(u64::try_from(value)?)
}

async fn postgres_environment(
    registry: &PostgresConnectorRegistry,
) -> Result<Value, Box<dyn std::error::Error>> {
    let row = query::<Postgres>(
        r#"
        SELECT current_setting('server_version') AS server_version,
               current_setting('server_version_num') AS server_version_num,
               current_setting('max_connections') AS max_connections,
               current_setting('shared_buffers') AS shared_buffers
        "#,
    )
    .fetch_one(registry.pool())
    .await?;
    Ok(json!({
        "server_version": row.try_get::<String, _>("server_version")?,
        "server_version_num": row.try_get::<String, _>("server_version_num")?,
        "max_connections": row.try_get::<String, _>("max_connections")?,
        "shared_buffers": row.try_get::<String, _>("shared_buffers")?,
    }))
}

fn process_rss_kib() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        status.lines().find_map(|line| {
            let value = line.strip_prefix("VmHWM:")?.trim();
            value
                .strip_suffix("kB")
                .unwrap_or(value)
                .trim()
                .parse()
                .ok()
        })
    }
    #[cfg(not(target_os = "linux"))]
    {
        let output = std::process::Command::new("ps")
            .args(["-o", "rss=", "-p", &std::process::id().to_string()])
            .output()
            .ok()?;
        String::from_utf8(output.stdout).ok()?.trim().parse().ok()
    }
}
