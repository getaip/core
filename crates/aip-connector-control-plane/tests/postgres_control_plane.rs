//! Live composition check for the restricted PostgreSQL lifecycle role.

#![forbid(unsafe_code)]
#![allow(clippy::expect_used)]

use aip_connector_control_plane::{ConnectorControlPlaneArgs, build_application};
use aip_connector_host::{
    CONNECTOR_HOST_CONTROL_PATH, ConnectorHostControlPlane, ConnectorHostHeartbeat,
    ConnectorHostRegistration, ConnectorHostTransition, HttpConnectorHostControlPlane,
};
use aip_connector_registry::{
    ActionTargetResolver, ArtifactAttestation, ArtifactCheckStatus, CapabilityBinding,
    ConnectorInstance, ConnectorInstanceId, ConnectorInstanceStatus, ConnectorRegistryAdmin,
    ConnectorRegistryReader, ConnectorReplica, ConnectorReplicaId, ConnectorReplicaStatus,
    ConnectorType, ConnectorTypeId, ConnectorVersion, ConnectorVersionId, ConnectorVersionStatus,
    RouteResolutionRequest, RouteSettlement, RouteTopologyPreference, digest_json,
    schema_bundle_digest,
};
use aip_connector_registry_postgres::PostgresConnectorRegistry;
use aip_core::{
    ActionId, Capability, CapabilityId, CapabilityKind, Manifest, MessageId, Principal,
    PrincipalId, PrincipalKind, ProfileId,
};
use aip_crypto::{did_key_from_verifying_key, signing_key_from_seed};
use aip_discovery::CapabilityImplementationSupport;
use aip_gateway::CallbackSigner;
use axum::{body::Body, http::Request};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};
use time::{Duration, OffsetDateTime};
use tokio::net::TcpListener;
use tower::ServiceExt;
use url::Url;
use uuid::Uuid;

#[tokio::test]
async fn restricted_lifecycle_role_builds_ready_service_without_admin_pool()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(database_url) = env::var("AIP_POSTGRES_CONTROL_TEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("AIP_POSTGRES_CONTROL_TEST_URL is not set; skipping live control-plane test");
        return Ok(());
    };
    let root = TemporaryDirectory(env::temp_dir().join(format!(
        "aip-connector-control-plane-{}",
        Uuid::now_v7().simple()
    )));
    fs::create_dir(&root.0)?;
    let database_url_file = root.0.join("database-url");
    let signing_seed_file = root.0.join("signing-seed");
    write_owner_secret(&database_url_file, database_url.as_bytes())?;
    write_owner_secret(&signing_seed_file, "11".repeat(32).as_bytes())?;
    let application = build_application(ConnectorControlPlaneArgs {
        database_url_file: Some(database_url_file),
        signing_seed_file: Some(signing_seed_file),
        bind: "127.0.0.1:0".parse::<SocketAddr>()?,
        allow_proxy_network_bind: false,
        principal_id: "service:test-connector-control-plane".to_owned(),
        lease_ttl_ms: 30_000,
        max_connections: 4,
        acquire_timeout_ms: 5_000,
    })
    .await?;
    let pools = application.pool_snapshot();
    assert_eq!(pools.control_size, 0);
    assert_eq!(pools.control_max, 0);

    let ready = application
        .router()
        .oneshot(Request::builder().uri("/ready").body(Body::empty())?)
        .await?;
    assert_eq!(ready.status(), 200);
    let metrics = application
        .router()
        .oneshot(Request::builder().uri("/metrics").body(Body::empty())?)
        .await?;
    assert_eq!(metrics.status(), 200);
    let body = axum::body::to_bytes(metrics.into_body(), 64 * 1024).await?;
    let metrics: Value = serde_json::from_slice(&body)?;
    assert_eq!(metrics.get("control_max").and_then(Value::as_u64), Some(0));
    drop(application);
    Ok(())
}

#[tokio::test]
async fn signed_lifecycle_exact_replay_survives_control_plane_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let Some(admin_database_url) = env::var("AIP_POSTGRES_TEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("AIP_POSTGRES_TEST_URL is not set; skipping live lifecycle restart test");
        return Ok(());
    };
    let Some(lifecycle_database_url) = env::var("AIP_POSTGRES_CONTROL_TEST_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
    else {
        eprintln!("AIP_POSTGRES_CONTROL_TEST_URL is not set; skipping live lifecycle restart test");
        return Ok(());
    };
    let root = TemporaryDirectory(env::temp_dir().join(format!(
        "aip-connector-control-plane-restart-{}",
        Uuid::now_v7().simple()
    )));
    fs::create_dir(&root.0)?;
    let database_url_file = root.0.join("database-url");
    let signing_seed_file = root.0.join("signing-seed");
    write_owner_secret(&database_url_file, lifecycle_database_url.as_bytes())?;
    write_owner_secret(&signing_seed_file, "22".repeat(32).as_bytes())?;
    let application_args = || ConnectorControlPlaneArgs {
        database_url_file: Some(database_url_file.clone()),
        signing_seed_file: Some(signing_seed_file.clone()),
        bind: "127.0.0.1:0".parse::<SocketAddr>().expect("test bind"),
        allow_proxy_network_bind: false,
        principal_id: "service:test-connector-control-plane".to_owned(),
        lease_ttl_ms: 30_000,
        max_connections: 4,
        acquire_timeout_ms: 5_000,
    };
    let admin = PostgresConnectorRegistry::connect(&admin_database_url).await?;
    let host_signer = CallbackSigner {
        principal: Principal::new(
            PrincipalId::trusted(format!("service:test-control-host:{}", Uuid::now_v7())),
            PrincipalKind::Service,
        ),
        signing_key: Arc::new(signing_key_from_seed([33_u8; 32])),
    };
    let registration = provision_replica(&admin, &host_signer).await?;

    let first_application = build_application(application_args()).await?;
    assert_eq!(first_application.pool_snapshot().control_max, 0);
    let first_signer_did = first_application.signer_did.clone();
    let (first_endpoint, first_server) = start_server(first_application.router()).await?;
    let first_remote = HttpConnectorHostControlPlane::new(
        first_endpoint,
        host_signer.clone(),
        first_signer_did.clone(),
        true,
        5_000,
    )?;
    let registration_request_id = MessageId::new();
    let first_lease = first_remote
        .register_once(registration_request_id.clone(), registration.clone())
        .await?;
    first_server.abort();
    let _ = first_server.await;
    drop(first_application);

    let second_application = build_application(application_args()).await?;
    assert_eq!(second_application.signer_did, first_signer_did);
    let (second_endpoint, second_server) = start_server(second_application.router()).await?;
    let second_remote = HttpConnectorHostControlPlane::new(
        second_endpoint,
        host_signer,
        second_application.signer_did.clone(),
        true,
        5_000,
    )?;
    let replayed_lease = second_remote
        .register_once(registration_request_id.clone(), registration.clone())
        .await?;
    assert_eq!(replayed_lease, first_lease);
    let heartbeat_lease = second_remote
        .heartbeat(ConnectorHostHeartbeat {
            replica_id: registration.replica.id.clone(),
            previous_sequence: replayed_lease.sequence,
            in_flight: 0,
            connector_ready: true,
        })
        .await?;
    second_remote
        .offline(ConnectorHostTransition {
            replica_id: registration.replica.id.clone(),
            previous_sequence: heartbeat_lease.sequence,
        })
        .await?;
    let historical_replay = second_remote
        .register_once(registration_request_id, registration.clone())
        .await
        .expect_err("historical registration replay must remain consumed after later states");
    assert!(historical_replay.to_string().contains("already consumed"));
    let offline = admin
        .connector_replica(&registration.replica.id)
        .await?
        .ok_or_else(|| std::io::Error::other("lifecycle replica disappeared"))?;
    assert_eq!(offline.status, ConnectorReplicaStatus::Offline);
    assert_eq!(offline.health_revision, heartbeat_lease.sequence + 1);
    assert!(offline.last_control_request_id.is_some());

    let recovered_lease = second_remote.register(registration.clone()).await?;
    let capability_id = admin
        .connector_version(&registration.replica.version_id)
        .await?
        .ok_or_else(|| std::io::Error::other("admitted lifecycle version disappeared"))?
        .manifest
        .capabilities
        .first()
        .ok_or_else(|| std::io::Error::other("lifecycle capability disappeared"))?
        .id
        .clone();
    admin
        .put_binding(CapabilityBinding {
            tenant_id: registration.tenant_id.clone(),
            capability_id: capability_id.clone(),
            instance_id: registration.replica.instance_id.clone(),
            priority: 0,
            policy_revision: 1,
            credential_revision_ref: None,
            quota_policy_ref: None,
            enabled: true,
        })
        .await?;
    let assignment = admin
        .resolve(RouteResolutionRequest {
            action_id: ActionId::parse(format!(
                "act_test_control_takeover_{}",
                Uuid::now_v7().simple()
            ))?,
            capability_id,
            tenant_id: registration.tenant_id.clone(),
            topology: RouteTopologyPreference::default(),
        })
        .await?;
    let live_takeover = second_remote
        .register(registration.clone())
        .await
        .expect_err("a second process must not take over a live replica");
    assert!(live_takeover.to_string().contains("lease expiry"));

    let mut expired = admin
        .connector_replica(&registration.replica.id)
        .await?
        .ok_or_else(|| std::io::Error::other("active lifecycle replica disappeared"))?;
    assert_eq!(expired.active_assignments, 1);
    expired.lease_expires_at = OffsetDateTime::now_utc() - Duration::milliseconds(1);
    expired.health_revision += 1;
    admin.put_replica(expired).await?;

    let takeover_lease = second_remote.register(registration.clone()).await?;
    let recovered = admin
        .connector_replica(&registration.replica.id)
        .await?
        .ok_or_else(|| std::io::Error::other("recovered lifecycle replica disappeared"))?;
    assert_eq!(recovered.status, ConnectorReplicaStatus::Ready);
    assert_eq!(recovered.health_revision, takeover_lease.sequence);
    assert_eq!(recovered.active_assignments, 1);
    admin
        .settle(&assignment, RouteSettlement::Completed)
        .await?;
    second_remote
        .offline(ConnectorHostTransition {
            replica_id: registration.replica.id.clone(),
            previous_sequence: takeover_lease.sequence,
        })
        .await?;
    let settled = admin
        .connector_replica(&registration.replica.id)
        .await?
        .ok_or_else(|| std::io::Error::other("settled lifecycle replica disappeared"))?;
    assert_eq!(settled.status, ConnectorReplicaStatus::Offline);
    assert_eq!(settled.active_assignments, 0);
    assert!(settled.health_revision > recovered_lease.sequence);
    second_server.abort();
    let _ = second_server.await;
    drop(second_application);
    Ok(())
}

async fn provision_replica(
    registry: &PostgresConnectorRegistry,
    host_signer: &CallbackSigner,
) -> Result<ConnectorHostRegistration, Box<dyn std::error::Error>> {
    let connector_type_id = ConnectorTypeId::new();
    registry
        .put_connector_type(ConnectorType {
            id: connector_type_id.clone(),
            name: "Control-plane lifecycle fixture".to_owned(),
            owner: "AIP conformance".to_owned(),
            enabled: true,
        })
        .await?;
    let capability_id =
        CapabilityId::trusted(format!("cap:test:control:{}", Uuid::now_v7().simple()));
    let manifest = Manifest {
        manifest_version: "aip-manifest/v1".to_owned(),
        agent: host_signer.principal.clone(),
        capabilities: vec![Capability {
            id: capability_id.clone(),
            name: "Lifecycle fixture".to_owned(),
            kind: CapabilityKind::Tool,
            input_schema: serde_json::json!({ "type": "object" }),
            output_schema: Some(serde_json::json!({ "type": "object" })),
            description: Some("Deterministic control-plane fixture".to_owned()),
            risk: None,
            stability: None,
            cost: None,
            auth: None,
            bindings: Vec::new(),
            requires_human_approval: None,
            contract: None,
        }],
        profiles: vec![ProfileId::from("aip.native.http.v1")],
        resources: Vec::new(),
        channels: Vec::new(),
        security: None,
        governance: None,
        limits: None,
        compatibility: None,
        extensions: None,
    };
    let version_id = ConnectorVersionId::new();
    let artifact_digest = unique_digest();
    let manifest_digest = digest_json(&serde_json::to_value(&manifest)?)?;
    registry
        .admit_version(ConnectorVersion {
            id: version_id.clone(),
            connector_type_id: connector_type_id.clone(),
            version: format!("1.0.0+{}", Uuid::now_v7().simple()),
            status: ConnectorVersionStatus::Active,
            manifest: manifest.clone(),
            manifest_digest: manifest_digest.clone(),
            attestation: ArtifactAttestation {
                artifact_digest: artifact_digest.clone(),
                schema_bundle_digest: schema_bundle_digest(&manifest)?,
                sbom_digest: unique_digest(),
                provenance_digest: unique_digest(),
                conformance_report_digest: unique_digest(),
                vulnerability_report_digest: unique_digest(),
                license_report_digest: unique_digest(),
                signature_ref: "sigstore:test-control-plane".to_owned(),
                signer_identity: "https://fulcio.example/identity/control-plane-test".to_owned(),
                owner: "AIP conformance".to_owned(),
                supported_aip_versions: BTreeSet::from([aip_core::AIP_VERSION.to_owned()]),
                sdk_version_requirement: format!("^{}", env!("CARGO_PKG_VERSION")),
                conformance_status: ArtifactCheckStatus::Passed,
                vulnerability_policy_status: ArtifactCheckStatus::Passed,
                license_policy_status: ArtifactCheckStatus::Passed,
                revocation_status: ArtifactCheckStatus::Passed,
            },
            implementation_support: BTreeMap::from([(
                capability_id,
                CapabilityImplementationSupport {
                    invocation: true,
                    ..CapabilityImplementationSupport::default()
                },
            )]),
            admitted_at: OffsetDateTime::now_utc(),
        })
        .await?;
    let tenant_id = format!("tenant-control-{}", Uuid::now_v7().simple());
    let instance_id = ConnectorInstanceId::new();
    let secret_provider_ref = format!("vault://{tenant_id}/fixture");
    registry
        .put_instance(ConnectorInstance {
            id: instance_id.clone(),
            connector_type_id,
            version_id: version_id.clone(),
            tenant_id: tenant_id.clone(),
            config_revision: 1,
            secret_provider_ref: secret_provider_ref.clone(),
            status: ConnectorInstanceStatus::Enabled,
        })
        .await?;
    let replica_id = ConnectorReplicaId::new();
    let endpoint = "http://127.0.0.1:19090/aip/v1/messages".to_owned();
    let peer_did = did_key_from_verifying_key(&host_signer.signing_key.verifying_key());
    registry
        .put_replica(ConnectorReplica {
            id: replica_id.clone(),
            instance_id: instance_id.clone(),
            version_id: version_id.clone(),
            endpoint: endpoint.clone(),
            peer_principal_id: host_signer.principal.id.clone(),
            peer_principal_kind: host_signer.principal.kind,
            peer_did: peer_did.clone(),
            trust_domain: "connectors.test".to_owned(),
            transport_profile: ProfileId::from("aip.native.http.v1"),
            topology: Default::default(),
            status: ConnectorReplicaStatus::Offline,
            lease_expires_at: OffsetDateTime::now_utc(),
            capacity: 4,
            active_assignments: 0,
            health_revision: 1,
            last_control_request_id: None,
            last_control_request_digest: None,
        })
        .await?;
    Ok(ConnectorHostRegistration {
        replica: ConnectorReplica {
            id: replica_id,
            instance_id,
            version_id,
            endpoint,
            peer_principal_id: host_signer.principal.id.clone(),
            peer_principal_kind: host_signer.principal.kind,
            peer_did,
            trust_domain: "connectors.test".to_owned(),
            transport_profile: ProfileId::from("aip.native.http.v1"),
            topology: Default::default(),
            status: ConnectorReplicaStatus::Ready,
            lease_expires_at: OffsetDateTime::now_utc() + Duration::seconds(30),
            capacity: 4,
            active_assignments: 0,
            health_revision: 0,
            last_control_request_id: None,
            last_control_request_digest: None,
        },
        manifest_digest,
        artifact_digest,
        tenant_id,
        config_revision: 1,
        secret_provider_ref,
        capability_count: 1,
    })
}

async fn start_server(
    router: axum::Router,
) -> Result<(Url, tokio::task::JoinHandle<()>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router.into_make_service()).await;
    });
    let endpoint = Url::parse(&format!("http://{address}{CONNECTOR_HOST_CONTROL_PATH}"))?;
    Ok((endpoint, server))
}

fn unique_digest() -> String {
    use sha2::{Digest as _, Sha256};
    format!(
        "sha256:{}",
        hex::encode(Sha256::digest(Uuid::now_v7().as_bytes()))
    )
}

struct TemporaryDirectory(PathBuf);

impl Drop for TemporaryDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn write_owner_secret(path: &Path, value: &[u8]) -> Result<(), Box<dyn std::error::Error>> {
    fs::write(path, value)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
