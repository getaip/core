//! Deterministic, cryptographically separated connector-fleet qualification fixture.
//!
//! This binary exists only to exercise the production admission, lifecycle,
//! routing, and restart paths with the two database-backed sandbox connectors.
//! It never runs in `getaip-server`, never receives catalog credentials, and never
//! substitutes for release attestations emitted by the publishing workflow.

#![forbid(unsafe_code)]

use aip_connector::{Connector, ConnectorContext, ConnectorSecret, FrozenConnector};
use aip_connector_admission::{
    ADMISSION_PACKAGE_SCHEMA, AdmissionPackage, AdmissionTrustPolicy, ConnectorVersionDeclaration,
    EVIDENCE_STATEMENT_SCHEMA, EvidenceKind, EvidenceStatement, SignedAdmissionPackage,
    sign_admission_package, sign_evidence, verify_admission_package,
};
use aip_connector_cal_diy::{CalDiyAuth, CalDiyConnector};
use aip_connector_chatwoot::ChatwootConnector;
use aip_connector_crewai::{ALL_CREW_OPERATIONS, CrewAiSidecarConnector, CrewDescriptor};
use aip_connector_dify::{
    DifyApp, DifyAppCredential, DifyConnector, DifyKnowledgeBase, DifyKnowledgeCredential,
};
use aip_connector_enterprise_sandbox::{
    enterprise_sandbox_implementation_support, enterprise_sandbox_manifest,
};
use aip_connector_hermes_agent::{HermesAgentConnector, HermesAgentEndpoint};
use aip_connector_host::bind_manifest_to_host_principal;
use aip_connector_host_bootstrap::{read_json_config, read_secret_utf8};
use aip_connector_orchestration::{
    DeploymentIntent, ORCHESTRATION_SCHEMA, OrchestrationLimits, OrchestrationTrustPolicy,
};
use aip_connector_registry::{
    AdmissionPolicy, CapabilityBinding, ConnectorInstance, ConnectorInstanceId,
    ConnectorInstanceStatus, ConnectorReplica, ConnectorReplicaId, ConnectorReplicaStatus,
    ConnectorTopology, ConnectorType, ConnectorTypeId, ConnectorVersionId, ConnectorVersionStatus,
    digest_json,
};
use aip_connector_support_sandbox::{
    support_sandbox_implementation_support, support_sandbox_manifest,
};
use aip_connector_twenty::{
    InMemoryTwentyWebhookReplayStore, TwentyConnector, TwentyIdempotentIngestPolicy,
    TwentyOperation,
};
use aip_connector_wa_archive::{
    WaArchiveConnector, WaArchiveControlOperation, WaArchiveOperation, WaArchiveQueryOperation,
};
use aip_core::{AIP_VERSION, Manifest, ProfileId};
use aip_crypto::{did_key_from_verifying_key, signing_key_from_seed};
use aip_discovery::CapabilityImplementationSupport;
use clap::Parser;
use ed25519_dalek::SigningKey;
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
};
use time::{Duration, OffsetDateTime};
use zeroize::Zeroize;

const MAX_SECRET_BYTES: usize = 1_024;
const MAX_TWENTY_POLICY_BYTES: usize = 1024 * 1024;
const MAX_WA_POLICY_BYTES: usize = 1024 * 1024;
const QUALIFICATION_POLICY_REF: &str = "policy:connector-fleet-qualification";
const NATIVE_HTTP_PROFILE: &str = "aip.native.http.v1";

#[derive(Debug, Parser)]
#[command(
    name = "aip-connector-fleet-fixture",
    about = "Generate the signed, deterministic sandbox fleet qualification package"
)]
struct Args {
    /// Directory containing owner-controlled signing seed files.
    #[arg(long, value_name = "DIR")]
    secrets_dir: PathBuf,
    /// Directory receiving public DIDs, trust policy, and signed packages.
    #[arg(long, value_name = "DIR")]
    output_dir: PathBuf,
    /// Immutable local or OCI digest of the support host image.
    #[arg(long)]
    support_artifact_digest: String,
    /// Immutable local or OCI digest of the enterprise host image.
    #[arg(long)]
    enterprise_artifact_digest: String,
    /// Immutable local or OCI digest of the Cal.diy host image.
    #[arg(long)]
    cal_artifact_digest: String,
    /// Immutable local or OCI digest of the Hermes host image.
    #[arg(long)]
    hermes_artifact_digest: String,
    /// Immutable local or OCI digest of the Chatwoot host image.
    #[arg(long)]
    chatwoot_artifact_digest: String,
    /// Immutable local or OCI digest of the Dify host image.
    #[arg(long)]
    dify_artifact_digest: String,
    /// Immutable local or OCI digest of the CrewAI host image.
    #[arg(long)]
    crewai_artifact_digest: String,
    /// Immutable local or OCI digest of the Twenty host image.
    #[arg(long)]
    twenty_artifact_digest: String,
    /// Twenty workspace UUID bound to the admitted connector instance.
    #[arg(long, default_value = "b61e197a-0cb8-4035-acbc-3e9cf4fe8a0a")]
    twenty_workspace_id: String,
    /// Optional JSON array of admitted Twenty capability suffixes.
    #[arg(long, value_name = "FILE")]
    twenty_operations_file: Option<PathBuf>,
    /// Optional field-scoped idempotent-ingest policy used by the Twenty host.
    #[arg(long, value_name = "FILE")]
    twenty_idempotent_ingest_policy_file: Option<PathBuf>,
    /// Immutable local or OCI digest of the WA Archive host image.
    #[arg(long)]
    wa_archive_artifact_digest: String,
    /// Canonical WhatsApp account JID bound to the admitted WA Archive instance.
    #[arg(long)]
    wa_archive_account_id: String,
    /// Optional JSON array of admitted WA Archive provider operation suffixes.
    #[arg(long, value_name = "FILE")]
    wa_archive_operations_file: Option<PathBuf>,
    /// Optional JSON array of admitted WA Archive archive-query suffixes.
    #[arg(long, value_name = "FILE")]
    wa_archive_query_operations_file: Option<PathBuf>,
    /// Optional JSON array of admitted WA Archive operator-control suffixes.
    #[arg(long, value_name = "FILE")]
    wa_archive_control_operations_file: Option<PathBuf>,
    /// Lowercase release identifier appended to immutable version and replica IDs.
    ///
    /// A source-digest prefix keeps independently built artifacts from being
    /// admitted under the same registry identity.
    #[arg(long, default_value = "local")]
    release_id: String,
    /// Monotonic admission and connector configuration revision for this release.
    #[arg(long, default_value_t = 1)]
    release_revision: u64,
    /// Stable deployment trust domain.
    #[arg(long, default_value = "fleet.test")]
    trust_domain: String,
    /// Connector owner enforced by the qualification registry.
    #[arg(long, default_value = "WAI LLC")]
    owner: String,
    /// First replica endpoint for the tenant-acme support instance.
    #[arg(
        long,
        default_value = "https://support-acme-a.fleet.test:8443/aip/v1/messages"
    )]
    support_acme_a_endpoint: String,
    /// Second replica endpoint for the tenant-acme support instance.
    #[arg(
        long,
        default_value = "https://support-acme-b.fleet.test:8443/aip/v1/messages"
    )]
    support_acme_b_endpoint: String,
    /// Replica endpoint for the tenant-beta support instance.
    #[arg(
        long,
        default_value = "https://support-beta-a.fleet.test:8443/aip/v1/messages"
    )]
    support_beta_a_endpoint: String,
    /// Replica endpoint for the tenant-acme enterprise instance.
    #[arg(
        long,
        default_value = "https://enterprise-acme-a.fleet.test:8443/aip/v1/messages"
    )]
    enterprise_acme_a_endpoint: String,
    /// Cal.diy host endpoint for tenant-acme.
    #[arg(
        long,
        default_value = "https://cal-acme-a.fleet.test:8443/aip/v1/messages"
    )]
    cal_acme_a_endpoint: String,
    /// Hermes host endpoint for tenant-acme.
    #[arg(
        long,
        default_value = "https://hermes-acme-a.fleet.test:8443/aip/v1/messages"
    )]
    hermes_acme_a_endpoint: String,
    /// Chatwoot host endpoint for tenant-acme.
    #[arg(
        long,
        default_value = "https://chatwoot-acme-a.fleet.test:8443/aip/v1/messages"
    )]
    chatwoot_acme_a_endpoint: String,
    /// Dify host endpoint for tenant-acme.
    #[arg(
        long,
        default_value = "https://dify-acme-a.fleet.test:8443/aip/v1/messages"
    )]
    dify_acme_a_endpoint: String,
    /// CrewAI host endpoint for tenant-acme.
    #[arg(
        long,
        default_value = "https://crewai-acme-a.fleet.test:8443/aip/v1/messages"
    )]
    crewai_acme_a_endpoint: String,
    /// Twenty host endpoint for tenant-acme.
    #[arg(
        long,
        default_value = "https://twenty-acme-a.fleet.test:8443/aip/v1/messages"
    )]
    twenty_acme_a_endpoint: String,
    /// WA Archive host endpoint for tenant-acme.
    #[arg(
        long,
        default_value = "https://wa-archive-acme-a.fleet.test:8443/aip/v1/messages"
    )]
    wa_archive_acme_a_endpoint: String,
}

#[derive(Serialize)]
struct IdentitySummary {
    schema_version: &'static str,
    trust_domain: String,
    control_plane_did: String,
    gateway_did: String,
    package_signer_did: String,
    orchestration_signer_did: String,
    evidence_signer_dids: BTreeMap<EvidenceKind, String>,
    client_signer_dids: BTreeMap<String, String>,
    replica_dids: BTreeMap<String, String>,
}

struct FixtureKeys {
    package: SigningKey,
    evidence: BTreeMap<EvidenceKind, SigningKey>,
    control_plane_did: String,
    gateway_did: String,
    orchestration_did: String,
    clients: BTreeMap<&'static str, SigningKey>,
    replicas: BTreeMap<&'static str, SigningKey>,
}

#[tokio::main]
async fn main() -> ExitCode {
    match run(Args::parse()).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), String> {
    validate_text("trust domain", &args.trust_domain, 253)?;
    validate_text("connector owner", &args.owner, 512)?;
    validate_artifact_digest("support artifact", &args.support_artifact_digest)?;
    validate_artifact_digest("enterprise artifact", &args.enterprise_artifact_digest)?;
    validate_artifact_digest("Cal.diy artifact", &args.cal_artifact_digest)?;
    validate_artifact_digest("Hermes artifact", &args.hermes_artifact_digest)?;
    validate_artifact_digest("Chatwoot artifact", &args.chatwoot_artifact_digest)?;
    validate_artifact_digest("Dify artifact", &args.dify_artifact_digest)?;
    validate_artifact_digest("CrewAI artifact", &args.crewai_artifact_digest)?;
    validate_artifact_digest("Twenty artifact", &args.twenty_artifact_digest)?;
    validate_text("Twenty workspace id", &args.twenty_workspace_id, 36)?;
    validate_artifact_digest("WA Archive artifact", &args.wa_archive_artifact_digest)?;
    validate_text("WA Archive account id", &args.wa_archive_account_id, 512)?;
    validate_release_id(&args.release_id)?;
    if args.release_revision == 0 {
        return Err("release revision must be greater than zero".to_owned());
    }
    let issued_at = read_issued_at(&args.secrets_dir.join("issued-at.txt"))?;
    let now = OffsetDateTime::now_utc();
    if issued_at > now + Duration::minutes(5) || issued_at < now - Duration::days(29) {
        return Err(
            "qualification issuance time must be within the active 30-day fixture window"
                .to_owned(),
        );
    }
    fs::create_dir_all(&args.output_dir)
        .map_err(|error| format!("cannot create output directory: {error}"))?;

    let keys = load_keys(&args.secrets_dir)?;
    let policy = admission_policy(&keys, &args.owner);
    let support = support_package(&args, &keys, issued_at)?;
    let enterprise = enterprise_package(&args, &keys, issued_at)?;
    let products = product_packages(&args, &keys, issued_at).await?;
    let verified_support = verify_admission_package(support.clone(), &policy, now)
        .map_err(|error| format!("support package failed self-verification: {error}"))?;
    verify_admission_package(enterprise.clone(), &policy, now)
        .map_err(|error| format!("enterprise package failed self-verification: {error}"))?;
    for (name, package) in &products {
        verify_admission_package(package.clone(), &policy, now)
            .map_err(|error| format!("{name} package failed self-verification: {error}"))?;
    }

    let package_signer_did = did_key_from_verifying_key(&keys.package.verifying_key());
    let evidence_signer_dids = keys
        .evidence
        .iter()
        .map(|(kind, key)| (*kind, did_key_from_verifying_key(&key.verifying_key())))
        .collect::<BTreeMap<_, _>>();
    let replica_dids = keys
        .replicas
        .iter()
        .map(|(name, key)| {
            (
                (*name).to_owned(),
                did_key_from_verifying_key(&key.verifying_key()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let client_signer_dids = keys
        .clients
        .iter()
        .map(|(name, key)| {
            (
                (*name).to_owned(),
                did_key_from_verifying_key(&key.verifying_key()),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let summary = IdentitySummary {
        schema_version: "aip.connector-fleet-qualification-identities/v1",
        trust_domain: args.trust_domain,
        control_plane_did: keys.control_plane_did.clone(),
        gateway_did: keys.gateway_did.clone(),
        package_signer_did,
        orchestration_signer_did: keys.orchestration_did.clone(),
        evidence_signer_dids,
        client_signer_dids,
        replica_dids,
    };

    write_json_atomic(
        &args.output_dir.join("trusted-signers.json"),
        &trusted_signer_directory(&keys),
    )?;
    write_json_atomic(
        &args.output_dir.join("trusted-identities.json"),
        &trusted_identity_directory(issued_at, &args.twenty_workspace_id)?,
    )?;
    write_json_atomic(
        &args.output_dir.join("approval-authorities.json"),
        &approval_authority_directory(issued_at)?,
    )?;

    write_json_atomic(&args.output_dir.join("admission-policy.json"), &policy)?;
    write_json_atomic(&args.output_dir.join("support-admission.json"), &support)?;
    write_json_atomic(
        &args.output_dir.join("enterprise-admission.json"),
        &enterprise,
    )?;
    for (name, package) in &products {
        write_json_atomic(
            &args.output_dir.join(format!("{name}-admission.json")),
            package,
        )?;
    }
    write_json_atomic(&args.output_dir.join("identities.json"), &summary)?;
    write_json_atomic(
        &args.output_dir.join("orchestration-policy.json"),
        &OrchestrationTrustPolicy {
            trusted_signer_dids: BTreeSet::from([keys.orchestration_did.clone()]),
            limits: OrchestrationLimits::default(),
        },
    )?;
    write_json_atomic(
        &args.output_dir.join("support-acme-intent.json"),
        &DeploymentIntent {
            schema_version: ORCHESTRATION_SCHEMA.to_owned(),
            generation: args.release_revision,
            rollback_of_generation: None,
            package_id: verified_support.package.package_id.clone(),
            package_revision: verified_support.package.revision,
            package_digest: verified_support.package_digest,
            instance_id: ConnectorInstanceId::trusted("cinst_support_acme"),
            desired_replicas: BTreeSet::from([
                ConnectorReplicaId::trusted(release_scoped_id(
                    "crepl_support_acme_a",
                    &args.release_id,
                )),
                ConnectorReplicaId::trusted(release_scoped_id(
                    "crepl_support_acme_b",
                    &args.release_id,
                )),
            ]),
            max_surge: 1,
            max_unavailable: 1,
            issued_at: now,
            expires_at: now + Duration::minutes(5),
        },
    )?;
    write_json_atomic(
        &args.output_dir.join("support-acme-observed.json"),
        &Vec::<Value>::new(),
    )?;
    write_text_atomic(
        &args.output_dir.join("control-plane.did"),
        &keys.control_plane_did,
    )?;
    write_text_atomic(&args.output_dir.join("gateway.did"), &keys.gateway_did)?;
    Ok(())
}

fn validate_artifact_digest(label: &str, digest: &str) -> Result<(), String> {
    let Some(hex_digest) = digest.strip_prefix("sha256:") else {
        return Err(format!("{label} digest must use the sha256 algorithm"));
    };
    if hex_digest.len() != 64
        || !hex_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!(
            "{label} digest must contain exactly 64 lowercase hexadecimal characters"
        ));
    }
    if hex_digest.bytes().all(|byte| byte == b'0') {
        return Err(format!("{label} digest must not be a placeholder"));
    }
    Ok(())
}

fn validate_release_id(release_id: &str) -> Result<(), String> {
    if release_id.is_empty()
        || release_id.len() > 32
        || !release_id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err("release id must contain 1 to 32 lowercase ASCII letters or digits".to_owned());
    }
    Ok(())
}

fn release_scoped_id(base: &str, release_id: &str) -> String {
    format!("{base}_{release_id}")
}

fn load_keys(directory: &Path) -> Result<FixtureKeys, String> {
    let package = read_signing_key(&directory.join("release-signing-seed.hex"))?;
    let mut evidence = BTreeMap::new();
    for kind in EvidenceKind::all() {
        evidence.insert(
            kind,
            read_signing_key(&directory.join(evidence_seed_name(kind)))?,
        );
    }
    let control = read_signing_key(&directory.join("control-signing-seed.hex"))?;
    let gateway = read_signing_key(&directory.join("gateway-signing-seed.hex"))?;
    let orchestration = read_signing_key(&directory.join("orchestration-signing-seed.hex"))?;
    let clients = BTreeMap::from([
        (
            "tenant-acme",
            read_signing_key(&directory.join("client-acme-signing-seed.hex"))?,
        ),
        (
            "tenant-beta",
            read_signing_key(&directory.join("client-beta-signing-seed.hex"))?,
        ),
        (
            "cal-acme",
            read_signing_key(&directory.join("client-cal-acme-signing-seed.hex"))?,
        ),
        (
            "chatwoot-acme",
            read_signing_key(&directory.join("client-chatwoot-acme-signing-seed.hex"))?,
        ),
        (
            "twenty-acme",
            read_signing_key(&directory.join("client-twenty-acme-signing-seed.hex"))?,
        ),
        (
            "approver-acme",
            read_signing_key(&directory.join("approval-acme-signing-seed.hex"))?,
        ),
    ]);
    let replicas = BTreeMap::from([
        (
            "support-acme-a",
            read_signing_key(&directory.join("support-acme-a-signing-seed.hex"))?,
        ),
        (
            "support-acme-b",
            read_signing_key(&directory.join("support-acme-b-signing-seed.hex"))?,
        ),
        (
            "support-beta-a",
            read_signing_key(&directory.join("support-beta-a-signing-seed.hex"))?,
        ),
        (
            "enterprise-acme-a",
            read_signing_key(&directory.join("enterprise-acme-a-signing-seed.hex"))?,
        ),
        (
            "cal-acme-a",
            read_signing_key(&directory.join("cal-acme-a-signing-seed.hex"))?,
        ),
        (
            "hermes-acme-a",
            read_signing_key(&directory.join("hermes-acme-a-signing-seed.hex"))?,
        ),
        (
            "chatwoot-acme-a",
            read_signing_key(&directory.join("chatwoot-acme-a-signing-seed.hex"))?,
        ),
        (
            "dify-acme-a",
            read_signing_key(&directory.join("dify-acme-a-signing-seed.hex"))?,
        ),
        (
            "crewai-acme-a",
            read_signing_key(&directory.join("crewai-acme-a-signing-seed.hex"))?,
        ),
        (
            "twenty-acme-a",
            read_signing_key(&directory.join("twenty-acme-a-signing-seed.hex"))?,
        ),
        (
            "wa-archive-acme-a",
            read_signing_key(&directory.join("wa-archive-acme-a-signing-seed.hex"))?,
        ),
    ]);
    Ok(FixtureKeys {
        package,
        evidence,
        control_plane_did: did_key_from_verifying_key(&control.verifying_key()),
        gateway_did: did_key_from_verifying_key(&gateway.verifying_key()),
        orchestration_did: did_key_from_verifying_key(&orchestration.verifying_key()),
        clients,
        replicas,
    })
}

fn admission_policy(keys: &FixtureKeys, owner: &str) -> AdmissionTrustPolicy {
    AdmissionTrustPolicy {
        trusted_package_signer_dids: BTreeSet::from([did_key_from_verifying_key(
            &keys.package.verifying_key(),
        )]),
        trusted_evidence_signer_dids: keys
            .evidence
            .iter()
            .map(|(kind, key)| {
                (
                    *kind,
                    BTreeSet::from([did_key_from_verifying_key(&key.verifying_key())]),
                )
            })
            .collect(),
        require_distinct_signers: true,
        required_owner: Some(owner.to_owned()),
        max_package_bytes: 16 * 1024 * 1024,
        max_evidence_document_bytes: 1024 * 1024,
        max_instances: 16,
        max_replicas: 32,
        max_bindings: 4_096,
        max_clock_skew_seconds: 300,
    }
}

fn trusted_signer_directory(keys: &FixtureKeys) -> Vec<Value> {
    [
        ("tenant-acme", "service:getaip:cli:qualification-acme"),
        ("tenant-beta", "service:getaip:cli:qualification-beta"),
        ("cal-acme", "service:getaip:cli:qualification-cal"),
        ("chatwoot-acme", "service:getaip:cli:qualification-chatwoot"),
        ("twenty-acme", "service:getaip:cli:qualification-twenty"),
        ("approver-acme", "human:qualification-approver"),
    ]
    .into_iter()
    .map(|(tenant, principal_id)| {
        json!({
            "signer_did": did_key_from_verifying_key(&keys.clients[tenant].verifying_key()),
            "principal_id": principal_id
        })
    })
    .collect()
}

fn trusted_identity_directory(
    issued_at: OffsetDateTime,
    twenty_workspace_id: &str,
) -> Result<Vec<Value>, String> {
    let verified_at = issued_at
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| error.to_string())?;
    let expires_at = (issued_at + Duration::days(30))
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| error.to_string())?;
    let tenant_binding =
        |tenant_id: &str, principal_id: &str, identity: Option<Value>| -> Result<Value, String> {
            let mut binding = json!({
                "principal_id": principal_id,
                "tenant": {
                    "tenant": {
                        "id": tenant_id,
                        "system": "connector-fleet-qualification"
                    },
                    "membership_id": format!("qualification-membership-{tenant_id}-{principal_id}"),
                    "roles": ["connector-fleet-qualification"],
                    "groups": [],
                    "verified_at": verified_at,
                    "expires_at": expires_at
                },
                "revision": 1,
                "revoked": false
            });
            if let Some(identity) = identity {
                let object = binding
                    .as_object_mut()
                    .ok_or_else(|| "trusted identity binding must be a JSON object".to_owned())?;
                object.insert("identity".to_owned(), identity);
            }
            Ok(binding)
        };
    Ok(vec![
        tenant_binding("tenant-acme", "service:getaip:cli:qualification-acme", None)?,
        tenant_binding("tenant-beta", "service:getaip:cli:qualification-beta", None)?,
        tenant_binding(
            "tenant-acme",
            "service:getaip:cli:qualification-cal",
            Some(json!({
                "tenant": {
                    "id": "tenant-acme",
                    "system": "connector-fleet-qualification"
                },
                "external_account": {"id": "42", "system": "cal_diy"}
            })),
        )?,
        tenant_binding(
            "tenant-acme",
            "service:getaip:cli:qualification-chatwoot",
            Some(json!({
                "tenant": {
                    "id": "tenant-acme",
                    "system": "connector-fleet-qualification"
                },
                "external_account": {"id": "42", "system": "chatwoot"}
            })),
        )?,
        tenant_binding(
            "tenant-acme",
            "service:getaip:cli:qualification-twenty",
            Some(json!({
                "tenant": {
                    "id": "tenant-acme",
                    "system": "connector-fleet-qualification"
                },
                "external_account": {
                    "id": twenty_workspace_id,
                    "system": "twenty"
                }
            })),
        )?,
    ])
}

fn approval_authority_directory(issued_at: OffsetDateTime) -> Result<Vec<Value>, String> {
    let expires_at = (issued_at + Duration::days(30))
        .format(&time::format_description::well_known::Rfc3339)
        .map_err(|error| error.to_string())?;
    Ok(vec![json!({
        "principal_id": "human:qualification-approver",
        "tenant_id": "tenant-acme",
        "roles": ["connector-fleet-approver"],
        "groups": [],
        "tenant_policies": ["policy:connector-fleet-qualification"],
        "external_systems": [],
        "delegated_scopes": [],
        "revision": 1,
        "expires_at": expires_at,
        "revoked": false
    })])
}

fn support_package(
    args: &Args,
    keys: &FixtureKeys,
    issued_at: OffsetDateTime,
) -> Result<SignedAdmissionPackage, String> {
    let connector_type_id =
        ConnectorTypeId::parse("ctype_support_sandbox").map_err(|error| error.to_string())?;
    let version_id = ConnectorVersionId::parse(release_scoped_id(
        "cver_support_sandbox_1_0_0",
        &args.release_id,
    ))
    .map_err(|error| error.to_string())?;
    let acme_instance =
        ConnectorInstanceId::parse("cinst_support_acme").map_err(|error| error.to_string())?;
    let beta_instance =
        ConnectorInstanceId::parse("cinst_support_beta").map_err(|error| error.to_string())?;
    let host_key = &keys.replicas["support-acme-a"];
    let manifest = qualified_manifest(
        support_sandbox_manifest().map_err(|error| error.to_string())?,
        host_key,
        &args.trust_domain,
    )?;
    let implementation_support = manifest
        .capabilities
        .iter()
        .map(|capability| {
            (
                capability.id.clone(),
                support_sandbox_implementation_support(capability),
            )
        })
        .collect();
    let instances = vec![
        instance(
            acme_instance.clone(),
            connector_type_id.clone(),
            version_id.clone(),
            "tenant-acme",
            "secret://qualification/support/acme",
            args.release_revision,
        ),
        instance(
            beta_instance.clone(),
            connector_type_id.clone(),
            version_id.clone(),
            "tenant-beta",
            "secret://qualification/support/beta",
            args.release_revision,
        ),
    ];
    let replicas = vec![
        replica(
            &release_scoped_id("crepl_support_acme_a", &args.release_id),
            acme_instance.clone(),
            version_id.clone(),
            &args.support_acme_a_endpoint,
            &manifest,
            &keys.replicas["support-acme-a"],
            &args.trust_domain,
            "zone-a",
        )?,
        replica(
            &release_scoped_id("crepl_support_acme_b", &args.release_id),
            acme_instance.clone(),
            version_id.clone(),
            &args.support_acme_b_endpoint,
            &manifest,
            &keys.replicas["support-acme-b"],
            &args.trust_domain,
            "zone-b",
        )?,
        replica(
            &release_scoped_id("crepl_support_beta_a", &args.release_id),
            beta_instance.clone(),
            version_id.clone(),
            &args.support_beta_a_endpoint,
            &manifest,
            &keys.replicas["support-beta-a"],
            &args.trust_domain,
            "zone-a",
        )?,
    ];
    let mut bindings = capability_bindings(
        &manifest,
        "tenant-acme",
        &acme_instance,
        args.release_revision,
    );
    bindings.extend(capability_bindings(
        &manifest,
        "tenant-beta",
        &beta_instance,
        args.release_revision,
    ));
    signed_package(
        keys,
        issued_at,
        ConnectorType {
            id: connector_type_id.clone(),
            name: "AIP support sandbox".to_owned(),
            owner: args.owner.clone(),
            enabled: true,
        },
        version_declaration(
            version_id,
            connector_type_id,
            manifest,
            args.support_artifact_digest.clone(),
            implementation_support,
            &args.release_id,
        )?,
        instances,
        replicas,
        bindings,
        "qualification-support-sandbox",
        args.release_revision,
    )
}

fn enterprise_package(
    args: &Args,
    keys: &FixtureKeys,
    issued_at: OffsetDateTime,
) -> Result<SignedAdmissionPackage, String> {
    let connector_type_id =
        ConnectorTypeId::parse("ctype_enterprise_sandbox").map_err(|error| error.to_string())?;
    let version_id = ConnectorVersionId::parse(release_scoped_id(
        "cver_enterprise_sandbox_1_0_0",
        &args.release_id,
    ))
    .map_err(|error| error.to_string())?;
    let instance_id =
        ConnectorInstanceId::parse("cinst_enterprise_acme").map_err(|error| error.to_string())?;
    let host_key = &keys.replicas["enterprise-acme-a"];
    let manifest = qualified_manifest(
        enterprise_sandbox_manifest().map_err(|error| error.to_string())?,
        host_key,
        &args.trust_domain,
    )?;
    let implementation_support = manifest
        .capabilities
        .iter()
        .map(|capability| {
            (
                capability.id.clone(),
                enterprise_sandbox_implementation_support(capability),
            )
        })
        .collect();
    let instances = vec![instance(
        instance_id.clone(),
        connector_type_id.clone(),
        version_id.clone(),
        "tenant-acme",
        "secret://qualification/enterprise/acme",
        args.release_revision,
    )];
    let replicas = vec![replica(
        &release_scoped_id("crepl_enterprise_acme_a", &args.release_id),
        instance_id.clone(),
        version_id.clone(),
        &args.enterprise_acme_a_endpoint,
        &manifest,
        host_key,
        &args.trust_domain,
        "zone-a",
    )?];
    let bindings = capability_bindings(
        &manifest,
        "tenant-acme",
        &instance_id,
        args.release_revision,
    );
    signed_package(
        keys,
        issued_at,
        ConnectorType {
            id: connector_type_id.clone(),
            name: "AIP enterprise sandbox".to_owned(),
            owner: args.owner.clone(),
            enabled: true,
        },
        version_declaration(
            version_id,
            connector_type_id,
            manifest,
            args.enterprise_artifact_digest.clone(),
            implementation_support,
            &args.release_id,
        )?,
        instances,
        replicas,
        bindings,
        "qualification-enterprise-sandbox",
        args.release_revision,
    )
}

async fn product_packages(
    args: &Args,
    keys: &FixtureKeys,
    issued_at: OffsetDateTime,
) -> Result<Vec<(&'static str, SignedAdmissionPackage)>, String> {
    let context = ConnectorContext {
        tenant_id: Some("tenant-acme".to_owned()),
        metadata: BTreeMap::new(),
    };

    let cal = CalDiyConnector::with_auth(
        "https://cal-provider.fleet.test:8443",
        "42",
        CalDiyAuth::Bearer(ConnectorSecret::new(b"qualification-cal-token")),
    )
    .map_err(|error| error.to_string())?;
    let cal_manifest = cal
        .discover(&context)
        .await
        .map_err(|error| error.to_string())?;
    let cal_support = implementation_support(&cal, &cal_manifest);

    let hermes_endpoint = HermesAgentEndpoint::new(
        "qualification",
        "https://hermes-provider.fleet.test:8443",
        Some("qualification-hermes-token".to_owned()),
    )
    .map_err(|error| error.to_string())?
    .with_display_name("Qualification Hermes")
    .with_tenant_id("tenant-acme")
    .map_err(|error| error.to_string())?;
    let hermes =
        HermesAgentConnector::new(vec![hermes_endpoint]).map_err(|error| error.to_string())?;
    let hermes_manifest = hermes
        .discover(&context)
        .await
        .map_err(|error| error.to_string())?;
    let hermes_support = implementation_support(&hermes, &hermes_manifest);

    let chatwoot = ChatwootConnector::with_api_token(
        "https://chatwoot-provider.fleet.test:8443",
        "42",
        ConnectorSecret::new(b"qualification-chatwoot-token"),
    )
    .map_err(|error| error.to_string())?
    .with_webhook_secret(b"qualification-chatwoot-webhook".to_vec());
    let chatwoot_manifest = chatwoot
        .discover(&context)
        .await
        .map_err(|error| error.to_string())?;
    let chatwoot_support = implementation_support(&chatwoot, &chatwoot_manifest);

    let dify_app = DifyApp {
        id: "qualification-app".to_owned(),
        name: "Qualification App".to_owned(),
        mode: "chat".to_owned(),
        description: Some("Pinned product-fleet qualification app".to_owned()),
    };
    let dify_knowledge = DifyKnowledgeBase {
        id: "qualification-kb".to_owned(),
        name: "Qualification Knowledge".to_owned(),
        description: Some("Pinned product-fleet qualification knowledge base".to_owned()),
    };
    let dify = DifyConnector::with_credentials(
        "https://dify-provider.fleet.test:8443",
        vec![DifyAppCredential {
            app: dify_app,
            api_key: ConnectorSecret::new(b"qualification-dify-app-token"),
        }],
        vec![DifyKnowledgeCredential {
            knowledge: dify_knowledge,
            api_key: ConnectorSecret::new(b"qualification-dify-knowledge-token"),
        }],
    )
    .map_err(|error| error.to_string())?;
    let dify_manifest = dify
        .discover(&context)
        .await
        .map_err(|error| error.to_string())?;
    let dify_support = implementation_support(&dify, &dify_manifest);

    let crew = CrewDescriptor {
        id: "support-qualification".to_owned(),
        name: "Support qualification crew".to_owned(),
        description: Some("Pinned real-CrewAI product-fleet qualification crew".to_owned()),
        allowed_operations: ALL_CREW_OPERATIONS.iter().copied().collect(),
    };
    let crewai = CrewAiSidecarConnector::new("https://crewai-sidecar.fleet.test:8443", vec![crew])
        .map_err(|error| error.to_string())?
        .with_bearer_secret(ConnectorSecret::new(b"qualification-crewai-sidecar-token"))
        .map_err(|error| error.to_string())?;
    let crewai_manifest = crewai
        .discover(&context)
        .await
        .map_err(|error| error.to_string())?;
    let crewai_support = implementation_support(&crewai, &crewai_manifest);

    let mut twenty = TwentyConnector::with_api_token(
        "https://twenty-provider.fleet.test:8443",
        &args.twenty_workspace_id,
        ConnectorSecret::new(b"qualification-twenty-token"),
        false,
    )
    .map_err(|error| error.to_string())?
    .with_webhook_security(
        ConnectorSecret::new(b"qualification-twenty-webhook"),
        Arc::new(InMemoryTwentyWebhookReplayStore::default()),
    )
    .map_err(|error| error.to_string())?;
    if let Some(path) = args.twenty_operations_file.as_ref() {
        let suffixes: Vec<String> =
            read_json_config(path, MAX_TWENTY_POLICY_BYTES).map_err(|error| error.to_string())?;
        let operations = suffixes
            .iter()
            .map(|suffix| {
                TwentyOperation::from_suffix(suffix)
                    .ok_or_else(|| format!("unknown Twenty operation suffix `{suffix}`"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        twenty = twenty
            .with_allowed_operations(operations)
            .map_err(|error| error.to_string())?;
    }
    if let Some(path) = args.twenty_idempotent_ingest_policy_file.as_ref() {
        let policy: TwentyIdempotentIngestPolicy =
            read_json_config(path, MAX_TWENTY_POLICY_BYTES).map_err(|error| error.to_string())?;
        twenty = twenty
            .with_idempotent_ingest_policy(policy)
            .map_err(|error| error.to_string())?;
    }
    let twenty_manifest = twenty
        .discover(&context)
        .await
        .map_err(|error| error.to_string())?;
    let twenty_support = implementation_support(&twenty, &twenty_manifest);

    let mut wa_archive = WaArchiveConnector::new(
        "https://wa-archive-provider.fleet.test:8443",
        &args.wa_archive_account_id,
        ConnectorSecret::new(b"qualification-wa-archive-token"),
    )
    .map_err(|error| error.to_string())?;
    if let Some(path) = args.wa_archive_operations_file.as_ref() {
        let suffixes: Vec<String> =
            read_json_config(path, MAX_WA_POLICY_BYTES).map_err(|error| error.to_string())?;
        let operations = suffixes
            .iter()
            .map(|suffix| {
                WaArchiveOperation::from_suffix(suffix)
                    .ok_or_else(|| format!("unknown WA Archive operation suffix `{suffix}`"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        wa_archive = wa_archive
            .with_allowed_operations(operations)
            .map_err(|error| error.to_string())?;
    }
    if let Some(path) = args.wa_archive_query_operations_file.as_ref() {
        let suffixes: Vec<String> =
            read_json_config(path, MAX_WA_POLICY_BYTES).map_err(|error| error.to_string())?;
        let operations = suffixes
            .iter()
            .map(|suffix| {
                WaArchiveQueryOperation::from_suffix(suffix)
                    .ok_or_else(|| format!("unknown WA Archive query operation suffix `{suffix}`"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        wa_archive = wa_archive
            .with_allowed_query_operations(operations)
            .map_err(|error| error.to_string())?;
    }
    if let Some(path) = args.wa_archive_control_operations_file.as_ref() {
        let suffixes: Vec<String> =
            read_json_config(path, MAX_WA_POLICY_BYTES).map_err(|error| error.to_string())?;
        let operations = suffixes
            .iter()
            .map(|suffix| {
                WaArchiveControlOperation::from_suffix(suffix).ok_or_else(|| {
                    format!("unknown WA Archive control operation suffix `{suffix}`")
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        wa_archive = wa_archive
            .with_allowed_control_operations(operations)
            .map_err(|error| error.to_string())?;
    }
    let wa_archive_manifest = wa_archive
        .qualified_manifest()
        .map_err(|error| error.to_string())?;
    let wa_archive_support = implementation_support(&wa_archive, &wa_archive_manifest);

    Ok(vec![
        (
            "cal",
            product_package(
                args,
                keys,
                issued_at,
                ProductPackage {
                    slug: "cal_diy",
                    key_name: "cal-acme-a",
                    display_name: "AIP Cal.diy connector",
                    artifact_digest: &args.cal_artifact_digest,
                    endpoint: &args.cal_acme_a_endpoint,
                    manifest: cal_manifest,
                    implementation_support: cal_support,
                },
            )?,
        ),
        (
            "hermes",
            product_package(
                args,
                keys,
                issued_at,
                ProductPackage {
                    slug: "hermes_agent",
                    key_name: "hermes-acme-a",
                    display_name: "AIP Hermes Agent connector",
                    artifact_digest: &args.hermes_artifact_digest,
                    endpoint: &args.hermes_acme_a_endpoint,
                    manifest: hermes_manifest,
                    implementation_support: hermes_support,
                },
            )?,
        ),
        (
            "chatwoot",
            product_package(
                args,
                keys,
                issued_at,
                ProductPackage {
                    slug: "chatwoot",
                    key_name: "chatwoot-acme-a",
                    display_name: "AIP Chatwoot connector",
                    artifact_digest: &args.chatwoot_artifact_digest,
                    endpoint: &args.chatwoot_acme_a_endpoint,
                    manifest: chatwoot_manifest,
                    implementation_support: chatwoot_support,
                },
            )?,
        ),
        (
            "dify",
            product_package(
                args,
                keys,
                issued_at,
                ProductPackage {
                    slug: "dify",
                    key_name: "dify-acme-a",
                    display_name: "AIP Dify connector",
                    artifact_digest: &args.dify_artifact_digest,
                    endpoint: &args.dify_acme_a_endpoint,
                    manifest: dify_manifest,
                    implementation_support: dify_support,
                },
            )?,
        ),
        (
            "crewai",
            product_package(
                args,
                keys,
                issued_at,
                ProductPackage {
                    slug: "crewai",
                    key_name: "crewai-acme-a",
                    display_name: "AIP CrewAI connector",
                    artifact_digest: &args.crewai_artifact_digest,
                    endpoint: &args.crewai_acme_a_endpoint,
                    manifest: crewai_manifest,
                    implementation_support: crewai_support,
                },
            )?,
        ),
        (
            "twenty",
            product_package(
                args,
                keys,
                issued_at,
                ProductPackage {
                    slug: "twenty",
                    key_name: "twenty-acme-a",
                    display_name: "AIP Twenty connector",
                    artifact_digest: &args.twenty_artifact_digest,
                    endpoint: &args.twenty_acme_a_endpoint,
                    manifest: twenty_manifest,
                    implementation_support: twenty_support,
                },
            )?,
        ),
        (
            "wa-archive",
            product_package(
                args,
                keys,
                issued_at,
                ProductPackage {
                    slug: "wa_archive",
                    key_name: "wa-archive-acme-a",
                    display_name: "AIP WA Archive connector",
                    artifact_digest: &args.wa_archive_artifact_digest,
                    endpoint: &args.wa_archive_acme_a_endpoint,
                    manifest: wa_archive_manifest,
                    implementation_support: wa_archive_support,
                },
            )?,
        ),
    ])
}

struct ProductPackage<'a> {
    slug: &'a str,
    key_name: &'a str,
    display_name: &'a str,
    artifact_digest: &'a str,
    endpoint: &'a str,
    manifest: Manifest,
    implementation_support: BTreeMap<aip_core::CapabilityId, CapabilityImplementationSupport>,
}

fn implementation_support<C>(
    connector: &C,
    manifest: &Manifest,
) -> BTreeMap<aip_core::CapabilityId, CapabilityImplementationSupport>
where
    C: FrozenConnector,
{
    manifest
        .capabilities
        .iter()
        .map(|capability| {
            (
                capability.id.clone(),
                connector.implementation_support(capability),
            )
        })
        .collect()
}

fn product_package(
    args: &Args,
    keys: &FixtureKeys,
    issued_at: OffsetDateTime,
    product: ProductPackage<'_>,
) -> Result<SignedAdmissionPackage, String> {
    let connector_type_id = ConnectorTypeId::parse(format!("ctype_{}", product.slug))
        .map_err(|error| error.to_string())?;
    let version_id = ConnectorVersionId::parse(release_scoped_id(
        &format!("cver_{}_1_0_0", product.slug),
        &args.release_id,
    ))
    .map_err(|error| error.to_string())?;
    let instance_id = ConnectorInstanceId::parse(format!("cinst_{}_acme", product.slug))
        .map_err(|error| error.to_string())?;
    let replica_id = format!("crepl_{}_acme_a", product.slug);
    let host_key = keys
        .replicas
        .get(product.key_name)
        .ok_or_else(|| format!("missing qualification key for {}", product.key_name))?;
    let manifest = qualified_manifest(product.manifest, host_key, &args.trust_domain)?;
    let instance = instance(
        instance_id.clone(),
        connector_type_id.clone(),
        version_id.clone(),
        "tenant-acme",
        &format!("secret://qualification/{}/acme", product.slug),
        args.release_revision,
    );
    let replica = replica(
        &release_scoped_id(&replica_id, &args.release_id),
        instance_id.clone(),
        version_id.clone(),
        product.endpoint,
        &manifest,
        host_key,
        &args.trust_domain,
        "zone-a",
    )?;
    let bindings = capability_bindings(
        &manifest,
        "tenant-acme",
        &instance_id,
        args.release_revision,
    );
    signed_package(
        keys,
        issued_at,
        ConnectorType {
            id: connector_type_id.clone(),
            name: product.display_name.to_owned(),
            owner: args.owner.clone(),
            enabled: true,
        },
        version_declaration(
            version_id,
            connector_type_id,
            manifest,
            product.artifact_digest.to_owned(),
            product.implementation_support,
            &args.release_id,
        )?,
        vec![instance],
        vec![replica],
        bindings,
        &format!("qualification-{}", product.slug),
        args.release_revision,
    )
}

fn qualified_manifest(
    manifest: Manifest,
    signing_key: &SigningKey,
    trust_domain: &str,
) -> Result<Manifest, String> {
    let mut principal = manifest.agent.clone();
    principal.trust_domain = Some(trust_domain.to_owned());
    principal.did = Some(did_key_from_verifying_key(&signing_key.verifying_key()));
    bind_manifest_to_host_principal(manifest, &principal).map_err(|error| error.to_string())
}

fn version_declaration(
    id: ConnectorVersionId,
    connector_type_id: ConnectorTypeId,
    manifest: Manifest,
    artifact_digest: String,
    implementation_support: BTreeMap<aip_core::CapabilityId, CapabilityImplementationSupport>,
    release_id: &str,
) -> Result<ConnectorVersionDeclaration, String> {
    let manifest_digest =
        digest_json(&serde_json::to_value(&manifest).map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    Ok(ConnectorVersionDeclaration {
        id,
        connector_type_id,
        version: format!("1.0.0+{release_id}"),
        status: ConnectorVersionStatus::Active,
        manifest,
        manifest_digest,
        artifact_digest,
        implementation_support,
        supported_aip_versions: BTreeSet::from([AIP_VERSION.to_owned()]),
        sdk_version_requirement: format!("^{}", env!("CARGO_PKG_VERSION")),
    })
}

fn instance(
    id: ConnectorInstanceId,
    connector_type_id: ConnectorTypeId,
    version_id: ConnectorVersionId,
    tenant_id: &str,
    secret_provider_ref: &str,
    config_revision: u64,
) -> ConnectorInstance {
    ConnectorInstance {
        id,
        connector_type_id,
        version_id,
        tenant_id: tenant_id.to_owned(),
        config_revision,
        secret_provider_ref: secret_provider_ref.to_owned(),
        status: ConnectorInstanceStatus::Enabled,
    }
}

#[allow(clippy::too_many_arguments)]
fn replica(
    id: &str,
    instance_id: ConnectorInstanceId,
    version_id: ConnectorVersionId,
    endpoint: &str,
    manifest: &Manifest,
    signing_key: &SigningKey,
    trust_domain: &str,
    zone: &str,
) -> Result<ConnectorReplica, String> {
    Ok(ConnectorReplica {
        id: ConnectorReplicaId::parse(id).map_err(|error| error.to_string())?,
        instance_id,
        version_id,
        endpoint: endpoint.to_owned(),
        peer_principal_id: manifest.agent.id.clone(),
        peer_principal_kind: manifest.agent.kind,
        peer_did: did_key_from_verifying_key(&signing_key.verifying_key()),
        trust_domain: trust_domain.to_owned(),
        transport_profile: ProfileId::from(NATIVE_HTTP_PROFILE),
        topology: ConnectorTopology {
            region: "qualification".to_owned(),
            zone: zone.to_owned(),
            capacity_class: "standard".to_owned(),
        },
        status: ConnectorReplicaStatus::Offline,
        lease_expires_at: OffsetDateTime::UNIX_EPOCH,
        capacity: 16,
        active_assignments: 0,
        health_revision: 0,
        last_control_request_id: None,
        last_control_request_digest: None,
    })
}

fn capability_bindings(
    manifest: &Manifest,
    tenant_id: &str,
    instance_id: &ConnectorInstanceId,
    policy_revision: u64,
) -> Vec<CapabilityBinding> {
    manifest
        .capabilities
        .iter()
        .enumerate()
        .map(|(index, capability)| CapabilityBinding {
            tenant_id: tenant_id.to_owned(),
            capability_id: capability.id.clone(),
            instance_id: instance_id.clone(),
            priority: u32::try_from(index).unwrap_or(u32::MAX),
            policy_revision,
            credential_revision_ref: Some("credential-v1".to_owned()),
            quota_policy_ref: Some(QUALIFICATION_POLICY_REF.to_owned()),
            enabled: true,
        })
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn signed_package(
    keys: &FixtureKeys,
    issued_at: OffsetDateTime,
    connector_type: ConnectorType,
    version: ConnectorVersionDeclaration,
    instances: Vec<ConnectorInstance>,
    replicas: Vec<ConnectorReplica>,
    bindings: Vec<CapabilityBinding>,
    package_id: &str,
    revision: u64,
) -> Result<SignedAdmissionPackage, String> {
    let evidence = signed_evidence(keys, &version, issued_at)?;
    let package = AdmissionPackage {
        schema_version: ADMISSION_PACKAGE_SCHEMA.to_owned(),
        package_id: package_id.to_owned(),
        revision,
        issued_at,
        expires_at: issued_at + Duration::days(30),
        connector_type,
        version,
        admission_policies: vec![AdmissionPolicy::conservative(QUALIFICATION_POLICY_REF)],
        instances,
        replicas,
        bindings,
        evidence,
    };
    sign_admission_package(
        package,
        "aip-connector-fleet-qualification-release-authority",
        &keys.package,
    )
    .map_err(|error| error.to_string())
}

fn signed_evidence(
    keys: &FixtureKeys,
    version: &ConnectorVersionDeclaration,
    issued_at: OffsetDateTime,
) -> Result<BTreeMap<EvidenceKind, aip_connector_admission::SignedEvidence>, String> {
    let mut result = BTreeMap::new();
    for kind in EvidenceKind::all() {
        let document = qualification_document(kind, version);
        let statement = EvidenceStatement {
            schema_version: EVIDENCE_STATEMENT_SCHEMA.to_owned(),
            kind,
            artifact_digest: version.artifact_digest.clone(),
            manifest_digest: version.manifest_digest.clone(),
            document_digest: digest_json(&document).map_err(|error| error.to_string())?,
            signer_identity: format!("aip-qualification-policy/{kind:?}"),
            issued_at,
            expires_at: issued_at + Duration::days(30),
            outcome: kind.required_outcome(),
        };
        result.insert(
            kind,
            sign_evidence(statement, document, &keys.evidence[&kind])
                .map_err(|error| error.to_string())?,
        );
    }
    Ok(result)
}

fn qualification_document(kind: EvidenceKind, version: &ConnectorVersionDeclaration) -> Value {
    let common = json!({
        "schema_version": "aip.connector-fleet-qualification-evidence/v1",
        "scope": "local_deterministic_qualification",
        "kind": kind,
        "artifact_digest": version.artifact_digest,
        "manifest_digest": version.manifest_digest,
        "source_revision": option_env!("AIP_SOURCE_REVISION").unwrap_or("workspace"),
    });
    match kind {
        EvidenceKind::OciSignature => merge_json(
            common,
            json!({
                "verification": "fixture authority bound the immutable image digest"
            }),
        ),
        EvidenceKind::Sbom => merge_json(
            common,
            json!({
                "format": "CycloneDX",
                "component": "connector-host qualification image",
                "qualification_only": true
            }),
        ),
        EvidenceKind::Provenance => merge_json(
            common,
            json!({
                "predicate_type": "https://slsa.dev/provenance/v1",
                "builder": "local BuildKit qualification pipeline"
            }),
        ),
        EvidenceKind::Conformance => merge_json(
            common,
            json!({
                "suite": "AIP connector host multiprocess qualification",
                "result": "passed"
            }),
        ),
        EvidenceKind::Vulnerability => merge_json(
            common,
            json!({
                "policy": "no known critical or high findings at qualification time",
                "result": "passed"
            }),
        ),
        EvidenceKind::License => merge_json(
            common,
            json!({
                "policy": "AIP Core BUSL-1.1 qualification boundary",
                "result": "passed"
            }),
        ),
        EvidenceKind::Revocation => merge_json(
            common,
            json!({
                "registry": "isolated qualification trust root",
                "revoked": false,
                "result": "passed"
            }),
        ),
    }
}

fn merge_json(mut left: Value, right: Value) -> Value {
    if let (Some(left), Some(right)) = (left.as_object_mut(), right.as_object()) {
        left.extend(right.clone());
    }
    left
}

fn evidence_seed_name(kind: EvidenceKind) -> &'static str {
    match kind {
        EvidenceKind::OciSignature => "evidence-oci-signature-seed.hex",
        EvidenceKind::Sbom => "evidence-sbom-seed.hex",
        EvidenceKind::Provenance => "evidence-provenance-seed.hex",
        EvidenceKind::Conformance => "evidence-conformance-seed.hex",
        EvidenceKind::Vulnerability => "evidence-vulnerability-seed.hex",
        EvidenceKind::License => "evidence-license-seed.hex",
        EvidenceKind::Revocation => "evidence-revocation-seed.hex",
    }
}

fn read_signing_key(path: &Path) -> Result<SigningKey, String> {
    let encoded = read_secret_utf8(path, MAX_SECRET_BYTES).map_err(|error| error.to_string())?;
    let mut decoded = hex::decode(encoded.as_bytes())
        .map_err(|_| format!("signing seed `{}` is not hexadecimal", path.display()))?;
    let mut seed: [u8; 32] = decoded.as_slice().try_into().map_err(|_| {
        format!(
            "signing seed `{}` must encode exactly 32 bytes",
            path.display()
        )
    })?;
    decoded.zeroize();
    let key = signing_key_from_seed(seed);
    seed.zeroize();
    Ok(key)
}

fn read_issued_at(path: &Path) -> Result<OffsetDateTime, String> {
    let value = read_secret_utf8(path, 64).map_err(|error| error.to_string())?;
    let timestamp = value
        .parse::<i64>()
        .map_err(|_| "issued-at.txt must contain a Unix timestamp".to_owned())?;
    OffsetDateTime::from_unix_timestamp(timestamp)
        .map_err(|error| format!("issued-at.txt is outside the supported time range: {error}"))
}

fn validate_text(label: &str, value: &str, max_bytes: usize) -> Result<(), String> {
    if value.trim().is_empty() || value.len() > max_bytes || value.chars().any(char::is_control) {
        return Err(format!(
            "{label} must contain 1 to {max_bytes} printable bytes"
        ));
    }
    Ok(())
}

fn write_json_atomic(path: &Path, value: &impl Serialize) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    write_atomic(path, &bytes)
}

fn write_text_atomic(path: &Path, value: &str) -> Result<(), String> {
    let mut bytes = value.as_bytes().to_vec();
    bytes.push(b'\n');
    write_atomic(path, &bytes)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), String> {
    let parent = path
        .parent()
        .ok_or_else(|| format!("output path `{}` has no parent", path.display()))?;
    fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    let temp = parent.join(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| "output file name must be UTF-8".to_owned())?,
        std::process::id()
    ));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|error| format!("cannot create `{}`: {error}", temp.display()))?;
    let result = (|| {
        file.write_all(bytes).map_err(|error| error.to_string())?;
        file.sync_all().map_err(|error| error.to_string())?;
        fs::rename(&temp, path).map_err(|error| error.to_string())?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| error.to_string())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::{
        approval_authority_directory, release_scoped_id, trusted_identity_directory,
        validate_artifact_digest, validate_release_id,
    };
    use serde_json::Value;
    use time::{Duration, OffsetDateTime};

    fn issued_at() -> OffsetDateTime {
        OffsetDateTime::UNIX_EPOCH + Duration::seconds(1_900_000_000)
    }

    fn identity_for<'a>(bindings: &'a [Value], principal_id: &str) -> Result<&'a Value, String> {
        bindings
            .iter()
            .find(|binding| binding["principal_id"] == principal_id)
            .and_then(|binding| binding.get("identity"))
            .ok_or_else(|| format!("product principal `{principal_id}` has no trusted identity"))
    }

    #[test]
    fn release_ids_are_safe_for_registry_identifiers_and_semver_metadata() {
        assert!(validate_release_id("2cb720cd8cc0e5d6").is_ok());
        assert_eq!(
            release_scoped_id("cver_chatwoot_1_0_0", "2cb720cd8cc0e5d6"),
            "cver_chatwoot_1_0_0_2cb720cd8cc0e5d6"
        );
    }

    #[test]
    fn release_ids_reject_ambiguous_or_unsafe_values() {
        for value in ["", "UPPER", "contains-dash", "contains space"] {
            assert!(validate_release_id(value).is_err(), "accepted `{value}`");
        }
        assert!(validate_release_id(&"a".repeat(33)).is_err());
    }

    #[test]
    fn artifact_digest_accepts_a_canonical_non_placeholder_digest() {
        assert!(
            validate_artifact_digest("fixture", &format!("sha256:{}", "a1".repeat(32))).is_ok()
        );
    }

    #[test]
    fn artifact_digest_rejects_placeholders_and_noncanonical_text() {
        for digest in [
            format!("sha256:{}", "0".repeat(64)),
            format!("sha256:{}", "A1".repeat(32)),
            "sha512:abcd".to_owned(),
        ] {
            assert!(validate_artifact_digest("fixture", &digest).is_err());
        }
    }

    #[test]
    fn product_identities_are_bound_to_exact_external_accounts() -> Result<(), String> {
        let twenty_workspace_id = "b61e197a-0cb8-4035-acbc-3e9cf4fe8a0a";
        let bindings = trusted_identity_directory(issued_at(), twenty_workspace_id)?;
        assert_eq!(bindings.len(), 5);

        assert_eq!(
            identity_for(&bindings, "service:getaip:cli:qualification-cal")?["external_account"],
            serde_json::json!({"id": "42", "system": "cal_diy"})
        );
        assert_eq!(
            identity_for(&bindings, "service:getaip:cli:qualification-chatwoot")?["external_account"],
            serde_json::json!({"id": "42", "system": "chatwoot"})
        );
        assert_eq!(
            identity_for(&bindings, "service:getaip:cli:qualification-twenty")?["external_account"],
            serde_json::json!({
                "id": twenty_workspace_id,
                "system": "twenty"
            })
        );
        assert!(
            bindings
                .iter()
                .find(|binding| {
                    binding["principal_id"] == "service:getaip:cli:qualification-acme"
                })
                .and_then(|binding| binding.get("identity"))
                .is_none(),
            "the generic tenant principal must not inherit a provider account"
        );
        Ok(())
    }

    #[test]
    fn approval_authority_is_human_tenant_scoped_and_policy_scoped() -> Result<(), String> {
        let authorities = approval_authority_directory(issued_at())?;
        assert_eq!(authorities.len(), 1);
        let authority = &authorities[0];
        assert_eq!(authority["principal_id"], "human:qualification-approver");
        assert_eq!(authority["tenant_id"], "tenant-acme");
        assert_eq!(
            authority["tenant_policies"],
            serde_json::json!(["policy:connector-fleet-qualification"])
        );
        assert_eq!(authority["revoked"], false);
        assert_eq!(authority["revision"], 1);
        Ok(())
    }
}
