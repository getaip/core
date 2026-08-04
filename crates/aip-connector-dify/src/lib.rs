//! Dify connector mappings for AIP.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic))]

mod operations;

pub use operations::{
    ALL_DIFY_OPERATIONS, DifyHttpMethod, DifyOperation, DifyOperationScope, DifyRequestKind,
    DifyResponseKind, DifyUserLocation, UPSTREAM_REVISION,
};

use aip_connector::{
    CapabilityImplementationSupport, CapabilityProviderConnector, Connector, ConnectorContext,
    ConnectorError, ConnectorFailure, ConnectorHealth, ConnectorOperation, ConnectorResult,
    ConnectorSecret, FrozenConnector, OutboundConnector,
};
use aip_core::{
    Action, ActionId, ActionResult, ActionResultStatus, ApprovalPolicy, ApproverSelector,
    Capability, CapabilityContract, CapabilityId, CapabilityKind, CompensationContract,
    CompensationMode, DataContract, DataSensitivity, ErrorCategory, Escalation, EscalationKind,
    EvidenceRequirement, ExecutionContract, ExpectedCompletionMode, IdempotencyCollisionBehavior,
    IdempotencyContract, IdempotencyKeyScope, IdempotencyRequirement, Manifest, MessagePart,
    Principal, PrincipalId, PrincipalKind, ProfileId, ProtocolError, RetrySafety, RiskLevel,
    ServiceLevelContract, SideEffect, StreamChunk, StreamChunkKind,
};
use aip_runtime::{
    ActionExecutionContext, ActionHandler, ProfileStateStore, RuntimeError, RuntimeResult,
};
use async_trait::async_trait;
use base64::Engine;
use futures_util::{StreamExt, stream};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fmt,
    net::IpAddr,
    path::{Path, PathBuf},
    str,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;
use tokio::sync::RwLock;
use url::Url;

/// Stable connector id.
pub const CONNECTOR_ID: &str = "dify";
/// AIP profile id for Dify-specific binding metadata.
pub const PROFILE_ID: &str = "aip.connector.dify.v1";
const MAX_SSE_FRAME_BYTES: usize = 1024 * 1024;
const MAX_SSE_EVENTS: usize = 10_000;
const DEFAULT_MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const MAX_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
const HEALTH_CONCURRENCY: usize = 32;
const MAX_UPLOAD_BYTES: usize = 32 * 1024 * 1024;
const MAX_JSON_REQUEST_BYTES: usize = 8 * 1024 * 1024;
const MAX_QUERY_VALUE_BYTES: usize = 32 * 1024;
const MAX_REQUEST_URL_BYTES: usize = 128 * 1024;

/// Dify application descriptor.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DifyApp {
    /// Dify app id.
    pub id: String,
    /// App name.
    pub name: String,
    /// App mode, for example `workflow` or `agent`.
    pub mode: String,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// One Dify application and the credential issued specifically for that app.
///
/// Dify service API keys are application-scoped. Production hosts must use
/// this type instead of accidentally sharing one key across unrelated apps.
#[derive(Clone)]
pub struct DifyAppCredential {
    /// Public application descriptor included in discovery.
    pub app: DifyApp,
    /// Protected application API key.
    pub api_key: ConnectorSecret,
}

impl fmt::Debug for DifyAppCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DifyAppCredential")
            .field("app", &self.app)
            .field("api_key", &self.api_key)
            .finish()
    }
}

/// Public descriptor for one workspace-scoped Dify Knowledge API credential.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DifyKnowledgeBase {
    /// Stable local credential id used in capability identifiers.
    pub id: String,
    /// Human-readable workspace or knowledge integration name.
    pub name: String,
    /// Optional operator description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// One workspace Knowledge API descriptor and its protected API key.
#[derive(Clone)]
pub struct DifyKnowledgeCredential {
    /// Public descriptor included in discovery.
    pub knowledge: DifyKnowledgeBase,
    /// Protected workspace Knowledge API key.
    pub api_key: ConnectorSecret,
}

impl fmt::Debug for DifyKnowledgeCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DifyKnowledgeCredential")
            .field("knowledge", &self.knowledge)
            .field("api_key", &self.api_key)
            .finish()
    }
}

/// Dify streaming event.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DifyStreamEvent {
    /// Event name from Dify.
    pub event: String,
    /// Event payload.
    pub data: Value,
}

/// Dify HTTP connector.
#[derive(Clone)]
pub struct DifyConnector {
    base_url: Url,
    apps: BTreeMap<String, DifyApp>,
    api_keys: BTreeMap<String, ConnectorSecret>,
    knowledge: BTreeMap<String, DifyKnowledgeBase>,
    knowledge_api_keys: BTreeMap<String, ConnectorSecret>,
    client: reqwest::Client,
    active_tasks: Arc<dyn DifyTaskStore>,
    max_response_bytes: usize,
}

impl fmt::Debug for DifyConnector {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DifyConnector")
            .field("base_url", &self.base_url)
            .field("apps", &self.apps)
            .field("api_keys", &"[REDACTED]")
            .field("knowledge", &self.knowledge)
            .field("knowledge_api_keys", &"[REDACTED]")
            .field("max_response_bytes", &self.max_response_bytes)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DifyApiFamily {
    Workflow,
    Completion,
    Chat,
}

/// Durable remote task identity needed to cancel a Dify execution.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DifyTaskReference {
    /// Configured Dify application id.
    pub app_id: String,
    /// Remote Dify task id.
    pub task_id: String,
    /// Dify user value required by the stop endpoint.
    pub user: String,
}

/// Durable mapping from AIP action ids to active Dify task ids.
#[async_trait]
pub trait DifyTaskStore: Send + Sync {
    /// Stores or replaces the active task for an action.
    async fn put(&self, action_id: &ActionId, task: DifyTaskReference) -> Result<(), String>;
    /// Returns the active task without destroying the cancellation evidence.
    async fn get(&self, action_id: &ActionId) -> Result<Option<DifyTaskReference>, String>;
    /// Removes and returns the active task for an action.
    async fn take(&self, action_id: &ActionId) -> Result<Option<DifyTaskReference>, String>;
    /// Removes a completed task mapping.
    async fn remove(&self, action_id: &ActionId) -> Result<(), String>;
}

/// Process-local task store for tests and ephemeral deployments.
#[derive(Debug, Default)]
pub struct InMemoryDifyTaskStore {
    tasks: RwLock<BTreeMap<String, DifyTaskReference>>,
}

/// Cluster-safe Dify task correlation backed by runtime profile state.
#[derive(Clone)]
pub struct ProfileStateDifyTaskStore {
    state: ProfileStateStore,
    scope: String,
}

impl std::fmt::Debug for ProfileStateDifyTaskStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileStateDifyTaskStore")
            .field("scope", &self.scope)
            .finish_non_exhaustive()
    }
}

impl ProfileStateDifyTaskStore {
    /// Creates task correlation for one logical connector instance.
    pub fn new(state: ProfileStateStore, scope: impl Into<String>) -> Result<Self, String> {
        let scope = scope.into();
        if scope.trim().is_empty()
            || scope.len() > 512
            || scope.contains('\0')
            || scope.contains('/')
        {
            return Err(
                "Dify task-store scope must contain 1 to 512 bytes without NUL or slash".to_owned(),
            );
        }
        Ok(Self { state, scope })
    }

    fn key(&self, action_id: &ActionId) -> String {
        format!("{}/{}", self.scope, action_id)
    }
}

#[async_trait]
impl DifyTaskStore for ProfileStateDifyTaskStore {
    async fn put(&self, action_id: &ActionId, task: DifyTaskReference) -> Result<(), String> {
        self.state
            .put(
                "aip.connector.dify.active_tasks.v1",
                &self.key(action_id),
                serde_json::to_value(task)
                    .map_err(|error| format!("encode Dify task reference: {error}"))?,
            )
            .await
            .map(|_| ())
            .map_err(|error| error.to_string())
    }

    async fn get(&self, action_id: &ActionId) -> Result<Option<DifyTaskReference>, String> {
        self.state
            .get("aip.connector.dify.active_tasks.v1", &self.key(action_id))
            .await
            .map_err(|error| error.to_string())?
            .map(|entry| {
                serde_json::from_value(entry.value)
                    .map_err(|error| format!("decode Dify task reference: {error}"))
            })
            .transpose()
    }

    async fn take(&self, action_id: &ActionId) -> Result<Option<DifyTaskReference>, String> {
        const NAMESPACE: &str = "aip.connector.dify.active_tasks.v1";
        let key = self.key(action_id);
        for _ in 0..32 {
            let Some(entry) = self
                .state
                .get(NAMESPACE, &key)
                .await
                .map_err(|error| error.to_string())?
            else {
                return Ok(None);
            };
            let task = serde_json::from_value(entry.value.clone())
                .map_err(|error| format!("decode Dify task reference: {error}"))?;
            if self
                .state
                .delete(NAMESPACE, &key, entry.revision)
                .await
                .map_err(|error| error.to_string())?
            {
                return Ok(Some(task));
            }
            tokio::task::yield_now().await;
        }
        Err("Dify task reference remained contended after 32 attempts".to_owned())
    }

    async fn remove(&self, action_id: &ActionId) -> Result<(), String> {
        self.take(action_id).await.map(|_| ())
    }
}

#[async_trait]
impl DifyTaskStore for InMemoryDifyTaskStore {
    async fn put(&self, action_id: &ActionId, task: DifyTaskReference) -> Result<(), String> {
        self.tasks.write().await.insert(action_id.to_string(), task);
        Ok(())
    }

    async fn get(&self, action_id: &ActionId) -> Result<Option<DifyTaskReference>, String> {
        Ok(self.tasks.read().await.get(&action_id.to_string()).cloned())
    }

    async fn take(&self, action_id: &ActionId) -> Result<Option<DifyTaskReference>, String> {
        Ok(self.tasks.write().await.remove(&action_id.to_string()))
    }

    async fn remove(&self, action_id: &ActionId) -> Result<(), String> {
        self.tasks.write().await.remove(&action_id.to_string());
        Ok(())
    }
}

/// Durable single-host Dify task store using atomic file replacement.
#[derive(Debug)]
pub struct FileDifyTaskStore {
    path: PathBuf,
    lock: tokio::sync::Mutex<()>,
}

impl FileDifyTaskStore {
    /// Creates a task store at the supplied durable state path.
    #[must_use]
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            lock: tokio::sync::Mutex::new(()),
        }
    }

    /// Returns the durable state path.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    async fn update<T>(
        &self,
        update: impl FnOnce(&mut BTreeMap<String, DifyTaskReference>) -> T,
    ) -> Result<T, String> {
        let _guard = self.lock.lock().await;
        let mut tasks = match tokio::fs::read(&self.path).await {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| format!("decode Dify task store: {error}"))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(format!("read Dify task store: {error}")),
        };
        let result = update(&mut tasks);
        if let Some(parent) = self.path.parent()
            && !parent.as_os_str().is_empty()
        {
            tokio::fs::create_dir_all(parent)
                .await
                .map_err(|error| format!("create Dify task-store directory: {error}"))?;
        }
        let temporary = self.path.with_extension("tmp");
        let encoded = serde_json::to_vec(&tasks)
            .map_err(|error| format!("encode Dify task store: {error}"))?;
        tokio::fs::write(&temporary, encoded)
            .await
            .map_err(|error| format!("write Dify task store: {error}"))?;
        tokio::fs::rename(&temporary, &self.path)
            .await
            .map_err(|error| format!("replace Dify task store: {error}"))?;
        Ok(result)
    }
}

#[async_trait]
impl DifyTaskStore for FileDifyTaskStore {
    async fn put(&self, action_id: &ActionId, task: DifyTaskReference) -> Result<(), String> {
        self.update(|tasks| {
            tasks.insert(action_id.to_string(), task);
        })
        .await
    }

    async fn get(&self, action_id: &ActionId) -> Result<Option<DifyTaskReference>, String> {
        let _guard = self.lock.lock().await;
        let tasks = match tokio::fs::read(&self.path).await {
            Ok(bytes) => serde_json::from_slice::<BTreeMap<String, DifyTaskReference>>(&bytes)
                .map_err(|error| format!("decode Dify task store: {error}"))?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(format!("read Dify task store: {error}")),
        };
        Ok(tasks.get(&action_id.to_string()).cloned())
    }

    async fn take(&self, action_id: &ActionId) -> Result<Option<DifyTaskReference>, String> {
        self.update(|tasks| tasks.remove(&action_id.to_string()))
            .await
    }

    async fn remove(&self, action_id: &ActionId) -> Result<(), String> {
        self.update(|tasks| {
            tasks.remove(&action_id.to_string());
        })
        .await
    }
}

impl DifyConnector {
    /// Creates a connector from static app descriptors and an API key.
    pub fn new(
        base_url: impl AsRef<str>,
        api_key: impl Into<String>,
        apps: Vec<DifyApp>,
    ) -> Result<Self, DifyConnectorError> {
        Self::with_api_key(base_url, ConnectorSecret::from(api_key.into()), apps)
    }

    /// Creates a connector from static app descriptors and protected API-key material.
    ///
    /// Standalone production hosts should use this constructor so the key never
    /// passes through an unprotected intermediate `String` owned by the connector.
    pub fn with_api_key(
        base_url: impl AsRef<str>,
        api_key: ConnectorSecret,
        apps: Vec<DifyApp>,
    ) -> Result<Self, DifyConnectorError> {
        let credentials = apps
            .into_iter()
            .map(|app| DifyAppCredential {
                app,
                api_key: api_key.clone(),
            })
            .collect();
        Self::with_app_credentials(base_url, credentials)
    }

    /// Creates a connector with one protected service API key per Dify app.
    pub fn with_app_credentials(
        base_url: impl AsRef<str>,
        credentials: Vec<DifyAppCredential>,
    ) -> Result<Self, DifyConnectorError> {
        Self::with_credentials(base_url, credentials, Vec::new())
    }

    /// Creates a connector with independently scoped application and Knowledge API credentials.
    pub fn with_credentials(
        base_url: impl AsRef<str>,
        credentials: Vec<DifyAppCredential>,
        knowledge_credentials: Vec<DifyKnowledgeCredential>,
    ) -> Result<Self, DifyConnectorError> {
        let base_url = validate_base_url(base_url.as_ref())?;
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(900))
            .build()
            .map_err(|error| DifyConnectorError::InvalidClient(error.to_string()))?;
        if credentials.is_empty() && knowledge_credentials.is_empty() {
            return Err(DifyConnectorError::NoApps);
        }
        let mut configured_apps = BTreeMap::new();
        let mut api_keys = BTreeMap::new();
        for credential in credentials {
            let DifyAppCredential { app, api_key } = credential;
            validate_app(&app)?;
            validate_api_key(&api_key)?;
            let app_id = app.id.clone();
            if configured_apps.insert(app_id.clone(), app).is_some() {
                return Err(DifyConnectorError::InvalidApp(
                    "Dify app ids must be unique".to_owned(),
                ));
            }
            api_keys.insert(app_id, api_key);
        }
        let mut knowledge = BTreeMap::new();
        let mut knowledge_api_keys = BTreeMap::new();
        for credential in knowledge_credentials {
            let DifyKnowledgeCredential {
                knowledge: descriptor,
                api_key,
            } = credential;
            validate_knowledge(&descriptor)?;
            validate_api_key(&api_key)?;
            let descriptor_id = descriptor.id.clone();
            if knowledge
                .insert(descriptor_id.clone(), descriptor)
                .is_some()
            {
                return Err(DifyConnectorError::InvalidApp(
                    "Dify knowledge credential ids must be unique".to_owned(),
                ));
            }
            knowledge_api_keys.insert(descriptor_id, api_key);
        }
        Ok(Self {
            base_url,
            apps: configured_apps,
            api_keys,
            knowledge,
            knowledge_api_keys,
            client,
            active_tasks: Arc::new(InMemoryDifyTaskStore::default()),
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        })
    }

    /// Returns the configured Dify apps.
    #[must_use]
    pub fn apps(&self) -> &BTreeMap<String, DifyApp> {
        &self.apps
    }

    /// Returns configured workspace Knowledge API descriptors.
    #[must_use]
    pub fn knowledge_credentials(&self) -> &BTreeMap<String, DifyKnowledgeBase> {
        &self.knowledge
    }

    /// Sets the durable mapping used to recover remote Dify task ids.
    #[must_use]
    pub fn with_task_store(mut self, task_store: Arc<dyn DifyTaskStore>) -> Self {
        self.active_tasks = task_store;
        self
    }

    /// Sets the maximum accepted blocking response or complete event stream.
    pub fn with_max_response_bytes(
        mut self,
        max_response_bytes: usize,
    ) -> Result<Self, DifyConnectorError> {
        if !(1..=MAX_RESPONSE_BYTES).contains(&max_response_bytes) {
            return Err(DifyConnectorError::InvalidApp(format!(
                "max_response_bytes must be between 1 and {MAX_RESPONSE_BYTES}"
            )));
        }
        self.max_response_bytes = max_response_bytes;
        Ok(self)
    }

    fn api_key(&self, app_id: &str) -> Result<&str, DifyConnectorError> {
        self.api_keys
            .get(app_id)
            .ok_or_else(|| DifyConnectorError::CapabilityNotFound(format!("cap:dify:{app_id}")))?
            .expose_str()
            .map_err(|_| DifyConnectorError::InvalidCredential)
    }

    fn knowledge_api_key(&self, credential_id: &str) -> Result<&str, DifyConnectorError> {
        self.knowledge_api_keys
            .get(credential_id)
            .ok_or_else(|| {
                DifyConnectorError::CapabilityNotFound(format!(
                    "cap:dify:knowledge:{credential_id}"
                ))
            })?
            .expose_str()
            .map_err(|_| DifyConnectorError::InvalidCredential)
    }
}

fn validate_app(app: &DifyApp) -> Result<(), DifyConnectorError> {
    if app.id.trim().is_empty()
        || app.name.trim().is_empty()
        || app.id == "knowledge"
        || app.id.len() > 256
        || app.name.len() > 512
        || app.id.chars().any(char::is_control)
        || app.name.chars().any(char::is_control)
    {
        return Err(DifyConnectorError::InvalidApp(
            "app id and name must be non-empty".to_owned(),
        ));
    }
    CapabilityId::parse(format!("cap:dify:{}", app.id))
        .map_err(|error| DifyConnectorError::InvalidApp(error.to_string()))?;
    dify_api_family(&app.mode).map(|_| ())
}

fn validate_knowledge(knowledge: &DifyKnowledgeBase) -> Result<(), DifyConnectorError> {
    if knowledge.id.trim().is_empty()
        || knowledge.name.trim().is_empty()
        || knowledge.id.len() > 256
        || knowledge.name.len() > 512
        || knowledge.id.chars().any(char::is_control)
        || knowledge.name.chars().any(char::is_control)
    {
        return Err(DifyConnectorError::InvalidApp(
            "knowledge credential id and name must be non-empty and the id must not contain control characters"
                .to_owned(),
        ));
    }
    CapabilityId::parse(format!("cap:dify:knowledge:{}:dataset.list", knowledge.id))
        .map_err(|error| DifyConnectorError::InvalidApp(error.to_string()))?;
    Ok(())
}

fn validate_api_key(api_key: &ConnectorSecret) -> Result<(), DifyConnectorError> {
    let value = api_key
        .expose_str()
        .map_err(|_| DifyConnectorError::InvalidCredential)?;
    if value.trim().is_empty()
        || value.len() > 16 * 1024
        || value.bytes().any(|byte| byte.is_ascii_whitespace())
        || value.chars().any(char::is_control)
    {
        return Err(DifyConnectorError::InvalidCredential);
    }
    Ok(())
}

fn validate_base_url(value: &str) -> Result<Url, DifyConnectorError> {
    let url = Url::parse(value).map_err(DifyConnectorError::InvalidUrl)?;
    if url.host_str().is_none()
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || !matches!(url.path(), "" | "/")
    {
        return Err(DifyConnectorError::InvalidBaseUrl(
            "base URL must be an origin without credentials, path prefix, query, or fragment"
                .to_owned(),
        ));
    }
    let loopback = url.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("localhost")
            || host
                .parse::<IpAddr>()
                .is_ok_and(|address| address.is_loopback())
    });
    if url.scheme() != "https" && !(url.scheme() == "http" && loopback) {
        return Err(DifyConnectorError::InvalidBaseUrl(
            "Dify requires HTTPS except for an explicit loopback provider".to_owned(),
        ));
    }
    Ok(url)
}

fn parse_dify_capability<'a>(
    apps: &'a BTreeMap<String, DifyApp>,
    capability_id: &str,
) -> Option<(&'a DifyApp, Option<DifyOperation>)> {
    let raw = capability_id.strip_prefix("cap:dify:")?;
    if let Some(app) = apps.get(raw) {
        return Some((app, None));
    }
    apps.iter()
        .filter_map(|(app_id, app)| {
            let suffix = raw.strip_prefix(app_id)?.strip_prefix(':')?;
            let operation = DifyOperation::from_suffix(suffix)?;
            operation
                .supports_mode(&app.mode)
                .then_some((app_id.len(), app, operation))
        })
        .max_by_key(|(length, _, _)| *length)
        .map(|(_, app, operation)| (app, Some(operation)))
}

fn parse_dify_knowledge_capability<'a>(
    knowledge: &'a BTreeMap<String, DifyKnowledgeBase>,
    capability_id: &str,
) -> Option<(&'a DifyKnowledgeBase, DifyOperation)> {
    let raw = capability_id.strip_prefix("cap:dify:knowledge:")?;
    knowledge
        .iter()
        .filter_map(|(credential_id, descriptor)| {
            let suffix = raw.strip_prefix(credential_id)?.strip_prefix(':')?;
            let operation = DifyOperation::from_suffix(suffix)?;
            (operation.scope() == DifyOperationScope::Knowledge).then_some((
                credential_id.len(),
                descriptor,
                operation,
            ))
        })
        .max_by_key(|(length, _, _)| *length)
        .map(|(_, descriptor, operation)| (descriptor, operation))
}

fn dify_path_parameters(template: &str) -> Vec<&str> {
    template
        .split('/')
        .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
        .collect()
}

fn dify_operation_url(
    base_url: &Url,
    operation: DifyOperation,
    input: &Value,
) -> Result<Url, DifyConnectorError> {
    let mut url = base_url.clone();
    url.set_path("");
    let mut rendered = Vec::new();
    for segment in operation
        .path_template()
        .split('/')
        .filter(|value| !value.is_empty())
    {
        let value = match segment
            .strip_prefix('{')
            .and_then(|value| value.strip_suffix('}'))
        {
            Some(parameter) => required_dify_string(input, parameter)?.to_owned(),
            None => segment.to_owned(),
        };
        if value.len() > 512 || value.chars().any(char::is_control) {
            return Err(DifyConnectorError::InvalidInput(format!(
                "invalid path parameter for Dify operation `{}`",
                operation.suffix()
            )));
        }
        rendered.push(value);
    }
    {
        let mut segments = url.path_segments_mut().map_err(|()| {
            DifyConnectorError::InvalidInput("Dify base URL cannot accept path segments".to_owned())
        })?;
        segments.clear();
        for segment in &rendered {
            segments.push(segment);
        }
    }
    Ok(url)
}

fn append_dify_query(
    url: &mut Url,
    query: Option<&Value>,
    user: Option<&str>,
) -> Result<(), DifyConnectorError> {
    let query = query
        .map(|value| {
            value.as_object().ok_or_else(|| {
                DifyConnectorError::InvalidInput("input `query` must be an object".to_owned())
            })
        })
        .transpose()?;
    if query.is_some_and(|query| query.len() > 128) {
        return Err(DifyConnectorError::InvalidInput(
            "input `query` exceeds 128 keys".to_owned(),
        ));
    }
    let mut appended = false;
    let mut pairs = url.query_pairs_mut();
    if let Some(query) = query {
        for (key, value) in query {
            if key == "user" && user.is_some_and(|user| value.as_str() != Some(user)) {
                return Err(DifyConnectorError::InvalidInput(
                    "query `user` conflicts with the required end-user identity".to_owned(),
                ));
            }
            if key.is_empty() || key.len() > 256 || key.chars().any(char::is_control) {
                return Err(DifyConnectorError::InvalidInput(
                    "query names must contain 1 to 256 bytes without control characters".to_owned(),
                ));
            }
            match value {
                Value::Null => {}
                Value::Array(values) if values.len() <= 256 => {
                    for value in values {
                        pairs.append_pair(key, &dify_query_scalar(value)?);
                        appended = true;
                    }
                }
                Value::Array(_) => {
                    return Err(DifyConnectorError::InvalidInput(format!(
                        "query `{key}` exceeds 256 values"
                    )));
                }
                value => {
                    pairs.append_pair(key, &dify_query_scalar(value)?);
                    appended = true;
                }
            }
        }
    }
    if let Some(user) = user {
        if user.len() > 256 || user.chars().any(char::is_control) {
            return Err(DifyConnectorError::InvalidInput(
                "Dify user query identity exceeds its bound".to_owned(),
            ));
        }
        pairs.append_pair("user", user);
        appended = true;
    }
    drop(pairs);
    // `Url::query_pairs_mut` materializes an empty `?` even when no pair is
    // appended. Preserve canonical upstream paths for operations with an
    // absent or all-null query object.
    if !appended {
        url.set_query(None);
    }
    if url.as_str().len() > MAX_REQUEST_URL_BYTES {
        return Err(DifyConnectorError::InvalidInput(format!(
            "encoded request URL exceeds {MAX_REQUEST_URL_BYTES} bytes"
        )));
    }
    Ok(())
}

fn dify_query_scalar(value: &Value) -> Result<String, DifyConnectorError> {
    let value = match value {
        Value::String(value) => value.clone(),
        Value::Number(value) => value.to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Null => String::new(),
        Value::Array(_) | Value::Object(_) => Err(DifyConnectorError::InvalidInput(
            "query values must be scalar or arrays of scalars".to_owned(),
        ))?,
    };
    if value.len() > MAX_QUERY_VALUE_BYTES || value.chars().any(char::is_control) {
        return Err(DifyConnectorError::InvalidInput(format!(
            "query value exceeds {MAX_QUERY_VALUE_BYTES} bytes or contains control characters"
        )));
    }
    Ok(value)
}

fn required_dify_string<'a>(input: &'a Value, field: &str) -> Result<&'a str, DifyConnectorError> {
    input
        .get(field)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DifyConnectorError::InvalidInput(format!("missing input `{field}`")))
}

fn required_dify_user(input: &Value) -> Result<&str, DifyConnectorError> {
    let user = required_dify_string(input, "user")?;
    if user.len() > 256 || user.chars().any(char::is_control) {
        return Err(DifyConnectorError::InvalidInput(
            "user must contain 1 to 256 bytes without control characters".to_owned(),
        ));
    }
    Ok(user)
}

fn required_dify_idempotency_key(action: &Action) -> Result<&str, DifyConnectorError> {
    action
        .idempotency_key
        .as_deref()
        .filter(|key| {
            !key.trim().is_empty() && key.len() <= 512 && !key.chars().any(char::is_control)
        })
        .ok_or_else(|| {
            DifyConnectorError::InvalidInput(
                "Dify mutations require Action.idempotency_key".to_owned(),
            )
        })
}

fn insert_dify_user(
    body: &mut serde_json::Map<String, Value>,
    user: &str,
) -> Result<(), DifyConnectorError> {
    if body
        .get("user")
        .is_some_and(|value| value.as_str() != Some(user))
    {
        return Err(DifyConnectorError::InvalidInput(
            "body `user` conflicts with the required end-user identity".to_owned(),
        ));
    }
    body.insert("user".to_owned(), Value::String(user.to_owned()));
    Ok(())
}

fn dify_upload_part(input: &Value) -> Result<reqwest::multipart::Part, DifyConnectorError> {
    let file = input
        .get("file")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            DifyConnectorError::InvalidInput("input `file` must be an object".to_owned())
        })?;
    let filename = file
        .get("filename")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| DifyConnectorError::InvalidInput("file filename is required".to_owned()))?;
    if filename.len() > 512
        || filename.chars().any(char::is_control)
        || filename.contains(['/', '\\'])
    {
        return Err(DifyConnectorError::InvalidInput(
            "file filename is not a safe basename".to_owned(),
        ));
    }
    let encoded = file
        .get("content_base64")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            DifyConnectorError::InvalidInput("file content_base64 is required".to_owned())
        })?;
    if encoded.len()
        > MAX_UPLOAD_BYTES
            .saturating_mul(4)
            .div_ceil(3)
            .saturating_add(4)
    {
        return Err(DifyConnectorError::InvalidInput(format!(
            "decoded file exceeds {MAX_UPLOAD_BYTES} bytes"
        )));
    }
    let content = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| {
            DifyConnectorError::InvalidInput(format!("invalid file base64: {error}"))
        })?;
    if content.len() > MAX_UPLOAD_BYTES {
        return Err(DifyConnectorError::InvalidInput(format!(
            "decoded file exceeds {MAX_UPLOAD_BYTES} bytes"
        )));
    }
    let content_type = file
        .get("content_type")
        .and_then(Value::as_str)
        .unwrap_or("application/octet-stream");
    reqwest::multipart::Part::bytes(content)
        .file_name(filename.to_owned())
        .mime_str(content_type)
        .map_err(DifyConnectorError::Http)
}

fn dify_api_family(mode: &str) -> Result<DifyApiFamily, DifyConnectorError> {
    match mode {
        "workflow" => Ok(DifyApiFamily::Workflow),
        "completion" => Ok(DifyApiFamily::Completion),
        "chat" | "agent-chat" | "advanced-chat" | "agent" => Ok(DifyApiFamily::Chat),
        unsupported => Err(DifyConnectorError::InvalidApp(format!(
            "unsupported app mode `{unsupported}`"
        ))),
    }
}

fn invocation_path(app: &DifyApp) -> Result<&'static str, DifyConnectorError> {
    match dify_api_family(&app.mode)? {
        DifyApiFamily::Workflow => Ok("/v1/workflows/run"),
        DifyApiFamily::Completion => Ok("/v1/completion-messages"),
        DifyApiFamily::Chat => Ok("/v1/chat-messages"),
    }
}

fn invocation_path_for_mode(mode: &str) -> &'static str {
    match mode {
        "workflow" => "/v1/workflows/run",
        "completion" => "/v1/completion-messages",
        _ => "/v1/chat-messages",
    }
}

fn cancellation_path(app: &DifyApp, task_id: &str) -> Result<String, DifyConnectorError> {
    match dify_api_family(&app.mode)? {
        DifyApiFamily::Workflow => Ok(format!("/v1/workflows/tasks/{task_id}/stop")),
        DifyApiFamily::Completion => Ok(format!("/v1/completion-messages/{task_id}/stop")),
        DifyApiFamily::Chat => Ok(format!("/v1/chat-messages/{task_id}/stop")),
    }
}

#[async_trait]
impl ActionHandler for DifyConnector {
    async fn handle(&self, action: Action) -> RuntimeResult<ActionResult> {
        self.invoke(&ConnectorContext::default(), action)
            .await
            .map_err(|error| RuntimeError::Handler(error.to_string()))
    }

    async fn handle_with_context(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> RuntimeResult<ActionResult> {
        FrozenConnector::invoke_typed(self, action, context)
            .await
            .map_err(|failure| RuntimeError::Protocol(failure.to_protocol_error()))
    }

    async fn cancel(&self, action: &Action) -> RuntimeResult<()> {
        OutboundConnector::cancel(self, &ConnectorContext::default(), action)
            .await
            .map_err(|error| RuntimeError::Handler(error.to_string()))
    }

    async fn cancel_with_context(
        &self,
        action: &Action,
        context: &ActionExecutionContext,
    ) -> RuntimeResult<()> {
        FrozenConnector::cancel_typed(self, action, context.clone())
            .await
            .map_err(|failure| RuntimeError::Protocol(failure.to_protocol_error()))
    }
}

#[async_trait]
impl FrozenConnector for DifyConnector {
    fn implementation_support(&self, capability: &Capability) -> CapabilityImplementationSupport {
        let parsed = parse_dify_capability(&self.apps, capability.id.as_str());
        let app = parsed.map(|(app, _)| app);
        let app_operation = parsed.and_then(|(_, operation)| operation);
        let knowledge_operation =
            parse_dify_knowledge_capability(&self.knowledge, capability.id.as_str())
                .map(|(_, operation)| operation);
        let operation = app_operation.or(knowledge_operation);
        let invocation = app.is_some() || knowledge_operation.is_some();
        let cancellable = app.is_some() && operation.is_none_or(DifyOperation::supports_cancel);
        let streaming = app.is_some()
            && operation.is_none_or(|operation| {
                matches!(
                    operation.response_kind(),
                    DifyResponseKind::ServerSentEvents
                )
            });
        CapabilityImplementationSupport {
            invocation,
            cancellation: cancellable,
            streaming,
            retry: operation.is_some_and(DifyOperation::retry_safe),
            transaction: false,
            reconciliation: false,
            compensation: false,
            approval: app.is_some_and(app_requires_approval)
                || operation.is_some_and(DifyOperation::is_mutation),
            credentials: false,
        }
    }

    async fn invoke_typed(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, ConnectorFailure> {
        let safety = self.action_safety(&action);
        self.invoke_dify_streaming(action, context)
            .await
            .map_err(|error| dify_failure(error, ConnectorOperation::Invocation, safety))
    }

    async fn cancel_typed(
        &self,
        action: &Action,
        _context: ActionExecutionContext,
    ) -> Result<(), ConnectorFailure> {
        let safety = self.action_safety(action);
        self.cancel_dify(action)
            .await
            .map_err(|error| dify_failure(error, ConnectorOperation::Cancellation, safety))
    }
}

/// Dify connector error.
#[derive(Debug, Error)]
pub enum DifyConnectorError {
    /// No apps were configured.
    #[error("at least one Dify app or knowledge credential is required")]
    NoApps,
    /// A configured app descriptor is invalid or unsupported.
    #[error("invalid Dify app descriptor: {0}")]
    InvalidApp(String),
    /// Base URL failed to parse.
    #[error("invalid Dify URL: {0}")]
    InvalidUrl(url::ParseError),
    /// Parsed base URL violates the provider transport policy.
    #[error("invalid Dify base URL: {0}")]
    InvalidBaseUrl(String),
    /// The hardened provider HTTP client could not be constructed.
    #[error("invalid Dify HTTP client: {0}")]
    InvalidClient(String),
    /// Capability id does not match a configured app.
    #[error("Dify capability `{0}` is not configured")]
    CapabilityNotFound(String),
    /// HTTP request failed.
    #[error("Dify request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// Dify returned a non-success HTTP status.
    #[error("Dify returned HTTP {status}")]
    Status {
        /// HTTP status code.
        status: u16,
        /// Response body.
        body: Value,
    },
    /// Dify emitted an invalid or unbounded SSE stream.
    #[error("invalid Dify event stream: {0}")]
    Stream(String),
    /// Provider response exceeded the configured memory bound.
    #[error("Dify response exceeded the configured {limit}-byte bound")]
    ResponseTooLarge {
        /// Active response-size limit.
        limit: usize,
    },
    /// Runtime cancellation interrupted an operation after dispatch began.
    #[error("Dify invocation was cancelled by the AIP runtime")]
    Cancelled {
        /// Whether Dify confirmed its remote task was stopped.
        remote_stop_confirmed: bool,
    },
    /// Invocation input does not satisfy the selected Dify API family.
    #[error("invalid Dify action input: {0}")]
    InvalidInput(String),
    /// Configured credential material is not valid UTF-8.
    #[error("configured Dify credential is not valid UTF-8")]
    InvalidCredential,
    /// Durable task mapping failed.
    #[error("Dify task store failed: {0}")]
    TaskStore(String),
}

/// Creates an AIP manifest for a set of Dify apps.
pub fn manifest_from_apps(
    apps: Vec<DifyApp>,
    tenant_id: &str,
) -> Result<Manifest, aip_core::IdParseError> {
    manifest_from_configuration(apps, Vec::new(), tenant_id)
}

/// Creates an AIP manifest for configured Dify applications and Knowledge API credentials.
pub fn manifest_from_configuration(
    apps: Vec<DifyApp>,
    knowledge: Vec<DifyKnowledgeBase>,
    tenant_id: &str,
) -> Result<Manifest, aip_core::IdParseError> {
    let app_count = apps.len();
    let knowledge_count = knowledge.len();
    let mut capabilities = Vec::new();
    for app in apps {
        capabilities.push(capability_from_app(app.clone())?);
        capabilities.extend(capabilities_from_app(&app)?);
    }
    for descriptor in &knowledge {
        capabilities.extend(capabilities_from_knowledge(descriptor)?);
    }
    Ok(Manifest {
        manifest_version: "aip-manifest/v1".to_owned(),
        agent: Principal::new(
            PrincipalId::parse(format!("agent:dify:{tenant_id}"))?,
            PrincipalKind::Agent,
        ),
        capabilities,
        profiles: vec![
            ProfileId::from(aip_profile_mcp::PROFILE_ID),
            ProfileId::from("aip.native.http.v1"),
            ProfileId::from(PROFILE_ID),
        ],
        resources: Vec::new(),
        channels: Vec::new(),
        security: None,
        governance: None,
        limits: None,
        compatibility: Some(json!({
            "system": "dify",
            "connector": CONNECTOR_ID,
            "tenant_id": tenant_id,
            "upstream_revision": UPSTREAM_REVISION,
            "application_credentials": app_count,
            "knowledge_credentials": knowledge_count,
            "service_api_operations": ALL_DIFY_OPERATIONS.len()
        })),
        extensions: None,
    })
}

#[async_trait]
impl Connector for DifyConnector {
    fn id(&self) -> &str {
        CONNECTOR_ID
    }

    async fn discover(&self, context: &ConnectorContext) -> ConnectorResult<Manifest> {
        manifest_from_configuration(
            self.apps.values().cloned().collect(),
            self.knowledge.values().cloned().collect(),
            context.tenant_id.as_deref().unwrap_or("default"),
        )
        .map_err(|error| ConnectorError::Discovery(error.to_string()))
    }

    fn map_error(&self, error: &ConnectorError) -> ProtocolError {
        ProtocolError {
            code: "connector.dify".to_owned(),
            message: error.to_string(),
            category: ErrorCategory::Connector,
            retryable: Some(false),
            retry_after_ms: None,
            details: None,
            source: Some(Box::new(json!({ "connector": CONNECTOR_ID }))),
        }
    }

    async fn health(&self, _context: &ConnectorContext) -> ConnectorResult<ConnectorHealth> {
        let credentials = self
            .apps
            .keys()
            .cloned()
            .map(|id| (false, id))
            .chain(self.knowledge.keys().cloned().map(|id| (true, id)))
            .collect::<Vec<_>>();
        let checks = stream::iter(credentials)
            .map(|(is_knowledge, credential_id)| async move {
                let mut url = self
                    .base_url
                    .join(if is_knowledge {
                        "/v1/datasets"
                    } else {
                        "/v1/parameters"
                    })
                    .map_err(DifyConnectorError::InvalidUrl)?;
                if is_knowledge {
                    url.query_pairs_mut().append_pair("limit", "1");
                }
                let api_key = if is_knowledge {
                    self.knowledge_api_key(&credential_id)?
                } else {
                    self.api_key(&credential_id)?
                };
                let response = self.client.get(url).bearer_auth(api_key).send().await?;
                if !response.status().is_success() {
                    let status = response.status().as_u16();
                    let body = response_body(response, self.max_response_bytes).await?;
                    return Err(DifyConnectorError::Status { status, body });
                }
                Ok::<_, DifyConnectorError>(credential_id)
            })
            .buffer_unordered(HEALTH_CONCURRENCY)
            .collect::<Vec<_>>()
            .await;
        for check in checks {
            check.map_err(|error| ConnectorError::Discovery(error.to_string()))?;
        }
        Ok(ConnectorHealth {
            ready: true,
            detail: format!(
                "Dify Service API is reachable with {} application and {} knowledge credential(s)",
                self.apps.len(),
                self.knowledge.len()
            ),
        })
    }
}

#[async_trait]
impl CapabilityProviderConnector for DifyConnector {
    async fn capabilities(&self, _context: &ConnectorContext) -> ConnectorResult<Vec<Capability>> {
        let mut capabilities = Vec::new();
        for app in self.apps.values() {
            capabilities.push(
                capability_from_app(app.clone())
                    .map_err(|error| ConnectorError::Discovery(error.to_string()))?,
            );
            capabilities.extend(
                capabilities_from_app(app)
                    .map_err(|error| ConnectorError::Discovery(error.to_string()))?,
            );
        }
        for descriptor in self.knowledge.values() {
            capabilities.extend(
                capabilities_from_knowledge(descriptor)
                    .map_err(|error| ConnectorError::Discovery(error.to_string()))?,
            );
        }
        Ok(capabilities)
    }
}

#[async_trait]
impl OutboundConnector for DifyConnector {
    async fn invoke(
        &self,
        _context: &ConnectorContext,
        action: Action,
    ) -> ConnectorResult<ActionResult> {
        let safety = self.action_safety(&action);
        self.invoke_dify(action).await.map_err(|error| {
            ConnectorError::Failure(dify_failure(error, ConnectorOperation::Invocation, safety))
        })
    }

    async fn emit(
        &self,
        _context: &ConnectorContext,
        _result: ActionResult,
    ) -> ConnectorResult<()> {
        Err(ConnectorFailure::unsupported(ConnectorOperation::Emission, self.id()).into())
    }

    async fn cancel(&self, _context: &ConnectorContext, action: &Action) -> ConnectorResult<()> {
        let safety = self.action_safety(action);
        self.cancel_dify(action).await.map_err(|error| {
            ConnectorError::Failure(dify_failure(
                error,
                ConnectorOperation::Cancellation,
                safety,
            ))
        })
    }
}

impl DifyConnector {
    fn action_safety(&self, action: &Action) -> DifyOperationSafety {
        let operation = parse_dify_capability(&self.apps, action.capability_id.as_str())
            .and_then(|(_, operation)| operation)
            .or_else(|| {
                parse_dify_knowledge_capability(&self.knowledge, action.capability_id.as_str())
                    .map(|(_, operation)| operation)
            });
        operation.map_or(DifyOperationSafety::MUTATION_UNSAFE, |operation| {
            DifyOperationSafety {
                retry_safe: operation.retry_safe(),
                mutation: operation.is_mutation(),
            }
        })
    }

    async fn cancel_dify(&self, action: &Action) -> Result<(), DifyConnectorError> {
        let parsed_operation = parse_dify_capability(&self.apps, action.capability_id.as_str())
            .and_then(|(_, operation)| operation);
        if parsed_operation == Some(DifyOperation::WorkflowEvents) {
            // Cancelling an event subscription closes only the local response
            // stream. Stopping the underlying workflow would be a different,
            // state-changing operation and must never be inferred here.
            return Ok(());
        }
        if parsed_operation.is_some_and(|operation| !operation.supports_cancel()) {
            return Err(DifyConnectorError::InvalidInput(format!(
                "Dify capability `{}` does not support cancellation",
                action.capability_id
            )));
        }
        let tracked = self
            .active_tasks
            .get(&action.id)
            .await
            .map_err(DifyConnectorError::TaskStore)?;
        let task = tracked.or_else(|| {
            let task_id = action.input.get("task_id").and_then(Value::as_str)?;
            let (app, _) = parse_dify_capability(&self.apps, action.capability_id.as_str())?;
            let user = required_dify_user(&action.input).ok()?;
            Some(DifyTaskReference {
                app_id: app.id.clone(),
                task_id: task_id.to_owned(),
                user: user.to_owned(),
            })
        });
        let Some(task) = task else {
            // An independent cancellation call does not own the in-flight HTTP
            // response and cannot prove whether Dify admitted the request. A
            // missing durable task id must therefore remain uncertain rather
            // than being reported as a successful remote stop.
            return Err(DifyConnectorError::Cancelled {
                remote_stop_confirmed: false,
            });
        };
        self.stop_task(&task).await?;
        self.active_tasks
            .remove(&action.id)
            .await
            .map_err(DifyConnectorError::TaskStore)
    }
}

impl DifyConnector {
    async fn stop_task(&self, task: &DifyTaskReference) -> Result<(), DifyConnectorError> {
        let app = self.apps.get(&task.app_id).ok_or_else(|| {
            DifyConnectorError::CapabilityNotFound(format!("cap:dify:{}", task.app_id))
        })?;
        let path = cancellation_path(app, &task.task_id)?;
        let url = self
            .base_url
            .join(&path)
            .map_err(DifyConnectorError::InvalidUrl)?;
        let response = self
            .client
            .post(url)
            .bearer_auth(self.api_key(&task.app_id)?)
            .json(&json!({ "user": task.user }))
            .send()
            .await?;
        if response.status().is_success() || response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(());
        }
        let status = response.status().as_u16();
        let body = response_body(response, self.max_response_bytes).await?;
        Err(DifyConnectorError::Status { status, body })
    }

    async fn cancel_active_task(&self, action: &Action) -> Result<bool, DifyConnectorError> {
        let Some(task) = self
            .active_tasks
            .get(&action.id)
            .await
            .map_err(DifyConnectorError::TaskStore)?
        else {
            // The request may already have reached Dify even when its first SSE
            // event (and therefore task id) has not reached this process.
            return Ok(false);
        };
        self.stop_task(&task).await?;
        self.active_tasks
            .remove(&action.id)
            .await
            .map_err(DifyConnectorError::TaskStore)?;
        Ok(true)
    }

    fn dify_operation_request(
        &self,
        api_key: &str,
        operation: DifyOperation,
        action: &Action,
        response_mode_override: Option<&str>,
    ) -> Result<reqwest::RequestBuilder, DifyConnectorError> {
        let idempotency_key = if operation.is_mutation() {
            Some(required_dify_idempotency_key(action)?)
        } else {
            action.idempotency_key.as_deref()
        };
        let mut url = dify_operation_url(&self.base_url, operation, &action.input)?;
        let user = match operation.user_location() {
            DifyUserLocation::None => None,
            DifyUserLocation::Query | DifyUserLocation::Json | DifyUserLocation::Multipart => {
                Some(required_dify_user(&action.input)?)
            }
        };
        append_dify_query(
            &mut url,
            action.input.get("query"),
            (operation.user_location() == DifyUserLocation::Query)
                .then_some(user)
                .flatten(),
        )?;
        let method = match operation.method() {
            DifyHttpMethod::Get => reqwest::Method::GET,
            DifyHttpMethod::Post => reqwest::Method::POST,
            DifyHttpMethod::Put => reqwest::Method::PUT,
            DifyHttpMethod::Patch => reqwest::Method::PATCH,
            DifyHttpMethod::Delete => reqwest::Method::DELETE,
        };
        let mut request = self
            .client
            .request(method, url)
            .bearer_auth(api_key)
            .header("X-AIP-Action-ID", action.id.to_string());
        if let Some(key) = idempotency_key {
            request = request.header("Idempotency-Key", key);
        }
        if operation.request_kind() == DifyRequestKind::Multipart {
            if action.input.get("body").is_some() && !operation.accepts_multipart_data() {
                return Err(DifyConnectorError::InvalidInput(format!(
                    "Dify multipart operation `{}` does not accept a `body` data field",
                    operation.suffix()
                )));
            }
            let file = dify_upload_part(&action.input)?;
            let mut form = reqwest::multipart::Form::new().part("file", file);
            if let Some(user) = user {
                form = form.text("user", user.to_owned());
            }
            if operation.accepts_multipart_data() {
                let data = action
                    .input
                    .get("body")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                if !data.is_object() {
                    return Err(DifyConnectorError::InvalidInput(
                        "input `body` must be an object".to_owned(),
                    ));
                }
                let encoded = serde_json::to_string(&data)
                    .map_err(|error| DifyConnectorError::InvalidInput(error.to_string()))?;
                if encoded.len() > MAX_JSON_REQUEST_BYTES {
                    return Err(DifyConnectorError::InvalidInput(format!(
                        "Dify multipart data exceeds {MAX_JSON_REQUEST_BYTES} bytes"
                    )));
                }
                form = form.text("data", encoded);
            }
            return Ok(request.multipart(form));
        }
        if matches!(operation.method(), DifyHttpMethod::Get) && action.input.get("body").is_some() {
            return Err(DifyConnectorError::InvalidInput(
                "Dify GET operations do not accept a request body".to_owned(),
            ));
        }
        let mut body = action
            .input
            .get("body")
            .map(|body| {
                body.as_object().cloned().ok_or_else(|| {
                    DifyConnectorError::InvalidInput("input `body` must be an object".to_owned())
                })
            })
            .transpose()?
            .unwrap_or_default();
        if operation.user_location() == DifyUserLocation::Json {
            insert_dify_user(&mut body, user.unwrap_or_default())?;
        }
        if let Some(response_mode) = response_mode_override {
            body.insert(
                "response_mode".to_owned(),
                Value::String(response_mode.to_owned()),
            );
        }
        if !body.is_empty() {
            let encoded = serde_json::to_vec(&body)
                .map_err(|error| DifyConnectorError::InvalidInput(error.to_string()))?;
            if encoded.len() > MAX_JSON_REQUEST_BYTES {
                return Err(DifyConnectorError::InvalidInput(format!(
                    "Dify JSON body exceeds {MAX_JSON_REQUEST_BYTES} bytes"
                )));
            }
            request = request.json(&body);
        }
        Ok(request)
    }

    async fn invoke_dify(&self, action: Action) -> Result<ActionResult, DifyConnectorError> {
        if let Some((app, operation)) =
            parse_dify_capability(&self.apps, action.capability_id.as_str())
        {
            if let Some(operation) = operation {
                return self
                    .invoke_dify_operation(self.api_key(&app.id)?, operation, action)
                    .await;
            }
            let app_id = app.id.as_str();
            let idempotency_key = required_dify_idempotency_key(&action)?;
            let path = invocation_path(app)?;
            let url = self
                .base_url
                .join(path)
                .map_err(DifyConnectorError::InvalidUrl)?;
            let response = self
                .client
                .post(url)
                .bearer_auth(self.api_key(app_id)?)
                .header("Idempotency-Key", idempotency_key)
                .header("X-AIP-Action-ID", action.id.to_string())
                .json(&dify_request_body(app, &action.input, "blocking")?)
                .send()
                .await?;
            let status = response.status();
            let body = response_body(response, self.max_response_bytes).await?;
            if !status.is_success() {
                return Err(DifyConnectorError::Status {
                    status: status.as_u16(),
                    body,
                });
            }
            return if dify_response_requires_human(&body) {
                Ok(dify_requires_human_result(action, body))
            } else {
                Ok(completed_dify_result(action, body))
            };
        }
        if let Some((knowledge, operation)) =
            parse_dify_knowledge_capability(&self.knowledge, action.capability_id.as_str())
        {
            return self
                .invoke_dify_operation(self.knowledge_api_key(&knowledge.id)?, operation, action)
                .await;
        }
        Err(DifyConnectorError::CapabilityNotFound(
            action.capability_id.to_string(),
        ))
    }

    async fn invoke_dify_operation(
        &self,
        api_key: &str,
        operation: DifyOperation,
        action: Action,
    ) -> Result<ActionResult, DifyConnectorError> {
        let response = self
            .dify_operation_request(
                api_key,
                operation,
                &action,
                (operation == DifyOperation::WorkflowRunById).then_some("blocking"),
            )?
            .send()
            .await?;
        let status = response.status();
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let provider_request_id = response
            .headers()
            .get("x-request-id")
            .and_then(|value| value.to_str().ok())
            .map(ToOwned::to_owned);
        let body = response_bytes(response, self.max_response_bytes).await?;
        if !status.is_success() {
            return Err(DifyConnectorError::Status {
                status: status.as_u16(),
                body: decode_response_value(&body),
            });
        }
        let output = if operation.response_kind() == DifyResponseKind::Binary {
            json!({
                "http_status": status.as_u16(),
                "content_base64": base64::engine::general_purpose::STANDARD.encode(&body),
                "content_type": content_type,
                "size_bytes": body.len(),
                "provider_request_id": provider_request_id
            })
        } else {
            json!({
                "http_status": status.as_u16(),
                "body": decode_response_value(&body),
                "content_type": content_type,
                "provider_request_id": provider_request_id
            })
        };
        Ok(completed_dify_result(action, output))
    }

    async fn invoke_dify_streaming(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, DifyConnectorError> {
        let cleanup_action = action.clone();
        let result = self.invoke_dify_streaming_inner(action, context).await;
        if result.is_err()
            && let Err(cleanup_error) = self.cancel_active_task(&cleanup_action).await
        {
            return Err(DifyConnectorError::Stream(format!(
                "stream processing failed and remote cleanup was not confirmed: {cleanup_error}"
            )));
        }
        result
    }

    async fn invoke_dify_streaming_inner(
        &self,
        action: Action,
        context: ActionExecutionContext,
    ) -> Result<ActionResult, DifyConnectorError> {
        let (app, operation) = parse_dify_capability(&self.apps, action.capability_id.as_str())
            .map_or((None, None), |(app, operation)| (Some(app), operation));
        if app.is_none()
            && let Some((knowledge, operation)) =
                parse_dify_knowledge_capability(&self.knowledge, action.capability_id.as_str())
        {
            let invocation = self.invoke_dify_operation(
                self.knowledge_api_key(&knowledge.id)?,
                operation,
                action,
            );
            return tokio::select! {
                result = invocation => result,
                () = context.cancellation.cancelled() => Err(DifyConnectorError::Cancelled {
                    remote_stop_confirmed: false,
                }),
            };
        }
        let app = app.ok_or_else(|| {
            DifyConnectorError::CapabilityNotFound(action.capability_id.to_string())
        })?;
        if let Some(operation) = operation
            && operation.response_kind() != DifyResponseKind::ServerSentEvents
        {
            let invocation = self.invoke_dify_operation(self.api_key(&app.id)?, operation, action);
            return tokio::select! {
                result = invocation => result,
                () = context.cancellation.cancelled() => Err(DifyConnectorError::Cancelled {
                    remote_stop_confirmed: false,
                }),
            };
        }
        let app_id = app.id.clone();
        let request = match operation {
            Some(operation) => self.dify_operation_request(
                self.api_key(&app.id)?,
                operation,
                &action,
                Some("streaming"),
            )?,
            None => {
                let idempotency_key = required_dify_idempotency_key(&action)?;
                let path = invocation_path(app)?;
                let url = self
                    .base_url
                    .join(path)
                    .map_err(DifyConnectorError::InvalidUrl)?;
                self.client
                    .post(url)
                    .bearer_auth(self.api_key(&app_id)?)
                    .header("Idempotency-Key", idempotency_key)
                    .header("X-AIP-Action-ID", action.id.to_string())
                    .json(&dify_request_body(app, &action.input, "streaming")?)
            }
        };
        let send = request.send();
        let response = tokio::select! {
            response = send => response?,
            () = context.cancellation.cancelled() => {
                return Err(DifyConnectorError::Cancelled {
                    remote_stop_confirmed: false,
                });
            }
        };
        let status = response.status();
        if !status.is_success() {
            return Err(DifyConnectorError::Status {
                status: status.as_u16(),
                body: response_body(response, self.max_response_bytes).await?,
            });
        }

        let user = required_dify_user(&action.input)?.to_owned();
        let mut upstream = response.bytes_stream();
        let mut buffer = Vec::new();
        let mut sequence = 0_u64;
        let mut response_bytes = 0_usize;
        let mut answer = String::new();
        let mut final_data = None;
        let mut human_input = None;
        let mut terminal = false;
        loop {
            let next = tokio::select! {
                chunk = upstream.next() => chunk,
                () = context.cancellation.cancelled() => {
                    let remote_stop_confirmed = self.cancel_active_task(&action).await?;
                    return Err(DifyConnectorError::Cancelled {
                        remote_stop_confirmed,
                    });
                }
            };
            let Some(chunk) = next else {
                break;
            };
            let chunk = chunk?;
            response_bytes = response_bytes.checked_add(chunk.len()).ok_or(
                DifyConnectorError::ResponseTooLarge {
                    limit: self.max_response_bytes,
                },
            )?;
            if response_bytes > self.max_response_bytes {
                return Err(DifyConnectorError::ResponseTooLarge {
                    limit: self.max_response_bytes,
                });
            }
            buffer.extend_from_slice(&chunk);
            while let Some(frame) = take_sse_frame(&mut buffer)? {
                let Some(event) = parse_dify_sse_frame(&frame)? else {
                    continue;
                };
                if let Some(task_id) = event.task_id.clone() {
                    self.active_tasks
                        .put(
                            &action.id,
                            DifyTaskReference {
                                app_id: app_id.clone(),
                                task_id,
                                user: user.clone(),
                            },
                        )
                        .await
                        .map_err(DifyConnectorError::TaskStore)?;
                }
                append_dify_answer(&mut answer, &event, self.max_response_bytes)?;
                if sequence as usize >= MAX_SSE_EVENTS {
                    return Err(DifyConnectorError::Stream(format!(
                        "SSE stream exceeded {MAX_SSE_EVENTS} events"
                    )));
                }
                context
                    .stream
                    .emit(stream_chunk_from_dify(
                        action.id.clone(),
                        sequence,
                        event.event.clone(),
                    ))
                    .await
                    .map_err(|error| DifyConnectorError::Stream(error.to_string()))?;
                sequence = sequence.saturating_add(1);
                final_data = Some(event.event.data.clone());
                if event.requires_human {
                    human_input = Some(event.event.data.clone());
                }
                if event.failed {
                    self.active_tasks
                        .remove(&action.id)
                        .await
                        .map_err(DifyConnectorError::TaskStore)?;
                    return Ok(dify_failed_result(&action, event.event.data));
                }
                if event.terminal {
                    terminal = true;
                    break;
                }
            }
            // A transport chunk may legitimately contain many complete frames.
            // Bound only the un-delimited remainder, not the entire chunk.
            if buffer.len() > MAX_SSE_FRAME_BYTES {
                return Err(DifyConnectorError::Stream(format!(
                    "SSE frame exceeded {MAX_SSE_FRAME_BYTES} bytes"
                )));
            }
            if terminal {
                break;
            }
        }
        if !terminal && !buffer.is_empty() {
            if buffer.len() > MAX_SSE_FRAME_BYTES {
                return Err(DifyConnectorError::Stream(format!(
                    "SSE frame exceeded {MAX_SSE_FRAME_BYTES} bytes"
                )));
            }
            if let Some(event) = parse_dify_sse_frame(&buffer)? {
                append_dify_answer(&mut answer, &event, self.max_response_bytes)?;
                if sequence as usize >= MAX_SSE_EVENTS {
                    return Err(DifyConnectorError::Stream(format!(
                        "SSE stream exceeded {MAX_SSE_EVENTS} events"
                    )));
                }
                context
                    .stream
                    .emit(stream_chunk_from_dify(
                        action.id.clone(),
                        sequence,
                        event.event.clone(),
                    ))
                    .await
                    .map_err(|error| DifyConnectorError::Stream(error.to_string()))?;
                final_data = Some(event.event.data.clone());
                if event.requires_human {
                    human_input = Some(event.event.data.clone());
                }
                terminal = event.terminal;
                if event.failed {
                    self.active_tasks
                        .remove(&action.id)
                        .await
                        .map_err(DifyConnectorError::TaskStore)?;
                    return Ok(dify_failed_result(&action, event.event.data));
                }
            }
        }
        if !terminal {
            return Err(DifyConnectorError::Stream(
                "upstream closed before a terminal Dify event".to_owned(),
            ));
        }
        self.active_tasks
            .remove(&action.id)
            .await
            .map_err(DifyConnectorError::TaskStore)?;
        let final_data = final_data.unwrap_or(Value::Null);
        let output = if answer.is_empty() {
            final_data
        } else {
            json!({ "answer": answer, "final_event": final_data })
        };
        if let Some(human_input) = human_input {
            Ok(dify_requires_human_result(
                action,
                json!({ "human_input": human_input, "final_event": output }),
            ))
        } else {
            Ok(completed_dify_result(action, output))
        }
    }
}

/// Maps a Dify app/workflow/agent into an AIP capability.
pub fn capability_from_app(app: DifyApp) -> Result<Capability, aip_core::IdParseError> {
    let requires_human_approval = app_requires_approval(&app);
    let contract = dify_contract(&app);
    Ok(Capability {
        id: CapabilityId::parse(format!("cap:dify:{}", app.id))?,
        name: app.name,
        kind: if app.mode == "workflow" {
            CapabilityKind::Workflow
        } else {
            CapabilityKind::Agent
        },
        input_schema: json!({
            "type": "object",
            "required": ["user"],
            "properties": {
                "query": { "type": "string", "maxLength": 1048576 },
                "prompt": { "type": "string", "maxLength": 1048576 },
                "inputs": { "type": "object" },
                "user": { "type": "string", "minLength": 1, "maxLength": 256 },
                "conversation_id": { "type": "string", "maxLength": 256 },
                "files": { "type": "array", "maxItems": 100, "items": { "type": "object" } },
                "auto_generate_name": { "type": "boolean" }
            },
            "additionalProperties": false
        }),
        output_schema: Some(json!({
            "type": "object",
            "description": "Dify blocking response or normalized streaming terminal output"
        })),
        description: app.description,
        risk: Some(RiskLevel::Medium),
        stability: None,
        cost: None,
        auth: Some(json!({ "type": "dify_app_api_key" })),
        bindings: vec![
            aip_core::Binding {
                profile: ProfileId::from("aip.native.http.v1"),
                metadata: json!({
                    "method": "POST",
                    "path": invocation_path_for_mode(&app.mode),
                    "message_type": "aip.core.v1.action"
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            },
            aip_core::Binding {
                profile: ProfileId::from(PROFILE_ID),
                metadata: json!({
                    "system": "dify",
                    "connector": CONNECTOR_ID,
                    "app_id": app.id,
                    "mode": app.mode
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            },
        ],
        requires_human_approval: Some(requires_human_approval),
        contract: Some(contract),
    })
}

/// Creates every frozen Dify Service API capability supported by one app mode.
pub fn capabilities_from_app(app: &DifyApp) -> Result<Vec<Capability>, aip_core::IdParseError> {
    ALL_DIFY_OPERATIONS
        .iter()
        .copied()
        .filter(|operation| {
            operation.scope() == DifyOperationScope::App && operation.supports_mode(&app.mode)
        })
        .map(|operation| dify_operation_capability(app, operation))
        .collect()
}

/// Creates every frozen Dify Knowledge API capability for one workspace credential.
pub fn capabilities_from_knowledge(
    knowledge: &DifyKnowledgeBase,
) -> Result<Vec<Capability>, aip_core::IdParseError> {
    ALL_DIFY_OPERATIONS
        .iter()
        .copied()
        .filter(|operation| operation.scope() == DifyOperationScope::Knowledge)
        .map(|operation| dify_knowledge_operation_capability(knowledge, operation))
        .collect()
}

fn dify_operation_capability(
    app: &DifyApp,
    operation: DifyOperation,
) -> Result<Capability, aip_core::IdParseError> {
    dify_operation_capability_for(
        format!("cap:dify:{}", app.id),
        &app.name,
        &app.id,
        "dify_app_api_key",
        operation,
    )
}

fn dify_knowledge_operation_capability(
    knowledge: &DifyKnowledgeBase,
    operation: DifyOperation,
) -> Result<Capability, aip_core::IdParseError> {
    dify_operation_capability_for(
        format!("cap:dify:knowledge:{}", knowledge.id),
        &knowledge.name,
        &knowledge.id,
        "dify_knowledge_api_key",
        operation,
    )
}

fn dify_operation_capability_for(
    capability_prefix: String,
    display_target: &str,
    credential_id: &str,
    credential_type: &str,
    operation: DifyOperation,
) -> Result<Capability, aip_core::IdParseError> {
    let id = CapabilityId::parse(format!("{capability_prefix}:{}", operation.suffix()))?;
    let mutation = operation.is_mutation();
    let output_schema = match operation.response_kind() {
        DifyResponseKind::Json | DifyResponseKind::ServerSentEvents => json!({
            "type": "object",
            "required": ["http_status", "body"],
            "properties": {
                "http_status": { "type": "integer", "minimum": 100, "maximum": 599 },
                "body": {},
                "content_type": { "type": ["string", "null"] },
                "provider_request_id": { "type": ["string", "null"] }
            },
            "additionalProperties": false
        }),
        DifyResponseKind::Binary => json!({
            "type": "object",
            "required": ["http_status", "content_base64", "size_bytes"],
            "properties": {
                "http_status": { "type": "integer", "minimum": 100, "maximum": 599 },
                "content_base64": { "type": "string" },
                "content_type": { "type": ["string", "null"] },
                "size_bytes": { "type": "integer", "minimum": 0 },
                "provider_request_id": { "type": ["string", "null"] }
            },
            "additionalProperties": false
        }),
    };
    Ok(Capability {
        id,
        name: format!("Dify {display_target}: {}", operation.display_name()),
        kind: operation.capability_kind(),
        input_schema: dify_operation_input_schema(operation),
        output_schema: Some(output_schema),
        description: Some(format!(
            "Maps a frozen AIP capability to Dify {} {} at upstream revision {}.",
            dify_method_name(operation.method()),
            operation.path_template(),
            UPSTREAM_REVISION
        )),
        risk: Some(operation.risk()),
        stability: None,
        cost: None,
        auth: Some(json!({ "type": credential_type, "credential_id": credential_id })),
        bindings: vec![
            aip_core::Binding {
                profile: ProfileId::from("aip.native.http.v1"),
                metadata: json!({
                    "connector": CONNECTOR_ID,
                    "credential_id": credential_id,
                    "credential_type": credential_type,
                    "operation": operation.suffix(),
                    "method": dify_method_name(operation.method()),
                    "path_template": operation.path_template(),
                    "upstream_revision": UPSTREAM_REVISION
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            },
            aip_core::Binding {
                profile: ProfileId::from(PROFILE_ID),
                metadata: json!({
                    "system": "dify",
                    "connector": CONNECTOR_ID,
                    "credential_id": credential_id,
                    "credential_type": credential_type,
                    "operation": operation.suffix(),
                    "upstream_revision": UPSTREAM_REVISION
                })
                .as_object()
                .cloned()
                .unwrap_or_default(),
            },
        ],
        requires_human_approval: Some(mutation),
        contract: Some(dify_operation_contract(operation)),
    })
}

fn dify_operation_input_schema(operation: DifyOperation) -> Value {
    let mut properties = serde_json::Map::new();
    let mut required = Vec::new();
    for parameter in dify_path_parameters(operation.path_template()) {
        properties.insert(
            parameter.to_owned(),
            json!({ "type": "string", "minLength": 1, "maxLength": 512 }),
        );
        required.push(Value::String(parameter.to_owned()));
    }
    if operation.user_location() != DifyUserLocation::None {
        properties.insert(
            "user".to_owned(),
            json!({ "type": "string", "minLength": 1, "maxLength": 256 }),
        );
        required.push(Value::String("user".to_owned()));
    }
    properties.insert(
        "query".to_owned(),
        json!({
            "type": "object",
            "maxProperties": 128,
            "additionalProperties": {
                "oneOf": [
                    { "type": ["string", "number", "integer", "boolean", "null"] },
                    { "type": "array", "maxItems": 256, "items": { "type": ["string", "number", "integer", "boolean", "null"] } }
                ]
            }
        }),
    );
    if !matches!(operation.method(), DifyHttpMethod::Get)
        && (operation.request_kind() == DifyRequestKind::Json || operation.accepts_multipart_data())
    {
        properties.insert(
            "body".to_owned(),
            json!({ "type": "object", "maxProperties": 512 }),
        );
    }
    if operation.request_kind() == DifyRequestKind::Multipart {
        properties.insert(
            "file".to_owned(),
            json!({
                "type": "object",
                "required": ["filename", "content_base64"],
                "properties": {
                    "filename": { "type": "string", "minLength": 1, "maxLength": 512 },
                    "content_type": { "type": "string", "minLength": 1, "maxLength": 256 },
                    "content_base64": { "type": "string", "maxLength": 50331648 }
                },
                "additionalProperties": false
            }),
        );
        required.push(Value::String("file".to_owned()));
    }
    json!({
        "type": "object",
        "required": required,
        "properties": properties,
        "additionalProperties": false
    })
}

fn dify_operation_contract(operation: DifyOperation) -> CapabilityContract {
    let mutation = operation.is_mutation();
    CapabilityContract {
        side_effects: if mutation {
            vec![SideEffect::Write, SideEffect::ExternalNetwork]
        } else {
            vec![SideEffect::Read, SideEffect::ExternalNetwork]
        },
        idempotency: IdempotencyContract {
            requirement: if mutation {
                IdempotencyRequirement::Required
            } else {
                IdempotencyRequirement::Optional
            },
            collision_behavior: IdempotencyCollisionBehavior::RevalidateInputHash,
            key_scope: IdempotencyKeyScope::Tenant,
            ttl_ms: Some(86_400_000),
        },
        execution: ExecutionContract {
            supports_sync: true,
            supports_async: operation.response_kind() == DifyResponseKind::ServerSentEvents,
            supports_streaming: operation.response_kind() == DifyResponseKind::ServerSentEvents,
            supports_cancel: operation.supports_cancel(),
            supports_retry: operation.retry_safe(),
            expected_completion: if operation.response_kind() == DifyResponseKind::ServerSentEvents
            {
                ExpectedCompletionMode::Any
            } else {
                ExpectedCompletionMode::Sync
            },
            retry_safety: if operation.retry_safe() {
                RetrySafety::Safe
            } else {
                RetrySafety::Unsafe
            },
        },
        data: DataContract {
            sensitivity: DataSensitivity::Confidential,
            contains_pii: true,
            redaction_required: true,
            residency: None,
            retention: None,
        },
        credentials: None,
        approval: mutation.then(|| ApprovalPolicy {
            required: true,
            reason: Some("Dify mutation or model execution changes provider state.".to_owned()),
            approver_selector: ApproverSelector::TenantPolicy,
            ttl_ms: Some(900_000),
            evidence_requirements: vec![
                EvidenceRequirement::Reason,
                EvidenceRequirement::InputSnapshot,
                EvidenceRequirement::PolicyDecision,
            ],
            policy_version: Some("dify-service-api-v1".to_owned()),
            ..ApprovalPolicy::default()
        }),
        sla: Some(ServiceLevelContract {
            expected_latency_ms: Some(
                if operation.response_kind() == DifyResponseKind::ServerSentEvents {
                    20_000
                } else {
                    5_000
                },
            ),
            timeout_ms: Some(300_000),
            async_expected: operation.response_kind() == DifyResponseKind::ServerSentEvents,
            max_queue_delay_ms: Some(10_000),
            availability_target: Some("99.5%".to_owned()),
        }),
        transaction: None,
        compensation: mutation.then_some(CompensationContract {
            mode: CompensationMode::RollbackNotSupported,
            compensation_capability_id: None,
            compensation_window_ms: None,
            requires_approval: true,
        }),
    }
}

const fn dify_method_name(method: DifyHttpMethod) -> &'static str {
    match method {
        DifyHttpMethod::Get => "GET",
        DifyHttpMethod::Post => "POST",
        DifyHttpMethod::Put => "PUT",
        DifyHttpMethod::Patch => "PATCH",
        DifyHttpMethod::Delete => "DELETE",
    }
}

fn app_requires_approval(app: &DifyApp) -> bool {
    matches!(
        app.mode.as_str(),
        "workflow" | "advanced-chat" | "agent-chat" | "agent"
    )
}

fn dify_contract(app: &DifyApp) -> CapabilityContract {
    let approval_required = app_requires_approval(app);
    CapabilityContract {
        side_effects: vec![
            SideEffect::Read,
            SideEffect::Write,
            SideEffect::ExternalNetwork,
        ],
        idempotency: IdempotencyContract {
            requirement: IdempotencyRequirement::Required,
            collision_behavior: IdempotencyCollisionBehavior::RevalidateInputHash,
            key_scope: IdempotencyKeyScope::Tenant,
            ttl_ms: Some(86_400_000),
        },
        execution: ExecutionContract {
            supports_sync: true,
            supports_async: true,
            supports_streaming: true,
            supports_cancel: true,
            supports_retry: false,
            expected_completion: ExpectedCompletionMode::Any,
            retry_safety: RetrySafety::Unsafe,
        },
        data: DataContract {
            sensitivity: DataSensitivity::Confidential,
            contains_pii: true,
            redaction_required: true,
            residency: None,
            retention: None,
        },
        credentials: None,
        approval: approval_required.then(|| ApprovalPolicy {
            required: true,
            reason: Some("Dify workflows and agents may call downstream tools or produce customer-visible work.".to_owned()),
            approver_selector: ApproverSelector::TenantPolicy,
            ttl_ms: Some(900_000),
            evidence_requirements: vec![
                EvidenceRequirement::Reason,
                EvidenceRequirement::InputSnapshot,
                EvidenceRequirement::PolicyDecision,
            ],
            delegated_authority: None,
            ..ApprovalPolicy::default()
        }),
        sla: Some(ServiceLevelContract {
            expected_latency_ms: Some(20_000),
            timeout_ms: Some(300_000),
            async_expected: true,
            max_queue_delay_ms: Some(10_000),
            availability_target: Some("99.5%".to_owned()),
        }),
        transaction: None,
        compensation: Some(CompensationContract {
            mode: CompensationMode::RollbackNotSupported,
            compensation_capability_id: None,
            compensation_window_ms: None,
            requires_approval: approval_required,
        }),
    }
}

/// Projects Dify apps into MCP `tools/list` through the AIP MCP profile.
pub fn mcp_tools_from_apps(
    apps: Vec<DifyApp>,
    tenant_id: &str,
) -> Result<Value, aip_core::IdParseError> {
    let manifest = manifest_from_apps(apps, tenant_id)?;
    Ok(aip_profile_mcp::tools_list_result(&manifest))
}

/// Maps a Dify streaming event to an AIP stream chunk.
#[must_use]
pub fn stream_chunk_from_dify(
    action_id: aip_core::ActionId,
    sequence: u64,
    event: DifyStreamEvent,
) -> StreamChunk {
    let kind = match event.event.as_str() {
        "workflow_started" | "node_started" => StreamChunkKind::Progress,
        "tool_call" => StreamChunkKind::Tool,
        "agent_thought" => StreamChunkKind::Thought,
        "message" => StreamChunkKind::Data,
        "human_input_required" | "workflow_paused" => StreamChunkKind::PendingApproval,
        "error" => StreamChunkKind::Error,
        "message_end" | "workflow_finished" => StreamChunkKind::Done,
        _ => StreamChunkKind::Progress,
    };
    StreamChunk {
        action_id,
        sequence,
        kind,
        part: event
            .data
            .get("answer")
            .and_then(Value::as_str)
            .filter(|answer| !answer.is_empty())
            .map(MessagePart::text),
        data: Some(event.data),
    }
}

/// Maps Dify `ask_human` semantics to AIP escalation.
#[must_use]
pub fn escalation_from_ask_human(reason: String, requested_by: Principal) -> Escalation {
    Escalation {
        kind: EscalationKind::Input,
        reason,
        requested_by,
        form: None,
        risk: Some(RiskLevel::Medium),
        timeout_ms: None,
        allowed_decisions: Vec::new(),
        conversation: None,
    }
}

fn dify_request_body(
    app: &DifyApp,
    input: &Value,
    response_mode: &str,
) -> Result<Value, DifyConnectorError> {
    let query = input
        .get("query")
        .or_else(|| input.get("prompt"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .trim();
    let inputs = input.get("inputs").cloned().unwrap_or_else(|| json!({}));
    let user = input
        .get("user")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|user| !user.is_empty())
        .ok_or_else(|| {
            DifyConnectorError::InvalidInput(
                "user is required to preserve Dify end-user isolation".to_owned(),
            )
        })?;
    let family = dify_api_family(&app.mode)?;
    let mut body = if family == DifyApiFamily::Workflow {
        json!({
            "inputs": inputs,
            "response_mode": response_mode,
            "user": user
        })
    } else {
        if query.is_empty() {
            return Err(DifyConnectorError::InvalidInput(
                "query or prompt is required for completion and chat apps".to_owned(),
            ));
        }
        json!({
            "query": query,
            "inputs": inputs,
            "response_mode": response_mode,
            "user": user
        })
    };
    if family == DifyApiFamily::Chat {
        for field in ["conversation_id", "files", "auto_generate_name"] {
            if let Some(value) = input.get(field) {
                body[field] = value.clone();
            }
        }
    } else if family == DifyApiFamily::Completion
        && let Some(files) = input.get("files")
    {
        body["files"] = files.clone();
    }
    ensure_dify_json_request_size(&body)?;
    Ok(body)
}

fn ensure_dify_json_request_size(body: &Value) -> Result<(), DifyConnectorError> {
    let encoded = serde_json::to_vec(body)
        .map_err(|error| DifyConnectorError::InvalidInput(error.to_string()))?;
    if encoded.len() > MAX_JSON_REQUEST_BYTES {
        return Err(DifyConnectorError::InvalidInput(format!(
            "Dify JSON body exceeds {MAX_JSON_REQUEST_BYTES} bytes"
        )));
    }
    Ok(())
}

async fn response_body(
    response: reqwest::Response,
    max_response_bytes: usize,
) -> Result<Value, DifyConnectorError> {
    let bytes = response_bytes(response, max_response_bytes).await?;
    Ok(decode_response_value(&bytes))
}

async fn response_bytes(
    response: reqwest::Response,
    max_response_bytes: usize,
) -> Result<Vec<u8>, DifyConnectorError> {
    if response
        .content_length()
        .is_some_and(|length| length > max_response_bytes as u64)
    {
        return Err(DifyConnectorError::ResponseTooLarge {
            limit: max_response_bytes,
        });
    }
    let mut bytes = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if bytes.len().saturating_add(chunk.len()) > max_response_bytes {
            return Err(DifyConnectorError::ResponseTooLarge {
                limit: max_response_bytes,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

fn decode_response_value(bytes: &[u8]) -> Value {
    if bytes.is_empty() {
        return Value::Null;
    }
    serde_json::from_slice(bytes)
        .unwrap_or_else(|_| json!({ "text": String::from_utf8_lossy(bytes) }))
}

#[derive(Debug)]
struct ParsedDifyEvent {
    event: DifyStreamEvent,
    task_id: Option<String>,
    terminal: bool,
    failed: bool,
    requires_human: bool,
}

fn parse_dify_sse_frame(frame: &[u8]) -> Result<Option<ParsedDifyEvent>, DifyConnectorError> {
    let frame = str::from_utf8(frame)
        .map_err(|error| DifyConnectorError::Stream(format!("SSE frame is not UTF-8: {error}")))?;
    let mut data_lines = Vec::new();
    for raw_line in frame.lines() {
        let line = raw_line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        let (field, value) = line.split_once(':').map_or((line, ""), |(field, value)| {
            (field, value.strip_prefix(' ').unwrap_or(value))
        });
        if field == "data" {
            data_lines.push(value);
        }
    }
    if data_lines.is_empty() {
        return Ok(None);
    }
    let raw_data = data_lines.join("\n");
    if raw_data.trim() == "[DONE]" {
        return Ok(Some(ParsedDifyEvent {
            event: DifyStreamEvent {
                event: "message_end".to_owned(),
                data: json!({ "done": true }),
            },
            task_id: None,
            terminal: true,
            failed: false,
            requires_human: false,
        }));
    }
    let value = serde_json::from_str::<Value>(&raw_data).map_err(|error| {
        DifyConnectorError::Stream(format!("SSE data is not valid JSON: {error}"))
    })?;
    let event_name = value
        .get("event")
        .and_then(Value::as_str)
        .ok_or_else(|| DifyConnectorError::Stream("SSE data is missing `event`".to_owned()))?
        .to_owned();
    let data = value.get("data").cloned().unwrap_or_else(|| value.clone());
    let task_id = value
        .get("task_id")
        .or_else(|| value.pointer("/data/task_id"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let terminal = matches!(
        event_name.as_str(),
        "message_end" | "workflow_finished" | "workflow_paused"
    );
    let failed = event_name == "error"
        || (event_name == "workflow_finished"
            && data
                .get("status")
                .and_then(Value::as_str)
                .is_some_and(|status| status != "succeeded"));
    let requires_human = matches!(
        event_name.as_str(),
        "human_input_required" | "workflow_paused"
    );
    Ok(Some(ParsedDifyEvent {
        event: DifyStreamEvent {
            event: event_name,
            data,
        },
        task_id,
        terminal,
        failed,
        requires_human,
    }))
}

fn take_sse_frame(buffer: &mut Vec<u8>) -> Result<Option<Vec<u8>>, DifyConnectorError> {
    let lf = buffer.windows(2).position(|window| window == b"\n\n");
    let crlf = buffer.windows(4).position(|window| window == b"\r\n\r\n");
    let (position, delimiter_len) = match (lf, crlf) {
        (Some(lf), Some(crlf)) if lf <= crlf => (lf, 2),
        (Some(_), Some(crlf)) => (crlf, 4),
        (Some(lf), None) => (lf, 2),
        (None, Some(crlf)) => (crlf, 4),
        (None, None) => return Ok(None),
    };
    if position > MAX_SSE_FRAME_BYTES {
        return Err(DifyConnectorError::Stream(format!(
            "SSE frame exceeded {MAX_SSE_FRAME_BYTES} bytes"
        )));
    }
    let frame = buffer[..position].to_vec();
    buffer.drain(..position + delimiter_len);
    Ok(Some(frame))
}

fn append_dify_answer(
    answer: &mut String,
    event: &ParsedDifyEvent,
    max_response_bytes: usize,
) -> Result<(), DifyConnectorError> {
    if event.event.event == "message"
        && let Some(delta) = event.event.data.get("answer").and_then(Value::as_str)
    {
        if answer.len().saturating_add(delta.len()) > max_response_bytes {
            return Err(DifyConnectorError::ResponseTooLarge {
                limit: max_response_bytes,
            });
        }
        answer.push_str(delta);
    }
    Ok(())
}

fn completed_dify_result(action: Action, output: Value) -> ActionResult {
    ActionResult {
        action_id: action.id,
        status: ActionResultStatus::Completed,
        output: Some(output.clone()),
        message: vec![MessagePart::Json {
            data: output,
            schema: None,
        }],
        memory_update: None,
        usage: None,
        receipt: None,
        error: None,
    }
}

fn dify_response_requires_human(value: &Value) -> bool {
    value
        .get("event")
        .and_then(Value::as_str)
        .is_some_and(|event| matches!(event, "human_input_required" | "workflow_paused"))
        || value
            .get("status")
            .or_else(|| value.pointer("/data/status"))
            .and_then(Value::as_str)
            .is_some_and(|status| status == "paused")
        || value.get("pause_reasons").is_some()
        || value.pointer("/data/pause_reasons").is_some()
}

fn dify_requires_human_result(action: Action, output: Value) -> ActionResult {
    ActionResult {
        action_id: action.id,
        status: ActionResultStatus::RequiresHuman,
        output: Some(output.clone()),
        message: vec![MessagePart::Json {
            data: output,
            schema: None,
        }],
        memory_update: None,
        usage: None,
        receipt: None,
        error: None,
    }
}

fn dify_failed_result(action: &Action, details: Value) -> ActionResult {
    ActionResult {
        action_id: action.id.clone(),
        status: ActionResultStatus::Failed,
        output: Some(details.clone()),
        message: Vec::new(),
        memory_update: None,
        usage: None,
        receipt: None,
        error: Some(ProtocolError {
            code: "connector.dify.upstream_failed".to_owned(),
            message: "Dify reported a terminal execution failure".to_owned(),
            category: ErrorCategory::Connector,
            retryable: Some(false),
            retry_after_ms: None,
            details: Some(Box::new(details)),
            source: Some(Box::new(json!({ "connector": CONNECTOR_ID }))),
        }),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct DifyOperationSafety {
    retry_safe: bool,
    mutation: bool,
}

impl DifyOperationSafety {
    const MUTATION_UNSAFE: Self = Self {
        retry_safe: false,
        mutation: true,
    };
}

fn dify_failure(
    error: DifyConnectorError,
    operation: ConnectorOperation,
    safety: DifyOperationSafety,
) -> ConnectorFailure {
    let (code, category, retryable, remote_status, uncertain_outcome) = match &error {
        DifyConnectorError::Status { status, .. } if matches!(*status, 401 | 403) => (
            "connector.dify.authentication",
            ErrorCategory::Auth,
            false,
            Some(*status),
            false,
        ),
        DifyConnectorError::Status { status, .. } if *status == 429 || *status >= 500 => (
            "connector.dify.remote_temporary",
            ErrorCategory::Temporary,
            safety.retry_safe,
            Some(*status),
            operation == ConnectorOperation::Invocation && safety.mutation,
        ),
        DifyConnectorError::Status { status, .. } => (
            "connector.dify.remote_rejected",
            ErrorCategory::Permanent,
            false,
            Some(*status),
            false,
        ),
        DifyConnectorError::Http(error) => (
            "connector.dify.transport",
            ErrorCategory::Transport,
            safety.retry_safe,
            None,
            operation == ConnectorOperation::Invocation && safety.mutation && !error.is_connect(),
        ),
        DifyConnectorError::Stream(_) => (
            "connector.dify.invalid_stream",
            ErrorCategory::Connector,
            safety.retry_safe,
            None,
            operation == ConnectorOperation::Invocation && safety.mutation,
        ),
        DifyConnectorError::ResponseTooLarge { .. } => (
            "connector.dify.response_too_large",
            ErrorCategory::Permanent,
            false,
            None,
            operation == ConnectorOperation::Invocation && safety.mutation,
        ),
        DifyConnectorError::Cancelled {
            remote_stop_confirmed,
        } => (
            "connector.dify.cancelled",
            ErrorCategory::Temporary,
            false,
            None,
            !remote_stop_confirmed && safety.mutation,
        ),
        DifyConnectorError::TaskStore(_) => (
            "connector.dify.task_store",
            ErrorCategory::Temporary,
            false,
            None,
            operation == ConnectorOperation::Invocation && safety.mutation,
        ),
        DifyConnectorError::InvalidCredential => (
            "connector.dify.invalid_credential",
            ErrorCategory::Auth,
            false,
            None,
            false,
        ),
        DifyConnectorError::InvalidInput(_)
        | DifyConnectorError::InvalidApp(_)
        | DifyConnectorError::NoApps
        | DifyConnectorError::InvalidUrl(_)
        | DifyConnectorError::InvalidBaseUrl(_)
        | DifyConnectorError::InvalidClient(_)
        | DifyConnectorError::CapabilityNotFound(_) => (
            "connector.dify.configuration_or_input",
            ErrorCategory::Permanent,
            false,
            None,
            false,
        ),
    };
    ConnectorFailure {
        code: code.to_owned(),
        message: error.to_string(),
        category,
        retryable,
        retry_after_ms: None,
        provider_request_id: None,
        provider_operation: None,
        remote_status,
        uncertain_outcome,
        redacted_details: None,
        source_component: CONNECTOR_ID.to_owned(),
        operation,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ALL_DIFY_OPERATIONS, DifyApp, DifyConnector, DifyConnectorError, DifyHttpMethod,
        DifyKnowledgeBase, DifyKnowledgeCredential, DifyOperation, DifyOperationScope,
        DifyRequestKind, DifyTaskReference, DifyTaskStore, FileDifyTaskStore,
        MAX_JSON_REQUEST_BYTES, MAX_QUERY_VALUE_BYTES, append_dify_query,
        capabilities_from_knowledge, dify_operation_input_schema, dify_operation_url,
        dify_request_body, manifest_from_apps, manifest_from_configuration, parse_dify_sse_frame,
        stream_chunk_from_dify, take_sse_frame,
    };
    use aip_auth::{AuthScheme, AuthenticatedPrincipal, VerifiedTenant};
    use aip_connector::{
        ConnectorContext, ConnectorError, ConnectorOperation, ConnectorSecret,
        FrozenConnectorHandler, OutboundConnector,
    };
    use aip_core::{
        Action, ActionResultStatus, Cancel, CancelTarget, CapabilityId, IdentityContext,
        MessageBody, Principal, PrincipalId, PrincipalKind, StreamChunkKind, TenantRef,
    };
    use aip_runtime::{ActionHandler, MessageContext, Runtime};
    use axum::{
        Json, Router,
        body::{Body, to_bytes},
        extract::{Path, Request, State},
        http::{HeaderMap, Response, StatusCode, header},
        routing::{patch, post},
    };
    use base64::Engine;
    use bytes::Bytes;
    use futures_util::stream;
    use serde_json::{Value, json};
    use std::{
        collections::BTreeSet,
        convert::Infallible,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::{net::TcpListener, sync::Notify, task::JoinHandle};

    #[derive(Clone, Default)]
    struct MockDifyState {
        release: Arc<Notify>,
        stop_count: Arc<AtomicUsize>,
    }

    #[test]
    fn frozen_service_api_catalog_is_complete_unique_and_governed() {
        assert_eq!(ALL_DIFY_OPERATIONS.len(), 79);
        assert_eq!(
            ALL_DIFY_OPERATIONS
                .iter()
                .filter(|operation| operation.scope() == DifyOperationScope::App)
                .count(),
            33
        );
        assert_eq!(
            ALL_DIFY_OPERATIONS
                .iter()
                .filter(|operation| operation.scope() == DifyOperationScope::Knowledge)
                .count(),
            46
        );
        let suffixes = ALL_DIFY_OPERATIONS
            .iter()
            .map(|operation| operation.suffix())
            .collect::<BTreeSet<_>>();
        assert_eq!(suffixes.len(), ALL_DIFY_OPERATIONS.len());
        let routes = ALL_DIFY_OPERATIONS
            .iter()
            .map(|operation| (operation.method(), operation.path_template()))
            .collect::<BTreeSet<_>>();
        assert_eq!(routes.len(), ALL_DIFY_OPERATIONS.len());
        for operation in ALL_DIFY_OPERATIONS {
            assert!(operation.path_template().starts_with("/v1/"));
            assert_eq!(
                operation.retry_safe(),
                operation.method() == DifyHttpMethod::Get
            );
            assert_eq!(operation.is_mutation(), !operation.retry_safe());
            assert_eq!(
                operation.supports_cancel(),
                matches!(
                    operation,
                    DifyOperation::WorkflowRunById | DifyOperation::WorkflowEvents
                )
            );

            let schema = dify_operation_input_schema(*operation);
            let properties = schema["properties"]
                .as_object()
                .expect("operation schema properties");
            let accepts_body = operation.method() != DifyHttpMethod::Get
                && (operation.request_kind() == DifyRequestKind::Json
                    || operation.accepts_multipart_data());
            assert_eq!(
                properties.contains_key("body"),
                accepts_body,
                "unexpected body contract for {}",
                operation.suffix()
            );
        }
    }

    #[test]
    fn cancellation_contract_distinguishes_stop_commands_from_cancellable_runs() {
        for stop_command in [
            DifyOperation::CompletionStop,
            DifyOperation::ChatStop,
            DifyOperation::WorkflowStop,
        ] {
            assert!(stop_command.is_mutation());
            assert!(!stop_command.supports_cancel());
        }
        assert!(DifyOperation::WorkflowRunById.supports_cancel());
        assert!(DifyOperation::WorkflowEvents.supports_cancel());
    }

    #[test]
    fn knowledge_manifest_declares_every_callable_operation() {
        let descriptor = DifyKnowledgeBase {
            id: "workspace-main".to_owned(),
            name: "Main workspace".to_owned(),
            description: Some("Production knowledge surface".to_owned()),
        };
        let capabilities =
            capabilities_from_knowledge(&descriptor).expect("knowledge capabilities");
        assert_eq!(capabilities.len(), 46);
        assert!(capabilities.iter().all(|capability| {
            capability
                .id
                .as_str()
                .starts_with("cap:dify:knowledge:workspace-main:")
        }));
        let manifest = manifest_from_configuration(Vec::new(), vec![descriptor], "tenant-1")
            .expect("knowledge manifest");
        assert_eq!(manifest.capabilities.len(), 46);
    }

    #[test]
    fn operations_without_query_pairs_preserve_canonical_upstream_path() {
        let base_url = url::Url::parse("https://api.dify.ai").expect("Dify base URL");
        let mut url = dify_operation_url(
            &base_url,
            DifyOperation::DatasetCreate,
            &json!({ "body": { "name": "Qualification Dataset" } }),
        )
        .expect("dataset create URL");
        append_dify_query(&mut url, None, None).expect("empty query");
        assert_eq!(url.as_str(), "https://api.dify.ai/v1/datasets");

        append_dify_query(&mut url, Some(&json!({ "ignored": null })), None)
            .expect("all-null query");
        assert_eq!(url.as_str(), "https://api.dify.ai/v1/datasets");
    }

    #[test]
    fn provider_query_and_app_request_are_bounded_before_dispatch() {
        let mut url = url::Url::parse("https://api.dify.ai/v1/datasets").expect("Dify URL");
        assert!(
            append_dify_query(
                &mut url,
                Some(&json!({ "keyword": "x".repeat(MAX_QUERY_VALUE_BYTES + 1) })),
                None
            )
            .is_err()
        );
        let app = DifyApp {
            id: "support".to_owned(),
            name: "Support".to_owned(),
            mode: "chat".to_owned(),
            description: None,
        };
        assert!(
            dify_request_body(
                &app,
                &json!({
                    "query": "hello",
                    "user": "tenant-user",
                    "inputs": { "payload": "x".repeat(MAX_JSON_REQUEST_BYTES + 1) }
                }),
                "blocking"
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn knowledge_mutation_uses_scoped_key_patch_body_and_idempotency() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind knowledge mock");
        let address = listener.local_addr().expect("knowledge mock address");
        let router =
            Router::new().route(
                "/v1/datasets/{dataset_id}",
                patch(
                    |Path(dataset_id): Path<String>,
                     headers: HeaderMap,
                     Json(body): Json<Value>| async move {
                        assert_eq!(dataset_id, "dataset-1");
                        assert_eq!(
                            headers
                                .get(header::AUTHORIZATION)
                                .and_then(|value| value.to_str().ok()),
                            Some("Bearer knowledge-secret")
                        );
                        assert_eq!(
                            headers
                                .get("idempotency-key")
                                .and_then(|value| value.to_str().ok()),
                            Some("dataset-update-1")
                        );
                        assert_eq!(body, json!({ "name": "Updated" }));
                        Json(json!({ "id": dataset_id, "name": "Updated" }))
                    },
                ),
            );
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve knowledge mock");
        });
        let connector = knowledge_connector(&format!("http://{address}"));
        let mut action = Action::new(
            CapabilityId::trusted("cap:dify:knowledge:workspace-main:dataset.update"),
            json!({
                "dataset_id": "dataset-1",
                "body": { "name": "Updated" }
            }),
        );
        action.idempotency_key = Some("dataset-update-1".to_owned());
        let result = connector
            .invoke(&ConnectorContext::default(), action)
            .await
            .expect("knowledge update");
        assert_eq!(result.status, ActionResultStatus::Completed);
        assert_eq!(
            result
                .output
                .as_ref()
                .and_then(|output| output.pointer("/body/name")),
            Some(&json!("Updated"))
        );
        server.abort();
    }

    #[tokio::test]
    async fn knowledge_file_upload_is_bounded_multipart_with_serialized_data() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind multipart mock");
        let address = listener.local_addr().expect("multipart mock address");
        let router = Router::new().route(
            "/v1/datasets/{dataset_id}/document/create-by-file",
            post(
                |Path(dataset_id): Path<String>, headers: HeaderMap, request: Request| async move {
                    assert_eq!(dataset_id, "dataset-1");
                    assert_eq!(
                        headers
                            .get(header::AUTHORIZATION)
                            .and_then(|value| value.to_str().ok()),
                        Some("Bearer knowledge-secret")
                    );
                    let content_type = headers
                        .get(header::CONTENT_TYPE)
                        .and_then(|value| value.to_str().ok())
                        .expect("multipart content type");
                    assert!(content_type.starts_with("multipart/form-data; boundary="));
                    let bytes = to_bytes(request.into_body(), 1024 * 1024)
                        .await
                        .expect("multipart body");
                    let body = String::from_utf8(bytes.to_vec()).expect("utf8 multipart fixture");
                    assert!(body.contains("name=\"file\"; filename=\"case.txt\""));
                    assert!(body.contains("case evidence"));
                    assert!(body.contains("name=\"data\""));
                    assert!(body.contains("indexing_technique"));
                    Json(json!({ "batch": "batch-1" }))
                },
            ),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve multipart mock");
        });
        let connector = knowledge_connector(&format!("http://{address}"));
        let mut action = Action::new(
            CapabilityId::trusted("cap:dify:knowledge:workspace-main:document.file.create"),
            json!({
                "dataset_id": "dataset-1",
                "file": {
                    "filename": "case.txt",
                    "content_type": "text/plain",
                    "content_base64": base64::engine::general_purpose::STANDARD.encode(b"case evidence")
                },
                "body": {
                    "indexing_technique": "high_quality",
                    "process_rule": { "mode": "automatic" }
                }
            }),
        );
        action.idempotency_key = Some("file-create-1".to_owned());
        let result = connector
            .invoke(&ConnectorContext::default(), action)
            .await
            .expect("knowledge file upload");
        assert_eq!(result.status, ActionResultStatus::Completed);
        server.abort();
    }

    #[tokio::test]
    async fn knowledge_binary_response_is_bounded_and_base64_encoded() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind binary mock");
        let address = listener.local_addr().expect("binary mock address");
        let router = Router::new().route(
            "/v1/datasets/{dataset_id}/documents/download-zip",
            post(|| async {
                Response::builder()
                    .status(StatusCode::OK)
                    .header(header::CONTENT_TYPE, "application/zip")
                    .body(Body::from(Bytes::from_static(b"PK-test-archive")))
                    .expect("binary response")
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("serve binary mock");
        });
        let connector = knowledge_connector(&format!("http://{address}"));
        let mut action = Action::new(
            CapabilityId::trusted("cap:dify:knowledge:workspace-main:document.download_zip"),
            json!({
                "dataset_id": "dataset-1",
                "body": { "document_ids": ["document-1"] }
            }),
        );
        action.idempotency_key = Some("download-1".to_owned());
        let result = connector
            .invoke(&ConnectorContext::default(), action)
            .await
            .expect("binary knowledge response");
        let output = result.output.expect("binary output");
        assert_eq!(output.get("size_bytes"), Some(&json!(15)));
        assert_eq!(
            output.get("content_base64"),
            Some(&json!(
                base64::engine::general_purpose::STANDARD.encode(b"PK-test-archive")
            ))
        );
        server.abort();
    }

    #[tokio::test]
    async fn knowledge_mutations_fail_closed_without_idempotency() {
        let connector = knowledge_connector("http://127.0.0.1:9");
        let action = Action::new(
            CapabilityId::trusted("cap:dify:knowledge:workspace-main:dataset.create"),
            json!({ "body": { "name": "Unsafe duplicate" } }),
        );
        let error = connector
            .invoke(&ConnectorContext::default(), action)
            .await
            .expect_err("missing idempotency must fail before transport");
        assert!(error.to_string().contains("idempotency_key"));
    }

    #[test]
    fn runtime_failures_match_the_published_retry_contract() {
        let connector = knowledge_connector("http://127.0.0.1:9");
        let read = Action::new(
            CapabilityId::trusted("cap:dify:knowledge:workspace-main:dataset.list"),
            json!({}),
        );
        let read_failure = super::dify_failure(
            DifyConnectorError::Status {
                status: 503,
                body: json!({ "error": "unavailable" }),
            },
            ConnectorOperation::Invocation,
            connector.action_safety(&read),
        );
        assert!(read_failure.retryable);
        assert!(!read_failure.uncertain_outcome);

        let app_connector = DifyConnector::new(
            "http://127.0.0.1:9",
            "test-secret",
            vec![DifyApp {
                id: "chat-app".to_owned(),
                name: "Chat app".to_owned(),
                mode: "chat".to_owned(),
                description: None,
            }],
        )
        .expect("Dify connector");
        let mutation = Action::new(
            CapabilityId::trusted("cap:dify:chat-app"),
            json!({ "query": "hello", "user": "test" }),
        );
        let mutation_failure = super::dify_failure(
            DifyConnectorError::Status {
                status: 503,
                body: json!({ "error": "unavailable" }),
            },
            ConnectorOperation::Invocation,
            app_connector.action_safety(&mutation),
        );
        assert!(!mutation_failure.retryable);
        assert!(mutation_failure.uncertain_outcome);
    }

    #[tokio::test]
    async fn dify_sse_is_published_incrementally_through_native_runtime() {
        let state = MockDifyState::default();
        let (base_url, server) = spawn_mock_dify(state.clone()).await;
        let (runtime, principal, mut action, context) = configured_runtime(&base_url).await;
        let action_id = action.id.clone();
        action.input = json!({ "query": "hello", "user": "stream-test" });
        let execution = {
            let runtime = runtime.clone();
            let principal = principal.clone();
            tokio::spawn(async move {
                runtime
                    .process_action_with_context(action, &principal, context)
                    .await
            })
        };

        let first_chunks = wait_for_chunks(&runtime, &action_id, 1).await;
        assert_eq!(first_chunks.len(), 1);
        assert_eq!(first_chunks[0].sequence, 0);
        assert_eq!(first_chunks[0].kind, StreamChunkKind::Data);
        assert!(!execution.is_finished());

        state.release.notify_waiters();
        let result = execution
            .await
            .expect("execution task")
            .expect("Dify action result");
        assert_eq!(result.status, ActionResultStatus::Completed);
        assert_eq!(
            result.output.as_ref().and_then(|value| value.get("answer")),
            Some(&json!("hello world"))
        );
        let chunks = wait_for_chunks(&runtime, &action_id, 3).await;
        assert_eq!(
            chunks.last().map(|chunk| chunk.kind),
            Some(StreamChunkKind::Done)
        );
        server.abort();
    }

    #[tokio::test]
    async fn native_cancel_calls_dify_stop_and_preserves_cancelled_terminal_state() {
        let state = MockDifyState::default();
        let (base_url, server) = spawn_mock_dify(state.clone()).await;
        let (runtime, principal, mut action, context) = configured_runtime(&base_url).await;
        let action_id = action.id.clone();
        action.input = json!({ "query": "cancel", "user": "cancel-test" });
        let execution = {
            let runtime = runtime.clone();
            let principal = principal.clone();
            tokio::spawn(async move {
                runtime
                    .process_action_with_context(action, &principal, context)
                    .await
            })
        };
        wait_for_chunks(&runtime, &action_id, 1).await;

        let response = runtime
            .handle_cancel(
                Cancel {
                    target: CancelTarget::Action(action_id.clone()),
                    reason: Some("operator cancelled test".to_owned()),
                },
                trusted_dify_context(&principal),
            )
            .await
            .expect("cancel action");
        assert!(matches!(response, MessageBody::ActionResult(_)));
        let result = execution
            .await
            .expect("execution task")
            .expect("cancelled result");
        assert_eq!(result.status, ActionResultStatus::Cancelled);
        assert_eq!(state.stop_count.load(Ordering::SeqCst), 1);
        assert_eq!(
            runtime
                .lifecycle
                .action_result(&action_id)
                .await
                .expect("stored result")
                .expect("terminal result")
                .status,
            ActionResultStatus::Cancelled
        );
        state.release.notify_waiters();
        server.abort();
    }

    #[tokio::test]
    async fn malformed_stream_after_task_admission_triggers_confirmed_remote_stop() {
        let state = MockDifyState::default();
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind malformed Dify mock");
        let address = listener.local_addr().expect("malformed Dify address");
        let app = Router::new()
            .route("/v1/chat-messages", post(mock_malformed_stream))
            .route("/v1/chat-messages/{task_id}/stop", post(mock_stop))
            .with_state(state.clone());
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve malformed Dify mock");
        });
        let (runtime, principal, mut action, context) =
            configured_runtime(&format!("http://{address}")).await;
        action.input = json!({ "query": "malformed", "user": "cancel-test" });
        runtime
            .process_action_with_context(action, &principal, context)
            .await
            .expect_err("malformed provider stream must fail");
        assert_eq!(state.stop_count.load(Ordering::SeqCst), 1);
        server.abort();
    }

    #[tokio::test]
    async fn durable_task_store_recovers_remote_cancellation_after_restart() {
        let state = MockDifyState::default();
        let (base_url, server) = spawn_mock_dify(state.clone()).await;
        let path =
            std::env::temp_dir().join(format!("aip-dify-tasks-{}.json", aip_core::ActionId::new()));
        let app = DifyApp {
            id: "chat-app".to_owned(),
            name: "Chat app".to_owned(),
            mode: "chat".to_owned(),
            description: None,
        };
        let action = Action::new(
            CapabilityId::trusted("cap:dify:chat-app"),
            json!({ "query": "cancel", "user": "cancel-test" }),
        );
        let first_store = FileDifyTaskStore::new(&path);
        first_store
            .put(
                &action.id,
                DifyTaskReference {
                    app_id: "chat-app".to_owned(),
                    task_id: "task-1".to_owned(),
                    user: "cancel-test".to_owned(),
                },
            )
            .await
            .expect("persist active Dify task");
        drop(first_store);

        let restarted = DifyConnector::new(base_url, "test-secret", vec![app])
            .expect("restarted connector")
            .with_task_store(Arc::new(FileDifyTaskStore::new(&path)));
        OutboundConnector::cancel(&restarted, &ConnectorContext::default(), &action)
            .await
            .expect("cancel recovered Dify task");
        assert_eq!(state.stop_count.load(Ordering::SeqCst), 1);
        tokio::fs::remove_file(path)
            .await
            .expect("remove Dify task fixture");
        state.release.notify_waiters();
        server.abort();
    }

    #[tokio::test]
    async fn cancellation_without_a_durable_task_id_is_never_reported_as_confirmed() {
        let connector = DifyConnector::new(
            "http://127.0.0.1:9",
            "test-secret",
            vec![DifyApp {
                id: "chat-app".to_owned(),
                name: "Chat app".to_owned(),
                mode: "chat".to_owned(),
                description: None,
            }],
        )
        .expect("Dify connector");
        let action = Action::new(
            CapabilityId::trusted("cap:dify:chat-app"),
            json!({ "query": "cancel", "user": "cancel-test" }),
        );
        let error = OutboundConnector::cancel(&connector, &ConnectorContext::default(), &action)
            .await
            .expect_err("missing durable task id must fail closed");
        let ConnectorError::Failure(failure) = error else {
            panic!("expected structured connector failure");
        };
        assert_eq!(failure.code, "connector.dify.cancelled");
        assert!(failure.uncertain_outcome);
    }

    #[tokio::test]
    async fn completion_apps_use_the_completion_api_and_preserve_request_fields() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind completion mock");
        let address = listener.local_addr().expect("completion mock address");
        let app = Router::new().route(
            "/v1/completion-messages",
            post(|Json(request): Json<Value>| async move {
                assert_eq!(request.get("query"), Some(&json!("summarize")));
                assert_eq!(request.get("user"), Some(&json!("user-1")));
                assert_eq!(request.pointer("/inputs/case_id"), Some(&json!("case-1")));
                Json(json!({ "answer": "summary", "message_id": "message-1" }))
            }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve completion mock");
        });
        let connector = DifyConnector::new(
            format!("http://{address}"),
            "completion-secret",
            vec![DifyApp {
                id: "completion-app".to_owned(),
                name: "Completion app".to_owned(),
                mode: "completion".to_owned(),
                description: None,
            }],
        )
        .expect("completion connector");
        let mut action = Action::new(
            CapabilityId::trusted("cap:dify:completion-app"),
            json!({
                "query": "summarize",
                "user": "user-1",
                "inputs": { "case_id": "case-1" }
            }),
        );
        action.idempotency_key = Some("completion-case-1".to_owned());
        let result = connector
            .invoke(&ConnectorContext::default(), action)
            .await
            .expect("completion invocation");
        assert_eq!(result.status, ActionResultStatus::Completed);
        assert_eq!(
            result.output.and_then(|value| value.get("answer").cloned()),
            Some(json!("summary"))
        );
        assert!(!format!("{connector:?}").contains("completion-secret"));
        server.abort();
    }

    #[test]
    fn dify_sse_parser_accepts_crlf_and_rejects_missing_event_name() {
        let event = parse_dify_sse_frame(
            b"event: message\r\ndata: {\"event\":\"message\",\"answer\":\"ok\"}\r\n",
        )
        .expect("parse frame")
        .expect("event");
        assert_eq!(event.event.event, "message");
        assert!(parse_dify_sse_frame(b"data: {\"answer\":\"missing\"}\n").is_err());

        let paused = parse_dify_sse_frame(
            b"data: {\"event\":\"workflow_paused\",\"data\":{\"reasons\":[]}}\n",
        )
        .expect("parse paused frame")
        .expect("paused event");
        assert!(paused.terminal);
        assert!(paused.requires_human);
        let chunk = stream_chunk_from_dify(aip_core::ActionId::new(), 0, paused.event);
        assert_eq!(chunk.kind, StreamChunkKind::PendingApproval);
    }

    #[test]
    fn sse_framing_bounds_individual_frames_not_transport_chunks() {
        let payload = "x".repeat(4_096);
        let encoded = format!("data: {{\"event\":\"message\",\"answer\":\"{payload}\"}}\n\n");
        let frame_count = (super::MAX_SSE_FRAME_BYTES / encoded.len()) + 2;
        let mut transport_chunk = encoded.repeat(frame_count).into_bytes();
        assert!(transport_chunk.len() > super::MAX_SSE_FRAME_BYTES);

        let mut drained = 0;
        while let Some(frame) = take_sse_frame(&mut transport_chunk).expect("bounded frame") {
            assert!(frame.len() <= super::MAX_SSE_FRAME_BYTES);
            drained += 1;
        }
        assert_eq!(drained, frame_count);
        assert!(transport_chunk.is_empty());

        let mut oversized = vec![b'x'; super::MAX_SSE_FRAME_BYTES + 1];
        oversized.extend_from_slice(b"\n\n");
        assert!(take_sse_frame(&mut oversized).is_err());
    }

    async fn configured_runtime(base_url: &str) -> (Runtime, Principal, Action, MessageContext) {
        let app = DifyApp {
            id: "chat-app".to_owned(),
            name: "Chat app".to_owned(),
            mode: "chat".to_owned(),
            description: None,
        };
        let connector =
            DifyConnector::new(base_url, "test-secret", vec![app.clone()]).expect("Dify connector");
        let runtime = Runtime::new();
        let capability_id = CapabilityId::trusted("cap:dify:chat-app");
        let manifest = manifest_from_apps(vec![app], "test").expect("Dify manifest");
        let connector = Arc::new(connector);
        let handlers = manifest
            .capabilities
            .iter()
            .cloned()
            .map(|capability| {
                (
                    capability.id.clone(),
                    Arc::new(FrozenConnectorHandler::new(connector.clone(), capability))
                        as Arc<dyn ActionHandler>,
                )
            })
            .collect();
        runtime
            .admit_manifest_with_handlers("dify-test", manifest, handlers)
            .await
            .expect("atomically admit Dify manifest and handler");
        let principal = Principal::new(
            PrincipalId::trusted("agent:dify-connector-test"),
            PrincipalKind::Agent,
        );
        let mut action = Action::new(capability_id, json!({}));
        action.idempotency_key = Some(format!("dify-test:{}", action.id));
        action.identity = Some(IdentityContext {
            tenant: Some(TenantRef {
                id: "test-tenant".to_owned(),
                system: Some("test".to_owned()),
            }),
            external_account: None,
            external_user: None,
            human_actor: None,
            service_account: None,
            acted_on_behalf_of: None,
            credential_ref: None,
            oauth: None,
        });
        let context = trusted_dify_context(&principal);
        (runtime, principal, action, context)
    }

    fn trusted_dify_context(principal: &Principal) -> MessageContext {
        let tenant = TenantRef {
            id: "test-tenant".to_owned(),
            system: Some("test".to_owned()),
        };
        MessageContext {
            actor: Some(principal.clone()),
            authenticated: Some(AuthenticatedPrincipal {
                principal: principal.clone(),
                scheme: AuthScheme::DidProof,
                issuer: "test://dify-edge".to_owned(),
                audience: Some("aip-runtime".to_owned()),
                scopes: ["action:write".to_owned()].into_iter().collect(),
                authenticated_at: time::OffsetDateTime::now_utc(),
                expires_at: None,
                credential_fingerprint: Some("sha256:dify-test".to_owned()),
            }),
            tenant: Some(VerifiedTenant {
                tenant: tenant.clone(),
                membership_id: "membership:dify-test".to_owned(),
                roles: Default::default(),
                groups: Default::default(),
                verified_at: time::OffsetDateTime::now_utc(),
                expires_at: None,
            }),
            resolved_identity: Some(IdentityContext {
                tenant: Some(tenant),
                external_account: None,
                external_user: None,
                human_actor: None,
                service_account: None,
                acted_on_behalf_of: None,
                credential_ref: None,
                oauth: None,
            }),
            ..MessageContext::default()
        }
    }

    fn knowledge_connector(base_url: &str) -> DifyConnector {
        DifyConnector::with_credentials(
            base_url,
            Vec::new(),
            vec![DifyKnowledgeCredential {
                knowledge: DifyKnowledgeBase {
                    id: "workspace-main".to_owned(),
                    name: "Main workspace".to_owned(),
                    description: None,
                },
                api_key: ConnectorSecret::from("knowledge-secret".to_owned()),
            }],
        )
        .expect("knowledge connector")
    }

    async fn wait_for_chunks(
        runtime: &Runtime,
        action_id: &aip_core::ActionId,
        minimum: usize,
    ) -> Vec<aip_core::StreamChunk> {
        for _ in 0..200 {
            let chunks = runtime
                .lifecycle
                .stream_chunks(action_id)
                .await
                .expect("stream chunks");
            if chunks.len() >= minimum {
                return chunks;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("Dify stream did not publish {minimum} chunks in time");
    }

    async fn spawn_mock_dify(state: MockDifyState) -> (String, JoinHandle<()>) {
        let app = Router::new()
            .route("/v1/chat-messages", post(mock_stream))
            .route("/v1/chat-messages/{task_id}/stop", post(mock_stop))
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock Dify");
        let address = listener.local_addr().expect("mock address");
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serve mock Dify");
        });
        (format!("http://{address}"), server)
    }

    async fn mock_stream(
        State(state): State<MockDifyState>,
        Json(request): Json<Value>,
    ) -> Response<Body> {
        assert_eq!(request.get("response_mode"), Some(&json!("streaming")));
        let first = Bytes::from_static(
            b"data: {\"event\":\"message\",\"task_id\":\"task-1\",\"answer\":\"hello \"}\n\n",
        );
        let second = Bytes::from_static(
            b"data: {\"event\":\"message\",\"task_id\":\"task-1\",\"answer\":\"world\"}\n\ndata: {\"event\":\"message_end\",\"task_id\":\"task-1\",\"metadata\":{}}\n\n",
        );
        let body_stream = stream::unfold((0_u8, state.release), move |(stage, release)| {
            let first = first.clone();
            let second = second.clone();
            async move {
                match stage {
                    0 => Some((Ok::<Bytes, Infallible>(first), (1, release))),
                    1 => {
                        release.notified().await;
                        Some((Ok(second), (2, release)))
                    }
                    _ => None,
                }
            }
        });
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from_stream(body_stream))
            .expect("stream response")
    }

    async fn mock_malformed_stream(Json(request): Json<Value>) -> Response<Body> {
        assert_eq!(request.get("response_mode"), Some(&json!("streaming")));
        Response::builder()
            .status(StatusCode::OK)
            .header(header::CONTENT_TYPE, "text/event-stream")
            .body(Body::from(Bytes::from_static(
                b"data: {\"event\":\"message\",\"task_id\":\"task-1\",\"answer\":\"accepted\"}\n\ndata: {\"answer\":\"missing event\"}\n\n",
            )))
            .expect("malformed stream response")
    }

    async fn mock_stop(
        State(state): State<MockDifyState>,
        Path(task_id): Path<String>,
        Json(request): Json<Value>,
    ) -> Json<Value> {
        assert_eq!(task_id, "task-1");
        assert_eq!(request.get("user"), Some(&json!("cancel-test")));
        state.stop_count.fetch_add(1, Ordering::SeqCst);
        Json(json!({ "result": "success" }))
    }
}
