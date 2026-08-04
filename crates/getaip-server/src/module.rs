//! Product-neutral local module composition for `getaip-server`.
//!
//! Local modules are a migration and trusted first-party extension boundary.
//! Long-tail connector implementations run out of process and use the native
//! AIP connector-fleet path instead.

use aip_connector::Connector;
use aip_core::{Capability, CapabilityId, Manifest, PrincipalId};
use aip_runtime::{ActionHandler, DelegationRouter, RuntimeStores};
use async_trait::async_trait;
use axum::Router;
use std::{collections::BTreeMap, error::Error, fmt, sync::Arc};

/// Maximum number of trusted local modules admitted into one daemon process.
pub const MAX_LOCAL_MODULES: usize = 64;
/// Maximum serialized manifest contribution accepted from one module.
pub const MAX_MODULE_MANIFEST_BYTES: usize = 4 * 1024 * 1024;
/// Maximum executable capabilities accepted from one local module.
pub const MAX_MODULE_HANDLERS: usize = 4_096;
/// Maximum declared HTTP routes accepted from one local module.
pub const MAX_MODULE_HTTP_ROUTES: usize = 256;
/// Default upper bound for local module preparation.
pub const DEFAULT_MODULE_STARTUP_TIMEOUT_MS: u64 = 30_000;
/// Only HTTP namespace available to trusted local migration modules.
pub const LOCAL_MODULE_HTTP_ROUTE_PREFIX: &str = "/connectors/";

/// Validated deployment-local module identifier.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LocalModuleId(String);

impl LocalModuleId {
    /// Parses a bounded lower-case identifier used only for process
    /// composition and readiness. It is not part of the AIP wire schema.
    pub fn parse(value: impl Into<String>) -> Result<Self, DaemonModuleError> {
        let value = value.into();
        let valid = !value.is_empty()
            && value.len() <= 64
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'_' | b'-')
            });
        if !valid {
            return Err(DaemonModuleError::new(
                "aip.server.module.invalid_id",
                "module id must contain 1-64 lower-case ASCII letters, digits, dots, underscores, or hyphens",
            ));
        }
        Ok(Self(value))
    }

    /// Returns the validated identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LocalModuleId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

/// Static local module admission policy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalModuleDescriptor {
    /// Stable module identifier.
    pub id: LocalModuleId,
    /// Whether preparation failure must stop daemon startup.
    pub required: bool,
    /// Bounded module preparation timeout.
    pub startup_timeout_ms: u64,
}

impl LocalModuleDescriptor {
    /// Creates one required module descriptor.
    pub fn required(id: impl Into<String>) -> Result<Self, DaemonModuleError> {
        Ok(Self {
            id: LocalModuleId::parse(id)?,
            required: true,
            startup_timeout_ms: DEFAULT_MODULE_STARTUP_TIMEOUT_MS,
        })
    }

    /// Creates one optional module descriptor.
    pub fn optional(id: impl Into<String>) -> Result<Self, DaemonModuleError> {
        Ok(Self {
            id: LocalModuleId::parse(id)?,
            required: false,
            startup_timeout_ms: DEFAULT_MODULE_STARTUP_TIMEOUT_MS,
        })
    }

    /// Creates a required descriptor for a compile-time module identifier.
    ///
    /// This constructor exists for infallible [`DaemonModuleFactory::descriptor`]
    /// implementations. The daemon revalidates the identifier before sorting or
    /// preparing any factory, so an invalid trusted constant still fails startup.
    #[must_use]
    pub fn required_static(id: &'static str) -> Self {
        Self {
            id: LocalModuleId(id.to_owned()),
            required: true,
            startup_timeout_ms: DEFAULT_MODULE_STARTUP_TIMEOUT_MS,
        }
    }

    /// Replaces the bounded preparation timeout.
    pub fn with_startup_timeout_ms(mut self, timeout_ms: u64) -> Result<Self, DaemonModuleError> {
        if timeout_ms == 0 || timeout_ms > 300_000 {
            return Err(DaemonModuleError::new(
                "aip.server.module.invalid_timeout",
                "module startup timeout must be between 1 and 300000 milliseconds",
            ));
        }
        self.startup_timeout_ms = timeout_ms;
        Ok(self)
    }
}

/// One HTTP method/path claim made by a local module.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct DaemonHttpRoute {
    /// Upper-case HTTP method.
    pub method: String,
    /// Absolute Axum route path.
    pub path: String,
}

impl DaemonHttpRoute {
    /// Creates one validated HTTP route claim.
    pub fn new(
        method: impl Into<String>,
        path: impl Into<String>,
    ) -> Result<Self, DaemonModuleError> {
        let method = method.into().to_ascii_uppercase();
        let path = path.into();
        if method.is_empty()
            || !method.bytes().all(|byte| byte.is_ascii_uppercase())
            || !path.starts_with('/')
            || path.contains("//")
            || path.len() > 512
        {
            return Err(DaemonModuleError::new(
                "aip.server.module.invalid_http_route",
                "module HTTP routes require an upper-case method and a bounded absolute path",
            ));
        }
        if !path.starts_with(LOCAL_MODULE_HTTP_ROUTE_PREFIX) {
            return Err(DaemonModuleError::new(
                "aip.server.module.reserved_http_route",
                format!("module HTTP route must remain under {LOCAL_MODULE_HTTP_ROUTE_PREFIX}"),
            ));
        }
        Ok(Self { method, path })
    }

    pub(crate) fn conflict_key(&self) -> String {
        format!("{} {}", self.method, self.path)
    }
}

/// State-complete Axum router mounted atomically with a local module.
#[derive(Clone)]
pub struct DaemonHttpMount {
    routes: Vec<DaemonHttpRoute>,
    router: Router,
}

impl fmt::Debug for DaemonHttpMount {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DaemonHttpMount")
            .field("routes", &self.routes)
            .finish_non_exhaustive()
    }
}

impl DaemonHttpMount {
    /// Creates a mount with explicit route claims used for deterministic
    /// conflict detection before the listener is opened.
    pub fn new(routes: Vec<DaemonHttpRoute>, router: Router) -> Result<Self, DaemonModuleError> {
        if routes.is_empty() || routes.len() > MAX_MODULE_HTTP_ROUTES {
            return Err(DaemonModuleError::new(
                "aip.server.module.invalid_http_mount",
                format!(
                    "module HTTP mount must declare between 1 and {MAX_MODULE_HTTP_ROUTES} routes"
                ),
            ));
        }
        let mut unique = routes
            .iter()
            .map(DaemonHttpRoute::conflict_key)
            .collect::<Vec<_>>();
        unique.sort();
        unique.dedup();
        if unique.len() != routes.len() {
            return Err(DaemonModuleError::new(
                "aip.server.module.duplicate_http_route",
                "module HTTP mount contains duplicate route claims",
            ));
        }
        Ok(Self { routes, router })
    }

    pub(crate) fn routes(&self) -> &[DaemonHttpRoute] {
        &self.routes
    }

    pub(crate) fn router(&self) -> Router {
        self.router.clone()
    }
}

/// Narrow daemon services exposed while a trusted local module is prepared.
#[derive(Clone)]
pub struct DaemonServices {
    service_id: PrincipalId,
    stores: RuntimeStores,
}

impl DaemonServices {
    pub(crate) fn new(service_id: PrincipalId, stores: RuntimeStores) -> Self {
        Self { service_id, stores }
    }

    /// Returns the daemon service principal id.
    #[must_use]
    pub fn service_id(&self) -> &PrincipalId {
        &self.service_id
    }

    /// Returns cloned handles to the runtime-owned stores. Implementations do
    /// not receive the runtime router, active-action map, callback dispatcher,
    /// or policy engine.
    #[must_use]
    pub fn runtime_stores(&self) -> RuntimeStores {
        self.stores.clone()
    }
}

/// Fully prepared local module admitted atomically before listener startup.
pub struct PreparedDaemonModule {
    /// Descriptor returned by the factory.
    pub descriptor: LocalModuleDescriptor,
    /// Product-local manifest contribution.
    pub manifest: Manifest,
    handlers: BTreeMap<CapabilityId, Arc<dyn ActionHandler>>,
    connectors: Vec<Arc<dyn Connector>>,
    delegation_routers: Vec<Arc<dyn DelegationRouter>>,
    http_mounts: Vec<DaemonHttpMount>,
}

impl fmt::Debug for PreparedDaemonModule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PreparedDaemonModule")
            .field("descriptor", &self.descriptor)
            .field("manifest_capabilities", &self.manifest.capabilities.len())
            .field("handlers", &self.handlers.keys().collect::<Vec<_>>())
            .field("connectors", &self.connectors.len())
            .field("delegation_routers", &self.delegation_routers.len())
            .field("http_mounts", &self.http_mounts)
            .finish()
    }
}

impl PreparedDaemonModule {
    /// Creates an empty prepared module around one manifest contribution.
    #[must_use]
    pub fn new(descriptor: LocalModuleDescriptor, manifest: Manifest) -> Self {
        Self {
            descriptor,
            manifest,
            handlers: BTreeMap::new(),
            connectors: Vec::new(),
            delegation_routers: Vec::new(),
            http_mounts: Vec::new(),
        }
    }

    /// Adds one executable capability handler.
    pub fn with_handler(
        mut self,
        capability: Capability,
        handler: Arc<dyn ActionHandler>,
    ) -> Result<Self, DaemonModuleError> {
        if self.handlers.len() >= MAX_MODULE_HANDLERS {
            return Err(DaemonModuleError::new(
                "aip.server.module.handler_limit",
                format!("module exceeds {MAX_MODULE_HANDLERS} executable handlers"),
            ));
        }
        if capability.kind == aip_core::CapabilityKind::Resource {
            return Err(DaemonModuleError::new(
                "aip.server.module.resource_handler",
                format!(
                    "resource capability `{}` cannot register an action handler",
                    capability.id
                ),
            ));
        }
        if self
            .handlers
            .insert(capability.id.clone(), handler)
            .is_some()
        {
            return Err(DaemonModuleError::new(
                "aip.server.module.duplicate_handler",
                format!("duplicate handler for capability `{}`", capability.id),
            ));
        }
        Ok(self)
    }

    /// Adds a readiness connector shared by the gateway.
    #[must_use]
    pub fn with_connector_arc(mut self, connector: Arc<dyn Connector>) -> Self {
        self.connectors.push(connector);
        self
    }

    /// Adds a connector-owned native delegation router.
    #[must_use]
    pub fn with_delegation_router_arc(mut self, router: Arc<dyn DelegationRouter>) -> Self {
        self.delegation_routers.push(router);
        self
    }

    /// Adds one state-complete HTTP mount.
    #[must_use]
    pub fn with_http_mount(mut self, mount: DaemonHttpMount) -> Self {
        self.http_mounts.push(mount);
        self
    }

    pub(crate) fn handlers(&self) -> &BTreeMap<CapabilityId, Arc<dyn ActionHandler>> {
        &self.handlers
    }

    pub(crate) fn connectors(&self) -> &[Arc<dyn Connector>] {
        &self.connectors
    }

    pub(crate) fn delegation_routers(&self) -> &[Arc<dyn DelegationRouter>] {
        &self.delegation_routers
    }

    pub(crate) fn http_mounts(&self) -> &[DaemonHttpMount] {
        &self.http_mounts
    }
}

/// Asynchronous factory for one trusted local module.
#[async_trait]
pub trait DaemonModuleFactory: Send + Sync {
    /// Returns static admission policy without contacting a provider.
    fn descriptor(&self) -> LocalModuleDescriptor;

    /// Prepares all manifest, handler, readiness, delegation, and HTTP
    /// contributions before any listener is opened.
    async fn prepare(
        &self,
        services: &DaemonServices,
    ) -> Result<PreparedDaemonModule, DaemonModuleError>;
}

/// Bounded, serializable-safe local module preparation error.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DaemonModuleError {
    /// Stable operator-facing error code.
    pub code: &'static str,
    /// Detail that must not contain credentials or provider payloads.
    pub message: String,
}

impl DaemonModuleError {
    /// Creates one bounded error.
    #[must_use]
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        let mut message = message.into();
        message.truncate(1_024);
        Self { code, message }
    }
}

impl fmt::Display for DaemonModuleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.code, self.message)
    }
}

impl Error for DaemonModuleError {}

#[cfg(test)]
mod tests {
    use super::{
        DaemonHttpMount, DaemonHttpRoute, DaemonModuleError, DaemonModuleFactory, DaemonServices,
        LOCAL_MODULE_HTTP_ROUTE_PREFIX, LocalModuleDescriptor, MAX_LOCAL_MODULES,
        PreparedDaemonModule,
    };
    use crate::{
        AipDaemonConfig, BuiltInHealthHandler, health_capability,
        manifest_from_config_with_runtime_storage, prepare_local_modules,
    };
    use aip_core::CapabilityId;
    use aip_runtime::Runtime;
    use async_trait::async_trait;
    use axum::Router;
    use std::{sync::Arc, time::Instant};

    #[derive(Clone)]
    struct TestFactory {
        descriptor: LocalModuleDescriptor,
        capability_id: String,
        route: Option<String>,
        omit_handler: bool,
        failure: Option<DaemonModuleError>,
    }

    impl TestFactory {
        fn required(id: &str, capability_id: &str) -> Self {
            Self {
                descriptor: LocalModuleDescriptor::required(id).expect("descriptor"),
                capability_id: capability_id.to_owned(),
                route: None,
                omit_handler: false,
                failure: None,
            }
        }
    }

    #[async_trait]
    impl DaemonModuleFactory for TestFactory {
        fn descriptor(&self) -> LocalModuleDescriptor {
            self.descriptor.clone()
        }

        async fn prepare(
            &self,
            _services: &DaemonServices,
        ) -> Result<PreparedDaemonModule, DaemonModuleError> {
            if let Some(error) = &self.failure {
                return Err(error.clone());
            }
            let mut capability = health_capability();
            capability.id = CapabilityId::trusted(self.capability_id.clone());
            capability.name = self.capability_id.clone();
            let mut manifest =
                manifest_from_config_with_runtime_storage(&AipDaemonConfig::default(), "memory");
            manifest.capabilities = vec![capability.clone()];
            let mut module = PreparedDaemonModule::new(self.descriptor(), manifest);
            if !self.omit_handler {
                module = module.with_handler(
                    capability,
                    Arc::new(BuiltInHealthHandler {
                        started_at: Instant::now(),
                    }),
                )?;
            }
            if let Some(path) = &self.route {
                module = module.with_http_mount(DaemonHttpMount::new(
                    vec![DaemonHttpRoute::new("POST", path)?],
                    Router::new(),
                )?);
            }
            Ok(module)
        }
    }

    fn base_manifest() -> aip_core::Manifest {
        manifest_from_config_with_runtime_storage(&AipDaemonConfig::default(), "memory")
    }

    #[test]
    fn module_http_routes_are_confined_to_the_connector_namespace() {
        assert_eq!(LOCAL_MODULE_HTTP_ROUTE_PREFIX, "/connectors/");
        assert!(DaemonHttpRoute::new("POST", "/connectors/cal/events").is_ok());
        let error = DaemonHttpRoute::new("POST", "/aip/v1/messages")
            .expect_err("a module must not claim a core route");
        assert_eq!(error.code, "aip.server.module.reserved_http_route");
        assert!(DaemonHttpRoute::new("POST", "/connectors").is_err());
    }

    #[tokio::test]
    async fn duplicate_module_ids_are_rejected_before_preparation() {
        let factories: Vec<Arc<dyn DaemonModuleFactory>> = vec![
            Arc::new(TestFactory::required("duplicate", "cap:test:one")),
            Arc::new(TestFactory::required("duplicate", "cap:test:two")),
        ];
        let error = prepare_local_modules(
            factories,
            &Runtime::new(),
            &aip_core::PrincipalId::trusted("agent:test"),
            &base_manifest(),
        )
        .await
        .expect_err("duplicate ids must fail");
        assert!(error.to_string().contains("duplicate local module id"));
    }

    #[tokio::test]
    async fn capability_and_http_conflicts_are_rejected_atomically() {
        let mut left = TestFactory::required("left", "cap:test:shared");
        left.route = Some("/connectors/shared/events".to_owned());
        let mut right = TestFactory::required("right", "cap:test:shared");
        right.route = Some("/connectors/shared/events".to_owned());
        let error = prepare_local_modules(
            vec![Arc::new(left), Arc::new(right)],
            &Runtime::new(),
            &aip_core::PrincipalId::trusted("agent:test"),
            &base_manifest(),
        )
        .await
        .expect_err("capability conflict must fail");
        assert!(error.to_string().contains("capability"));

        let mut left = TestFactory::required("left-route", "cap:test:left");
        left.route = Some("/connectors/shared/events".to_owned());
        let mut right = TestFactory::required("right-route", "cap:test:right");
        right.route = Some("/connectors/shared/events".to_owned());
        let error = prepare_local_modules(
            vec![Arc::new(left), Arc::new(right)],
            &Runtime::new(),
            &aip_core::PrincipalId::trusted("agent:test"),
            &base_manifest(),
        )
        .await
        .expect_err("route conflict must fail");
        assert!(error.to_string().contains("route"));
    }

    #[tokio::test]
    async fn handler_mismatch_fails_and_optional_failure_is_bounded() {
        let mut missing = TestFactory::required("missing", "cap:test:missing");
        missing.omit_handler = true;
        let error = prepare_local_modules(
            vec![Arc::new(missing)],
            &Runtime::new(),
            &aip_core::PrincipalId::trusted("agent:test"),
            &base_manifest(),
        )
        .await
        .expect_err("missing handler must fail");
        assert!(error.to_string().contains("has no handler"));

        let optional = TestFactory {
            descriptor: LocalModuleDescriptor::optional("optional").expect("descriptor"),
            capability_id: "cap:test:optional".to_owned(),
            route: None,
            omit_handler: false,
            failure: Some(DaemonModuleError::new(
                "aip.server.module.test_failure",
                "x".repeat(2_000),
            )),
        };
        let (prepared, statuses) = prepare_local_modules(
            vec![Arc::new(optional)],
            &Runtime::new(),
            &aip_core::PrincipalId::trusted("agent:test"),
            &base_manifest(),
        )
        .await
        .expect("optional failure must not stop startup");
        assert!(prepared.is_empty());
        let status = statuses.get("optional").expect("optional status");
        assert!(!status.ready);
        assert!(status.detail.len() <= 1_100);
    }

    #[tokio::test]
    async fn module_count_is_bounded_and_preparation_order_is_deterministic() {
        let too_many = (0..=MAX_LOCAL_MODULES)
            .map(|index| {
                Arc::new(TestFactory::required(
                    &format!("module-{index:02}"),
                    &format!("cap:test:{index}"),
                )) as Arc<dyn DaemonModuleFactory>
            })
            .collect();
        assert!(
            prepare_local_modules(
                too_many,
                &Runtime::new(),
                &aip_core::PrincipalId::trusted("agent:test"),
                &base_manifest(),
            )
            .await
            .is_err()
        );

        let (prepared, _) = prepare_local_modules(
            vec![
                Arc::new(TestFactory::required("zeta", "cap:test:zeta")),
                Arc::new(TestFactory::required("alpha", "cap:test:alpha")),
            ],
            &Runtime::new(),
            &aip_core::PrincipalId::trusted("agent:test"),
            &base_manifest(),
        )
        .await
        .expect("modules");
        assert_eq!(prepared[0].descriptor.id.as_str(), "alpha");
        assert_eq!(prepared[1].descriptor.id.as_str(), "zeta");
    }
}
