//! Public Rust SDK facade for Agent Interoperability Protocol.
//!
//! The facade re-exports the stable API surface from the workspace crates while
//! preserving feature-gated access to heavier runtime, transport, profile, and
//! connector modules.

#![forbid(unsafe_code)]

pub use aip_core::*;

/// Authentication and authorization primitives.
#[cfg(feature = "auth")]
pub mod auth {
    pub use aip_auth::*;
}

/// Conformance suite.
#[cfg(feature = "conformance")]
pub mod conformance {
    pub use aip_conformance::*;
}

/// Product-neutral connector framework and optional product mappings.
#[cfg(feature = "connector")]
pub mod connector {
    pub use aip_connector::*;

    /// Process-isolated connector host runtime.
    #[cfg(feature = "connector-host")]
    pub mod host {
        pub use aip_connector_host::*;
    }

    /// Connector fleet identifiers, catalog, routing, and admission contracts.
    #[cfg(feature = "connector-registry")]
    pub mod registry {
        pub use aip_connector_registry::*;

        /// PostgreSQL control-plane and data-plane registry backend.
        #[cfg(feature = "connector-registry-postgres")]
        pub mod postgres {
            pub use aip_connector_registry_postgres::*;
        }
    }

    /// Native AIP dispatch and authenticated fleet ingress.
    #[cfg(feature = "connector-remote")]
    pub mod remote {
        pub use aip_connector_remote::*;
    }

    /// Chatwoot connector mappings.
    #[cfg(feature = "connector-chatwoot")]
    pub mod chatwoot {
        pub use aip_connector_chatwoot::*;
    }

    /// Cal.diy scheduling connector mappings.
    #[cfg(feature = "connector-cal-diy")]
    pub mod cal_diy {
        pub use aip_connector_cal_diy::*;
    }

    /// CrewAI connector mappings.
    #[cfg(feature = "connector-crewai")]
    pub mod crewai {
        pub use aip_connector_crewai::*;
    }

    /// Dify connector mappings.
    #[cfg(feature = "connector-dify")]
    pub mod dify {
        pub use aip_connector_dify::*;
    }

    /// Hermes Agent connector mappings.
    #[cfg(feature = "connector-hermes-agent")]
    pub mod hermes_agent {
        pub use aip_connector_hermes_agent::*;
    }

    /// Support sandbox connector mappings.
    #[cfg(feature = "connector-support-sandbox")]
    pub mod support_sandbox {
        pub use aip_connector_support_sandbox::*;
    }
}

/// Cryptographic primitives.
#[cfg(feature = "crypto")]
pub mod crypto {
    pub use aip_crypto::*;
}

/// Discovery services.
#[cfg(feature = "discovery")]
pub mod discovery {
    pub use aip_discovery::*;
}

/// Gateway service.
#[cfg(feature = "gateway")]
pub mod gateway {
    pub use aip_gateway::*;
}

/// MCP compatibility runtime and bridge components.
pub mod mcp {
    /// Outbound MCP client bridge.
    #[cfg(feature = "mcp-client")]
    pub mod client {
        pub use aip_mcp_client::*;
    }

    /// MCP conformance checks.
    #[cfg(feature = "mcp-conformance")]
    pub mod conformance {
        pub use aip_mcp_conformance::*;
    }

    /// AIP-backed MCP server runtime.
    #[cfg(feature = "mcp-server")]
    pub mod server {
        pub use aip_mcp_server::*;
    }
}

/// Observability conventions.
#[cfg(feature = "observability")]
pub mod observability {
    pub use aip_observability::*;
}

/// Compatibility profiles.
pub mod profile {
    /// A2A compatibility profile.
    #[cfg(feature = "profile-a2a")]
    pub mod a2a {
        pub use aip_profile_a2a::*;
    }

    /// MCP compatibility profile.
    #[cfg(feature = "profile-mcp")]
    pub mod mcp {
        pub use aip_profile_mcp::*;
    }

    /// Generic webhook profile.
    #[cfg(feature = "profile-webhook")]
    pub mod webhook {
        pub use aip_profile_webhook::*;
    }
}

/// Runtime services.
#[cfg(feature = "runtime")]
pub mod runtime {
    pub use aip_runtime::*;
}

/// JSON Schema registry.
#[cfg(feature = "schema")]
pub mod schema {
    pub use aip_schema::*;
}

/// Production storage backends.
pub mod storage {
    /// PostgreSQL runtime store.
    #[cfg(feature = "storage-postgres")]
    pub mod postgres {
        pub use aip_storage_postgres::*;
    }
}

/// Testkit helpers.
#[cfg(feature = "testkit")]
pub mod testkit {
    pub use aip_testkit::*;
}

/// Transport bindings.
#[cfg(feature = "transport")]
pub mod transport {
    pub use aip_transport::*;

    /// HTTP binding.
    #[cfg(feature = "transport-http")]
    pub mod http {
        pub use aip_transport_http::*;
    }

    /// MCP stdio binding.
    #[cfg(feature = "transport-mcp-stdio")]
    pub mod mcp_stdio {
        pub use aip_transport_mcp_stdio::*;
    }

    /// MCP Streamable HTTP binding.
    #[cfg(feature = "transport-mcp-streamable-http")]
    pub mod mcp_streamable_http {
        pub use aip_transport_mcp_streamable_http::*;
    }

    /// NATS binding.
    #[cfg(feature = "transport-nats")]
    pub mod nats {
        pub use aip_transport_nats::*;
    }

    /// SSE binding.
    #[cfg(feature = "transport-sse")]
    pub mod sse {
        pub use aip_transport_sse::*;
    }

    /// WebSocket binding.
    #[cfg(feature = "transport-websocket")]
    pub mod websocket {
        pub use aip_transport_websocket::*;
    }
}
