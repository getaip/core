//! Frozen CrewAI operation catalogue verified against one upstream revision.

use aip_core::{CapabilityKind, RiskLevel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// CrewAI upstream revision used to verify method signatures.
pub const UPSTREAM_REVISION: &str = "bfa652a7be8637562cc9b0833f75d927a64552d1";

/// Product operation implemented by the immutable CrewAI sidecar.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CrewOperation {
    /// Execute one crew with native async streaming.
    Run,
    /// Read a durable job record.
    Status,
    /// Replay a durable job event stream from a cursor.
    Events,
    /// Cancel an active durable job.
    Cancel,
    /// Execute the crew for a bounded collection of inputs.
    BatchRun,
    /// Replay execution from one CrewAI task id.
    Replay,
    /// Train a crew into an operator-owned artifact.
    Train,
    /// Evaluate a crew with a selected evaluator model.
    Test,
    /// Query crew knowledge without executing its task graph.
    KnowledgeQuery,
    /// Reset an explicitly selected crew memory domain.
    MemoryReset,
}

/// Every operation supported by the pinned connector and sidecar contract.
pub const ALL_CREW_OPERATIONS: &[CrewOperation] = &[
    CrewOperation::Run,
    CrewOperation::Status,
    CrewOperation::Events,
    CrewOperation::Cancel,
    CrewOperation::BatchRun,
    CrewOperation::Replay,
    CrewOperation::Train,
    CrewOperation::Test,
    CrewOperation::KnowledgeQuery,
    CrewOperation::MemoryReset,
];

impl CrewOperation {
    /// Stable capability suffix. `run` retains the historical base capability.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::Run => "run",
            Self::Status => "status",
            Self::Events => "events",
            Self::Cancel => "cancel",
            Self::BatchRun => "batch_run",
            Self::Replay => "replay",
            Self::Train => "train",
            Self::Test => "test",
            Self::KnowledgeQuery => "knowledge_query",
            Self::MemoryReset => "memory_reset",
        }
    }

    /// Parse one exact, policy-controlled operation name.
    #[must_use]
    pub fn from_suffix(value: &str) -> Option<Self> {
        ALL_CREW_OPERATIONS
            .iter()
            .copied()
            .find(|operation| operation.suffix() == value)
    }

    /// Sidecar HTTP method.
    #[must_use]
    pub const fn method(self) -> &'static str {
        match self {
            Self::Status | Self::Events => "GET",
            _ => "POST",
        }
    }

    /// Fixed sidecar path template.
    #[must_use]
    pub const fn path_template(self) -> &'static str {
        match self {
            Self::Run => "/jobs",
            Self::Status => "/jobs/{run_action_id}",
            Self::Events => "/jobs/{run_action_id}/events",
            Self::Cancel => "/jobs/{run_action_id}/cancel",
            Self::BatchRun
            | Self::Replay
            | Self::Train
            | Self::Test
            | Self::KnowledgeQuery
            | Self::MemoryReset => "/jobs",
        }
    }

    /// Human-readable operation name.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::Run => "run crew",
            Self::Status => "get run status",
            Self::Events => "replay run events",
            Self::Cancel => "cancel run",
            Self::BatchRun => "run bounded input batch",
            Self::Replay => "replay from task",
            Self::Train => "train crew",
            Self::Test => "test crew",
            Self::KnowledgeQuery => "query crew knowledge",
            Self::MemoryReset => "reset crew memory",
        }
    }

    /// AIP capability kind.
    #[must_use]
    pub const fn capability_kind(self) -> CapabilityKind {
        match self {
            Self::Run | Self::BatchRun | Self::Replay => CapabilityKind::Agent,
            Self::Train | Self::Test => CapabilityKind::Workflow,
            _ => CapabilityKind::Tool,
        }
    }

    /// Provider-side risk classification.
    #[must_use]
    pub const fn risk(self) -> RiskLevel {
        match self {
            Self::Status | Self::Events | Self::KnowledgeQuery => RiskLevel::Low,
            Self::Run | Self::BatchRun | Self::Replay | Self::Cancel | Self::Test => {
                RiskLevel::Medium
            }
            Self::Train | Self::MemoryReset => RiskLevel::High,
        }
    }

    /// Whether the operation may change provider or external state.
    #[must_use]
    pub const fn is_mutation(self) -> bool {
        !matches!(self, Self::Status | Self::Events | Self::KnowledgeQuery)
    }

    /// Whether the sidecar must create or mutate a durable job record.
    /// Knowledge queries are read-only at the provider, but still use the
    /// durable job boundary and therefore require replay-safe admission.
    #[must_use]
    pub const fn requires_idempotency(self) -> bool {
        !matches!(self, Self::Status | Self::Events)
    }

    /// Whether the operation can emit a long-running event stream.
    #[must_use]
    pub const fn supports_streaming(self) -> bool {
        matches!(
            self,
            Self::Run | Self::Events | Self::BatchRun | Self::Replay | Self::Train | Self::Test
        )
    }

    /// Whether an in-flight job can be cancelled.
    #[must_use]
    pub const fn supports_cancel(self) -> bool {
        matches!(self, Self::Run | Self::BatchRun)
    }

    /// Backward-compatible least-privilege policy for descriptors that predate
    /// the operation catalogue.
    #[must_use]
    pub fn default_policy() -> BTreeSet<Self> {
        [Self::Run, Self::Status, Self::Events, Self::Cancel]
            .into_iter()
            .collect()
    }
}
