//! Semantic core for Agent Interoperability Protocol (AIP).
//!
//! `aip-core` contains the protocol data model and pure validation logic. It is
//! intentionally free of async runtimes, transport implementations, product
//! connectors, and cryptographic dependencies so the same types can be reused in
//! gateways, SDKs, tests, and constrained environments.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

mod envelope;
mod error;
mod ids;
mod messages;
mod model;
mod validation;

pub use envelope::{AIP_VERSION, Envelope, MessageBody, MessageType};
pub use error::{AipError, AipResult};
pub use ids::{
    ActionId, ApprovalId, CapabilityId, ConversationId, CorrelationId, DelegationId, EventId,
    IdParseError, MessageId, PrincipalId, ProfileId, ReceiptId, SessionId, TransactionId,
};
pub use messages::*;
pub use model::*;
pub use validation::{ValidationIssue, validate_envelope};
