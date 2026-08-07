//! Error taxonomy for pure protocol operations.

use thiserror::Error;

/// Convenient result alias used by core protocol functions.
pub type AipResult<T> = Result<T, AipError>;

/// Errors raised by protocol parsing, validation, and lifecycle checks.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AipError {
    /// The envelope `aip_version` is not supported.
    #[error("unsupported AIP version `{0}`")]
    UnsupportedVersion(String),
    /// The message body does not match the declared message type.
    #[error("message body does not match declared message type `{0}`")]
    MessageTypeMismatch(String),
    /// A required field was absent or empty.
    #[error("missing required field `{0}`")]
    MissingField(&'static str),
    /// A state transition is not allowed by the lifecycle.
    #[error("invalid state transition from `{from}` to `{to}`")]
    InvalidStateTransition {
        /// Previous state.
        from: &'static str,
        /// Requested next state.
        to: &'static str,
    },
    /// A structured validation rule failed.
    #[error("validation failed: {0}")]
    Validation(String),
    /// JSON serialization failed.
    #[error("json error: {0}")]
    Json(String),
}

impl From<serde_json::Error> for AipError {
    fn from(error: serde_json::Error) -> Self {
        Self::Json(error.to_string())
    }
}
