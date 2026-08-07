//! Strongly typed identifiers used by AIP messages.

use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;
use uuid::Uuid;

/// Error returned when an identifier is empty or uses the wrong prefix.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdParseError {
    /// The provided identifier was empty.
    #[error("identifier is empty")]
    Empty,
    /// The provided identifier did not start with the expected prefix.
    #[error("identifier `{actual}` does not start with expected prefix `{expected}`")]
    InvalidPrefix {
        /// Required prefix.
        expected: &'static str,
        /// Provided identifier.
        actual: String,
    },
}

macro_rules! typed_id {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        #[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Creates a new time-sortable identifier.
            #[must_use]
            pub fn new() -> Self {
                Self(format!("{}{}", $prefix, Uuid::now_v7().simple()))
            }

            /// Creates an identifier after validating the required prefix.
            pub fn parse(value: impl Into<String>) -> Result<Self, IdParseError> {
                let value = value.into();
                if value.is_empty() {
                    return Err(IdParseError::Empty);
                }
                if !value.starts_with($prefix) {
                    return Err(IdParseError::InvalidPrefix {
                        expected: $prefix,
                        actual: value,
                    });
                }
                Ok(Self(value))
            }

            /// Borrows the identifier as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the typed id and returns the underlying string.
            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl FromStr for $name {
            type Err = IdParseError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::parse(value)
            }
        }
    };
}

typed_id!(MessageId, "msg_", "Unique AIP message identifier.");
typed_id!(SessionId, "sess_", "Session identifier.");
typed_id!(CorrelationId, "corr_", "Request correlation identifier.");
typed_id!(ActionId, "act_", "Action identifier.");
typed_id!(ApprovalId, "appr_", "Human approval workflow identifier.");
typed_id!(DelegationId, "dlg_", "Delegation graph edge identifier.");
typed_id!(EventId, "evt_", "Event identifier.");
typed_id!(ReceiptId, "rcpt_", "Receipt identifier.");
typed_id!(
    TransactionId,
    "txn_",
    "Transactional action or saga identifier."
);
typed_id!(ConversationId, "conv_", "Conversation identifier.");

/// Stable principal identifier.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrincipalId(String);

impl PrincipalId {
    /// Creates a trusted principal id without runtime validation.
    ///
    /// Use this for compile-time constants and generated identifiers that are
    /// known to be non-empty. External input should use [`Self::parse`].
    #[must_use]
    pub fn trusted(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Creates a principal id from a non-empty string.
    pub fn parse(value: impl Into<String>) -> Result<Self, IdParseError> {
        let value = value.into();
        if value.is_empty() {
            return Err(IdParseError::Empty);
        }
        Ok(Self(value))
    }

    /// Borrows the principal id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for PrincipalId {
    type Err = IdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// Stable capability identifier.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CapabilityId(String);

impl CapabilityId {
    /// Creates a trusted capability id without runtime validation.
    ///
    /// Use this for compile-time constants and generated identifiers that are
    /// known to be non-empty. External input should use [`Self::parse`].
    #[must_use]
    pub fn trusted(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Creates a capability id from a non-empty string.
    pub fn parse(value: impl Into<String>) -> Result<Self, IdParseError> {
        let value = value.into();
        if value.is_empty() {
            return Err(IdParseError::Empty);
        }
        Ok(Self(value))
    }

    /// Borrows the capability id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for CapabilityId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for CapabilityId {
    type Err = IdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

/// AIP profile identifier such as `aip.native.http.v1`.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ProfileId(String);

impl ProfileId {
    /// Creates a profile id from a non-empty string.
    pub fn parse(value: impl Into<String>) -> Result<Self, IdParseError> {
        let value = value.into();
        if value.is_empty() {
            return Err(IdParseError::Empty);
        }
        Ok(Self(value))
    }

    /// Borrows the profile id as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ProfileId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl From<&str> for ProfileId {
    fn from(value: &str) -> Self {
        Self(value.to_owned())
    }
}

impl FromStr for ProfileId {
    type Err = IdParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Self::parse(value)
    }
}

#[cfg(test)]
mod tests {
    use super::{MessageId, SessionId};

    #[test]
    fn generated_ids_use_expected_prefixes() {
        assert!(MessageId::new().as_str().starts_with("msg_"));
        assert!(SessionId::new().as_str().starts_with("sess_"));
    }

    #[test]
    fn parser_rejects_wrong_prefix() {
        assert!(MessageId::parse("sess_123").is_err());
    }
}
