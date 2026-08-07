//! Authentication and authorization primitives for AIP.
//!
//! This crate intentionally provides policy building blocks instead of embedding
//! enterprise policy rules. Gateways and applications compose these primitives
//! with their own tenant, data, and compliance requirements.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::panic, clippy::unwrap_used))]

use aip_core::{
    ApprovalPolicy, Capability, CredentialPolicy, DelegationEntry, Principal, PrincipalKind,
    RiskLevel,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use thiserror::Error;

mod query;
mod trusted;

pub use query::{
    FieldDisclosure, QueryAuthorizationRequest, QueryAuthorizationService, QueryObject,
    QueryOperation,
};
pub use trusted::{
    ApprovalAuthorityResolver, AuthenticatedPrincipal, AuthorityCachePolicy, AuthorityMembership,
    BearerToken, CachedApprovalAuthorityResolver, CachedTrustedIdentityResolver, CredentialHandle,
    CredentialMaterial, CredentialProvider, DelegatedAuthorityScope,
    DenyAllApprovalAuthorityResolver, DenyAllTrustedIdentityResolver, HttpTokenIntrospector,
    IdentityCachePolicy, IdentityResolutionRequest, IntrospectionTokenVerifier, ResolvedIdentity,
    StaticApprovalAuthorityResolver, StaticTrustedIdentityResolver, TokenIntrospection,
    TokenIntrospector, TokenVerificationRequest, TokenVerifier, TrustedIdentityBinding,
    TrustedIdentityResolver, VerifiedTenant, VerifiedToken,
};

/// Authentication scheme supported by AIP profiles.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthScheme {
    /// DID proof.
    DidProof,
    /// Bearer token.
    Bearer,
    /// OAuth2 token.
    Oauth2,
    /// HMAC webhook.
    HmacWebhook,
    /// Mutual TLS identity.
    Mtls,
    /// API key.
    ApiKey,
}

/// Authenticated credential context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Credential {
    /// Auth scheme.
    pub scheme: AuthScheme,
    /// Subject principal id or external subject.
    pub subject: String,
    /// Granted scopes.
    #[serde(default, skip_serializing_if = "BTreeSet::is_empty")]
    pub scopes: BTreeSet<String>,
}

impl Credential {
    /// Checks whether the credential has a scope.
    #[must_use]
    pub fn has_scope(&self, scope: &str) -> bool {
        self.scopes.contains(scope) || self.scopes.contains("*")
    }
}

/// Authorization request.
#[derive(Clone, Debug, PartialEq)]
pub struct AuthorizationRequest<'a> {
    /// Acting principal.
    pub principal: &'a Principal,
    /// Target capability.
    pub capability: &'a Capability,
    /// Delegation chain authorizing this invocation.
    pub delegation_chain: &'a [DelegationEntry],
    /// Credential, if already authenticated.
    pub credential: Option<&'a Credential>,
}

/// Authorization outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationDecision {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Machine-readable reason.
    pub reason: String,
    /// Human approval requirement.
    pub requires_human_approval: bool,
    /// Approval policy that triggered or describes the approval requirement.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approval_policy: Option<ApprovalPolicy>,
}

/// Authorization error.
#[derive(Debug, Error)]
pub enum AuthError {
    /// Authentication information is missing.
    #[error("missing credential")]
    MissingCredential,
    /// Required scope is absent.
    #[error("missing required scope `{0}`")]
    MissingScope(String),
    /// Authentication or identity resolution failed closed.
    #[error("identity resolution failed: {0}")]
    Resolution(String),
    /// A bearer token failed verification.
    #[error("token verification failed: {0}")]
    Token(String),
    /// A credential handle could not be resolved.
    #[error("credential resolution failed: {0}")]
    Credential(String),
    /// Transport authentication has expired.
    #[error("transport authentication has expired")]
    AuthenticationExpired,
    /// A tenant-scoped operation did not include verified membership.
    #[error("verified tenant membership is required")]
    TenantMembershipRequired,
    /// A tenant-bound actor omitted the tenant selector from a scoped query.
    #[error("tenant-scoped query must include a tenant selector")]
    TenantSelectorRequired,
    /// Verified tenant membership has expired or been revoked.
    #[error("verified tenant membership has expired")]
    TenantMembershipExpired,
    /// The selected tenant does not match the verified membership.
    #[error("requested tenant `{requested}` does not match verified tenant `{verified}`")]
    TenantMismatch {
        /// Tenant selected by the protocol request.
        requested: String,
        /// Tenant established by the trusted resolver.
        verified: String,
    },
    /// Object ownership or delegated authority did not authorize the operation.
    #[error("object ownership or delegated authority check failed")]
    OwnershipDenied,
    /// A resolved credential is no longer valid.
    #[error("credential has expired")]
    CredentialExpired,
}

/// Capability-scoped policy primitive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CapabilityPolicy {
    /// Scope required for invocation.
    pub required_scope: Option<String>,
    /// Principal kinds allowed to invoke.
    pub allowed_principal_kinds: BTreeSet<PrincipalKindKey>,
    /// Maximum risk allowed without human approval.
    pub max_auto_approved_risk: RiskLevel,
    /// Maximum accepted delegation hops.
    pub max_delegation_depth: usize,
}

/// Hashable representation of `PrincipalKind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrincipalKindKey {
    /// Human principal.
    Human,
    /// Agent principal.
    Agent,
    /// Service principal.
    Service,
    /// Tenant principal.
    Tenant,
    /// Customer principal.
    Customer,
    /// Contact principal.
    Contact,
    /// System principal.
    System,
}

impl From<PrincipalKind> for PrincipalKindKey {
    fn from(kind: PrincipalKind) -> Self {
        match kind {
            PrincipalKind::Human => Self::Human,
            PrincipalKind::Agent => Self::Agent,
            PrincipalKind::Service => Self::Service,
            PrincipalKind::Tenant => Self::Tenant,
            PrincipalKind::Customer => Self::Customer,
            PrincipalKind::Contact => Self::Contact,
            PrincipalKind::System => Self::System,
        }
    }
}

impl Default for CapabilityPolicy {
    fn default() -> Self {
        Self {
            required_scope: None,
            allowed_principal_kinds: BTreeSet::from([
                PrincipalKindKey::Human,
                PrincipalKindKey::Agent,
                PrincipalKindKey::Service,
                PrincipalKindKey::System,
            ]),
            max_auto_approved_risk: RiskLevel::Medium,
            max_delegation_depth: 10,
        }
    }
}

impl CapabilityPolicy {
    /// Authorizes a capability invocation.
    pub fn authorize(
        &self,
        request: AuthorizationRequest<'_>,
    ) -> Result<AuthorizationDecision, AuthError> {
        if !self
            .allowed_principal_kinds
            .contains(&PrincipalKindKey::from(request.principal.kind))
        {
            return Ok(AuthorizationDecision {
                allowed: false,
                reason: "principal_kind_denied".to_owned(),
                requires_human_approval: false,
                approval_policy: None,
            });
        }

        if request.delegation_chain.len() > self.max_delegation_depth {
            return Ok(AuthorizationDecision {
                allowed: false,
                reason: "delegation_depth_exceeded".to_owned(),
                requires_human_approval: false,
                approval_policy: None,
            });
        }
        if let Some(invalid) = request
            .delegation_chain
            .iter()
            .find(|entry| entry.scope.trim().is_empty())
        {
            return Ok(AuthorizationDecision {
                allowed: false,
                reason: format!(
                    "delegation_empty_scope:{}:{}",
                    invalid.from.id, invalid.to.id
                ),
                requires_human_approval: false,
                approval_policy: None,
            });
        }
        if let Some(last_hop) = request.delegation_chain.last()
            && last_hop.to.id != request.principal.id
        {
            return Ok(AuthorizationDecision {
                allowed: false,
                reason: "delegation_terminal_principal_mismatch".to_owned(),
                requires_human_approval: false,
                approval_policy: None,
            });
        }

        if let Some(required_scope) = &self.required_scope {
            let credential = request.credential.ok_or(AuthError::MissingCredential)?;
            if !credential.has_scope(required_scope) {
                return Err(AuthError::MissingScope(required_scope.clone()));
            }
        }
        if let Some(policy) = request
            .capability
            .contract
            .as_ref()
            .and_then(|contract| contract.credentials.as_ref())
        {
            authorize_credential_policy(policy, request.credential)?;
        }

        let approval_policy = request
            .capability
            .contract
            .as_ref()
            .and_then(|contract| contract.approval.clone());
        let contract_requires_approval = approval_policy
            .as_ref()
            .is_some_and(|policy| policy.required);
        let requires_human_approval = contract_requires_approval
            || request.capability.requires_human_approval.unwrap_or(false)
            || request
                .capability
                .risk
                .is_some_and(|risk| risk_rank(risk) > risk_rank(self.max_auto_approved_risk));

        Ok(AuthorizationDecision {
            allowed: true,
            reason: "allowed".to_owned(),
            requires_human_approval,
            approval_policy,
        })
    }
}

fn authorize_credential_policy(
    policy: &CredentialPolicy,
    credential: Option<&Credential>,
) -> Result<(), AuthError> {
    let Some(credential) = credential else {
        return if policy.required {
            Err(AuthError::MissingCredential)
        } else {
            Ok(())
        };
    };
    for scope in &policy.required_scopes {
        if !credential.has_scope(scope) {
            return Err(AuthError::MissingScope(scope.clone()));
        }
    }
    Ok(())
}

fn risk_rank(risk: RiskLevel) -> u8 {
    match risk {
        RiskLevel::Low => 1,
        RiskLevel::Medium => 2,
        RiskLevel::High => 3,
        RiskLevel::Critical => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AuthError, AuthScheme, AuthorizationRequest, CapabilityPolicy, Credential,
        authorize_credential_policy,
    };
    use aip_core::{
        Capability, CapabilityId, CapabilityKind, CredentialPolicy, DelegationEntry, Principal,
        PrincipalId, PrincipalKind, RiskLevel,
    };
    use serde_json::json;
    use std::collections::BTreeSet;
    use time::OffsetDateTime;

    #[test]
    fn optional_credential_policy_validates_only_supplied_credentials() {
        let policy = CredentialPolicy {
            required: false,
            accepted_issuers: vec!["deployment-connector".to_owned()],
            required_scopes: vec!["records:read".to_owned()],
            allow_oauth_refresh: false,
        };

        authorize_credential_policy(&policy, None).expect("optional credential");

        let wrong_scope = Credential {
            scheme: AuthScheme::Oauth2,
            subject: "service:caller".to_owned(),
            scopes: BTreeSet::from(["records:write".to_owned()]),
        };
        assert!(matches!(
            authorize_credential_policy(&policy, Some(&wrong_scope)),
            Err(AuthError::MissingScope(scope)) if scope == "records:read"
        ));

        let required = CredentialPolicy {
            required: true,
            ..policy
        };
        assert!(matches!(
            authorize_credential_policy(&required, None),
            Err(AuthError::MissingCredential)
        ));
    }

    #[test]
    fn wildcard_credential_scope_matches_capability_scopes_consistently() {
        let policy = CredentialPolicy {
            required: true,
            accepted_issuers: Vec::new(),
            required_scopes: vec!["cal_diy:booking.create".to_owned()],
            allow_oauth_refresh: false,
        };
        let credential = Credential {
            scheme: AuthScheme::Oauth2,
            subject: "service:qualified-connector".to_owned(),
            scopes: BTreeSet::from(["*".to_owned()]),
        };

        authorize_credential_policy(&policy, Some(&credential))
            .expect("wildcard scope must authorize every capability scope");
    }

    #[test]
    fn high_risk_capability_requires_human_approval() {
        let principal = Principal::new(
            PrincipalId::parse("principal:test").expect("principal id"),
            PrincipalKind::Agent,
        );
        let capability = Capability {
            id: CapabilityId::parse("cap:test").expect("cap id"),
            name: "test".to_owned(),
            kind: CapabilityKind::Tool,
            input_schema: json!({"type": "object"}),
            output_schema: None,
            description: None,
            risk: Some(RiskLevel::High),
            stability: None,
            cost: None,
            auth: None,
            bindings: Vec::new(),
            requires_human_approval: None,
            contract: None,
        };
        let decision = CapabilityPolicy::default()
            .authorize(AuthorizationRequest {
                principal: &principal,
                capability: &capability,
                delegation_chain: &[],
                credential: None,
            })
            .expect("policy decision");
        assert!(decision.requires_human_approval);
    }

    #[test]
    fn delegation_chain_must_terminate_at_acting_principal() {
        let requester = Principal::new(
            PrincipalId::parse("agent:requester").expect("requester"),
            PrincipalKind::Agent,
        );
        let delegate = Principal::new(
            PrincipalId::parse("agent:delegate").expect("delegate"),
            PrincipalKind::Agent,
        );
        let impostor = Principal::new(
            PrincipalId::parse("agent:impostor").expect("impostor"),
            PrincipalKind::Agent,
        );
        let capability = Capability {
            id: CapabilityId::parse("cap:test").expect("cap id"),
            name: "test".to_owned(),
            kind: CapabilityKind::Tool,
            input_schema: json!({"type": "object"}),
            output_schema: None,
            description: None,
            risk: Some(RiskLevel::Low),
            stability: None,
            cost: None,
            auth: None,
            bindings: Vec::new(),
            requires_human_approval: None,
            contract: None,
        };
        let chain = vec![DelegationEntry {
            from: requester,
            to: delegate,
            scope: "cap:test".to_owned(),
            delegated_at: OffsetDateTime::now_utc(),
        }];

        let decision = CapabilityPolicy::default()
            .authorize(AuthorizationRequest {
                principal: &impostor,
                capability: &capability,
                delegation_chain: &chain,
                credential: None,
            })
            .expect("policy decision");

        assert!(!decision.allowed);
        assert_eq!(decision.reason, "delegation_terminal_principal_mismatch");
    }
}
