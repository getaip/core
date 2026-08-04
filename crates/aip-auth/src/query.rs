//! Uniform fail-closed authorization for native operational queries.

use crate::{AuthError, AuthenticatedPrincipal, VerifiedTenant};
use aip_core::PrincipalId;
use std::collections::BTreeSet;
use time::OffsetDateTime;

/// Native object family being queried.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryObject {
    /// Action lifecycle state or output.
    Action,
    /// Session state.
    Session,
    /// Approval state.
    Approval,
    /// Transaction or reconciliation state.
    Transaction,
    /// Receipt chain.
    Receipt,
    /// Audit event or evidence package.
    Audit,
    /// Callback delivery state.
    Callback,
    /// Native resource.
    Resource,
    /// Event stream.
    Event,
}

impl QueryObject {
    /// Returns the stable scope prefix.
    #[must_use]
    pub const fn scope_prefix(self) -> &'static str {
        match self {
            Self::Action => "action",
            Self::Session => "session",
            Self::Approval => "approval",
            Self::Transaction => "transaction",
            Self::Receipt => "receipt",
            Self::Audit => "audit",
            Self::Callback => "callback",
            Self::Resource => "resource",
            Self::Event => "events",
        }
    }
}

/// Operation being performed on a native object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QueryOperation {
    /// Read one or list objects.
    Read,
    /// Mutate lifecycle state, for example closing a session.
    Write,
    /// Export evidence beyond the normal redacted view.
    Export,
}

impl QueryOperation {
    const fn scope_suffix(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::Export => "export",
        }
    }
}

/// Field-level disclosure outcome returned by authorization.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FieldDisclosure {
    /// Fields that must be removed from the response.
    pub redact: BTreeSet<String>,
}

/// One fail-closed query authorization request.
pub struct QueryAuthorizationRequest<'a> {
    /// Transport-authenticated actor.
    pub actor: &'a AuthenticatedPrincipal,
    /// Verified tenant membership, when the object is tenant-scoped.
    pub tenant: Option<&'a VerifiedTenant>,
    /// Object family.
    pub object: QueryObject,
    /// Requested operation.
    pub operation: QueryOperation,
    /// Object owner, if known.
    pub owner: Option<&'a PrincipalId>,
    /// Requested owner selector, if any.
    pub selected_principal: Option<&'a PrincipalId>,
    /// Object/request tenant id, if any.
    pub tenant_id: Option<&'a str>,
    /// Additional scopes required by the concrete query.
    pub additional_scopes: BTreeSet<String>,
    /// Sensitive fields present in the response.
    pub sensitive_fields: BTreeSet<String>,
}

/// Uniform operational-query authorization service.
#[derive(Clone, Debug, Default)]
pub struct QueryAuthorizationService;

impl QueryAuthorizationService {
    /// Authorizes ownership, tenant, scopes, delegated authority, and field
    /// disclosure. Missing information is denied rather than treated as public.
    pub fn authorize(
        &self,
        request: QueryAuthorizationRequest<'_>,
    ) -> Result<FieldDisclosure, AuthError> {
        let prefix = request.object.scope_prefix();
        let operation = request.operation.scope_suffix();
        let own_scope = format!("{prefix}:{operation}");
        let any_scope = format!("{prefix}:{operation}:any");
        let mut required = request.additional_scopes;
        required.insert(own_scope.clone());
        request.actor.validate(&BTreeSet::new())?;

        let owns_object = request
            .owner
            .is_none_or(|owner| owner == &request.actor.principal.id);
        let selects_self = request
            .selected_principal
            .is_none_or(|principal| principal == &request.actor.principal.id);
        let delegated = request
            .selected_principal
            .or(request.owner)
            .is_some_and(|principal| {
                trusted_delegated_scope(request.actor, principal, &own_scope)
                    || trusted_delegated_scope(request.actor, principal, &any_scope)
            });
        if (!owns_object || !selects_self)
            && !request.actor.scopes.contains(&any_scope)
            && !request.actor.scopes.contains("principal:read:any")
            && !request.actor.scopes.contains("*")
            && !delegated
        {
            return Err(AuthError::OwnershipDenied);
        }

        if let Some(tenant_id) = request.tenant_id {
            let tenant = request.tenant.ok_or(AuthError::TenantMembershipRequired)?;
            tenant.validate()?;
            if tenant.tenant.id != tenant_id
                && !request.actor.scopes.contains("tenant:read:any")
                && !request.actor.scopes.contains(&any_scope)
                && !request.actor.scopes.contains("*")
            {
                return Err(AuthError::TenantMismatch {
                    requested: tenant_id.to_owned(),
                    verified: tenant.tenant.id.clone(),
                });
            }
        } else if request.tenant.is_some()
            && !request.actor.scopes.contains("tenant:read:any")
            && !request.actor.scopes.contains(&any_scope)
            && !request.actor.scopes.contains("*")
        {
            return Err(AuthError::TenantSelectorRequired);
        }

        let has_own_scope = request.actor.scopes.contains(&own_scope)
            || request.actor.scopes.contains(&any_scope)
            || request.actor.scopes.contains("*");
        if !has_own_scope && !delegated {
            return Err(AuthError::MissingScope(own_scope));
        }
        for scope in required {
            if scope == own_scope && delegated {
                continue;
            }
            if !(request.actor.scopes.contains(&scope)
                || request.actor.scopes.contains("*")
                || scope == own_scope && request.actor.scopes.contains(&any_scope))
            {
                return Err(AuthError::MissingScope(scope));
            }
        }

        let can_read_sensitive = request
            .actor
            .scopes
            .contains(&format!("{prefix}:sensitive"))
            || request.actor.scopes.contains("data:sensitive:read")
            || request.actor.scopes.contains("*");
        Ok(FieldDisclosure {
            redact: if can_read_sensitive {
                BTreeSet::new()
            } else {
                request.sensitive_fields
            },
        })
    }
}

fn trusted_delegated_scope(
    actor: &AuthenticatedPrincipal,
    principal_id: &PrincipalId,
    required_scope: &str,
) -> bool {
    let now = OffsetDateTime::now_utc();
    actor.principal.delegated_authority.iter().any(|grant| {
        &grant.principal_id == principal_id
            && grant.expires_at.is_none_or(|expires_at| expires_at > now)
            && grant
                .scopes
                .iter()
                .any(|scope| scope == required_scope || scope == "*")
    })
}

#[cfg(test)]
mod tests {
    use super::{
        QueryAuthorizationRequest, QueryAuthorizationService, QueryObject, QueryOperation,
    };
    use crate::{AuthScheme, AuthenticatedPrincipal};
    use aip_core::{Principal, PrincipalId, PrincipalKind};
    use std::collections::BTreeSet;
    use time::OffsetDateTime;

    fn actor(scopes: &[&str]) -> AuthenticatedPrincipal {
        AuthenticatedPrincipal {
            principal: Principal::new(
                PrincipalId::trusted("principal:reader"),
                PrincipalKind::Human,
            ),
            scheme: AuthScheme::Oauth2,
            issuer: "https://issuer.example".to_owned(),
            audience: Some("aip".to_owned()),
            scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
            authenticated_at: OffsetDateTime::now_utc(),
            expires_at: None,
            credential_fingerprint: Some("sha256:test".to_owned()),
        }
    }

    #[test]
    fn missing_scope_is_denied_fail_closed() {
        let error = QueryAuthorizationService
            .authorize(QueryAuthorizationRequest {
                actor: &actor(&[]),
                tenant: None,
                object: QueryObject::Action,
                operation: QueryOperation::Read,
                owner: Some(&PrincipalId::trusted("principal:reader")),
                selected_principal: None,
                tenant_id: None,
                additional_scopes: BTreeSet::new(),
                sensitive_fields: BTreeSet::new(),
            })
            .expect_err("missing scope must fail");
        assert!(error.to_string().contains("action:read"));
    }

    #[test]
    fn sensitive_fields_are_redacted_without_explicit_scope() {
        let disclosure = QueryAuthorizationService
            .authorize(QueryAuthorizationRequest {
                actor: &actor(&["action:read"]),
                tenant: None,
                object: QueryObject::Action,
                operation: QueryOperation::Read,
                owner: Some(&PrincipalId::trusted("principal:reader")),
                selected_principal: None,
                tenant_id: None,
                additional_scopes: BTreeSet::new(),
                sensitive_fields: BTreeSet::from(["input".to_owned(), "output".to_owned()]),
            })
            .expect("authorized");
        assert_eq!(disclosure.redact.len(), 2);
    }
}
