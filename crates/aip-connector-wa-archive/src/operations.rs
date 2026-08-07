//! Version-pinned WA Archive operation catalogue.

use serde::{Deserialize, Serialize};

/// Immutable tracked-worktree digest of the WA Archive provider qualified here.
pub const PROVIDER_REVISION: &str =
    "6d83d9582e16c7e5e36d9b9ac91ac1f38a8267bae54333a0c52abd95ddecee1f";
/// SHA-256 of the provider source defining version-one operation payloads.
pub const OPERATION_CONTRACT_SHA256: &str =
    "197420bb8d5a3126573968aec17a315032a154d2df574369f978cdfaaa04c6f9";
/// Typed provider operation contract version.
pub const OPERATION_CONTRACT_VERSION: u32 = 1;
/// Durable provider change-feed contract version.
pub const CONNECTOR_FEED_VERSION: u32 = 1;
/// Complete AIP-facing provider HTTP contract required by this connector.
pub const PROVIDER_CONNECTOR_CONTRACT: &str = "wa-archive-aip-connector/v1";
/// Canonical provider operation-schema document version.
pub const OPERATION_SCHEMA_DOCUMENT_VERSION: &str = "wa-archive-aip-operation-schemas/v1";
/// SHA-256 of the canonical compact operation-schema document.
pub const OPERATION_SCHEMA_CONTRACT_SHA256: &str =
    "0d1c9b50db21aa87a10873ac7a93e9edd8c1e6e9a25282d18cf582acf6e5030e";

/// Provider safety class applied before an operation enters the outbox.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaArchiveSafetyClass {
    /// A provider query with no remote account mutation.
    ReadOnly,
    /// An ordinary communication or reversible account action.
    Standard,
    /// An account, privacy, membership, publication, or call mutation.
    Sensitive,
    /// A deletion, revoke, leave, block, or report action.
    Destructive,
}

impl WaArchiveSafetyClass {
    /// Stable provider representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read_only",
            Self::Standard => "standard",
            Self::Sensitive => "sensitive",
            Self::Destructive => "destructive",
        }
    }

    /// Whether AIP must supply verified human approval before commit.
    #[must_use]
    pub const fn requires_approval(self) -> bool {
        matches!(self, Self::Sensitive | Self::Destructive)
    }
}

/// One exact version-one provider operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WaArchiveOperation(&'static str);

impl WaArchiveOperation {
    const fn new(suffix: &'static str) -> Self {
        Self(suffix)
    }

    /// Stable AIP capability suffix and provider operation kind.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        self.0
    }

    /// Parses an exact provider operation kind.
    #[must_use]
    pub fn from_suffix(suffix: &str) -> Option<Self> {
        ALL_WA_ARCHIVE_OPERATIONS
            .iter()
            .copied()
            .find(|operation| operation.suffix() == suffix)
    }

    /// Human-readable operation name.
    #[must_use]
    pub fn display_name(self) -> String {
        self.0.replace('_', " ")
    }

    /// Provider safety classification mirrored from the pinned source.
    #[must_use]
    pub fn safety_class(self) -> WaArchiveSafetyClass {
        if READ_ONLY_OPERATIONS.contains(&self.0) {
            WaArchiveSafetyClass::ReadOnly
        } else if DESTRUCTIVE_OPERATIONS.contains(&self.0) {
            WaArchiveSafetyClass::Destructive
        } else if self.0.starts_with("profile_")
            || self.0.starts_with("privacy_")
            || self.0.starts_with("group_")
            || self.0.starts_with("community_")
            || self.0.starts_with("status_")
            || self.0.starts_with("label_")
            || self.0.starts_with("call_")
            || SENSITIVE_NEWSLETTER_OPERATIONS.contains(&self.0)
        {
            WaArchiveSafetyClass::Sensitive
        } else {
            WaArchiveSafetyClass::Standard
        }
    }

    /// Whether the operation accepts managed media.
    #[must_use]
    pub fn accepts_media(self) -> bool {
        matches!(
            self.0,
            "send_message"
                | "send_sticker"
                | "profile_set_picture"
                | "group_set_profile_picture"
                | "status_send_image"
                | "status_send_video"
        )
    }

    /// Whether the provider requires media for every valid invocation.
    #[must_use]
    pub fn requires_media(self) -> bool {
        matches!(
            self.0,
            "send_sticker"
                | "profile_set_picture"
                | "group_set_profile_picture"
                | "status_send_image"
                | "status_send_video"
        )
    }
}

/// Every typed operation implemented by the pinned WA Archive provider.
pub const ALL_WA_ARCHIVE_OPERATIONS: &[WaArchiveOperation] = &[
    WaArchiveOperation::new("send_message"),
    WaArchiveOperation::new("send_reaction"),
    WaArchiveOperation::new("edit_message"),
    WaArchiveOperation::new("edit_message_encrypted"),
    WaArchiveOperation::new("revoke_message"),
    WaArchiveOperation::new("pin_message"),
    WaArchiveOperation::new("unpin_message"),
    WaArchiveOperation::new("keep_message"),
    WaArchiveOperation::new("send_location"),
    WaArchiveOperation::new("send_contacts"),
    WaArchiveOperation::new("send_sticker"),
    WaArchiveOperation::new("create_poll"),
    WaArchiveOperation::new("create_quiz"),
    WaArchiveOperation::new("vote_poll"),
    WaArchiveOperation::new("read_receipt"),
    WaArchiveOperation::new("played_receipt"),
    WaArchiveOperation::new("chat_archive"),
    WaArchiveOperation::new("chat_unarchive"),
    WaArchiveOperation::new("chat_pin"),
    WaArchiveOperation::new("chat_unpin"),
    WaArchiveOperation::new("chat_mute"),
    WaArchiveOperation::new("chat_unmute"),
    WaArchiveOperation::new("message_star"),
    WaArchiveOperation::new("message_unstar"),
    WaArchiveOperation::new("chat_mark_read"),
    WaArchiveOperation::new("chat_delete"),
    WaArchiveOperation::new("chat_clear"),
    WaArchiveOperation::new("chat_status_mute"),
    WaArchiveOperation::new("chat_set_disappearing"),
    WaArchiveOperation::new("chat_save_contact"),
    WaArchiveOperation::new("message_delete_for_me"),
    WaArchiveOperation::new("chat_state"),
    WaArchiveOperation::new("presence_available"),
    WaArchiveOperation::new("presence_unavailable"),
    WaArchiveOperation::new("presence_subscribe"),
    WaArchiveOperation::new("presence_unsubscribe"),
    WaArchiveOperation::new("contact_is_on_whatsapp"),
    WaArchiveOperation::new("contact_profile_picture"),
    WaArchiveOperation::new("contact_profile_picture_with_timeout"),
    WaArchiveOperation::new("contact_user_info"),
    WaArchiveOperation::new("contact_business_profile"),
    WaArchiveOperation::new("profile_set_about"),
    WaArchiveOperation::new("profile_set_push_name"),
    WaArchiveOperation::new("profile_set_picture"),
    WaArchiveOperation::new("profile_remove_picture"),
    WaArchiveOperation::new("privacy_get"),
    WaArchiveOperation::new("privacy_set"),
    WaArchiveOperation::new("privacy_set_disallowed_list"),
    WaArchiveOperation::new("privacy_set_default_disappearing"),
    WaArchiveOperation::new("blocklist_get"),
    WaArchiveOperation::new("blocklist_is_blocked"),
    WaArchiveOperation::new("blocklist_block"),
    WaArchiveOperation::new("blocklist_unblock"),
    WaArchiveOperation::new("group_get_metadata"),
    WaArchiveOperation::new("group_query_info"),
    WaArchiveOperation::new("group_query_info_fresh"),
    WaArchiveOperation::new("group_list_participating"),
    WaArchiveOperation::new("group_batch_get_info"),
    WaArchiveOperation::new("group_get_profile_pictures"),
    WaArchiveOperation::new("group_set_profile_picture"),
    WaArchiveOperation::new("group_remove_profile_picture"),
    WaArchiveOperation::new("group_create"),
    WaArchiveOperation::new("group_set_subject"),
    WaArchiveOperation::new("group_set_description"),
    WaArchiveOperation::new("group_leave"),
    WaArchiveOperation::new("group_add_participants"),
    WaArchiveOperation::new("group_remove_participants"),
    WaArchiveOperation::new("group_remove_participants_linked"),
    WaArchiveOperation::new("group_promote_participants"),
    WaArchiveOperation::new("group_demote_participants"),
    WaArchiveOperation::new("group_get_invite_link"),
    WaArchiveOperation::new("group_set_locked"),
    WaArchiveOperation::new("group_set_announcement"),
    WaArchiveOperation::new("group_set_ephemeral"),
    WaArchiveOperation::new("group_set_membership_approval"),
    WaArchiveOperation::new("group_join_invite"),
    WaArchiveOperation::new("group_get_invite_info"),
    WaArchiveOperation::new("group_join_invite_v4"),
    WaArchiveOperation::new("group_get_membership_requests"),
    WaArchiveOperation::new("group_approve_membership"),
    WaArchiveOperation::new("group_reject_membership"),
    WaArchiveOperation::new("group_cancel_membership"),
    WaArchiveOperation::new("group_revoke_request_code"),
    WaArchiveOperation::new("group_set_member_add_mode"),
    WaArchiveOperation::new("group_set_no_frequently_forwarded"),
    WaArchiveOperation::new("group_set_allow_admin_reports"),
    WaArchiveOperation::new("group_set_history"),
    WaArchiveOperation::new("group_set_member_link_mode"),
    WaArchiveOperation::new("group_set_member_share_history_mode"),
    WaArchiveOperation::new("group_set_limit_sharing"),
    WaArchiveOperation::new("group_acknowledge"),
    WaArchiveOperation::new("group_update_member_label"),
    WaArchiveOperation::new("community_create"),
    WaArchiveOperation::new("community_create_subgroup"),
    WaArchiveOperation::new("community_deactivate"),
    WaArchiveOperation::new("community_remove_participants"),
    WaArchiveOperation::new("community_link_subgroups"),
    WaArchiveOperation::new("community_unlink_subgroups"),
    WaArchiveOperation::new("community_get_subgroups"),
    WaArchiveOperation::new("community_list_participating"),
    WaArchiveOperation::new("community_get_subgroup_participant_counts"),
    WaArchiveOperation::new("community_query_linked_group"),
    WaArchiveOperation::new("community_join_subgroup"),
    WaArchiveOperation::new("community_get_linked_participants"),
    WaArchiveOperation::new("status_send_text"),
    WaArchiveOperation::new("status_send_image"),
    WaArchiveOperation::new("status_send_video"),
    WaArchiveOperation::new("status_revoke"),
    WaArchiveOperation::new("newsletter_list_subscribed"),
    WaArchiveOperation::new("newsletter_get_metadata"),
    WaArchiveOperation::new("newsletter_get_metadata_by_invite"),
    WaArchiveOperation::new("newsletter_create"),
    WaArchiveOperation::new("newsletter_join"),
    WaArchiveOperation::new("newsletter_leave"),
    WaArchiveOperation::new("newsletter_update"),
    WaArchiveOperation::new("newsletter_set_follower_mute"),
    WaArchiveOperation::new("newsletter_set_admin_mute"),
    WaArchiveOperation::new("newsletter_subscribe_live_updates"),
    WaArchiveOperation::new("newsletter_react"),
    WaArchiveOperation::new("newsletter_edit_message"),
    WaArchiveOperation::new("newsletter_revoke_message"),
    WaArchiveOperation::new("newsletter_get_messages"),
    WaArchiveOperation::new("event_create"),
    WaArchiveOperation::new("event_respond"),
    WaArchiveOperation::new("label_upsert"),
    WaArchiveOperation::new("label_delete"),
    WaArchiveOperation::new("label_add_to_chat"),
    WaArchiveOperation::new("label_remove_from_chat"),
    WaArchiveOperation::new("send_comment"),
    WaArchiveOperation::new("call_reject"),
    WaArchiveOperation::new("call_reject_with_creator"),
    WaArchiveOperation::new("call_dial"),
    WaArchiveOperation::new("call_accept"),
    WaArchiveOperation::new("call_terminate"),
    WaArchiveOperation::new("report_spam"),
];

const READ_ONLY_OPERATIONS: &[&str] = &[
    "contact_is_on_whatsapp",
    "contact_profile_picture",
    "contact_profile_picture_with_timeout",
    "contact_user_info",
    "contact_business_profile",
    "privacy_get",
    "blocklist_get",
    "blocklist_is_blocked",
    "group_get_metadata",
    "group_query_info",
    "group_query_info_fresh",
    "group_list_participating",
    "group_batch_get_info",
    "group_get_profile_pictures",
    "group_get_invite_info",
    "group_get_membership_requests",
    "community_get_subgroups",
    "community_list_participating",
    "community_get_subgroup_participant_counts",
    "community_query_linked_group",
    "community_get_linked_participants",
    "newsletter_list_subscribed",
    "newsletter_get_metadata",
    "newsletter_get_metadata_by_invite",
    "newsletter_get_messages",
];

const DESTRUCTIVE_OPERATIONS: &[&str] = &[
    "revoke_message",
    "chat_delete",
    "chat_clear",
    "message_delete_for_me",
    "blocklist_block",
    "blocklist_unblock",
    "group_leave",
    "group_remove_participants",
    "group_remove_participants_linked",
    "group_reject_membership",
    "group_cancel_membership",
    "group_revoke_request_code",
    "community_deactivate",
    "community_remove_participants",
    "community_unlink_subgroups",
    "status_revoke",
    "newsletter_leave",
    "newsletter_revoke_message",
    "label_delete",
    "report_spam",
];

const SENSITIVE_NEWSLETTER_OPERATIONS: &[&str] = &[
    "newsletter_create",
    "newsletter_join",
    "newsletter_update",
    "newsletter_edit_message",
];

/// Read-only archive surface implemented directly by the provider HTTP API.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WaArchiveQueryOperation {
    /// Search or page archived messages.
    MessageList,
    /// List known conversations.
    ChatList,
    /// Search normalized contacts.
    ContactSearch,
    /// Read edit, revoke, and reaction events.
    MessageEventList,
    /// Read non-message protocol events.
    ProtocolEventList,
    /// Export one conversation.
    ConversationExport,
    /// Fetch one archived attachment by its message id.
    MediaGet,
    /// Page transactional outbox state.
    OutboxList,
    /// Resolve one provider operation by its stable idempotency key.
    OutboxGet,
    /// Read the linked-account binding.
    AccountGet,
    /// Read the append-only resolution ledger for one ambiguous operation.
    AmbiguityResolutionList,
}

/// Every read-only archive operation exposed by the connector.
pub const ALL_WA_ARCHIVE_QUERY_OPERATIONS: &[WaArchiveQueryOperation] = &[
    WaArchiveQueryOperation::MessageList,
    WaArchiveQueryOperation::ChatList,
    WaArchiveQueryOperation::ContactSearch,
    WaArchiveQueryOperation::MessageEventList,
    WaArchiveQueryOperation::ProtocolEventList,
    WaArchiveQueryOperation::ConversationExport,
    WaArchiveQueryOperation::MediaGet,
    WaArchiveQueryOperation::OutboxList,
    WaArchiveQueryOperation::OutboxGet,
    WaArchiveQueryOperation::AccountGet,
    WaArchiveQueryOperation::AmbiguityResolutionList,
];

impl WaArchiveQueryOperation {
    /// Stable capability suffix.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::MessageList => "archive.message.list",
            Self::ChatList => "archive.chat.list",
            Self::ContactSearch => "archive.contact.search",
            Self::MessageEventList => "archive.message_event.list",
            Self::ProtocolEventList => "archive.protocol_event.list",
            Self::ConversationExport => "archive.conversation.export",
            Self::MediaGet => "archive.media.get",
            Self::OutboxList => "archive.outbox.list",
            Self::OutboxGet => "archive.outbox.get",
            Self::AccountGet => "archive.account.get",
            Self::AmbiguityResolutionList => "archive.ambiguity_resolution.list",
        }
    }

    /// Human-readable operation name.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::MessageList => "list messages",
            Self::ChatList => "list chats",
            Self::ContactSearch => "search contacts",
            Self::MessageEventList => "list message events",
            Self::ProtocolEventList => "list protocol events",
            Self::ConversationExport => "export conversation",
            Self::MediaGet => "get message media",
            Self::OutboxList => "list outbox operations",
            Self::OutboxGet => "get outbox operation",
            Self::AccountGet => "get linked account",
            Self::AmbiguityResolutionList => "list ambiguity resolutions",
        }
    }

    /// Parses an exact query capability suffix.
    #[must_use]
    pub fn from_suffix(suffix: &str) -> Option<Self> {
        ALL_WA_ARCHIVE_QUERY_OPERATIONS
            .iter()
            .copied()
            .find(|operation| operation.suffix() == suffix)
    }
}

/// Operator-only controls over durable provider uncertainty.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WaArchiveControlOperation {
    /// Resolve one ambiguous operation from independent evidence.
    ResolveAmbiguity,
}

/// Every operator control exposed by the connector.
pub const ALL_WA_ARCHIVE_CONTROL_OPERATIONS: &[WaArchiveControlOperation] =
    &[WaArchiveControlOperation::ResolveAmbiguity];

impl WaArchiveControlOperation {
    /// Stable capability suffix.
    #[must_use]
    pub const fn suffix(self) -> &'static str {
        match self {
            Self::ResolveAmbiguity => "archive.ambiguity.resolve",
        }
    }

    /// Human-readable operation name.
    #[must_use]
    pub const fn display_name(self) -> &'static str {
        match self {
            Self::ResolveAmbiguity => "resolve ambiguous operation",
        }
    }

    /// Parses an exact operator-control capability suffix.
    #[must_use]
    pub fn from_suffix(suffix: &str) -> Option<Self> {
        ALL_WA_ARCHIVE_CONTROL_OPERATIONS
            .iter()
            .copied()
            .find(|operation| operation.suffix() == suffix)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    #[test]
    fn catalog_is_complete_unique_and_safety_partitioned() {
        assert_eq!(ALL_WA_ARCHIVE_OPERATIONS.len(), 135);
        let unique = ALL_WA_ARCHIVE_OPERATIONS
            .iter()
            .map(|operation| operation.suffix())
            .collect::<BTreeSet<_>>();
        assert_eq!(unique.len(), ALL_WA_ARCHIVE_OPERATIONS.len());
        assert_eq!(ALL_WA_ARCHIVE_QUERY_OPERATIONS.len(), 11);
        assert_eq!(ALL_WA_ARCHIVE_CONTROL_OPERATIONS.len(), 1);
        assert_eq!(
            WaArchiveOperation::from_suffix("privacy_get").map(WaArchiveOperation::safety_class),
            Some(WaArchiveSafetyClass::ReadOnly)
        );
        assert_eq!(
            WaArchiveOperation::from_suffix("send_message").map(WaArchiveOperation::safety_class),
            Some(WaArchiveSafetyClass::Standard)
        );
        assert_eq!(
            WaArchiveOperation::from_suffix("profile_set_about")
                .map(WaArchiveOperation::safety_class),
            Some(WaArchiveSafetyClass::Sensitive)
        );
        assert_eq!(
            WaArchiveOperation::from_suffix("report_spam").map(WaArchiveOperation::safety_class),
            Some(WaArchiveSafetyClass::Destructive)
        );
    }
}
