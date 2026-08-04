//! Version-pinned Chatwoot account API operation catalogue.

use aip_core::{CapabilityKind, RiskLevel};
use serde::{Deserialize, Serialize};

/// Chatwoot upstream revision used to verify this operation catalogue.
pub const UPSTREAM_REVISION: &str = "8818d276b954ac4f84cffd8915c99f40e43804ed";

/// HTTP method used by a frozen Chatwoot operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatwootHttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PATCH.
    Patch,
    /// HTTP PUT.
    Put,
    /// HTTP DELETE.
    Delete,
}

macro_rules! chatwoot_operations {
    ($(($variant:ident, $doc:literal, $suffix:literal, $method:ident, $path:literal, $name:literal)),+ $(,)?) => {
        /// Complete frozen Chatwoot account-operation set published by AIP.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum ChatwootOperation {
            $(#[doc = $doc] $variant),+
        }

        /// Every operation in the pinned production catalogue.
        pub const ALL_CHATWOOT_OPERATIONS: &[ChatwootOperation] = &[
            $(ChatwootOperation::$variant),+
        ];

        impl ChatwootOperation {
            /// Stable capability suffix.
            #[must_use]
            pub const fn suffix(self) -> &'static str {
                match self { $(Self::$variant => $suffix),+ }
            }

            /// Upstream HTTP method.
            #[must_use]
            pub const fn method(self) -> ChatwootHttpMethod {
                match self { $(Self::$variant => ChatwootHttpMethod::$method),+ }
            }

            /// Account-scoped upstream path template.
            #[must_use]
            pub const fn path_template(self) -> &'static str {
                match self { $(Self::$variant => $path),+ }
            }

            /// Human-readable operation name.
            #[must_use]
            pub const fn display_name(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }

            /// Parses a stable capability suffix.
            #[must_use]
            pub fn from_suffix(suffix: &str) -> Option<Self> {
                ALL_CHATWOOT_OPERATIONS
                    .iter()
                    .copied()
                    .find(|operation| operation.suffix() == suffix)
            }
        }
    };
}

chatwoot_operations!(
    (
        AccountGet,
        "Read the configured account.",
        "account.get",
        Get,
        "/api/v1/accounts/{account_id}",
        "get account"
    ),
    (
        AccountUpdate,
        "Update the configured account.",
        "account.update",
        Patch,
        "/api/v1/accounts/{account_id}",
        "update account"
    ),
    (
        AgentList,
        "List account agents.",
        "agent.list",
        Get,
        "/api/v1/accounts/{account_id}/agents",
        "list agents"
    ),
    (
        AgentCreate,
        "Create an account agent.",
        "agent.create",
        Post,
        "/api/v1/accounts/{account_id}/agents",
        "create agent"
    ),
    (
        AgentUpdate,
        "Update an account agent.",
        "agent.update",
        Patch,
        "/api/v1/accounts/{account_id}/agents/{agent_id}",
        "update agent"
    ),
    (
        AgentDelete,
        "Delete an account agent.",
        "agent.delete",
        Delete,
        "/api/v1/accounts/{account_id}/agents/{agent_id}",
        "delete agent"
    ),
    (
        AgentBulkCreate,
        "Create account agents in a bounded bulk request.",
        "agent.bulk_create",
        Post,
        "/api/v1/accounts/{account_id}/agents/bulk_create",
        "bulk create agents"
    ),
    (
        AssignableAgentList,
        "List agents assignable in the account.",
        "agent.assignable.list",
        Get,
        "/api/v1/accounts/{account_id}/assignable_agents",
        "list assignable agents"
    ),
    (
        CannedResponseList,
        "List canned responses.",
        "canned_response.list",
        Get,
        "/api/v1/accounts/{account_id}/canned_responses",
        "list canned responses"
    ),
    (
        CannedResponseCreate,
        "Create a canned response.",
        "canned_response.create",
        Post,
        "/api/v1/accounts/{account_id}/canned_responses",
        "create canned response"
    ),
    (
        CannedResponseUpdate,
        "Update a canned response.",
        "canned_response.update",
        Patch,
        "/api/v1/accounts/{account_id}/canned_responses/{canned_response_id}",
        "update canned response"
    ),
    (
        CannedResponseDelete,
        "Delete a canned response.",
        "canned_response.delete",
        Delete,
        "/api/v1/accounts/{account_id}/canned_responses/{canned_response_id}",
        "delete canned response"
    ),
    (
        AutomationRuleList,
        "List automation rules.",
        "automation_rule.list",
        Get,
        "/api/v1/accounts/{account_id}/automation_rules",
        "list automation rules"
    ),
    (
        AutomationRuleGet,
        "Read an automation rule.",
        "automation_rule.get",
        Get,
        "/api/v1/accounts/{account_id}/automation_rules/{automation_rule_id}",
        "get automation rule"
    ),
    (
        AutomationRuleCreate,
        "Create an automation rule.",
        "automation_rule.create",
        Post,
        "/api/v1/accounts/{account_id}/automation_rules",
        "create automation rule"
    ),
    (
        AutomationRuleUpdate,
        "Update an automation rule.",
        "automation_rule.update",
        Patch,
        "/api/v1/accounts/{account_id}/automation_rules/{automation_rule_id}",
        "update automation rule"
    ),
    (
        AutomationRuleDelete,
        "Delete an automation rule.",
        "automation_rule.delete",
        Delete,
        "/api/v1/accounts/{account_id}/automation_rules/{automation_rule_id}",
        "delete automation rule"
    ),
    (
        AutomationRuleClone,
        "Clone an automation rule.",
        "automation_rule.clone",
        Post,
        "/api/v1/accounts/{account_id}/automation_rules/{automation_rule_id}/clone",
        "clone automation rule"
    ),
    (
        MacroList,
        "List macros.",
        "macro.list",
        Get,
        "/api/v1/accounts/{account_id}/macros",
        "list macros"
    ),
    (
        MacroGet,
        "Read a macro.",
        "macro.get",
        Get,
        "/api/v1/accounts/{account_id}/macros/{macro_id}",
        "get macro"
    ),
    (
        MacroCreate,
        "Create a macro.",
        "macro.create",
        Post,
        "/api/v1/accounts/{account_id}/macros",
        "create macro"
    ),
    (
        MacroUpdate,
        "Update a macro.",
        "macro.update",
        Patch,
        "/api/v1/accounts/{account_id}/macros/{macro_id}",
        "update macro"
    ),
    (
        MacroDelete,
        "Delete a macro.",
        "macro.delete",
        Delete,
        "/api/v1/accounts/{account_id}/macros/{macro_id}",
        "delete macro"
    ),
    (
        MacroExecute,
        "Execute a macro against its declared target.",
        "macro.execute",
        Post,
        "/api/v1/accounts/{account_id}/macros/{macro_id}/execute",
        "execute macro"
    ),
    (
        ConversationList,
        "List conversations.",
        "conversation.list",
        Get,
        "/api/v1/accounts/{account_id}/conversations",
        "list conversations"
    ),
    (
        ConversationCreate,
        "Create a conversation.",
        "conversation.create",
        Post,
        "/api/v1/accounts/{account_id}/conversations",
        "create conversation"
    ),
    (
        ConversationGet,
        "Read a conversation.",
        "conversation.get",
        Get,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}",
        "get conversation"
    ),
    (
        ConversationUpdate,
        "Update a conversation.",
        "conversation.update",
        Patch,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}",
        "update conversation"
    ),
    (
        ConversationDelete,
        "Delete a conversation.",
        "conversation.delete",
        Delete,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}",
        "delete conversation"
    ),
    (
        ConversationMeta,
        "Read conversation counters and metadata.",
        "conversation.meta",
        Get,
        "/api/v1/accounts/{account_id}/conversations/meta",
        "get conversation metadata"
    ),
    (
        ConversationSearch,
        "Search conversations.",
        "conversation.search",
        Get,
        "/api/v1/accounts/{account_id}/conversations/search",
        "search conversations"
    ),
    (
        ConversationUnreadCounts,
        "Read conversation unread counts.",
        "conversation.unread_counts",
        Get,
        "/api/v1/accounts/{account_id}/conversations/unread_counts",
        "get unread counts"
    ),
    (
        ConversationFilter,
        "Filter conversations.",
        "conversation.filter",
        Post,
        "/api/v1/accounts/{account_id}/conversations/filter",
        "filter conversations"
    ),
    (
        ConversationMute,
        "Mute a conversation.",
        "conversation.mute",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/mute",
        "mute conversation"
    ),
    (
        ConversationUnmute,
        "Unmute a conversation.",
        "conversation.unmute",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/unmute",
        "unmute conversation"
    ),
    (
        ConversationTranscript,
        "Request a conversation transcript.",
        "conversation.transcript",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/transcript",
        "request transcript"
    ),
    (
        ConversationPriority,
        "Update conversation priority.",
        "conversation.priority",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/toggle_priority",
        "update conversation priority"
    ),
    (
        ConversationUnread,
        "Mark a conversation unread.",
        "conversation.unread",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/unread",
        "mark conversation unread"
    ),
    (
        ConversationCustomAttributes,
        "Update conversation custom attributes.",
        "conversation.custom_attributes",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/custom_attributes",
        "update conversation custom attributes"
    ),
    (
        ConversationAttachments,
        "List conversation attachments.",
        "conversation.attachment.list",
        Get,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/attachments",
        "list conversation attachments"
    ),
    (
        MessageList,
        "List conversation messages.",
        "message.list",
        Get,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/messages",
        "list messages"
    ),
    (
        MessageUpdate,
        "Update a conversation message.",
        "message.update",
        Patch,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/messages/{message_id}",
        "update message"
    ),
    (
        MessageDelete,
        "Delete a conversation message.",
        "message.delete",
        Delete,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/messages/{message_id}",
        "delete message"
    ),
    (
        MessageTranslate,
        "Translate a conversation message.",
        "message.translate",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/messages/{message_id}/translate",
        "translate message"
    ),
    (
        MessageRetry,
        "Retry a failed outgoing message.",
        "message.retry",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/messages/{message_id}/retry",
        "retry message"
    ),
    (
        ConversationAssignment,
        "Assign a conversation to an agent or team.",
        "conversation.assignment",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/assignments",
        "assign conversation"
    ),
    (
        ConversationLabelList,
        "List labels applied to a conversation.",
        "conversation.label.list",
        Get,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/labels",
        "list conversation labels"
    ),
    (
        ConversationLabelUpdate,
        "Replace labels applied to a conversation.",
        "conversation.label.update",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/labels",
        "update conversation labels"
    ),
    (
        ContactList,
        "List contacts.",
        "contact.list",
        Get,
        "/api/v1/accounts/{account_id}/contacts",
        "list contacts"
    ),
    (
        ContactCreate,
        "Create a contact.",
        "contact.create",
        Post,
        "/api/v1/accounts/{account_id}/contacts",
        "create contact"
    ),
    (
        ContactGet,
        "Read a contact.",
        "contact.get",
        Get,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}",
        "get contact"
    ),
    (
        ContactUpdate,
        "Update a contact.",
        "contact.update",
        Patch,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}",
        "update contact"
    ),
    (
        ContactDelete,
        "Delete a contact.",
        "contact.delete",
        Delete,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}",
        "delete contact"
    ),
    (
        ContactActive,
        "List active contacts.",
        "contact.active",
        Get,
        "/api/v1/accounts/{account_id}/contacts/active",
        "list active contacts"
    ),
    (
        ContactSearch,
        "Search contacts.",
        "contact.search",
        Get,
        "/api/v1/accounts/{account_id}/contacts/search",
        "search contacts"
    ),
    (
        ContactFilter,
        "Filter contacts.",
        "contact.filter",
        Post,
        "/api/v1/accounts/{account_id}/contacts/filter",
        "filter contacts"
    ),
    (
        ContactImport,
        "Import contacts.",
        "contact.import",
        Post,
        "/api/v1/accounts/{account_id}/contacts/import",
        "import contacts"
    ),
    (
        ContactExport,
        "Export contacts.",
        "contact.export",
        Post,
        "/api/v1/accounts/{account_id}/contacts/export",
        "export contacts"
    ),
    (
        ContactConversations,
        "List a contact's conversations.",
        "contact.conversation.list",
        Get,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}/conversations",
        "list contact conversations"
    ),
    (
        ContactInboxCreate,
        "Associate a contact with an inbox.",
        "contact.inbox.create",
        Post,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}/contact_inboxes",
        "associate contact inbox"
    ),
    (
        ContactLabelList,
        "List labels applied to a contact.",
        "contact.label.list",
        Get,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}/labels",
        "list contact labels"
    ),
    (
        ContactLabelUpdate,
        "Replace labels applied to a contact.",
        "contact.label.update",
        Post,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}/labels",
        "update contact labels"
    ),
    (
        ContactNoteList,
        "List contact notes.",
        "contact.note.list",
        Get,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}/notes",
        "list contact notes"
    ),
    (
        ContactNoteCreate,
        "Create a contact note.",
        "contact.note.create",
        Post,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}/notes",
        "create contact note"
    ),
    (
        ContactNoteGet,
        "Read a contact note.",
        "contact.note.get",
        Get,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}/notes/{note_id}",
        "get contact note"
    ),
    (
        ContactNoteUpdate,
        "Update a contact note.",
        "contact.note.update",
        Patch,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}/notes/{note_id}",
        "update contact note"
    ),
    (
        ContactNoteDelete,
        "Delete a contact note.",
        "contact.note.delete",
        Delete,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}/notes/{note_id}",
        "delete contact note"
    ),
    (
        CompanyList,
        "List companies.",
        "company.list",
        Get,
        "/api/v1/accounts/{account_id}/companies",
        "list companies"
    ),
    (
        CompanyCreate,
        "Create a company.",
        "company.create",
        Post,
        "/api/v1/accounts/{account_id}/companies",
        "create company"
    ),
    (
        CompanyGet,
        "Read a company.",
        "company.get",
        Get,
        "/api/v1/accounts/{account_id}/companies/{company_id}",
        "get company"
    ),
    (
        CompanyUpdate,
        "Update a company.",
        "company.update",
        Patch,
        "/api/v1/accounts/{account_id}/companies/{company_id}",
        "update company"
    ),
    (
        CompanyDelete,
        "Delete a company.",
        "company.delete",
        Delete,
        "/api/v1/accounts/{account_id}/companies/{company_id}",
        "delete company"
    ),
    (
        CompanySearch,
        "Search companies.",
        "company.search",
        Get,
        "/api/v1/accounts/{account_id}/companies/search",
        "search companies"
    ),
    (
        CompanyContactList,
        "List company contacts.",
        "company.contact.list",
        Get,
        "/api/v1/accounts/{account_id}/companies/{company_id}/contacts",
        "list company contacts"
    ),
    (
        CompanyContactCreate,
        "Attach a contact to a company.",
        "company.contact.create",
        Post,
        "/api/v1/accounts/{account_id}/companies/{company_id}/contacts",
        "attach company contact"
    ),
    (
        CompanyContactDelete,
        "Detach a contact from a company.",
        "company.contact.delete",
        Delete,
        "/api/v1/accounts/{account_id}/companies/{company_id}/contacts/{contact_id}",
        "detach company contact"
    ),
    (
        CompanyConversationList,
        "List company conversations.",
        "company.conversation.list",
        Get,
        "/api/v1/accounts/{account_id}/companies/{company_id}/conversations",
        "list company conversations"
    ),
    (
        InboxList,
        "List inboxes.",
        "inbox.list",
        Get,
        "/api/v1/accounts/{account_id}/inboxes",
        "list inboxes"
    ),
    (
        InboxCreate,
        "Create an inbox.",
        "inbox.create",
        Post,
        "/api/v1/accounts/{account_id}/inboxes",
        "create inbox"
    ),
    (
        InboxGet,
        "Read an inbox.",
        "inbox.get",
        Get,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}",
        "get inbox"
    ),
    (
        InboxUpdate,
        "Update an inbox.",
        "inbox.update",
        Patch,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}",
        "update inbox"
    ),
    (
        InboxDelete,
        "Delete an inbox.",
        "inbox.delete",
        Delete,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}",
        "delete inbox"
    ),
    (
        InboxAssignableAgents,
        "List agents assignable to an inbox.",
        "inbox.agent.list",
        Get,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/assignable_agents",
        "list inbox agents"
    ),
    (
        InboxHealth,
        "Read inbox health.",
        "inbox.health",
        Get,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/health",
        "get inbox health"
    ),
    (
        InboxSyncTemplates,
        "Synchronize inbox templates.",
        "inbox.template.sync",
        Post,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/sync_templates",
        "synchronize inbox templates"
    ),
    (
        InboxRegisterWebhook,
        "Register the provider webhook for an inbox.",
        "inbox.webhook.register",
        Post,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/register_webhook",
        "register inbox webhook"
    ),
    (
        InboxMemberGet,
        "Read inbox members.",
        "inbox.member.list",
        Get,
        "/api/v1/accounts/{account_id}/inbox_members/{inbox_id}",
        "list inbox members"
    ),
    (
        InboxMemberCreate,
        "Add inbox members.",
        "inbox.member.create",
        Post,
        "/api/v1/accounts/{account_id}/inbox_members",
        "add inbox members"
    ),
    (
        InboxMemberUpdate,
        "Replace inbox members.",
        "inbox.member.update",
        Patch,
        "/api/v1/accounts/{account_id}/inbox_members",
        "update inbox members"
    ),
    (
        InboxMemberDelete,
        "Remove inbox members.",
        "inbox.member.delete",
        Delete,
        "/api/v1/accounts/{account_id}/inbox_members",
        "remove inbox members"
    ),
    (
        LabelList,
        "List account labels.",
        "label.list",
        Get,
        "/api/v1/accounts/{account_id}/labels",
        "list labels"
    ),
    (
        LabelCreate,
        "Create an account label.",
        "label.create",
        Post,
        "/api/v1/accounts/{account_id}/labels",
        "create label"
    ),
    (
        LabelGet,
        "Read an account label.",
        "label.get",
        Get,
        "/api/v1/accounts/{account_id}/labels/{label_id}",
        "get label"
    ),
    (
        LabelUpdate,
        "Update an account label.",
        "label.update",
        Patch,
        "/api/v1/accounts/{account_id}/labels/{label_id}",
        "update label"
    ),
    (
        LabelDelete,
        "Delete an account label.",
        "label.delete",
        Delete,
        "/api/v1/accounts/{account_id}/labels/{label_id}",
        "delete label"
    ),
    (
        TeamList,
        "List teams.",
        "team.list",
        Get,
        "/api/v1/accounts/{account_id}/teams",
        "list teams"
    ),
    (
        TeamCreate,
        "Create a team.",
        "team.create",
        Post,
        "/api/v1/accounts/{account_id}/teams",
        "create team"
    ),
    (
        TeamGet,
        "Read a team.",
        "team.get",
        Get,
        "/api/v1/accounts/{account_id}/teams/{team_id}",
        "get team"
    ),
    (
        TeamUpdate,
        "Update a team.",
        "team.update",
        Patch,
        "/api/v1/accounts/{account_id}/teams/{team_id}",
        "update team"
    ),
    (
        TeamDelete,
        "Delete a team.",
        "team.delete",
        Delete,
        "/api/v1/accounts/{account_id}/teams/{team_id}",
        "delete team"
    ),
    (
        TeamMemberList,
        "List team members.",
        "team.member.list",
        Get,
        "/api/v1/accounts/{account_id}/teams/{team_id}/team_members",
        "list team members"
    ),
    (
        TeamMemberCreate,
        "Add team members.",
        "team.member.create",
        Post,
        "/api/v1/accounts/{account_id}/teams/{team_id}/team_members",
        "add team members"
    ),
    (
        TeamMemberUpdate,
        "Replace team members.",
        "team.member.update",
        Patch,
        "/api/v1/accounts/{account_id}/teams/{team_id}/team_members",
        "update team members"
    ),
    (
        TeamMemberDelete,
        "Remove team members.",
        "team.member.delete",
        Delete,
        "/api/v1/accounts/{account_id}/teams/{team_id}/team_members",
        "remove team members"
    ),
    (
        AgentBotList,
        "List account agent bots.",
        "agent_bot.list",
        Get,
        "/api/v1/accounts/{account_id}/agent_bots",
        "list agent bots"
    ),
    (
        AgentBotCreate,
        "Create an account agent bot.",
        "agent_bot.create",
        Post,
        "/api/v1/accounts/{account_id}/agent_bots",
        "create agent bot"
    ),
    (
        AgentBotGet,
        "Read an account agent bot.",
        "agent_bot.get",
        Get,
        "/api/v1/accounts/{account_id}/agent_bots/{agent_bot_id}",
        "get agent bot"
    ),
    (
        AgentBotUpdate,
        "Update an account agent bot.",
        "agent_bot.update",
        Patch,
        "/api/v1/accounts/{account_id}/agent_bots/{agent_bot_id}",
        "update agent bot"
    ),
    (
        AgentBotDelete,
        "Delete an account agent bot.",
        "agent_bot.delete",
        Delete,
        "/api/v1/accounts/{account_id}/agent_bots/{agent_bot_id}",
        "delete agent bot"
    ),
    (
        AuditLogList,
        "List account audit log entries.",
        "audit_log.list",
        Get,
        "/api/v1/accounts/{account_id}/audit_logs",
        "list audit logs"
    ),
    (
        CustomAttributeList,
        "List custom attribute definitions.",
        "custom_attribute.list",
        Get,
        "/api/v1/accounts/{account_id}/custom_attribute_definitions",
        "list custom attributes"
    ),
    (
        CustomAttributeCreate,
        "Create a custom attribute definition.",
        "custom_attribute.create",
        Post,
        "/api/v1/accounts/{account_id}/custom_attribute_definitions",
        "create custom attribute"
    ),
    (
        CustomAttributeGet,
        "Read a custom attribute definition.",
        "custom_attribute.get",
        Get,
        "/api/v1/accounts/{account_id}/custom_attribute_definitions/{custom_attribute_id}",
        "get custom attribute"
    ),
    (
        CustomAttributeUpdate,
        "Update a custom attribute definition.",
        "custom_attribute.update",
        Patch,
        "/api/v1/accounts/{account_id}/custom_attribute_definitions/{custom_attribute_id}",
        "update custom attribute"
    ),
    (
        CustomAttributeDelete,
        "Delete a custom attribute definition.",
        "custom_attribute.delete",
        Delete,
        "/api/v1/accounts/{account_id}/custom_attribute_definitions/{custom_attribute_id}",
        "delete custom attribute"
    ),
    (
        CustomFilterList,
        "List saved custom filters.",
        "custom_filter.list",
        Get,
        "/api/v1/accounts/{account_id}/custom_filters",
        "list custom filters"
    ),
    (
        CustomFilterCreate,
        "Create a saved custom filter.",
        "custom_filter.create",
        Post,
        "/api/v1/accounts/{account_id}/custom_filters",
        "create custom filter"
    ),
    (
        CustomFilterGet,
        "Read a saved custom filter.",
        "custom_filter.get",
        Get,
        "/api/v1/accounts/{account_id}/custom_filters/{custom_filter_id}",
        "get custom filter"
    ),
    (
        CustomFilterUpdate,
        "Update a saved custom filter.",
        "custom_filter.update",
        Patch,
        "/api/v1/accounts/{account_id}/custom_filters/{custom_filter_id}",
        "update custom filter"
    ),
    (
        CustomFilterDelete,
        "Delete a saved custom filter.",
        "custom_filter.delete",
        Delete,
        "/api/v1/accounts/{account_id}/custom_filters/{custom_filter_id}",
        "delete custom filter"
    ),
    (
        ContactMerge,
        "Merge one contact into another contact.",
        "contact.merge",
        Post,
        "/api/v1/accounts/{account_id}/actions/contact_merge",
        "merge contacts"
    ),
    (
        ContactableInboxList,
        "List inboxes to which a contact can be attached.",
        "contact.contactable_inbox.list",
        Get,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}/contactable_inboxes",
        "list contactable inboxes"
    ),
    (
        ConversationToggleStatus,
        "Toggle a conversation status through the canonical account API.",
        "conversation.toggle_status",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/toggle_status",
        "toggle conversation status"
    ),
    (
        ConversationToggleTyping,
        "Publish a conversation typing-state transition.",
        "conversation.toggle_typing",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/toggle_typing_status",
        "toggle conversation typing"
    ),
    (
        ConversationReportingEvents,
        "List enterprise reporting events for a conversation.",
        "conversation.reporting_event.list",
        Get,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/reporting_events",
        "list conversation reporting events"
    ),
    (
        MessageCreate,
        "Create a conversation message, including optional attachments.",
        "message.create",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/messages",
        "create message"
    ),
    (
        IntegrationAppList,
        "List account integration applications.",
        "integration.app.list",
        Get,
        "/api/v1/accounts/{account_id}/integrations/apps",
        "list integration apps"
    ),
    (
        IntegrationHookCreate,
        "Create an integration hook.",
        "integration.hook.create",
        Post,
        "/api/v1/accounts/{account_id}/integrations/hooks",
        "create integration hook"
    ),
    (
        IntegrationHookUpdate,
        "Update an integration hook.",
        "integration.hook.update",
        Patch,
        "/api/v1/accounts/{account_id}/integrations/hooks/{hook_id}",
        "update integration hook"
    ),
    (
        IntegrationHookDelete,
        "Delete an integration hook.",
        "integration.hook.delete",
        Delete,
        "/api/v1/accounts/{account_id}/integrations/hooks/{hook_id}",
        "delete integration hook"
    ),
    (
        PortalList,
        "List account help-center portals.",
        "portal.list",
        Get,
        "/api/v1/accounts/{account_id}/portals",
        "list portals"
    ),
    (
        PortalCreate,
        "Create a help-center portal.",
        "portal.create",
        Post,
        "/api/v1/accounts/{account_id}/portals",
        "create portal"
    ),
    (
        PortalUpdate,
        "Update a help-center portal.",
        "portal.update",
        Patch,
        "/api/v1/accounts/{account_id}/portals/{portal_id}",
        "update portal"
    ),
    (
        PortalCategoryCreate,
        "Create a help-center category.",
        "portal.category.create",
        Post,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/categories",
        "create portal category"
    ),
    (
        PortalArticleCreate,
        "Create a help-center article.",
        "portal.article.create",
        Post,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/articles",
        "create portal article"
    ),
    (
        AccountReportingEventList,
        "List account reporting events.",
        "reporting_event.list",
        Get,
        "/api/v1/accounts/{account_id}/reporting_events",
        "list reporting events"
    ),
    (
        ReportList,
        "Read the version-two account report series.",
        "report.list",
        Get,
        "/api/v2/accounts/{account_id}/reports",
        "list reports"
    ),
    (
        ReportSummary,
        "Read a version-two report summary.",
        "report.summary",
        Get,
        "/api/v2/accounts/{account_id}/reports/summary",
        "get report summary"
    ),
    (
        ReportConversations,
        "Read version-two conversation metrics.",
        "report.conversation",
        Get,
        "/api/v2/accounts/{account_id}/reports/conversations",
        "get conversation report"
    ),
    (
        ReportFirstResponseDistribution,
        "Read first-response-time distribution metrics.",
        "report.first_response_distribution",
        Get,
        "/api/v2/accounts/{account_id}/reports/first_response_time_distribution",
        "get first response distribution"
    ),
    (
        ReportInboxLabelMatrix,
        "Read the inbox and label metric matrix.",
        "report.inbox_label_matrix",
        Get,
        "/api/v2/accounts/{account_id}/reports/inbox_label_matrix",
        "get inbox label matrix"
    ),
    (
        ReportOutgoingMessageCount,
        "Read outgoing message counts.",
        "report.outgoing_message_count",
        Get,
        "/api/v2/accounts/{account_id}/reports/outgoing_messages_count",
        "get outgoing message count"
    ),
    (
        ReportAgentSummary,
        "Read agent summary metrics.",
        "report.agent_summary",
        Get,
        "/api/v2/accounts/{account_id}/summary_reports/agent",
        "get agent summary"
    ),
    (
        ReportTeamSummary,
        "Read team summary metrics.",
        "report.team_summary",
        Get,
        "/api/v2/accounts/{account_id}/summary_reports/team",
        "get team summary"
    ),
    (
        ReportInboxSummary,
        "Read inbox summary metrics.",
        "report.inbox_summary",
        Get,
        "/api/v2/accounts/{account_id}/summary_reports/inbox",
        "get inbox summary"
    ),
    (
        ReportChannelSummary,
        "Read channel summary metrics.",
        "report.channel_summary",
        Get,
        "/api/v2/accounts/{account_id}/summary_reports/channel",
        "get channel summary"
    ),
    (
        AccountBulkActionCreate,
        "Execute one bounded account bulk action.",
        "account.bulk_action.create",
        Post,
        "/api/v1/accounts/{account_id}/bulk_actions",
        "execute account bulk action"
    ),
    (
        AccountOnboardingUpdate,
        "Update account onboarding state.",
        "account.onboarding.update",
        Patch,
        "/api/v1/accounts/{account_id}/onboarding",
        "update account onboarding"
    ),
    (
        AccountOnboardingHelpCenterGeneration,
        "Read help-center generation state for onboarding.",
        "account.onboarding.help_center_generation",
        Get,
        "/api/v1/accounts/{account_id}/onboarding/help_center_generation",
        "get onboarding help-center generation"
    ),
    (
        SlaPolicyList,
        "List SLA policies.",
        "sla_policy.list",
        Get,
        "/api/v1/accounts/{account_id}/sla_policies",
        "list SLA policies"
    ),
    (
        SlaPolicyGet,
        "Read an SLA policy.",
        "sla_policy.get",
        Get,
        "/api/v1/accounts/{account_id}/sla_policies/{sla_policy_id}",
        "get SLA policy"
    ),
    (
        SlaPolicyCreate,
        "Create an SLA policy.",
        "sla_policy.create",
        Post,
        "/api/v1/accounts/{account_id}/sla_policies",
        "create SLA policy"
    ),
    (
        SlaPolicyUpdate,
        "Update an SLA policy.",
        "sla_policy.update",
        Patch,
        "/api/v1/accounts/{account_id}/sla_policies/{sla_policy_id}",
        "update SLA policy"
    ),
    (
        SlaPolicyDelete,
        "Delete an SLA policy.",
        "sla_policy.delete",
        Delete,
        "/api/v1/accounts/{account_id}/sla_policies/{sla_policy_id}",
        "delete SLA policy"
    ),
    (
        CustomRoleList,
        "List custom roles.",
        "custom_role.list",
        Get,
        "/api/v1/accounts/{account_id}/custom_roles",
        "list custom roles"
    ),
    (
        CustomRoleGet,
        "Read a custom role.",
        "custom_role.get",
        Get,
        "/api/v1/accounts/{account_id}/custom_roles/{custom_role_id}",
        "get custom role"
    ),
    (
        CustomRoleCreate,
        "Create a custom role.",
        "custom_role.create",
        Post,
        "/api/v1/accounts/{account_id}/custom_roles",
        "create custom role"
    ),
    (
        CustomRoleUpdate,
        "Update a custom role.",
        "custom_role.update",
        Patch,
        "/api/v1/accounts/{account_id}/custom_roles/{custom_role_id}",
        "update custom role"
    ),
    (
        CustomRoleDelete,
        "Delete a custom role.",
        "custom_role.delete",
        Delete,
        "/api/v1/accounts/{account_id}/custom_roles/{custom_role_id}",
        "delete custom role"
    ),
    (
        AgentCapacityPolicyList,
        "List agent capacity policies.",
        "agent_capacity_policy.list",
        Get,
        "/api/v1/accounts/{account_id}/agent_capacity_policies",
        "list agent capacity policies"
    ),
    (
        AgentCapacityPolicyGet,
        "Read an agent capacity policy.",
        "agent_capacity_policy.get",
        Get,
        "/api/v1/accounts/{account_id}/agent_capacity_policies/{agent_capacity_policy_id}",
        "get agent capacity policy"
    ),
    (
        AgentCapacityPolicyCreate,
        "Create an agent capacity policy.",
        "agent_capacity_policy.create",
        Post,
        "/api/v1/accounts/{account_id}/agent_capacity_policies",
        "create agent capacity policy"
    ),
    (
        AgentCapacityPolicyUpdate,
        "Update an agent capacity policy.",
        "agent_capacity_policy.update",
        Patch,
        "/api/v1/accounts/{account_id}/agent_capacity_policies/{agent_capacity_policy_id}",
        "update agent capacity policy"
    ),
    (
        AgentCapacityPolicyDelete,
        "Delete an agent capacity policy.",
        "agent_capacity_policy.delete",
        Delete,
        "/api/v1/accounts/{account_id}/agent_capacity_policies/{agent_capacity_policy_id}",
        "delete agent capacity policy"
    ),
    (
        AgentCapacityPolicyUserList,
        "List users assigned to an agent capacity policy.",
        "agent_capacity_policy.user.list",
        Get,
        "/api/v1/accounts/{account_id}/agent_capacity_policies/{agent_capacity_policy_id}/users",
        "list agent capacity policy users"
    ),
    (
        AgentCapacityPolicyUserCreate,
        "Assign a user to an agent capacity policy.",
        "agent_capacity_policy.user.create",
        Post,
        "/api/v1/accounts/{account_id}/agent_capacity_policies/{agent_capacity_policy_id}/users",
        "assign agent capacity policy user"
    ),
    (
        AgentCapacityPolicyUserDelete,
        "Remove a user from an agent capacity policy.",
        "agent_capacity_policy.user.delete",
        Delete,
        "/api/v1/accounts/{account_id}/agent_capacity_policies/{agent_capacity_policy_id}/users/{user_id}",
        "remove agent capacity policy user"
    ),
    (
        AgentCapacityPolicyInboxLimitCreate,
        "Create an inbox limit for an agent capacity policy.",
        "agent_capacity_policy.inbox_limit.create",
        Post,
        "/api/v1/accounts/{account_id}/agent_capacity_policies/{agent_capacity_policy_id}/inbox_limits",
        "create agent capacity inbox limit"
    ),
    (
        AgentCapacityPolicyInboxLimitUpdate,
        "Update an inbox limit for an agent capacity policy.",
        "agent_capacity_policy.inbox_limit.update",
        Patch,
        "/api/v1/accounts/{account_id}/agent_capacity_policies/{agent_capacity_policy_id}/inbox_limits/{inbox_limit_id}",
        "update agent capacity inbox limit"
    ),
    (
        AgentCapacityPolicyInboxLimitDelete,
        "Delete an inbox limit from an agent capacity policy.",
        "agent_capacity_policy.inbox_limit.delete",
        Delete,
        "/api/v1/accounts/{account_id}/agent_capacity_policies/{agent_capacity_policy_id}/inbox_limits/{inbox_limit_id}",
        "delete agent capacity inbox limit"
    ),
    (
        CampaignList,
        "List campaigns.",
        "campaign.list",
        Get,
        "/api/v1/accounts/{account_id}/campaigns",
        "list campaigns"
    ),
    (
        CampaignGet,
        "Read a campaign.",
        "campaign.get",
        Get,
        "/api/v1/accounts/{account_id}/campaigns/{campaign_id}",
        "get campaign"
    ),
    (
        CampaignCreate,
        "Create a campaign.",
        "campaign.create",
        Post,
        "/api/v1/accounts/{account_id}/campaigns",
        "create campaign"
    ),
    (
        CampaignUpdate,
        "Update a campaign.",
        "campaign.update",
        Patch,
        "/api/v1/accounts/{account_id}/campaigns/{campaign_id}",
        "update campaign"
    ),
    (
        CampaignDelete,
        "Delete a campaign.",
        "campaign.delete",
        Delete,
        "/api/v1/accounts/{account_id}/campaigns/{campaign_id}",
        "delete campaign"
    ),
    (
        DashboardAppList,
        "List dashboard applications.",
        "dashboard_app.list",
        Get,
        "/api/v1/accounts/{account_id}/dashboard_apps",
        "list dashboard applications"
    ),
    (
        DashboardAppGet,
        "Read a dashboard application.",
        "dashboard_app.get",
        Get,
        "/api/v1/accounts/{account_id}/dashboard_apps/{dashboard_app_id}",
        "get dashboard application"
    ),
    (
        DashboardAppCreate,
        "Create a dashboard application.",
        "dashboard_app.create",
        Post,
        "/api/v1/accounts/{account_id}/dashboard_apps",
        "create dashboard application"
    ),
    (
        DashboardAppUpdate,
        "Update a dashboard application.",
        "dashboard_app.update",
        Patch,
        "/api/v1/accounts/{account_id}/dashboard_apps/{dashboard_app_id}",
        "update dashboard application"
    ),
    (
        DashboardAppDelete,
        "Delete a dashboard application.",
        "dashboard_app.delete",
        Delete,
        "/api/v1/accounts/{account_id}/dashboard_apps/{dashboard_app_id}",
        "delete dashboard application"
    ),
    (
        CaptainPreferenceGet,
        "Read Captain preferences.",
        "captain.preference.get",
        Get,
        "/api/v1/accounts/{account_id}/captain/preferences",
        "get Captain preferences"
    ),
    (
        CaptainPreferenceUpdate,
        "Update Captain preferences.",
        "captain.preference.update",
        Patch,
        "/api/v1/accounts/{account_id}/captain/preferences",
        "update Captain preferences"
    ),
    (
        CaptainAssistantList,
        "List Captain assistants.",
        "captain.assistant.list",
        Get,
        "/api/v1/accounts/{account_id}/captain/assistants",
        "list Captain assistants"
    ),
    (
        CaptainAssistantGet,
        "Read a Captain assistant.",
        "captain.assistant.get",
        Get,
        "/api/v1/accounts/{account_id}/captain/assistants/{assistant_id}",
        "get Captain assistant"
    ),
    (
        CaptainAssistantCreate,
        "Create a Captain assistant.",
        "captain.assistant.create",
        Post,
        "/api/v1/accounts/{account_id}/captain/assistants",
        "create Captain assistant"
    ),
    (
        CaptainAssistantUpdate,
        "Update a Captain assistant.",
        "captain.assistant.update",
        Patch,
        "/api/v1/accounts/{account_id}/captain/assistants/{assistant_id}",
        "update Captain assistant"
    ),
    (
        CaptainAssistantDelete,
        "Delete a Captain assistant.",
        "captain.assistant.delete",
        Delete,
        "/api/v1/accounts/{account_id}/captain/assistants/{assistant_id}",
        "delete Captain assistant"
    ),
    (
        CaptainAssistantPlayground,
        "Run a bounded Captain assistant playground request.",
        "captain.assistant.playground",
        Post,
        "/api/v1/accounts/{account_id}/captain/assistants/{assistant_id}/playground",
        "run Captain assistant playground"
    ),
    (
        CaptainAssistantToolList,
        "List Captain assistant tools.",
        "captain.assistant.tool.list",
        Get,
        "/api/v1/accounts/{account_id}/captain/assistants/tools",
        "list Captain assistant tools"
    ),
    (
        CaptainAssistantInboxList,
        "List inboxes assigned to a Captain assistant.",
        "captain.assistant.inbox.list",
        Get,
        "/api/v1/accounts/{account_id}/captain/assistants/{assistant_id}/inboxes",
        "list Captain assistant inboxes"
    ),
    (
        CaptainAssistantInboxCreate,
        "Assign an inbox to a Captain assistant.",
        "captain.assistant.inbox.create",
        Post,
        "/api/v1/accounts/{account_id}/captain/assistants/{assistant_id}/inboxes",
        "assign Captain assistant inbox"
    ),
    (
        CaptainAssistantInboxDelete,
        "Remove an inbox from a Captain assistant.",
        "captain.assistant.inbox.delete",
        Delete,
        "/api/v1/accounts/{account_id}/captain/assistants/{assistant_id}/inboxes/{inbox_id}",
        "remove Captain assistant inbox"
    ),
    (
        CaptainScenarioList,
        "List Captain assistant scenarios.",
        "captain.scenario.list",
        Get,
        "/api/v1/accounts/{account_id}/captain/assistants/{assistant_id}/scenarios",
        "list Captain scenarios"
    ),
    (
        CaptainScenarioGet,
        "Read a Captain assistant scenario.",
        "captain.scenario.get",
        Get,
        "/api/v1/accounts/{account_id}/captain/assistants/{assistant_id}/scenarios/{scenario_id}",
        "get Captain scenario"
    ),
    (
        CaptainScenarioCreate,
        "Create a Captain assistant scenario.",
        "captain.scenario.create",
        Post,
        "/api/v1/accounts/{account_id}/captain/assistants/{assistant_id}/scenarios",
        "create Captain scenario"
    ),
    (
        CaptainScenarioUpdate,
        "Update a Captain assistant scenario.",
        "captain.scenario.update",
        Patch,
        "/api/v1/accounts/{account_id}/captain/assistants/{assistant_id}/scenarios/{scenario_id}",
        "update Captain scenario"
    ),
    (
        CaptainScenarioDelete,
        "Delete a Captain assistant scenario.",
        "captain.scenario.delete",
        Delete,
        "/api/v1/accounts/{account_id}/captain/assistants/{assistant_id}/scenarios/{scenario_id}",
        "delete Captain scenario"
    ),
    (
        CaptainAssistantResponseList,
        "List Captain assistant responses.",
        "captain.assistant_response.list",
        Get,
        "/api/v1/accounts/{account_id}/captain/assistant_responses",
        "list Captain assistant responses"
    ),
    (
        CaptainAssistantResponseGet,
        "Read a Captain assistant response.",
        "captain.assistant_response.get",
        Get,
        "/api/v1/accounts/{account_id}/captain/assistant_responses/{assistant_response_id}",
        "get Captain assistant response"
    ),
    (
        CaptainAssistantResponseCreate,
        "Create a Captain assistant response.",
        "captain.assistant_response.create",
        Post,
        "/api/v1/accounts/{account_id}/captain/assistant_responses",
        "create Captain assistant response"
    ),
    (
        CaptainAssistantResponseUpdate,
        "Update a Captain assistant response.",
        "captain.assistant_response.update",
        Patch,
        "/api/v1/accounts/{account_id}/captain/assistant_responses/{assistant_response_id}",
        "update Captain assistant response"
    ),
    (
        CaptainAssistantResponseDelete,
        "Delete a Captain assistant response.",
        "captain.assistant_response.delete",
        Delete,
        "/api/v1/accounts/{account_id}/captain/assistant_responses/{assistant_response_id}",
        "delete Captain assistant response"
    ),
    (
        CaptainMessageReportCreate,
        "Create a Captain message report.",
        "captain.message_report.create",
        Post,
        "/api/v1/accounts/{account_id}/captain/message_reports",
        "create Captain message report"
    ),
    (
        CaptainBulkActionCreate,
        "Execute one bounded Captain bulk action.",
        "captain.bulk_action.create",
        Post,
        "/api/v1/accounts/{account_id}/captain/bulk_actions",
        "execute Captain bulk action"
    ),
    (
        CaptainCopilotThreadList,
        "List Captain Copilot threads.",
        "captain.copilot_thread.list",
        Get,
        "/api/v1/accounts/{account_id}/captain/copilot_threads",
        "list Captain Copilot threads"
    ),
    (
        CaptainCopilotThreadCreate,
        "Create a Captain Copilot thread.",
        "captain.copilot_thread.create",
        Post,
        "/api/v1/accounts/{account_id}/captain/copilot_threads",
        "create Captain Copilot thread"
    ),
    (
        CaptainCopilotMessageList,
        "List messages in a Captain Copilot thread.",
        "captain.copilot_message.list",
        Get,
        "/api/v1/accounts/{account_id}/captain/copilot_threads/{copilot_thread_id}/copilot_messages",
        "list Captain Copilot messages"
    ),
    (
        CaptainCopilotMessageCreate,
        "Create a message in a Captain Copilot thread.",
        "captain.copilot_message.create",
        Post,
        "/api/v1/accounts/{account_id}/captain/copilot_threads/{copilot_thread_id}/copilot_messages",
        "create Captain Copilot message"
    ),
    (
        CaptainCustomToolList,
        "List Captain custom tools.",
        "captain.custom_tool.list",
        Get,
        "/api/v1/accounts/{account_id}/captain/custom_tools",
        "list Captain custom tools"
    ),
    (
        CaptainCustomToolGet,
        "Read a Captain custom tool.",
        "captain.custom_tool.get",
        Get,
        "/api/v1/accounts/{account_id}/captain/custom_tools/{custom_tool_id}",
        "get Captain custom tool"
    ),
    (
        CaptainCustomToolCreate,
        "Create a Captain custom tool.",
        "captain.custom_tool.create",
        Post,
        "/api/v1/accounts/{account_id}/captain/custom_tools",
        "create Captain custom tool"
    ),
    (
        CaptainCustomToolUpdate,
        "Update a Captain custom tool.",
        "captain.custom_tool.update",
        Patch,
        "/api/v1/accounts/{account_id}/captain/custom_tools/{custom_tool_id}",
        "update Captain custom tool"
    ),
    (
        CaptainCustomToolDelete,
        "Delete a Captain custom tool.",
        "captain.custom_tool.delete",
        Delete,
        "/api/v1/accounts/{account_id}/captain/custom_tools/{custom_tool_id}",
        "delete Captain custom tool"
    ),
    (
        CaptainCustomToolTest,
        "Test a Captain custom tool without publishing it.",
        "captain.custom_tool.test",
        Post,
        "/api/v1/accounts/{account_id}/captain/custom_tools/test",
        "test Captain custom tool"
    ),
    (
        CaptainDocumentList,
        "List Captain documents.",
        "captain.document.list",
        Get,
        "/api/v1/accounts/{account_id}/captain/documents",
        "list Captain documents"
    ),
    (
        CaptainDocumentGet,
        "Read a Captain document.",
        "captain.document.get",
        Get,
        "/api/v1/accounts/{account_id}/captain/documents/{document_id}",
        "get Captain document"
    ),
    (
        CaptainDocumentCreate,
        "Create a Captain document.",
        "captain.document.create",
        Post,
        "/api/v1/accounts/{account_id}/captain/documents",
        "create Captain document"
    ),
    (
        CaptainDocumentDelete,
        "Delete a Captain document.",
        "captain.document.delete",
        Delete,
        "/api/v1/accounts/{account_id}/captain/documents/{document_id}",
        "delete Captain document"
    ),
    (
        CaptainDocumentSync,
        "Synchronize a Captain document.",
        "captain.document.sync",
        Post,
        "/api/v1/accounts/{account_id}/captain/documents/{document_id}/sync",
        "synchronize Captain document"
    ),
    (
        CaptainTaskRewrite,
        "Rewrite supplied content with Captain.",
        "captain.task.rewrite",
        Post,
        "/api/v1/accounts/{account_id}/captain/tasks/rewrite",
        "rewrite with Captain"
    ),
    (
        CaptainTaskSummarize,
        "Summarize supplied content with Captain.",
        "captain.task.summarize",
        Post,
        "/api/v1/accounts/{account_id}/captain/tasks/summarize",
        "summarize with Captain"
    ),
    (
        CaptainTaskReplySuggestion,
        "Generate a bounded reply suggestion with Captain.",
        "captain.task.reply_suggestion",
        Post,
        "/api/v1/accounts/{account_id}/captain/tasks/reply_suggestion",
        "suggest reply with Captain"
    ),
    (
        CaptainTaskLabelSuggestion,
        "Generate bounded label suggestions with Captain.",
        "captain.task.label_suggestion",
        Post,
        "/api/v1/accounts/{account_id}/captain/tasks/label_suggestion",
        "suggest labels with Captain"
    ),
    (
        CaptainTaskFollowUp,
        "Generate a bounded follow-up with Captain.",
        "captain.task.follow_up",
        Post,
        "/api/v1/accounts/{account_id}/captain/tasks/follow_up",
        "generate follow-up with Captain"
    ),
    (
        ConversationParticipantGet,
        "Read conversation participants.",
        "conversation.participant.get",
        Get,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/participants",
        "get conversation participants"
    ),
    (
        ConversationParticipantCreate,
        "Add conversation participants.",
        "conversation.participant.create",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/participants",
        "add conversation participants"
    ),
    (
        ConversationParticipantUpdate,
        "Update conversation participants.",
        "conversation.participant.update",
        Patch,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/participants",
        "update conversation participants"
    ),
    (
        ConversationParticipantDelete,
        "Remove conversation participants.",
        "conversation.participant.delete",
        Delete,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/participants",
        "remove conversation participants"
    ),
    (
        ConversationDirectUploadCreate,
        "Create a direct upload for a conversation.",
        "conversation.direct_upload.create",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/direct_uploads",
        "create conversation direct upload"
    ),
    (
        ConversationDraftMessageGet,
        "Read the draft message for a conversation.",
        "conversation.draft_message.get",
        Get,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/draft_messages",
        "get conversation draft message"
    ),
    (
        ConversationDraftMessageUpdate,
        "Update the draft message for a conversation.",
        "conversation.draft_message.update",
        Patch,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/draft_messages",
        "update conversation draft message"
    ),
    (
        ConversationDraftMessageDelete,
        "Delete the draft message for a conversation.",
        "conversation.draft_message.delete",
        Delete,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/draft_messages",
        "delete conversation draft message"
    ),
    (
        ConversationUpdateLastSeen,
        "Update the current user's last-seen cursor for a conversation.",
        "conversation.last_seen.update",
        Post,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/update_last_seen",
        "update conversation last seen"
    ),
    (
        ConversationInboxAssistant,
        "Read the assistant configured for a conversation inbox.",
        "conversation.inbox_assistant.get",
        Get,
        "/api/v1/accounts/{account_id}/conversations/{conversation_id}/inbox_assistant",
        "get conversation inbox assistant"
    ),
    (
        SearchAll,
        "Search all supported account resources.",
        "search.all",
        Get,
        "/api/v1/accounts/{account_id}/search",
        "search account resources"
    ),
    (
        SearchConversation,
        "Search conversations across the account.",
        "search.conversation",
        Get,
        "/api/v1/accounts/{account_id}/search/conversations",
        "search account conversations"
    ),
    (
        SearchMessage,
        "Search messages across the account.",
        "search.message",
        Get,
        "/api/v1/accounts/{account_id}/search/messages",
        "search account messages"
    ),
    (
        SearchContact,
        "Search contacts across the account.",
        "search.contact",
        Get,
        "/api/v1/accounts/{account_id}/search/contacts",
        "search account contacts"
    ),
    (
        SearchArticle,
        "Search help-center articles across the account.",
        "search.article",
        Get,
        "/api/v1/accounts/{account_id}/search/articles",
        "search help-center articles"
    ),
    (
        CompanyDestroyCustomAttributes,
        "Remove selected custom attributes from a company.",
        "company.custom_attributes.destroy",
        Post,
        "/api/v1/accounts/{account_id}/companies/{company_id}/destroy_custom_attributes",
        "remove company custom attributes"
    ),
    (
        CompanyAvatarDelete,
        "Delete a company's avatar.",
        "company.avatar.delete",
        Delete,
        "/api/v1/accounts/{account_id}/companies/{company_id}/avatar",
        "delete company avatar"
    ),
    (
        CompanyContactSearch,
        "Search contacts associated with a company.",
        "company.contact.search",
        Get,
        "/api/v1/accounts/{account_id}/companies/{company_id}/contacts/search",
        "search company contacts"
    ),
    (
        CompanyNoteList,
        "List notes associated with a company.",
        "company.note.list",
        Get,
        "/api/v1/accounts/{account_id}/companies/{company_id}/notes",
        "list company notes"
    ),
    (
        ContactDestroyCustomAttributes,
        "Remove selected custom attributes from a contact.",
        "contact.custom_attributes.destroy",
        Post,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}/destroy_custom_attributes",
        "remove contact custom attributes"
    ),
    (
        ContactAvatarDelete,
        "Delete a contact's avatar.",
        "contact.avatar.delete",
        Delete,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}/avatar",
        "delete contact avatar"
    ),
    (
        ContactAttachmentList,
        "List attachments associated with a contact.",
        "contact.attachment.list",
        Get,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}/attachments",
        "list contact attachments"
    ),
    (
        ContactCallCreate,
        "Initiate an enterprise contact call.",
        "contact.call.create",
        Post,
        "/api/v1/accounts/{account_id}/contacts/{contact_id}/call",
        "initiate contact call"
    ),
    (
        CsatSurveyResponseList,
        "List CSAT survey responses.",
        "csat_survey_response.list",
        Get,
        "/api/v1/accounts/{account_id}/csat_survey_responses",
        "list CSAT survey responses"
    ),
    (
        CsatSurveyResponseMetrics,
        "Read CSAT survey metrics.",
        "csat_survey_response.metrics",
        Get,
        "/api/v1/accounts/{account_id}/csat_survey_responses/metrics",
        "get CSAT survey metrics"
    ),
    (
        CsatSurveyResponseDownload,
        "Download CSAT survey responses.",
        "csat_survey_response.download",
        Get,
        "/api/v1/accounts/{account_id}/csat_survey_responses/download",
        "download CSAT survey responses"
    ),
    (
        CsatSurveyResponseUpdate,
        "Update an enterprise CSAT survey response.",
        "csat_survey_response.update",
        Patch,
        "/api/v1/accounts/{account_id}/csat_survey_responses/{csat_survey_response_id}/update",
        "update CSAT survey response"
    ),
    (
        AppliedSlaList,
        "List applied SLA records.",
        "applied_sla.list",
        Get,
        "/api/v1/accounts/{account_id}/applied_slas",
        "list applied SLA records"
    ),
    (
        AppliedSlaMetrics,
        "Read applied SLA metrics.",
        "applied_sla.metrics",
        Get,
        "/api/v1/accounts/{account_id}/applied_slas/metrics",
        "get applied SLA metrics"
    ),
    (
        AppliedSlaDownload,
        "Download applied SLA records.",
        "applied_sla.download",
        Get,
        "/api/v1/accounts/{account_id}/applied_slas/download",
        "download applied SLA records"
    ),
    (
        WhatsappCallGet,
        "Read an enterprise WhatsApp call.",
        "whatsapp_call.get",
        Get,
        "/api/v1/accounts/{account_id}/whatsapp_calls/{whatsapp_call_id}",
        "get WhatsApp call"
    ),
    (
        WhatsappCallAccept,
        "Accept an enterprise WhatsApp call.",
        "whatsapp_call.accept",
        Post,
        "/api/v1/accounts/{account_id}/whatsapp_calls/{whatsapp_call_id}/accept",
        "accept WhatsApp call"
    ),
    (
        WhatsappCallReject,
        "Reject an enterprise WhatsApp call.",
        "whatsapp_call.reject",
        Post,
        "/api/v1/accounts/{account_id}/whatsapp_calls/{whatsapp_call_id}/reject",
        "reject WhatsApp call"
    ),
    (
        WhatsappCallTerminate,
        "Terminate an enterprise WhatsApp call.",
        "whatsapp_call.terminate",
        Post,
        "/api/v1/accounts/{account_id}/whatsapp_calls/{whatsapp_call_id}/terminate",
        "terminate WhatsApp call"
    ),
    (
        WhatsappCallUploadRecording,
        "Upload a recording for an enterprise WhatsApp call.",
        "whatsapp_call.recording.upload",
        Post,
        "/api/v1/accounts/{account_id}/whatsapp_calls/{whatsapp_call_id}/upload_recording",
        "upload WhatsApp call recording"
    ),
    (
        WhatsappCallInitiate,
        "Initiate an enterprise WhatsApp call.",
        "whatsapp_call.initiate",
        Post,
        "/api/v1/accounts/{account_id}/whatsapp_calls/initiate",
        "initiate WhatsApp call"
    ),
    (
        InboxCampaignList,
        "List campaigns associated with an inbox.",
        "inbox.campaign.list",
        Get,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/campaigns",
        "list inbox campaigns"
    ),
    (
        InboxAgentBotGet,
        "Read the agent bot assigned to an inbox.",
        "inbox.agent_bot.get",
        Get,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/agent_bot",
        "get inbox agent bot"
    ),
    (
        InboxAgentBotSet,
        "Assign or replace the agent bot for an inbox.",
        "inbox.agent_bot.set",
        Post,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/set_agent_bot",
        "set inbox agent bot"
    ),
    (
        InboxAvatarDelete,
        "Delete an inbox avatar.",
        "inbox.avatar.delete",
        Delete,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/avatar",
        "delete inbox avatar"
    ),
    (
        InboxConferenceCreate,
        "Create an enterprise inbox conference.",
        "inbox.conference.create",
        Post,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/conference",
        "create inbox conference"
    ),
    (
        InboxConferenceDelete,
        "Delete an enterprise inbox conference.",
        "inbox.conference.delete",
        Delete,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/conference",
        "delete inbox conference"
    ),
    (
        InboxWhatsappCallingEnable,
        "Enable enterprise WhatsApp calling on an inbox.",
        "inbox.whatsapp_calling.enable",
        Post,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/enable_whatsapp_calling",
        "enable inbox WhatsApp calling"
    ),
    (
        InboxWhatsappCallingDisable,
        "Disable enterprise WhatsApp calling on an inbox.",
        "inbox.whatsapp_calling.disable",
        Post,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/disable_whatsapp_calling",
        "disable inbox WhatsApp calling"
    ),
    (
        InboxInboundCallsSet,
        "Set enterprise inbound-call policy for an inbox.",
        "inbox.inbound_calls.set",
        Post,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/set_inbound_calls",
        "set inbox inbound calls"
    ),
    (
        InboxCsatTemplateGet,
        "Read an inbox CSAT template.",
        "inbox.csat_template.get",
        Get,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/csat_template",
        "get inbox CSAT template"
    ),
    (
        InboxCsatTemplateCreate,
        "Create an inbox CSAT template.",
        "inbox.csat_template.create",
        Post,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/csat_template",
        "create inbox CSAT template"
    ),
    (
        InboxCsatTemplateAnalyze,
        "Analyze an inbox CSAT template.",
        "inbox.csat_template.analyze",
        Post,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/csat_template/analyze",
        "analyze inbox CSAT template"
    ),
    (
        NotificationList,
        "List account notifications.",
        "notification.list",
        Get,
        "/api/v1/accounts/{account_id}/notifications",
        "list notifications"
    ),
    (
        NotificationUpdate,
        "Update a notification.",
        "notification.update",
        Patch,
        "/api/v1/accounts/{account_id}/notifications/{notification_id}",
        "update notification"
    ),
    (
        NotificationDelete,
        "Delete a notification.",
        "notification.delete",
        Delete,
        "/api/v1/accounts/{account_id}/notifications/{notification_id}",
        "delete notification"
    ),
    (
        NotificationReadAll,
        "Mark all notifications as read.",
        "notification.read_all",
        Post,
        "/api/v1/accounts/{account_id}/notifications/read_all",
        "mark all notifications read"
    ),
    (
        NotificationUnreadCount,
        "Read the unread notification count.",
        "notification.unread_count",
        Get,
        "/api/v1/accounts/{account_id}/notifications/unread_count",
        "get unread notification count"
    ),
    (
        NotificationDeleteAll,
        "Delete all notifications.",
        "notification.delete_all",
        Post,
        "/api/v1/accounts/{account_id}/notifications/destroy_all",
        "delete all notifications"
    ),
    (
        NotificationSnooze,
        "Snooze a notification.",
        "notification.snooze",
        Post,
        "/api/v1/accounts/{account_id}/notifications/{notification_id}/snooze",
        "snooze notification"
    ),
    (
        NotificationUnread,
        "Mark a notification unread.",
        "notification.unread",
        Post,
        "/api/v1/accounts/{account_id}/notifications/{notification_id}/unread",
        "mark notification unread"
    ),
    (
        NotificationSettingGet,
        "Read notification settings.",
        "notification_setting.get",
        Get,
        "/api/v1/accounts/{account_id}/notification_settings",
        "get notification settings"
    ),
    (
        NotificationSettingUpdate,
        "Update notification settings.",
        "notification_setting.update",
        Patch,
        "/api/v1/accounts/{account_id}/notification_settings",
        "update notification settings"
    ),
    (
        AssignmentPolicyList,
        "List assignment policies.",
        "assignment_policy.list",
        Get,
        "/api/v1/accounts/{account_id}/assignment_policies",
        "list assignment policies"
    ),
    (
        AssignmentPolicyGet,
        "Read an assignment policy.",
        "assignment_policy.get",
        Get,
        "/api/v1/accounts/{account_id}/assignment_policies/{assignment_policy_id}",
        "get assignment policy"
    ),
    (
        AssignmentPolicyCreate,
        "Create an assignment policy.",
        "assignment_policy.create",
        Post,
        "/api/v1/accounts/{account_id}/assignment_policies",
        "create assignment policy"
    ),
    (
        AssignmentPolicyUpdate,
        "Update an assignment policy.",
        "assignment_policy.update",
        Patch,
        "/api/v1/accounts/{account_id}/assignment_policies/{assignment_policy_id}",
        "update assignment policy"
    ),
    (
        AssignmentPolicyDelete,
        "Delete an assignment policy.",
        "assignment_policy.delete",
        Delete,
        "/api/v1/accounts/{account_id}/assignment_policies/{assignment_policy_id}",
        "delete assignment policy"
    ),
    (
        AssignmentPolicyInboxList,
        "List inboxes assigned to an assignment policy.",
        "assignment_policy.inbox.list",
        Get,
        "/api/v1/accounts/{account_id}/assignment_policies/{assignment_policy_id}/inboxes",
        "list assignment policy inboxes"
    ),
    (
        AssignmentPolicyInboxCreate,
        "Assign an inbox to an assignment policy.",
        "assignment_policy.inbox.create",
        Post,
        "/api/v1/accounts/{account_id}/assignment_policies/{assignment_policy_id}/inboxes",
        "assign assignment policy inbox"
    ),
    (
        AssignmentPolicyInboxDelete,
        "Remove an inbox from an assignment policy.",
        "assignment_policy.inbox.delete",
        Delete,
        "/api/v1/accounts/{account_id}/assignment_policies/{assignment_policy_id}/inboxes/{inbox_id}",
        "remove assignment policy inbox"
    ),
    (
        InboxAssignmentPolicyGet,
        "Read the assignment policy attached to an inbox.",
        "inbox.assignment_policy.get",
        Get,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/assignment_policy",
        "get inbox assignment policy"
    ),
    (
        InboxAssignmentPolicyCreate,
        "Attach an assignment policy to an inbox.",
        "inbox.assignment_policy.create",
        Post,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/assignment_policy",
        "attach inbox assignment policy"
    ),
    (
        InboxAssignmentPolicyDelete,
        "Remove the assignment policy from an inbox.",
        "inbox.assignment_policy.delete",
        Delete,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/assignment_policy",
        "remove inbox assignment policy"
    ),
    (
        IntegrationAppGet,
        "Read an installed integration application.",
        "integration.app.get",
        Get,
        "/api/v1/accounts/{account_id}/integrations/apps/{app_id}",
        "get integration application"
    ),
    (
        IntegrationHookGet,
        "Read an integration hook.",
        "integration.hook.get",
        Get,
        "/api/v1/accounts/{account_id}/integrations/hooks/{hook_id}",
        "get integration hook"
    ),
    (
        IntegrationHookProcessEvent,
        "Process one explicitly approved integration-hook event.",
        "integration.hook.process_event",
        Post,
        "/api/v1/accounts/{account_id}/integrations/hooks/{hook_id}/process_event",
        "process integration hook event"
    ),
    (
        PortalGet,
        "Read a help-center portal.",
        "portal.get",
        Get,
        "/api/v1/accounts/{account_id}/portals/{portal_id}",
        "get portal"
    ),
    (
        PortalDelete,
        "Delete a help-center portal.",
        "portal.delete",
        Delete,
        "/api/v1/accounts/{account_id}/portals/{portal_id}",
        "delete portal"
    ),
    (
        PortalArchive,
        "Archive a help-center portal.",
        "portal.archive",
        Patch,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/archive",
        "archive portal"
    ),
    (
        PortalLogoDelete,
        "Delete a help-center portal logo.",
        "portal.logo.delete",
        Delete,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/logo",
        "delete portal logo"
    ),
    (
        PortalSendInstructions,
        "Send help-center portal instructions.",
        "portal.instructions.send",
        Post,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/send_instructions",
        "send portal instructions"
    ),
    (
        PortalSslStatus,
        "Read help-center portal SSL status.",
        "portal.ssl_status",
        Get,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/ssl_status",
        "get portal SSL status"
    ),
    (
        PortalCategoryList,
        "List help-center portal categories.",
        "portal.category.list",
        Get,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/categories",
        "list portal categories"
    ),
    (
        PortalCategoryGet,
        "Read a help-center portal category.",
        "portal.category.get",
        Get,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/categories/{category_id}",
        "get portal category"
    ),
    (
        PortalCategoryUpdate,
        "Update a help-center portal category.",
        "portal.category.update",
        Patch,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/categories/{category_id}",
        "update portal category"
    ),
    (
        PortalCategoryDelete,
        "Delete a help-center portal category.",
        "portal.category.delete",
        Delete,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/categories/{category_id}",
        "delete portal category"
    ),
    (
        PortalCategoryReorder,
        "Reorder help-center portal categories.",
        "portal.category.reorder",
        Post,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/categories/reorder",
        "reorder portal categories"
    ),
    (
        PortalArticleList,
        "List help-center portal articles.",
        "portal.article.list",
        Get,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/articles",
        "list portal articles"
    ),
    (
        PortalArticleGet,
        "Read a help-center portal article.",
        "portal.article.get",
        Get,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/articles/{article_id}",
        "get portal article"
    ),
    (
        PortalArticleUpdate,
        "Update a help-center portal article.",
        "portal.article.update",
        Patch,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/articles/{article_id}",
        "update portal article"
    ),
    (
        PortalArticleDelete,
        "Delete a help-center portal article.",
        "portal.article.delete",
        Delete,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/articles/{article_id}",
        "delete portal article"
    ),
    (
        PortalArticleReorder,
        "Reorder help-center portal articles.",
        "portal.article.reorder",
        Post,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/articles/reorder",
        "reorder portal articles"
    ),
    (
        PortalArticleBulkTranslate,
        "Translate a bounded set of help-center portal articles.",
        "portal.article.bulk.translate",
        Post,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/articles/bulk_actions/translate",
        "translate portal articles"
    ),
    (
        PortalArticleBulkUpdateStatus,
        "Update status for a bounded set of help-center portal articles.",
        "portal.article.bulk.update_status",
        Patch,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/articles/bulk_actions/update_status",
        "update portal article status"
    ),
    (
        PortalArticleBulkUpdateCategory,
        "Update category for a bounded set of help-center portal articles.",
        "portal.article.bulk.update_category",
        Patch,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/articles/bulk_actions/update_category",
        "update portal article category"
    ),
    (
        PortalArticleBulkDelete,
        "Delete a bounded set of help-center portal articles.",
        "portal.article.bulk.delete",
        Delete,
        "/api/v1/accounts/{account_id}/portals/{portal_id}/articles/bulk_actions/delete_articles",
        "delete portal articles"
    ),
    (
        UploadCreate,
        "Create an authenticated account upload.",
        "upload.create",
        Post,
        "/api/v1/accounts/{account_id}/upload",
        "create account upload"
    ),
    (
        ReportLabelSummary,
        "Read label summary metrics.",
        "report.label_summary",
        Get,
        "/api/v2/accounts/{account_id}/summary_reports/label",
        "get label summary"
    ),
    (
        ReportBotSummary,
        "Read bot summary report data.",
        "report.bot_summary",
        Get,
        "/api/v2/accounts/{account_id}/reports/bot_summary",
        "get bot summary report"
    ),
    (
        ReportAgents,
        "Read agent report data.",
        "report.agents",
        Get,
        "/api/v2/accounts/{account_id}/reports/agents",
        "get agent report"
    ),
    (
        ReportInboxes,
        "Read inbox report data.",
        "report.inboxes",
        Get,
        "/api/v2/accounts/{account_id}/reports/inboxes",
        "get inbox report"
    ),
    (
        ReportLabels,
        "Read label report data.",
        "report.labels",
        Get,
        "/api/v2/accounts/{account_id}/reports/labels",
        "get label report"
    ),
    (
        ReportTeams,
        "Read team report data.",
        "report.teams",
        Get,
        "/api/v2/accounts/{account_id}/reports/teams",
        "get team report"
    ),
    (
        ReportConversationsSummary,
        "Read conversation summary report data.",
        "report.conversations_summary",
        Get,
        "/api/v2/accounts/{account_id}/reports/conversations_summary",
        "get conversation summary report"
    ),
    (
        ReportConversationTraffic,
        "Read conversation traffic report data.",
        "report.conversation_traffic",
        Get,
        "/api/v2/accounts/{account_id}/reports/conversation_traffic",
        "get conversation traffic report"
    ),
    (
        ReportDrilldown,
        "Read report drilldown data.",
        "report.drilldown",
        Get,
        "/api/v2/accounts/{account_id}/reports/drilldown",
        "get report drilldown"
    ),
    (
        ReportBotMetrics,
        "Read bot metrics.",
        "report.bot_metrics",
        Get,
        "/api/v2/accounts/{account_id}/reports/bot_metrics",
        "get bot metrics"
    ),
    (
        ReportYearInReview,
        "Read the account year-in-review report.",
        "report.year_in_review",
        Get,
        "/api/v2/accounts/{account_id}/year_in_review",
        "get year in review"
    ),
    (
        LiveReportConversationMetrics,
        "Read live conversation metrics.",
        "report.live.conversation_metrics",
        Get,
        "/api/v2/accounts/{account_id}/live_reports/conversation_metrics",
        "get live conversation metrics"
    ),
    (
        LiveReportGroupedConversationMetrics,
        "Read grouped live conversation metrics.",
        "report.live.grouped_conversation_metrics",
        Get,
        "/api/v2/accounts/{account_id}/live_reports/grouped_conversation_metrics",
        "get grouped live conversation metrics"
    ),
    (
        AgentBotAvatarDelete,
        "Delete an agent-bot avatar without rotating its credentials.",
        "agent_bot.avatar.delete",
        Delete,
        "/api/v1/accounts/{account_id}/agent_bots/{agent_bot_id}/avatar",
        "delete agent-bot avatar"
    ),
    (
        WebhookList,
        "List account webhooks.",
        "webhook.list",
        Get,
        "/api/v1/accounts/{account_id}/webhooks",
        "list webhooks"
    ),
    (
        WebhookCreate,
        "Create an account webhook.",
        "webhook.create",
        Post,
        "/api/v1/accounts/{account_id}/webhooks",
        "create webhook"
    ),
    (
        WebhookUpdate,
        "Update an account webhook.",
        "webhook.update",
        Patch,
        "/api/v1/accounts/{account_id}/webhooks/{webhook_id}",
        "update webhook"
    ),
    (
        WebhookDelete,
        "Delete an account webhook.",
        "webhook.delete",
        Delete,
        "/api/v1/accounts/{account_id}/webhooks/{webhook_id}",
        "delete webhook"
    )
);

/// Account and identity administration routes deliberately kept outside the
/// agent-callable product surface.
///
/// The connector publishes the complete configured-account business surface
/// from the pinned route set. Routes below create account identities, rotate
/// credentials, establish third-party OAuth sessions, or cross into another
/// provider's control plane. They remain operator actions instead of silently
/// becoming broadly callable AIP capabilities.
pub const OPERATOR_ONLY_EXCLUDED_ROUTES: &[(ChatwootHttpMethod, &str)] = &[
    (ChatwootHttpMethod::Post, "/api/v1/accounts"),
    (
        ChatwootHttpMethod::Post,
        "/api/v1/accounts/{account_id}/update_active_at",
    ),
    (
        ChatwootHttpMethod::Get,
        "/api/v1/accounts/{account_id}/cache_keys",
    ),
    (
        ChatwootHttpMethod::Get,
        "/api/v1/accounts/{account_id}/saml_settings",
    ),
    (
        ChatwootHttpMethod::Post,
        "/api/v1/accounts/{account_id}/saml_settings",
    ),
    (
        ChatwootHttpMethod::Patch,
        "/api/v1/accounts/{account_id}/saml_settings",
    ),
    (
        ChatwootHttpMethod::Delete,
        "/api/v1/accounts/{account_id}/saml_settings",
    ),
    (
        ChatwootHttpMethod::Post,
        "/api/v1/accounts/{account_id}/agent_bots/{agent_bot_id}/reset_access_token",
    ),
    (
        ChatwootHttpMethod::Post,
        "/api/v1/accounts/{account_id}/agent_bots/{agent_bot_id}/reset_secret",
    ),
    (
        ChatwootHttpMethod::Post,
        "/api/v1/accounts/{account_id}/channels/twilio_channel",
    ),
    (
        ChatwootHttpMethod::Post,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/reset_secret",
    ),
    (
        ChatwootHttpMethod::Get,
        "/api/v1/accounts/{account_id}/inboxes/{inbox_id}/conference/token",
    ),
    (
        ChatwootHttpMethod::Post,
        "/api/v1/accounts/{account_id}/{provider}/authorization",
    ),
    (
        ChatwootHttpMethod::Post,
        "/api/v1/accounts/{account_id}/callbacks/{provider}",
    ),
    (
        ChatwootHttpMethod::Post,
        "/api/v1/accounts/{account_id}/integrations/{provider}",
    ),
    (
        ChatwootHttpMethod::Patch,
        "/api/v1/accounts/{account_id}/integrations/{provider}",
    ),
    (
        ChatwootHttpMethod::Delete,
        "/api/v1/accounts/{account_id}/integrations/{provider}",
    ),
];

impl ChatwootOperation {
    /// Capability kind used by AIP discovery.
    #[must_use]
    pub const fn capability_kind(self) -> CapabilityKind {
        match self {
            Self::AutomationRuleClone | Self::MacroExecute | Self::ConversationTranscript => {
                CapabilityKind::Workflow
            }
            // Chatwoot records are provider resources, but every catalog entry
            // here is an executable HTTP operation. Native AIP resources use
            // ResourceList/ResourceRead and intentionally have no Action
            // handler, so CRUD operations must remain callable tools.
            _ => CapabilityKind::Tool,
        }
    }

    /// Risk classification for policy and approval enforcement.
    #[must_use]
    pub const fn risk(self) -> RiskLevel {
        match self.method() {
            ChatwootHttpMethod::Get => RiskLevel::Low,
            ChatwootHttpMethod::Delete => RiskLevel::High,
            ChatwootHttpMethod::Post | ChatwootHttpMethod::Patch | ChatwootHttpMethod::Put => {
                match self {
                    Self::MacroExecute
                    | Self::ContactImport
                    | Self::ContactExport
                    | Self::InboxRegisterWebhook
                    | Self::AccountBulkActionCreate
                    | Self::CaptainBulkActionCreate
                    | Self::CaptainAssistantPlayground
                    | Self::CaptainCustomToolTest
                    | Self::IntegrationHookProcessEvent
                    | Self::ContactCallCreate
                    | Self::WhatsappCallAccept
                    | Self::WhatsappCallReject
                    | Self::WhatsappCallTerminate
                    | Self::WhatsappCallUploadRecording
                    | Self::WhatsappCallInitiate
                    | Self::InboxConferenceCreate
                    | Self::InboxConferenceDelete
                    | Self::InboxWhatsappCallingEnable
                    | Self::InboxWhatsappCallingDisable
                    | Self::InboxInboundCallsSet
                    | Self::PortalArticleBulkTranslate
                    | Self::PortalArticleBulkUpdateStatus
                    | Self::PortalArticleBulkUpdateCategory => RiskLevel::High,
                    _ => RiskLevel::Medium,
                }
            }
        }
    }

    /// Whether the operation mutates external state.
    #[must_use]
    pub const fn is_mutation(self) -> bool {
        !matches!(self.method(), ChatwootHttpMethod::Get)
    }

    /// Whether a retry is safe after a confirmed transport failure.
    #[must_use]
    pub const fn retry_safe(self) -> bool {
        matches!(self.method(), ChatwootHttpMethod::Get)
    }

    /// Whether the pinned upstream endpoint accepts multipart form data.
    #[must_use]
    pub const fn supports_multipart(self) -> bool {
        matches!(
            self,
            Self::MessageCreate
                | Self::ContactImport
                | Self::ConversationDirectUploadCreate
                | Self::CaptainDocumentCreate
                | Self::WhatsappCallUploadRecording
                | Self::UploadCreate
        )
    }

    /// Whether upstream only registers this route in the enterprise edition.
    #[must_use]
    pub const fn requires_enterprise_edition(self) -> bool {
        matches!(
            self,
            Self::ConversationReportingEvents
                | Self::ContactCallCreate
                | Self::CsatSurveyResponseUpdate
                | Self::AccountReportingEventList
                | Self::WhatsappCallGet
                | Self::WhatsappCallAccept
                | Self::WhatsappCallReject
                | Self::WhatsappCallTerminate
                | Self::WhatsappCallUploadRecording
                | Self::WhatsappCallInitiate
                | Self::InboxConferenceCreate
                | Self::InboxConferenceDelete
                | Self::InboxWhatsappCallingEnable
                | Self::InboxWhatsappCallingDisable
                | Self::InboxInboundCallsSet
        )
    }
}
