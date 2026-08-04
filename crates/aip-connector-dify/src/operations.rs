//! Version-pinned Dify Service API operation catalogue.

use aip_core::{CapabilityKind, RiskLevel};

/// Dify upstream revision used to verify this catalogue.
pub const UPSTREAM_REVISION: &str = "f8d47616c15d0959f604f6a5e2e1d32d3108991b";

/// HTTP method used by a frozen Dify operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DifyHttpMethod {
    /// HTTP GET.
    Get,
    /// HTTP POST.
    Post,
    /// HTTP PUT.
    Put,
    /// HTTP PATCH.
    Patch,
    /// HTTP DELETE.
    Delete,
}

/// Credential and discovery domain that owns an operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DifyOperationScope {
    /// Published application Service API key.
    App,
    /// Workspace knowledge Service API key.
    Knowledge,
}

/// Request encoding required by the upstream route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DifyRequestKind {
    /// Query parameters and an optional JSON body.
    Json,
    /// One bounded file plus an optional serialized `data` form field.
    Multipart,
}

/// Location where Dify expects its mandatory end-user identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DifyUserLocation {
    /// Operation is app-scoped and does not resolve an end user.
    None,
    /// `user` is sent as a query parameter.
    Query,
    /// `user` is sent in the JSON request body.
    Json,
    /// `user` is sent in a multipart form.
    Multipart,
}

/// Response transport emitted by Dify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DifyResponseKind {
    /// JSON or UTF-8 response.
    Json,
    /// Raw binary response represented as bounded base64 in AIP.
    Binary,
    /// Server-sent event response.
    ServerSentEvents,
}

macro_rules! dify_operations {
    ($(($variant:ident, $doc:literal, $suffix:literal, $scope:ident, $method:ident, $path:literal, $name:literal, $user:ident, $request:ident, $response:ident)),+ $(,)?) => {
        /// Complete supported Dify Service API operation set beyond the app invocation alias.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum DifyOperation {
            $(#[doc = $doc] $variant),+
        }

        /// Every operation in the pinned Dify Service API catalogue.
        pub const ALL_DIFY_OPERATIONS: &[DifyOperation] = &[
            $(DifyOperation::$variant),+
        ];

        impl DifyOperation {
            /// Stable suffix appended to an app-scoped capability id.
            #[must_use]
            pub const fn suffix(self) -> &'static str {
                match self { $(Self::$variant => $suffix),+ }
            }

            /// Credential and discovery domain that owns the operation.
            #[must_use]
            pub const fn scope(self) -> DifyOperationScope {
                match self { $(Self::$variant => DifyOperationScope::$scope),+ }
            }

            /// Upstream HTTP method.
            #[must_use]
            pub const fn method(self) -> DifyHttpMethod {
                match self { $(Self::$variant => DifyHttpMethod::$method),+ }
            }

            /// Dify Service API path template.
            #[must_use]
            pub const fn path_template(self) -> &'static str {
                match self { $(Self::$variant => $path),+ }
            }

            /// Human-readable operation name.
            #[must_use]
            pub const fn display_name(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }

            /// End-user placement required by Dify's token validation wrapper.
            #[must_use]
            pub const fn user_location(self) -> DifyUserLocation {
                match self { $(Self::$variant => DifyUserLocation::$user),+ }
            }

            /// Request encoding used by the Dify route.
            #[must_use]
            pub const fn request_kind(self) -> DifyRequestKind {
                match self { $(Self::$variant => DifyRequestKind::$request),+ }
            }

            /// Expected response transport.
            #[must_use]
            pub const fn response_kind(self) -> DifyResponseKind {
                match self { $(Self::$variant => DifyResponseKind::$response),+ }
            }

            /// Parses a stable operation suffix.
            #[must_use]
            pub fn from_suffix(suffix: &str) -> Option<Self> {
                ALL_DIFY_OPERATIONS
                    .iter()
                    .copied()
                    .find(|operation| operation.suffix() == suffix)
            }
        }
    };
}

dify_operations!(
    (
        ParametersGet,
        "Read published application parameters.",
        "parameters.get",
        App,
        Get,
        "/v1/parameters",
        "get parameters",
        None,
        Json,
        Json
    ),
    (
        MetaGet,
        "Read application tool and model metadata.",
        "meta.get",
        App,
        Get,
        "/v1/meta",
        "get metadata",
        None,
        Json,
        Json
    ),
    (
        InfoGet,
        "Read published application information.",
        "info.get",
        App,
        Get,
        "/v1/info",
        "get application information",
        None,
        Json,
        Json
    ),
    (
        SiteGet,
        "Read published application site settings.",
        "site.get",
        App,
        Get,
        "/v1/site",
        "get site settings",
        None,
        Json,
        Json
    ),
    (
        FileUpload,
        "Upload one end-user file.",
        "file.upload",
        App,
        Post,
        "/v1/files/upload",
        "upload file",
        Multipart,
        Multipart,
        Json
    ),
    (
        FilePreview,
        "Download one end-user message file.",
        "file.preview",
        App,
        Get,
        "/v1/files/{file_id}/preview",
        "preview file",
        Query,
        Json,
        Binary
    ),
    (
        CompletionStop,
        "Stop a streaming completion task.",
        "completion.stop",
        App,
        Post,
        "/v1/completion-messages/{task_id}/stop",
        "stop completion",
        Json,
        Json,
        Json
    ),
    (
        ChatStop,
        "Stop a streaming chat task.",
        "chat.stop",
        App,
        Post,
        "/v1/chat-messages/{task_id}/stop",
        "stop chat",
        Json,
        Json,
        Json
    ),
    (
        WorkflowRunGet,
        "Read a workflow run.",
        "workflow.run.get",
        App,
        Get,
        "/v1/workflows/run/{workflow_run_id}",
        "get workflow run",
        None,
        Json,
        Json
    ),
    (
        WorkflowRunById,
        "Execute a pinned published workflow version.",
        "workflow.run_by_id",
        App,
        Post,
        "/v1/workflows/{workflow_id}/run",
        "run workflow by id",
        Json,
        Json,
        ServerSentEvents
    ),
    (
        WorkflowStop,
        "Stop a streaming workflow task.",
        "workflow.stop",
        App,
        Post,
        "/v1/workflows/tasks/{task_id}/stop",
        "stop workflow",
        Json,
        Json,
        Json
    ),
    (
        WorkflowLogs,
        "List workflow execution logs.",
        "workflow.log.list",
        App,
        Get,
        "/v1/workflows/logs",
        "list workflow logs",
        None,
        Json,
        Json
    ),
    (
        WorkflowEvents,
        "Resume workflow events for an active task.",
        "workflow.event.stream",
        App,
        Get,
        "/v1/workflow/{task_id}/events",
        "stream workflow events",
        Query,
        Json,
        ServerSentEvents
    ),
    (
        MessageList,
        "List end-user messages.",
        "message.list",
        App,
        Get,
        "/v1/messages",
        "list messages",
        Query,
        Json,
        Json
    ),
    (
        MessageFeedbackCreate,
        "Create or replace message feedback.",
        "message.feedback.create",
        App,
        Post,
        "/v1/messages/{message_id}/feedbacks",
        "submit message feedback",
        Json,
        Json,
        Json
    ),
    (
        AppFeedbackList,
        "List application feedback.",
        "feedback.list",
        App,
        Get,
        "/v1/app/feedbacks",
        "list application feedback",
        None,
        Json,
        Json
    ),
    (
        MessageSuggestedGet,
        "Read suggested questions after a message.",
        "message.suggested.get",
        App,
        Get,
        "/v1/messages/{message_id}/suggested",
        "get suggested questions",
        Query,
        Json,
        Json
    ),
    (
        ConversationList,
        "List end-user conversations.",
        "conversation.list",
        App,
        Get,
        "/v1/conversations",
        "list conversations",
        Query,
        Json,
        Json
    ),
    (
        ConversationDelete,
        "Delete an end-user conversation.",
        "conversation.delete",
        App,
        Delete,
        "/v1/conversations/{conversation_id}",
        "delete conversation",
        Json,
        Json,
        Json
    ),
    (
        ConversationRename,
        "Rename an end-user conversation.",
        "conversation.rename",
        App,
        Post,
        "/v1/conversations/{conversation_id}/name",
        "rename conversation",
        Json,
        Json,
        Json
    ),
    (
        ConversationVariableList,
        "List conversation variables.",
        "conversation.variable.list",
        App,
        Get,
        "/v1/conversations/{conversation_id}/variables",
        "list conversation variables",
        Query,
        Json,
        Json
    ),
    (
        ConversationVariableUpdate,
        "Update one conversation variable.",
        "conversation.variable.update",
        App,
        Put,
        "/v1/conversations/{conversation_id}/variables/{variable_id}",
        "update conversation variable",
        Json,
        Json,
        Json
    ),
    (
        AudioToText,
        "Convert an end-user audio file to text.",
        "audio.transcribe",
        App,
        Post,
        "/v1/audio-to-text",
        "transcribe audio",
        Multipart,
        Multipart,
        Json
    ),
    (
        TextToAudio,
        "Convert text to bounded audio output.",
        "audio.synthesize",
        App,
        Post,
        "/v1/text-to-audio",
        "synthesize audio",
        Json,
        Json,
        Binary
    ),
    (
        EndUserGet,
        "Read an application end user.",
        "end_user.get",
        App,
        Get,
        "/v1/end-users/{end_user_id}",
        "get end user",
        None,
        Json,
        Json
    ),
    (
        HumanInputFormGet,
        "Read a pending workflow human-input form.",
        "human_input_form.get",
        App,
        Get,
        "/v1/form/human_input/{form_token}",
        "get human input form",
        None,
        Json,
        Json
    ),
    (
        HumanInputFormSubmit,
        "Submit a pending workflow human-input form.",
        "human_input_form.submit",
        App,
        Post,
        "/v1/form/human_input/{form_token}",
        "submit human input form",
        Json,
        Json,
        Json
    ),
    (
        AnnotationReplyToggle,
        "Enable or disable annotation reply.",
        "annotation_reply.toggle",
        App,
        Post,
        "/v1/apps/annotation-reply/{action}",
        "toggle annotation reply",
        None,
        Json,
        Json
    ),
    (
        AnnotationReplyStatus,
        "Read annotation-reply background-job status.",
        "annotation_reply.status",
        App,
        Get,
        "/v1/apps/annotation-reply/{action}/status/{job_id}",
        "get annotation reply status",
        None,
        Json,
        Json
    ),
    (
        AnnotationList,
        "List application annotations.",
        "annotation.list",
        App,
        Get,
        "/v1/apps/annotations",
        "list annotations",
        None,
        Json,
        Json
    ),
    (
        AnnotationCreate,
        "Create an application annotation.",
        "annotation.create",
        App,
        Post,
        "/v1/apps/annotations",
        "create annotation",
        None,
        Json,
        Json
    ),
    (
        AnnotationUpdate,
        "Update an application annotation.",
        "annotation.update",
        App,
        Put,
        "/v1/apps/annotations/{annotation_id}",
        "update annotation",
        None,
        Json,
        Json
    ),
    (
        AnnotationDelete,
        "Delete an application annotation.",
        "annotation.delete",
        App,
        Delete,
        "/v1/apps/annotations/{annotation_id}",
        "delete annotation",
        None,
        Json,
        Json
    ),
    (
        KnowledgeModelList,
        "List models available to the current Dify workspace.",
        "model.list",
        Knowledge,
        Get,
        "/v1/workspaces/current/models/model-types/{model_type}",
        "list workspace models",
        None,
        Json,
        Json
    ),
    (
        DatasetList,
        "List knowledge bases.",
        "dataset.list",
        Knowledge,
        Get,
        "/v1/datasets",
        "list knowledge bases",
        None,
        Json,
        Json
    ),
    (
        DatasetCreate,
        "Create an empty knowledge base.",
        "dataset.create",
        Knowledge,
        Post,
        "/v1/datasets",
        "create knowledge base",
        None,
        Json,
        Json
    ),
    (
        DatasetGet,
        "Read one knowledge base.",
        "dataset.get",
        Knowledge,
        Get,
        "/v1/datasets/{dataset_id}",
        "get knowledge base",
        None,
        Json,
        Json
    ),
    (
        DatasetUpdate,
        "Update one knowledge base.",
        "dataset.update",
        Knowledge,
        Patch,
        "/v1/datasets/{dataset_id}",
        "update knowledge base",
        None,
        Json,
        Json
    ),
    (
        DatasetDelete,
        "Delete one knowledge base.",
        "dataset.delete",
        Knowledge,
        Delete,
        "/v1/datasets/{dataset_id}",
        "delete knowledge base",
        None,
        Json,
        Json
    ),
    (
        DocumentStatusUpdate,
        "Update status for a bounded document set.",
        "document.status.update",
        Knowledge,
        Patch,
        "/v1/datasets/{dataset_id}/documents/status/{action}",
        "update document status",
        None,
        Json,
        Json
    ),
    (
        DatasetTagList,
        "List workspace knowledge-base tags.",
        "dataset.tag.list",
        Knowledge,
        Get,
        "/v1/datasets/tags",
        "list knowledge tags",
        None,
        Json,
        Json
    ),
    (
        DatasetTagCreate,
        "Create a knowledge-base tag.",
        "dataset.tag.create",
        Knowledge,
        Post,
        "/v1/datasets/tags",
        "create knowledge tag",
        None,
        Json,
        Json
    ),
    (
        DatasetTagUpdate,
        "Update a knowledge-base tag.",
        "dataset.tag.update",
        Knowledge,
        Patch,
        "/v1/datasets/tags",
        "update knowledge tag",
        None,
        Json,
        Json
    ),
    (
        DatasetTagDelete,
        "Delete a knowledge-base tag.",
        "dataset.tag.delete",
        Knowledge,
        Delete,
        "/v1/datasets/tags",
        "delete knowledge tag",
        None,
        Json,
        Json
    ),
    (
        DatasetTagBind,
        "Bind tags to a knowledge base.",
        "dataset.tag.bind",
        Knowledge,
        Post,
        "/v1/datasets/tags/binding",
        "bind knowledge tags",
        None,
        Json,
        Json
    ),
    (
        DatasetTagUnbind,
        "Remove tags from a knowledge base.",
        "dataset.tag.unbind",
        Knowledge,
        Post,
        "/v1/datasets/tags/unbinding",
        "unbind knowledge tags",
        None,
        Json,
        Json
    ),
    (
        DatasetTagGet,
        "List tags bound to one knowledge base.",
        "dataset.tag.get",
        Knowledge,
        Get,
        "/v1/datasets/{dataset_id}/tags",
        "get knowledge-base tags",
        None,
        Json,
        Json
    ),
    (
        DocumentCreateText,
        "Create a knowledge document from text.",
        "document.text.create",
        Knowledge,
        Post,
        "/v1/datasets/{dataset_id}/document/create-by-text",
        "create text document",
        None,
        Json,
        Json
    ),
    (
        DocumentUpdateText,
        "Update a knowledge document from text.",
        "document.text.update",
        Knowledge,
        Post,
        "/v1/datasets/{dataset_id}/documents/{document_id}/update-by-text",
        "update text document",
        None,
        Json,
        Json
    ),
    (
        DocumentCreateFile,
        "Create a knowledge document from one file.",
        "document.file.create",
        Knowledge,
        Post,
        "/v1/datasets/{dataset_id}/document/create-by-file",
        "create file document",
        None,
        Multipart,
        Json
    ),
    (
        DocumentUpdateFile,
        "Update a knowledge document from one file.",
        "document.file.update",
        Knowledge,
        Post,
        "/v1/datasets/{dataset_id}/documents/{document_id}/update-by-file",
        "update file document",
        None,
        Multipart,
        Json
    ),
    (
        DocumentList,
        "List documents in a knowledge base.",
        "document.list",
        Knowledge,
        Get,
        "/v1/datasets/{dataset_id}/documents",
        "list documents",
        None,
        Json,
        Json
    ),
    (
        DocumentDownloadZip,
        "Download selected source documents as a ZIP archive.",
        "document.download_zip",
        Knowledge,
        Post,
        "/v1/datasets/{dataset_id}/documents/download-zip",
        "download document archive",
        None,
        Json,
        Binary
    ),
    (
        DocumentIndexingStatus,
        "Read asynchronous document indexing status.",
        "document.indexing_status",
        Knowledge,
        Get,
        "/v1/datasets/{dataset_id}/documents/{batch}/indexing-status",
        "get indexing status",
        None,
        Json,
        Json
    ),
    (
        DocumentDownload,
        "Read a source-document download descriptor.",
        "document.download",
        Knowledge,
        Get,
        "/v1/datasets/{dataset_id}/documents/{document_id}/download",
        "download document",
        None,
        Json,
        Json
    ),
    (
        DocumentGet,
        "Read one knowledge document.",
        "document.get",
        Knowledge,
        Get,
        "/v1/datasets/{dataset_id}/documents/{document_id}",
        "get document",
        None,
        Json,
        Json
    ),
    (
        DocumentUpdate,
        "Update one knowledge document from a file.",
        "document.update",
        Knowledge,
        Patch,
        "/v1/datasets/{dataset_id}/documents/{document_id}",
        "update document",
        None,
        Multipart,
        Json
    ),
    (
        DocumentDelete,
        "Delete one knowledge document.",
        "document.delete",
        Knowledge,
        Delete,
        "/v1/datasets/{dataset_id}/documents/{document_id}",
        "delete document",
        None,
        Json,
        Json
    ),
    (
        DatasetRetrieve,
        "Retrieve chunks from a knowledge base.",
        "dataset.retrieve",
        Knowledge,
        Post,
        "/v1/datasets/{dataset_id}/retrieve",
        "retrieve knowledge chunks",
        None,
        Json,
        Json
    ),
    (
        MetadataCreate,
        "Create a custom metadata field.",
        "metadata.create",
        Knowledge,
        Post,
        "/v1/datasets/{dataset_id}/metadata",
        "create metadata field",
        None,
        Json,
        Json
    ),
    (
        MetadataList,
        "List metadata fields.",
        "metadata.list",
        Knowledge,
        Get,
        "/v1/datasets/{dataset_id}/metadata",
        "list metadata fields",
        None,
        Json,
        Json
    ),
    (
        MetadataUpdate,
        "Update a custom metadata field.",
        "metadata.update",
        Knowledge,
        Patch,
        "/v1/datasets/{dataset_id}/metadata/{metadata_id}",
        "update metadata field",
        None,
        Json,
        Json
    ),
    (
        MetadataDelete,
        "Delete a custom metadata field.",
        "metadata.delete",
        Knowledge,
        Delete,
        "/v1/datasets/{dataset_id}/metadata/{metadata_id}",
        "delete metadata field",
        None,
        Json,
        Json
    ),
    (
        MetadataBuiltinList,
        "List built-in metadata fields.",
        "metadata.builtin.list",
        Knowledge,
        Get,
        "/v1/datasets/{dataset_id}/metadata/built-in",
        "list built-in metadata",
        None,
        Json,
        Json
    ),
    (
        MetadataBuiltinUpdate,
        "Enable or disable a built-in metadata field.",
        "metadata.builtin.update",
        Knowledge,
        Post,
        "/v1/datasets/{dataset_id}/metadata/built-in/{action}",
        "update built-in metadata",
        None,
        Json,
        Json
    ),
    (
        DocumentMetadataUpdate,
        "Update metadata for a bounded document set.",
        "document.metadata.update",
        Knowledge,
        Post,
        "/v1/datasets/{dataset_id}/documents/metadata",
        "update document metadata",
        None,
        Json,
        Json
    ),
    (
        DatasourcePluginList,
        "List knowledge-pipeline datasource plugins.",
        "pipeline.datasource_plugin.list",
        Knowledge,
        Get,
        "/v1/datasets/{dataset_id}/pipeline/datasource-plugins",
        "list datasource plugins",
        None,
        Json,
        Json
    ),
    (
        DatasourceNodeRun,
        "Run one knowledge-pipeline datasource node.",
        "pipeline.datasource_node.run",
        Knowledge,
        Post,
        "/v1/datasets/{dataset_id}/pipeline/datasource/nodes/{node_id}/run",
        "run datasource node",
        None,
        Json,
        Json
    ),
    (
        PipelineRun,
        "Run a knowledge pipeline.",
        "pipeline.run",
        Knowledge,
        Post,
        "/v1/datasets/{dataset_id}/pipeline/run",
        "run knowledge pipeline",
        None,
        Json,
        Json
    ),
    (
        PipelineFileUpload,
        "Upload one file for a knowledge pipeline.",
        "pipeline.file.upload",
        Knowledge,
        Post,
        "/v1/datasets/pipeline/file-upload",
        "upload pipeline file",
        None,
        Multipart,
        Json
    ),
    (
        SegmentCreate,
        "Create document chunks.",
        "segment.create",
        Knowledge,
        Post,
        "/v1/datasets/{dataset_id}/documents/{document_id}/segments",
        "create chunks",
        None,
        Json,
        Json
    ),
    (
        SegmentList,
        "List document chunks.",
        "segment.list",
        Knowledge,
        Get,
        "/v1/datasets/{dataset_id}/documents/{document_id}/segments",
        "list chunks",
        None,
        Json,
        Json
    ),
    (
        SegmentGet,
        "Read one document chunk.",
        "segment.get",
        Knowledge,
        Get,
        "/v1/datasets/{dataset_id}/documents/{document_id}/segments/{segment_id}",
        "get chunk",
        None,
        Json,
        Json
    ),
    (
        SegmentUpdate,
        "Update one document chunk.",
        "segment.update",
        Knowledge,
        Post,
        "/v1/datasets/{dataset_id}/documents/{document_id}/segments/{segment_id}",
        "update chunk",
        None,
        Json,
        Json
    ),
    (
        SegmentDelete,
        "Delete one document chunk.",
        "segment.delete",
        Knowledge,
        Delete,
        "/v1/datasets/{dataset_id}/documents/{document_id}/segments/{segment_id}",
        "delete chunk",
        None,
        Json,
        Json
    ),
    (
        ChildChunkCreate,
        "Create child chunks.",
        "child_chunk.create",
        Knowledge,
        Post,
        "/v1/datasets/{dataset_id}/documents/{document_id}/segments/{segment_id}/child_chunks",
        "create child chunks",
        None,
        Json,
        Json
    ),
    (
        ChildChunkList,
        "List child chunks.",
        "child_chunk.list",
        Knowledge,
        Get,
        "/v1/datasets/{dataset_id}/documents/{document_id}/segments/{segment_id}/child_chunks",
        "list child chunks",
        None,
        Json,
        Json
    ),
    (
        ChildChunkUpdate,
        "Update one child chunk.",
        "child_chunk.update",
        Knowledge,
        Patch,
        "/v1/datasets/{dataset_id}/documents/{document_id}/segments/{segment_id}/child_chunks/{child_chunk_id}",
        "update child chunk",
        None,
        Json,
        Json
    ),
    (
        ChildChunkDelete,
        "Delete one child chunk.",
        "child_chunk.delete",
        Knowledge,
        Delete,
        "/v1/datasets/{dataset_id}/documents/{document_id}/segments/{segment_id}/child_chunks/{child_chunk_id}",
        "delete child chunk",
        None,
        Json,
        Json
    )
);

impl DifyOperation {
    /// Whether the operation is available for the configured Dify app mode.
    #[must_use]
    pub fn supports_mode(self, mode: &str) -> bool {
        if self.scope() != DifyOperationScope::App {
            return false;
        }
        match self {
            Self::CompletionStop => mode == "completion",
            Self::ChatStop
            | Self::MessageList
            | Self::MessageFeedbackCreate
            | Self::MessageSuggestedGet
            | Self::ConversationList
            | Self::ConversationDelete
            | Self::ConversationRename
            | Self::ConversationVariableList
            | Self::ConversationVariableUpdate => {
                matches!(mode, "chat" | "agent-chat" | "advanced-chat" | "agent")
            }
            Self::WorkflowRunById | Self::WorkflowStop | Self::WorkflowEvents => mode == "workflow",
            Self::WorkflowRunGet | Self::WorkflowLogs => {
                matches!(mode, "workflow" | "advanced-chat")
            }
            _ => true,
        }
    }

    /// AIP capability kind.
    #[must_use]
    pub const fn capability_kind(self) -> CapabilityKind {
        match self {
            Self::WorkflowRunById
            | Self::WorkflowRunGet
            | Self::WorkflowStop
            | Self::WorkflowEvents
            | Self::HumanInputFormGet
            | Self::HumanInputFormSubmit => CapabilityKind::Workflow,
            _ => CapabilityKind::Tool,
        }
    }

    /// Risk level used by AIP policy evaluation.
    #[must_use]
    pub const fn risk(self) -> RiskLevel {
        match self.method() {
            DifyHttpMethod::Get => RiskLevel::Low,
            DifyHttpMethod::Delete => RiskLevel::High,
            DifyHttpMethod::Post | DifyHttpMethod::Put | DifyHttpMethod::Patch => match self {
                Self::WorkflowRunById | Self::AnnotationReplyToggle | Self::AnnotationDelete => {
                    RiskLevel::High
                }
                _ => RiskLevel::Medium,
            },
        }
    }

    /// Whether the operation mutates provider state or invokes a model.
    #[must_use]
    pub const fn is_mutation(self) -> bool {
        !matches!(self.method(), DifyHttpMethod::Get)
    }

    /// Whether transport-level retry is intrinsically safe.
    #[must_use]
    pub const fn retry_safe(self) -> bool {
        matches!(self.method(), DifyHttpMethod::Get)
    }

    /// Whether a multipart endpoint accepts the provider's serialized `data`
    /// form field in addition to the file itself.
    #[must_use]
    pub const fn accepts_multipart_data(self) -> bool {
        matches!(
            self,
            Self::DocumentCreateFile | Self::DocumentUpdateFile | Self::DocumentUpdate
        )
    }

    /// Whether cancelling this AIP invocation has a defined provider or local
    /// stream outcome.
    #[must_use]
    pub const fn supports_cancel(self) -> bool {
        matches!(self, Self::WorkflowRunById | Self::WorkflowEvents)
    }
}
