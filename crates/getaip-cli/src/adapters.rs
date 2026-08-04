use getaip_distribution::{
    InstallRoots, atomic_write_bytes, atomic_write_json, read_bounded_file, read_json_file,
    sha256_hex,
};
use jsonc_parser::{
    ParseOptions,
    cst::{CstInputValue, CstRootNode},
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use std::{
    collections::BTreeSet,
    fs, io,
    path::{Path, PathBuf},
};
use toml_edit::{Array, DocumentMut, Item, Table, value};

const MANAGED_SCHEMA: &str = "org.getaip.managed-clients.v1";
const MAX_CLIENT_CONFIG_BYTES: usize = 4 * 1024 * 1024;

/// Supported local MCP client adapter.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ClientKind {
    Codex,
    Claude,
    Cursor,
    Gemini,
    OpenCode,
}

impl ClientKind {
    fn label(self) -> &'static str {
        match self {
            Self::Codex => "codex",
            Self::Claude => "claude",
            Self::Cursor => "cursor",
            Self::Gemini => "gemini",
            Self::OpenCode => "opencode",
        }
    }
}

/// User-global or project-local configuration scope.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum ClientScope {
    Global,
    Project,
}

impl ClientScope {
    fn label(self) -> &'static str {
        match self {
            Self::Global => "global",
            Self::Project => "project",
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ConfigureClients {
    pub clients: Vec<ClientKind>,
    pub scope: ClientScope,
    pub home: PathBuf,
    pub project_root: PathBuf,
    pub server: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedClients {
    schema: String,
    entries: Vec<ManagedClientEntry>,
}

impl Default for ManagedClients {
    fn default() -> Self {
        Self {
            schema: MANAGED_SCHEMA.to_owned(),
            entries: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ManagedClientEntry {
    client: ClientKind,
    scope: ClientScope,
    path: PathBuf,
    format: ConfigFormat,
    owned: bool,
    created_file: bool,
    backup: Option<PathBuf>,
    owned_value_sha256: String,
    server: PathBuf,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum ConfigFormat {
    CodexToml,
    McpServersJson,
    OpenCodeV2Json,
    OpenCodeV2Jsonc,
}

#[derive(Debug)]
struct Mutation {
    path: PathBuf,
    original: Option<Vec<u8>>,
    replacement: Option<Vec<u8>>,
    entry: ManagedClientEntry,
}

/// Applies all selected adapters after the native distribution has verified.
pub(crate) fn configure(
    roots: &InstallRoots,
    request: ConfigureClients,
    dry_run: bool,
) -> Result<Vec<String>, String> {
    configure_with_managed_writer(roots, request, dry_run, |path, managed| {
        atomic_write_json(path, managed).map_err(|error| error.to_string())
    })
}

fn configure_with_managed_writer<F>(
    roots: &InstallRoots,
    request: ConfigureClients,
    dry_run: bool,
    write_managed: F,
) -> Result<Vec<String>, String>
where
    F: FnOnce(&Path, &ManagedClients) -> Result<(), String>,
{
    let request = normalize_request(request, !dry_run)?;
    let mut clients = BTreeSet::new();
    clients.extend(request.clients.iter().copied());
    if clients.is_empty() {
        return Ok(Vec::new());
    }
    let mut managed = load_managed(roots)?;
    let mut mutations = Vec::new();
    for client in clients {
        let (path, format) = config_path(client, request.scope, &request)?;
        let prior = managed
            .entries
            .iter()
            .find(|entry| {
                entry.client == client && entry.scope == request.scope && entry.path == path
            })
            .cloned();
        mutations.push(plan_mutation(
            roots,
            client,
            request.scope,
            path,
            format,
            &request.server,
            prior.as_ref(),
        )?);
    }
    let summary = mutations
        .iter()
        .map(|mutation| {
            format!(
                "{}:{}:{}",
                mutation.entry.client.label(),
                mutation.entry.scope.label(),
                mutation.path.display()
            )
        })
        .collect();
    if dry_run {
        return Ok(summary);
    }

    for mutation in &mutations {
        write_backup(roots, mutation)?;
    }
    for (index, mutation) in mutations.iter().enumerate() {
        if let Err(error) = apply_mutation(mutation) {
            rollback_mutations(&mutations[..index]);
            return Err(error);
        }
    }
    for mutation in &mutations {
        managed.entries.retain(|entry| {
            !(entry.client == mutation.entry.client
                && entry.scope == mutation.entry.scope
                && entry.path == mutation.entry.path)
        });
        managed.entries.push(mutation.entry.clone());
    }
    managed.entries.sort_by(|left, right| {
        (left.client, left.scope.label(), &left.path).cmp(&(
            right.client,
            right.scope.label(),
            &right.path,
        ))
    });
    if let Err(error) = write_managed(&roots.managed_clients(), &managed) {
        rollback_mutations(&mutations);
        return Err(error);
    }
    Ok(summary)
}

/// Updates every owned adapter to the newly active exact server path.
pub(crate) fn refresh_owned(
    roots: &InstallRoots,
    server: &Path,
    dry_run: bool,
) -> Result<Vec<String>, String> {
    let managed = load_managed(roots)?;
    let owned: Vec<_> = managed
        .entries
        .iter()
        .filter(|entry| entry.owned)
        .map(|entry| (entry.client, entry.scope, entry.path.clone()))
        .collect();
    if owned.is_empty() {
        return Ok(Vec::new());
    }
    let mut summaries = Vec::new();
    let mut updated = managed;
    let mut mutations = Vec::new();
    for (client, scope, path) in owned {
        let prior = updated
            .entries
            .iter()
            .find(|entry| entry.client == client && entry.scope == scope && entry.path == path)
            .cloned()
            .ok_or_else(|| "managed client state changed during refresh".to_owned())?;
        let mutation = plan_mutation(
            roots,
            client,
            scope,
            path,
            prior.format,
            server,
            Some(&prior),
        )?;
        summaries.push(format!(
            "{}:{}:{}",
            client.label(),
            scope.label(),
            mutation.path.display()
        ));
        mutations.push(mutation);
    }
    if dry_run {
        return Ok(summaries);
    }
    for (index, mutation) in mutations.iter().enumerate() {
        if let Err(error) = apply_mutation(mutation) {
            rollback_mutations(&mutations[..index]);
            return Err(error);
        }
    }
    for mutation in &mutations {
        updated.entries.retain(|entry| {
            !(entry.client == mutation.entry.client
                && entry.scope == mutation.entry.scope
                && entry.path == mutation.entry.path)
        });
        updated.entries.push(mutation.entry.clone());
    }
    if let Err(error) = atomic_write_json(&roots.managed_clients(), &updated) {
        rollback_mutations(&mutations);
        return Err(error.to_string());
    }
    Ok(summaries)
}

/// Removes only configuration entries whose exact owned value is unchanged.
pub(crate) fn remove_owned(roots: &InstallRoots, dry_run: bool) -> Result<Vec<String>, String> {
    let mut managed = load_managed(roots)?;
    let mut mutations = Vec::new();
    for entry in managed.entries.iter().filter(|entry| entry.owned) {
        mutations.push(plan_removal(entry)?);
    }
    let summary = mutations
        .iter()
        .map(|mutation| mutation.path.display().to_string())
        .collect();
    if dry_run {
        return Ok(summary);
    }
    for (index, mutation) in mutations.iter().enumerate() {
        if let Err(error) = apply_mutation(mutation) {
            rollback_mutations(&mutations[..index]);
            return Err(error);
        }
    }
    managed.entries.retain(|entry| !entry.owned);
    if let Err(error) = atomic_write_json(&roots.managed_clients(), &managed) {
        rollback_mutations(&mutations);
        return Err(error.to_string());
    }
    Ok(summary)
}

/// Revalidates every recorded client entry without mutating client files.
pub(crate) fn verify_managed(
    roots: &InstallRoots,
    active_server: &Path,
) -> Result<(usize, usize), String> {
    if !active_server.is_absolute() {
        return Err("active adapter server path must be absolute".to_owned());
    }
    let managed = load_managed(roots)?;
    let mut identities = BTreeSet::new();
    let mut owned = 0;
    for entry in &managed.entries {
        if !entry.path.is_absolute() || !entry.server.is_absolute() {
            return Err("managed client paths must be absolute".to_owned());
        }
        if !identities.insert((entry.client, entry.scope, entry.path.clone())) {
            return Err("managed client state contains a duplicate entry".to_owned());
        }
        if entry.owned_value_sha256.len() != 64
            || !entry
                .owned_value_sha256
                .bytes()
                .all(|value| value.is_ascii_digit() || (b'a'..=b'f').contains(&value))
        {
            return Err("managed client entry contains an invalid ownership digest".to_owned());
        }
        if entry.owned {
            owned += 1;
            if entry.server != active_server {
                return Err("managed GetAIP client entry points to a non-active server".to_owned());
            }
        }
        if let Some(backup) = entry.backup.as_deref() {
            if !backup.starts_with(&roots.config) {
                return Err("managed client backup escaped the GetAIP config root".to_owned());
            }
            let metadata = fs::symlink_metadata(backup)
                .map_err(|error| format!("managed client backup cannot be inspected: {error}"))?;
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err("managed client backup must be a regular non-symlink file".to_owned());
            }
        }
        plan_mutation(
            roots,
            entry.client,
            entry.scope,
            entry.path.clone(),
            entry.format,
            &entry.server,
            Some(entry),
        )?;
    }
    Ok((managed.entries.len(), owned))
}

fn normalize_request(
    mut request: ConfigureClients,
    require_server: bool,
) -> Result<ConfigureClients, String> {
    for (label, path) in [
        ("adapter home", request.home.as_path()),
        ("project root", request.project_root.as_path()),
        ("verified server", request.server.as_path()),
    ] {
        if !path.is_absolute() {
            return Err(format!("{label} must be absolute: {}", path.display()));
        }
    }
    request.home = normalize_directory(&request.home, "adapter home", require_server)?;
    request.project_root =
        normalize_directory(&request.project_root, "project root", require_server)?;
    if require_server {
        let metadata = fs::symlink_metadata(&request.server).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("adapter server must be a verified regular file".to_owned());
        }
    }
    Ok(request)
}

fn canonical_directory(path: &Path, label: &str) -> Result<PathBuf, String> {
    let canonical = fs::canonicalize(path)
        .map_err(|error| format!("cannot resolve {label} {}: {error}", path.display()))?;
    let metadata = fs::symlink_metadata(&canonical).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("{label} must resolve to a real directory"));
    }
    Ok(canonical)
}

fn normalize_directory(path: &Path, label: &str, require_exists: bool) -> Result<PathBuf, String> {
    if path.exists() || require_exists {
        return canonical_directory(path, label);
    }
    let mut missing = Vec::new();
    let mut ancestor = path;
    while !ancestor.exists() {
        let name = ancestor
            .file_name()
            .ok_or_else(|| format!("cannot resolve planned {label} {}", path.display()))?;
        missing.push(name.to_os_string());
        ancestor = ancestor
            .parent()
            .ok_or_else(|| format!("cannot resolve planned {label} {}", path.display()))?;
    }
    let mut normalized = canonical_directory(ancestor, label)?;
    for name in missing.iter().rev() {
        normalized.push(name);
    }
    Ok(normalized)
}

fn config_path(
    client: ClientKind,
    scope: ClientScope,
    request: &ConfigureClients,
) -> Result<(PathBuf, ConfigFormat), String> {
    let result = match (client, scope) {
        (ClientKind::Codex, ClientScope::Global) => (
            request.home.join(".codex/config.toml"),
            ConfigFormat::CodexToml,
        ),
        (ClientKind::Codex, ClientScope::Project) => (
            request.project_root.join(".codex/config.toml"),
            ConfigFormat::CodexToml,
        ),
        (ClientKind::Claude, ClientScope::Global) => (
            request.home.join(".claude.json"),
            ConfigFormat::McpServersJson,
        ),
        (ClientKind::Claude, ClientScope::Project) => (
            request.project_root.join(".mcp.json"),
            ConfigFormat::McpServersJson,
        ),
        (ClientKind::Cursor, ClientScope::Global) => (
            request.home.join(".cursor/mcp.json"),
            ConfigFormat::McpServersJson,
        ),
        (ClientKind::Cursor, ClientScope::Project) => (
            request.project_root.join(".cursor/mcp.json"),
            ConfigFormat::McpServersJson,
        ),
        (ClientKind::Gemini, ClientScope::Global) => (
            request.home.join(".gemini/settings.json"),
            ConfigFormat::McpServersJson,
        ),
        (ClientKind::Gemini, ClientScope::Project) => (
            request.project_root.join(".gemini/settings.json"),
            ConfigFormat::McpServersJson,
        ),
        (ClientKind::OpenCode, ClientScope::Global) => {
            select_opencode_config(&request.home.join(".config/opencode/opencode"))?
        }
        (ClientKind::OpenCode, ClientScope::Project) => {
            select_opencode_config(&request.project_root.join(".opencode/opencode"))?
        }
    };
    if result.0.components().any(|component| {
        matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )
    }) {
        return Err("client configuration path is not normalized".to_owned());
    }
    Ok(result)
}

fn select_opencode_config(base: &Path) -> Result<(PathBuf, ConfigFormat), String> {
    let json = base.with_extension("json");
    let jsonc = base.with_extension("jsonc");
    let json_exists = json.exists();
    let jsonc_exists = jsonc.exists();
    match (json_exists, jsonc_exists) {
        (true, true) => Err(format!(
            "OpenCode has both {} and {}; remove the ambiguous duplicate before setup",
            json.display(),
            jsonc.display()
        )),
        (false, true) => Ok((jsonc, ConfigFormat::OpenCodeV2Jsonc)),
        _ => Ok((json, ConfigFormat::OpenCodeV2Json)),
    }
}

fn load_managed(roots: &InstallRoots) -> Result<ManagedClients, String> {
    match fs::symlink_metadata(roots.managed_clients()) {
        Ok(_) => {
            let managed: ManagedClients =
                read_json_file(&roots.managed_clients()).map_err(|error| error.to_string())?;
            if managed.schema != MANAGED_SCHEMA {
                return Err(format!(
                    "unsupported managed-client schema {}",
                    managed.schema
                ));
            }
            Ok(managed)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(ManagedClients::default()),
        Err(error) => Err(error.to_string()),
    }
}

fn plan_mutation(
    roots: &InstallRoots,
    client: ClientKind,
    scope: ClientScope,
    path: PathBuf,
    format: ConfigFormat,
    server: &Path,
    prior: Option<&ManagedClientEntry>,
) -> Result<Mutation, String> {
    let original = read_optional_config(&path)?;
    let entry_existed = contains_getaip_entry(format, original.as_deref())?;
    let (replacement, desired_digest, _) = match format {
        ConfigFormat::CodexToml => mutate_codex(original.as_deref(), server, prior, false)?,
        ConfigFormat::McpServersJson => {
            mutate_standard_json(original.as_deref(), server, prior, false)?
        }
        ConfigFormat::OpenCodeV2Json => {
            mutate_opencode_json(original.as_deref(), server, prior, false)?
        }
        ConfigFormat::OpenCodeV2Jsonc => {
            mutate_opencode_jsonc(original.as_deref(), server, prior, false)?
        }
    };
    let owned = prior.map(|entry| entry.owned).unwrap_or(!entry_existed);
    let backup = prior.and_then(|entry| entry.backup.clone()).or_else(|| {
        original.as_ref().map(|_| {
            roots.config.join("backups").join(format!(
                "{}-{}-{}.bak",
                client.label(),
                scope.label(),
                &sha256_hex(path.to_string_lossy().as_bytes())[..16]
            ))
        })
    });
    Ok(Mutation {
        path: path.clone(),
        original: original.clone(),
        replacement: Some(replacement),
        entry: ManagedClientEntry {
            client,
            scope,
            path,
            format,
            owned,
            created_file: prior
                .map(|entry| entry.created_file)
                .unwrap_or(original.is_none()),
            backup,
            owned_value_sha256: desired_digest,
            server: server.to_path_buf(),
        },
    })
}

fn plan_removal(entry: &ManagedClientEntry) -> Result<Mutation, String> {
    let original = read_optional_config(&entry.path)?
        .ok_or_else(|| format!("managed client file is missing: {}", entry.path.display()))?;
    let replacement = match entry.format {
        ConfigFormat::CodexToml => {
            mutate_codex(Some(&original), &entry.server, Some(entry), true)?.0
        }
        ConfigFormat::McpServersJson => {
            mutate_standard_json(Some(&original), &entry.server, Some(entry), true)?.0
        }
        ConfigFormat::OpenCodeV2Json => {
            mutate_opencode_json(Some(&original), &entry.server, Some(entry), true)?.0
        }
        ConfigFormat::OpenCodeV2Jsonc => {
            mutate_opencode_jsonc(Some(&original), &entry.server, Some(entry), true)?.0
        }
    };
    let replacement = if entry.created_file && structurally_empty(entry.format, &replacement)? {
        None
    } else {
        Some(replacement)
    };
    Ok(Mutation {
        path: entry.path.clone(),
        original: Some(original),
        replacement,
        entry: entry.clone(),
    })
}

fn mutate_standard_json(
    original: Option<&[u8]>,
    server: &Path,
    prior: Option<&ManagedClientEntry>,
    remove: bool,
) -> Result<(Vec<u8>, String, bool), String> {
    let mut document = parse_json_object(original)?;
    let servers = object_child_mut(&mut document, "mcpServers")?;
    let desired = json!({
        "command": path_text(server)?,
        "args": ["--mcp-stdio"]
    });
    mutate_json_entry(servers, desired, prior, remove)?;
    Ok((
        pretty_json(&Value::Object(document))?,
        value_digest(&json!({
            "command": path_text(server)?,
            "args": ["--mcp-stdio"]
        }))?,
        prior.map(|entry| entry.owned).unwrap_or(true),
    ))
}

fn mutate_opencode_json(
    original: Option<&[u8]>,
    server: &Path,
    prior: Option<&ManagedClientEntry>,
    remove: bool,
) -> Result<(Vec<u8>, String, bool), String> {
    let mut document = parse_json_object(original)?;
    let mcp = object_child_mut(&mut document, "mcp")?;
    let servers = object_child_mut(mcp, "servers")?;
    let desired = json!({
        "type": "local",
        "command": [path_text(server)?, "--mcp-stdio"]
    });
    mutate_json_entry(servers, desired.clone(), prior, remove)?;
    Ok((
        pretty_json(&Value::Object(document))?,
        value_digest(&desired)?,
        prior.map(|entry| entry.owned).unwrap_or(true),
    ))
}

fn mutate_opencode_jsonc(
    original: Option<&[u8]>,
    server: &Path,
    prior: Option<&ManagedClientEntry>,
    remove: bool,
) -> Result<(Vec<u8>, String, bool), String> {
    let text = match original {
        Some(bytes) => std::str::from_utf8(bytes)
            .map_err(|_| "OpenCode JSONC configuration is not UTF-8".to_owned())?,
        None => "{}\n",
    };
    let root = CstRootNode::parse(text, &ParseOptions::default())
        .map_err(|error| format!("OpenCode JSONC is invalid: {error}"))?;
    let object = root
        .object_value_or_create()
        .ok_or_else(|| "OpenCode JSONC root must be an object".to_owned())?;
    let mcp = object
        .object_value_or_create("mcp")
        .ok_or_else(|| "OpenCode JSONC mcp field must be an object".to_owned())?;
    let servers = mcp
        .object_value_or_create("servers")
        .ok_or_else(|| "OpenCode JSONC mcp.servers field must be an object".to_owned())?;
    let desired = json!({
        "type": "local",
        "command": [path_text(server)?, "--mcp-stdio"]
    });
    match servers.get("getaip") {
        Some(property) => {
            let current = property
                .to_serde_value()
                .ok_or_else(|| "OpenCode JSONC GetAIP entry has no value".to_owned())?;
            validate_current_entry(&current, &desired, prior)?;
            if remove {
                property.remove();
            } else {
                property.set_value(opencode_cst_value(server)?);
            }
        }
        None if remove => {
            return Err(
                "managed OpenCode GetAIP entry is missing; refusing broad restore".to_owned(),
            );
        }
        None => {
            servers.append("getaip", opencode_cst_value(server)?);
        }
    }
    Ok((
        root.to_string().into_bytes(),
        value_digest(&desired)?,
        prior.map(|entry| entry.owned).unwrap_or(true),
    ))
}

fn opencode_cst_value(server: &Path) -> Result<CstInputValue, String> {
    Ok(CstInputValue::Object(vec![
        ("type".to_owned(), CstInputValue::String("local".to_owned())),
        (
            "command".to_owned(),
            CstInputValue::Array(vec![
                CstInputValue::String(path_text(server)?),
                CstInputValue::String("--mcp-stdio".to_owned()),
            ]),
        ),
    ]))
}

fn validate_current_entry(
    current: &Value,
    desired: &Value,
    prior: Option<&ManagedClientEntry>,
) -> Result<(), String> {
    if let Some(prior) = prior {
        let digest = value_digest(current)?;
        if prior.owned && digest != prior.owned_value_sha256 {
            return Err(
                "managed GetAIP client entry was changed by the user; refusing overwrite"
                    .to_owned(),
            );
        }
        if !prior.owned && current != desired {
            return Err("unowned GetAIP client entry conflicts with this release".to_owned());
        }
    } else if current != desired {
        return Err("client already has a different GetAIP MCP entry".to_owned());
    }
    Ok(())
}

fn mutate_json_entry(
    servers: &mut Map<String, Value>,
    desired: Value,
    prior: Option<&ManagedClientEntry>,
    remove: bool,
) -> Result<(), String> {
    match servers.get("getaip") {
        Some(current) => {
            let digest = value_digest(current)?;
            if let Some(prior) = prior {
                if prior.owned && digest != prior.owned_value_sha256 {
                    return Err(
                        "managed GetAIP client entry was changed by the user; refusing overwrite"
                            .to_owned(),
                    );
                }
                if !prior.owned && *current != desired {
                    return Err(
                        "unowned GetAIP client entry conflicts with this release".to_owned()
                    );
                }
            } else if *current != desired {
                return Err("client already has a different GetAIP MCP entry".to_owned());
            }
        }
        None if remove => {
            return Err(
                "managed GetAIP client entry is missing; refusing broad restore".to_owned(),
            );
        }
        None => {}
    }
    if remove {
        servers.remove("getaip");
    } else {
        servers.insert("getaip".to_owned(), desired);
    }
    Ok(())
}

fn mutate_codex(
    original: Option<&[u8]>,
    server: &Path,
    prior: Option<&ManagedClientEntry>,
    remove: bool,
) -> Result<(Vec<u8>, String, bool), String> {
    let text = match original {
        Some(bytes) => {
            std::str::from_utf8(bytes).map_err(|_| "Codex config.toml is not UTF-8".to_owned())?
        }
        None => "",
    };
    let mut document = text
        .parse::<DocumentMut>()
        .map_err(|error| format!("Codex config.toml is invalid: {error}"))?;
    let desired = codex_item(server)?;
    let desired_digest = sha256_hex(desired.to_string().as_bytes());
    let existing = document
        .get("mcp_servers")
        .and_then(Item::as_table_like)
        .and_then(|table| table.get("getaip"));
    if let Some(current) = existing {
        let digest = sha256_hex(current.to_string().as_bytes());
        if let Some(prior) = prior {
            if prior.owned && digest != prior.owned_value_sha256 {
                return Err(
                    "managed Codex GetAIP entry was changed by the user; refusing overwrite"
                        .to_owned(),
                );
            }
            if !prior.owned && current.to_string() != desired.to_string() {
                return Err("unowned Codex GetAIP entry conflicts with this release".to_owned());
            }
        } else if current.to_string() != desired.to_string() {
            return Err("Codex already has a different GetAIP MCP entry".to_owned());
        }
    } else if remove {
        return Err("managed Codex GetAIP entry is missing; refusing broad restore".to_owned());
    }
    if remove {
        let table = document
            .get_mut("mcp_servers")
            .and_then(Item::as_table_like_mut)
            .ok_or_else(|| "Codex mcp_servers is not a table".to_owned())?;
        table.remove("getaip");
        if table.is_empty() {
            document.remove("mcp_servers");
        }
    } else {
        if !document.contains_key("mcp_servers") {
            document["mcp_servers"] = Item::Table(Table::new());
        }
        let table = document["mcp_servers"]
            .as_table_like_mut()
            .ok_or_else(|| "Codex mcp_servers is not a table".to_owned())?;
        table.insert("getaip", desired);
    }
    Ok((
        document.to_string().into_bytes(),
        desired_digest,
        prior.map(|entry| entry.owned).unwrap_or(true),
    ))
}

fn codex_item(server: &Path) -> Result<Item, String> {
    let mut table = Table::new();
    table["command"] = value(path_text(server)?);
    let mut arguments = Array::new();
    arguments.push("--mcp-stdio");
    table["args"] = value(arguments);
    Ok(Item::Table(table))
}

fn parse_json_object(original: Option<&[u8]>) -> Result<Map<String, Value>, String> {
    match original {
        Some(bytes) => serde_json::from_slice::<Value>(bytes)
            .map_err(|error| format!("client JSON is invalid: {error}"))?
            .as_object()
            .cloned()
            .ok_or_else(|| "client JSON root must be an object".to_owned()),
        None => Ok(Map::new()),
    }
}

fn object_child_mut<'a>(
    parent: &'a mut Map<String, Value>,
    key: &str,
) -> Result<&'a mut Map<String, Value>, String> {
    let value = parent
        .entry(key.to_owned())
        .or_insert_with(|| Value::Object(Map::new()));
    value
        .as_object_mut()
        .ok_or_else(|| format!("client JSON {key} field must be an object"))
}

fn structurally_empty(format: ConfigFormat, bytes: &[u8]) -> Result<bool, String> {
    match format {
        ConfigFormat::CodexToml => {
            let document = std::str::from_utf8(bytes)
                .map_err(|_| "Codex config is not UTF-8".to_owned())?
                .parse::<DocumentMut>()
                .map_err(|error| error.to_string())?;
            Ok(document.is_empty())
        }
        ConfigFormat::McpServersJson | ConfigFormat::OpenCodeV2Json => {
            let value: Value = serde_json::from_slice(bytes).map_err(|error| error.to_string())?;
            Ok(json_is_structurally_empty(&value))
        }
        ConfigFormat::OpenCodeV2Jsonc => {
            let text =
                std::str::from_utf8(bytes).map_err(|_| "OpenCode JSONC is not UTF-8".to_owned())?;
            let root = CstRootNode::parse(text, &ParseOptions::default())
                .map_err(|error| error.to_string())?;
            let value = root
                .object_value()
                .and_then(|object| object.to_serde_value())
                .ok_or_else(|| "OpenCode JSONC root must be an object".to_owned())?;
            Ok(json_is_structurally_empty(&value))
        }
    }
}

fn json_is_structurally_empty(value: &Value) -> bool {
    match value {
        Value::Object(object) => object.values().all(json_is_structurally_empty),
        _ => false,
    }
}

fn write_backup(roots: &InstallRoots, mutation: &Mutation) -> Result<(), String> {
    let Some(backup) = mutation.entry.backup.as_deref() else {
        return Ok(());
    };
    if backup.exists() {
        return Ok(());
    }
    let Some(original) = mutation.original.as_deref() else {
        return Ok(());
    };
    let parent = backup
        .parent()
        .ok_or_else(|| "backup path has no parent".to_owned())?;
    if !backup.starts_with(&roots.config) {
        return Err("adapter backup escaped the GetAIP config root".to_owned());
    }
    create_real_directory(parent)?;
    atomic_write_bytes(backup, original).map_err(|error| error.to_string())?;
    Ok(())
}

fn apply_mutation(mutation: &Mutation) -> Result<(), String> {
    match mutation.replacement.as_deref() {
        Some(bytes) => {
            let parent = mutation
                .path
                .parent()
                .ok_or_else(|| "client config path has no parent".to_owned())?;
            create_real_directory(parent)?;
            atomic_write_bytes(&mutation.path, bytes).map_err(|error| error.to_string())
        }
        None => remove_regular_file(&mutation.path),
    }
}

fn rollback_mutations(mutations: &[Mutation]) {
    for mutation in mutations.iter().rev() {
        match mutation.original.as_deref() {
            Some(bytes) => {
                let _ = atomic_write_bytes(&mutation.path, bytes);
            }
            None => {
                let _ = remove_regular_file(&mutation.path);
            }
        }
    }
}

fn read_optional_config(path: &Path) -> Result<Option<Vec<u8>>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(format!(
                    "client config must be a regular non-symlink file: {}",
                    path.display()
                ));
            }
            if metadata.len() as usize > MAX_CLIENT_CONFIG_BYTES {
                return Err(format!(
                    "client config exceeds safety limit: {}",
                    path.display()
                ));
            }
            read_bounded_file(path)
                .map(Some)
                .map_err(|error| error.to_string())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.to_string()),
    }
}

fn create_real_directory(path: &Path) -> Result<(), String> {
    reject_symlink_ancestors(path)?;
    fs::create_dir_all(path).map_err(|error| error.to_string())?;
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(format!("unsafe client config directory {}", path.display()));
    }
    Ok(())
}

fn reject_symlink_ancestors(path: &Path) -> Result<(), String> {
    let mut current = PathBuf::new();
    for component in path.components() {
        current.push(component.as_os_str());
        match fs::symlink_metadata(&current) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() {
                    if !trusted_system_directory_symlink(&current)? {
                        return Err(format!(
                            "unsafe client config path component {}",
                            current.display()
                        ));
                    }
                } else if !metadata.is_dir() {
                    return Err(format!(
                        "unsafe client config path component {}",
                        current.display()
                    ));
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => break,
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn trusted_system_directory_symlink(path: &Path) -> Result<bool, String> {
    use std::os::unix::fs::MetadataExt;
    let link = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    let target = fs::metadata(path).map_err(|error| error.to_string())?;
    Ok(link.uid() == 0 && target.is_dir())
}

#[cfg(not(unix))]
fn trusted_system_directory_symlink(_path: &Path) -> Result<bool, String> {
    Ok(false)
}

fn contains_getaip_entry(format: ConfigFormat, original: Option<&[u8]>) -> Result<bool, String> {
    let Some(original) = original else {
        return Ok(false);
    };
    match format {
        ConfigFormat::CodexToml => {
            let text = std::str::from_utf8(original)
                .map_err(|_| "Codex config.toml is not UTF-8".to_owned())?;
            let document = text
                .parse::<DocumentMut>()
                .map_err(|error| format!("Codex config.toml is invalid: {error}"))?;
            Ok(document
                .get("mcp_servers")
                .and_then(Item::as_table_like)
                .is_some_and(|table| table.contains_key("getaip")))
        }
        ConfigFormat::McpServersJson => Ok(parse_json_object(Some(original))?
            .get("mcpServers")
            .and_then(Value::as_object)
            .is_some_and(|servers| servers.contains_key("getaip"))),
        ConfigFormat::OpenCodeV2Json => Ok(parse_json_object(Some(original))?
            .get("mcp")
            .and_then(Value::as_object)
            .and_then(|mcp| mcp.get("servers"))
            .and_then(Value::as_object)
            .is_some_and(|servers| servers.contains_key("getaip"))),
        ConfigFormat::OpenCodeV2Jsonc => {
            let text = std::str::from_utf8(original)
                .map_err(|_| "OpenCode JSONC is not UTF-8".to_owned())?;
            let root = CstRootNode::parse(text, &ParseOptions::default())
                .map_err(|error| format!("OpenCode JSONC is invalid: {error}"))?;
            Ok(root
                .object_value()
                .and_then(|object| object.object_value("mcp"))
                .and_then(|mcp| mcp.object_value("servers"))
                .is_some_and(|servers| servers.get("getaip").is_some()))
        }
    }
}

fn remove_regular_file(path: &Path) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => Err(format!(
            "unsafe client config removal target {}",
            path.display()
        )),
        Ok(_) => fs::remove_file(path).map_err(|error| error.to_string()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.to_string()),
    }
}

fn pretty_json(value: &Value) -> Result<Vec<u8>, String> {
    let mut bytes = serde_json::to_vec_pretty(value).map_err(|error| error.to_string())?;
    bytes.push(b'\n');
    Ok(bytes)
}

fn value_digest(value: &Value) -> Result<String, String> {
    serde_json::to_vec(value)
        .map(|bytes| sha256_hex(&bytes))
        .map_err(|error| error.to_string())
}

fn path_text(path: &Path) -> Result<String, String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("client command path is not UTF-8: {}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn every_adapter_preserves_unrelated_settings_and_removes_only_owned_entry() {
        let temporary = tempdir().expect("tempdir");
        let roots = InstallRoots::under_test_root(&temporary.path().join("install"))
            .expect("install roots");
        fs::create_dir_all(&roots.config).expect("config root");
        let home = temporary.path().join("home");
        let project = temporary.path().join("project");
        let server = temporary.path().join("getaip-server");
        fs::create_dir_all(&home).expect("home");
        fs::create_dir_all(&project).expect("project");
        fs::write(&server, b"server").expect("server");

        let clients = vec![
            ClientKind::Codex,
            ClientKind::Claude,
            ClientKind::Cursor,
            ClientKind::Gemini,
            ClientKind::OpenCode,
        ];
        let summary = configure(
            &roots,
            ConfigureClients {
                clients,
                scope: ClientScope::Project,
                home,
                project_root: project.clone(),
                server: server.clone(),
            },
            false,
        )
        .expect("configure clients");
        assert_eq!(summary.len(), 5);
        assert!(project.join(".codex/config.toml").exists());
        assert!(project.join(".mcp.json").exists());
        assert!(project.join(".cursor/mcp.json").exists());
        assert!(project.join(".gemini/settings.json").exists());
        assert!(project.join(".opencode/opencode.json").exists());
        assert_eq!(
            verify_managed(&roots, &server).expect("verify managed clients"),
            (5, 5)
        );

        let removed = remove_owned(&roots, false).expect("remove owned entries");
        assert_eq!(removed.len(), 5);
        assert!(!project.join(".mcp.json").exists());
        assert!(!project.join(".codex/config.toml").exists());
    }

    #[test]
    fn conflicting_existing_entry_is_never_overwritten() {
        let temporary = tempdir().expect("tempdir");
        let roots = InstallRoots::under_test_root(&temporary.path().join("install"))
            .expect("install roots");
        fs::create_dir_all(&roots.config).expect("config root");
        let home = temporary.path().join("home");
        let project = temporary.path().join("project");
        let server = temporary.path().join("getaip-server");
        fs::create_dir_all(project.join(".cursor")).expect("cursor");
        fs::create_dir_all(&home).expect("home");
        fs::write(&server, b"server").expect("server");
        let config = project.join(".cursor/mcp.json");
        fs::write(
            &config,
            br#"{"unrelated":true,"mcpServers":{"getaip":{"command":"other"}}}"#,
        )
        .expect("existing config");
        let before = fs::read(&config).expect("before");
        let error = configure(
            &roots,
            ConfigureClients {
                clients: vec![ClientKind::Cursor],
                scope: ClientScope::Project,
                home,
                project_root: project,
                server,
            },
            false,
        )
        .expect_err("conflict must fail");
        assert!(error.contains("different GetAIP"));
        assert_eq!(fs::read(config).expect("after"), before);
    }

    #[test]
    fn identical_existing_entry_is_recorded_as_unowned_and_preserved() {
        let temporary = tempdir().expect("tempdir");
        let roots = InstallRoots::under_test_root(&temporary.path().join("install"))
            .expect("install roots");
        fs::create_dir_all(&roots.config).expect("config root");
        let home = temporary.path().join("home");
        let project = temporary.path().join("project");
        let server = temporary.path().join("getaip-server");
        fs::create_dir_all(project.join(".cursor")).expect("cursor");
        fs::create_dir_all(&home).expect("home");
        fs::write(&server, b"server").expect("server");
        let config = project.join(".cursor/mcp.json");
        let original = pretty_json(&json!({
            "unrelated": true,
            "mcpServers": {
                "getaip": {
                    "command": server.to_str().expect("UTF-8"),
                    "args": ["--mcp-stdio"]
                }
            }
        }))
        .expect("JSON");
        fs::write(&config, &original).expect("existing config");
        configure(
            &roots,
            ConfigureClients {
                clients: vec![ClientKind::Cursor],
                scope: ClientScope::Project,
                home,
                project_root: project,
                server,
            },
            false,
        )
        .expect("configure identical entry");
        assert!(
            remove_owned(&roots, false)
                .expect("remove owned")
                .is_empty()
        );
        assert_eq!(fs::read(config).expect("preserved config"), original);
    }

    #[test]
    fn first_mutation_is_backed_up_and_user_edit_blocks_removal() {
        let temporary = tempdir().expect("tempdir");
        let roots = InstallRoots::under_test_root(&temporary.path().join("install"))
            .expect("install roots");
        fs::create_dir_all(&roots.config).expect("config root");
        let home = temporary.path().join("home");
        let project = temporary.path().join("project");
        let server = temporary.path().join("getaip-server");
        fs::create_dir_all(project.join(".cursor")).expect("cursor");
        fs::create_dir_all(&home).expect("home");
        fs::write(&server, b"server").expect("server");
        let config = project.join(".cursor/mcp.json");
        let original = b"{\"unrelated\":true}\n".to_vec();
        fs::write(&config, &original).expect("existing config");
        let request = ConfigureClients {
            clients: vec![ClientKind::Cursor],
            scope: ClientScope::Project,
            home,
            project_root: project,
            server,
        };
        configure(&roots, request.clone(), false).expect("configure");
        let managed = load_managed(&roots).expect("managed state");
        let backup = managed.entries[0].backup.as_ref().expect("backup");
        assert_eq!(fs::read(backup).expect("backup bytes"), original);
        configure(&roots, request.clone(), false).expect("idempotent configure");
        assert_eq!(fs::read(backup).expect("stable backup"), original);

        let mut edited: Value =
            serde_json::from_slice(&fs::read(&config).expect("config")).expect("valid JSON");
        edited["mcpServers"]["getaip"]["args"] = json!(["--user-edited"]);
        fs::write(&config, pretty_json(&edited).expect("JSON")).expect("user edit");
        let before = fs::read(&config).expect("before removal");
        let diagnostic = verify_managed(&roots, &request.server)
            .expect_err("edited entry must fail managed verification");
        assert!(diagnostic.contains("changed by the user"));
        let error = remove_owned(&roots, false).expect_err("edited entry must fail");
        assert!(error.contains("changed by the user"));
        assert_eq!(fs::read(config).expect("after removal"), before);
    }

    #[test]
    fn managed_state_failure_rolls_back_new_client_file() {
        let temporary = tempdir().expect("tempdir");
        let roots = InstallRoots::under_test_root(&temporary.path().join("install"))
            .expect("install roots");
        fs::create_dir_all(&roots.config).expect("config root");
        let home = temporary.path().join("home");
        let project = temporary.path().join("project");
        let server = temporary.path().join("getaip-server");
        fs::create_dir_all(project.join(".cursor")).expect("cursor");
        fs::create_dir_all(&home).expect("home");
        fs::write(&server, b"server").expect("server");
        let config = project.join(".cursor/mcp.json");
        let result = configure_with_managed_writer(
            &roots,
            ConfigureClients {
                clients: vec![ClientKind::Cursor],
                scope: ClientScope::Project,
                home,
                project_root: project,
                server,
            },
            false,
            |_, _| Err("injected managed-state write failure".to_owned()),
        );
        assert_eq!(
            result.expect_err("managed state write must fail"),
            "injected managed-state write failure"
        );
        assert!(!config.exists());
    }

    #[test]
    fn opencode_jsonc_comments_are_preserved_and_duplicate_formats_are_rejected() {
        let temporary = tempdir().expect("tempdir");
        let roots = InstallRoots::under_test_root(&temporary.path().join("install"))
            .expect("install roots");
        fs::create_dir_all(&roots.config).expect("config root");
        let home = temporary.path().join("home");
        let project = temporary.path().join("project");
        let server = temporary.path().join("getaip-server");
        fs::create_dir_all(project.join(".opencode")).expect("opencode");
        fs::create_dir_all(&home).expect("home");
        fs::write(&server, b"server").expect("server");
        let config = project.join(".opencode/opencode.jsonc");
        fs::write(
            &config,
            b"{\n  // preserve this operator note\n  \"theme\": \"dark\",\n}\n",
        )
        .expect("JSONC config");
        let request = ConfigureClients {
            clients: vec![ClientKind::OpenCode],
            scope: ClientScope::Project,
            home,
            project_root: project.clone(),
            server,
        };
        configure(&roots, request.clone(), false).expect("configure JSONC");
        let configured = fs::read_to_string(&config).expect("configured JSONC");
        assert!(configured.contains("// preserve this operator note"));
        assert!(configured.contains("\"theme\": \"dark\""));
        assert!(configured.contains("\"getaip\""));
        remove_owned(&roots, false).expect("remove JSONC entry");
        let removed = fs::read_to_string(&config).expect("removed JSONC");
        assert!(removed.contains("// preserve this operator note"));
        assert!(removed.contains("\"theme\": \"dark\""));
        assert!(!removed.contains("\"getaip\""));

        fs::write(project.join(".opencode/opencode.json"), b"{}\n").expect("duplicate JSON");
        let error = configure(&roots, request, true).expect_err("duplicate formats must fail");
        assert!(error.contains("ambiguous duplicate"));
    }
}
