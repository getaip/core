use serde::{Deserialize, Serialize};

/// GetAIP software version compiled into this crate.
pub const GETAIP_SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// AIP protocol version preserved by GetAIP Part 2.
pub const AIP_PROTOCOL_VERSION: &str = "1.0";

/// Immutable build identity reported by release and development binaries.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct BuildVersion {
    /// GetAIP software version.
    pub software_version: String,
    /// AIP protocol version.
    pub aip_protocol_version: String,
    /// Exact full source commit when injected by the reviewed build.
    pub source_commit: Option<String>,
    /// Exact full source tree when injected by the reviewed build.
    pub source_tree: Option<String>,
    /// Build profile reported by Cargo.
    pub build_profile: String,
    /// Whether the builder explicitly marked the source as dirty.
    pub dirty: bool,
    /// Whether this identity satisfies the release-build requirements.
    pub release_build: bool,
}

impl BuildVersion {
    /// Reads compile-time release identity without performing a network lookup.
    #[must_use]
    pub fn current() -> Self {
        let source_commit = non_empty(option_env!("GETAIP_BUILD_GIT_COMMIT"));
        let source_tree = non_empty(option_env!("GETAIP_BUILD_GIT_TREE"));
        let dirty = matches!(
            option_env!("GETAIP_BUILD_DIRTY"),
            Some("1" | "true" | "yes")
        );
        let build_profile = option_env!("GETAIP_BUILD_PROFILE")
            .unwrap_or("development")
            .to_owned();
        let release_build = source_commit.is_some()
            && source_tree.is_some()
            && !dirty
            && build_profile == "release";
        Self {
            software_version: GETAIP_SOFTWARE_VERSION.to_owned(),
            aip_protocol_version: AIP_PROTOCOL_VERSION.to_owned(),
            source_commit,
            source_tree,
            build_profile,
            dirty,
            release_build,
        }
    }
}

fn non_empty(value: Option<&'static str>) -> Option<String> {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_preserves_protocol_boundary() {
        let version = BuildVersion::current();
        assert_eq!(version.software_version, env!("CARGO_PKG_VERSION"));
        assert_eq!(version.aip_protocol_version, "1.0");
    }
}
