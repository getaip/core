use crate::Platform;
use std::{
    env,
    path::{Path, PathBuf},
};
use thiserror::Error;

/// Separated user-owned roots for GetAIP installation and runtime state.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InstallRoots {
    /// Immutable distributions and active-version pointer.
    pub data: PathBuf,
    /// User configuration and managed-client records.
    pub config: PathBuf,
    /// Installation, rollback, and service state.
    pub state: PathBuf,
    /// Reusable downloads that may be removed safely.
    pub cache: PathBuf,
    /// User-visible runtime logs.
    pub logs: PathBuf,
}

impl InstallRoots {
    /// Resolves all roots below one explicit test boundary.
    ///
    /// Production callers should use [Self::for_current_user]. The CLI exposes
    /// this only as an explicit test flag so project files cannot redirect an
    /// installation silently.
    pub fn under_test_root(root: &Path) -> Result<Self, LayoutError> {
        if !root.is_absolute() {
            return Err(LayoutError::TestRootNotAbsolute(root.to_path_buf()));
        }
        Ok(Self {
            data: root.join("data"),
            config: root.join("config"),
            state: root.join("state"),
            cache: root.join("cache"),
            logs: root.join("logs"),
        })
    }

    /// Resolves the current user's platform-native layout.
    pub fn for_current_user(platform: Platform) -> Result<Self, LayoutError> {
        let home = env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or(LayoutError::MissingHome)?;
        Self::from_environment(platform, &home, |name| env::var_os(name).map(PathBuf::from))
    }

    /// Resolves a layout from explicit inputs for deterministic testing.
    pub fn from_environment<F>(
        platform: Platform,
        home: &Path,
        mut environment: F,
    ) -> Result<Self, LayoutError>
    where
        F: FnMut(&str) -> Option<PathBuf>,
    {
        if !home.is_absolute() {
            return Err(LayoutError::HomeNotAbsolute(home.to_path_buf()));
        }
        match platform {
            Platform::DarwinArm64 | Platform::DarwinX64 => Ok(Self {
                data: home.join("Library/Application Support/GetAIP"),
                config: home.join("Library/Preferences/GetAIP"),
                state: home.join("Library/Application Support/GetAIP/State"),
                cache: home.join("Library/Caches/GetAIP"),
                logs: home.join("Library/Logs/GetAIP"),
            }),
            Platform::LinuxArm64 | Platform::LinuxX64 => Ok(Self {
                data: xdg_root(&mut environment, "XDG_DATA_HOME", home.join(".local/share"))?
                    .join("getaip"),
                config: xdg_root(&mut environment, "XDG_CONFIG_HOME", home.join(".config"))?
                    .join("getaip"),
                state: xdg_root(
                    &mut environment,
                    "XDG_STATE_HOME",
                    home.join(".local/state"),
                )?
                .join("getaip"),
                cache: xdg_root(&mut environment, "XDG_CACHE_HOME", home.join(".cache"))?
                    .join("getaip"),
                logs: xdg_root(
                    &mut environment,
                    "XDG_STATE_HOME",
                    home.join(".local/state"),
                )?
                .join("getaip/logs"),
            }),
        }
    }

    /// Immutable directory for one software version.
    #[must_use]
    pub fn version_dir(&self, version: &str) -> PathBuf {
        self.data.join("versions").join(version)
    }

    /// Active-version pointer path.
    #[must_use]
    pub fn current_pointer(&self) -> PathBuf {
        self.data.join("current")
    }

    /// Installer-owned state document.
    #[must_use]
    pub fn install_state(&self) -> PathBuf {
        self.state.join("install-state.json")
    }

    /// Exact signed release manifest retained for offline diagnostics.
    #[must_use]
    pub fn release_manifest(&self) -> PathBuf {
        self.state.join("release-manifest.json")
    }

    /// Detached signature retained for offline diagnostics.
    #[must_use]
    pub fn release_manifest_signature(&self) -> PathBuf {
        self.state.join("release-manifest.json.sig")
    }

    /// Rollback state document.
    #[must_use]
    pub fn rollback_state(&self) -> PathBuf {
        self.state.join("rollback.json")
    }

    /// Immutable release-evidence directory for one installed version.
    #[must_use]
    pub fn release_state_dir(&self, version: &str) -> PathBuf {
        self.state.join("releases").join(version)
    }

    /// Managed MCP-client ownership record.
    #[must_use]
    pub fn managed_clients(&self) -> PathBuf {
        self.config.join("managed-clients.json")
    }

    /// Managed user-service ownership record.
    #[must_use]
    pub fn managed_service(&self) -> PathBuf {
        self.state.join("managed-service.json")
    }

    /// User-owned product configuration.
    #[must_use]
    pub fn configuration(&self) -> PathBuf {
        self.config.join("config.json")
    }

    /// Installer coordination lock.
    #[must_use]
    pub fn install_lock(&self) -> PathBuf {
        self.state.join("install.lock")
    }
}

fn xdg_root<F>(environment: &mut F, name: &str, fallback: PathBuf) -> Result<PathBuf, LayoutError>
where
    F: FnMut(&str) -> Option<PathBuf>,
{
    let path = environment(name).unwrap_or(fallback);
    if !path.is_absolute() {
        return Err(LayoutError::EnvironmentPathNotAbsolute {
            name: name.to_owned(),
            path,
        });
    }
    Ok(path)
}

/// Installation-layout error.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum LayoutError {
    /// No current-user home was available.
    #[error("cannot resolve the current user home directory")]
    MissingHome,
    /// An explicit home path was relative.
    #[error("home directory must be absolute: {0}")]
    HomeNotAbsolute(PathBuf),
    /// An XDG override was relative.
    #[error("{name} must be an absolute path: {path}")]
    EnvironmentPathNotAbsolute {
        /// Environment variable name.
        name: String,
        /// Rejected path.
        path: PathBuf,
    },
    /// An explicit test root was relative.
    #[error("test root must be an absolute path: {0}")]
    TestRootNotAbsolute(PathBuf),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn linux_layout_separates_all_roots() {
        let roots =
            InstallRoots::from_environment(Platform::LinuxX64, Path::new("/users/alice"), |name| {
                match name {
                    "XDG_DATA_HOME" => Some(PathBuf::from("/data")),
                    "XDG_CONFIG_HOME" => Some(PathBuf::from("/config")),
                    "XDG_STATE_HOME" => Some(PathBuf::from("/state")),
                    "XDG_CACHE_HOME" => Some(PathBuf::from("/cache")),
                    _ => None,
                }
            })
            .expect("layout");
        assert_eq!(roots.data, PathBuf::from("/data/getaip"));
        assert_eq!(roots.config, PathBuf::from("/config/getaip"));
        assert_eq!(roots.state, PathBuf::from("/state/getaip"));
        assert_eq!(roots.cache, PathBuf::from("/cache/getaip"));
        assert_eq!(roots.logs, PathBuf::from("/state/getaip/logs"));
        assert_eq!(
            roots.version_dir("2.1.0"),
            PathBuf::from("/data/getaip/versions/2.1.0")
        );
    }

    #[test]
    fn relative_xdg_override_is_rejected() {
        let error =
            InstallRoots::from_environment(Platform::LinuxX64, Path::new("/users/alice"), |name| {
                (name == "XDG_DATA_HOME").then(|| PathBuf::from("relative"))
            })
            .expect_err("relative XDG path must fail");
        assert!(matches!(
            error,
            LayoutError::EnvironmentPathNotAbsolute { .. }
        ));
    }

    #[test]
    fn explicit_test_root_is_visibly_separated() {
        let roots =
            InstallRoots::under_test_root(Path::new("/tmp/getaip-test")).expect("test layout");
        assert_eq!(roots.data, PathBuf::from("/tmp/getaip-test/data"));
        assert_eq!(
            roots.managed_clients(),
            PathBuf::from("/tmp/getaip-test/config/managed-clients.json")
        );
    }
}
