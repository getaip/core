use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Supported GetAIP native distribution target.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Platform {
    /// Apple Silicon macOS.
    DarwinArm64,
    /// Intel macOS.
    DarwinX64,
    /// GNU/Linux on ARM64.
    LinuxArm64,
    /// GNU/Linux on x86-64.
    LinuxX64,
}

impl Platform {
    /// Detects the compile-time host target.
    pub fn detect() -> Result<Self, PlatformError> {
        if cfg!(all(target_os = "macos", target_arch = "aarch64")) {
            Ok(Self::DarwinArm64)
        } else if cfg!(all(target_os = "macos", target_arch = "x86_64")) {
            Ok(Self::DarwinX64)
        } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
            Ok(Self::LinuxArm64)
        } else if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
            Ok(Self::LinuxX64)
        } else {
            Err(PlatformError::Unsupported {
                os: std::env::consts::OS.to_owned(),
                architecture: std::env::consts::ARCH.to_owned(),
            })
        }
    }

    /// Stable release-asset label.
    #[must_use]
    pub const fn asset_label(self) -> &'static str {
        match self {
            Self::DarwinArm64 => "darwin-arm64",
            Self::DarwinX64 => "darwin-x64",
            Self::LinuxArm64 => "linux-arm64",
            Self::LinuxX64 => "linux-x64",
        }
    }

    /// Rust compilation target triple.
    #[must_use]
    pub const fn rust_target(self) -> &'static str {
        match self {
            Self::DarwinArm64 => "aarch64-apple-darwin",
            Self::DarwinX64 => "x86_64-apple-darwin",
            Self::LinuxArm64 => "aarch64-unknown-linux-gnu",
            Self::LinuxX64 => "x86_64-unknown-linux-gnu",
        }
    }

    /// All targets required by the first public Part 2 release.
    #[must_use]
    pub const fn initial_release_matrix() -> [Self; 4] {
        [
            Self::DarwinArm64,
            Self::DarwinX64,
            Self::LinuxArm64,
            Self::LinuxX64,
        ]
    }
}

/// Platform-detection error.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PlatformError {
    /// The host has no qualified GetAIP distribution.
    #[error("unsupported GetAIP platform: operating system `{os}`, architecture `{architecture}`")]
    Unsupported {
        /// Operating-system identifier.
        os: String,
        /// Architecture identifier.
        architecture: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_labels_and_targets_are_unique() {
        let matrix = Platform::initial_release_matrix();
        let labels = matrix.map(Platform::asset_label);
        let targets = matrix.map(Platform::rust_target);
        assert_eq!(
            labels
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            4
        );
        assert_eq!(
            targets
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            4
        );
    }
}
