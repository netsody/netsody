use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Serialize, Deserialize)]
pub struct VersionInfo {
    pub version: String,
    git_commit: String,
    git_dirty: String,
    pub build_timestamp: String,
    debug: String,
    pub features: String,
}

impl Default for VersionInfo {
    fn default() -> Self {
        Self::new()
    }
}

impl VersionInfo {
    pub fn new() -> Self {
        // extract version information from build-time environment variables
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            git_commit: env!("VERGEN_GIT_SHA").to_string(),
            git_dirty: env!("VERGEN_GIT_DIRTY").to_string(),
            build_timestamp: env!("VERGEN_BUILD_TIMESTAMP").to_string(),
            debug: env!("VERGEN_CARGO_DEBUG").to_string(),
            features: env!("VERGEN_CARGO_FEATURES").to_string(),
        }
    }

    // combine git commit hash with dirty flag
    pub fn full_commit(&self) -> String {
        if self.git_dirty == "true" {
            format!("{0}-dirty", self.git_commit)
        } else {
            self.git_commit.to_string()
        }
    }

    // determine build profile (debug or release)
    pub fn profile(&self) -> String {
        (if self.debug == "true" {
            "debug"
        } else {
            "release"
        })
        .to_string()
    }
}

impl fmt::Display for VersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "  Version: {}", self.version)?;
        writeln!(f, "  Git Commit: {}", self.full_commit())?;
        writeln!(f, "  Build Profile: {}", self.profile())?;
        writeln!(f, "  Build Timestamp: {}", self.build_timestamp)?;
        writeln!(f, "  Features: {}", self.features)?;
        Ok(())
    }
}
