//! Core policy types and parsing

use serde::{Deserialize, Serialize};
use std::path::Path;
use crate::PolicyError;

/// Network access mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum NetworkMode {
    /// No network access (default, most secure)
    #[default]
    None,
    /// Only allowed hosts can be accessed
    Allowlist,
    /// Full host network access (least secure)
    Host,
}

/// Filesystem access mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum FilesystemMode {
    /// No filesystem access
    None,
    /// Only explicitly mounted paths
    #[default]
    Explicit,
    /// Workspace directory access
    Workspace,
}

/// Mount configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MountConfig {
    /// Host path to mount
    pub path: String,
    /// Mount mode: "ro" (read-only) or "rw" (read-write)
    #[serde(default = "default_mount_mode")]
    pub mode: String,
    /// Optional size limit for tmpfs mounts
    pub size: Option<String>,
}

fn default_mount_mode() -> String {
    "ro".to_string()
}

/// Tool access mode
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "lowercase")]
pub enum ToolMode {
    /// All tools allowed
    #[default]
    All,
    /// Only listed tools allowed
    Allowlist,
    /// All except listed tools allowed
    Blocklist,
}

/// Tool access configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolsConfig {
    /// Tool access mode
    #[serde(default)]
    pub mode: ToolMode,
    /// Allowed tools (when mode is Allowlist)
    #[serde(default)]
    pub allowed: Vec<String>,
    /// Blocked tools (when mode is Blocklist)
    #[serde(default)]
    pub blocked: Vec<String>,
}

impl ToolsConfig {
    /// Check if a tool is allowed by this policy
    pub fn is_allowed(&self, tool_name: &str) -> bool {
        match self.mode {
            ToolMode::All => true,
            ToolMode::Allowlist => self.allowed.iter().any(|t| t == tool_name),
            ToolMode::Blocklist => !self.blocked.iter().any(|t| t == tool_name),
        }
    }
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct NetworkConfig {
    /// Network access mode
    #[serde(default)]
    pub mode: NetworkMode,
    /// Allowed hosts (when mode is Allowlist)
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

impl NetworkConfig {
    /// Check if a host is allowed
    pub fn is_host_allowed(&self, host: &str) -> bool {
        match self.mode {
            NetworkMode::None => false,
            NetworkMode::Host => true,
            NetworkMode::Allowlist => self.allowed_hosts.iter().any(|h| {
                h == host || host.ends_with(&format!(".{}", h))
            }),
        }
    }
}

/// Filesystem configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct FilesystemConfig {
    /// Filesystem access mode
    #[serde(default)]
    pub mode: FilesystemMode,
    /// Mount configurations
    #[serde(default)]
    pub mounts: Vec<MountConfig>,
}

/// Resource limits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    /// Memory limit (e.g., "512M", "1G")
    #[serde(default = "default_memory")]
    pub memory: String,
    /// CPU limit (e.g., "1.0", "0.5")
    #[serde(default = "default_cpu")]
    pub cpu: f64,
    /// Maximum number of processes
    #[serde(default = "default_pids")]
    pub pids: u32,
    /// Execution timeout
    #[serde(default = "default_timeout")]
    pub timeout: String,
}

fn default_memory() -> String { "512M".to_string() }
fn default_cpu() -> f64 { 1.0 }
fn default_pids() -> u32 { 100 }
fn default_timeout() -> String { "300s".to_string() }

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            memory: default_memory(),
            cpu: default_cpu(),
            pids: default_pids(),
            timeout: default_timeout(),
        }
    }
}

/// Audit configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AuditConfig {
    /// Enable audit logging
    #[serde(default)]
    pub enabled: bool,
    /// Log level
    #[serde(default = "default_log_level")]
    pub level: String,
    /// Log destination directory
    pub destination: Option<String>,
}

fn default_log_level() -> String { "info".to_string() }

/// Complete policy configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Policy name
    pub name: String,
    /// Policy version
    #[serde(default = "default_version")]
    pub version: u32,
    /// Network configuration
    #[serde(default)]
    pub network: NetworkConfig,
    /// Filesystem configuration
    #[serde(default)]
    pub filesystem: FilesystemConfig,
    /// Tools configuration
    #[serde(default)]
    pub tools: ToolsConfig,
    /// Resource limits
    #[serde(default)]
    pub resources: ResourceLimits,
    /// Audit configuration
    #[serde(default)]
    pub audit: AuditConfig,
}

fn default_version() -> u32 { 1 }

impl Policy {
    /// Load policy from a YAML file
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self, PolicyError> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)
            .map_err(|e| PolicyError::NotFound(format!("{}: {}", path.display(), e)))?;
        Self::from_yaml(&content)
    }

    /// Parse policy from YAML string
    pub fn from_yaml(yaml: &str) -> Result<Self, PolicyError> {
        serde_yaml::from_str(yaml)
            .map_err(|e| PolicyError::ParseError(e.to_string()))
    }

    /// Serialize policy to YAML
    pub fn to_yaml(&self) -> Result<String, PolicyError> {
        serde_yaml::to_string(self)
            .map_err(|e| PolicyError::ParseError(e.to_string()))
    }

    /// Check if a tool call is allowed
    pub fn validate_tool(&self, tool_name: &str) -> Result<(), PolicyError> {
        if self.tools.is_allowed(tool_name) {
            Ok(())
        } else {
            Err(PolicyError::ToolBlocked(tool_name.to_string()))
        }
    }

    /// Check if a path is allowed for access
    pub fn validate_path(&self, path: &str) -> Result<(), PolicyError> {
        match self.filesystem.mode {
            FilesystemMode::None => Err(PolicyError::PathNotAllowed(path.to_string())),
            FilesystemMode::Explicit => {
                let allowed = self.filesystem.mounts.iter().any(|m| {
                    path.starts_with(&m.path)
                });
                if allowed {
                    Ok(())
                } else {
                    Err(PolicyError::PathNotAllowed(path.to_string()))
                }
            }
            FilesystemMode::Workspace => Ok(()),
        }
    }

    /// Check if network access to a host is allowed
    pub fn validate_host(&self, host: &str) -> Result<(), PolicyError> {
        if self.network.is_host_allowed(host) {
            Ok(())
        } else {
            Err(PolicyError::NetworkDenied(host.to_string()))
        }
    }

    /// Get Docker network mode string
    pub fn docker_network_mode(&self) -> &'static str {
        match self.network.mode {
            NetworkMode::None => "none",
            NetworkMode::Host => "host",
            NetworkMode::Allowlist => "bridge",
        }
    }

    /// Parse memory limit to bytes
    pub fn memory_bytes(&self) -> u64 {
        parse_size(&self.resources.memory).unwrap_or(512 * 1024 * 1024)
    }

    /// Parse timeout to seconds
    pub fn timeout_seconds(&self) -> u64 {
        parse_duration(&self.resources.timeout).unwrap_or(300)
    }
}

/// Parse size string like "512M" or "1G" to bytes
fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num, suffix) = if s.ends_with(|c: char| c.is_alphabetic()) {
        let idx = s.len() - 1;
        (&s[..idx], &s[idx..])
    } else {
        (s, "")
    };

    let num: u64 = num.parse().ok()?;
    let multiplier = match suffix.to_uppercase().as_str() {
        "K" => 1024,
        "M" => 1024 * 1024,
        "G" => 1024 * 1024 * 1024,
        "" => 1,
        _ => return None,
    };

    Some(num * multiplier)
}

/// Parse duration string like "300s" or "5m" to seconds
fn parse_duration(s: &str) -> Option<u64> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }

    let (num, suffix) = if s.ends_with(|c: char| c.is_alphabetic()) {
        let idx = s.len() - 1;
        (&s[..idx], &s[idx..])
    } else {
        (s, "")
    };

    let num: u64 = num.parse().ok()?;
    let multiplier = match suffix.to_lowercase().as_str() {
        "s" | "" => 1,
        "m" => 60,
        "h" => 3600,
        _ => return None,
    };

    Some(num * multiplier)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("512M"), Some(512 * 1024 * 1024));
        assert_eq!(parse_size("1G"), Some(1024 * 1024 * 1024));
        assert_eq!(parse_size("100K"), Some(100 * 1024));
    }

    #[test]
    fn test_parse_duration() {
        assert_eq!(parse_duration("300s"), Some(300));
        assert_eq!(parse_duration("5m"), Some(300));
        assert_eq!(parse_duration("1h"), Some(3600));
    }

    #[test]
    fn test_tool_allowlist() {
        let config = ToolsConfig {
            mode: ToolMode::Allowlist,
            allowed: vec!["read_file".to_string(), "list_directory".to_string()],
            blocked: vec![],
        };
        assert!(config.is_allowed("read_file"));
        assert!(!config.is_allowed("execute_command"));
    }

    #[test]
    fn test_tool_blocklist() {
        let config = ToolsConfig {
            mode: ToolMode::Blocklist,
            allowed: vec![],
            blocked: vec!["execute_command".to_string()],
        };
        assert!(config.is_allowed("read_file"));
        assert!(!config.is_allowed("execute_command"));
    }
}
