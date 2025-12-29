//! Built-in policy templates

use crate::policy::*;

/// Strict policy - maximum security, minimal access
pub fn strict_policy() -> Policy {
    Policy {
        name: "strict".to_string(),
        version: 1,
        network: NetworkConfig {
            mode: NetworkMode::None,
            allowed_hosts: vec![],
        },
        filesystem: FilesystemConfig {
            mode: FilesystemMode::Explicit,
            mounts: vec![
                MountConfig {
                    path: "/tmp".to_string(),
                    mode: "rw".to_string(),
                    size: Some("100M".to_string()),
                },
            ],
        },
        tools: ToolsConfig {
            mode: ToolMode::Blocklist,
            allowed: vec![],
            blocked: vec![
                "execute_command".to_string(),
                "run_shell".to_string(),
                "exec".to_string(),
                "shell".to_string(),
            ],
        },
        resources: ResourceLimits {
            memory: "256M".to_string(),
            cpu: 0.5,
            pids: 50,
            timeout: "60s".to_string(),
        },
        audit: AuditConfig {
            enabled: true,
            level: "info".to_string(),
            destination: None,
        },
    }
}

/// Read-only policy - no writes, no network, no exec
pub fn readonly_policy() -> Policy {
    Policy {
        name: "readonly".to_string(),
        version: 1,
        network: NetworkConfig {
            mode: NetworkMode::None,
            allowed_hosts: vec![],
        },
        filesystem: FilesystemConfig {
            mode: FilesystemMode::Explicit,
            mounts: vec![
                MountConfig {
                    path: "/workspace".to_string(),
                    mode: "ro".to_string(),
                    size: None,
                },
            ],
        },
        tools: ToolsConfig {
            mode: ToolMode::Allowlist,
            allowed: vec![
                "read_file".to_string(),
                "list_directory".to_string(),
                "search_files".to_string(),
                "get_file_info".to_string(),
            ],
            blocked: vec![],
        },
        resources: ResourceLimits::default(),
        audit: AuditConfig {
            enabled: true,
            level: "info".to_string(),
            destination: None,
        },
    }
}

/// Development policy - more permissive for local dev
pub fn development_policy() -> Policy {
    Policy {
        name: "development".to_string(),
        version: 1,
        network: NetworkConfig {
            mode: NetworkMode::Allowlist,
            allowed_hosts: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
            ],
        },
        filesystem: FilesystemConfig {
            mode: FilesystemMode::Explicit,
            mounts: vec![
                MountConfig {
                    path: "/workspace".to_string(),
                    mode: "rw".to_string(),
                    size: None,
                },
                MountConfig {
                    path: "/tmp".to_string(),
                    mode: "rw".to_string(),
                    size: Some("500M".to_string()),
                },
            ],
        },
        tools: ToolsConfig {
            mode: ToolMode::Blocklist,
            allowed: vec![],
            blocked: vec![
                "execute_command".to_string(),
                "run_shell".to_string(),
            ],
        },
        resources: ResourceLimits {
            memory: "1G".to_string(),
            cpu: 2.0,
            pids: 200,
            timeout: "600s".to_string(),
        },
        audit: AuditConfig {
            enabled: true,
            level: "debug".to_string(),
            destination: None,
        },
    }
}

/// Network-isolated policy - allows filesystem but no network
pub fn network_isolated_policy() -> Policy {
    Policy {
        name: "network-isolated".to_string(),
        version: 1,
        network: NetworkConfig {
            mode: NetworkMode::None,
            allowed_hosts: vec![],
        },
        filesystem: FilesystemConfig {
            mode: FilesystemMode::Explicit,
            mounts: vec![
                MountConfig {
                    path: "/workspace".to_string(),
                    mode: "rw".to_string(),
                    size: None,
                },
            ],
        },
        tools: ToolsConfig::default(),
        resources: ResourceLimits::default(),
        audit: AuditConfig {
            enabled: true,
            level: "info".to_string(),
            destination: None,
        },
    }
}

/// Get a built-in policy by name
pub fn get_builtin_policy(name: &str) -> Option<Policy> {
    match name {
        "strict" => Some(strict_policy()),
        "readonly" => Some(readonly_policy()),
        "development" | "dev" => Some(development_policy()),
        "network-isolated" => Some(network_isolated_policy()),
        _ => None,
    }
}

/// List all available built-in policy names
pub fn list_builtin_policies() -> Vec<&'static str> {
    vec!["strict", "readonly", "development", "network-isolated"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_strict_policy_blocks_exec() {
        let policy = strict_policy();
        assert!(!policy.tools.is_allowed("execute_command"));
        assert!(!policy.tools.is_allowed("shell"));
    }

    #[test]
    fn test_readonly_only_allows_reads() {
        let policy = readonly_policy();
        assert!(policy.tools.is_allowed("read_file"));
        assert!(!policy.tools.is_allowed("write_file"));
    }

    #[test]
    fn test_get_builtin() {
        assert!(get_builtin_policy("strict").is_some());
        assert!(get_builtin_policy("unknown").is_none());
    }
}
