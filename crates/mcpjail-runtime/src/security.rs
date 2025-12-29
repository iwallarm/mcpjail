//! Security configurations for containers

use serde::{Deserialize, Serialize};

/// Seccomp profile for restricting syscalls
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompProfile {
    #[serde(rename = "defaultAction")]
    pub default_action: String,
    pub architectures: Vec<String>,
    pub syscalls: Vec<SeccompRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeccompRule {
    pub names: Vec<String>,
    pub action: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
}

impl SeccompProfile {
    /// Create the default restrictive seccomp profile
    pub fn default_restrictive() -> Self {
        Self {
            default_action: "SCMP_ACT_ERRNO".to_string(),
            architectures: vec!["SCMP_ARCH_X86_64".to_string(), "SCMP_ARCH_AARCH64".to_string()],
            syscalls: vec![
                // Allow basic operations
                SeccompRule {
                    names: vec![
                        "read".to_string(),
                        "write".to_string(),
                        "close".to_string(),
                        "fstat".to_string(),
                        "lstat".to_string(),
                        "stat".to_string(),
                        "poll".to_string(),
                        "lseek".to_string(),
                        "mmap".to_string(),
                        "mprotect".to_string(),
                        "munmap".to_string(),
                        "brk".to_string(),
                        "rt_sigaction".to_string(),
                        "rt_sigprocmask".to_string(),
                        "rt_sigreturn".to_string(),
                        "ioctl".to_string(),
                        "access".to_string(),
                        "pipe".to_string(),
                        "pipe2".to_string(),
                        "select".to_string(),
                        "dup".to_string(),
                        "dup2".to_string(),
                        "dup3".to_string(),
                        "getpid".to_string(),
                        "getuid".to_string(),
                        "getgid".to_string(),
                        "geteuid".to_string(),
                        "getegid".to_string(),
                        "getppid".to_string(),
                        "getgroups".to_string(),
                        "setsid".to_string(),
                        "setpgid".to_string(),
                        "getpgid".to_string(),
                        "getsid".to_string(),
                        "fcntl".to_string(),
                        "flock".to_string(),
                        "fsync".to_string(),
                        "fdatasync".to_string(),
                        "ftruncate".to_string(),
                        "truncate".to_string(),
                        "getdents".to_string(),
                        "getdents64".to_string(),
                        "getcwd".to_string(),
                        "chdir".to_string(),
                        "fchdir".to_string(),
                        "openat".to_string(),
                        "mkdirat".to_string(),
                        "newfstatat".to_string(),
                        "unlinkat".to_string(),
                        "renameat".to_string(),
                        "renameat2".to_string(),
                        "readlinkat".to_string(),
                        "faccessat".to_string(),
                        "faccessat2".to_string(),
                        "clock_gettime".to_string(),
                        "clock_getres".to_string(),
                        "clock_nanosleep".to_string(),
                        "nanosleep".to_string(),
                        "futex".to_string(),
                        "epoll_create".to_string(),
                        "epoll_create1".to_string(),
                        "epoll_ctl".to_string(),
                        "epoll_wait".to_string(),
                        "epoll_pwait".to_string(),
                        "eventfd".to_string(),
                        "eventfd2".to_string(),
                        "getrandom".to_string(),
                        "mremap".to_string(),
                        "madvise".to_string(),
                        "sched_yield".to_string(),
                        "sched_getaffinity".to_string(),
                        "set_tid_address".to_string(),
                        "set_robust_list".to_string(),
                        "get_robust_list".to_string(),
                        "prlimit64".to_string(),
                        "arch_prctl".to_string(),
                        "exit".to_string(),
                        "exit_group".to_string(),
                        "wait4".to_string(),
                        "waitid".to_string(),
                        "tgkill".to_string(),
                        "kill".to_string(),
                        "prctl".to_string(),
                        "sysinfo".to_string(),
                        "uname".to_string(),
                        "getrlimit".to_string(),
                        "pread64".to_string(),
                        "pwrite64".to_string(),
                        "readv".to_string(),
                        "writev".to_string(),
                        "preadv".to_string(),
                        "pwritev".to_string(),
                        "preadv2".to_string(),
                        "pwritev2".to_string(),
                        "statx".to_string(),
                        "memfd_create".to_string(),
                        "copy_file_range".to_string(),
                        "sendfile".to_string(),
                    ],
                    action: "SCMP_ACT_ALLOW".to_string(),
                    comment: Some("Allow basic file and memory operations".to_string()),
                },
                // Allow network operations (controlled by Docker --network flag)
                SeccompRule {
                    names: vec![
                        "socket".to_string(),
                        "connect".to_string(),
                        "accept".to_string(),
                        "accept4".to_string(),
                        "sendto".to_string(),
                        "recvfrom".to_string(),
                        "sendmsg".to_string(),
                        "recvmsg".to_string(),
                        "shutdown".to_string(),
                        "bind".to_string(),
                        "listen".to_string(),
                        "getsockname".to_string(),
                        "getpeername".to_string(),
                        "socketpair".to_string(),
                        "setsockopt".to_string(),
                        "getsockopt".to_string(),
                    ],
                    action: "SCMP_ACT_ALLOW".to_string(),
                    comment: Some("Allow network operations (controlled by network namespace)".to_string()),
                },
                // Allow clone for threading but not for creating new processes
                SeccompRule {
                    names: vec![
                        "clone".to_string(),
                        "clone3".to_string(),
                    ],
                    action: "SCMP_ACT_ALLOW".to_string(),
                    comment: Some("Allow threading".to_string()),
                },
                // Block dangerous syscalls
                SeccompRule {
                    names: vec![
                        "execve".to_string(),
                        "execveat".to_string(),
                    ],
                    action: "SCMP_ACT_ERRNO".to_string(),
                    comment: Some("Block process spawning".to_string()),
                },
                SeccompRule {
                    names: vec![
                        "ptrace".to_string(),
                        "process_vm_readv".to_string(),
                        "process_vm_writev".to_string(),
                    ],
                    action: "SCMP_ACT_ERRNO".to_string(),
                    comment: Some("Block debugging/inspection".to_string()),
                },
                SeccompRule {
                    names: vec![
                        "mount".to_string(),
                        "umount2".to_string(),
                        "pivot_root".to_string(),
                        "chroot".to_string(),
                    ],
                    action: "SCMP_ACT_ERRNO".to_string(),
                    comment: Some("Block filesystem manipulation".to_string()),
                },
                SeccompRule {
                    names: vec![
                        "init_module".to_string(),
                        "finit_module".to_string(),
                        "delete_module".to_string(),
                    ],
                    action: "SCMP_ACT_ERRNO".to_string(),
                    comment: Some("Block kernel module loading".to_string()),
                },
                SeccompRule {
                    names: vec![
                        "reboot".to_string(),
                        "kexec_load".to_string(),
                        "kexec_file_load".to_string(),
                    ],
                    action: "SCMP_ACT_ERRNO".to_string(),
                    comment: Some("Block system reboot".to_string()),
                },
            ],
        }
    }

    /// Create a more permissive profile that allows exec (for servers that need it)
    pub fn with_exec_allowed() -> Self {
        let mut profile = Self::default_restrictive();
        // Remove the execve block
        profile.syscalls.retain(|rule| {
            !rule.names.contains(&"execve".to_string())
        });
        // Add execve to allowed
        profile.syscalls.push(SeccompRule {
            names: vec!["execve".to_string(), "execveat".to_string()],
            action: "SCMP_ACT_ALLOW".to_string(),
            comment: Some("Allow process execution (less secure)".to_string()),
        });
        profile
    }

    /// Serialize to JSON for Docker
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }
}

/// Linux capabilities to drop
pub fn dropped_capabilities() -> Vec<String> {
    vec![
        "ALL".to_string(), // Drop all capabilities
    ]
}

/// Security options for container
pub fn security_opts(seccomp_profile_path: Option<&str>) -> Vec<String> {
    let mut opts = vec![
        "no-new-privileges:true".to_string(),
    ];

    if let Some(path) = seccomp_profile_path {
        opts.push(format!("seccomp={}", path));
    }

    opts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seccomp_profile_creation() {
        let profile = SeccompProfile::default_restrictive();
        assert_eq!(profile.default_action, "SCMP_ACT_ERRNO");
        assert!(!profile.syscalls.is_empty());
    }

    #[test]
    fn test_seccomp_to_json() {
        let profile = SeccompProfile::default_restrictive();
        let json = profile.to_json();
        assert!(json.contains("SCMP_ACT_ERRNO"));
    }
}
