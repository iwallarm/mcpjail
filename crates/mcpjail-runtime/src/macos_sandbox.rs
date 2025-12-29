//! macOS Sandbox (Seatbelt) support
//!
//! Uses sandbox-exec to isolate MCP servers when Docker is not available.
//! https://mcpjail.com

use crate::error::RuntimeError;
use mcpjail_policy::{Policy, NetworkMode, FilesystemMode};
use std::path::Path;
use std::process::Stdio;
use tokio::process::Command;
use tracing::{debug, info};

/// Check if we're running on macOS
pub fn is_macos() -> bool {
    cfg!(target_os = "macos")
}

/// Check if sandbox-exec is available
pub async fn is_sandbox_available() -> bool {
    if !is_macos() {
        return false;
    }

    // Check if sandbox-exec exists
    Command::new("which")
        .arg("sandbox-exec")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Generate a Seatbelt sandbox profile from a Policy
pub fn generate_sandbox_profile(policy: &Policy, workspace: Option<&str>) -> String {
    let mut profile = String::new();

    // Version declaration
    profile.push_str("(version 1)\n");
    profile.push_str("(deny default)\n\n");

    // Essential process operations
    profile.push_str("; Essential process operations\n");
    profile.push_str("(allow process-exec*)\n");
    profile.push_str("(allow process-fork)\n");
    profile.push_str("(allow signal)\n");
    profile.push_str("(allow process-info*)\n\n");

    // Essential system access
    profile.push_str("; Essential system access\n");
    profile.push_str("(allow sysctl-read)\n");
    profile.push_str("(allow user-preference-read)\n");
    profile.push_str("(allow mach-lookup)\n\n");  // Allow all mach lookups for compatibility

    // Device files
    profile.push_str("; Device files\n");
    profile.push_str("(allow file-read*\n");
    profile.push_str("    (literal \"/dev/null\")\n");
    profile.push_str("    (literal \"/dev/zero\")\n");
    profile.push_str("    (literal \"/dev/random\")\n");
    profile.push_str("    (literal \"/dev/urandom\")\n");
    profile.push_str("    (literal \"/dev/tty\"))\n\n");

    profile.push_str("(allow file-write*\n");
    profile.push_str("    (literal \"/dev/null\")\n");
    profile.push_str("    (literal \"/dev/tty\"))\n\n");

    // System libraries and frameworks (required for any process)
    profile.push_str("; System libraries and frameworks\n");
    profile.push_str("(allow file-read*\n");
    profile.push_str("    (subpath \"/usr/lib\")\n");
    profile.push_str("    (subpath \"/usr/local/lib\")\n");
    profile.push_str("    (subpath \"/usr/share\")\n");
    profile.push_str("    (subpath \"/usr/local/share\")\n");
    profile.push_str("    (subpath \"/System/Library\")\n");
    profile.push_str("    (subpath \"/Library/Frameworks\")\n");
    profile.push_str("    (subpath \"/Library/Preferences\")\n");
    profile.push_str("    (subpath \"/private/var/db\")\n");
    profile.push_str("    (subpath \"/opt/homebrew\")\n");  // M1 Mac Homebrew
    profile.push_str("    (subpath \"/usr/local/Cellar\")\n");  // Intel Mac Homebrew
    profile.push_str("    (subpath \"/usr/local/opt\")\n");
    profile.push_str("    (literal \"/\")\n");
    profile.push_str("    (literal \"/etc\")\n");
    profile.push_str("    (literal \"/tmp\")\n");
    profile.push_str("    (literal \"/var\")\n");
    profile.push_str("    (literal \"/private\")\n");
    profile.push_str("    (literal \"/private/etc\")\n");
    profile.push_str("    (literal \"/private/tmp\")\n");
    profile.push_str("    (literal \"/private/var\"))\n\n");

    // Executables
    profile.push_str("; Executables\n");
    profile.push_str("(allow file-read*\n");
    profile.push_str("    (subpath \"/usr/bin\")\n");
    profile.push_str("    (subpath \"/usr/local/bin\")\n");
    profile.push_str("    (subpath \"/bin\")\n");
    profile.push_str("    (subpath \"/sbin\")\n");
    profile.push_str("    (subpath \"/opt/homebrew/bin\"))\n\n");

    // Node.js / npm / npx paths
    profile.push_str("; Node.js and npm\n");
    profile.push_str("(allow file-read*\n");
    profile.push_str("    (subpath \"/usr/local/lib/node_modules\")\n");
    profile.push_str("    (subpath \"/opt/homebrew/lib/node_modules\")\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.npm\")\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.node\")\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.nvm\"))\n\n");

    // Python paths
    profile.push_str("; Python\n");
    profile.push_str("(allow file-read*\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.pyenv\")\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.local/lib/python\"))\n\n");

    // Temp directories - always allow write
    profile.push_str("; Temp directories (write allowed)\n");
    profile.push_str("(allow file-read* file-write*\n");
    profile.push_str("    (subpath \"/tmp\")\n");
    profile.push_str("    (subpath \"/private/tmp\")\n");
    profile.push_str("    (regex #\"^/private/var/folders/\"))\n\n");

    // npm cache write
    profile.push_str("; npm/node cache (write allowed)\n");
    profile.push_str("(allow file-read* file-write*\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.npm/_cacache\"))\n\n");

    // Block sensitive paths BEFORE allowing home directory
    profile.push_str("; BLOCK sensitive paths (before any home access)\n");
    profile.push_str("(deny file-read* file-write*\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.ssh\")\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.aws\")\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.gnupg\")\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.gcloud\")\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.azure\")\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.docker\")\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.kube\")\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.config/gcloud\")\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.netrc\")\n");
    profile.push_str("    (regex #\"^/Users/[^/]+/\\.git-credentials\")\n");
    profile.push_str("    (regex #\"\\.env$\")\n");
    profile.push_str("    (regex #\"\\.env\\.local$\")\n");
    profile.push_str("    (regex #\"\\.env\\.production$\")\n");
    profile.push_str("    (regex #\"secrets?\\.ya?ml$\")\n");
    profile.push_str("    (regex #\"credentials\\.json$\"))\n\n");

    // Workspace access based on policy
    if let Some(ws) = workspace {
        match policy.filesystem.mode {
            FilesystemMode::None => {
                profile.push_str("; Filesystem: NONE - no workspace access\n");
            }
            FilesystemMode::Explicit => {
                profile.push_str("; Filesystem: EXPLICIT - specific mounts only\n");
                for mount in &policy.filesystem.mounts {
                    let mode = if mount.mode == "rw" { "file-read* file-write*" } else { "file-read*" };
                    profile.push_str(&format!("(allow {}\n    (subpath \"{}\"))\n", mode, mount.path));
                }
            }
            FilesystemMode::Workspace => {
                profile.push_str("; Filesystem: WORKSPACE - read-only workspace\n");
                profile.push_str(&format!("(allow file-read*\n    (subpath \"{}\"))\n", ws));
            }
        }
        profile.push('\n');
    }

    // Network access based on policy
    profile.push_str("; Network access\n");
    match policy.network.mode {
        NetworkMode::None => {
            profile.push_str("(deny network*)\n");
        }
        NetworkMode::Allowlist => {
            profile.push_str("(deny network*)\n");
            // Allow localhost for potential IPC
            profile.push_str("(allow network* (remote ip \"localhost:*\"))\n");
            profile.push_str("(allow network* (remote ip \"127.0.0.1:*\"))\n");
            // Note: sandbox-exec doesn't support hostname-based allowlists well
            // The proxy layer will handle host validation
        }
        NetworkMode::Host => {
            profile.push_str("(allow network*)\n");
        }
    }
    profile.push('\n');

    // Pty/tty for stdio
    profile.push_str("; Terminal/PTY for stdio\n");
    profile.push_str("(allow file-ioctl)\n");

    profile
}

/// Write sandbox profile to a temporary file
pub fn write_sandbox_profile(profile: &str) -> Result<std::path::PathBuf, RuntimeError> {
    use std::io::Write;

    let temp_dir = std::env::temp_dir();
    let profile_path = temp_dir.join(format!("mcpjail-{}.sb", std::process::id()));

    let mut file = std::fs::File::create(&profile_path)
        .map_err(|e| RuntimeError::Io(e))?;

    file.write_all(profile.as_bytes())
        .map_err(|e| RuntimeError::Io(e))?;

    debug!("Wrote sandbox profile to: {:?}", profile_path);
    Ok(profile_path)
}

/// Create a sandboxed command using sandbox-exec
pub fn create_sandboxed_command(
    profile_path: &Path,
    command: &[String],
) -> Command {
    let mut cmd = Command::new("sandbox-exec");
    cmd.arg("-f")
        .arg(profile_path)
        .arg("--")
        .args(command);

    cmd
}

/// Clean up sandbox profile
pub fn cleanup_profile(profile_path: &Path) {
    if let Err(e) = std::fs::remove_file(profile_path) {
        debug!("Failed to clean up sandbox profile: {}", e);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mcpjail_policy::get_builtin_policy;

    #[test]
    fn test_generate_profile_strict() {
        let policy = get_builtin_policy("strict").unwrap();
        let profile = generate_sandbox_profile(&policy, Some("/tmp/workspace"));

        assert!(profile.contains("(version 1)"));
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains(".ssh"));
        assert!(profile.contains(".aws"));
    }

    #[test]
    fn test_generate_profile_development() {
        let policy = get_builtin_policy("development").unwrap();
        let profile = generate_sandbox_profile(&policy, Some("/tmp/workspace"));

        assert!(profile.contains("(version 1)"));
        // Development policy might allow network
    }
}
