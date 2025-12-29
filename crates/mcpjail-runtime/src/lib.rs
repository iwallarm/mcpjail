//! MCP Jail Runtime - Docker container management for MCP servers
//!
//! Provides hardened container configuration and execution for MCP servers.
//! https://mcpjail.com

mod container;
mod security;
mod error;
pub mod macos_sandbox;

pub use container::*;
pub use security::*;
pub use error::*;
pub use macos_sandbox::{is_macos, is_sandbox_available, generate_sandbox_profile, write_sandbox_profile, create_sandboxed_command, cleanup_profile};
