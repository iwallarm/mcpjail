//! Proxy error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("Invalid JSON-RPC message: {0}")]
    InvalidMessage(String),

    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    #[error("Tool blocked by policy: {0}")]
    ToolBlocked(String),

    #[error("Path blocked by policy: {0}")]
    PathBlocked(String),

    #[error("Network access blocked: {0}")]
    NetworkBlocked(String),

    #[error("Parse error: {0}")]
    ParseError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Policy error: {0}")]
    Policy(#[from] mcpjail_policy::PolicyError),
}
