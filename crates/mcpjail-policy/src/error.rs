//! Policy error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Failed to parse policy file: {0}")]
    ParseError(String),

    #[error("Policy file not found: {0}")]
    NotFound(String),

    #[error("Invalid policy configuration: {0}")]
    InvalidConfig(String),

    #[error("Tool '{0}' is blocked by policy")]
    ToolBlocked(String),

    #[error("Path '{0}' is not allowed by policy")]
    PathNotAllowed(String),

    #[error("Network access denied: {0}")]
    NetworkDenied(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
