//! Runtime error types

use thiserror::Error;

#[derive(Error, Debug)]
pub enum RuntimeError {
    #[error("Docker error: {0}")]
    Docker(#[from] bollard::errors::Error),

    #[error("Container not found: {0}")]
    ContainerNotFound(String),

    #[error("Container failed to start: {0}")]
    StartFailed(String),

    #[error("Container execution timeout")]
    Timeout,

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}
