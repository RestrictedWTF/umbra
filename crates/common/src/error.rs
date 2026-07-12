use thiserror::Error;
use serde::{Serialize, Deserialize};

#[derive(Error, Debug, Clone, Serialize, Deserialize)]
pub enum DebugError {
    #[error("Windows COM error: {message}")]
    Com { message: String },
    #[error("DbgEng operation failed: {message}")]
    DbgEng { message: String },
    #[error("Session not found: {id}")]
    SessionNotFound { id: String },
    #[error("Not attached to any target")]
    NotAttached,
    #[error("Invalid parameter: {message}")]
    InvalidParameter { message: String },
    #[error("Operation timed out")]
    Timeout,
    #[error("Operation not supported: {message}")]
    NotSupported { message: String },
    #[error("Target error: {message}")]
    Target { message: String },
}

pub type Result<T> = std::result::Result<T, DebugError>;

#[cfg(target_os = "windows")]
impl From<windows::core::Error> for DebugError {
    fn from(e: windows::core::Error) -> Self {
        DebugError::Com { message: e.to_string() }
    }
}

impl From<serde_json::Error> for DebugError {
    fn from(e: serde_json::Error) -> Self {
        DebugError::InvalidParameter { message: e.to_string() }
    }
}

impl From<std::io::Error> for DebugError {
    fn from(e: std::io::Error) -> Self {
        DebugError::Target { message: e.to_string() }
    }
}
