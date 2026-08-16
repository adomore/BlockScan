use thiserror::Error;

#[derive(Error, Debug)]
pub enum AppError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("RPC error: {0}")]
    Rpc(String),

    #[error("Etherscan API error: {0}")]
    Etherscan(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("invalid address: {0}")]
    Address(String),
}

pub type Result<T> = std::result::Result<T, AppError>;
