//! PE loader — parse and map Windows PE32/PE32+ executables into memory.
//!
//! # Workflow
//!
//! ```text
//! File bytes → parser::ParsedPe → mapper::MappedImage
//!                                    ↓
//!                          relocations::apply()
//!                                    ↓
//!                          imports::enumerate()
//! ```

pub mod imports;
pub mod mapper;
pub mod parser;
pub mod relocations;

use thiserror::Error;

/// Errors returned by the PE loader subsystem.
#[derive(Debug, Error)]
pub enum PeError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("not a valid PE file: {0}")]
    InvalidPe(String),

    #[error("unsupported PE format: {0}")]
    Unsupported(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("mapping error: {0}")]
    Mapping(String),

    #[error("relocation error: {0}")]
    Relocation(String),
}

pub type PeResult<T> = Result<T, PeError>;
