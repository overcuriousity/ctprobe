mod leaf;
mod x509;

pub use leaf::{
    decode_merkle_leaf, decode_tile, decode_timestamped_entry, EntryKind, TileEntry,
    TimestampedEntryView,
};
pub use x509::extract;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("truncated entry")]
    Truncated,
    #[error("unsupported leaf: {0}")]
    Unsupported(&'static str),
    #[error("invalid certificate: {0}")]
    X509(String),
}
