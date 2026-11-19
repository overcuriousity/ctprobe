//! The key-value store: one fjall database in `<data>/kv` for everything that
//! is looked up by key. Registry, positions, the DNS retry queue, the last
//! answer per name and the address index each have a keyspace in it. Keys are
//! big-endian wherever their order matters.

use anyhow::{Context, Result};
use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode};
use std::path::Path;

pub const DIR: &str = "kv";
/// Block cache shared by all keyspaces.
pub const DEFAULT_CACHE: u64 = 256 << 20;

pub type Db = Database;

pub fn open_db(path: &Path) -> Result<Db> {
    open_db_with(path, DEFAULT_CACHE)
}

pub fn open_db_with(path: &Path, cache_bytes: u64) -> Result<Db> {
    Database::builder(path).cache_size(cache_bytes).open().with_context(|| format!("opening {}", path.display()))
}

pub fn keyspace(db: &Db, name: &str) -> Result<Keyspace> {
    Ok(db.keyspace(name, KeyspaceCreateOptions::default)?)
}

/// A batch that is on disk when `commit` returns.
pub fn durable(db: &Db) -> fjall::OwnedWriteBatch {
    db.batch().durability(Some(PersistMode::SyncAll))
}

pub fn u64_of(b: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(b.try_into().ok()?))
}
