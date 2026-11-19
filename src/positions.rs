use anyhow::Result;
use fjall::Keyspace;

pub use crate::kv::open_db;
use crate::kv::{durable, keyspace, u64_of, Db};
use crate::types::LogId;

const EPOCH: &[u8] = b"epoch";

pub struct Positions {
    db: Db,
    positions: Keyspace,
    meta: Keyspace,
}

impl Positions {
    pub fn new(db: Db) -> Result<Self> {
        let positions = keyspace(&db, "positions")?;
        let meta = keyspace(&db, "meta")?;
        Ok(Positions { db, positions, meta })
    }

    pub fn get(&self, log: LogId) -> Result<Option<u64>> {
        Ok(self.positions.get(log.to_be_bytes())?.and_then(|v| u64_of(&v)))
    }

    pub fn commit(&self, updates: &[(LogId, u64)]) -> Result<()> {
        let mut b = durable(&self.db);
        for (log, pos) in updates {
            b.insert(&self.positions, log.to_be_bytes(), pos.to_be_bytes());
        }
        b.commit()?;
        Ok(())
    }

    /// The commit point: positions and epoch change together.
    pub fn commit_epoch(&self, updates: &[(LogId, u64)], epoch: u64) -> Result<()> {
        let mut b = durable(&self.db);
        for (log, pos) in updates {
            b.insert(&self.positions, log.to_be_bytes(), pos.to_be_bytes());
        }
        b.insert(&self.meta, EPOCH, epoch.to_be_bytes());
        b.commit()?;
        Ok(())
    }

    pub fn epoch(&self) -> Result<u64> {
        Ok(self.meta.get(EPOCH)?.and_then(|v| u64_of(&v)).unwrap_or(0))
    }

    pub fn all(&self) -> Result<Vec<(LogId, u64)>> {
        let mut out = Vec::new();
        for row in self.positions.iter() {
            let (k, v) = row.into_inner()?;
            if let (Ok(k), Some(v)) = (k.as_ref().try_into(), u64_of(&v)) {
                out.push((LogId::from_be_bytes(k), v));
            }
        }
        Ok(out)
    }
}
