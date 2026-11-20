use anyhow::Result;
use fjall::Keyspace;

pub use crate::kv::open_db;
use crate::kv::{durable, keyspace, u64_of, Db};
use crate::types::LogId;

const EPOCH: &[u8] = b"epoch";
const FINAL_THROUGH: &[u8] = b"final_through";

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

    /// The commit point: positions, epoch and the time every certificate
    /// up to which is committed change together.
    pub fn commit_epoch(&self, updates: &[(LogId, u64)], epoch: u64, final_through_ms: i64) -> Result<()> {
        let mut b = durable(&self.db);
        for (log, pos) in updates {
            b.insert(&self.positions, log.to_be_bytes(), pos.to_be_bytes());
        }
        b.insert(&self.meta, EPOCH, epoch.to_be_bytes());
        b.insert(&self.meta, FINAL_THROUGH, (final_through_ms.max(0) as u64).to_be_bytes());
        b.commit()?;
        Ok(())
    }

    pub fn epoch(&self) -> Result<u64> {
        Ok(self.meta.get(EPOCH)?.and_then(|v| u64_of(&v)).unwrap_or(0))
    }

    /// `final_through` of the last commit, 0 before the first.
    pub fn final_through(&self) -> Result<i64> {
        Ok(self.meta.get(FINAL_THROUGH)?.and_then(|v| u64_of(&v)).unwrap_or(0) as i64)
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
