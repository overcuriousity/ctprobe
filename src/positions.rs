use anyhow::Result;
use redb::{Database, ReadableTable, TableDefinition};
use std::path::Path;
use std::sync::Arc;

use crate::types::LogId;

const POSITIONS: TableDefinition<u16, u64> = TableDefinition::new("positions");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

/// Opens the single redb file shared by registry, positions and nightly state.
pub fn open_db(path: &Path) -> Result<Arc<Database>> {
    Ok(Arc::new(Database::create(path)?))
}

pub struct Positions {
    db: Arc<Database>,
}

impl Positions {
    pub fn new(db: Arc<Database>) -> Self {
        Positions { db }
    }

    pub fn get(&self, log: LogId) -> Result<Option<u64>> {
        let tx = self.db.begin_read()?;
        match tx.open_table(POSITIONS) {
            Ok(t) => Ok(t.get(log)?.map(|v| v.value())),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn commit(&self, updates: &[(LogId, u64)]) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(POSITIONS)?;
            for (log, pos) in updates {
                t.insert(*log, *pos)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// The commit point: positions and epoch change together.
    pub fn commit_epoch(&self, updates: &[(LogId, u64)], epoch: u64) -> Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(POSITIONS)?;
            for (log, pos) in updates {
                t.insert(*log, *pos)?;
            }
            tx.open_table(META)?.insert("epoch", epoch)?;
        }
        tx.commit()?;
        Ok(())
    }

    pub fn epoch(&self) -> Result<u64> {
        let tx = self.db.begin_read()?;
        match tx.open_table(META) {
            Ok(t) => Ok(t.get("epoch")?.map_or(0, |v| v.value())),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    pub fn all(&self) -> Result<Vec<(LogId, u64)>> {
        let tx = self.db.begin_read()?;
        let t = match tx.open_table(POSITIONS) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(vec![]),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::new();
        for row in t.iter()? {
            let (k, v) = row?;
            out.push((k.value(), v.value()));
        }
        Ok(out)
    }
}
