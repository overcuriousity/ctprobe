//! Read-only access for the web layer. Queries run on their own small runtime,
//! so they cannot starve ingest.

pub mod buckets;
mod search;
mod sql;

pub use search::{DomainHit, Mode};
pub use sql::{quote, CertFilter, CertPage, CertScope, DnsFilter, QueryError, QueryResult, SortKey, MAX_OFFSET};

use anyhow::Result;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;
use tokio::runtime::Handle;
use tokio::sync::Semaphore;

const MAX_CONCURRENT: usize = 2;
const QUERY_THREADS: usize = 2;
pub const SQL_TIMEOUT: Duration = Duration::from_secs(30);

pub struct QueryEngine {
    data: PathBuf,
    rt: Handle,
    limiter: Arc<Semaphore>,
    timeout: Duration,
    index: RwLock<Option<search::SearchIndex>>,
}

impl QueryEngine {
    pub fn open(data: &Path) -> Result<QueryEngine> {
        // Lives as long as the process; a runtime cannot drop inside async code.
        let rt = Box::leak(Box::new(
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(QUERY_THREADS)
                .thread_name("ctprobe-query")
                .enable_all()
                .build()?,
        ));
        Ok(QueryEngine {
            data: data.to_path_buf(),
            rt: rt.handle().clone(),
            limiter: Arc::new(Semaphore::new(MAX_CONCURRENT)),
            timeout: SQL_TIMEOUT,
            index: RwLock::new(None),
        })
    }

    pub fn set_timeout(&mut self, t: Duration) {
        self.timeout = t;
    }

    pub fn data_dir(&self) -> &Path {
        &self.data
    }
}
