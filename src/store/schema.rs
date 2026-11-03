use arrow::datatypes::{DataType, Field, Schema, SchemaRef, TimeUnit};
use std::sync::{Arc, OnceLock};

fn ts() -> DataType {
    DataType::Timestamp(TimeUnit::Millisecond, None)
}

fn list() -> DataType {
    DataType::List(Arc::new(Field::new_list_field(DataType::Utf8, true)))
}

macro_rules! schema {
    ($name:ident, [$(($col:literal, $ty:expr, $null:expr)),* $(,)?]) => {
        pub fn $name() -> SchemaRef {
            static S: OnceLock<SchemaRef> = OnceLock::new();
            S.get_or_init(|| Arc::new(Schema::new(vec![$(Field::new($col, $ty, $null)),*]))).clone()
        }
    };
}

use DataType::{Boolean, Date32, Float64, Int32, Int64, UInt64, Utf8};

schema!(certs_schema, [
    ("seen_at", ts(), false),
    ("not_before", ts(), false),
    ("not_after", ts(), false),
    ("issuer_cn", Utf8, false),
    ("issuer_org", Utf8, false),
    ("serial", Utf8, false),
    ("cn", Utf8, true),
    ("names", list(), false),
    ("reg_domains", list(), false),
    ("primary_domain", Utf8, true),
    ("tld", Utf8, true),
    ("san_count", Int32, false),
    ("depth", Int32, false),
    ("key_type", Utf8, false),
    ("key_bits", Int32, false),
    ("sig_type", Utf8, false),
    ("is_precert", Boolean, false),
    ("is_wildcard", Boolean, false),
    ("renewal", Utf8, false),
    ("days_since_seen", Int32, true),
    ("new_names", Int32, false),
    ("new_domains", Int32, false),
    ("log_id", Int32, false),
    ("entry_index", Int64, false),
    ("der_size", Int32, false),
    ("sct_lag_ms", Int64, false),
    ("not_before_lag_ms", Int64, false),
    ("cert_hash", UInt64, false),
]);

schema!(sightings_schema, [
    ("cert_hash", UInt64, false),
    ("log_id", Int32, false),
    ("seen_at", ts(), false),
]);

schema!(rollup_minute_schema, [
    ("minute", ts(), false),
    ("log_id", Int32, false),
    ("entries", Int64, false),
    ("bytes", Int64, false),
    ("errors", Int64, false),
    ("malformed", Int64, false),
    ("http_429", Int64, false),
    ("busy_ms", Int64, false),
    ("peak_per_sec", Int64, false),
    ("sct_lag_p50_ms", Int64, true),
    ("sct_lag_p99_ms", Int64, true),
    ("nb_lag_p50_ms", Int64, true),
    ("nb_lag_p99_ms", Int64, true),
    ("tracker_names", Int64, true),
    ("tracker_bytes", Int64, true),
    ("rss_bytes", Int64, true),
    ("cpu_ms", Int64, true),
    ("disk_bytes", Int64, true),
    ("raw_entries", Int64, true),
    ("backlog", Int64, true),
    ("limited_backlog", Int64, true),
    ("healthy_logs", Int64, true),
]);

schema!(rollup_daily_schema, [
    ("day", Date32, false),
    ("issuer_cn", Utf8, false),
    ("issuer_org", Utf8, false),
    ("tld", Utf8, true),
    ("key_type", Utf8, false),
    ("validity_bucket", Utf8, false),
    ("renewal", Utf8, false),
    ("certs", Int64, false),
    ("sans", Int64, false),
    ("new_names", Int64, false),
    ("new_domains", Int64, false),
]);

schema!(daily_stages_schema, [
    ("day", Date32, false),
    ("raw_entries", Int64, false),
    ("unique_certs", Int64, false),
    ("names", Int64, false),
    ("new_names", Int64, false),
    ("new_domains", Int64, false),
]);

schema!(daily_top_schema, [
    ("day", Date32, false),
    ("kind", Utf8, false),
    ("rank", Int32, false),
    ("key", Utf8, false),
    ("certs", Int64, false),
    ("day_total", Int64, false),
]);

schema!(daily_coverage_schema, [
    ("day", Date32, false),
    ("n", Int32, false),
    ("log_id", Int32, false),
    ("added_certs", Int64, false),
    ("cumulative_certs", Int64, false),
    ("cumulative_pct", Float64, false),
]);

schema!(domains_schema, [
    ("domain", Utf8, false),
    ("skeleton", Utf8, false),
    ("first_seen", ts(), false),
    ("last_seen", ts(), false),
    ("cert_count", Int64, false),
]);

schema!(dns_schema, [
    ("probed_at", ts(), false),
    ("name", Utf8, false),
    ("kind", Utf8, false),
    ("reg_domain", Utf8, true),
    ("cert_hash", UInt64, false),
    ("cert_seen_at", ts(), false),
    ("attempt", Int32, false),
    ("renewal", Utf8, false),
    ("status", Utf8, false),
    ("v4", list(), false),
    ("v6", list(), false),
    ("cnames", list(), false),
    ("ttl", Int64, true),
    ("latency_ms", Int32, false),
    ("last_miss_at", ts(), true),
    ("prev_days", Int32, true),
    ("prev_status", Utf8, true),
    ("prev_v4", list(), true),
    ("prev_v6", list(), true),
    ("prev_complete", Boolean, true),
    ("changed", Boolean, true),
    ("status_changed", Boolean, true),
    ("v4_changed", Boolean, true),
    ("v6_changed", Boolean, true),
    ("cname_changed", Boolean, true),
    ("network_changed", Boolean, true),
]);

schema!(dns_minute_schema, [
    ("minute", ts(), false),
    ("probes", Int64, false),
    ("first_probes", Int64, false),
    ("first_resolved", Int64, false),
    ("first_v4", Int64, false),
    ("first_v6", Int64, false),
    ("first_nodata", Int64, false),
    ("first_nxdomain", Int64, false),
    ("first_failed", Int64, false),
    ("resolved_later", Int64, false),
    ("never", Int64, false),
    ("compared", Int64, false),
    ("changed", Int64, false),
    ("v4_compared", Int64, false),
    ("v4_changed", Int64, false),
    ("v6_compared", Int64, false),
    ("v6_changed", Int64, false),
    ("network_changed", Int64, false),
    ("skipped", Int64, false),
    ("ttd_p50_ms", Int64, true),
    ("ttd_p90_ms", Int64, true),
    // Added after the first release, so older files read them as null.
    ("found_15m", Int64, true),
    ("found_1h", Int64, true),
    ("found_1d", Int64, true),
    ("found_later", Int64, true),
    ("queries", Int64, true),
]);
