use arrow::array::{AsArray, RecordBatch};
use chrono::NaiveDate;
use ctprobe::config::Config;
use ctprobe::nightly::{self, archive::{self, Outcome}};
use ctprobe::store::{archive_file, list_archive, Writer};
use ctprobe::types::{CertRow, ParsedCert, RenewalClass};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::path::Path;

const DAY_MS: i64 = 86_400_000;
const D: i64 = 20_000 * DAY_MS; // 2024-10-04

fn day() -> NaiveDate {
    NaiveDate::from_ymd_opt(2024, 10, 4).unwrap()
}

fn cfg(dir: &Path) -> Config {
    Config {
        bind: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.to_path_buf(),
        disk_budget_bytes: 1 << 30,
        tracker_max_bytes: 1 << 20,
        include_logs: vec![],
        exclude_logs: vec![],
        log_list_url: String::new(),
        extra_log_lists: vec![],
        include_test_logs: false,
        coverage_target: 95.0,
        dns: Default::default(),
        hot_days: None,
        dns_days: None,
        archive_budget_bytes: None,
    }
}

fn row(serial: &str, domain: &str, seen: i64, issuer: &str, days: i64, renewal: RenewalClass) -> CertRow {
    CertRow {
        parsed: ParsedCert {
            issuer_cn: issuer.into(),
            issuer_org: "Org".into(),
            issuer_der: vec![],
            serial_hex: serial.into(),
            subject_cn: Some(domain.into()),
            names: vec![domain.into(), format!("www.{domain}")],
            san_count: 2,
            key_type: "ecdsa".into(),
            key_bits: 256,
            sig_type: "ecdsa-sha256".into(),
            not_before_ms: seen,
            not_after_ms: seen + days * DAY_MS,
        },
        reg_domains: vec![domain.into()],
        primary_domain: Some(domain.into()),
        is_wildcard: false,
        is_precert: false,
        renewal,
        days_since_seen: None,
        new_names: 2,
        new_domains: 1,
        log: 0,
        index: 1,
        der_size: 100,
        seen_at_ms: seen,
        sct_lag_ms: 1,
        not_before_lag_ms: 1,
        cert_hash: 0,
    }
}


fn seed_certs(dir: &Path, rows: Vec<CertRow>) {
    let mut w = Writer::open(dir, 0).unwrap();
    for r in rows {
        w.push_cert(r);
    }
    w.flush(1).unwrap();
    w.publish(1).unwrap();
}

fn multi(serial: &str, names: &[&str], regs: &[&str], primary: Option<&str>, seen: i64) -> CertRow {
    let mut r = row(serial, "x.com", seen, "LE", 90, RenewalClass::New);
    r.parsed.names = names.iter().map(|s| s.to_string()).collect();
    r.reg_domains = regs.iter().map(|s| s.to_string()).collect();
    r.primary_domain = primary.map(str::to_string);
    r
}

fn read_file(p: &Path) -> RecordBatch {
    let f = std::fs::File::open(p).unwrap();
    let b: Vec<_> = ParquetRecordBatchReaderBuilder::try_new(f).unwrap().build().unwrap().map(|b| b.unwrap()).collect();
    arrow::compute::concat_batches(&b[0].schema(), &b).unwrap()
}

fn strings(b: &RecordBatch, c: &str) -> Vec<Option<String>> {
    b.column_by_name(c).unwrap().as_string::<i32>().iter().map(|s| s.map(str::to_string)).collect()
}

const DAY: &str = "2024-10-04";

#[tokio::test(flavor = "multi_thread")]
async fn one_row_per_registered_domain() {
    let d = tempfile::tempdir().unwrap();
    seed_certs(d.path(), vec![multi("1", &["a.one.com", "*.one.com", "b.two.org"], &["one.com", "two.org"], Some("one.com"), D)]);
    let o = archive::certs(d.path(), DAY, u64::MAX).await.unwrap();
    assert!(matches!(o, Outcome::Written { rows: 2, .. }), "{o:?}");
    let b = read_file(&archive_file(d.path(), "certs", DAY));
    assert_eq!(b.num_rows(), 2);
    assert_eq!(strings(&b, "reg_domain"), vec![Some("one.com".into()), Some("two.org".into())]);
    assert_eq!(strings(&b, "primary_domain"), vec![None, Some("one.com".into())]);
    let names = b.column_by_name("names").unwrap().as_list::<i32>();
    let row = |i: usize| -> Vec<String> {
        names.value(i).as_string::<i32>().iter().flatten().map(str::to_string).collect()
    };
    assert_eq!(row(0), vec!["*.one.com", "a.one.com"]);
    assert_eq!(row(1), vec!["b.two.org"]);
    assert_eq!(b.schema(), ctprobe::store::archive_certs_schema());
}

#[tokio::test(flavor = "multi_thread")]
async fn no_registered_domain_no_row() {
    let d = tempfile::tempdir().unwrap();
    seed_certs(d.path(), vec![multi("1", &["localhost"], &[], None, D)]);
    assert_eq!(archive::certs(d.path(), DAY, u64::MAX).await.unwrap(), Outcome::Empty);
    assert!(list_archive(d.path(), "certs").is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn no_hot_files_is_empty() {
    let d = tempfile::tempdir().unwrap();
    assert_eq!(archive::certs(d.path(), DAY, u64::MAX).await.unwrap(), Outcome::Empty);
}

#[tokio::test(flavor = "multi_thread")]
async fn sorted_with_bloom() {
    let d = tempfile::tempdir().unwrap();
    let rows = ["zeta.com", "alpha.org", "mid.net", "alpha.org", "beta.io"]
        .iter()
        .enumerate()
        .map(|(i, n)| row(&i.to_string(), n, D + i as i64, "LE", 90, RenewalClass::New))
        .collect();
    seed_certs(d.path(), rows);
    archive::certs(d.path(), DAY, u64::MAX).await.unwrap();
    let p = archive_file(d.path(), "certs", DAY);
    let b = read_file(&p);
    let v = strings(&b, "reg_domain");
    assert!(v.windows(2).all(|w| w[0] <= w[1]), "{v:?}");
    let r = parquet::file::reader::SerializedFileReader::new(std::fs::File::open(&p).unwrap()).unwrap();
    use parquet::file::reader::FileReader;
    let rg = r.metadata().row_group(0);
    let idx = rg.columns().iter().position(|c| c.column_path().string() == "reg_domain").unwrap();
    assert!(rg.column(idx).bloom_filter_offset().is_some());
}

#[tokio::test(flavor = "multi_thread")]
async fn budget_full_writes_nothing() {
    let d = tempfile::tempdir().unwrap();
    seed_certs(d.path(), vec![row("1", "a.com", D, "LE", 90, RenewalClass::New)]);
    let other = archive_file(d.path(), "certs", "2024-10-03");
    std::fs::create_dir_all(other.parent().unwrap()).unwrap();
    std::fs::write(&other, b"existing").unwrap();
    assert_eq!(archive::certs(d.path(), DAY, 1).await.unwrap(), Outcome::BudgetFull);
    assert!(!archive_file(d.path(), "certs", DAY).exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn budget_full_sets_no_marker_and_stays_pending() {
    let d = tempfile::tempdir().unwrap();
    seed_certs(d.path(), vec![row("1", "a.com", D, "LE", 90, RenewalClass::New)]);
    let other = archive_file(d.path(), "certs", "2024-10-03");
    std::fs::create_dir_all(other.parent().unwrap()).unwrap();
    std::fs::write(&other, b"existing").unwrap();
    let mut c = cfg(d.path());
    c.archive_budget_bytes = Some(1);
    nightly::run_nightly(&c, day()).await.unwrap();
    assert!(!d.path().join("nightly").join(format!("{DAY}.archive")).exists());
    assert!(!archive_file(d.path(), "certs", DAY).exists());
    let today = NaiveDate::from_ymd_opt(2024, 10, 5).unwrap();
    assert_eq!(nightly::pending_days(d.path(), today, true), vec![day()]);
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_file_is_done_even_over_budget() {
    let d = tempfile::tempdir().unwrap();
    seed_certs(d.path(), vec![row("1", "a.com", D, "LE", 90, RenewalClass::New), row("2", "b.com", D, "LE", 90, RenewalClass::New)]);
    archive::certs(d.path(), DAY, u64::MAX).await.unwrap();
    let f = archive_file(d.path(), "certs", DAY);
    let before = std::fs::read(&f).unwrap();
    let o = archive::certs(d.path(), DAY, 1).await.unwrap();
    assert_eq!(o, Outcome::Written { rows: 2, bytes: before.len() as u64 });
    assert_eq!(std::fs::read(&f).unwrap(), before);
}

#[tokio::test(flavor = "multi_thread")]
async fn rerun_after_crash_is_clean() {
    let d = tempfile::tempdir().unwrap();
    seed_certs(d.path(), vec![row("1", "a.com", D, "LE", 90, RenewalClass::New), row("2", "b.com", D + 1, "LE", 90, RenewalClass::New)]);
    let f = archive_file(d.path(), "certs", DAY);
    std::fs::create_dir_all(f.parent().unwrap()).unwrap();
    std::fs::write(f.with_extension("parquet.tmp"), b"junk").unwrap();
    let a = archive::certs(d.path(), DAY, u64::MAX).await.unwrap();
    let b = archive::certs(d.path(), DAY, u64::MAX).await.unwrap();
    assert!(matches!(a, Outcome::Written { rows: 2, .. }) && matches!(b, Outcome::Written { rows: 2, .. }), "{a:?} {b:?}");
    assert_eq!(a, b);
    assert_eq!(list_archive(d.path(), "certs"), vec![f.clone()]);
    assert_eq!(read_file(&f).num_rows(), 2);
    assert!(!f.with_extension("parquet.tmp").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn existing_hot_days_become_pending() {
    let d = tempfile::tempdir().unwrap();
    for day in ["2024-10-03", "2024-10-04"] {
        std::fs::create_dir_all(d.path().join("certs").join(format!("day={day}"))).unwrap();
        std::fs::create_dir_all(d.path().join("nightly")).unwrap();
        std::fs::write(d.path().join("nightly").join(format!("{day}.domains")), b"").unwrap();
    }
    let today = NaiveDate::from_ymd_opt(2024, 10, 5).unwrap();
    assert_eq!(nightly::pending_days(d.path(), today, true).len(), 2);
    assert!(nightly::pending_days(d.path(), today, false).is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn disabled_writes_no_directory() {
    let d = tempfile::tempdir().unwrap();
    seed_certs(d.path(), vec![row("1", "a.com", D, "LE", 90, RenewalClass::New)]);
    nightly::run_nightly(&cfg(d.path()), day()).await.unwrap();
    assert!(!d.path().join("archive").exists());
}

#[tokio::test(flavor = "multi_thread")]
async fn enabled_run_writes_file_and_marker() {
    let d = tempfile::tempdir().unwrap();
    seed_certs(d.path(), vec![row("1", "a.com", D, "LE", 90, RenewalClass::New)]);
    let mut c = cfg(d.path());
    c.archive_budget_bytes = Some(1 << 30);
    nightly::run_nightly(&c, day()).await.unwrap();
    assert!(archive_file(d.path(), "certs", DAY).exists());
    assert!(d.path().join("nightly").join(format!("{DAY}.archive")).exists());
}

mod retention {
    use chrono::{Duration, NaiveDate};
    use ctprobe::nightly::expire::{enforce, Retention};
    use std::path::Path;

    const BIG: u64 = 1 << 40;

    fn today() -> NaiveDate {
        NaiveDate::from_ymd_opt(2026, 1, 25).unwrap()
    }

    fn name(ago: i64) -> String {
        (today() - Duration::days(ago)).format("%Y-%m-%d").to_string()
    }

    fn put(dir: &Path, table: &str, ago: i64, n: usize) {
        let p = dir.join(table).join(format!("day={}", name(ago)));
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("daily.parquet"), vec![0u8; n]).unwrap();
    }

    fn mark(dir: &Path, ago: i64, step: &str) {
        let p = dir.join("nightly");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join(format!("{}.{step}", name(ago))), b"").unwrap();
    }

    fn has(dir: &Path, table: &str, ago: i64) -> bool {
        dir.join(table).join(format!("day={}", name(ago))).exists()
    }

    fn ret(budget: u64, hot: Option<u32>, dns: Option<u32>, archive: bool) -> Retention {
        Retention { budget, hot_days: hot, dns_days: dns, archive }
    }

    /// A fixed archive that no rule may touch; returns its file list.
    fn archive(dir: &Path) -> Vec<String> {
        let p = dir.join("archive/certs");
        std::fs::create_dir_all(&p).unwrap();
        std::fs::write(p.join("a.parquet"), vec![0u8; 5000]).unwrap();
        listing(dir)
    }

    fn listing(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = std::fs::read_dir(dir.join("archive/certs"))
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn no_keys_behaves_as_before() {
        let d = tempfile::tempdir().unwrap();
        for ago in [1, 2, 3, 4] {
            put(d.path(), "certs", ago, 1000);
            put(d.path(), "dns", ago, 10);
        }
        let r = ret(BIG, None, None, false);
        assert_eq!(enforce(d.path(), &r, today()).unwrap(), None);
        for ago in [1, 2, 3, 4] {
            assert!(has(d.path(), "certs", ago) && has(d.path(), "dns", ago));
        }
        // Over budget: the oldest finished day goes, certs and dns together.
        for ago in [2, 3, 4] {
            mark(d.path(), ago, "domains");
        }
        assert_eq!(enforce(d.path(), &ret(4100, None, None, false), today()).unwrap(), None);
        assert!(!has(d.path(), "certs", 4) && !has(d.path(), "dns", 4));
        assert!(has(d.path(), "certs", 3));
    }

    #[test]
    fn age_removes_old_certs_days() {
        let d = tempfile::tempdir().unwrap();
        for ago in [1, 2, 3, 4] {
            put(d.path(), "certs", ago, 10);
            put(d.path(), "dns", ago, 10);
        }
        put(d.path(), "certs", 0, 10);
        let r = ret(BIG, Some(2), None, false);
        assert_eq!(enforce(d.path(), &r, today()).unwrap(), None);
        for ago in [0, 1, 2] {
            assert!(has(d.path(), "certs", ago), "certs {ago}");
        }
        for ago in [3, 4] {
            assert!(!has(d.path(), "certs", ago), "certs {ago}");
        }
        for ago in [1, 2, 3, 4] {
            assert!(has(d.path(), "dns", ago), "dns {ago}");
        }
    }

    #[test]
    fn age_waits_for_the_archive() {
        let d = tempfile::tempdir().unwrap();
        for ago in [3, 4] {
            put(d.path(), "certs", ago, 10);
        }
        mark(d.path(), 4, "archive");
        let r = ret(BIG, Some(2), None, true);
        assert_eq!(enforce(d.path(), &r, today()).unwrap(), None);
        assert!(!has(d.path(), "certs", 4));
        assert!(has(d.path(), "certs", 3), "not archived yet");
    }

    #[test]
    fn dns_age_waits_for_its_own_marker() {
        let d = tempfile::tempdir().unwrap();
        for ago in [3, 4] {
            put(d.path(), "dns", ago, 10);
            mark(d.path(), ago, "archive");
        }
        let r = ret(BIG, None, Some(2), true);
        assert_eq!(enforce(d.path(), &r, today()).unwrap(), None);
        assert!(has(d.path(), "dns", 3) && has(d.path(), "dns", 4));
        mark(d.path(), 4, "archive-dns");
        enforce(d.path(), &r, today()).unwrap();
        assert!(!has(d.path(), "dns", 4));
        assert!(has(d.path(), "dns", 3));
    }

    #[test]
    fn budget_ignores_archive_bytes() {
        let d = tempfile::tempdir().unwrap();
        let before = archive(d.path());
        put(d.path(), "certs", 3, 1000);
        mark(d.path(), 3, "domains");
        let r = ret(2000, None, None, true);
        assert_eq!(enforce(d.path(), &r, today()).unwrap(), None);
        assert!(has(d.path(), "certs", 3));
        assert_eq!(listing(d.path()), before);
        assert_eq!(ctprobe::metrics::hot_size(d.path()), 1000);
    }

    #[test]
    fn budget_takes_archived_days_first() {
        let d = tempfile::tempdir().unwrap();
        let before = archive(d.path());
        for ago in [2, 3, 4] {
            put(d.path(), "certs", ago, 1000);
            mark(d.path(), ago, "domains");
        }
        mark(d.path(), 3, "archive");
        let r = ret(2300, None, None, true);
        assert_eq!(enforce(d.path(), &r, today()).unwrap(), None);
        assert!(!has(d.path(), "certs", 3), "archived day first");
        assert!(has(d.path(), "certs", 4) && has(d.path(), "certs", 2));
        assert_eq!(listing(d.path()), before);
    }

    #[test]
    fn budget_last_resort_logs_and_removes() {
        let d = tempfile::tempdir().unwrap();
        let before = archive(d.path());
        for ago in [3, 4] {
            put(d.path(), "certs", ago, 1000);
            mark(d.path(), ago, "domains");
        }
        let r = ret(1500, None, None, true);
        assert_eq!(enforce(d.path(), &r, today()).unwrap(), None);
        assert!(!has(d.path(), "certs", 4));
        assert!(has(d.path(), "certs", 3));
        assert_eq!(listing(d.path()), before);
    }

    #[test]
    fn archive_dir_untouched() {
        let d = tempfile::tempdir().unwrap();
        let before = archive(d.path());
        for ago in [0, 1, 5, 9] {
            put(d.path(), "certs", ago, 1000);
            put(d.path(), "dns", ago, 1000);
            mark(d.path(), ago, "domains");
            mark(d.path(), ago, "archive");
            mark(d.path(), ago, "archive-dns");
        }
        let r = ret(10, Some(1), Some(1), true);
        assert!(enforce(d.path(), &r, today()).unwrap().is_some());
        assert!(has(d.path(), "certs", 0), "today is never deleted");
        assert_eq!(listing(d.path()), before);
        assert!(d.path().join("archive/certs/a.parquet").exists());
    }
}
