use ctprobe::mocklog::{MockEntry, MockLog, MockOpts, TestCa};
use ctprobe::positions::{open_db, Positions};
use ctprobe::store::list_parts;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use std::time::Duration;
use wiremock::matchers::path;
use wiremock::{Mock, MockServer, ResponseTemplate};

#[tokio::test(flavor = "multi_thread")]
async fn sigterm_commits_before_exit() {
    let d = tempfile::tempdir().unwrap();
    let ca = TestCa::default();
    let es: Vec<MockEntry> =
        (0..300).map(|i| ca.final_cert(i + 1, &[&format!("h{i}.example.com")])).collect();
    let log = MockLog::start(MockOpts::rfc6962(0).with_entries(es)).await;
    log.set_tree_size(100);

    let list = MockServer::start().await;
    let body = serde_json::json!({ "operators": [{ "name": "op", "logs": [{
        "description": "Mock", "log_id": "bW9jaw==", "url": log.url(), "state": { "usable": {} }
    }]}]});
    Mock::given(path("/list.json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(body))
        .mount(&list)
        .await;

    let cfg = d.path().join("c.toml");
    std::fs::write(
        &cfg,
        format!(
            "bind = \"127.0.0.1:0\"\ndata_dir = \"{}\"\ndisk_budget = \"1GiB\"\ntracker_max = \"64MiB\"\nlog_list_url = \"{}/list.json\"\nextra_log_lists = []\n",
            d.path().join("data").display(),
            list.uri()
        ),
    )
    .unwrap();
    let mut child = std::process::Command::new(env!("CARGO_BIN_EXE_ctprobe"))
        .args(["run", "--config", cfg.to_str().unwrap()])
        .spawn()
        .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await; // Follows from head, 100.
    log.set_tree_size(300);
    tokio::time::sleep(Duration::from_secs(12)).await; // One poll interval.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let status = child.wait().unwrap();
    assert!(status.success(), "{status:?}");

    let data = d.path().join("data");
    let pos = Positions::new(open_db(&data.join("state.redb")).unwrap());
    assert_eq!(pos.all().unwrap(), [(0, 300)]);
    let rows: usize = list_parts(&data, "certs")
        .iter()
        .map(|p| {
            ParquetRecordBatchReaderBuilder::try_new(std::fs::File::open(p).unwrap())
                .unwrap()
                .build()
                .unwrap()
                .map(|b| b.unwrap().num_rows())
                .sum::<usize>()
        })
        .sum();
    assert_eq!(rows, 200, "no backfill: only entries after the head");
}
