//! Bucket definitions shared by Trends and certificate filters, so that a
//! filtered search finds what a Trends bar counted.

/// Certificate lifetime. Labels match `validity_bucket` in `rollup_daily`.
pub fn validity_case() -> String {
    let sp = "((CAST(not_after AS BIGINT) - CAST(not_before AS BIGINT)) / 86400000.0)";
    format!(
        "CASE WHEN {sp} <= 7 THEN '<=7d' WHEN {sp} <= 47 THEN '<=47d' WHEN {sp} <= 100 THEN '<=100d' \
         WHEN {sp} <= 200 THEN '<=200d' ELSE '>200d' END"
    )
}

pub fn san_case() -> String {
    "CASE WHEN san_count <= 1 THEN '1' WHEN san_count = 2 THEN '2' \
     WHEN san_count <= 5 THEN '3-5' WHEN san_count <= 10 THEN '6-10' \
     WHEN san_count <= 100 THEN '11-100' ELSE '>100' END"
        .to_string()
}

pub fn size_case() -> String {
    "CASE WHEN der_size < 1024 THEN '<1 KiB' WHEN der_size < 2048 THEN '1-2 KiB' \
     WHEN der_size < 4096 THEN '2-4 KiB' WHEN der_size < 16384 THEN '4-16 KiB' \
     ELSE '>=16 KiB' END"
        .to_string()
}
