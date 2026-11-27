//! Prints CVE match counts of the embedded NVD table for a few reference products.
//!
//! `cargo run -p foca-analysis --example cve_stats [<table.tsv.gz>]`
//! Used to compare tables before and after `signatures/tools/update_nvd.py` runs.

use foca_analysis::cve::{CveDb, CveQuery, NVD_GZ};

const PRODUCTS: &[(&str, &str, Option<&str>)] = &[
    ("Chromium m142", "google:chrome", Some("m142")),
    ("macOS 26", "apple:macos apple:mac_os_x", Some("26.0")),
    ("Word 2010", "microsoft:office microsoft:word", Some("14.0")),
    ("Word 2013", "microsoft:office microsoft:word", Some("15.0")),
    ("Word 2016", "microsoft:office microsoft:word", Some("16.0")),
    ("Word 2019", "microsoft:office microsoft:word", Some("2019")),
    (
        "Excel 2016",
        "microsoft:office microsoft:excel",
        Some("16.0"),
    ),
    (
        "Outlook 2007",
        "microsoft:office microsoft:outlook",
        Some("12.0"),
    ),
    ("jQuery 2.2.4", "jquery:jquery", Some("2.2.4")),
    ("Bootstrap 3.3.5", "getbootstrap:bootstrap", Some("3.3.5")),
    ("nginx (no version)", "f5:nginx nginx:nginx", None),
];

fn main() {
    let raw = std::env::args()
        .nth(1)
        .map(|p| std::fs::read(p).expect("table"));
    let db = CveDb::parse(raw.as_deref().unwrap_or(NVD_GZ)).expect("table");
    println!("snapshot {} cves {}", db.meta.snapshot, db.meta.cves);
    println!("product\tknown\tmatched\tunbounded\tkev\tcrit\thigh\tupgrade");
    for (label, keys, ver) in PRODUCTS {
        let q = CveQuery {
            keys: keys.split(' ').map(str::to_string).collect(),
            version: ver.map(str::to_string),
            ..Default::default()
        };
        match db.lookup(&q) {
            Some(s) => println!(
                "{label}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                s.known,
                s.matched,
                s.unbounded,
                s.kev,
                s.critical,
                s.high,
                s.fixed_in.as_deref().unwrap_or("-")
            ),
            None => println!("{label}\t-"),
        }
    }
}
