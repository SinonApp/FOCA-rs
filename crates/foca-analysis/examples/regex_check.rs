//! Build-time helper for the signature ingest scripts (`signatures/tools/sigsrc.py`): reads JSON
//! lines `{"p": "<pattern>", "ci": true}` from stdin and prints `ok` or `err <class>` per line,
//! compiling with the same `regex` crate and limits the app uses. Classes: `lookaround`,
//! `backref`, `size`, `other`.

use std::io::{BufRead, Write};

fn class(e: &regex::Error) -> &'static str {
    let s = e.to_string();
    if s.contains("look-around") || s.contains("look-behind") || s.contains("look-ahead") {
        "lookaround"
    } else if s.contains("backreference") {
        "backref"
    } else if matches!(e, regex::Error::CompiledTooBig(_)) {
        "size"
    } else {
        "other"
    }
}

fn main() {
    let stdin = std::io::stdin();
    let mut out = std::io::BufWriter::new(std::io::stdout());
    for line in stdin.lock().lines() {
        let line = line.expect("stdin");
        let v: serde_json::Value = serde_json::from_str(&line).expect("json line");
        let p = v["p"].as_str().unwrap_or_default();
        let ci = v["ci"].as_bool().unwrap_or(false);
        let r = regex::RegexBuilder::new(p)
            .case_insensitive(ci)
            .size_limit(1 << 20)
            .build();
        match r {
            Ok(_) => writeln!(out, "ok"),
            Err(e) => writeln!(out, "err {}", class(&e)),
        }
        .expect("stdout");
    }
}
