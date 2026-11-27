//! Multilingual people-in-text fixtures: per-language precision and recall of
//! `textpeople::scan` on synthetic snippets (`tests/fixtures/people/<lang>.txt`, invented
//! names). Run with `--nocapture` to see the table.

use std::collections::BTreeSet;

use foca_analysis::textpeople;

struct Score {
    lang: String,
    tp: usize,
    fp: Vec<String>,
    missed: Vec<String>,
}

fn score(lang: &str, src: &str) -> Score {
    let mut expect: BTreeSet<String> = BTreeSet::new();
    let mut text = String::new();
    for line in src.lines() {
        if let Some(e) = line.strip_prefix("# expect:") {
            expect.extend(
                e.split('|')
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty()),
            );
        } else if !line.starts_with('#') {
            text.push_str(line);
            text.push('\n');
        }
    }
    let found: BTreeSet<String> = textpeople::scan(&text)
        .people
        .into_iter()
        .map(|m| m.name)
        .collect();
    Score {
        lang: lang.to_string(),
        tp: found.intersection(&expect).count(),
        fp: found.difference(&expect).cloned().collect(),
        missed: expect.difference(&found).cloned().collect(),
    }
}

#[test]
fn multilingual_fixtures_precision_recall() {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/people");
    let mut files: Vec<_> = std::fs::read_dir(dir)
        .expect("fixtures dir")
        .filter_map(Result::ok)
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "txt"))
        .collect();
    files.sort();
    let mut bad = Vec::new();
    println!(
        "{:<8} {:>4} {:>4} {:>4} {:>7} {:>9}",
        "lang", "tp", "fp", "fn", "recall", "precision"
    );
    let (mut ttp, mut tfp, mut tfn) = (0, 0, 0);
    for p in files {
        let lang = p
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or("?")
            .to_string();
        let s = score(&lang, &std::fs::read_to_string(&p).expect("fixture"));
        let rec = s.tp as f64 / (s.tp + s.missed.len()).max(1) as f64;
        let prec = s.tp as f64 / (s.tp + s.fp.len()).max(1) as f64;
        println!(
            "{:<8} {:>4} {:>4} {:>4} {:>7.2} {:>9.2}",
            s.lang,
            s.tp,
            s.fp.len(),
            s.missed.len(),
            rec,
            prec
        );
        if !s.fp.is_empty() || !s.missed.is_empty() {
            println!("         fp {:?} missed {:?}", s.fp, s.missed);
        }
        ttp += s.tp;
        tfp += s.fp.len();
        tfn += s.missed.len();
        if rec < 0.8 || prec < 0.9 {
            bad.push(format!("{}: recall {rec:.2} precision {prec:.2}", s.lang));
        }
    }
    println!(
        "{:<8} {:>4} {:>4} {:>4} {:>7.2} {:>9.2}",
        "total",
        ttp,
        tfp,
        tfn,
        ttp as f64 / (ttp + tfn).max(1) as f64,
        ttp as f64 / (ttp + tfp).max(1) as f64
    );
    assert!(bad.is_empty(), "below target: {bad:?}");
}
