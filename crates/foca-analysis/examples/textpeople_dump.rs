//! Local evaluation helper: prints `textpeople::scan` results of text files as JSON lines.
use foca_analysis::textpeople;

fn main() {
    if std::env::args().nth(1).as_deref() == Some("-") {
        let mut text = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut text).ok();
        for m in textpeople::scan(&text).people {
            println!(
                "{:?} {} | {:?} | {:?} | sig={}",
                m.form, m.name, m.title, m.unit, m.signatory
            );
        }
        return;
    }
    for path in std::env::args().skip(1) {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        let t0 = std::time::Instant::now();
        let s = textpeople::scan(&text);
        let ms = t0.elapsed().as_secs_f64() * 1000.0;
        let people: Vec<serde_json::Value> = s
            .people
            .iter()
            .map(|m| {
                serde_json::json!({
                    "name": m.name, "form": format!("{:?}", m.form), "lang": m.lang, "line": m.line,
                    "title": m.title, "unit": m.unit, "sig": m.signatory, "cited": m.cited,
                    "phones": m.phones.len(), "emails": m.emails, "ids": m.ids,
                })
            })
            .collect();
        let phones: Vec<String> = s.phones.iter().map(|p| p.value.clone()).collect();
        println!(
            "{}",
            serde_json::json!({"path": path, "lang": s.lang, "ms": ms, "people": people,
                "phones": phones, "emails": s.emails, "counts": s.counts})
        );
    }
}
