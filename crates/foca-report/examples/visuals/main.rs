//! Renders a sample HTML/Markdown report with all four diagrams from synthetic data.
//!
//! ```text
//! cargo run -p foca-report --example visuals [OUT_DIR]   # default: examples/out
//! ```
//!
//! Writes `visuals-sample.<lang>.html`, `visuals-sample.ru.md` and the bare diagrams
//! `viz-*.svg`. Nothing here is committed: the files are for visual review (Playwright, print
//! to PDF).

mod data;

use std::path::PathBuf;

use foca_core::api::Snapshot;
use foca_report::{build_report_with_visuals, svg, Lang, ReportFormat, ReportOptions, Sections};
use time::macros::datetime;

fn main() {
    let dir = std::env::args()
        .nth(1)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples/out"));
    std::fs::create_dir_all(&dir).expect("create output dir");
    let vis = data::demo();
    let mut snap = Snapshot::default();
    snap.project.name = "Приклад (демо)".into();
    snap.scope.client = "ТОВ «Приклад»".into();
    let now = datetime!(2026-11-20 12:00 UTC);
    for (lang, code) in [(Lang::Uk, "uk"), (Lang::Ru, "ru"), (Lang::En, "en")] {
        let o = ReportOptions {
            fmt: ReportFormat::Html,
            lang,
            sections: Sections::all(),
            company: "ТОВ «Кібер Аудит»".into(),
            ..Default::default()
        };
        let a = build_report_with_visuals(&snap, &[], &vis, &o, now);
        let path = dir.join(format!("visuals-sample.{code}.html"));
        std::fs::write(&path, &a.bytes).expect("write html");
        println!("{}", path.display());
    }
    let o = ReportOptions {
        fmt: ReportFormat::Md,
        sections: Sections::all(),
        ..Default::default()
    };
    let md = build_report_with_visuals(&snap, &[], &vis, &o, now);
    std::fs::write(dir.join("visuals-sample.ru.md"), &md.bytes).expect("write md");
    let figs = [
        ("graph", svg::graph::render(&vis.graph, Lang::Uk)),
        ("netmap", svg::netmap::render(&vis.netmap, Lang::Uk)),
        ("timeline", svg::timeline::render(&vis.timeline, Lang::Uk)),
        ("activity", svg::heatmap::render(&vis.activity, Lang::Uk)),
    ];
    for (name, f) in figs {
        if let Some(f) = f {
            std::fs::write(dir.join(format!("viz-{name}.svg")), f.svg).expect("write svg");
        }
    }
}
