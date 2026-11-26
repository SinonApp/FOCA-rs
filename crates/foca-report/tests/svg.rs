//! Integration tests for the static SVG diagrams (`foca_report::svg`) and their embedding in
//! the HTML/Markdown report: escaping of hostile labels, well-formed XML, determinism (golden
//! files), size limits, strict CSP and conditional sections.
//!
//! Regenerate the golden diagrams with `UPDATE_GOLDEN=1 cargo test -p foca-report --test svg`.

#[path = "../examples/visuals/data.rs"]
mod data;

use std::path::Path;

use foca_core::api::Snapshot;
use foca_report::svg::{self, Graph, GraphEdge, GraphNode, NodeKind, Visuals};
use foca_report::{
    build_report_with_log, build_report_with_visuals, Lang, ReportFormat, ReportOptions, Sections,
};
use quick_xml::events::Event;
use time::macros::datetime;

const SVG_TAGS: &[&str] = &[
    "svg", "title", "g", "rect", "path", "circle", "ellipse", "text", "tspan",
];

fn figures(v: &Visuals, l: Lang) -> Vec<(&'static str, svg::Figure)> {
    [
        ("graph", svg::graph::render(&v.graph, l)),
        ("netmap", svg::netmap::render(&v.netmap, l)),
        ("timeline", svg::timeline::render(&v.timeline, l)),
        ("activity", svg::heatmap::render(&v.activity, l)),
    ]
    .into_iter()
    .map(|(n, f)| (n, f.unwrap_or_else(|| panic!("{n} rendered nothing"))))
    .collect()
}

/// Parses the SVG as XML and checks elements and attributes against a whitelist.
fn assert_safe_svg(name: &str, s: &str) {
    let mut r = quick_xml::Reader::from_str(s);
    let mut elements = 0usize;
    loop {
        match r.read_event() {
            Ok(Event::Start(e)) | Ok(Event::Empty(e)) => {
                let tag = e.name().into_inner().to_string();
                assert!(SVG_TAGS.contains(&tag.as_str()), "{name}: tag <{tag}>");
                for a in e.attributes() {
                    let a = a.unwrap_or_else(|err| panic!("{name}: bad attribute {err}"));
                    let k = a.key.into_inner().to_lowercase();
                    assert!(!k.starts_with("on"), "{name}: handler {k}");
                    assert!(
                        k != "href" && k != "xlink:href" && k != "style",
                        "{name}: {k}"
                    );
                    let v = format!("{:?}", a.value).to_lowercase();
                    assert!(
                        !v.contains("url(") && !v.contains("javascript"),
                        "{name}: {k}={v}"
                    );
                }
                elements += 1;
            }
            Ok(Event::CData(_)) => panic!("{name}: CDATA section"),
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => panic!("{name}: not well-formed XML: {e}"),
        }
    }
    assert!(elements > 0);
    let lower = s.to_lowercase();
    for bad in [
        "<script",
        "<foreignobject",
        "<iframe",
        "<![cdata[",
        "<image",
        "<use",
        "]]>",
    ] {
        assert!(!lower.contains(bad), "{name}: found {bad}");
    }
    assert!(
        !s.contains('\u{202e}') && !s.contains('\u{0}'),
        "{name}: control characters"
    );
}

#[test]
fn hostile_labels_are_escaped_in_every_diagram() {
    let v = data::hostile();
    for l in [Lang::Ru, Lang::Uk, Lang::En] {
        for (name, f) in figures(&v, l) {
            assert_safe_svg(name, &f.svg);
        }
    }
    // The payload survives as visible, escaped text (truncation aside).
    let g = svg::graph::render(&v.graph, Lang::En).unwrap().svg;
    assert!(g.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    let a = svg::heatmap::render(&v.activity, Lang::En).unwrap().svg;
    assert!(a.contains("&quot;&gt;&lt;svg onload=alert(2)&gt;"));
}

#[test]
fn output_is_deterministic_and_matches_golden() {
    let v = data::demo();
    let a = figures(&v, Lang::Uk);
    let b = figures(&v.clone(), Lang::Uk);
    assert_eq!(a, b);
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden");
    let update = std::env::var("UPDATE_GOLDEN").is_ok_and(|v| v == "1");
    for (name, f) in a {
        assert_safe_svg(name, &f.svg);
        // One element per line keeps golden diffs readable.
        let got = f.svg.replace("><", ">\n<") + "\n";
        let path = dir.join(format!("viz-{name}.svg"));
        if update || !path.exists() {
            std::fs::write(&path, &got).unwrap();
            assert!(
                update,
                "golden {name} was missing and has been created; review it"
            );
            continue;
        }
        let exp = std::fs::read_to_string(&path).unwrap();
        if exp != got {
            let line = exp
                .lines()
                .zip(got.lines())
                .position(|(x, y)| x != y)
                .unwrap_or(0);
            panic!(
                "viz-{name}.svg differs at line {}:\n  expected: {:?}\n  got:      {:?}\n\
                 update: UPDATE_GOLDEN=1 cargo test -p foca-report --test svg",
                line + 1,
                exp.lines().nth(line),
                got.lines().nth(line)
            );
        }
    }
}

#[test]
fn size_is_bounded_for_huge_inputs() {
    let mut g = Graph::default();
    let kinds = [
        NodeKind::Person,
        NodeKind::Document,
        NodeKind::Workstation,
        NodeKind::Printer,
        NodeKind::Share,
        NodeKind::Server,
        NodeKind::Domain,
        NodeKind::Pki,
    ];
    for i in 0..6000 {
        g.nodes.push(GraphNode {
            id: format!("n{i}"),
            kind: kinds[i % kinds.len()],
            label: "x".repeat(300),
            critical: i % 97 == 0,
        });
    }
    for i in 0..30_000usize {
        g.edges.push(GraphEdge {
            from: format!("n{}", i % 6000),
            to: format!("n{}", (i * 7 + 13) % 6000),
        });
    }
    let f = svg::graph::render(&g, Lang::Ru).unwrap();
    assert!(f.svg.len() < 200_000, "graph SVG is {} bytes", f.svg.len());
    assert_eq!(
        f.svg.matches("<g><title>").count(),
        4 * svg::graph::MAX_PER_LAYER
    );
    let mut tl = svg::Timeline::default();
    for i in 0..50_000 {
        tl.events.push(svg::TimelineEvent {
            lane: svg::Lane::Wayback,
            year: 1970 + (i % 120),
            label: format!("snapshot {i} {}", "y".repeat(200)),
        });
    }
    let f = svg::timeline::render(&tl, Lang::En).unwrap();
    assert!(
        f.svg.len() < 120_000,
        "timeline SVG is {} bytes",
        f.svg.len()
    );
}

fn opts(fmt: ReportFormat, lang: Lang) -> ReportOptions {
    ReportOptions {
        fmt,
        lang,
        sections: Sections::all(),
        ..Default::default()
    }
}

fn snap() -> Snapshot {
    let mut s = Snapshot::default();
    s.project.name = "Demo".into();
    s
}

#[test]
fn html_embeds_sections_and_keeps_csp_strict() {
    let now = datetime!(2026-11-20 12:00 UTC);
    let o = opts(ReportFormat::Html, Lang::Uk);
    let h =
        String::from_utf8(build_report_with_visuals(&snap(), &[], &data::hostile(), &o, now).bytes)
            .unwrap();
    for id in ["graph", "netmap", "timeline", "activity"] {
        assert!(
            h.contains(&format!("<section id=\"{id}\" class=\"viz-sec\">")),
            "{id}"
        );
        assert!(h.contains(&format!("<a href=\"#{id}\">")), "toc {id}");
    }
    let csp = h
        .split("Content-Security-Policy\" content=\"")
        .nth(1)
        .and_then(|r| r.split('"').next())
        .unwrap();
    assert!(csp.contains("default-src 'none'"));
    assert!(!csp.contains("script-src") && !csp.contains("unsafe-eval"));
    let lower = h.to_lowercase();
    assert!(!lower.contains("<script") && !lower.contains("<foreignobject"));
    // Payloads appear only as escaped text (`&lt;svg onload=…`), never as markup.
    assert!(!lower.contains("url(") && !lower.contains("<svg onload"));
    for (i, _) in h.match_indices("<svg ") {
        let end = h[i..].find("</svg>").unwrap() + i + 6;
        assert_safe_svg("embedded", &h[i..end]);
    }
    assert!(h.contains("section#graph, section#netmap, section#timeline { break-before: page; }"));
}

#[test]
fn empty_visuals_change_nothing() {
    let now = datetime!(2026-11-20 12:00 UTC);
    for fmt in [ReportFormat::Html, ReportFormat::Md] {
        let o = opts(fmt, Lang::Ru);
        let a = build_report_with_log(&snap(), &[], &o, now);
        let b = build_report_with_visuals(&snap(), &[], &Visuals::default(), &o, now);
        assert_eq!(a.bytes, b.bytes);
        let t = String::from_utf8(a.bytes).unwrap();
        assert!(!t.contains("viz-sec") && !t.contains("Граф связей"));
    }
    // Partial data: only the sections that have it.
    let v = Visuals {
        activity: data::demo().activity,
        ..Visuals::default()
    };
    let o = opts(ReportFormat::Html, Lang::En);
    let h = String::from_utf8(build_report_with_visuals(&snap(), &[], &v, &o, now).bytes).unwrap();
    assert!(h.contains("id=\"activity\"") && !h.contains("id=\"graph\""));
}

#[test]
fn markdown_has_text_form() {
    let now = datetime!(2026-11-20 12:00 UTC);
    let o = opts(ReportFormat::Md, Lang::Ru);
    let md =
        String::from_utf8(build_report_with_visuals(&snap(), &[], &data::hostile(), &o, now).bytes)
            .unwrap();
    for h in [
        "## Граф связей",
        "## Схема внутренней сети",
        "## Хронология",
        "## Активность",
    ] {
        assert!(md.contains(h), "{h}");
    }
    assert!(md.contains("  - Рабочая станция: BUH-PC01"));
    assert!(md.contains("| Год |"));
    // Hostile labels stay inert: every tag start is backslash-escaped.
    for tag in ["<script", "<svg"] {
        assert!(md.match_indices(tag).all(|(i, _)| md[..i].ends_with('\\')));
    }
    assert!(md.contains("\\<script\\>"));
}

#[test]
fn docx_has_chronology_table() {
    let now = datetime!(2026-11-20 12:00 UTC);
    let o = opts(ReportFormat::Docx, Lang::Ru);
    let b = build_report_with_visuals(&snap(), &[], &data::hostile(), &o, now).bytes;
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(b)).unwrap();
    let mut x = String::new();
    std::io::Read::read_to_string(&mut z.by_name("word/document.xml").unwrap(), &mut x).unwrap();
    assert!(x.contains("Хронология"), "no chronology section");
    assert!(!x.contains("<script"));
}
