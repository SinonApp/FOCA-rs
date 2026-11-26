//! Report integration tests: Chain of custody block and digest.

mod common;

use common::*;

#[test]
fn custody_block_is_strictly_gated_and_safe() {
    let snap = &fixture().snap;
    for fmt in [ReportFormat::Html, ReportFormat::Md] {
        let off = opts(fmt);
        assert!(!off.custody);
        let a_off = build(snap, &off);
        let mut on = off.clone();
        on.custody = true;
        let a_on = build(snap, &on);
        assert_ne!(a_off.bytes, a_on.bytes);
        let txt = text(&a_on);
        assert!(txt.contains("Chain of Custody"));
        assert!(txt.contains("SHA-256"));
        let expect_verify = if fmt == ReportFormat::Md {
            "report\\_verify"
        } else {
            "report_verify"
        };
        assert!(txt.contains(expect_verify), "{fmt:?} missing verify hint");
        if fmt == ReportFormat::Html {
            assert_safe_html(&txt);
        }
        // Raw secrets remain redacted inside Chain of Custody.
        let rec = foca_report::custody::build_record_for(
            snap,
            &fixture().log,
            &on,
            &a_on.file_name,
            &a_on.bytes,
            NOW,
        );
        assert!(
            txt.contains(&rec.inputs_sha256),
            "inputs_sha256 missing from rendered custody block in {fmt:?}"
        );
        let rec_json = serde_json::to_string(&rec).unwrap();
        assert_eq!(rec.report_sha256.len(), 64);
        assert_eq!(rec.inputs_sha256.len(), 64);
        assert_eq!(
            rec.report_sha256,
            foca_report::custody::sha256_hex(&a_on.bytes)
        );
        for sec in snap.secrets.iter().filter(|s| s.kind != "host") {
            let v = sec.value.expose();
            if v.len() >= 8 {
                assert!(!rec_json.contains(v), "secret leaked into custody JSON");
            }
        }
    }
    // Hostile XSS input must be escaped in Chain of Custody HTML too.
    let bad = hostile();
    let mut o = tpl_opts(Template::Executive, Lang::Uk, ReportFormat::Html);
    o.custody = true;
    let html = text(&build(&bad, &o));
    assert_safe_html(&html);
    assert!(html.contains("Ланцюг збереження (Chain of Custody)"));
}

#[test]
fn custody_inputs_digest_ignores_format_and_generation_time() {
    let snap = &fixture().snap;
    let later = NOW + time::Duration::hours(5);
    let mut digests = Vec::new();
    for fmt in [ReportFormat::Html, ReportFormat::Md, ReportFormat::Docx] {
        let o = ReportOptions {
            custody: true,
            ..opts(fmt)
        };
        for now in [NOW, later] {
            let a = build_report_with_log(snap, &fixture().log, &o, now);
            let rec = foca_report::custody::build_record_for(
                snap,
                &fixture().log,
                &o,
                &a.file_name,
                &a.bytes,
                now,
            );
            if fmt != ReportFormat::Docx {
                assert!(text(&a).contains(&rec.inputs_sha256), "{fmt:?}");
            }
            digests.push(rec.inputs_sha256);
        }
    }
    assert!(digests.windows(2).all(|w| w[0] == w[1]), "{digests:?}");
}
