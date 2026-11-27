//! The report logo from Settings → Report: `report_logo_set` checks format, size and dimensions,
//! `report_logo_get` returns it, `report_build` with `logo: true` embeds it (HTML `data:` URL,
//! DOCX image part), and `report_logo_clear` brings the initials back.

use std::io::Read;

use crate::common;
use serde_json::json;

/// A real 8×4 RGB PNG.
const PNG_8X4: &str = "iVBORw0KGgoAAAANSUhEUgAAAAgAAAAECAIAAAA8r+mnAAAAJUlEQVR42mNgCDghF3DCJuBEVMCJioAT0wJObAk4cSngBAP1JAAgOzAh+r1X4QAAAABJRU5ErkJggg==";

fn png_header(w: u32, h: u32) -> Vec<u8> {
    let mut v = b"\x89PNG\r\n\x1a\n\0\0\0\x0dIHDR".to_vec();
    v.extend_from_slice(&w.to_be_bytes());
    v.extend_from_slice(&h.to_be_bytes());
    v.extend_from_slice(&[8, 2, 0, 0, 0]);
    v
}

fn data_url(mime: &str, bytes: &[u8]) -> String {
    format!("data:{mime};base64,{}", foca_core::b64::encode(bytes))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn report_logo_is_checked_saved_used_and_cleared() {
    let e = common::env(0).await;
    assert_eq!(
        e.call("report_logo_get", json!({})).await,
        json!({ "logo": null })
    );

    // refused: SVG, GIF, a declared type that does not match, too many pixels, too many bytes
    let svg = data_url("image/svg+xml", b"<svg onload=\"alert(1)\"/>");
    let gif = data_url("image/gif", b"GIF89a\x08\0\x04\0");
    let lie = format!("data:image/jpeg;base64,{PNG_8X4}");
    let wide = data_url("image/png", &png_header(1024, 100));
    let mut heavy = png_header(64, 64);
    heavy.resize(2 * 1024 * 1024 + 1, 0);
    let heavy = data_url("image/png", &heavy);
    for (data, code) in [
        (svg.as_str(), "logo_format"),
        (gif.as_str(), "logo_format"),
        (lie.as_str(), "logo_format"),
        ("data:image/png;base64,iVBORw0KGgo=", "logo_corrupt"),
        (wide.as_str(), "logo_too_big"),
        (heavy.as_str(), "logo_too_large"),
        ("https://example.test/logo.png", "logo_format"),
    ] {
        let err = e
            .err("report_logo_set", json!({ "data": data, "name": "x.png" }))
            .await;
        assert_eq!(err.code, code, "{}", &data[..data.len().min(40)]);
    }
    assert_eq!(
        e.call("report_logo_get", json!({})).await["logo"],
        json!(null)
    );

    // accepted: a PNG with a hostile file name
    let set = e
        .call(
            "report_logo_set",
            json!({ "data": format!("data:image/png;base64,{PNG_8X4}"),
                "name": "C:\\Users\\me\\<i>logo\".png" }),
        )
        .await;
    let logo = &set["logo"];
    assert_eq!(logo["mime"], "image/png");
    assert_eq!((logo["w"].as_u64(), logo["h"].as_u64()), (Some(8), Some(4)));
    assert_eq!(logo["bytes"], 94);
    assert_eq!(logo["name"], "ilogo.png");
    assert_eq!(e.call("report_logo_get", json!({})).await, set);
    // the settings JSON stays small
    let st = e.call("settings_get", json!({})).await;
    assert!(!st.to_string().contains(PNG_8X4));

    let id = e.project("example.test").await;
    let build = |fmt: &str, logo: bool| {
        json!({ "project": id, "opts": { "tpl_id": "full", "fmt": fmt, "lang": "EN",
            "company": "Cyber Audit LLC", "logo": logo } })
    };
    let read = |rep: &serde_json::Value| std::fs::read(rep["path"].as_str().unwrap()).unwrap();
    let html = String::from_utf8(read(&e.call("report_build", build("html", true)).await)).unwrap();
    assert!(html.contains(&format!("<img src=\"data:image/png;base64,{PNG_8X4}\"")));
    // the option off: no logo at all
    let off = String::from_utf8(read(&e.call("report_build", build("html", false)).await)).unwrap();
    assert!(!off.contains("data:image/png") && !off.contains("class=\"initials\""));
    let docx = read(&e.call("report_build", build("docx", true)).await);
    let mut z = zip::ZipArchive::new(std::io::Cursor::new(docx)).unwrap();
    let mut part = Vec::new();
    z.by_name("word/media/logo.png")
        .expect("logo image part")
        .read_to_end(&mut part)
        .unwrap();
    assert_eq!(foca_core::b64::encode(&part), PNG_8X4);
    // the report history keeps the flag, never the image
    let list = e.call("report_list", json!({ "project": id })).await;
    assert!(!list.to_string().contains(PNG_8X4));

    // cleared: the initials come back
    assert_eq!(
        e.call("report_logo_clear", json!({})).await,
        json!({ "logo": null })
    );
    let html = String::from_utf8(read(&e.call("report_build", build("html", true)).await)).unwrap();
    assert!(!html.contains("data:image/png"));
    assert!(html.contains("<div class=\"initials\" aria-hidden=\"true\">CA</div>"));
}
