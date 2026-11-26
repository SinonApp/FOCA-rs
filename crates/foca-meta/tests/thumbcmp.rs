//! EXIF thumbnail versus photo pixel comparison (guards against false high-severity findings
//! on photos saved by Photoshop). Fixtures live in tests/corpus/thumb (generated with Pillow, see SOURCES.md).

use foca_meta::thumbcmp::{thumbnail_differs, thumbnail_distance};

fn f(n: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/thumb/{n}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn same_picture_with_letterbox_is_not_different() {
    let d = thumbnail_distance(&f("photo.jpg"), &f("thumb_same.jpg")).unwrap();
    assert!(d.0 < 10.0 && d.1 < 0.05, "{d:?}");
    assert_eq!(
        thumbnail_differs(&f("photo.jpg"), &f("thumb_same.jpg")),
        Some(false)
    );
}

#[test]
fn uncropped_or_unredacted_thumbnail_differs() {
    assert_eq!(
        thumbnail_differs(&f("photo.jpg"), &f("thumb_uncropped.jpg")),
        Some(true)
    );
    assert_eq!(
        thumbnail_differs(&f("photo_redacted.jpg"), &f("thumb_same.jpg")),
        Some(true)
    );
}

#[test]
fn garbage_is_none() {
    assert_eq!(thumbnail_differs(b"not a jpeg", &f("thumb_same.jpg")), None);
}

/// Live check against real photos (Wikimedia files saved by Photoshop, thumbnail equals photo):
/// `FOCA_PHOTOS=<photo dir> cargo test -p foca-meta --test thumbcmp -- --ignored --nocapture`
#[test]
#[ignore]
fn real_photos_report() {
    let Ok(dir) = std::env::var("FOCA_PHOTOS") else {
        return;
    };
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.extension().and_then(|x| x.to_str()) != Some("jpg") {
            continue;
        }
        let b = std::fs::read(&p).unwrap();
        let m = foca_meta::extract(
            &b,
            p.file_name().and_then(|n| n.to_str()),
            &Default::default(),
        )
        .unwrap();
        let t = m.thumbnail.as_ref();
        println!(
            "{}: миниатюра {} differs={:?} dist={:?}",
            p.display(),
            t.is_some(),
            t.and_then(|t| t.differs),
            t.and_then(|t| thumbnail_distance(&b, &t.data))
        );
    }
}
