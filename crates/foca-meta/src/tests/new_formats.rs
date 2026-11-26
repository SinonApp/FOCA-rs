//! Tests of the extended formats (LNK, EML, MSG, Visio, Publisher, InDesign, WordPerfect, Works,
//! iCalendar, vCard, MP4/MOV/HEIC, ZIP): key fields from the synthetic corpus, detection,
//! limits and a mutation fuzzer.
//!
//! The quick mutation pass runs with every `cargo test`. The long fuzzer is ignored by default:
//! `FOCA_FUZZ_SECS=120 cargo test -p foca-meta --release fuzz_new_formats -- --ignored --nocapture`
//! (seconds per format). Inputs that panic or take longer than 2 s are written to
//! `target/fuzz-new-formats/`.

use std::io::{Cursor, Write};
use std::time::{Duration, Instant};

use foca_core::DocFormat;

use crate::util::Rng;
use crate::{detect, detect_with_hint, extract, text, Limits, MetaError};

fn corpus(rel: &str) -> Vec<u8> {
    let p = format!("{}/../../tests/corpus/{rel}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read(&p).unwrap_or_else(|e| panic!("{p}: {e}"))
}

fn meta(rel: &str) -> crate::Metadata {
    let name = rel.rsplit('/').next();
    extract(&corpus(rel), name, &Limits::default()).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

/// Corpus seeds: (file, format).
const SEEDS: [(&str, DocFormat); 22] = [
    ("lnk/report.lnk", DocFormat::Lnk),
    ("lnk/network.lnk", DocFormat::Lnk),
    ("mail/budget.eml", DocFormat::Eml),
    ("mail/budget.msg", DocFormat::Msg),
    ("visio/network.vsdx", DocFormat::Vsdx),
    ("legacy/network.vsd", DocFormat::Vsd),
    ("legacy/leaflet.pub", DocFormat::Pub),
    ("legacy/annual.indd", DocFormat::Indd),
    ("legacy/budget.wpd", DocFormat::Wpd),
    ("legacy/letter.wps", DocFormat::Wps),
    ("legacy/budget.wks", DocFormat::Wks),
    ("pim/meeting.ics", DocFormat::Ics),
    ("pim/contacts.vcf", DocFormat::Vcf),
    ("media/survey.mp4", DocFormat::Mp4),
    ("media/iphone.mov", DocFormat::Mov),
    ("media/photo.heic", DocFormat::Heic),
    ("archive/backup.zip", DocFormat::Zip),
    ("lnk/broken-linkinfo.lnk", DocFormat::Lnk),
    ("mail/broken-mime.eml", DocFormat::Eml),
    ("mail/broken.msg", DocFormat::Msg),
    ("media/broken-iloc.heic", DocFormat::Heic),
    ("archive/broken.zip", DocFormat::Zip),
];

#[test]
fn detection() {
    for (f, fmt) in SEEDS {
        let b = corpus(f);
        let name = f.rsplit('/').next();
        assert_eq!(detect_with_hint(&b, name), fmt, "{f}");
    }
    // binary signatures do not depend on the name; text formats are found without a name
    for f in [
        "lnk/report.lnk",
        "mail/budget.eml",
        "pim/meeting.ics",
        "pim/contacts.vcf",
        "media/photo.heic",
        "mail/budget.msg",
    ] {
        let b = corpus(f);
        assert_eq!(detect(&b), detect_with_hint(&b, Some("x.bin")), "{f}");
    }
    // a DOS-era Lotus worksheet needs the extension
    assert_eq!(detect(&corpus("legacy/budget.wks")), DocFormat::Unknown);
    // a short header block is mail only with an .eml name
    let short = b"From: a@example.com\r\nSubject: hi\r\n\r\nbody";
    assert_eq!(detect(short), DocFormat::Unknown);
    assert_eq!(detect_with_hint(short, Some("a.eml")), DocFormat::Eml);
    // RDP stays RDP
    assert_eq!(
        detect_with_hint(b"full address:s:srv\r\nusername:s:x\r\n", Some("a.rdp")),
        DocFormat::Rdp
    );
}

#[test]
fn lnk_fields() {
    let m = meta("lnk/report.lnk");
    assert_eq!(m.fields["lnk:mac"], "0a:00:27:00:00:2a");
    assert_eq!(m.fields["lnk:machine_id"], "ws-042");
    assert_eq!(m.fields["lnk:volume_serial"], "1A2B-3C4D");
    assert_eq!(m.fields["lnk:drive_type"], "fixed");
    assert_eq!(
        m.fields["lnk:local_base_path"],
        r"C:\Users\i.petrenko\Documents\Звіт.docx"
    );
    assert_eq!(m.fields["lnk:droid_time"], "2024-02-20T08:00:00Z");
    assert!(m.servers.iter().any(|s| s.name == "ws-042"));
    assert!(m.people.iter().any(|p| p.name == "i.petrenko"));
    let m = meta("lnk/network.lnk");
    assert_eq!(
        m.fields["lnk:network_path"],
        r"\\FS01.corp.example.test\buh$\Звіти\2024\Q1.xlsx"
    );
    assert!(m.servers.iter().any(|s| s.name == "FS01.corp.example.test"));
    assert!(!meta("lnk/broken-linkinfo.lnk").warnings.is_empty());
}

#[test]
fn eml_fields() {
    let m = meta("mail/budget.eml");
    assert_eq!(m.title.as_deref(), Some("Кошторис на 2024 рік"));
    assert_eq!(m.created.as_deref(), Some("2024-03-14T18:42:07+02:00"));
    assert_eq!(m.fields["eml:internal_ips"], "10.20.30.42, 10.20.0.15");
    assert_eq!(
        m.fields["eml:message_id_domain"],
        "exch01.corp.example.test"
    );
    assert_eq!(m.fields["eml:reply_to_differs"], "true");
    assert_eq!(m.stats["received_hops"], 3);
    assert!(
        !m.emails.iter().any(|e| e.starts_with("a1b2c3d4e5")),
        "{:?}",
        m.emails
    );
    assert_eq!(m.attachments.len(), 2);
    assert_eq!(m.attachments[0].name, "Кошторис.docx");
    assert_eq!(m.embedded.len(), 2);
    assert_eq!(m.embedded[0].metadata.format, DocFormat::Docx);
    assert_eq!(m.embedded[1].metadata.format, DocFormat::Eml);
    assert!(m.links.iter().any(|l| l.contains("sharepoint")));
    let t = text(&corpus("mail/budget.eml"), &Limits::default()).unwrap();
    assert!(t.contains("Добрий день") && t.contains("+380 44"), "{t}");
}

#[test]
fn msg_fields() {
    let m = meta("mail/budget.msg");
    assert_eq!(m.author.as_deref(), Some("Іван Петренко"));
    assert!(m.fields["msg:sender_x500"].starts_with("/O=EXCHANGELABS"));
    assert_eq!(m.stats["recipients"], 2);
    assert_eq!(m.created.as_deref(), Some("2024-03-14T16:42:07Z"));
    assert_eq!(m.fields["msg:internal_ips"], "10.20.30.42, 10.20.0.15");
    assert!(m.people.iter().any(|p| p.source == "msg:cc"));
    assert_eq!(m.embedded.len(), 2);
    assert_eq!(m.embedded[1].metadata.format, DocFormat::Msg);
    assert_eq!(
        m.embedded[1].metadata.fields["msg:internal_ips"],
        "192.168.10.7, 10.20.0.16"
    );
    let t = text(&corpus("mail/budget.msg"), &Limits::default()).unwrap();
    assert!(t.contains("Фінальна версія"), "{t}");
    // with depth 0 nothing is embedded
    let l = Limits {
        max_depth: 0,
        ..Limits::default()
    };
    let m = extract(&corpus("mail/budget.msg"), None, &l).unwrap();
    assert!(m.embedded.is_empty() && m.attachments.len() == 2);
}

#[test]
fn office_like_fields() {
    let m = meta("visio/network.vsdx");
    assert_eq!(m.stats["pages"], 2);
    assert_eq!(m.comments.len(), 1);
    assert!(m
        .servers
        .iter()
        .any(|s| s.name == "SQL01.corp.example.test"));
    let t = text(&corpus("visio/network.vsdx"), &Limits::default()).unwrap();
    assert!(t.contains("EXCH01.corp.example.test"));
    let m = meta("legacy/network.vsd");
    assert_eq!(m.author.as_deref(), Some("Іван Петренко"));
    assert_eq!(m.fields["visio:file_version"], "11");
    assert_eq!(
        meta("legacy/leaflet.pub").application.as_deref(),
        Some("Microsoft Publisher 16.0")
    );
    assert_eq!(meta("legacy/letter.wps").title.as_deref(), Some("Лист"));
    let m = meta("legacy/annual.indd");
    assert_eq!(
        m.application.as_deref(),
        Some("Adobe InDesign 19.2 (Windows)")
    );
    assert!(m.servers.iter().any(|s| s.name == "FS01.corp.example.test"));
    assert_eq!(
        meta("legacy/budget.wpd").application.as_deref(),
        Some("WordPerfect 6+ (2.1)")
    );
    assert!(meta("legacy/budget.wks").application.is_some());
}

#[test]
fn pim_fields() {
    let m = meta("pim/meeting.ics");
    assert!(m.fields["ics:meeting_links"].contains("teams.microsoft.com"));
    assert!(m.fields["ics:meeting_links"].contains("zoom.us"));
    assert_eq!(m.fields["ics:uid_domains"], "exchange.corp.example.test");
    assert_eq!(m.stats["attendees"], 2);
    assert!(m.emails.contains(&"john.doe@example.org".to_string()));
    let m = meta("pim/contacts.vcf");
    assert_eq!(m.stats["cards"], 2);
    assert!(m.person_names().contains(&"John Doe • IT"));
    assert_eq!(
        m.fields["vcf:01.tel"],
        "+380 67 000 00 00; +380 44 000 00 01"
    );
    let photo = &m.embedded[0].metadata;
    assert_eq!(photo.format, DocFormat::Jpeg);
    assert!(photo.gps.is_some());
}

#[test]
fn media_fields() {
    let m = meta("media/survey.mp4");
    let g = m.gps.unwrap();
    assert!((g.lat - 50.4501).abs() < 1e-6 && (g.lon - 30.5234).abs() < 1e-6);
    assert_eq!(
        m.camera.as_ref().unwrap().model.as_deref(),
        Some("ActionCam 4")
    );
    assert_eq!(m.created.as_deref(), Some("2024-03-14T16:42:00Z"));
    assert_eq!(
        m.xmp["xmp:CreatorTool"],
        "Adobe Premiere Pro 2024 (Windows)"
    );
    let m = meta("media/iphone.mov");
    assert_eq!(
        m.camera.as_ref().unwrap().serial.as_deref(),
        Some("EXAMPLE-SN-0042")
    );
    assert!((m.gps.unwrap().lat - 46.4825).abs() < 1e-6);
    let m = meta("media/photo.heic");
    assert_eq!(
        m.camera.as_ref().unwrap().serial.as_deref(),
        Some("EXAMPLE-BODY-0042")
    );
    assert!(m.gps.is_some());
    assert_eq!(m.author.as_deref(), Some("Іван Петренко"));
    assert!(!meta("media/broken-iloc.heic").warnings.is_empty());
}

fn zip_with(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut w = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let opts = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    for (n, d) in entries {
        w.start_file(*n, opts).unwrap();
        w.write_all(d).unwrap();
    }
    w.finish().unwrap().into_inner()
}

#[test]
fn archive_recursion_and_limits() {
    let m = meta("archive/backup.zip");
    assert_eq!(m.stats["files"], 5);
    assert!(m.fields["zip:unsafe_names"].contains("../../evil.txt"));
    let formats: Vec<DocFormat> = m.embedded.iter().map(|e| e.metadata.format).collect();
    assert_eq!(
        formats,
        vec![
            DocFormat::Docx,
            DocFormat::Lnk,
            DocFormat::Eml,
            DocFormat::Zip
        ]
    );
    // nested zip -> vcf -> photo is cut by the depth limit (zip=0, inner zip=1, vcf=2, jpeg=3)
    let inner = &m.embedded[3].metadata;
    assert_eq!(inner.embedded[0].metadata.format, DocFormat::Vcf);
    // an oversized member is skipped, the rest is parsed
    let zeros = vec![0u8; 4 * 1024 * 1024];
    let lnk = corpus("lnk/report.lnk");
    let z = zip_with(&[("big.bin", &zeros), ("a.lnk", &lnk)]);
    let l = Limits {
        max_unzipped_total: 1024 * 1024,
        ..Limits::default()
    };
    let m = extract(&z, None, &l).unwrap();
    assert_eq!(m.format, DocFormat::Zip);
    assert_eq!(m.embedded.len(), 1);
    assert!(m.warnings.iter().any(|w| w.contains("big.bin")));
    // nested archives share one budget: a tower of zips each holding 300 KiB
    let pad = vec![b'a'; 300 * 1024];
    let mut tower = zip_with(&[("pad.txt", &pad)]);
    for _ in 0..4 {
        tower = zip_with(&[("pad.txt", &pad), ("next.zip", &tower)]);
    }
    let l = Limits {
        max_unzipped_total: 1024 * 1024,
        max_depth: 10,
        ..Limits::default()
    };
    match extract(&tower, None, &l) {
        Err(MetaError::ZipBomb(_)) => {}
        Ok(m) => {
            fn warned(m: &crate::Metadata) -> bool {
                !m.warnings.is_empty() || m.embedded.iter().any(|e| warned(&e.metadata))
            }
            assert!(warned(&m), "{m:?}");
        }
        Err(e) => panic!("{e:?}"),
    }
    // the member iterator respects the budget too
    let mut seen = Vec::new();
    crate::for_each_zip_member(&corpus("archive/backup.zip"), &Limits::default(), |n, b| {
        seen.push((n.to_string(), b.len()));
    })
    .unwrap();
    assert_eq!(seen.len(), 5);
    assert!(matches!(
        crate::for_each_zip_member(&z, &l, |_, _| {}),
        Err(MetaError::ZipBomb(_))
    ));
}

#[test]
fn deep_mime_and_many_parts_are_bounded() {
    let mut eml = String::from("From: a@example.com\r\nTo: b@example.com\r\nSubject: x\r\n");
    for i in 0..200 {
        eml.push_str(&format!(
            "Content-Type: multipart/mixed; boundary=\"b{i}\"\r\n\r\n--b{i}\r\n"
        ));
    }
    let r = extract(eml.as_bytes(), Some("x.eml"), &Limits::default());
    assert!(r.is_ok(), "{r:?}");
    let mut eml = String::from(
        "From: a@example.com\r\nTo: b@example.com\r\nSubject: x\r\nContent-Type: multipart/mixed; boundary=\"q\"\r\n\r\n",
    );
    for _ in 0..500 {
        eml.push_str("--q\r\nContent-Type: text/plain\r\n\r\nhi\r\n");
    }
    let l = Limits {
        max_entries: 100,
        ..Limits::default()
    };
    assert!(matches!(
        extract(eml.as_bytes(), None, &l),
        Err(MetaError::TooManyEntries(_))
    ));
}

/// Mutates `seed`: byte flips, truncation, splicing of random bytes and repeated chunks.
fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    match rng.next() % 6 {
        0 => {
            let n = 1 + rng.next() % 16;
            for _ in 0..n {
                if v.is_empty() {
                    break;
                }
                let i = (rng.next() as usize) % v.len();
                v[i] = rng.next() as u8;
            }
        }
        1 => {
            let keep = (rng.next() as usize) % (v.len() + 1);
            v.truncate(keep);
        }
        2 => {
            // interesting integers at random offsets (sizes and offsets in binary formats)
            let vals: [u32; 6] = [0, 1, 0x7FFF_FFFF, 0xFFFF_FFFF, 0x8000_0000, 0xFFFF];
            for _ in 0..4 {
                if v.len() < 4 {
                    break;
                }
                let i = (rng.next() as usize) % (v.len() - 3);
                let x = vals[(rng.next() as usize) % vals.len()];
                let b = if rng.next().is_multiple_of(2) {
                    x.to_le_bytes()
                } else {
                    x.to_be_bytes()
                };
                v[i..i + 4].copy_from_slice(&b);
            }
        }
        3 => {
            let i = (rng.next() as usize) % (v.len() + 1);
            let n = (rng.next() % 64) as usize;
            let junk: Vec<u8> = (0..n).map(|_| rng.next() as u8).collect();
            v.splice(i..i, junk);
        }
        4 => {
            if !v.is_empty() {
                let a = (rng.next() as usize) % v.len();
                let len = ((rng.next() as usize) % 256).min(v.len() - a);
                let chunk = v[a..a + len].to_vec();
                let at = (rng.next() as usize) % (v.len() + 1);
                for _ in 0..(1 + rng.next() % 8) {
                    v.splice(at..at, chunk.iter().copied());
                }
            }
        }
        _ => {
            if !v.is_empty() {
                let a = (rng.next() as usize) % v.len();
                let b = a + ((rng.next() as usize) % (v.len() - a + 1));
                v.drain(a..b);
            }
        }
    }
    v
}

fn is_panic(r: &Result<crate::Metadata, MetaError>) -> bool {
    matches!(r, Err(MetaError::Malformed { msg, .. }) if msg == "внутренняя ошибка парсера")
}

/// Runs mutated inputs of every seed; returns (inputs, failures).
fn run_mutations(per_seed: Option<usize>, secs_per_format: u64) -> (u64, Vec<String>) {
    let seeds_of = |fmt: DocFormat| SEEDS.iter().filter(|(_, f)| *f == fmt).count().max(1) as u64;
    let limits = Limits {
        max_unzipped_total: 32 * 1024 * 1024,
        ..Limits::default()
    };
    let out_dir = format!(
        "{}/../../target/fuzz-new-formats",
        env!("CARGO_MANIFEST_DIR")
    );
    let mut total = 0u64;
    let mut fails = Vec::new();
    for (k, (f, fmt)) in SEEDS.iter().enumerate() {
        let seed = corpus(f);
        let name = f.rsplit('/').next().unwrap_or("x");
        let mut rng = Rng(0x0F0C_A13D ^ (k as u64 + 1).wrapping_mul(0x9E37_79B9_7F4A_7C15));
        let start = Instant::now();
        let mut n = 0usize;
        let mut cur = seed.clone();
        loop {
            match per_seed {
                Some(max) if n >= max => break,
                None if start.elapsed()
                    >= Duration::from_millis(secs_per_format * 1000 / seeds_of(*fmt)) =>
                {
                    break
                }
                _ => {}
            }
            // occasionally keep mutating the previous input to go deeper
            let base = if n % 4 == 3 {
                cur.clone()
            } else {
                seed.clone()
            };
            let input = mutate(&mut rng, &base);
            let t0 = Instant::now();
            let r = extract(&input, Some(name), &limits);
            let _ = text(&input, &limits);
            let dt = t0.elapsed();
            if is_panic(&r) || dt > Duration::from_secs(2) {
                let _ = std::fs::create_dir_all(&out_dir);
                let p = format!("{out_dir}/{fmt:?}-{n}.bin");
                let _ = std::fs::write(&p, &input);
                fails.push(format!(
                    "{f}: {} ({dt:?}) -> {p}",
                    if is_panic(&r) { "panic" } else { "slow" }
                ));
            }
            cur = input;
            n += 1;
        }
        total += n as u64;
        if per_seed.is_none() {
            eprintln!("{fmt:?} ({f}): {n} inputs in {:?}", start.elapsed());
        }
    }
    (total, fails)
}

#[test]
fn mutated_corpus_never_panics() {
    let (n, fails) = run_mutations(Some(150), 0);
    assert!(n >= 150 * SEEDS.len() as u64);
    assert!(fails.is_empty(), "{fails:#?}");
}

#[test]
fn random_prefixed_bytes_never_panic() {
    let mut rng = Rng(0x5EED_0013_0001_0001);
    let prefixes: Vec<Vec<u8>> = vec![
        crate::formats::lnk::MAGIC.to_vec(),
        crate::formats::media::indesign::MAGIC.to_vec(),
        crate::formats::detect::SEVENZ_MAGIC.to_vec(),
        b"8BPS\x00\x01".to_vec(),
        b"ID3\x03\x00\x00\x00\x00\x00\x10".to_vec(),
        b"\xFFWPC".to_vec(),
        b"\0\0\0\x18ftypheic\0\0\0\0mif1heic".to_vec(),
        b"\0\0\0\x14ftypqt  \0\0\0\0qt  ".to_vec(),
        b"BEGIN:VCALENDAR\r\n".to_vec(),
        b"BEGIN:VCARD\r\n".to_vec(),
        b"From: a@example.com\r\nTo: b@example.com\r\nSubject: s\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x\r\n".to_vec(),
    ];
    let limits = Limits::default();
    for i in 0..1600 {
        let len = (rng.next() % 4096) as usize;
        let mut v = prefixes[i % prefixes.len()].clone();
        v.extend((0..len).map(|_| rng.next() as u8));
        let r = extract(&v, Some("x.eml"), &limits);
        assert!(!is_panic(&r), "prefix {}", i % prefixes.len());
        let _ = text(&v, &limits);
    }
}

#[test]
#[ignore = "long fuzzer: FOCA_FUZZ_SECS=<seconds per format>"]
fn fuzz_new_formats() {
    let secs: u64 = std::env::var("FOCA_FUZZ_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(30);
    // seeds of the same format share the time budget
    let (n, fails) = run_mutations(None, secs);
    eprintln!("total: {n} inputs, {} failures", fails.len());
    assert!(fails.is_empty(), "{fails:#?}");
}

#[test]
fn epub_mp3_psd_and_sevenz_extract_metadata_and_resist_zip_slip() {
    // 1. EPUB with META-INF/container.xml, content.opf (Dublin Core + generator) and embedded JPEG
    let container_xml = br#"<?xml version="1.0"?>
<container version="1.0" xmlns="urn:oasis:names:tc:opendocument:xmlns:container">
  <rootfiles>
    <rootfile full-path="OEBPS/content.opf" media-type="application/oebps-package+xml"/>
  </rootfiles>
</container>"#;
    let opf_xml = br#"<?xml version="1.0" encoding="UTF-8"?>
<package xmlns="http://www.idpf.org/2007/opf" version="3.0">
  <metadata xmlns:dc="http://purl.org/dc/elements/1.1/">
    <dc:title>Internal Security Guidelines</dc:title>
    <dc:creator>Olena Kovalenko</dc:creator>
    <dc:publisher>Contoso Energy LLC</dc:publisher>
    <dc:language>uk</dc:language>
    <dc:date>2026-10-15</dc:date>
    <dc:identifier>urn:uuid:12345678-1234-5678-1234-567812345678</dc:identifier>
    <meta name="generator" content="calibre 7.12.0"/>
    <meta property="dcterms:modified">2026-10-16T09:30:00Z</meta>
  </metadata>
</package>"#;
    let jpg = corpus("images/photo.jpg");
    let epub_bytes = zip_with(&[
        ("mimetype", b"application/epub+zip"),
        ("META-INF/container.xml", container_xml),
        ("OEBPS/content.opf", opf_xml),
        ("OEBPS/images/cover.jpg", &jpg),
    ]);
    assert_eq!(crate::detect(&epub_bytes), DocFormat::Epub);
    let m_epub = extract(&epub_bytes, Some("guide.epub"), &Limits::default()).unwrap();
    assert_eq!(m_epub.format, DocFormat::Epub);
    assert_eq!(
        m_epub.title.as_deref(),
        Some("Internal Security Guidelines")
    );
    assert_eq!(m_epub.author.as_deref(), Some("Olena Kovalenko"));
    assert_eq!(m_epub.company.as_deref(), Some("Contoso Energy LLC"));
    assert_eq!(m_epub.application.as_deref(), Some("calibre 7.12.0"));
    assert_eq!(m_epub.embedded.len(), 1);
    assert!(m_epub.embedded[0].metadata.gps.is_some());

    // 2. MP3 with ID3v2.3 frames (TIT2, TPE1, TPUB, TSSE, TDRC, APIC cover photo with GPS)
    fn id3_frame(id: &[u8; 4], text: &str) -> Vec<u8> {
        let payload_len = 1 + text.len();
        let mut f = Vec::new();
        f.extend_from_slice(id);
        f.extend_from_slice(&(payload_len as u32).to_be_bytes());
        f.extend_from_slice(&[0, 0]);
        f.push(3); // UTF-8
        f.extend_from_slice(text.as_bytes());
        f
    }
    let mut frames = Vec::new();
    frames.extend(id3_frame(b"TIT2", "Board Meeting Recording"));
    frames.extend(id3_frame(b"TPE1", "Ihor Petrenko"));
    frames.extend(id3_frame(b"TPUB", "Contoso Audio Dept"));
    frames.extend(id3_frame(b"TSSE", "Lavf60.16.100"));
    frames.extend(id3_frame(b"TDRC", "2026-11-01"));
    // APIC frame with embedded JPEG
    let mut apic_body = vec![0u8];
    apic_body.extend_from_slice(b"image/jpeg\0\x03cover\0");
    apic_body.extend_from_slice(&jpg);
    frames.extend_from_slice(b"APIC");
    frames.extend_from_slice(&(apic_body.len() as u32).to_be_bytes());
    frames.extend_from_slice(&[0, 0]);
    frames.extend_from_slice(&apic_body);

    let len = frames.len() as u32;
    let synch = [
        ((len >> 21) & 0x7F) as u8,
        ((len >> 14) & 0x7F) as u8,
        ((len >> 7) & 0x7F) as u8,
        (len & 0x7F) as u8,
    ];
    let mut mp3_bytes = Vec::new();
    mp3_bytes.extend_from_slice(b"ID3\x03\x00\x00");
    mp3_bytes.extend_from_slice(&synch);
    mp3_bytes.extend_from_slice(&frames);
    assert_eq!(crate::detect(&mp3_bytes), DocFormat::Mp3);
    let m_mp3 = extract(&mp3_bytes, Some("meeting.mp3"), &Limits::default()).unwrap();
    assert_eq!(m_mp3.format, DocFormat::Mp3);
    assert_eq!(m_mp3.title.as_deref(), Some("Board Meeting Recording"));
    assert_eq!(m_mp3.author.as_deref(), Some("Ihor Petrenko"));
    assert_eq!(m_mp3.company.as_deref(), Some("Contoso Audio Dept"));
    assert_eq!(m_mp3.application.as_deref(), Some("Lavf60.16.100"));
    assert_eq!(m_mp3.embedded.len(), 1);
    assert!(m_mp3.embedded[0].metadata.gps.is_some());

    // 3. PSD with 8BPS header and 8BIM 0x0424 XMP resource block
    let xmp_xml = br#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#" xmlns:xmp="http://ns.adobe.com/xap/1.0/" xmlns:dc="http://purl.org/dc/elements/1.1/"><rdf:Description xmp:CreatorTool="Adobe Photoshop 25.0 (Windows)"><dc:creator><rdf:Seq><rdf:li>Taras Shevchenko</rdf:li></rdf:Seq></dc:creator></rdf:Description></rdf:RDF></x:xmpmeta>"#;
    let mut psd_bytes = Vec::new();
    psd_bytes.extend_from_slice(b"8BPS\x00\x01\0\0\0\0\0\0");
    psd_bytes.extend_from_slice(&3u16.to_be_bytes()); // channels
    psd_bytes.extend_from_slice(&1080u32.to_be_bytes()); // height
    psd_bytes.extend_from_slice(&1920u32.to_be_bytes()); // width
    psd_bytes.extend_from_slice(&8u16.to_be_bytes()); // depth
    psd_bytes.extend_from_slice(&3u16.to_be_bytes()); // RGB
    psd_bytes.extend_from_slice(&0u32.to_be_bytes()); // color mode len = 0
    let mut ir = Vec::new();
    ir.extend_from_slice(b"8BIM");
    ir.extend_from_slice(&0x0424u16.to_be_bytes());
    ir.extend_from_slice(&[0, 0]); // empty pascal name padded to 2 bytes
    ir.extend_from_slice(&(xmp_xml.len() as u32).to_be_bytes());
    ir.extend_from_slice(xmp_xml);
    if !xmp_xml.len().is_multiple_of(2) {
        ir.push(0);
    }
    psd_bytes.extend_from_slice(&(ir.len() as u32).to_be_bytes());
    psd_bytes.extend_from_slice(&ir);
    assert_eq!(crate::detect(&psd_bytes), DocFormat::Psd);
    let m_psd = extract(&psd_bytes, Some("banner.psd"), &Limits::default()).unwrap();
    assert_eq!(m_psd.format, DocFormat::Psd);
    assert_eq!(m_psd.stats["width"], 1920);
    assert_eq!(m_psd.stats["height"], 1080);
    assert_eq!(m_psd.author.as_deref(), Some("Taras Shevchenko"));
    assert!(m_psd
        .software
        .iter()
        .any(|s| s.contains("Adobe Photoshop 25.0")));

    // 4. 7z archive with UTF-16LE file names (including Zip-Slip `../secret.doc`) and stored LNK child
    let lnk = corpus("lnk/report.lnk");
    let mut utf16_names = Vec::new();
    for name in ["report.lnk", "../secret.doc"] {
        for u in name.encode_utf16() {
            utf16_names.extend_from_slice(&u.to_le_bytes());
        }
        utf16_names.extend_from_slice(&0u16.to_le_bytes());
    }
    let mut hdr = vec![
        0x01,                          // kHeader
        0x05,                          // kFilesInfo
        0x11,                          // kName
        (1 + utf16_names.len()) as u8, // varint size (< 128)
        0x00,                          // external = 0
    ];
    hdr.extend_from_slice(&utf16_names);
    hdr.push(0x00); // kEnd

    let mut sz_bytes = Vec::new();
    sz_bytes.extend_from_slice(&crate::formats::detect::SEVENZ_MAGIC);
    sz_bytes.extend_from_slice(&[0x00, 0x04]); // version 0.4
    sz_bytes.extend_from_slice(&0u32.to_le_bytes()); // start header crc
    sz_bytes.extend_from_slice(&(lnk.len() as u64).to_le_bytes()); // next_header_offset
    sz_bytes.extend_from_slice(&(hdr.len() as u64).to_le_bytes()); // next_header_size
    sz_bytes.extend_from_slice(&0u32.to_le_bytes()); // next_header_crc
    sz_bytes.extend_from_slice(&lnk);
    sz_bytes.extend_from_slice(&hdr);

    assert_eq!(crate::detect(&sz_bytes), DocFormat::SevenZ);
    let m_7z = extract(&sz_bytes, Some("backup.7z"), &Limits::default()).unwrap();
    assert_eq!(m_7z.format, DocFormat::SevenZ);
    assert_eq!(m_7z.stats["archive_files"], 2);
    assert_eq!(m_7z.stats["archive_unsafe_names"], 1);
    assert_eq!(m_7z.embedded.len(), 1);
    assert_eq!(m_7z.embedded[0].metadata.format, DocFormat::Lnk);
}

#[test]
fn ole10_native_and_clean_ole_and_isobmff_roundtrip() {
    use std::io::{Cursor, Write};

    // 1. OLE2 with `\u{1}Ole10Native` embedded package containing a LNK file and host paths
    let lnk = corpus("lnk/report.lnk");
    let mut ole10 = Vec::new();
    ole10.extend_from_slice(&0u32.to_le_bytes()); // total_size placeholder
    ole10.extend_from_slice(&2u16.to_le_bytes()); // flags1 = 2 (packaged file)
    ole10.extend_from_slice(b"report.lnk\0");
    ole10.extend_from_slice(b"C:\\Users\\ivan.petrenko\\Desktop\\report.lnk\0");
    ole10.extend_from_slice(&[0u8; 8]); // unknown1 + unknown2
    ole10.extend_from_slice(b"C:\\Users\\ivan.petrenko\\AppData\\Local\\Temp\\report.lnk\0");
    ole10.extend_from_slice(&(lnk.len() as u32).to_le_bytes());
    ole10.extend_from_slice(&lnk);
    let total_sz = (ole10.len() - 4) as u32;
    ole10[0..4].copy_from_slice(&total_sz.to_le_bytes());

    let cur = Cursor::new(Vec::new());
    let mut cf = cfb::CompoundFile::create(cur).unwrap();
    {
        let mut s = cf.create_stream("/\u{1}Ole10Native").unwrap();
        s.write_all(&ole10).unwrap();
    }
    let ole_bytes = cf.into_inner().into_inner();
    let m_ole = extract(&ole_bytes, Some("package.doc"), &Limits::default()).unwrap();
    assert_eq!(
        m_ole.fields.get("ole10:filename").map(String::as_str),
        Some("report.lnk")
    );
    assert!(m_ole
        .paths
        .iter()
        .any(|p| p.path.contains("ivan.petrenko\\Desktop\\report.lnk")));
    assert_eq!(m_ole.embedded.len(), 1);
    assert_eq!(m_ole.embedded[0].metadata.format, DocFormat::Lnk);

    // 2. Clean & verify binary OLE2 (.doc, .xls, .vsd, .pub) and ISO-BMFF (.mp4, .mov, .heic)
    for rel in [
        "ole/legacy.doc",
        "ole/budget.xls",
        "real/poi-SampleDoc.doc",
        "legacy/network.vsd",
        "legacy/leaflet.pub",
        "media/survey.mp4",
        "media/iphone.mov",
        "media/photo.heic",
    ] {
        let raw = corpus(rel);
        let kind = crate::detect(&raw);
        let res = crate::clean_and_verify(
            &raw,
            kind,
            &crate::CleanOptions::default(),
            &Limits::default(),
        )
        .unwrap_or_else(|e| panic!("clean_and_verify failed for {rel}: {e}"));
        assert!(
            res.report.clean && res.report.valid,
            "{rel} still had sensitive fields after clean: {:?}, valid={}, error={:?}",
            res.report.remaining,
            res.report.valid,
            res.report.error
        );
        assert!(!res.bytes.is_empty());
    }
}
