//! RTF parser tests: information group, code pages, Unicode, revisions, annotations, fields,
//! embedded objects and pictures, robustness.

use crate::util::Rng;
use crate::{extract, text, DocFormat, Limits};

fn ex(s: &[u8]) -> crate::Metadata {
    extract(s, Some("doc.rtf"), &Limits::default()).expect("rtf parses")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

#[test]
fn detects_by_magic_only() {
    assert_eq!(crate::detect(b"{\\rtf1\\ansi hello}"), DocFormat::Rtf);
    assert_eq!(crate::detect(b" {\\rtf1 x}"), DocFormat::Unknown);
}

#[test]
fn info_group_and_generator() {
    let doc = br"{\rtf1\ansi\ansicpg1252\deff0{\fonttbl{\f0 Arial;}}
{\*\generator Msftedit 5.41.21.2509;}
{\info{\title Quarterly plan}{\author Anna Smith}{\operator Bob Jones}{\company Contoso Ltd}
{\manager Carol}{\keywords plan, q3}{\doccomm Internal only}{\*\company Contoso}
{\creatim\yr2013\mo12\dy23\hr10\min5}{\revtim\yr2014\mo3\dy27\hr8\min0}{\printim\yr2014\mo3\dy28}
\version7\vern49255\edmins42\nofpages3\nofwords120\nofchars800}
{\*\userprops {\propname Project}\proptype30{\staticval Apollo}}
{\*\template \\\\fs01\\templates\\corp.dotm}
\pard Hello world\par}";
    let m = ex(doc);
    assert_eq!(m.format, DocFormat::Rtf);
    assert_eq!(m.title.as_deref(), Some("Quarterly plan"));
    assert_eq!(m.author.as_deref(), Some("Anna Smith"));
    assert_eq!(m.last_modified_by.as_deref(), Some("Bob Jones"));
    assert_eq!(m.company.as_deref(), Some("Contoso"));
    assert_eq!(m.manager.as_deref(), Some("Carol"));
    assert_eq!(m.description.as_deref(), Some("Internal only"));
    assert_eq!(m.created.as_deref(), Some("2013-12-23T10:05:00"));
    assert_eq!(m.modified.as_deref(), Some("2014-03-27T08:00:00"));
    assert_eq!(m.printed.as_deref(), Some("2014-03-28T00:00:00"));
    assert_eq!(m.revision.as_deref(), Some("7"));
    assert_eq!(m.edit_time_secs, Some(42 * 60));
    assert_eq!(m.stats.get("pages"), Some(&3));
    assert_eq!(m.application.as_deref(), Some("Msftedit 5.41.21.2509"));
    assert_eq!(m.custom.get("Project").map(String::as_str), Some("Apollo"));
    assert_eq!(
        m.template.as_deref(),
        Some("\\\\fs01\\templates\\corp.dotm")
    );
    assert!(m.paths.iter().any(|p| p.path.contains("fs01")));
    let t = text(doc, &Limits::default()).unwrap();
    assert!(t.contains("Hello world"));
    assert!(!t.contains("Arial"));
    assert!(!t.contains("Quarterly"));
}

#[test]
fn cyrillic_ansicpg1251_and_fcharset204() {
    // "Привет" in cp1251 through \'hh, author through \fcharset204 font
    let doc = br"{\rtf1\ansi\ansicpg1251\deff0{\fonttbl{\f0\fcharset204 Times New Roman;}{\f1\fcharset0 Arial;}}
{\info{\author \'c8\'e2\'e0\'ed\'ee\'e2}}
\pard\f0 \'cf\'f0\'e8\'e2\'e5\'f2 \f1 caf\'e9\par}";
    let m = ex(doc);
    assert_eq!(m.author.as_deref(), Some("Иванов"));
    let t = text(doc, &Limits::default()).unwrap();
    assert!(t.contains("Привет"), "{t}");
    assert!(t.contains("café"), "{t}");
}

#[test]
fn cjk_code_pages_and_unicode() {
    // Shift-JIS (fcharset128) and GBK (fcharset134) double-byte sequences, \u Arabic with
    // ANSI fallbacks, a surrogate pair and \uc0
    let doc = br"{\rtf1\ansi\ansicpg1252{\fonttbl{\f1\fcharset128 MS Mincho;}{\f2\fcharset134 SimSun;}}
\pard\f1 \'93\'fa\'96\'7b \f2 \'d6\'d0\'ce\'c4 \f0\u1605?\u1585?\u1581?\u1576?\u1575? {\uc0\u-10179\u-8704 }{\uc2\u20013\'3f\'3f}\par}";
    let t = text(doc, &Limits::default()).unwrap();
    assert!(t.contains("日本"), "{t}");
    assert!(t.contains("中文"), "{t}");
    assert!(t.contains("مرحبا"), "{t}");
    assert!(t.contains('\u{1F600}'), "{t}");
    assert!(t.contains('中'), "{t}");
    assert!(!t.contains('?'), "{t}");
}

#[test]
fn revisions_hidden_and_annotations() {
    let doc = br"{\rtf1\ansi{\*\revtbl {Unknown;}{Maria Garcia;}{Li Wei;}}
\pard Visible {\v secret hidden note} text {\deleted\revauthdel1 removed words} end.
{\*\atnid MG}{\*\atnauthor Maria Garcia}\chatn{\*\annotation{\*\atndate 0}\pard Please check budget}\par}";
    let m = ex(doc);
    assert!(m.people.iter().any(|p| p.name == "Li Wei"));
    assert!(m
        .hidden_content
        .iter()
        .any(|h| h.text == "secret hidden note"));
    let r = m.revisions.first().expect("deleted run");
    assert_eq!(r.text, "removed words");
    assert_eq!(r.author.as_deref(), Some("Maria Garcia"));
    let c = m.comments.first().expect("annotation");
    assert_eq!(c.author.as_deref(), Some("Maria Garcia"));
    assert_eq!(c.initials.as_deref(), Some("MG"));
    assert_eq!(c.text, "Please check budget");
    let t = text(doc, &Limits::default()).unwrap();
    assert!(t.contains("Visible"));
    assert!(!t.contains("removed words"));
    assert!(t.contains("Please check budget"));
}

#[test]
fn field_targets() {
    let doc = br#"{\rtf1\ansi
{\field{\*\fldinst {HYPERLINK "http://intranet.corp.example/wiki"}}{\fldrslt wiki}}
{\field{\*\fldinst INCLUDEPICTURE "\\\\\\\\fileserver\\\\share\\\\logo.png" \\* MERGEFORMATINET}{\fldrslt }}
{\field{\*\fldinst DDEAUTO c:\\windows\\system32\\cmd.exe "/k calc"}{\fldrslt }}}"#;
    let m = ex(doc);
    assert!(m
        .links
        .iter()
        .any(|l| l == "http://intranet.corp.example/wiki"));
    assert!(
        m.links
            .iter()
            .any(|l| l == "\\\\fileserver\\share\\logo.png"),
        "{:?}",
        m.links
    );
    assert!(m
        .servers
        .iter()
        .any(|s| s.name.eq_ignore_ascii_case("fileserver")));
    assert!(m
        .fields
        .get("rtf:dde")
        .is_some_and(|v| v.contains("cmd.exe")));
}

/// OLE1 object header for an embedded object of `class` with `native` data.
fn ole1(class: &str, native: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&0x0501u32.to_le_bytes());
    v.extend_from_slice(&2u32.to_le_bytes());
    for s in [class, "", ""] {
        let mut z = s.as_bytes().to_vec();
        z.push(0);
        v.extend_from_slice(&(z.len() as u32).to_le_bytes());
        v.extend_from_slice(&z);
    }
    v.extend_from_slice(&(native.len() as u32).to_le_bytes());
    v.extend_from_slice(native);
    v
}

#[test]
fn package_object_paths() {
    // packager native data: u16 2, label, source path, u16 0, u16 3, u32 len, temp path, data
    let mut native = vec![2, 0];
    native.extend_from_slice(b"report.txt\0C:\\Users\\jdoe\\Desktop\\report.txt\0");
    native.extend_from_slice(&[0, 0, 3, 0]);
    let tmp = b"C:\\Users\\jdoe\\AppData\\Local\\Temp\\report.txt\0";
    native.extend_from_slice(&(tmp.len() as u32).to_le_bytes());
    native.extend_from_slice(tmp);
    let data = b"user=admin password=hunter2";
    native.extend_from_slice(&(data.len() as u32).to_le_bytes());
    native.extend_from_slice(data);
    let doc = format!(
        "{{\\rtf1{{\\object\\objemb{{\\*\\objclass Package}}{{\\*\\objdata {}}}}}}}",
        hex(&ole1("Package", &native))
    );
    let m = ex(doc.as_bytes());
    assert!(
        m.paths
            .iter()
            .any(|p| p.path.contains("Desktop\\report.txt")),
        "{:?}",
        m.paths
    );
    assert!(m.paths.iter().any(|p| p.path.contains("Temp")));
    assert!(m.people.iter().any(|p| p.name == "jdoe"));
    assert_eq!(m.stats.get("objects"), Some(&1));
}

#[test]
fn embedded_compound_file_and_picture() {
    let png = {
        let mut v = b"\x89PNG\r\n\x1a\n".to_vec();
        let ihdr = [0u8, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0];
        v.extend_from_slice(&(ihdr.len() as u32).to_be_bytes());
        v.extend_from_slice(b"IHDR");
        v.extend_from_slice(&ihdr);
        v.extend_from_slice(&[0, 0, 0, 0]);
        let txt = b"Author\0Picture Maker";
        v.extend_from_slice(&(txt.len() as u32).to_be_bytes());
        v.extend_from_slice(b"tEXt");
        v.extend_from_slice(txt);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(&[0, 0, 0, 0]);
        v.extend_from_slice(b"IEND");
        v.extend_from_slice(&[0xAE, 0x42, 0x60, 0x82]);
        v
    };
    let doc = format!(
        "{{\\rtf1 x{{\\*\\shppict{{\\pict\\pngblip\\picw1\\pich1 {}}}}}{{\\nonshppict{{\\pict\\wmetafile8 0102}}}}}}",
        hex(&png)
    );
    let m = ex(doc.as_bytes());
    assert_eq!(m.embedded.len(), 1, "{:?}", m.warnings);
    assert_eq!(m.attachments.len(), 1);
    assert_eq!(m.stats.get("images"), Some(&2));
    let t = text(doc.as_bytes(), &Limits::default()).unwrap();
    assert!(!t.contains("8950"), "hex must not leak into text: {t}");
}

#[test]
fn malformed_input_never_panics() {
    let base = br"{\rtf1\ansi\ansicpg1251{\fonttbl{\f0\fcharset204 X;}}{\info{\author \'c8}{\creatim\yr2013}}{\*\objdata 0105000002000000}{\pict\jpegblip ffd8ff}\u-1\uc9\bin5 abc\'zz\'4{\field{\*\fldinst HYPERLINK}}text}";
    let limits = Limits::default();
    for n in 0..base.len() {
        let _ = extract(&base[..n], None, &limits);
        let _ = text(&base[..n], &limits);
    }
    let mut rng = Rng(0xF0CA_0001);
    for _ in 0..400 {
        let mut v = base.to_vec();
        for _ in 0..4 {
            let i = (rng.next() as usize) % v.len();
            v[i] = rng.next() as u8;
        }
        v[..5].copy_from_slice(b"{\\rtf");
        let _ = extract(&v, None, &limits);
        let _ = text(&v, &limits);
    }
    // deep nesting and a huge \bin
    let mut deep = b"{\\rtf1".to_vec();
    deep.extend(std::iter::repeat_n(b'{', 100_000));
    deep.extend_from_slice(b"x");
    assert!(extract(&deep, None, &limits).is_ok());
    assert!(extract(b"{\\rtf1{\\pict\\bin999999999 ab}}", None, &limits).is_ok());
}
