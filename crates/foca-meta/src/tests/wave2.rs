//! Formats added in 2.0.0-beta.4: synthetic fixtures built in code (PE, MSI, JAR, APK, DWG,
//! DXF, EPS, EMF, TAR, gzip, RAR, WAV, Matroska, ASF, FLAC, Ogg, KML/KMZ, GPX, source maps,
//! notebooks, ZIP central directory extras), detection, key fields and a mutation pass per
//! format that must never reach the panic guard.

use std::io::{Cursor, Write};

use foca_core::{DocFormat, SignatureKind};

use crate::util::Rng;
use crate::{detect, detect_with_hint, extract, text, Limits, MetaError};

const P7: &[u8] = include_bytes!("../../tests/fixtures/wave2/codesign.p7");
const CERT: &[u8] = include_bytes!("../../tests/fixtures/wave2/codesign.der");

fn utf16z(s: &str) -> Vec<u8> {
    let mut v: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
    v.extend_from_slice(&[0, 0]);
    v
}

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

fn put16(v: &mut [u8], at: usize, x: u16) {
    v[at..at + 2].copy_from_slice(&x.to_le_bytes());
}

fn put32(v: &mut [u8], at: usize, x: u32) {
    v[at..at + 4].copy_from_slice(&x.to_le_bytes());
}

fn zip_of(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut buf = Vec::new();
    {
        let mut zw = zip::ZipWriter::new(Cursor::new(&mut buf));
        let opts = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        for (n, d) in entries {
            zw.start_file(*n, opts).unwrap();
            zw.write_all(d).unwrap();
        }
        zw.finish().unwrap();
    }
    buf
}

fn run(b: &[u8], name: &str) -> crate::Metadata {
    extract(b, Some(name), &Limits::default()).unwrap_or_else(|e| panic!("{name}: {e}"))
}

// ---------------------------------------------------------------- PE

/// One `VS_VERSIONINFO` node.
fn vs_node(key: &str, value: &[u8], text: bool, children: &[Vec<u8>]) -> Vec<u8> {
    let mut v = vec![0u8; 6];
    v.extend(utf16z(key));
    pad4(&mut v);
    v.extend_from_slice(value);
    pad4(&mut v);
    for c in children {
        v.extend_from_slice(c);
        pad4(&mut v);
    }
    let len = v.len() as u16;
    put16(&mut v, 0, len);
    let vlen = if text {
        (value.len() / 2) as u16
    } else {
        value.len() as u16
    };
    put16(&mut v, 2, vlen);
    put16(&mut v, 4, u16::from(text));
    v
}

fn version_info() -> Vec<u8> {
    let strings: Vec<Vec<u8>> = [
        ("CompanyName", "Example Software Ltd"),
        ("ProductName", "Example Billing"),
        ("FileVersion", "1.2.3.4"),
        ("ProductVersion", "1.2.3"),
        ("OriginalFilename", "Billing.dll"),
        ("InternalName", "Billing"),
        ("LegalCopyright", "(c) Example Software Ltd"),
    ]
    .iter()
    .map(|(k, v)| vs_node(k, &utf16z(v), true, &[]))
    .collect();
    let table = vs_node("040904b0", &[], true, &strings);
    let sfi = vs_node("StringFileInfo", &[], true, &[table]);
    let mut fixed = vec![0u8; 52];
    put32(&mut fixed, 0, 0xFEEF_04BD);
    put32(&mut fixed, 8, 0x0001_0002);
    put32(&mut fixed, 12, 0x0003_0004);
    vs_node("VS_VERSION_INFO", &fixed, false, &[sfi])
}

pub(super) fn pe_fixture() -> Vec<u8> {
    let mut b = vec![0u8; 0x400];
    b[0..2].copy_from_slice(b"MZ");
    put32(&mut b, 0x3C, 0x80);
    b[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    put16(&mut b, coff, 0x8664);
    put16(&mut b, coff + 2, 1);
    put32(&mut b, coff + 4, 1_600_000_000);
    put16(&mut b, coff + 16, 240);
    put16(&mut b, coff + 18, 0x2022);
    let opt = coff + 20;
    put16(&mut b, opt, 0x20b);
    b[opt + 2] = 14;
    b[opt + 3] = 29;
    put16(&mut b, opt + 40, 6);
    put16(&mut b, opt + 68, 2);
    put32(&mut b, opt + 108, 16);
    let dirs = opt + 112;
    let sect = opt + 240;
    b[sect..sect + 5].copy_from_slice(b".rsrc");
    put32(&mut b, sect + 8, 0x1000);
    put32(&mut b, sect + 12, 0x1000);
    put32(&mut b, sect + 16, 0x1000);
    put32(&mut b, sect + 20, 0x400);
    // section data
    let mut s = vec![0u8; 0x1000];
    // resource tree: root -> type 16 -> name 1 -> lang 0x409 -> data entry
    put16(&mut s, 14, 1);
    put32(&mut s, 16, 16);
    put32(&mut s, 20, 0x8000_0018);
    put16(&mut s, 0x18 + 14, 1);
    put32(&mut s, 0x18 + 16, 1);
    put32(&mut s, 0x18 + 20, 0x8000_0030);
    put16(&mut s, 0x30 + 14, 1);
    put32(&mut s, 0x30 + 16, 0x409);
    put32(&mut s, 0x30 + 20, 0x48);
    let vi = version_info();
    put32(&mut s, 0x48, 0x1100);
    put32(&mut s, 0x4C, vi.len() as u32);
    s[0x100..0x100 + vi.len()].copy_from_slice(&vi);
    // debug directory at RVA 0x1800 -> CodeView at file offset 0x400 + 0x900
    let mut rsds = b"RSDS".to_vec();
    rsds.extend((1..=16).collect::<Vec<u8>>());
    rsds.extend(1u32.to_le_bytes());
    rsds.extend(br"C:\Users\jdeveloper\source\repos\Billing\obj\Release\Billing.pdb");
    rsds.push(0);
    put32(&mut s, 0x800 + 12, 2);
    put32(&mut s, 0x800 + 16, rsds.len() as u32);
    put32(&mut s, 0x800 + 20, 0x1900);
    put32(&mut s, 0x800 + 24, 0x400 + 0x900);
    s[0x900..0x900 + rsds.len()].copy_from_slice(&rsds);
    // CLR header at RVA 0x1A00, metadata root at 0x1A80
    put32(&mut s, 0xA00, 72);
    put32(&mut s, 0xA00 + 8, 0x1A80);
    put32(&mut s, 0xA00 + 12, 0x40);
    s[0xA80..0xA84].copy_from_slice(b"BSJB");
    put32(&mut s, 0xA80 + 12, 12);
    s[0xA80 + 16..0xA80 + 26].copy_from_slice(b"v4.0.30319");
    b.extend_from_slice(&s);
    // certificate table at the end of the file
    let cert_off = b.len();
    let mut wc = vec![0u8; 8];
    put32(&mut wc, 0, (8 + P7.len()) as u32);
    put16(&mut wc, 4, 0x200);
    put16(&mut wc, 6, 2);
    wc.extend_from_slice(P7);
    while !wc.len().is_multiple_of(8) {
        wc.push(0);
    }
    b.extend_from_slice(&wc);
    for (i, (a, l)) in [
        (2usize, (0x1000u32, 0x800u32)),
        (4, (cert_off as u32, wc.len() as u32)),
        (6, (0x1800, 28)),
        (14, (0x1A00, 72)),
    ] {
        put32(&mut b, dirs + i * 8, a);
        put32(&mut b, dirs + i * 8 + 4, l);
    }
    b
}

#[test]
fn pe_version_pdb_signer() {
    let b = pe_fixture();
    assert_eq!(detect(&b), DocFormat::Exe);
    let m = run(&b, "Billing.dll");
    assert_eq!(m.format, DocFormat::Exe);
    assert_eq!(m.company.as_deref(), Some("Example Software Ltd"));
    assert_eq!(m.fields["pe:OriginalFilename"], "Billing.dll");
    assert_eq!(m.fields["pe:FileVersionNumber"], "1.2.3.4");
    assert_eq!(m.fields["pe:machine"], "x64");
    assert_eq!(m.fields["pe:type"], "dll");
    assert_eq!(m.fields["pe:timestamp"], "2020-09-13T12:26:40Z");
    assert_eq!(m.fields["pe:dotnet_runtime"], "v4.0.30319");
    assert_eq!(
        m.fields["pe:build_folder"],
        r"C:\Users\jdeveloper\source\repos\Billing"
    );
    assert!(m.fields["pe:pdb_guid"].starts_with("04030201-0605-0807-090A"));
    assert!(m
        .paths
        .iter()
        .any(|p| p.source == "pe:pdb" && p.user.as_deref() == Some("jdeveloper")));
    assert!(m.people.iter().any(|p| p.name == "jdeveloper"));
    assert!(m.software.iter().any(|s| s == "Example Billing 1.2.3"));
    let sig = m
        .signatures
        .iter()
        .find(|s| s.kind == SignatureKind::Authenticode)
        .expect("authenticode");
    let signer = sig.signer.as_ref().unwrap();
    assert_eq!(signer.common_name.as_deref(), Some("Jane Developer"));
    assert_eq!(m.fields["pe:signer_org"], "Example Software Ltd");
    // a file without the MZ header is not PE
    assert_ne!(detect(&b[2..]), DocFormat::Exe);
}

// ---------------------------------------------------------------- MSI

fn property_set_lpstr(props: &[(u32, &str)]) -> Vec<u8> {
    let mut sec = Vec::new();
    let n = props.len() + 1;
    let mut offsets = Vec::new();
    let mut body = Vec::new();
    let base = 8 + n * 8;
    // codepage 1252
    offsets.push((1u32, base as u32));
    body.extend(2u32.to_le_bytes());
    body.extend(1252u16.to_le_bytes());
    body.extend([0, 0]);
    for (pid, s) in props {
        offsets.push((*pid, (base + body.len()) as u32));
        body.extend(0x1Eu32.to_le_bytes());
        body.extend(((s.len() + 1) as u32).to_le_bytes());
        body.extend(s.as_bytes());
        body.push(0);
        pad4(&mut body);
    }
    sec.extend(((base + body.len()) as u32).to_le_bytes());
    sec.extend((n as u32).to_le_bytes());
    for (pid, off) in offsets {
        sec.extend(pid.to_le_bytes());
        sec.extend(off.to_le_bytes());
    }
    sec.extend(body);
    let mut out = Vec::new();
    out.extend([0xFE, 0xFF, 0, 0]);
    out.extend(0x0002_0006u32.to_le_bytes());
    out.extend([0u8; 16]);
    out.extend(1u32.to_le_bytes());
    out.extend([
        0xE0, 0x85, 0x9F, 0xF2, 0xF9, 0x4F, 0x68, 0x10, 0xAB, 0x91, 0x08, 0x00, 0x2B, 0x27, 0xB3,
        0xD9,
    ]);
    out.extend(48u32.to_le_bytes());
    out.extend(sec);
    out
}

fn msi_fixture() -> Vec<u8> {
    let cur = Cursor::new(Vec::new());
    let mut cf = cfb::CompoundFile::create(cur).unwrap();
    cf.set_storage_clsid("/", "000c1084-0000-0000-c000-000000000046".parse().unwrap())
        .unwrap();
    let ps = property_set_lpstr(&[
        (2, "Installation Database"),
        (3, "Example Billing"),
        (4, "Example Software Ltd"),
        (7, "x64;1033"),
        (8, "build-agent"),
        (9, "{6F1B2C3D-0000-4000-8000-0000000000AA}"),
        (18, "Windows Installer XML Toolset (3.11.2.4516)"),
    ]);
    let mut s = cf.create_stream("/\u{5}SummaryInformation").unwrap();
    s.write_all(&ps).unwrap();
    drop(s);
    cf.into_inner().into_inner()
}

#[test]
fn msi_summary() {
    let b = msi_fixture();
    assert_eq!(detect(&b), DocFormat::Msi);
    let m = run(&b, "setup.msi");
    assert_eq!(m.author.as_deref(), Some("Example Software Ltd"));
    assert_eq!(m.last_modified_by.as_deref(), Some("build-agent"));
    assert_eq!(m.fields["msi:platform"], "x64;1033");
    assert_eq!(
        m.fields["msi:package_code"],
        "{6F1B2C3D-0000-4000-8000-0000000000AA}"
    );
    assert!(m.template.is_none() && m.revision.is_none());
    assert!(m
        .software
        .iter()
        .any(|s| s.starts_with("Windows Installer XML")));
}

// ---------------------------------------------------------------- JAR / APK

fn jar_fixture() -> Vec<u8> {
    zip_of(&[
        (
            "META-INF/MANIFEST.MF",
            b"Manifest-Version: 1.0\r\nBuilt-By: jbuilder\r\nCreated-By: Apache Maven 3.8.6\r\nBuild-Jdk: 17.0.2\r\nImplementation-Title: billing-core\r\nImplementation-Version: 4.1.0\r\nImplementation-Vendor: Example Software Ltd\r\n\r\n",
        ),
        (
            "META-INF/maven/com.example/billing-core/pom.properties",
            b"#Generated by Maven\ngroupId=com.example\nartifactId=billing-core\nversion=4.1.0\n",
        ),
        ("com/example/App.class", b"\xCA\xFE\xBA\xBE"),
        ("WEB-INF/lib/log4j-core-2.14.1.jar", b"PK"),
        ("META-INF/CERT.RSA", P7),
    ])
}

#[test]
fn jar_manifest_maven_signer() {
    let b = jar_fixture();
    assert_eq!(detect(&b), DocFormat::Jar);
    let m = run(&b, "billing.war");
    assert_eq!(m.author.as_deref(), Some("jbuilder"));
    assert_eq!(m.company.as_deref(), Some("Example Software Ltd"));
    assert!(m.software.iter().any(|s| s == "Java JDK 17.0.2"));
    assert!(m.software.iter().any(|s| s == "log4j-core 2.14.1"));
    assert!(m.software.iter().any(|s| s == "billing-core 4.1.0"));
    assert_eq!(
        m.fields["maven:billing-core"],
        "com.example:billing-core:4.1.0"
    );
    assert_eq!(m.signatures[0].kind, SignatureKind::Jar);
    assert!(m.people.iter().any(|p| p.name == "Jane Developer"));
}

/// Builds a tiny AXML document: `<manifest package versionName versionCode>` and one
/// `<uses-permission name>`.
fn axml_fixture() -> Vec<u8> {
    let strings = [
        "manifest",
        "package",
        "versionName",
        "versionCode",
        "com.example.field",
        "2.4.1",
        "uses-permission",
        "name",
        "android.permission.CAMERA",
    ];
    // string pool (UTF-16)
    let mut data = Vec::new();
    let mut offs = Vec::new();
    for s in &strings {
        offs.push(data.len() as u32);
        let u: Vec<u16> = s.encode_utf16().collect();
        data.extend((u.len() as u16).to_le_bytes());
        for c in u {
            data.extend(c.to_le_bytes());
        }
        data.extend([0, 0]);
    }
    pad4(&mut data);
    let hsize = 28u16;
    let start = hsize as u32 + 4 * strings.len() as u32;
    let mut pool = Vec::new();
    pool.extend(1u16.to_le_bytes());
    pool.extend(hsize.to_le_bytes());
    pool.extend(0u32.to_le_bytes());
    pool.extend((strings.len() as u32).to_le_bytes());
    pool.extend(0u32.to_le_bytes());
    pool.extend(0u32.to_le_bytes());
    pool.extend(start.to_le_bytes());
    pool.extend(0u32.to_le_bytes());
    for o in offs {
        pool.extend(o.to_le_bytes());
    }
    pool.extend(data);
    let plen = pool.len() as u32;
    put32(&mut pool, 4, plen);
    let elem = |name: u32, attrs: &[(u32, u32, u8, u32)]| {
        let mut e = Vec::new();
        e.extend(0x0102u16.to_le_bytes());
        e.extend(16u16.to_le_bytes());
        e.extend(0u32.to_le_bytes());
        e.extend(1u32.to_le_bytes());
        e.extend(u32::MAX.to_le_bytes());
        e.extend(u32::MAX.to_le_bytes());
        e.extend(name.to_le_bytes());
        e.extend(20u16.to_le_bytes());
        e.extend(20u16.to_le_bytes());
        e.extend((attrs.len() as u16).to_le_bytes());
        e.extend([0u8; 6]);
        for (n, raw, ty, d) in attrs {
            e.extend(u32::MAX.to_le_bytes());
            e.extend(n.to_le_bytes());
            e.extend(raw.to_le_bytes());
            e.extend(8u16.to_le_bytes());
            e.push(0);
            e.push(*ty);
            e.extend(d.to_le_bytes());
        }
        let l = e.len() as u32;
        put32(&mut e, 4, l);
        e
    };
    let m = elem(0, &[(1, 4, 3, 4), (2, 5, 3, 5), (3, u32::MAX, 0x10, 241)]);
    let p = elem(6, &[(7, 8, 3, 8)]);
    let mut doc = Vec::new();
    doc.extend(3u16.to_le_bytes());
    doc.extend(8u16.to_le_bytes());
    doc.extend(0u32.to_le_bytes());
    doc.extend(pool);
    doc.extend(m);
    doc.extend(p);
    let l = doc.len() as u32;
    put32(&mut doc, 4, l);
    doc
}

/// Inserts an APK Signature Scheme v2 block with `cert` before the central directory.
fn with_signing_block(zip: Vec<u8>, cert: &[u8]) -> Vec<u8> {
    let eocd = (0..zip.len() - 21)
        .rev()
        .find(|&i| &zip[i..i + 4] == b"PK\x05\x06")
        .unwrap();
    let cd = u32::from_le_bytes(zip[eocd + 16..eocd + 20].try_into().unwrap()) as usize;
    let lp = |v: &[u8]| {
        let mut o = (v.len() as u32).to_le_bytes().to_vec();
        o.extend_from_slice(v);
        o
    };
    let certs = lp(&lp(cert));
    let mut signed = lp(&[]);
    signed.extend(certs);
    let signer = lp(&lp(&signed));
    let signers = lp(&signer);
    let mut pair = Vec::new();
    pair.extend(((signers.len() + 4) as u64).to_le_bytes());
    pair.extend(0x7109_871au32.to_le_bytes());
    pair.extend(signers);
    let size = (pair.len() + 8 + 16) as u64;
    let mut block = size.to_le_bytes().to_vec();
    block.extend(pair);
    block.extend(size.to_le_bytes());
    block.extend(b"APK Sig Block 42");
    let mut out = zip[..cd].to_vec();
    out.extend(&block);
    out.extend(&zip[cd..]);
    let new_eocd = eocd + block.len();
    put32(&mut out, new_eocd + 16, (cd + block.len()) as u32);
    out
}

#[test]
fn apk_manifest_and_v2_signer() {
    let axml = axml_fixture();
    let z = zip_of(&[
        ("AndroidManifest.xml", &axml),
        ("classes.dex", b"dex\n035\0"),
    ]);
    let b = with_signing_block(z, CERT);
    assert_eq!(detect(&b), DocFormat::Apk);
    let m = run(&b, "field.apk");
    assert_eq!(m.fields["apk:package"], "com.example.field");
    assert_eq!(m.fields["apk:versionName"], "2.4.1");
    assert_eq!(m.fields["apk:versionCode"], "241");
    assert_eq!(m.fields["apk:permissions"], "android.permission.CAMERA");
    let s = &m.signatures[0];
    assert_eq!(s.source, "apk:v2");
    assert_eq!(
        s.signer.as_ref().unwrap().organization.as_deref(),
        Some("Example Software Ltd")
    );
}

// ---------------------------------------------------------------- CAD

fn dwg_fixture() -> Vec<u8> {
    let mut b = b"AC1032\0\0\0\0\0\0\0".to_vec();
    b.resize(0x80, 0);
    put16(&mut b, 0x13, 30);
    b.extend(vec![0xA5; 64]);
    b.extend(utf16z(
        r#"<ProductInformation name ="AutoCAD" build_version="R.47.0.0" registry_version="24.1"/>"#,
    ));
    b.extend(vec![0x5A; 16]);
    b.extend(utf16z(r"\\fs01.corp.example\cad\xref\site-plan.dwg"));
    b.extend(br"C:\Users\aroe\Documents\logo.png");
    b.push(0);
    b
}

#[test]
fn dwg_and_dxf() {
    let b = dwg_fixture();
    assert_eq!(detect(&b), DocFormat::Dwg);
    let m = run(&b, "plan.dwg");
    assert_eq!(m.fields["dwg:release"], "AutoCAD 2018");
    assert_eq!(m.application.as_deref(), Some("AutoCAD R.47.0.0"));
    assert!(m.servers.iter().any(|s| s.name == "fs01.corp.example"));
    assert!(m.people.iter().any(|p| p.name == "aroe"));

    let dxf = "999\nexported\n  0\nSECTION\n  2\nHEADER\n  9\n$ACADVER\n  1\nAC1027\n  9\n$TDCREATE\n 40\n2460310.5\n  9\n$LASTSAVEDBY\n  1\nmkovalenko\n  0\nENDSEC\n  0\nSECTION\n  2\nOBJECTS\n  0\nIMAGEDEF\n  1\n\\\\nas02\\gis\\ortho\\tile7.tif\n  0\nENDSEC\n  0\nEOF\n";
    assert_eq!(detect(dxf.as_bytes()), DocFormat::Dxf);
    let m = run(dxf.as_bytes(), "plan.dxf");
    assert_eq!(m.fields["dxf:release"], "AutoCAD 2013");
    assert_eq!(m.created.as_deref(), Some("2024-01-01T00:00:00"));
    assert_eq!(m.last_modified_by.as_deref(), Some("mkovalenko"));
    assert!(m.servers.iter().any(|s| s.name == "nas02"));
}

// ---------------------------------------------------------------- PostScript, metafiles

#[test]
fn eps_dsc_and_emf() {
    let eps = b"%!PS-Adobe-3.0 EPSF-3.0\n%%Creator: Adobe Illustrator(R) 24.0\n%%For: (Jane Roe)\n%%Title: (logo.eps)\n%%CreationDate: 2024-02-03T10:00:00\n%%DocumentFonts: Helvetica Times-Roman\n%%+ Courier\n%%BoundingBox: 0 0 100 100\n%%EndComments\n%%For: (not header)\n";
    assert_eq!(detect(eps), DocFormat::Eps);
    let m = run(eps, "logo.eps");
    assert_eq!(m.author.as_deref(), Some("Jane Roe"));
    assert_eq!(m.title.as_deref(), Some("logo.eps"));
    assert_eq!(m.fonts, vec!["Helvetica", "Times-Roman", "Courier"]);
    assert!(m.software.iter().any(|s| s.contains("Illustrator")));

    let mut emf = vec![0u8; 88];
    put32(&mut emf, 0, 1);
    put32(&mut emf, 4, 108);
    emf[40..44].copy_from_slice(b" EMF");
    let desc = utf16z("Example Draw 3.1\0Floor plan\0");
    put32(&mut emf, 44, (desc.len() / 2) as u32);
    put32(&mut emf, 48, 88);
    put32(&mut emf, 72, 1920);
    put32(&mut emf, 76, 1080);
    put32(&mut emf, 80, 508);
    put32(&mut emf, 84, 286);
    emf.extend(desc);
    assert_eq!(detect(&emf), DocFormat::Emf);
    let m = run(&emf, "plan.emf");
    assert_eq!(m.application.as_deref(), Some("Example Draw 3.1"));
    assert_eq!(m.title.as_deref(), Some("Floor plan"));
    assert_eq!(m.fields["emf:device_pixels"], "1920x1080");
}

// ---------------------------------------------------------------- archives

fn tar_header(name: &str, size: usize, uname: &str, mtime: u64) -> Vec<u8> {
    let mut h = vec![0u8; 512];
    h[..name.len()].copy_from_slice(name.as_bytes());
    h[100..107].copy_from_slice(b"0000644");
    h[108..115].copy_from_slice(b"0001750");
    h[116..123].copy_from_slice(b"0000024");
    let s = format!("{size:011o}");
    h[124..135].copy_from_slice(s.as_bytes());
    let t = format!("{mtime:011o}");
    h[136..147].copy_from_slice(t.as_bytes());
    h[156] = b'0';
    h[257..263].copy_from_slice(b"ustar\0");
    h[263..265].copy_from_slice(b"00");
    h[265..265 + uname.len()].copy_from_slice(uname.as_bytes());
    h[297..302].copy_from_slice(b"staff");
    h[148..156].copy_from_slice(b"        ");
    let sum: u32 = h.iter().map(|&c| u32::from(c)).sum();
    let c = format!("{sum:06o}\0 ");
    h[148..156].copy_from_slice(c.as_bytes());
    h
}

pub(super) fn tar_fixture() -> Vec<u8> {
    let rdp = b"full address:s:ts01.corp.example\r\nusername:s:CORP\\jdoe\r\n";
    let mut b = tar_header(
        "home/jdoe/project/office.rdp",
        rdp.len(),
        "jdoe",
        1_700_000_000,
    );
    b.extend_from_slice(rdp);
    b.resize(b.len().div_ceil(512) * 512, 0);
    b.extend(tar_header(
        "home/jdoe/project/empty.txt",
        0,
        "jdoe",
        1_700_100_000,
    ));
    b.extend(vec![0u8; 1024]);
    b
}

#[test]
fn tar_and_gzip() {
    let t = tar_fixture();
    assert_eq!(detect(&t), DocFormat::Tar);
    let m = run(&t, "backup.tar");
    assert_eq!(m.fields["tar:uname"], "jdoe");
    assert_eq!(m.fields["tar:gname"], "staff");
    assert_eq!(m.fields["tar:uid_gid"], "1000:20");
    assert_eq!(m.stats["files"], 2);
    assert_eq!(m.created.as_deref(), Some("2023-11-14T22:13:20Z"));
    assert!(m
        .paths
        .iter()
        .any(|p| p.path == "/home/jdoe/project/office.rdp"));
    assert_eq!(m.embedded.len(), 1);
    assert_eq!(m.embedded[0].metadata.format, DocFormat::Rdp);

    let mut gz = Vec::new();
    {
        let mut e = flate2::GzBuilder::new()
            .filename("backup.tar")
            .mtime(1_700_000_000)
            .write(&mut gz, flate2::Compression::fast());
        e.write_all(&t).unwrap();
        e.finish().unwrap();
    }
    assert_eq!(detect(&gz), DocFormat::Gzip);
    let m = run(&gz, "backup.tgz");
    assert_eq!(m.fields["gzip:name"], "backup.tar");
    assert_eq!(m.fields["gzip:mtime"], "2023-11-14T22:13:20Z");
    assert_eq!(m.embedded[0].metadata.format, DocFormat::Tar);
    assert_eq!(
        m.embedded[0].metadata.embedded[0].metadata.format,
        DocFormat::Rdp
    );

    // a gzip bomb is stopped by the shared budget
    let mut bomb = Vec::new();
    {
        let mut e = flate2::write::GzEncoder::new(&mut bomb, flate2::Compression::best());
        e.write_all(&vec![0u8; 4 << 20]).unwrap();
        e.finish().unwrap();
    }
    let lim = Limits {
        max_unzipped_total: 1 << 20,
        ..Limits::default()
    };
    assert!(matches!(
        extract(&bomb, Some("x.gz"), &lim),
        Err(MetaError::ZipBomb(_))
    ));
    assert_eq!(detect(b"BZh91AY&SY\0\0\0\0"), DocFormat::Bzip2);
    assert_eq!(
        detect(&[0xFD, b'7', b'z', b'X', b'Z', 0, 0, 4]),
        DocFormat::Xz
    );
    let m = run(&[0xFD, b'7', b'z', b'X', b'Z', 0, 0, 4], "a.xz");
    assert_eq!(m.fields["xz:check"], "crc64");
}

fn rar4_fixture() -> Vec<u8> {
    let mut b = b"Rar!\x1a\x07\x00".to_vec();
    // main header
    b.extend([0, 0, 0x73, 0, 0, 13, 0, 0, 0, 0, 0, 0, 0]);
    let name = b"Docs\\contract.docx";
    let data = b"xxxx";
    let mut h = vec![0u8; 32];
    h[2] = 0x74;
    put16(&mut h, 3, 0x8000);
    put16(&mut h, 5, (32 + name.len()) as u16);
    put32(&mut h, 7, data.len() as u32);
    put32(&mut h, 11, 2048);
    h[15] = 2;
    // 2024-03-05 10:20:30 in DOS format
    let dos = ((2024 - 1980) << 25) | (3 << 21) | (5 << 16) | (10 << 11) | (20 << 5) | 15;
    put32(&mut h, 20, dos);
    put16(&mut h, 26, name.len() as u16);
    h.extend_from_slice(name);
    b.extend(h);
    b.extend_from_slice(data);
    b.extend([0, 0, 0x7B, 0, 0, 7, 0]);
    b
}

fn rar5_fixture() -> Vec<u8> {
    let mut b = b"Rar!\x1a\x07\x01\x00".to_vec();
    b.extend([0, 0, 0, 0, 3, 1, 0, 0]);
    let name = b"home/jdoe/keys.txt";
    let mut body = vec![2u8, 2, 4, 2, 9, 0];
    body.extend(1_700_000_000u32.to_le_bytes());
    body.extend([0, 1, name.len() as u8]);
    body.extend_from_slice(name);
    b.extend([0, 0, 0, 0, body.len() as u8]);
    b.extend(body);
    b.extend(b"data");
    b.extend([0, 0, 0, 0, 3, 5, 0, 0]);
    b
}

#[test]
fn rar_headers() {
    let b = rar4_fixture();
    assert_eq!(detect(&b), DocFormat::Rar);
    let m = run(&b, "a.rar");
    assert_eq!(m.attachments[0].name, "Docs/contract.docx");
    assert_eq!(m.os.as_deref(), Some("Windows"));
    assert_eq!(m.created.as_deref(), Some("2024-03-05T10:20:30"));
    let b = rar5_fixture();
    let m = run(&b, "a.rar");
    assert_eq!(m.fields["rar:version"], "5");
    assert_eq!(m.attachments[0].name, "home/jdoe/keys.txt");
    assert_eq!(m.os.as_deref(), Some("Unix"));
    assert_eq!(m.modified.as_deref(), Some("2023-11-14T22:13:20Z"));
}

/// A stored ZIP with a Unix-made entry carrying uid/gid (0x7875) and an entry comment.
fn zip_with_extras() -> Vec<u8> {
    let name = b"notes.txt";
    let data = b"hello";
    let mut extra = vec![0x75, 0x78, 11, 0, 1, 4];
    extra.extend(1000u32.to_le_bytes());
    extra.push(4);
    extra.extend(1000u32.to_le_bytes());
    let comment = b"exported by ops";
    let mut z = Vec::new();
    z.extend(b"PK\x03\x04");
    z.extend([20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0]);
    z.extend(0x3610_A0F9u32.to_le_bytes());
    z.extend((data.len() as u32).to_le_bytes());
    z.extend((data.len() as u32).to_le_bytes());
    z.extend((name.len() as u16).to_le_bytes());
    z.extend(0u16.to_le_bytes());
    z.extend(name);
    z.extend(data);
    let cd = z.len();
    z.extend(b"PK\x01\x02");
    z.extend([30, 3, 20, 0, 0, 0, 0, 0, 0, 0, 0x21, 0]);
    z.extend(0x3610_A0F9u32.to_le_bytes());
    z.extend((data.len() as u32).to_le_bytes());
    z.extend((data.len() as u32).to_le_bytes());
    z.extend((name.len() as u16).to_le_bytes());
    z.extend((extra.len() as u16).to_le_bytes());
    z.extend((comment.len() as u16).to_le_bytes());
    z.extend([0u8; 8]);
    z.extend(0u32.to_le_bytes());
    z.extend(name);
    z.extend(&extra);
    z.extend(comment);
    let cd_len = z.len() - cd;
    z.extend(b"PK\x05\x06");
    z.extend([0, 0, 0, 0, 1, 0, 1, 0]);
    z.extend((cd_len as u32).to_le_bytes());
    z.extend((cd as u32).to_le_bytes());
    z.extend([0, 0]);
    z
}

#[test]
fn zip_central_directory_extras() {
    let b = zip_with_extras();
    let m = run(&b, "a.zip");
    assert_eq!(m.format, DocFormat::Zip);
    assert_eq!(m.fields["zip:host_os"], "Unix");
    assert_eq!(m.os.as_deref(), Some("Unix"));
    assert_eq!(m.fields["zip:uid"], "1000");
    assert_eq!(m.fields["zip:comment:notes.txt"], "exported by ops");
}

// ---------------------------------------------------------------- audio / video

fn chunk(id: &[u8; 4], data: &[u8]) -> Vec<u8> {
    let mut c = id.to_vec();
    c.extend((data.len() as u32).to_le_bytes());
    c.extend_from_slice(data);
    if data.len() % 2 == 1 {
        c.push(0);
    }
    c
}

fn wav_fixture() -> Vec<u8> {
    let mut info = b"INFO".to_vec();
    info.extend(chunk(b"IART", b"Olena Example\0"));
    info.extend(chunk(b"ISFT", b"Lavf60.3.100\0"));
    info.extend(chunk(b"ICRD", b"2024-04-01\0"));
    let mut bext = vec![0u8; 602];
    bext[..12].copy_from_slice(b"Board minute");
    bext[256..268].copy_from_slice(b"Example DAW ");
    bext[320..330].copy_from_slice(b"2024-04-01");
    bext[330..338].copy_from_slice(b"09:30:00");
    let mut body = b"WAVE".to_vec();
    body.extend(chunk(b"fmt ", &[0u8; 16]));
    body.extend(chunk(b"LIST", &info));
    body.extend(chunk(b"bext", &bext));
    body.extend(chunk(b"data", &[0u8; 8]));
    let mut b = b"RIFF".to_vec();
    b.extend((body.len() as u32).to_le_bytes());
    b.extend(body);
    b
}

fn ebml(id: &[u8], data: &[u8]) -> Vec<u8> {
    let mut v = id.to_vec();
    assert!(data.len() < 0x3FFF);
    v.extend([0x40 | (data.len() >> 8) as u8, data.len() as u8]);
    v.extend_from_slice(data);
    v
}

fn mkv_fixture() -> Vec<u8> {
    let mut b = ebml(&[0x1A, 0x45, 0xDF, 0xA3], &ebml(&[0x42, 0x82], b"webm"));
    let mut info = ebml(&[0x4D, 0x80], b"Lavf60.3.100");
    info.extend(ebml(&[0x57, 0x41], b"HandBrake 1.6.1"));
    info.extend(ebml(&[0x7B, 0xA9], b"Site walkthrough"));
    info.extend(ebml(
        &[0x44, 0x61],
        &(725_760_000_000_000_000i64).to_be_bytes(),
    ));
    let mut st = ebml(&[0x45, 0xA3], b"ARTIST");
    st.extend(ebml(&[0x44, 0x87], b"Petro Example"));
    let tags = ebml(
        &[0x12, 0x54, 0xC3, 0x67],
        &ebml(&[0x73, 0x73], &ebml(&[0x67, 0xC8], &st)),
    );
    let mut seg = ebml(&[0x15, 0x49, 0xA9, 0x66], &info);
    seg.extend(tags);
    seg.extend([
        0x1F, 0x43, 0xB6, 0x75, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ]);
    // Segment with unknown size
    b.extend([
        0x18, 0x53, 0x80, 0x67, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    ]);
    b.extend(seg);
    b
}

fn asf_fixture() -> Vec<u8> {
    use crate::formats::media::av::ASF_HEADER;
    let utf = |s: &str| utf16z(s);
    let mut cd = vec![
        0x33, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62, 0xCE,
        0x6C,
    ];
    let (t, a, c) = (utf("Quarterly"), utf("Ivan Example"), utf("(c) Example"));
    let body_len = 10 + t.len() + a.len() + c.len();
    cd.extend(((24 + body_len) as u64).to_le_bytes());
    for l in [t.len(), a.len(), c.len(), 0, 0] {
        cd.extend((l as u16).to_le_bytes());
    }
    cd.extend(t);
    cd.extend(a);
    cd.extend(c);
    let mut ext = vec![
        0x40, 0xA4, 0xD0, 0xD2, 0x07, 0xE3, 0xD2, 0x11, 0x97, 0xF0, 0x00, 0xA0, 0xC9, 0x5E, 0xA8,
        0x50,
    ];
    let mut items = 2u16.to_le_bytes().to_vec();
    for (k, v) in [
        ("WM/ToolName", "Example Movie Maker"),
        ("WM/ToolVersion", "6.1"),
    ] {
        let k = utf(k);
        let v = utf(v);
        items.extend((k.len() as u16).to_le_bytes());
        items.extend(k);
        items.extend(0u16.to_le_bytes());
        items.extend((v.len() as u16).to_le_bytes());
        items.extend(v);
    }
    ext.extend(((24 + items.len()) as u64).to_le_bytes());
    ext.extend(items);
    let mut b = ASF_HEADER.to_vec();
    b.extend(((30 + cd.len() + ext.len()) as u64).to_le_bytes());
    b.extend(2u32.to_le_bytes());
    b.extend([1, 2]);
    b.extend(cd);
    b.extend(ext);
    b
}

fn vorbis_block(vendor: &str, comments: &[&str]) -> Vec<u8> {
    let mut v = (vendor.len() as u32).to_le_bytes().to_vec();
    v.extend(vendor.as_bytes());
    v.extend((comments.len() as u32).to_le_bytes());
    for c in comments {
        v.extend((c.len() as u32).to_le_bytes());
        v.extend(c.as_bytes());
    }
    v
}

fn ogg_page(payload: &[u8], seq: u32) -> Vec<u8> {
    let mut p = b"OggS\0\0".to_vec();
    p.extend([0u8; 8]);
    p.extend(1u32.to_le_bytes());
    p.extend(seq.to_le_bytes());
    p.extend([0u8; 4]);
    let mut segs = vec![255u8; payload.len() / 255];
    segs.push((payload.len() % 255) as u8);
    p.push(segs.len() as u8);
    p.extend(segs);
    p.extend_from_slice(payload);
    p
}

#[test]
fn audio_video_tags() {
    let b = wav_fixture();
    assert_eq!(detect(&b), DocFormat::Wav);
    let m = run(&b, "a.wav");
    assert_eq!(m.author.as_deref(), Some("Olena Example"));
    assert!(m.software.iter().any(|s| s == "Lavf60.3.100"));
    assert!(m.software.iter().any(|s| s == "Example DAW"));
    assert_eq!(m.fields["bext:OriginationDate"], "2024-04-01T09:30:00");

    let b = mkv_fixture();
    assert_eq!(detect(&b), DocFormat::Mkv);
    let m = run(&b, "a.webm");
    assert_eq!(m.fields["mkv:doctype"], "webm");
    assert_eq!(m.application.as_deref(), Some("HandBrake 1.6.1"));
    assert_eq!(m.title.as_deref(), Some("Site walkthrough"));
    assert_eq!(m.created.as_deref(), Some("2024-01-01T00:00:00Z"));
    assert!(m.people.iter().any(|p| p.name == "Petro Example"));

    let b = asf_fixture();
    assert_eq!(detect(&b), DocFormat::Asf);
    let m = run(&b, "a.wmv");
    assert_eq!(m.author.as_deref(), Some("Ivan Example"));
    assert!(m.software.iter().any(|s| s == "Example Movie Maker 6.1"));

    let mut flac = b"fLaC".to_vec();
    flac.extend([0, 0, 0, 34]);
    flac.extend([0u8; 34]);
    let vc = vorbis_block(
        "reference libFLAC 1.4.3",
        &["ARTIST=Choir Example", "ENCODER=Example Ripper 2"],
    );
    flac.push(0x84);
    flac.extend(&(vc.len() as u32).to_be_bytes()[1..]);
    flac.extend(vc);
    assert_eq!(detect(&flac), DocFormat::Flac);
    let m = run(&flac, "a.flac");
    assert_eq!(m.author.as_deref(), Some("Choir Example"));
    assert!(m.software.iter().any(|s| s == "reference libFLAC 1.4.3"));

    let mut id = b"\x01vorbis".to_vec();
    id.extend([0u8; 23]);
    let mut c = b"\x03vorbis".to_vec();
    c.extend(vorbis_block(
        "Xiph.Org libVorbis I 20200704",
        &["TITLE=Voice memo", "ORGANIZATION=Example Radio"],
    ));
    let mut ogg = ogg_page(&id, 0);
    ogg.extend(ogg_page(&c, 1));
    assert_eq!(detect(&ogg), DocFormat::Ogg);
    let m = run(&ogg, "a.ogg");
    assert_eq!(m.fields["ogg:codec"], "Vorbis");
    assert_eq!(m.title.as_deref(), Some("Voice memo"));
    assert_eq!(m.company.as_deref(), Some("Example Radio"));
}

// ---------------------------------------------------------------- geodata

const KML: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<kml xmlns="http://www.opengis.net/kml/2.2" xmlns:atom="http://www.w3.org/2005/Atom">
<Document><name>Depots</name><atom:author><atom:name>Field Team</atom:name></atom:author>
<Placemark><name>Depot 1</name><TimeStamp><when>2024-05-01T08:00:00Z</when></TimeStamp>
<Point><coordinates>30.5234,50.4501,120</coordinates></Point></Placemark>
<Placemark><name>Route</name><LineString><coordinates>30.1,50.1 30.2,50.2 999,999</coordinates></LineString></Placemark>
</Document></kml>"#;

const GPX: &str = r#"<?xml version="1.0"?>
<gpx version="1.1" creator="Example Tracker 5.2" xmlns="http://www.topografix.com/GPX/1/1">
<metadata><name>Morning run</name><author><name>Runner Example</name><email id="runner" domain="example.com"/></author></metadata>
<trk><trkseg><trkpt lat="50.45" lon="30.52"><ele>170</ele><time>2024-05-02T06:00:00Z</time></trkpt>
<trkpt lat="50.46" lon="30.53"><time>2024-05-02T06:10:00Z</time></trkpt></trkseg></trk>
</gpx>"#;

#[test]
fn kml_kmz_gpx() {
    assert_eq!(detect(KML.as_bytes()), DocFormat::Kml);
    let m = run(KML.as_bytes(), "a.kml");
    assert_eq!(m.title.as_deref(), Some("Depots"));
    assert_eq!(m.author.as_deref(), Some("Field Team"));
    assert_eq!(m.geo_points.len(), 3);
    assert_eq!(m.geo_points[0].name.as_deref(), Some("Depot 1"));
    assert_eq!(m.geo_points[0].alt, Some(120.0));
    assert_eq!(
        m.geo_points[0].time.as_deref(),
        Some("2024-05-01T08:00:00Z")
    );
    let kmz = zip_of(&[("doc.kml", KML.as_bytes())]);
    assert_eq!(detect(&kmz), DocFormat::Kmz);
    let m = run(&kmz, "a.kmz");
    assert_eq!(m.format, DocFormat::Kmz);
    assert_eq!(m.stats["geo_points"], 3);

    assert_eq!(detect(GPX.as_bytes()), DocFormat::Gpx);
    let m = run(GPX.as_bytes(), "a.gpx");
    assert_eq!(m.application.as_deref(), Some("Example Tracker 5.2"));
    assert_eq!(m.author.as_deref(), Some("Runner Example"));
    assert!(m.emails.iter().any(|e| e == "runner@example.com"));
    assert_eq!(m.geo_points.len(), 2);
    assert_eq!(m.geo_points[0].source, "gpx:trkpt");
    assert_eq!(m.modified.as_deref(), Some("2024-05-02T06:10:00Z"));
}

// ---------------------------------------------------------------- developer files

const MAP: &str = r#"{"version":3,"file":"app.min.js","sourceRoot":"","sources":["webpack://billing/./src/index.ts","webpack:///./node_modules/@example/ui/button.js","file:///home/jdev/work/billing/src/api.ts","C:\\Users\\kdev\\repo\\src\\util.ts"],"sourcesContent":["const API_KEY = 'x';",null],"names":[],"mappings":"AAAA"}"#;

const NOTEBOOK: &str = r#"{"cells":[{"cell_type":"code","source":["import pandas as pd\n","df = pd.read_csv('/home/analyst/data/clients.csv')\n"],"metadata":{"execution":{"iopub.execute_input":"2024-06-01T10:00:00.000Z"}},"outputs":[{"output_type":"error","traceback":["\u001b[0;31mFileNotFoundError\u001b[0m: [Errno 2] No such file: 'C:\\Users\\o.analyst\\Desktop\\x.csv' contact owner@example.com"]}]}],"metadata":{"kernelspec":{"display_name":"Python 3 (ipykernel)","name":"python3","language":"python"},"language_info":{"name":"python","version":"3.11.4"}},"nbformat":4,"nbformat_minor":5}"#;

#[test]
fn sourcemap_and_notebook() {
    assert_eq!(detect(MAP.as_bytes()), DocFormat::SourceMap);
    let m = run(MAP.as_bytes(), "app.min.js.map");
    assert_eq!(m.title.as_deref(), Some("app.min.js"));
    assert_eq!(m.stats["sources"], 4);
    assert_eq!(m.stats["sources_content"], 1);
    assert_eq!(m.fields["sourcemap:packages"], "@example/ui");
    assert_eq!(m.fields["sourcemap:webpack_namespace"], "billing");
    for u in ["jdev", "kdev"] {
        assert!(m.people.iter().any(|p| p.name == u), "{u}: {:?}", m.people);
    }
    let t = text(MAP.as_bytes(), &Limits::default()).unwrap();
    assert!(t.contains("API_KEY"));
    let xssi = format!(")]}}'\n{MAP}");
    assert_eq!(detect(xssi.as_bytes()), DocFormat::SourceMap);
    assert_eq!(run(xssi.as_bytes(), "a.map").stats["sources"], 4);

    assert_eq!(detect(NOTEBOOK.as_bytes()), DocFormat::Ipynb);
    let m = run(NOTEBOOK.as_bytes(), "a.ipynb");
    assert_eq!(m.application.as_deref(), Some("Python 3 (ipykernel)"));
    assert!(m.software.iter().any(|s| s == "python 3.11.4"));
    assert!(m.people.iter().any(|p| p.name == "analyst"));
    assert!(m.people.iter().any(|p| p.name == "o.analyst"));
    assert!(m.emails.iter().any(|e| e == "owner@example.com"));
    assert_eq!(m.created.as_deref(), Some("2024-06-01T10:00:00.000Z"));
    assert!(text(NOTEBOOK.as_bytes(), &Limits::default())
        .unwrap()
        .contains("read_csv"));
}

// ---------------------------------------------------------------- robustness

fn fixtures() -> Vec<(&'static str, Vec<u8>)> {
    let mut flac = b"fLaC".to_vec();
    flac.extend([0x84, 0, 0, 20]);
    flac.extend(vorbis_block("v", &["A=b"]));
    let mut ogg = ogg_page(b"\x01vorbis", 0);
    ogg.extend(ogg_page(
        &[b"\x03vorbis".as_slice(), &vorbis_block("v", &["A=b"])].concat(),
        1,
    ));
    let mut gz = Vec::new();
    {
        let mut e = flate2::GzBuilder::new()
            .filename("x.tar")
            .write(&mut gz, flate2::Compression::fast());
        e.write_all(&tar_fixture()).unwrap();
        e.finish().unwrap();
    }
    vec![
        ("a.exe", pe_fixture()),
        ("a.msi", msi_fixture()),
        ("a.jar", jar_fixture()),
        (
            "a.apk",
            with_signing_block(zip_of(&[("AndroidManifest.xml", &axml_fixture())]), CERT),
        ),
        ("a.dwg", dwg_fixture()),
        ("a.tar", tar_fixture()),
        ("a.tgz", gz),
        ("a.rar", rar4_fixture()),
        ("b.rar", rar5_fixture()),
        ("a.zip", zip_with_extras()),
        ("a.wav", wav_fixture()),
        ("a.mkv", mkv_fixture()),
        ("a.wmv", asf_fixture()),
        ("a.flac", flac),
        ("a.ogg", ogg),
        ("a.kml", KML.as_bytes().to_vec()),
        ("a.gpx", GPX.as_bytes().to_vec()),
        ("a.map", MAP.as_bytes().to_vec()),
        ("a.ipynb", NOTEBOOK.as_bytes().to_vec()),
        (
            "a.eps",
            b"%!PS-Adobe-3.0\n%%For: (x)\n%%+ y\n%%EndComments\n".to_vec(),
        ),
    ]
}

fn assert_no_panic(name: &str, b: &[u8]) {
    let lim = Limits {
        max_unzipped_total: 8 << 20,
        ..Limits::default()
    };
    for r in [
        extract(b, Some(name), &lim).map(|_| ()),
        text(b, &lim).map(|_| ()),
    ] {
        if let Err(MetaError::Malformed { msg, .. }) = &r {
            assert!(
                !msg.contains("внутренняя ошибка"),
                "{name}: parser panicked on {} bytes",
                b.len()
            );
        }
    }
}

#[test]
fn new_parsers_survive_truncation_and_mutation() {
    let mut rng = Rng(0x5eed_2026);
    for (name, b) in fixtures() {
        assert_ne!(
            detect_with_hint(&b, Some(name)),
            DocFormat::Unknown,
            "{name}"
        );
        let step = (b.len() / 64).max(1);
        for cut in (0..b.len()).step_by(step) {
            assert_no_panic(name, &b[..cut]);
        }
        for _ in 0..150 {
            let mut m = b.clone();
            for _ in 0..1 + (rng.next() % 8) {
                let i = (rng.next() as usize) % m.len();
                m[i] = rng.next() as u8;
            }
            assert_no_panic(name, &m);
        }
    }
}

#[test]
fn random_bytes_behind_new_magics() {
    let mut rng = Rng(42);
    let magics: [&[u8]; 16] = [
        b"MZ\0\0",
        b"Rar!\x1a\x07\x00",
        b"Rar!\x1a\x07\x01\x00",
        &[0x1F, 0x8B, 0x08],
        &[
            0x30, 0x26, 0xB2, 0x75, 0x8E, 0x66, 0xCF, 0x11, 0xA6, 0xD9, 0x00, 0xAA, 0x00, 0x62,
            0xCE, 0x6C,
        ],
        &[0x1A, 0x45, 0xDF, 0xA3],
        b"fLaC",
        b"OggS",
        b"RIFF\0\0\0\0WAVE",
        b"RIFF\0\0\0\0AVI ",
        b"AC1032",
        b"%!PS-Adobe-3.0\n",
        &[0xC5, 0xD0, 0xD3, 0xC6],
        &[0xD7, 0xCD, 0xC6, 0x9A],
        b"{\"version\":3,\"sources\":[],\"mappings\":\"\"",
        b"{\"cells\":[],\"nbformat\":4",
    ];
    for m in magics {
        for len in [0usize, 8, 64, 600, 4096] {
            for _ in 0..20 {
                let mut b = m.to_vec();
                b.extend((0..len).map(|_| rng.next() as u8));
                if b.starts_with(b"MZ") && b.len() > 0x40 {
                    let off = (rng.next() % 512) as u32 + 0x40;
                    b[0x3C..0x40].copy_from_slice(&off.to_le_bytes());
                    if let Some(p) = b.get_mut(off as usize..off as usize + 4) {
                        p.copy_from_slice(b"PE\0\0");
                    }
                }
                assert_no_panic("x.bin", &b);
            }
        }
    }
}

// ---------------------------------------------------------------- Office data sources

fn b64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(T[(n >> (18 - 6 * i)) as usize & 63] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// MS-OVBA container with literal-only chunks.
fn ovba(data: &[u8]) -> Vec<u8> {
    let mut out = vec![1u8];
    for chunk in data.chunks(4096) {
        let mut body = Vec::new();
        for group in chunk.chunks(8) {
            body.push(0);
            body.extend_from_slice(group);
        }
        let h = 0xB000u16 | ((body.len() - 1) as u16 & 0x0FFF);
        out.extend(h.to_le_bytes());
        out.extend(body);
    }
    out
}

fn vba_project(source: &str) -> Vec<u8> {
    let mut dir = Vec::new();
    let rec = |dir: &mut Vec<u8>, id: u16, data: &[u8]| {
        dir.extend(id.to_le_bytes());
        dir.extend((data.len() as u32).to_le_bytes());
        dir.extend_from_slice(data);
    };
    rec(&mut dir, 0x0019, b"Module1");
    rec(&mut dir, 0x001A, b"Module1");
    rec(&mut dir, 0x0032, &utf16z("Module1")[..14]);
    rec(&mut dir, 0x0031, &0u32.to_le_bytes());
    rec(&mut dir, 0x002B, &[]);
    let cur = Cursor::new(Vec::new());
    let mut cf = cfb::CompoundFile::create(cur).unwrap();
    cf.create_storage("/VBA").unwrap();
    let mut d = cf.create_stream("/VBA/dir").unwrap();
    d.write_all(&ovba(&dir)).unwrap();
    drop(d);
    let mut m = cf.create_stream("/VBA/Module1").unwrap();
    m.write_all(&ovba(source.as_bytes())).unwrap();
    drop(m);
    cf.into_inner().into_inner()
}

#[test]
fn office_connections_power_query_mail_merge_vba() {
    let mashup_zip = zip_of(&[(
        "Formulas/Section1.m",
        b"section Section1;\nshared Sales = let Source = Sql.Database(\"sql02.corp.example\", \"Finance\") in Source;",
    )]);
    let mut mashup = 0u32.to_le_bytes().to_vec();
    mashup.extend((mashup_zip.len() as u32).to_le_bytes());
    mashup.extend(&mashup_zip);
    let custom = format!(
        r#"<?xml version="1.0"?><DataMashup xmlns="http://schemas.microsoft.com/DataMashup">{}</DataMashup>"#,
        b64(&mashup)
    );
    let vba = vba_project(
        "Attribute VB_Name = \"Module1\"\nSub Push()\n  u = \"https://intranet.corp.example/api\"\n  cn.Open \"Provider=SQLOLEDB;Data Source=sql01;User ID=sa;Password=Hunter22\"\nEnd Sub\n",
    );
    let xlsx = zip_of(&[
        ("[Content_Types].xml", b"<Types/>"),
        (
            "xl/workbook.xml",
            br#"<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheets><sheet name="S" sheetId="1"/></sheets><definedNames><definedName name="Rates">'\\fs01\fin\[rates.xlsx]Sheet1'!$A$1</definedName></definedNames></workbook>"#,
        ),
        (
            "xl/connections.xml",
            br#"<connections xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><connection id="1" name="Sales DB" type="5" savePassword="1"><dbPr connection="Provider=SQLOLEDB.1;Password=S3cret!;User ID=report_ro;Initial Catalog=Sales;Data Source=sql01.corp.example" command="SELECT * FROM t"/></connection><connection id="2" name="Feed" type="4"><webPr url="http://intranet.corp.example/feed.csv"/></connection></connections>"#,
        ),
        (
            "xl/styles.xml",
            br#"<styleSheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><fonts><font><name val="Aptos Narrow"/></font></fonts></styleSheet>"#,
        ),
        ("customXml/item1.xml", custom.as_bytes()),
        ("xl/vbaProject.bin", &vba),
    ]);
    assert_eq!(detect(&xlsx), DocFormat::Xlsx);
    let m = run(&xlsx, "book.xlsm");
    let js = serde_json::to_string(&m).unwrap();
    for secret in ["S3cret", "Hunter22"] {
        assert!(!js.contains(secret), "{secret} leaked: {js}");
    }
    let c = &m.connections[0];
    assert_eq!(c.server.as_deref(), Some("sql01.corp.example"));
    assert_eq!(c.user.as_deref(), Some("report_ro"));
    assert!(c.has_password);
    assert!(m.secrets.iter().any(|s| s.kind == "connection_password"));
    assert!(m
        .connections
        .iter()
        .any(|c| c.target.as_deref() == Some("http://intranet.corp.example/feed.csv")));
    assert!(m
        .connections
        .iter()
        .any(|c| c.kind == "powerquery:sql" && c.server.as_deref() == Some("sql02.corp.example")));
    assert!(
        m.servers.iter().any(|s| s.name == "fs01"),
        "{:?}",
        m.servers
    );
    assert_eq!(m.fonts, vec!["Aptos Narrow"]);
    assert!(m
        .links
        .iter()
        .any(|l| l == "https://intranet.corp.example/api"));
    assert!(m.has_macros && m.macro_modules.contains(&"Module1".to_string()));
    let t = text(&xlsx, &Limits::default()).unwrap();
    assert!(t.contains("Password=***") && !t.contains("S3cret"), "{t}");
    assert!(t.contains("Hunter22"), "VBA lines feed the secret scanner");

    let docx = zip_of(&[
        ("[Content_Types].xml", b"<Types/>"),
        ("word/document.xml", br#"<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body/></w:document>"#),
        (
            "word/settings.xml",
            br#"<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:mailMerge><w:mainDocumentType w:val="formLetters"/><w:connectString w:val="Provider=Microsoft.ACE.OLEDB.12.0;User ID=Admin;Data Source=C:\Users\hr.clerk\Documents\staff.xlsx;Jet OLEDB:Database Password=pw1"/><w:query w:val="SELECT * FROM `Sheet1$`"/></w:mailMerge><w:docVars><w:docVar w:name="CaseNo" w:val="HR-2024-17"/></w:docVars></w:settings>"#,
        ),
        (
            "word/fontTable.xml",
            br#"<w:fonts xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:font w:name="Calibri"/><w:font w:name="PT Astra Serif"/></w:fonts>"#,
        ),
    ]);
    let m = run(&docx, "letter.docx");
    let mm = &m.connections[0];
    assert_eq!(mm.kind, "mailmerge");
    assert!(mm.has_password);
    assert!(m.people.iter().any(|p| p.name == "hr.clerk"));
    assert_eq!(m.custom["docVar:CaseNo"], "HR-2024-17");
    assert_eq!(m.fonts, vec!["Calibri", "PT Astra Serif"]);
    assert!(!serde_json::to_string(&m).unwrap().contains("pw1"));
}

// ---------------------------------------------------------------- images

fn png_with(chunks: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
    let mut b = b"\x89PNG\r\n\x1a\n".to_vec();
    let mut ihdr = vec![0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0];
    let mut all: Vec<(&[u8; 4], Vec<u8>)> = vec![(b"IHDR", std::mem::take(&mut ihdr))];
    all.extend(chunks.iter().map(|(t, d)| (*t, d.to_vec())));
    all.push((b"IEND", Vec::new()));
    for (t, d) in all {
        b.extend((d.len() as u32).to_be_bytes());
        b.extend_from_slice(t);
        b.extend(&d);
        b.extend([0u8; 4]);
    }
    b
}

/// A bare TIFF whose EXIF maker note is a Canon IFD with owner name and serial number.
fn canon_tiff() -> Vec<u8> {
    let mut t = b"II*\0".to_vec();
    t.extend(8u32.to_le_bytes());
    let ent = |t: &mut Vec<u8>, tag: u16, ty: u16, n: u32, v: u32| {
        t.extend(tag.to_le_bytes());
        t.extend(ty.to_le_bytes());
        t.extend(n.to_le_bytes());
        t.extend(v.to_le_bytes());
    };
    t.extend(2u16.to_le_bytes());
    ent(&mut t, 0x010F, 2, 6, 38);
    ent(&mut t, 0x8769, 4, 1, 44);
    t.extend(0u32.to_le_bytes());
    t.extend(b"Canon\0");
    t.extend(1u16.to_le_bytes());
    ent(&mut t, 0x927C, 7, 48, 62);
    t.extend(0u32.to_le_bytes());
    t.extend(2u16.to_le_bytes());
    ent(&mut t, 0x0009, 2, 18, 92);
    ent(&mut t, 0x000C, 4, 1, 123_456_789);
    t.extend(0u32.to_le_bytes());
    t.extend(b"Jane Photographer\0");
    t
}

#[test]
fn images_ai_c2pa_icc_makernote() {
    let png = png_with(&[(
        b"tEXt",
        b"parameters\0a lighthouse at dusk\nNegative prompt: blurry\nSteps: 20, Sampler: Euler a, Model: dreamshaper_8",
    )]);
    let m = run(&png, "gen.png");
    let ai = m.ai_generated.as_ref().expect("ai marker");
    assert_eq!(ai.model.as_deref(), Some("dreamshaper_8"));
    assert_eq!(ai.prompt.as_deref(), Some("a lighthouse at dusk"));
    assert!(
        !m.fields.values().any(|v| v.contains("lighthouse")),
        "the prompt is not a plain field"
    );
    let cleaned = crate::clean(&png, DocFormat::Png).unwrap();
    assert!(run(&cleaned, "gen.png").ai_generated.is_none());

    let mut jumbf = b"JP\0\x01\0\0\0\x10jumbc2pa".to_vec();
    jumbf.extend(b"\x6Fclaim_generator\x6CExampleCam/1 c2pa.actions trainedAlgorithmicMedia");
    let mut icc = vec![0u8; 132];
    icc[36..40].copy_from_slice(b"acsp");
    icc[48..52].copy_from_slice(b"EXMP");
    icc[52..56].copy_from_slice(b"SCN1");
    let mut jpg = vec![0xFF, 0xD8];
    for (marker, data) in [
        (0xEBu8, jumbf),
        (0xE2, [b"ICC_PROFILE\0\x01\x01".to_vec(), icc].concat()),
    ] {
        jpg.extend([0xFF, marker]);
        jpg.extend(((data.len() + 2) as u16).to_be_bytes());
        jpg.extend(data);
    }
    jpg.extend([0xFF, 0xD9]);
    let m = run(&jpg, "a.jpg");
    assert_eq!(m.fields["c2pa:claim_generator"], "ExampleCam/1");
    assert_eq!(m.ai_generated.as_ref().unwrap().source, "c2pa");
    assert_eq!(m.fields["icc:device_model"], "SCN1");

    let t = canon_tiff();
    assert_eq!(detect(&t), DocFormat::Tiff);
    let m = run(&t, "a.tif");
    let cam = m.camera.as_ref().unwrap();
    assert_eq!(cam.serial.as_deref(), Some("123456789"));
    assert_eq!(cam.owner.as_deref(), Some("Jane Photographer"));
    assert!(m.people.iter().any(|p| p.name == "Jane Photographer"));
    for b in [png, jpg, t] {
        let mut rng = Rng(7);
        for _ in 0..200 {
            let mut x = b.clone();
            let i = rng.next() as usize % x.len();
            x[i] = rng.next() as u8;
            assert_no_panic("x.img", &x);
        }
    }
}

#[test]
fn pdf_forms_fonts_intents() {
    let pdf = b"%PDF-1.7\n1 0 obj << /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [4 0 R] /XFA 9 0 R >> /OutputIntents [5 0 R] /PieceInfo << /Illustrator << >> >> >> endobj\n2 0 obj << /Type /Pages /Kids [3 0 R] /Count 1 >> endobj\n3 0 obj << /Type /Page /Parent 2 0 R /Resources << /Font << /F1 6 0 R >> >> >> endobj\n4 0 obj << /FT /Tx /T (applicant_name) /V (Ivan Example) >> endobj\n5 0 obj << /Type /OutputIntent /S /GTS_PDFX /OutputConditionIdentifier (FOGRA39) >> endobj\n6 0 obj << /Type /Font /Subtype /TrueType /BaseFont /ABCDEF+PTSans-Regular >> endobj\ntrailer << /Root 1 0 R >>\n%%EOF\n";
    let m = run(pdf, "form.pdf");
    assert_eq!(m.fonts, vec!["PTSans-Regular"]);
    assert_eq!(m.form_fields[0].name, "applicant_name");
    assert_eq!(m.form_fields[0].value.as_deref(), Some("Ivan Example"));
    assert_eq!(m.fields["pdf:xfa"], "true");
    assert_eq!(m.fields["pdf:OutputIntent"], "FOGRA39");
    assert_eq!(m.fields["pdf:PieceInfo"], "Illustrator");
    assert!(m.software.iter().any(|s| s == "Adobe Illustrator"));
}
