//! Java and Android packages: JAR/WAR/EAR, APK/AAB.
//!
//! Reads `META-INF/MANIFEST.MF` (Built-By user, Created-By JDK, Implementation-* and Bundle-*
//! keys), Maven `pom.properties` coordinates, bundled library names (`WEB-INF/lib/*.jar`), the
//! signer of the JAR signature block (`META-INF/*.RSA|DSA|EC`) and of the APK v2/v3 signing
//! block, and for APKs the binary `AndroidManifest.xml` (package, versionName, versionCode,
//! SDK levels, permissions).

use foca_core::{DocFormat, Metadata, PersonRole, SignatureKind};

use crate::formats::signature;
use crate::util::{clean_str, find, rd_u32le, rd_u64le, truncate};
use crate::zipx::SafeZip;
use crate::{Ctx, MetaError};

const MAX_MANIFEST: u64 = 256 * 1024;
const MAX_LIBS: usize = 200;

/// Format of a ZIP that looks like a Java or Android package, by member names.
pub(crate) fn zip_kind(names: &[String]) -> Option<DocFormat> {
    let has = |n: &str| names.iter().any(|x| x == n);
    if has("AndroidManifest.xml")
        || has("base/manifest/AndroidManifest.xml")
        || has("BundleConfig.pb")
    {
        return Some(DocFormat::Apk);
    }
    if has("META-INF/MANIFEST.MF")
        && names.iter().any(|n| {
            n.ends_with(".class")
                || n.starts_with("WEB-INF/")
                || n.starts_with("META-INF/maven/")
                || n.starts_with("BOOT-INF/")
                || n.ends_with(".jar")
                || n.ends_with(".war")
        })
    {
        return Some(DocFormat::Jar);
    }
    None
}

pub fn extract(b: &[u8], format: DocFormat, ctx: &Ctx) -> Result<Metadata, MetaError> {
    crate::guard("jar", || extract_inner(b, format, ctx))
}

fn extract_inner(b: &[u8], format: DocFormat, ctx: &Ctx) -> Result<Metadata, MetaError> {
    let mut z = SafeZip::open(b, ctx.max_entries())?;
    let mut meta = Metadata::new(format);
    let names: Vec<String> = z.names().to_vec();
    meta.stats.insert("files".into(), names.len() as u64);
    if let Some(mf) = z.read_prefix("META-INF/MANIFEST.MF", MAX_MANIFEST, ctx)? {
        manifest(&mut meta, &String::from_utf8_lossy(&mf));
    }
    let mut maven = 0;
    for n in &names {
        if n.starts_with("META-INF/maven/") && n.ends_with("/pom.properties") && maven < 50 {
            maven += 1;
            if let Some(p) = z.read_prefix(n, 16 * 1024, ctx)? {
                pom_properties(&mut meta, &String::from_utf8_lossy(&p));
            }
        }
        if n.starts_with("META-INF/maven/") && n.ends_with("/pom.xml") && maven < 50 {
            if let Some(p) = z.read_prefix(n, 128 * 1024, ctx)? {
                for e in crate::paths::find_emails(&String::from_utf8_lossy(&p)) {
                    Metadata::add_unique(&mut meta.emails, &e);
                }
            }
        }
    }
    bundled_libraries(&mut meta, &names);
    // JAR signature block
    for n in names.iter().filter(|n| is_signature_block(n)).take(4) {
        if let Some(blob) = z.read_prefix(n, 512 * 1024, ctx)? {
            if let Some(cms) = signature::find_cms(&blob) {
                meta.signatures
                    .push(signature::from_cms(SignatureKind::Jar, n, &cms));
            }
        }
    }
    if format == DocFormat::Apk {
        if let Some(axml) = z.read_prefix("AndroidManifest.xml", 2 << 20, ctx)? {
            android_manifest(&mut meta, &axml);
        }
        if meta.signatures.is_empty() {
            apk_signing_block(&mut meta, b);
        }
        if names.iter().any(|n| n == "BundleConfig.pb") {
            meta.fields.insert("apk:bundle".into(), "aab".into());
        }
    }
    signature::apply_signers(&mut meta, "jar:signer");
    Ok(meta)
}

fn is_signature_block(n: &str) -> bool {
    let u = n.to_ascii_uppercase();
    u.starts_with("META-INF/")
        && u.matches('/').count() == 1
        && (u.ends_with(".RSA") || u.ends_with(".DSA") || u.ends_with(".EC"))
}

/// Main section of a JAR manifest (up to the first blank line); continuation lines start with
/// one space.
fn manifest(meta: &mut Metadata, text: &str) {
    let mut entries: Vec<(String, String)> = Vec::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            break;
        }
        if let Some(cont) = line.strip_prefix(' ') {
            if let Some(last) = entries.last_mut() {
                if last.1.len() < 4096 {
                    last.1.push_str(cont);
                }
            }
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            if entries.len() < 64 {
                entries.push((k.trim().to_string(), v.trim().to_string()));
            }
        }
    }
    for (k, v) in entries {
        let Some(v) = clean_str(&v) else { continue };
        let v = truncate(&v, 512);
        match k.as_str() {
            "Built-By" => {
                meta.add_person(&v, PersonRole::Creator, "MANIFEST.MF:Built-By");
                meta.author.get_or_insert(v.clone());
            }
            "Created-By" => {
                Metadata::add_unique(&mut meta.software, &created_by(&v));
                meta.application.get_or_insert(v.clone());
            }
            "Build-Jdk" | "Build-Jdk-Spec" => {
                Metadata::add_unique(&mut meta.software, &format!("Java JDK {v}"));
            }
            "Implementation-Vendor" | "Bundle-Vendor" | "Specification-Vendor" => {
                meta.company.get_or_insert(v.clone());
            }
            "Implementation-Title" | "Bundle-Name" => {
                meta.title.get_or_insert(v.clone());
            }
            "Bundle-Description" => {
                meta.description.get_or_insert(v.clone());
            }
            "Build-Date" | "Built-Date" | "Build-Time" | "Bnd-LastModified" => {
                let d = if k == "Bnd-LastModified" {
                    v.parse::<i64>()
                        .ok()
                        .and_then(|ms| crate::util::unix_to_iso(ms / 1000))
                } else {
                    crate::util::normalize_date(&v)
                };
                if let Some(d) = d {
                    meta.created.get_or_insert(d);
                }
            }
            "Built-OS" | "Build-Os" | "Build-OS" => {
                meta.os.get_or_insert(v.clone());
            }
            "Built-Host" | "Build-Host" => {
                meta.add_server(&v, "MANIFEST.MF:Build-Host");
            }
            _ => {}
        }
        meta.fields
            .insert(format!("manifest:{}", truncate(&k, 64)), v);
    }
    let title = meta.fields.get("manifest:Implementation-Title").cloned();
    let ver = meta
        .fields
        .get("manifest:Implementation-Version")
        .or_else(|| meta.fields.get("manifest:Bundle-Version"))
        .cloned();
    if let (Some(t), Some(v)) = (title, ver) {
        meta.revision.get_or_insert(v.clone());
        Metadata::add_unique(&mut meta.software, &format!("{t} {v}"));
    }
}

/// `Created-By: 17.0.2 (Eclipse Adoptium)` -> `Java JDK 17.0.2 (Eclipse Adoptium)`; tool
/// names (`Apache Maven 3.8.1`, `Gradle 7`) are kept.
fn created_by(v: &str) -> String {
    if v.starts_with(|c: char| c.is_ascii_digit()) {
        format!("Java JDK {v}")
    } else {
        v.to_string()
    }
}

fn pom_properties(meta: &mut Metadata, text: &str) {
    let mut g = None;
    let mut a = None;
    let mut v = None;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((k, val)) = line.split_once('=') {
            let val = truncate(val.trim(), 200);
            match k.trim() {
                "groupId" => g = Some(val),
                "artifactId" => a = Some(val),
                "version" => v = Some(val),
                _ => {}
            }
        }
    }
    if let (Some(g), Some(a)) = (g, a) {
        let coord = match &v {
            Some(v) => format!("{g}:{a}:{v}"),
            None => format!("{g}:{a}"),
        };
        meta.fields.insert(format!("maven:{a}"), coord);
        if let Some(v) = v {
            Metadata::add_unique(&mut meta.software, &format!("{a} {v}"));
        }
    }
}

/// Library jars bundled in WAR/EAR/fat JARs: `WEB-INF/lib/log4j-core-2.17.1.jar` -> software
/// `log4j-core 2.17.1`.
fn bundled_libraries(meta: &mut Metadata, names: &[String]) {
    let mut n = 0;
    for name in names {
        let in_lib = name.starts_with("WEB-INF/lib/")
            || name.starts_with("BOOT-INF/lib/")
            || name.starts_with("lib/")
            || name.starts_with("APP-INF/lib/");
        if !in_lib || !name.ends_with(".jar") || n >= MAX_LIBS {
            continue;
        }
        let file = name
            .rsplit('/')
            .next()
            .unwrap_or(name)
            .trim_end_matches(".jar");
        if let Some((lib, ver)) = split_version(file) {
            n += 1;
            Metadata::add_unique(&mut meta.software, &format!("{lib} {ver}"));
        }
    }
    if n > 0 {
        meta.stats.insert("bundled_libraries".into(), n as u64);
    }
}

/// `spring-core-5.3.20` -> (`spring-core`, `5.3.20`).
pub(crate) fn split_version(file: &str) -> Option<(&str, &str)> {
    let mut idx = None;
    for (i, _) in file.match_indices('-') {
        if file[i + 1..].starts_with(|c: char| c.is_ascii_digit()) {
            idx = Some(i);
            break;
        }
    }
    let i = idx?;
    let (lib, ver) = (&file[..i], &file[i + 1..]);
    (!lib.is_empty() && ver.len() <= 40).then_some((lib, ver))
}

/// APK Signature Scheme v2/v3 block: `... u64 size, "APK Sig Block 42"` before the central
/// directory. Takes the first signer certificate.
fn apk_signing_block(meta: &mut Metadata, b: &[u8]) {
    const MAGIC: &[u8] = b"APK Sig Block 42";
    let from = b.len().saturating_sub(64 << 20);
    let mut at = from;
    let mut magic = None;
    // the last occurrence is the real block
    while let Some(i) = find(b, MAGIC, at) {
        magic = Some(i);
        at = i + 1;
    }
    let Some(m) = magic else { return };
    let Some(size) = m.checked_sub(8).and_then(|o| rd_u64le(b, o)) else {
        return;
    };
    let Some(start) = (m + 16).checked_sub(size as usize + 8) else {
        return;
    };
    let mut i = start + 8;
    let end = m - 8;
    let mut pairs = 0;
    while i + 12 <= end && pairs < 32 {
        pairs += 1;
        let Some(len) = rd_u64le(b, i).map(|l| l as usize) else {
            return;
        };
        let id = rd_u32le(b, i + 8).unwrap_or(0);
        let Some(val) = b.get(i + 12..(i + 8).saturating_add(len).min(end)) else {
            return;
        };
        if matches!(id, 0x7109_871a | 0xf053_68c0) {
            if let Some(cert) = first_v2_cert(val) {
                if let Some(info) = signature::cert_info(cert) {
                    let mut s = signature::from_cms(
                        SignatureKind::Jar,
                        if id == 0x7109_871a {
                            "apk:v2"
                        } else {
                            "apk:v3"
                        },
                        &Default::default(),
                    );
                    s.signer = Some(info);
                    s.certificates = 1;
                    meta.signatures.push(s);
                    return;
                }
            }
        }
        i = (i + 8).saturating_add(len);
    }
}

/// Length-prefixed (u32 LE) item at the start of `b`: (item, rest).
fn lp(b: &[u8]) -> Option<(&[u8], &[u8])> {
    let n = rd_u32le(b, 0)? as usize;
    let item = b.get(4..4usize.checked_add(n)?)?;
    Some((item, &b[4 + n..]))
}

/// signers -> signer -> signed data -> (digests, certificates -> certificate).
fn first_v2_cert(v: &[u8]) -> Option<&[u8]> {
    let (signers, _) = lp(v)?;
    let (signer, _) = lp(signers)?;
    let (signed, _) = lp(signer)?;
    let (_digests, rest) = lp(signed)?;
    let (certs, _) = lp(rest)?;
    let (cert, _) = lp(certs)?;
    Some(cert)
}

/// Android binary XML (AXML) attributes of interest.
fn android_manifest(meta: &mut Metadata, b: &[u8]) {
    let Some(doc) = crate::formats::binary::axml::parse(b) else {
        meta.warnings
            .push("AndroidManifest.xml: двоичный XML не разобран".into());
        return;
    };
    let mut perms = Vec::new();
    for el in &doc {
        match el.name.as_str() {
            "manifest" => {
                for (k, v) in &el.attrs {
                    let key = match k.as_str() {
                        "package" => "apk:package",
                        "versionName" => "apk:versionName",
                        "versionCode" => "apk:versionCode",
                        "platformBuildVersionName" => "apk:platformBuildVersionName",
                        "compileSdkVersion" => "apk:compileSdkVersion",
                        _ => continue,
                    };
                    meta.fields.insert(key.into(), truncate(v, 256));
                }
            }
            "uses-sdk" => {
                for (k, v) in &el.attrs {
                    if k == "minSdkVersion" || k == "targetSdkVersion" {
                        meta.fields.insert(format!("apk:{k}"), truncate(v, 32));
                    }
                }
            }
            "uses-permission" if perms.len() < 100 => {
                if let Some((_, v)) = el.attrs.iter().find(|(k, _)| k == "name") {
                    perms.push(truncate(v, 128));
                }
            }
            _ => {}
        }
    }
    if !perms.is_empty() {
        meta.stats.insert("permissions".into(), perms.len() as u64);
        meta.fields
            .insert("apk:permissions".into(), perms.join("\n"));
    }
    if let Some(p) = meta.fields.get("apk:package").cloned() {
        meta.title.get_or_insert(p);
    }
    if let Some(v) = meta.fields.get("apk:versionName").cloned() {
        meta.revision = Some(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn library_versions() {
        assert_eq!(
            split_version("log4j-core-2.14.1"),
            Some(("log4j-core", "2.14.1"))
        );
        assert_eq!(split_version("commons-io"), None);
    }

    #[test]
    fn manifest_continuation() {
        let mut m = Metadata::default();
        manifest(
            &mut m,
            "Manifest-Version: 1.0\r\nBuilt-By: jdoe\r\nCreated-By: 17.0.2 (Example\r\n  Vendor)\r\n\r\nName: x\r\nBuilt-By: other\r\n",
        );
        assert_eq!(m.author.as_deref(), Some("jdoe"));
        assert!(m
            .software
            .iter()
            .any(|s| s == "Java JDK 17.0.2 (Example Vendor)"));
        assert!(!m.people.iter().any(|p| p.name == "other"));
    }
}
