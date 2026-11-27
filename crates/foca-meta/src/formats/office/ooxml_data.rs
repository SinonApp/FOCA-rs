//! Data sources of Office packages: spreadsheet connections (`xl/connections.xml`), Power Query
//! mashups (`customXml` DataMashup), external defined names, Word mail merge and document
//! variables, and fonts. Passwords in connection strings are detected and redacted: only the
//! fact that one was present is kept.

use std::io::{Cursor, Read};

use foca_core::{DataConnection, Metadata, SecretRef};

use crate::util::{clean_str, truncate};
use crate::xml::Element;
use crate::zipx::SafeZip;
use crate::{Ctx, MetaError};

const MAX_CONNECTIONS: usize = 200;

/// A parsed OLE DB/ODBC connection string with secrets removed.
#[derive(Default)]
pub(crate) struct ConnString {
    pub server: Option<String>,
    pub database: Option<String>,
    pub provider: Option<String>,
    pub user: Option<String>,
    pub has_password: bool,
    /// The input with password values replaced by `***`.
    pub redacted: String,
}

fn is_password_key(k: &str) -> bool {
    matches!(
        k,
        "password" | "pwd" | "pass" | "passwd" | "jet oledb:database password" | "accountkey"
    ) || k.ends_with("password")
}

/// Splits `k=v;k=v` (values may be quoted) and redacts password values.
pub(crate) fn parse_conn(cs: &str) -> ConnString {
    let mut out = ConnString::default();
    let mut parts: Vec<String> = Vec::new();
    for part in cs.split(';').take(64) {
        let Some((k, v)) = part.split_once('=') else {
            if !part.trim().is_empty() {
                parts.push(part.to_string());
            }
            continue;
        };
        let key = k.trim().to_ascii_lowercase();
        let val = v.trim().trim_matches(['"', '\'']);
        if is_password_key(&key) {
            if !val.is_empty() {
                out.has_password = true;
            }
            parts.push(format!("{k}=***"));
            continue;
        }
        parts.push(part.to_string());
        if val.is_empty() {
            continue;
        }
        let val = truncate(val, 256);
        match key.as_str() {
            "data source" | "server" | "address" | "addr" | "network address" | "host"
            | "hostname" | "dsn" | "location" | "dbq" => {
                out.server.get_or_insert(val);
            }
            "initial catalog" | "database" | "default database" => {
                out.database.get_or_insert(val);
            }
            "provider" | "driver" => {
                out.provider.get_or_insert(val);
            }
            "user id" | "uid" | "user" | "username" | "user name" => {
                out.user.get_or_insert(val);
            }
            _ => {}
        }
    }
    out.redacted = truncate(&parts.join(";"), 2048);
    out
}

/// Records a connection: model entry, server, and a secret marker when a password was present.
pub(crate) fn push_connection(meta: &mut Metadata, mut c: DataConnection) {
    if meta.connections.len() >= MAX_CONNECTIONS {
        return;
    }
    if let Some(s) = c.server.clone() {
        // `Data Source` of file providers is a path, not a host
        if !crate::paths::add_path(meta, &s, &c.source) {
            meta.add_server(&s, &c.source);
        }
    }
    if let Some(t) = c.target.clone() {
        if t.contains("://") {
            Metadata::add_unique(&mut meta.links, &t);
        } else {
            crate::paths::add_path(meta, &t, &c.source);
        }
    }
    if c.has_password {
        let name = c.name.clone().unwrap_or_else(|| c.kind.clone());
        meta.secrets.push(SecretRef {
            kind: "connection_password".into(),
            // never the password itself: a stable marker of where it was
            value: format!("[redacted password: {}]", truncate(&name, 64)),
            source: c.source.clone(),
        });
    }
    c.name = c.name.map(|n| truncate(&n, 128));
    meta.connections.push(c);
}

fn conn_kind(t: Option<&str>) -> &'static str {
    match t.unwrap_or("") {
        "1" => "odbc",
        "2" => "dao",
        "3" => "file",
        "4" => "web",
        "5" => "oledb",
        "6" => "text",
        "7" => "ado",
        "8" => "dsp",
        _ => "other",
    }
}

/// `xl/connections.xml`: every connection becomes a [`DataConnection`]; the raw fields keep
/// redacted connection strings only.
pub(crate) fn spreadsheet_connections(meta: &mut Metadata, e: &Element) {
    for c in e
        .descendants("connection")
        .into_iter()
        .take(MAX_CONNECTIONS)
    {
        let name = c.attr("name").unwrap_or("connection").to_string();
        let src = "xl/connections.xml".to_string();
        let mut dc = DataConnection {
            kind: conn_kind(c.attr("type")).into(),
            name: Some(name.clone()),
            source: src,
            ..Default::default()
        };
        for attr in ["odcFile", "credentialsFile", "sourceFile"] {
            if let Some(v) = c.attr(attr) {
                meta.fields
                    .insert(format!("xl:connection:{name}:{attr}"), truncate(v, 2048));
                if attr != "credentialsFile" {
                    dc.target.get_or_insert_with(|| truncate(v, 1024));
                }
            }
        }
        for child in ["dbPr", "olapPr"] {
            if let Some(cs) = c.child(child).and_then(|d| d.attr("connection")) {
                let p = parse_conn(cs);
                meta.fields.insert(
                    format!("xl:connection:{name}:connection"),
                    p.redacted.clone(),
                );
                if let Some(u) = &p.user {
                    meta.fields
                        .insert(format!("xl:connection:{name}:user"), u.clone());
                }
                if let Some(d) = &p.database {
                    meta.fields
                        .insert(format!("xl:connection:{name}:database"), d.clone());
                }
                dc.server = dc.server.or(p.server);
                dc.database = dc.database.or(p.database);
                dc.provider = dc.provider.or(p.provider);
                dc.user = dc.user.or(p.user);
                dc.has_password |= p.has_password;
            }
        }
        if let Some(cmd) = c.child("dbPr").and_then(|d| d.attr("command")) {
            meta.fields.insert(
                format!("xl:connection:{name}:command"),
                truncate(&parse_conn(cmd).redacted, 2048),
            );
        }
        if let Some(u) = c.child("webPr").and_then(|d| d.attr("url")) {
            meta.fields
                .insert(format!("xl:connection:{name}:url"), truncate(u, 2048));
            dc.target = Some(truncate(u, 1024));
        }
        if let Some(f) = c.child("textPr").and_then(|d| d.attr("sourceFile")) {
            dc.target = Some(truncate(f, 1024));
        }
        if c.attr("savePassword") == Some("1") {
            dc.has_password = true;
        }
        push_connection(meta, dc);
    }
}

/// Defined names whose formula points into another workbook or a share.
pub(crate) fn external_defined_names(meta: &mut Metadata, workbook: &Element) {
    let mut n = 0;
    for d in workbook.descendants("definedName") {
        let v = d.text();
        if !(v.contains('[') || v.contains(":\\") || v.contains("\\\\") || v.contains("://")) {
            continue;
        }
        let name = d.attr("name").unwrap_or("name");
        for p in crate::paths::find_paths(&v.replace('\'', " ")) {
            crate::paths::add_path(meta, &p, "xl:definedName");
        }
        if n < 50 {
            n += 1;
            meta.fields.insert(
                format!("xl:definedName:{}", truncate(name, 64)),
                truncate(&v, 512),
            );
        }
    }
}

/// Word `settings.xml`: mail merge data source and document variables.
pub(crate) fn word_settings(meta: &mut Metadata, e: &Element) {
    if let Some(mm) = e.child("mailMerge") {
        let val = |l: &str| mm.child(l).and_then(|x| x.attr_local("val"));
        let mut dc = DataConnection {
            kind: "mailmerge".into(),
            name: val("mainDocumentType").map(str::to_string),
            source: "word/settings.xml:mailMerge".into(),
            ..Default::default()
        };
        if let Some(cs) = val("connectString") {
            let p = parse_conn(cs);
            meta.fields.insert(
                "settings:mailMerge.connectString".into(),
                p.redacted.clone(),
            );
            dc.server = p.server;
            dc.database = p.database;
            dc.provider = p.provider;
            dc.user = p.user;
            dc.has_password = p.has_password;
        }
        if let Some(q) = val("query") {
            let q = truncate(&parse_conn(q).redacted, 1024);
            meta.fields.insert("settings:mailMerge.query".into(), q);
        }
        push_connection(meta, dc);
    }
    if let Some(dv) = e.child("docVars") {
        for v in dv.descendants("docVar").into_iter().take(100) {
            if let (Some(n), Some(val)) = (v.attr_local("name"), v.attr_local("val")) {
                meta.custom
                    .insert(format!("docVar:{}", truncate(n, 64)), truncate(val, 1024));
            }
        }
    }
}

/// Font names from `word/fontTable.xml` (`w:font w:name`), `xl/styles.xml` (`font/name val`)
/// and `ppt/presentation.xml` embedded fonts (`p:font typeface`).
pub(crate) fn fonts(meta: &mut Metadata, e: &Element) {
    for el in e.walk() {
        let name = match el.local() {
            "font" => el
                .attr_local("name")
                .or_else(|| el.attr("typeface"))
                .map(str::to_string)
                .or_else(|| {
                    el.child("name")
                        .and_then(|n| n.attr("val"))
                        .map(str::to_string)
                }),
            _ => None,
        };
        if let Some(n) = name.and_then(|n| clean_str(&n)) {
            if meta.fonts.len() < 200 {
                Metadata::add_unique(&mut meta.fonts, &truncate(&n, 128));
            }
        }
    }
}

/// Power Query: `customXml/item*.xml` with a base64 `DataMashup` holding a ZIP whose
/// `Formulas/Section1.m` lists the sources.
pub(crate) fn power_query(
    z: &mut SafeZip,
    names: &[String],
    ctx: &Ctx,
    meta: &mut Metadata,
) -> Result<(), MetaError> {
    for n in names
        .iter()
        .filter(|n| n.starts_with("customXml/item") && n.ends_with(".xml"))
        .take(20)
    {
        let Some(raw) = z.read_prefix(n, 16 << 20, ctx)? else {
            continue;
        };
        let text = crate::util::decode_text(&raw);
        let Some(start) = text.find("<DataMashup") else {
            continue;
        };
        let body = &text[start..];
        let Some(open_end) = body.find('>') else {
            continue;
        };
        let Some(close) = body.find("</DataMashup>") else {
            continue;
        };
        if close <= open_end {
            continue;
        }
        let Some(bin) = crate::formats::signature::base64(&body[open_end + 1..close]) else {
            continue;
        };
        ctx.spend(bin.len() as u64)?;
        if let Some(m) = mashup_section(&bin, ctx)? {
            meta.fields
                .insert("powerquery:formulas".into(), format!("{} bytes", m.len()));
            m_sources(meta, &m);
        }
    }
    Ok(())
}

/// `Version u32, PackagePartsLength u32, PackageParts (ZIP)` -> `Formulas/Section1.m`.
fn mashup_section(bin: &[u8], ctx: &Ctx) -> Result<Option<String>, MetaError> {
    let Some(len) = crate::util::rd_u32le(bin, 4) else {
        return Ok(None);
    };
    let Some(pkg) = bin.get(8..8usize.saturating_add(len as usize)) else {
        return Ok(None);
    };
    let Ok(mut zip) = zip::ZipArchive::new(Cursor::new(pkg)) else {
        return Ok(None);
    };
    let Ok(f) = zip.by_name("Formulas/Section1.m") else {
        return Ok(None);
    };
    let mut out = Vec::new();
    let cap = ctx.remaining().min(4 << 20);
    let _ = f.take(cap).read_to_end(&mut out);
    ctx.spend(out.len() as u64)?;
    Ok(Some(String::from_utf8_lossy(&out).into_owned()))
}

/// Source functions of Power Query M and the meaning of their first two string arguments.
const M_SOURCES: &[(&str, &str)] = &[
    ("Sql.Database", "sql"),
    ("Sql.Databases", "sql"),
    ("Oracle.Database", "oracle"),
    ("PostgreSQL.Database", "postgresql"),
    ("MySQL.Database", "mysql"),
    ("Odbc.DataSource", "odbc"),
    ("Odbc.Query", "odbc"),
    ("OleDb.DataSource", "oledb"),
    ("Web.Contents", "web"),
    ("Web.Page", "web"),
    ("OData.Feed", "odata"),
    ("SharePoint.Files", "sharepoint"),
    ("SharePoint.Contents", "sharepoint"),
    ("SharePoint.Tables", "sharepoint"),
    ("File.Contents", "file"),
    ("Folder.Files", "file"),
    ("Folder.Contents", "file"),
    ("AnalysisServices.Database", "ssas"),
    ("Exchange.Contents", "exchange"),
    ("ActiveDirectory.Domains", "ldap"),
];

fn m_sources(meta: &mut Metadata, m: &str) {
    let mut query = String::from("Section1");
    let mut count = 0;
    for line in m.lines().take(50_000) {
        let t = line.trim();
        if let Some(rest) = t.strip_prefix("shared ") {
            let name = rest
                .split('=')
                .next()
                .unwrap_or("")
                .trim()
                .trim_start_matches("#\"")
                .trim_end_matches('"');
            query = truncate(name, 128);
        }
        for (func, kind) in M_SOURCES {
            let mut from = 0;
            while let Some(i) = t[from..].find(func) {
                let at = from + i + func.len();
                from = at;
                let args = string_args(&t[at..]);
                if args.is_empty() || count >= MAX_CONNECTIONS {
                    continue;
                }
                count += 1;
                let mut dc = DataConnection {
                    kind: format!("powerquery:{kind}"),
                    name: Some(query.clone()),
                    source: "customXml:DataMashup".into(),
                    ..Default::default()
                };
                match *kind {
                    "web" | "odata" | "sharepoint" | "file" => {
                        dc.target = Some(truncate(&args[0], 1024));
                    }
                    "odbc" | "oledb" => {
                        let p = parse_conn(&args[0]);
                        dc.server = p.server;
                        dc.database = p.database;
                        dc.provider = p.provider;
                        dc.user = p.user;
                        dc.has_password = p.has_password;
                    }
                    _ => {
                        dc.server = Some(truncate(&args[0], 256));
                        dc.database = args.get(1).map(|d| truncate(d, 256));
                    }
                }
                push_connection(meta, dc);
            }
        }
    }
}

/// String literals right after `(`: `("a", "b"` -> `[a, b]` (M doubles quotes to escape).
fn string_args(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let Some(rest) = s.trim_start().strip_prefix('(') else {
        return out;
    };
    let mut chars = rest.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace() || *c == ',') {
            chars.next();
        }
        if chars.peek() != Some(&'"') || out.len() >= 2 {
            break;
        }
        chars.next();
        let mut v = String::new();
        loop {
            match chars.next() {
                Some('"') if chars.peek() == Some(&'"') => {
                    chars.next();
                    v.push('"');
                }
                Some('"') | None => break,
                Some(c) => {
                    if v.len() < 2048 {
                        v.push(c);
                    }
                }
            }
        }
        out.push(v);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_string_redacts_passwords() {
        let p = parse_conn(
            "Provider=SQLOLEDB.1;Password=S3cret!;Persist Security Info=True;User ID=report_ro;Initial Catalog=Sales;Data Source=sql01.corp.example",
        );
        assert!(p.has_password);
        assert!(!p.redacted.contains("S3cret"), "{}", p.redacted);
        assert!(p.redacted.contains("Password=***"));
        assert_eq!(p.server.as_deref(), Some("sql01.corp.example"));
        assert_eq!(p.user.as_deref(), Some("report_ro"));
        assert_eq!(p.database.as_deref(), Some("Sales"));
        assert_eq!(p.provider.as_deref(), Some("SQLOLEDB.1"));
        assert!(!parse_conn("DSN=x;UID=a").has_password);
    }

    #[test]
    fn m_code_sources() {
        let mut m = Metadata::default();
        m_sources(
            &mut m,
            "section Section1;\nshared #\"Sales 2024\" = let\n Source = Sql.Database(\"sql02.corp.example\", \"Finance\"),\n W = Web.Contents(\"https://intranet.corp.example/api?x=\"\"y\"\"\")\nin Source;\nshared Q2 = Odbc.DataSource(\"dsn=Ora;uid=etl;pwd=hunter2\", [HierarchicalNavigation=true]);",
        );
        assert_eq!(m.connections.len(), 3);
        assert_eq!(m.connections[0].name.as_deref(), Some("Sales 2024"));
        assert_eq!(
            m.connections[0].server.as_deref(),
            Some("sql02.corp.example")
        );
        assert_eq!(m.connections[0].database.as_deref(), Some("Finance"));
        assert_eq!(
            m.connections[1].target.as_deref(),
            Some("https://intranet.corp.example/api?x=\"y\"")
        );
        assert!(m.connections[2].has_password);
        assert_eq!(m.connections[2].user.as_deref(), Some("etl"));
        let js = serde_json::to_string(&m).unwrap();
        assert!(!js.contains("hunter2"), "{js}");
    }
}
