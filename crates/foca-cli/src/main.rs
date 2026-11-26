//! `foca`: a desktop CLI for exercising the core by hand (not a product, see ADR-0001).
//!
//! * `foca extract <file...> [--json] [--text]`: document metadata;
//! * `foca target <str...> [--json]`: target parsing;
//! * `foca clean <in> <out>`: metadata removal (OOXML, JPEG);
//! * `foca analyze <dir|files...> [--scope d1,d2] [--json]`: extraction + analysis (people,
//!   software, hosts, secrets, findings, risk) of local files;
//! * `foca project new|list|import`: projects in the store (`--store`, defaults to
//!   `$FOCA_HOME` or `./foca-data`);
//! * `foca dns <domain> [--whois] [--json]`: DNS records, SPF/DMARC/DKIM, dangling CNAMEs, RDAP;
//! * `foca subdomains <domain> [--resolve] [--json]`: subdomains from CT (crt.sh, CertSpotter);
//! * `foca search <domain> [--sources wayback,cc,crt] [--limit N] [--json]`: document search
//!   (passive sources only by default);
//! * `foca download <url...> --project id`: download into a project (project scope, request
//!   log, a queue that resumes after interruption);
//! * `foca report --project id [--format html|md|csv|json] [--lang ru|uk|en] [--out file]`:
//!   project report (self-contained HTML, Markdown, CSV, JSON per schema v1);
//! * `foca export --project id --kind users --format dict [--out file]`: table export
//!   (list, dict, csv, json, maltego, graphml, md);
//! * `foca scan --project id --profile passive --wait [--limit N]`: a scan through
//!   foca-engine (same launch rules, stages and `scan://event` events as the app);
//! * `foca serve --data dir [--port 8787] [--test-net net.json]`: e2e harness exposing the
//!   engine over HTTP (`POST /invoke`, SSE `/events`, static `ui/`) for browser UI tests;
//! * `foca testnet --port 8788 --write-config net.json`: a local "internet" for `serve`.

mod fuzz;
mod log;
mod net;
mod ports;
mod recon;
mod scan;
mod scenario;
mod serve;
mod testnet;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use foca_core::{Metadata, Target};
use foca_meta::Limits;

#[derive(Parser)]
#[command(
    name = "foca",
    version,
    about = "FOCA-rs: метаданные документов и разбор целей (CLI для тестов ядра)"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// E2E harness: the real engine over HTTP on 127.0.0.1 (POST /invoke, SSE /events, static ui/)
    Serve(serve::ServeOpts),
    /// Local "internet" for e2e: web archive, crt.sh, documents from tests/corpus (offline)
    Testnet(testnet::TestNetOpts),
    /// Extract metadata from files
    Extract {
        #[arg(required = true)]
        files: Vec<PathBuf>,
        /// JSON output (an array of {file, metadata|error} objects)
        #[arg(long)]
        json: bool,
        /// Also print the plain text of each document (for secret hunting)
        #[arg(long)]
        text: bool,
    },
    /// Parse target strings: domain, *.domain, URL, IP, CIDR, range, ASN, e-mail, organization
    Target {
        #[arg(required = true)]
        input: Vec<String>,
        #[arg(long)]
        json: bool,
    },
    /// Remove metadata (OOXML, JPEG)
    Clean { input: PathBuf, output: PathBuf },
    /// Analyze local files (directories are walked recursively)
    Analyze {
        #[arg(required = true)]
        inputs: Vec<PathBuf>,
        /// Comma-separated scope targets (domains, CIDR); prefix exclusions with `!`
        #[arg(long, value_delimiter = ',')]
        scope: Vec<String>,
        /// Full analysis result as JSON
        #[arg(long)]
        json: bool,
        /// Print full secret values in the JSON output (masked by default)
        #[arg(long)]
        reveal_secrets: bool,
    },
    /// DNS records, SPF/DMARC/DKIM (mail spoofing), dangling CNAMEs; --whois adds RDAP/RIPEstat
    Dns {
        domain: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        whois: bool,
        #[command(flatten)]
        net: net::NetOpts,
    },
    /// Subdomains from Certificate Transparency (crt.sh, CertSpotter); --resolve verifies them
    Subdomains {
        domain: String,
        #[arg(long)]
        json: bool,
        #[arg(long)]
        resolve: bool,
        /// Do not query CertSpotter
        #[arg(long)]
        no_certspotter: bool,
        #[command(flatten)]
        net: net::NetOpts,
    },
    /// Document search: wayback, cc, crt (passive, the default); crawler (crawls the target site);
    /// brave/searx take a key/URL from FOCA_BRAVE_KEY, FOCA_SEARX_URL
    Search {
        domain: String,
        #[arg(long, value_delimiter = ',')]
        sources: Vec<String>,
        /// Maximum URLs per source
        #[arg(long, default_value_t = 100)]
        limit: usize,
        /// Comma-separated extensions (default: the FOCA list)
        #[arg(long, default_value = "")]
        ext: String,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        net: net::NetOpts,
    },
    /// Download URLs into a project (project scope; archives are passive; resumes an interrupted queue)
    Download {
        #[arg(required = true)]
        urls: Vec<String>,
        #[arg(long)]
        project: String,
        #[arg(long, env = "FOCA_HOME", default_value = "foca-data")]
        store: PathBuf,
        /// File size limit, MB
        #[arg(long, default_value_t = 50)]
        max_size: u64,
        #[arg(long)]
        json: bool,
        #[command(flatten)]
        net: net::NetOpts,
    },
    /// Project report: HTML (self-contained), Markdown, CSV, JSON (schema v1)
    Report {
        #[arg(long)]
        project: String,
        #[arg(long, env = "FOCA_HOME", default_value = "foca-data")]
        store: PathBuf,
        /// html | md | csv | json
        #[arg(long, default_value = "html")]
        format: String,
        /// ru | uk | en
        #[arg(long, default_value = "ru")]
        lang: String,
        /// full | summary | data
        #[arg(long, default_value = "full")]
        template: String,
        /// Secrets: hide | partial | full
        #[arg(long, default_value = "hide")]
        secrets: String,
        /// Confirmed findings only
        #[arg(long)]
        confirmed: bool,
        /// Severity threshold: low | medium | high | critical
        #[arg(long)]
        min_sev: Option<String>,
        /// Author's company (cover, header)
        #[arg(long, default_value = "")]
        company: String,
        /// Output file (default: the report name in the current directory)
        #[arg(long)]
        out: Option<PathBuf>,
        /// Do not record the report in the project history
        #[arg(long)]
        no_history: bool,
    },
    /// Export findings|users|emails|paths|software|hosts|docs|log|all as
    /// list|dict|csv|json|maltego|graphml|md
    Export {
        #[arg(long)]
        project: String,
        #[arg(long, env = "FOCA_HOME", default_value = "foca-data")]
        store: PathBuf,
        #[arg(long)]
        kind: String,
        #[arg(long, default_value = "csv")]
        format: String,
        /// Secrets in clear text (hidden by default)
        #[arg(long)]
        include_secrets: bool,
        /// Names → initials, e-mail addresses/logins → masks
        #[arg(long)]
        redact_pii: bool,
        /// Login wordlist without variants (ivan.petrov → ipetrov, …)
        #[arg(long)]
        no_variants: bool,
        /// Comma-separated columns
        #[arg(long, value_delimiter = ',')]
        columns: Vec<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Scan a project through foca-engine (prints events with --wait)
    Scan(scan::ScanOpts),
    /// Run a declarative audit scenario TOML (offline/scan, report, CI/CD gate)
    Run(scenario::RunOpts),
    /// Fuzz the client's site: forgotten documents, backups, service files, listings, vhosts
    /// (scope hosts only; --dry-run estimates without network access)
    Fuzz(Box<fuzz::FuzzOpts>),
    /// TCP ports and banners of a host (active; only your own or authorized hosts)
    Ports(ports::PortsOpts),
    /// Site recon: technologies, favicon hash, JS, robots/sitemap/security.txt, cloud storage,
    /// grep.app (--passive uses only the archived copy and sends no requests to the site)
    Recon(Box<recon::ReconOpts>),
    /// Projects in the store
    Project {
        /// Store directory (projects.db and <id>.foca)
        #[arg(long, env = "FOCA_HOME", default_value = "foca-data")]
        store: PathBuf,
        #[command(subcommand)]
        cmd: ProjectCmd,
    },
}

#[derive(Subcommand)]
enum ProjectCmd {
    /// Create a project
    New {
        name: String,
        #[arg(long, default_value = "")]
        client: String,
        /// Targets (repeatable: --target a.ua --target 10.0.0.0/8)
        #[arg(long = "target")]
        targets: Vec<String>,
        #[arg(long = "exclude")]
        excludes: Vec<String>,
    },
    /// List projects
    List {
        #[arg(long)]
        json: bool,
    },
    /// Import a directory of documents into a project and analyze it
    Import {
        dir: PathBuf,
        /// Project id (default: a new project named after the directory)
        #[arg(long)]
        project: Option<String>,
        #[arg(long)]
        json: bool,
    },
}

/// Expands a list of paths into files (directories recursively, corpus service files
/// skipped).
fn collect_files(inputs: &[PathBuf]) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack: Vec<PathBuf> = inputs.to_vec();
    // Canonical paths of walked folders: a symbolic link back to a parent is walked only once.
    let mut seen = std::collections::HashSet::new();
    while let Some(p) = stack.pop() {
        if p.is_dir() {
            let Ok(canon) = std::fs::canonicalize(&p) else {
                continue;
            };
            if !seen.insert(canon) {
                continue;
            }
            if let Ok(rd) = std::fs::read_dir(&p) {
                stack.extend(rd.flatten().map(|e| e.path()));
            }
            continue;
        }
        let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name.starts_with('.') || [".json", ".md", ".py"].iter().any(|e| name.ends_with(e)) {
            continue;
        }
        out.push(p);
    }
    out.sort();
    out
}

/// Reads a file only if its size fits the parser limit, so a huge input is never loaded whole.
/// Hex SHA-256 of a file's bytes, the key the project store deduplicates documents by.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn read_limited(path: &Path, max: u64) -> Result<Vec<u8>> {
    let len = std::fs::metadata(path)
        .with_context(|| format!("чтение {}", path.display()))?
        .len();
    anyhow::ensure!(
        len <= max,
        "{}: файл больше лимита ({len} > {max} байт)",
        path.display()
    );
    std::fs::read(path).with_context(|| format!("чтение {}", path.display()))
}

/// Masks secret values in an analysis result (full values only with an explicit opt-in).
///
/// Besides `secrets[].value` this rewrites `{{s:…}}` markers and raw occurrences of a found
/// secret in the finding texts. Returns the raw values (for [`mask_json_strings`]).
fn mask_secrets(a: &mut foca_analysis::Analysis) -> Vec<String> {
    let mut raws: Vec<String> = a
        .secrets
        .iter()
        .map(|s| s.value.expose().to_string())
        .filter(|v| v.chars().count() >= MIN_RAW_SECRET)
        .collect();
    raws.sort_by_key(|v| std::cmp::Reverse(v.len()));
    raws.dedup();
    for s in &mut a.secrets {
        s.value = foca_core::api::SecretValue::new(s.value.masked());
    }
    let mask = |s: &mut String| *s = mask_secret_text(s, &raws);
    for f in &mut a.findings {
        for s in [
            &mut f.title,
            &mut f.description,
            &mut f.recommendation,
            &mut f.evidence,
            &mut f.request,
        ] {
            mask(s);
        }
    }
    raws
}

/// Raw secret values shorter than this are not searched outside `{{s:…}}` markers (too many
/// false hits in ordinary words).
const MIN_RAW_SECRET: usize = 6;

/// Masks `{{s:…}}` markers and raw occurrences of known secret values in one string.
fn mask_secret_text(s: &str, raws: &[String]) -> String {
    let mut out = if s.contains("{{s:") {
        foca_analysis::pii::mask_markers(s)
    } else {
        s.to_string()
    };
    for r in raws {
        if out.contains(r.as_str()) {
            out = out.replace(r.as_str(), &foca_core::api::mask(r));
        }
    }
    out
}

/// Rewrites every string value of a JSON tree through [`mask_secret_text`] (any nested field).
fn mask_json_strings(v: &mut serde_json::Value, raws: &[String]) {
    match v {
        serde_json::Value::String(s) => *s = mask_secret_text(s, raws),
        serde_json::Value::Array(xs) => xs.iter_mut().for_each(|x| mask_json_strings(x, raws)),
        serde_json::Value::Object(m) => m.values_mut().for_each(|x| mask_json_strings(x, raws)),
        _ => {}
    }
}

fn sev_label(s: foca_core::Severity) -> &'static str {
    foca_analysis::util::sev_name(s)
}

fn print_analysis(a: &foca_analysis::Analysis) {
    let an = a.docs.iter().filter(|d| d.status == "analyzed").count();
    println!("Документы: {} (разобрано {an})", a.docs.len());
    println!(
        "Риск: {} ({})",
        a.risk
            .score
            .map(|s| s.to_string())
            .unwrap_or_else(|| "-".into()),
        a.risk.level.label_ru()
    );
    println!("\nЛюди ({}):", a.people.len());
    for p in a.people.iter().take(25) {
        println!(
            "  {:<18} {:<28} док. {:<3}{}{}",
            p.login,
            p.name,
            p.docs,
            if p.service {
                " [служебная]"
            } else {
                ""
            },
            p.pc.as_deref()
                .map(|x| format!(" ПК {x}"))
                .unwrap_or_default()
        );
    }
    if let Some(p) = a.patterns.first() {
        println!(
            "\nШаблон e-mail: {}@{} ({}%, по {} адресам)",
            p.p, p.domain, p.conf, p.n
        );
    }
    let found = a.emails.iter().filter(|e| e.found).count();
    println!(
        "E-mail: найдено {found}, сгенерировано {}",
        a.emails.len() - found
    );
    println!("\nПО ({}):", a.software.len());
    for s in &a.software {
        println!(
            "  {:<16} {:<44} док. {:<3}{}",
            s.id,
            s.name,
            s.docs,
            if s.eol { " УСТАРЕЛО" } else { "" }
        );
    }
    if !a.os.is_empty() {
        let os: Vec<String> =
            a.os.iter()
                .map(|o| format!("{}{}", o.name, if o.eol { " (EOL)" } else { "" }))
                .collect();
        println!("ОС: {}", os.join(", "));
    }
    println!("\nХосты ({}):", a.hosts.len());
    for h in &a.hosts {
        println!(
            "  {:<36} {:<18} {:<12} {}",
            h.name,
            h.role,
            h.scope,
            if h.internal { "внутр." } else { "" }
        );
    }
    let pcs: Vec<String> = a
        .pcs
        .iter()
        .map(|p| format!("{} ({})", p.name, p.kind))
        .collect();
    if !pcs.is_empty() {
        println!("ПК: {}", pcs.join(", "));
    }
    println!("\nСекреты ({}):", a.secrets.len());
    for s in &a.secrets {
        println!(
            "  [{}] {:<5} {:<24} {}: док. {} ({})",
            sev_label(s.sev),
            s.kind,
            s.rule,
            s.value,
            s.doc,
            s.location
        );
    }
    println!("\nНаходки ({}):", a.findings.len());
    for f in &a.findings {
        println!("  [{}] {}", sev_label(f.sev), f.title);
    }
}

fn print_human(m: &Metadata) {
    let opt = |k: &str, v: &Option<String>| {
        if let Some(v) = v {
            println!("  {k:<16} {v}");
        }
    };
    println!("  {:<16} {:?}", "format", m.format);
    opt("title", &m.title);
    opt("author", &m.author);
    opt("last_modified_by", &m.last_modified_by);
    opt("company", &m.company);
    opt("application", &m.application);
    opt("producer", &m.producer);
    opt("template", &m.template);
    opt("os", &m.os);
    opt("created", &m.created);
    opt("modified", &m.modified);
    if !m.people.is_empty() {
        let names: Vec<String> = m
            .people
            .iter()
            .map(|p| format!("{} ({:?})", p.name, p.role))
            .collect();
        println!("  {:<16} {}", "people", names.join(", "));
    }
    let list = |k: &str, v: Vec<String>| {
        if !v.is_empty() {
            println!("  {k:<16} {}", v.join(" | "));
        }
    };
    list("emails", m.emails.clone());
    list("paths", m.paths.iter().map(|p| p.path.clone()).collect());
    list(
        "servers",
        m.servers.iter().map(|s| s.name.clone()).collect(),
    );
    list("printers", m.printers.clone());
    list("software", m.software.clone());
    list("links", m.links.clone());
    list("hidden_sheets", m.hidden_sheets.clone());
    list("macro_modules", m.macro_modules.clone());
    if let Some(g) = &m.gps {
        println!("  {:<16} {}, {}", "gps", g.lat, g.lon);
    }
    if let Some(c) = &m.camera {
        println!(
            "  {:<16} {:?} {:?} s/n {:?}",
            "camera", c.make, c.model, c.serial
        );
    }
    if let Some(t) = &m.thumbnail {
        println!("  {:<16} {} байт", "thumbnail", t.data.len());
    }
    if let Some(u) = m.incremental_updates {
        println!("  {:<16} {u}", "pdf_updates");
    }
    for (k, v) in [
        ("revisions", m.revisions.len()),
        ("comments", m.comments.len()),
        ("old_versions", m.old_versions.len()),
        ("secrets", m.secrets.len()),
    ] {
        if v > 0 {
            println!("  {k:<16} {v}");
        }
    }
    if m.has_macros {
        println!("  {:<16} да", "macros");
    }
    if m.has_javascript {
        println!("  {:<16} да", "javascript");
    }
    for e in &m.embedded {
        println!("  вложение {}:", e.name);
        print_human(&e.metadata);
    }
    for w in &m.warnings {
        println!("  ! {w}");
    }
}

fn run() -> Result<bool> {
    let cli = Cli::parse();
    let limits = Limits::default();
    match cli.cmd {
        Cmd::Scan(o) => scan::run(o),
        Cmd::Run(o) => scenario::run(o),
        Cmd::Fuzz(o) => fuzz::run(*o),
        Cmd::Ports(o) => ports::run(o),
        Cmd::Recon(o) => recon::run(*o),
        Cmd::Serve(o) => serve::run(o),
        Cmd::Testnet(o) => testnet::run(o),
        Cmd::Extract { files, json, text } => {
            let mut ok = true;
            let mut out = Vec::new();
            for f in files {
                let bytes = match read_limited(&f, limits.max_file) {
                    Ok(b) => b,
                    Err(e) => {
                        if json {
                            out.push(serde_json::json!({ "file": f.display().to_string(), "error": e.to_string() }));
                        } else {
                            println!("{}\n  ошибка: {e}", f.display());
                        }
                        ok = false;
                        continue;
                    }
                };
                let name = f.file_name().and_then(|n| n.to_str());
                let res = foca_meta::extract(&bytes, name, &limits);
                let txt = if text {
                    foca_meta::text(&bytes, &limits).ok()
                } else {
                    None
                };
                if json {
                    let mut v = match &res {
                        Ok(m) => {
                            serde_json::json!({ "file": f.display().to_string(), "metadata": m })
                        }
                        Err(e) => {
                            serde_json::json!({ "file": f.display().to_string(), "error": e.to_string() })
                        }
                    };
                    if let (Some(t), Some(obj)) = (&txt, v.as_object_mut()) {
                        obj.insert("text".into(), serde_json::Value::String(t.clone()));
                    }
                    out.push(v);
                } else {
                    println!("{}", f.display());
                    match &res {
                        Ok(m) => print_human(m),
                        Err(e) => println!("  ошибка: {e}"),
                    }
                    if let Some(t) = &txt {
                        println!("  --- текст ---\n{t}");
                    }
                }
                ok &= res.is_ok();
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
            Ok(ok)
        }
        Cmd::Target { input, json } => {
            let mut ok = true;
            let mut out = Vec::new();
            for s in input {
                let r = Target::parse(&s);
                if json {
                    out.push(match &r {
                        Ok(t) => serde_json::json!({ "input": s, "target": t }),
                        Err(e) => serde_json::json!({ "input": s, "error": e.to_string() }),
                    });
                } else {
                    match &r {
                        Ok(t) => println!("{s}\t{}\t{t}", t.kind()),
                        Err(e) => println!("{s}\tошибка: {e}"),
                    }
                }
                ok &= r.is_ok();
            }
            if json {
                println!("{}", serde_json::to_string_pretty(&out)?);
            }
            Ok(ok)
        }
        Cmd::Analyze {
            inputs,
            scope,
            json,
            reveal_secrets,
        } => {
            let files = collect_files(&inputs);
            anyhow::ensure!(!files.is_empty(), "файлы не найдены");
            let mut docs = Vec::new();
            let mut texts = Vec::new();
            for (i, f) in files.iter().enumerate() {
                let bytes = match read_limited(f, limits.max_file) {
                    Ok(b) => b,
                    Err(e) => {
                        eprintln!("{e}");
                        continue;
                    }
                };
                let name = f
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("file")
                    .to_string();
                let meta = foca_meta::extract(&bytes, Some(&name), &limits);
                if let Err(e) = &meta {
                    eprintln!("{}: {e}", f.display());
                }
                texts.push(foca_meta::text(&bytes, &limits).ok());
                docs.push(foca_core::Document {
                    id: i as u64 + 1,
                    ext: name.rsplit('.').next().unwrap_or("").to_lowercase(),
                    name,
                    url: Some(format!("file://{}", f.display())),
                    source: "local".into(),
                    size: bytes.len() as u64,
                    sha256: sha256_hex(&bytes),
                    status: if meta.is_ok() {
                        foca_core::DocStatus::Analyzed
                    } else {
                        foca_core::DocStatus::Error
                    },
                    metadata: meta.ok(),
                    ..Default::default()
                });
            }
            let (t, e): (Vec<String>, Vec<String>) =
                scope.into_iter().partition(|s| !s.starts_with('!'));
            let excl: Vec<String> = e.iter().map(|s| s[1..].to_string()).collect();
            let (sc, errs) = foca_core::Scope::from_lines(&t.join("\n"), &excl.join("\n"));
            for er in errs {
                eprintln!("скоуп: «{}»: {}", er.input, er.error);
            }
            let inputs: Vec<foca_analysis::DocInput> = docs
                .iter()
                .zip(&texts)
                .map(|(d, t)| foca_analysis::DocInput::new(d).with_text(t.as_deref()))
                .collect();
            let mut a = foca_analysis::analyze(&inputs, &sc, &foca_analysis::PrevState::default());
            let raws = if reveal_secrets {
                Vec::new()
            } else {
                mask_secrets(&mut a)
            };
            if json {
                let mut v = serde_json::to_value(&a)?;
                if !reveal_secrets {
                    mask_json_strings(&mut v, &raws);
                }
                println!("{}", serde_json::to_string_pretty(&v)?);
            } else {
                print_analysis(&a);
            }
            Ok(true)
        }
        Cmd::Project { store, cmd } => {
            let st = foca_store::Store::open(&store)
                .with_context(|| format!("хранилище {}", store.display()))?;
            match cmd {
                ProjectCmd::New {
                    name,
                    client,
                    targets,
                    excludes,
                } => {
                    let p = st.create_project(&foca_store::NewProject {
                        name,
                        client,
                        targets,
                        excludes,
                    })?;
                    println!("создан проект {} ({})", p.id, store.display());
                }
                ProjectCmd::List { json } => {
                    let list = st.list_projects()?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&list)?);
                    } else {
                        for p in list {
                            println!(
                                "{:<28} {:<30} док. {:<5} находок {:<4} риск {}",
                                p.id,
                                p.name,
                                p.docs,
                                p.findings,
                                p.risk.map(|r| r.to_string()).unwrap_or_else(|| "-".into())
                            );
                        }
                    }
                }
                ProjectCmd::Import { dir, project, json } => {
                    let id = match project {
                        Some(id) => id,
                        None => {
                            let name = dir
                                .canonicalize()
                                .ok()
                                .and_then(|p| {
                                    p.file_name().map(|n| n.to_string_lossy().to_string())
                                })
                                .unwrap_or_else(|| "import".into());
                            st.create_project(&foca_store::NewProject {
                                name,
                                ..Default::default()
                            })?
                            .id
                        }
                    };
                    let db = st.open_project(&id)?;
                    let scan_id = format!("import-{}", db.scans()?.len() + 1);
                    db.scan_start(&scan_id, "custom", false)?;
                    let (mut added, mut dup, mut failed) = (0, 0, 0);
                    for f in collect_files(std::slice::from_ref(&dir)) {
                        let bytes = std::fs::read(&f)?;
                        let name = f
                            .file_name()
                            .and_then(|n| n.to_str())
                            .unwrap_or("file")
                            .to_string();
                        let r = db.add_document(&foca_store::AddDoc {
                            url: Some(format!("file://{}", f.display())),
                            name: name.clone(),
                            source: "local".into(),
                            first_scan: Some(scan_id.clone()),
                            status: foca_core::DocStatus::Downloaded,
                            size: bytes.len() as u64,
                            sha256: Some(sha256_hex(&bytes)),
                            local_path: Some(f.display().to_string()),
                            ..Default::default()
                        })?;
                        if r.existing {
                            dup += 1;
                            continue;
                        }
                        added += 1;
                        match foca_meta::extract(&bytes, Some(&name), &limits) {
                            Ok(m) => {
                                let t = foca_meta::text(&bytes, &limits).ok();
                                db.set_analyzed(r.id, &m, t.as_deref())?;
                            }
                            Err(e) => {
                                failed += 1;
                                db.set_doc_error(r.id, &e.to_string())?;
                            }
                        }
                    }
                    let a = db.run_analysis(Some(&scan_id))?;
                    let snapshot = db.scan_snapshot()?;
                    let started = db
                        .scans()?
                        .into_iter()
                        .find(|s| s.id == scan_id)
                        .map(|s| s.started_at)
                        .unwrap_or_default();
                    db.scan_save(&foca_core::api::Scan {
                        id: scan_id.clone(),
                        profile_id: "custom".into(),
                        trigger: "manual".into(),
                        status: "done".into(),
                        started_at: started.clone(),
                        finished_at: Some(started),
                        egress: "локальный импорт".into(),
                        docs: snapshot.docs.len() as u32,
                        hosts: snapshot.hosts.len() as u32,
                        people: snapshot.people.len() as u32,
                        findings: a.findings.len() as u32,
                        new_findings: a.findings.len() as u32,
                        snapshot,
                        ..Default::default()
                    })?;
                    let sum = st.refresh_summary(&db)?;
                    if json {
                        println!("{}", serde_json::to_string_pretty(&sum)?);
                    } else {
                        println!(
                            "проект {}: добавлено {added}, дубликатов {dup}, ошибок разбора {failed}",
                            sum.id
                        );
                        print_analysis(&a);
                    }
                }
            }
            Ok(true)
        }
        Cmd::Report {
            project,
            store,
            format,
            lang,
            template,
            secrets,
            confirmed,
            min_sev,
            company,
            out,
            no_history,
        } => {
            use foca_report::*;
            let fmt = ReportFormat::parse(&format)
                .with_context(|| format!("неизвестный формат отчёта: {format}"))?;
            let lang = Lang::parse(&lang).with_context(|| format!("неизвестный язык: {lang}"))?;
            let tpl = Template::parse(&template)
                .with_context(|| format!("неизвестный шаблон: {template}"))?;
            let secrets = SecretMode::parse(&secrets)
                .with_context(|| format!("неизвестный режим секретов: {secrets}"))?;
            let min_sev = match min_sev {
                Some(s) => Some(
                    opts::parse_min_sev(&s)
                        .with_context(|| format!("неизвестная важность: {s}"))?,
                ),
                None => None,
            };
            let st = foca_store::Store::open(&store)
                .with_context(|| format!("хранилище {}", store.display()))?;
            let snap = st.project_snapshot(&project)?;
            let db = st.open_project(&project)?;
            let log = request_log(&db)?;
            let o = ReportOptions {
                tpl,
                fmt,
                lang,
                sections: Sections::for_template(tpl),
                confirmed,
                min_sev,
                secrets,
                company,
                ..Default::default()
            };
            let a = build_report_with_log(&snap, &log, &o, time::OffsetDateTime::now_utc());
            let path = out.unwrap_or_else(|| PathBuf::from(&a.file_name));
            std::fs::write(&path, &a.bytes)
                .with_context(|| format!("запись {}", path.display()))?;
            if !no_history {
                db.report_add(&foca_core::api::Report {
                    name: a.file_name.clone(),
                    tpl: tpl_label(tpl, lang).into(),
                    fmt: fmt.ext().into(),
                    lang: a.lang.clone(),
                    size: a.size_label(),
                    opts: a.opts.clone(),
                    ..Default::default()
                })?;
            }
            let s = &a.summary;
            println!(
                "{} ({}, {} байт): находок {} (крит. {}, выс. {}), исправлено {}, риск {} ({})",
                path.display(),
                a.mime,
                a.bytes.len(),
                s.total,
                s.counts.get(foca_core::Severity::Critical),
                s.counts.get(foca_core::Severity::High),
                s.fixed,
                s.risk.map(|r| r.to_string()).unwrap_or_else(|| "-".into()),
                s.risk_level
            );
            Ok(true)
        }
        Cmd::Export {
            project,
            store,
            kind,
            format,
            include_secrets,
            redact_pii,
            no_variants,
            columns,
            out,
        } => {
            use foca_report::*;
            let k = ExportKind::parse(&kind)
                .with_context(|| format!("неизвестный вид экспорта: {kind}"))?;
            let f = ExportFormat::parse(&format)
                .with_context(|| format!("неизвестный формат экспорта: {format}"))?;
            let st = foca_store::Store::open(&store)
                .with_context(|| format!("хранилище {}", store.display()))?;
            let snap = st.project_snapshot(&project)?;
            let db = st.open_project(&project)?;
            let log = request_log(&db)?;
            let o = ExportOptions {
                include_secrets,
                redact_pii,
                login_variants: !no_variants,
                columns: (!columns.is_empty()).then_some(columns),
                ..Default::default()
            };
            let a = export_with_log(&snap, &log, k, f, &o);
            let path = out.unwrap_or_else(|| PathBuf::from(&a.file_name));
            std::fs::write(&path, &a.bytes)
                .with_context(|| format!("запись {}", path.display()))?;
            println!(
                "{} ({}, {} байт): записей {}, секреты {}, PII скрыты: {}",
                path.display(),
                a.mime,
                a.bytes.len(),
                a.count,
                if a.secrets {
                    "открыты"
                } else {
                    "скрыты"
                },
                if a.pii_redacted { "да" } else { "нет" }
            );
            Ok(true)
        }
        Cmd::Dns {
            domain,
            json,
            whois,
            net,
        } => net::dns(&domain, json, whois, &net),
        Cmd::Subdomains {
            domain,
            json,
            resolve,
            no_certspotter,
            net,
        } => net::subdomains(&domain, json, resolve, !no_certspotter, &net),
        Cmd::Search {
            domain,
            sources,
            limit,
            ext,
            json,
            net,
        } => net::search(&domain, &sources, limit, &ext, json, &net),
        Cmd::Download {
            urls,
            project,
            store,
            max_size,
            json,
            net,
        } => net::download(&store, &project, &urls, max_size, json, &net),
        Cmd::Clean { input, output } => {
            let bytes =
                std::fs::read(&input).with_context(|| format!("чтение {}", input.display()))?;
            let kind = foca_meta::detect(&bytes);
            let cleaned = foca_meta::clean(&bytes, kind)?;
            std::fs::write(&output, &cleaned)
                .with_context(|| format!("запись {}", output.display()))?;
            println!(
                "{} → {} ({kind:?}, {} → {} байт)",
                input.display(),
                output.display(),
                bytes.len(),
                cleaned.len()
            );
            Ok(true)
        }
    }
}

/// Returns the project's outgoing request log in report form.
fn request_log(db: &foca_store::ProjectDb) -> Result<Vec<foca_report::RequestEntry>> {
    Ok(db
        .requests(None, false)?
        .into_iter()
        .map(|r| foca_report::RequestEntry {
            blocked: foca_report::RequestEntry::is_blocked_code(r.error.as_deref()),
            time: r.time,
            scan_id: r.scan_id,
            module: r.module,
            method: r.method,
            url: r.url,
            host: r.host,
            status: r.status,
            bytes: r.bytes,
            active: r.active,
            error: r.error,
            note: r.note,
            ctype: r.ctype,
        })
        .collect())
}

fn main() -> ExitCode {
    log::init();
    match run() {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::from(1),
        Err(e) => {
            eprintln!("ошибка: {e:#}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analysis_secrets_are_masked_by_default() {
        let mut a = foca_analysis::Analysis::default();
        a.secrets.push(foca_core::api::Secret {
            value: foca_core::api::SecretValue::new("Kont0so#2024!"),
            ..Default::default()
        });
        mask_secrets(&mut a);
        let json = serde_json::to_string(&a).unwrap();
        assert!(!json.contains("Kont0so#2024!"), "{json}");
    }

    #[test]
    fn read_limited_rejects_files_over_limit() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("big.bin");
        std::fs::write(&f, vec![1u8; 2048]).unwrap();
        assert!(read_limited(&f, 1024).is_err());
        assert_eq!(read_limited(&f, 4096).unwrap().len(), 2048);
    }

    #[cfg(unix)]
    #[test]
    fn collect_files_survives_symlink_cycles() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("docs");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("a.pdf"), b"x").unwrap();
        std::fs::write(root.join("sub/b.pdf"), b"y").unwrap();
        std::os::unix::fs::symlink(&root, root.join("sub/loop")).unwrap();
        let files = collect_files(std::slice::from_ref(&root));
        assert_eq!(files.len(), 2, "{files:?}");
    }
}
