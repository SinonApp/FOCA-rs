//! Document forensics: per-document facts (signatures and qualified certificates,
//! bad redactions, hidden content, PDF revisions, scans, data connections, LNK, e-mail headers,
//! calendars, contacts, media, archives, personal data, links, user rules) and the findings
//! built from them.
//!
//! Every value that reaches a finding is already safe to store: personal data comes masked from
//! [`crate::pii::sanitize`] (`Metadata::pii`), link tokens are masked by [`crate::links`] and
//! user rule values are masked unless the rule says otherwise.

use foca_core::{DocFormat, Metadata, PiiFound, Severity};

use crate::assess::draft::Draft;
use crate::links::{self, LinkHit};
use crate::rules::RuleSet;
use crate::{pii, DocFacts};

/// Signer of a document signature.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct SignerFacts {
    pub kind: String,
    pub name: String,
    pub org: Option<String>,
    pub edrpou: Option<String>,
    pub rnokpp_masked: Option<String>,
    pub title: Option<String>,
    pub email: Option<String>,
    pub issuer: Option<String>,
    pub signing_time: Option<String>,
    pub tsa_time: Option<String>,
    pub tsa: Option<String>,
    pub modified_after: bool,
    pub digest_invalid: bool,
    /// Days between the claimed signing time and the TSA time.
    pub tsa_gap_days: Option<i64>,
}

/// User rule matches in one document, grouped by rule.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RuleFacts {
    pub rule: String,
    pub title: String,
    pub sev: Severity,
    pub count: u32,
    pub samples: Vec<String>,
}

/// Forensic facts of one document (and its embedded children).
#[derive(Debug, Clone, Default)]
pub struct Fx {
    pub lnk_machine: Option<String>,
    pub lnk_mac: Vec<String>,
    pub lnk_volume: Option<String>,
    pub lnk_unc: Vec<String>,
    pub lnk_local: Option<String>,
    pub mail_internal: Vec<String>,
    pub mail_origin_ips: Vec<String>,
    pub mail_origin_internal: bool,
    pub mail_msgid_domain: Option<String>,
    pub mail_reply_to: Option<String>,
    pub mail_x500: Vec<String>,
    pub mail_tenant: Option<String>,
    pub meeting_links: Vec<String>,
    pub contact_pii: Vec<String>,
    pub media_serial: Option<String>,
    pub zip_unsafe: Vec<String>,
    pub bad_redactions: Vec<String>,
    pub signers: Vec<SignerFacts>,
    pub hidden: Vec<String>,
    pub hidden_with_text: bool,
    pub removed_text: Vec<String>,
    pub revision_authors: Vec<String>,
    pub scan_without_text: bool,
    pub scan_suspicious_name: bool,
    pub connections: Vec<String>,
    /// A data connection kept a password (the value itself is never stored).
    pub connection_password: bool,
    /// PDB build paths that name a user (`C:\Users\<dev>\source\...`).
    pub pdb_paths: Vec<String>,
    /// Generative AI marker: generator and model.
    pub ai_image: Option<String>,
    /// Geodata points (KML/GPX), shown as `name: lat, lon`.
    pub geo: Vec<String>,
    pub geo_total: u64,
    /// Source map facts: embedded sources and build paths.
    pub sourcemap: Vec<String>,
    pub pii: Vec<PiiFound>,
    pub links: Vec<LinkHit>,
    pub rules: Vec<RuleFacts>,
}

impl Fx {
    /// `true` when the document has any 1.3 forensic signal (used for the document flag).
    pub fn any(&self) -> bool {
        !self.bad_redactions.is_empty()
            || !self.signers.is_empty()
            || !self.hidden.is_empty()
            || !self.removed_text.is_empty()
            || self.scan_without_text
    }
}

/// File names that make an image-only scan sensitive.
const SENSITIVE_SCAN_NAMES: &[&str] = &[
    "паспорт",
    "passport",
    "договір",
    "договор",
    "контракт",
    "contract",
    "наказ",
    "приказ",
    "посвідч",
    "свідоцтв",
    "свидетельств",
    "id-card",
    "id_card",
    "idcard",
    "диплом",
    "заява",
    "заявлен",
    "довіреніст",
    "доверенност",
    "рнокпп",
    "іпн",
    "инн",
];

fn split_list(v: &str) -> impl Iterator<Item = String> + '_ {
    v.split([',', ';', ' ', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

fn push_uniq(v: &mut Vec<String>, s: impl Into<String>) {
    let s = s.into();
    if !s.is_empty() && !v.contains(&s) && v.len() < 50 {
        v.push(s);
    }
}

fn clip(s: &str, n: usize) -> String {
    let t: String = s.chars().take(n).collect();
    if t.len() < s.len() {
        format!("{t}…")
    } else {
        t
    }
}

/// Days since 0000-03-01 of a `YYYY-MM-DD…` date (proleptic Gregorian), for date differences.
fn day_number(s: &str) -> Option<i64> {
    let y: i64 = s.get(0..4)?.parse().ok()?;
    let m: i64 = s.get(5..7)?.parse().ok()?;
    let d: i64 = s.get(8..10)?.parse().ok()?;
    if !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    let (y, m) = if m <= 2 { (y - 1, m + 9) } else { (y, m - 3) };
    Some(365 * y + y / 4 - y / 100 + y / 400 + (153 * m + 2) / 5 + d - 1)
}

fn internal_host(h: &str) -> bool {
    let h = h.trim().trim_end_matches('.').to_ascii_lowercase();
    !h.contains('.')
        || [
            ".local",
            ".lan",
            ".corp",
            ".internal",
            ".intra",
            ".test",
            ".localdomain",
            ".ad",
        ]
        .iter()
        .any(|s| h.ends_with(s))
        || crate::util::is_internal_fqdn(&h)
        || priv_ip(&h)
}

fn priv_ip(s: &str) -> bool {
    crate::util::parse_ip(s).is_some_and(crate::util::is_private_ip)
}

/// Collects the facts of `m` (and, recursively, of embedded children) into `fx`.
fn collect(m: &Metadata, fx: &mut Fx, via: &str, depth: u8) {
    let at = |s: String| {
        if via.is_empty() {
            s
        } else {
            format!("{via}: {s}")
        }
    };
    let f = &m.fields;
    // LNK.
    if let Some(v) = f.get("lnk:machine_id") {
        fx.lnk_machine.get_or_insert_with(|| v.clone());
    }
    for k in ["lnk:mac", "lnk:birth_mac"] {
        if let Some(v) = f.get(k) {
            push_uniq(&mut fx.lnk_mac, v.clone());
        }
    }
    if let Some(v) = f.get("lnk:volume_serial") {
        fx.lnk_volume.get_or_insert_with(|| v.clone());
    }
    for k in ["lnk:network_path", "lnk:network_share"] {
        if let Some(v) = f.get(k) {
            push_uniq(&mut fx.lnk_unc, v.clone());
        }
    }
    if let Some(v) = f.get("lnk:local_base_path") {
        fx.lnk_local.get_or_insert_with(|| v.clone());
    }
    // E-mail (EML/MSG share the derived keys under their own prefix).
    for p in ["eml", "msg"] {
        for k in ["internal_hosts", "internal_ips"] {
            if let Some(v) = f.get(&format!("{p}:{k}")) {
                for x in split_list(v) {
                    push_uniq(&mut fx.mail_internal, x);
                }
            }
        }
        if let Some(v) = f.get(&format!("{p}:originating_ips")) {
            for x in split_list(v) {
                if priv_ip(&x) {
                    fx.mail_origin_internal = true;
                }
                push_uniq(&mut fx.mail_origin_ips, x);
            }
        }
        if let Some(v) = f.get(&format!("{p}:message_id_domain")) {
            if internal_host(v) {
                fx.mail_msgid_domain.get_or_insert_with(|| v.clone());
            }
        }
        if f.get(&format!("{p}:reply_to_differs")).map(String::as_str) == Some("true") {
            let rt = f.get(&format!("{p}:reply-to")).cloned().unwrap_or_default();
            fx.mail_reply_to.get_or_insert(rt);
        }
        if let Some(v) = f.get(&format!("{p}:x-ms-exchange-crosstenant-id")) {
            fx.mail_tenant.get_or_insert_with(|| v.clone());
        }
    }
    for (k, v) in f
        .iter()
        .filter(|(k, _)| k.starts_with("msg:") && k.contains("x500"))
    {
        let _ = k;
        push_uniq(&mut fx.mail_x500, clip(v, 160));
    }
    // Calendar and contacts.
    if let Some(v) = f.get("ics:meeting_links") {
        for x in split_list(v) {
            // Links are shown through the link classifier so passwords in them are masked.
            let shown = links::classify(&x).map(|h| h.url).unwrap_or(x);
            push_uniq(&mut fx.meeting_links, shown);
        }
    }
    if m.format == DocFormat::Vcf {
        for (k, v) in f {
            let field = k.rsplit('.').next().unwrap_or("");
            if matches!(field, "tel" | "adr" | "bday") {
                // Values are personal: only masks reach findings and reports.
                let shown: Vec<String> = v.split(';').map(|x| pii::pii_mask(x.trim())).collect();
                push_uniq(
                    &mut fx.contact_pii,
                    at(format!("{field}: {}", shown.join("; "))),
                );
            }
        }
    }
    // Media device serial.
    if matches!(m.format, DocFormat::Mp4 | DocFormat::Mov | DocFormat::Heic) {
        if let Some(s) = m.camera.as_ref().and_then(|c| c.serial.clone()) {
            fx.media_serial.get_or_insert(s);
        }
    }
    // Archives.
    if let Some(v) = f.get("zip:unsafe_names") {
        for x in v
            .split(['\n', ';'])
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            push_uniq(&mut fx.zip_unsafe, at(clip(x, 120)));
        }
    }
    // Bad redactions, hidden content, revisions, scans.
    for r in &m.bad_redactions {
        push_uniq(
            &mut fx.bad_redactions,
            at(format!(
                "стр. {} ({}): «{}»",
                r.page,
                r.fill,
                clip(&r.text, 80)
            )),
        );
    }
    for h in &m.hidden_content {
        if !h.text.is_empty() {
            fx.hidden_with_text = true;
        }
        let what = match h.kind.as_str() {
            "vanish" => "скрытый текст",
            "row" => "скрытые строки",
            "column" => "скрытые столбцы",
            _ => "скрытое содержимое",
        };
        let txt = if h.text.is_empty() {
            String::new()
        } else {
            format!(": «{}»", clip(&h.text, 80))
        };
        push_uniq(&mut fx.hidden, at(format!("{what} {}{txt}", h.location)));
    }
    let mut authors: Vec<String> = Vec::new();
    for r in &m.pdf_revisions {
        for t in &r.removed_text {
            push_uniq(
                &mut fx.removed_text,
                at(format!("ревизия {}: «{}»", r.revision, clip(t, 100))),
            );
        }
        for a in [&r.author, &r.creator, &r.producer].into_iter().flatten() {
            push_uniq(&mut authors, a.clone());
        }
    }
    if m.pdf_revisions.len() >= 2 && authors.len() >= 2 {
        let per: Vec<String> = m
            .pdf_revisions
            .iter()
            .map(|r| {
                let who: Vec<&str> = [&r.author, &r.creator, &r.producer]
                    .into_iter()
                    .flatten()
                    .map(String::as_str)
                    .collect();
                format!("ревизия {}: {}", r.revision, who.join(" / "))
            })
            .collect();
        let distinct_people: std::collections::BTreeSet<_> = m
            .pdf_revisions
            .iter()
            .filter_map(|r| r.author.as_ref())
            .collect();
        let distinct_tools: std::collections::BTreeSet<_> = m
            .pdf_revisions
            .iter()
            .filter_map(|r| r.producer.as_ref().or(r.creator.as_ref()))
            .collect();
        if distinct_people.len() > 1 || distinct_tools.len() > 1 {
            for p in per {
                push_uniq(&mut fx.revision_authors, at(p));
            }
        }
    }
    if m.scan_without_text {
        fx.scan_without_text = true;
    }
    // Data connections (XLSX connections/pivot caches, Visio data, chart external refs).
    for (k, v) in f {
        let conn = (k.starts_with("xl:connection:")
            && (k.ends_with(":odcFile")
                || k.ends_with(":database")
                || k.ends_with(":user")
                || k.ends_with(":credentialsFile")))
            || (k.starts_with("xl:pivotCache")
                && (k.ends_with(":refreshedBy") || k.ends_with(":source")))
            || (k.starts_with("visio:data.")
                && (k.ends_with(".connection") || k.ends_with(".file")))
            || (k.starts_with("chart:") && k.ends_with(":externalRef"));
        if conn {
            push_uniq(&mut fx.connections, at(format!("{k}: {}", clip(v, 160))));
        }
    }
    for c in &m.connections {
        let mut parts: Vec<String> = Vec::new();
        for (k, v) in [
            ("server", &c.server),
            ("database", &c.database),
            ("user", &c.user),
            ("provider", &c.provider),
            ("target", &c.target),
        ] {
            if let Some(v) = v {
                parts.push(format!("{k}={}", clip(v, 120)));
            }
        }
        if c.has_password {
            fx.connection_password = true;
            parts.push("password=***".into());
        }
        let name = c.name.as_deref().unwrap_or(&c.kind);
        push_uniq(
            &mut fx.connections,
            at(format!(
                "{} ({}): {}",
                clip(name, 60),
                c.kind,
                parts.join("; ")
            )),
        );
    }
    // Build paths of executables.
    for p in m.paths.iter().filter(|p| p.source == "pe:pdb") {
        if p.user.is_some() {
            push_uniq(&mut fx.pdb_paths, at(clip(&p.path, 200)));
        }
    }
    if let Some(a) = &m.ai_generated {
        let what = [a.generator.as_deref(), a.model.as_deref()]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>()
            .join(" / ");
        fx.ai_image.get_or_insert_with(|| {
            at(if what.is_empty() {
                a.source.clone()
            } else {
                format!("{what} ({})", a.source)
            })
        });
    }
    if !m.geo_points.is_empty() {
        fx.geo_total += m
            .stats
            .get("geo_points")
            .copied()
            .unwrap_or(m.geo_points.len() as u64);
        for g in m.geo_points.iter().take(5) {
            let name = g.name.as_deref().unwrap_or("-");
            push_uniq(
                &mut fx.geo,
                at(format!("{}: {:.5}, {:.5}", clip(name, 60), g.lat, g.lon)),
            );
        }
    }
    if m.format == DocFormat::SourceMap {
        if let Some(n) = m.stats.get("sources_content") {
            push_uniq(&mut fx.sourcemap, format!("sourcesContent: {n}"));
        }
        for p in m.paths.iter().filter(|p| p.source == "sourcemap:sources") {
            push_uniq(&mut fx.sourcemap, clip(&p.path, 200));
        }
    }
    // Signatures and qualified certificates.
    let last = m.signatures.len().saturating_sub(1);
    for (i, s) in m.signatures.iter().enumerate() {
        let c = s.signer.clone().unwrap_or_default();
        let name = c
            .common_name
            .clone()
            .or_else(|| match (&c.given_name, &c.surname) {
                (Some(g), Some(sn)) => Some(format!("{g} {sn}")),
                _ => None,
            })
            .unwrap_or_else(|| s.name.clone().unwrap_or_default());
        let tsa_time = s.timestamp.as_ref().and_then(|t| t.gen_time.clone());
        let gap = match (s.signing_time.as_deref(), tsa_time.as_deref()) {
            (Some(a), Some(b)) => match (day_number(a), day_number(b)) {
                (Some(x), Some(y)) => Some((x - y).abs()),
                _ => None,
            },
            _ => None,
        };
        fx.signers.push(SignerFacts {
            kind: match s.kind {
                foca_core::SignatureKind::Pdf => "pdf".into(),
                foca_core::SignatureKind::Ooxml => "ooxml".into(),
                foca_core::SignatureKind::Vba => "vba".into(),
                foca_core::SignatureKind::Authenticode => "authenticode".into(),
                foca_core::SignatureKind::Jar => "jar".into(),
            },
            name,
            org: c.organization.clone(),
            edrpou: c.edrpou.clone(),
            rnokpp_masked: c.rnokpp_masked.clone(),
            title: c.title.clone(),
            email: c.email.clone(),
            issuer: c
                .issuer_cn
                .clone()
                .or(Some(c.issuer.clone()).filter(|x| !x.is_empty())),
            signing_time: s.signing_time.clone(),
            tsa_time,
            tsa: s.timestamp.as_ref().and_then(|t| t.tsa.clone()),
            // Only the last signature being followed by edits matters; earlier signatures
            // are naturally followed by later ones.
            modified_after: s.modified_after_signing && (i == last || via.is_empty()),
            digest_invalid: s.digest_valid == Some(false),
            tsa_gap_days: gap,
        });
        if s.modified_after_signing && i != last {
            if let Some(x) = fx.signers.last_mut() {
                x.modified_after = false;
            }
        }
    }
    if depth < 3 {
        for e in &m.embedded {
            let label = if via.is_empty() {
                e.name.clone()
            } else {
                format!("{via} → {}", e.name)
            };
            collect(&e.metadata, fx, &label, depth + 1);
        }
    }
}

/// Builds the forensic facts of a document. `text` is the stored (PII-masked) text.
pub fn facts(m: &Metadata, name: &str, text: Option<&str>, rules: Option<&RuleSet>) -> Fx {
    let mut fx = Fx::default();
    collect(m, &mut fx, "", 0);
    if fx.scan_without_text {
        let n = name.to_lowercase();
        fx.scan_suspicious_name = SENSITIVE_SCAN_NAMES.iter().any(|w| n.contains(w));
    }
    // Personal data: the summary from storage, or (documents analysed straight from bytes,
    // e.g. the CLI) a scan of the text and metadata now.
    fx.pii = if m.pii.is_empty() {
        pii::sanitize(m, text).0.pii
    } else {
        m.pii.clone()
    };
    // Links: text plus metadata links.
    let mut lk: Vec<LinkHit> = text.map(links::interesting).unwrap_or_default();
    for l in &m.links {
        if let Some(h) = links::classify(l) {
            if (h.service.is_some() || !h.tokens.is_empty() || h.internal)
                && !lk.iter().any(|x| x.url == h.url)
            {
                lk.push(h);
            }
        }
    }
    // Plain internal links without a service or a token are already covered by the
    // internal hosts findings.
    lk.retain(|h| h.service.is_some() || !h.tokens.is_empty());
    lk.truncate(50);
    fx.links = lk;
    // User rules.
    if let (Some(rs), Some(t)) = (rules.filter(|r| !r.is_empty()), text) {
        for h in rs.scan(t, "текст") {
            let shown = if h.masked {
                pii::pii_mask(h.value.expose())
            } else {
                clip(h.value.expose(), 80)
            };
            let i = match fx.rules.iter().position(|r| r.rule == h.rule) {
                Some(i) => i,
                None => {
                    fx.rules.push(RuleFacts {
                        rule: h.rule.clone(),
                        title: h.title.clone(),
                        sev: h.sev,
                        ..Default::default()
                    });
                    fx.rules.len() - 1
                }
            };
            let r = &mut fx.rules[i];
            r.count += 1;
            if r.samples.len() < 5 {
                push_uniq(&mut r.samples, format!("{}: {shown}", h.location));
            }
        }
    }
    fx
}

fn base(rule: &'static str, d: &DocFacts, title: String, sev: Severity) -> Draft {
    let mut f = Draft::new(rule, d.key.clone(), title, sev);
    f.source = "Форензика документов";
    f.module = "forensics";
    f.docs = vec![d.id];
    f.people = d.people.clone();
    f
}

fn sig_line(s: &SignerFacts) -> String {
    let mut parts = vec![format!("Подписант: {}", s.name)];
    if let Some(o) = &s.org {
        parts.push(format!("Организация: {o}"));
    }
    if let Some(e) = &s.edrpou {
        parts.push(format!("ЄДРПОУ: {e}"));
    }
    if let Some(t) = &s.title {
        parts.push(format!("Должность: {t}"));
    }
    if let Some(e) = &s.email {
        parts.push(format!("E-mail: {e}"));
    }
    if let Some(r) = &s.rnokpp_masked {
        parts.push(format!("РНОКПП: {r}"));
    }
    if let Some(i) = &s.issuer {
        parts.push(format!("АЦСК: {i}"));
    }
    if let Some(t) = &s.signing_time {
        parts.push(format!("Время подписи: {t}"));
    }
    if let Some(t) = &s.tsa_time {
        parts.push(format!("Метка TSA: {t}"));
    }
    parts.join("\n")
}

/// Adds the forensic findings of the analysed documents.
pub(crate) fn drafts(an: &[&DocFacts], out: &mut Vec<Draft>) {
    for d in an {
        let x = &d.fx;
        if !x.bad_redactions.is_empty() {
            let mut f = base(
                "doc.bad_redaction",
                d,
                format!(
                    "Плохое замазывание: текст под закраской читается ({})",
                    d.name
                ),
                Severity::Critical,
            );
            f.mitre = "T1213 · Data from Information Repositories";
            f.cvss = Some(7.5);
            f.description = "Конфиденциальный фрагмент закрыт чёрным или белым прямоугольником поверх текста, но сам текст остался в документе: его можно скопировать или извлечь любой программой просмотра PDF.".into();
            f.recommendation = "Удалить документ с сайта; замазывать средствами настоящего редактирования (Redact → Apply), затем пересохранять PDF и проверять копированием текста.";
            f.evidence = x
                .bad_redactions
                .iter()
                .take(6)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            f.fields = vec!["bad_redactions".into()];
            f.tags = vec!["forensics"];
            out.push(f);
        }
        if let Some(s) = x.signers.iter().find(|s| s.modified_after) {
            let mut f = base(
                "doc.modified_after_signing",
                d,
                format!("Документ изменён после подписания ({})", d.name),
                Severity::High,
            );
            f.mitre = "T1565.001 · Data Manipulation: Stored Data Manipulation";
            f.description = "После байтов, покрытых подписью (/ByteRange), в файл дописаны изменения: видимое содержимое может отличаться от подписанного.".into();
            f.recommendation = "Сверить документ с подписанным оригиналом; публиковать только неизменённую подписанную версию.";
            f.evidence = sig_line(s);
            f.fields = vec!["signatures".into()];
            out.push(f);
        }
        if x.signers.iter().any(|s| s.digest_invalid) {
            let mut f = base(
                "doc.signature_digest_mismatch",
                d,
                format!("Хеш подписи не совпадает с содержимым ({})", d.name),
                Severity::High,
            );
            f.mitre = "T1565.001 · Data Manipulation: Stored Data Manipulation";
            f.description = "Хеш подписанных данных в подписи не совпадает с фактическим содержимым: документ повреждён или изменён после подписания.".into();
            f.recommendation = "Не доверять подписи; запросить оригинал у подписанта.";
            f.evidence = x
                .signers
                .iter()
                .filter(|s| s.digest_invalid)
                .map(sig_line)
                .collect::<Vec<_>>()
                .join("\n");
            f.fields = vec!["signatures".into()];
            out.push(f);
        }
        let named: Vec<&SignerFacts> = x.signers.iter().filter(|s| !s.name.is_empty()).collect();
        if !named.is_empty() {
            let personal = named
                .iter()
                .any(|s| s.rnokpp_masked.is_some() || s.email.is_some() || s.title.is_some());
            let mut f = base(
                "doc.signer_identity",
                d,
                format!(
                    "Данные подписанта (КЕП) в документе {}: {}",
                    d.name, named[0].name
                ),
                if personal {
                    Severity::Medium
                } else {
                    Severity::Info
                },
            );
            f.category = "people";
            f.mitre = "T1589.001 · Gather Victim Identity Information: Credentials";
            f.description = "Сертификат подписи раскрывает ФИО, должность, организацию и центр сертификации подписанта; для украинского КЕП: коды ЄДРПОУ и РНОКПП (РНОКПП хранится только маскированным).".into();
            f.recommendation = "Учитывать, что подписанные документы раскрывают данные сертификата; для публикации использовать печать организации или отдельную публичную подпись.";
            f.evidence = named
                .iter()
                .take(5)
                .map(|s| sig_line(s))
                .collect::<Vec<_>>()
                .join("\n");
            f.fields = vec!["signatures".into()];
            f.tags = vec!["qes"];
            out.push(f);
        }
        if let Some(s) = x
            .signers
            .iter()
            .find(|s| s.tsa_gap_days.is_some_and(|g| g > 1))
        {
            let mut f = base(
                "doc.signature_tsa_gap",
                d,
                format!(
                    "Время подписи и метка TSA расходятся более чем на сутки ({})",
                    d.name
                ),
                Severity::Low,
            );
            f.description = "Заявленное время подписания заметно отличается от времени метки доверенного сервиса (TSA): часы подписанта неверны или дата подписи указана задним числом.".into();
            f.recommendation = "Проверить дату подписания по метке времени TSA.";
            f.evidence = sig_line(s);
            f.fields = vec!["signatures".into()];
            out.push(f);
        }
        if !x.hidden.is_empty() {
            let mut f = base(
                "doc.hidden_content",
                d,
                format!("Скрытый текст и скрытые строки/столбцы в {}", d.name),
                if x.hidden_with_text {
                    Severity::High
                } else {
                    Severity::Medium
                },
            );
            f.mitre = "T1213 · Data from Information Repositories";
            f.description = "Документ содержит скрытое форматирование (w:vanish) или скрытые строки и столбцы таблицы: при просмотре их не видно, но данные остаются в файле.".into();
            f.recommendation = "Удалять, а не скрывать служебные данные; проверять документ Инспектором документов перед публикацией.";
            f.evidence = x
                .hidden
                .iter()
                .take(6)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            f.fields = vec!["hidden_content".into()];
            out.push(f);
        }
        if !x.removed_text.is_empty() {
            let mut f = base(
                "doc.pdf_removed_text",
                d,
                format!(
                    "Удалённый текст восстанавливается из старых ревизий PDF ({})",
                    d.name
                ),
                Severity::High,
            );
            f.mitre = "T1213 · Data from Information Repositories";
            f.description = "PDF сохранён инкрементально: в предыдущих ревизиях остался текст, удалённый из последней версии.".into();
            f.recommendation = "Пересохранить PDF полностью (без инкрементальных обновлений) и заменить опубликованный файл.";
            f.evidence = x
                .removed_text
                .iter()
                .take(6)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            f.fields = vec!["pdf_revisions".into()];
            out.push(f);
        }
        if !x.revision_authors.is_empty() {
            let mut f = base(
                "doc.pdf_revision_authors",
                d,
                format!("Разные авторы или программы в ревизиях PDF ({})", d.name),
                Severity::Medium,
            );
            f.description = "Ревизии PDF сохранены разными людьми или программами: видна цепочка согласования и использованное ПО.".into();
            f.recommendation = "Пересохранять итоговый PDF полностью перед публикацией.";
            f.evidence = x
                .revision_authors
                .iter()
                .take(8)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            f.fields = vec!["pdf_revisions".into()];
            out.push(f);
        }
        if x.scan_without_text {
            let mut f = base(
                "doc.scan_without_text",
                d,
                format!("Скан без текстового слоя: {}", d.name),
                if x.scan_suspicious_name {
                    Severity::High
                } else {
                    Severity::Medium
                },
            );
            f.description = if x.scan_suspicious_name {
                "Документ состоит только из изображений страниц, а имя файла указывает на личный или служебный документ (паспорт, договор, приказ): содержимое не проверяется поиском и DLP.".into()
            } else {
                "Документ состоит только из изображений страниц: его содержимое не проверяется поиском, DLP и этим анализом.".into()
            };
            f.recommendation = "Проверить скан вручную; не публиковать сканы личных документов.";
            f.evidence = d.name.clone();
            f.fields = vec!["scan_without_text".into()];
            out.push(f);
        }
        if !x.connections.is_empty() {
            let mut f = base(
                "doc.data_connection",
                d,
                format!("Внешние источники данных в {}", d.name),
                Severity::Medium,
            );
            if x.connection_password {
                f.sev = Severity::High;
            }
            f.mitre = "T1590 · Gather Victim Network Information";
            f.description = "Подключения к базам данных, файлы .odc, сводные таблицы и внешние ссылки диаграмм раскрывают серверы, базы, учётные записи и пути к файлам.".into();
            f.recommendation = "Удалять подключения к данным и кэши сводных таблиц перед публикацией (вставлять значения).";
            f.evidence = x
                .connections
                .iter()
                .take(6)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            f.fields = vec!["connections".into()];
            out.push(f);
        }
        if !x.pdb_paths.is_empty() {
            let mut f = base(
                "doc.pdb_user",
                d,
                format!("Имя разработчика в пути сборки (PDB) ({})", d.name),
                Severity::Medium,
            );
            f.mitre = "T1589.003 · Gather Victim Identity Information: Employee Names";
            f.description = "Исполняемый файл хранит путь к отладочным символам PDB с папкой пользователя: раскрываются логин разработчика, структура проектов и сборочная машина.".into();
            f.recommendation = "Собирать релизы на сборочном сервере с нейтральными путями (/pathmap, -fdebug-prefix-map) или без пути PDB.";
            f.evidence = x.pdb_paths.join("\n");
            f.fields = vec!["paths".into()];
            out.push(f);
        }
        if let Some(a) = &x.ai_image {
            let mut f = base(
                "doc.ai_generated",
                d,
                format!("Изображение создано генеративной нейросетью ({})", d.name),
                Severity::Low,
            );
            f.description = "В метаданных изображения остались параметры генерации или отметка C2PA о синтетическом содержимом: видно, что картинка не фотография, и какой сервис или модель её создали.".into();
            f.recommendation = "Отмечать сгенерированные изображения явно; удалять параметры генерации (промпт, модель) перед публикацией.";
            f.evidence = a.clone();
            f.fields = vec!["ai_generated".into()];
            out.push(f);
        }
        if !x.geo.is_empty() {
            let mut f = base(
                "doc.geodata",
                d,
                format!("Координаты в файле геоданных ({})", d.name),
                Severity::Medium,
            );
            f.mitre = "T1591.001 · Gather Victim Org Information: Determine Physical Locations";
            f.description = "Файл геоданных (KML/GPX) содержит координаты точек и треков, часто с именами и временем: раскрываются объекты, маршруты и места работы.".into();
            f.recommendation = "Проверить, какие точки и треки допустимо публиковать; удалить служебные объекты и время.";
            f.evidence = x.geo.join("\n");
            f.fields = vec!["geo_points".into()];
            out.push(f);
        }
        if !x.sourcemap.is_empty() {
            let mut f = base(
                "doc.sourcemap",
                d,
                format!(
                    "Карта исходников раскрывает исходный код и пути сборки ({})",
                    d.name
                ),
                Severity::Medium,
            );
            f.mitre = "T1592.002 · Gather Victim Host Information: Software";
            f.description = "Опубликованная карта исходников (.map) перечисляет исходные файлы проекта, иногда вместе с их полным текстом и путями на машине разработчика.".into();
            f.recommendation = "Не выкладывать .map в продуктив или закрыть к ним доступ; собирать без sourcesContent и абсолютных путей.";
            f.evidence = x
                .sourcemap
                .iter()
                .take(8)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            f.fields = vec!["paths".into()];
            out.push(f);
        }
        if x.lnk_machine.is_some() || !x.lnk_mac.is_empty() {
            let mut f = base(
                "doc.lnk_host_mac",
                d,
                format!(
                    "Ярлык LNK раскрывает имя компьютера и MAC-адрес ({})",
                    d.name
                ),
                Severity::High,
            );
            f.mitre = "T1592.001 · Gather Victim Host Information: Hardware";
            f.description = "Ярлык Windows хранит NetBIOS-имя компьютера, MAC-адрес сетевой карты и серийный номер тома, на котором он создан.".into();
            f.recommendation = "Не публиковать ярлыки .lnk; удалить файл с сайта.";
            let mut ev = Vec::new();
            if let Some(m) = &x.lnk_machine {
                ev.push(format!("Компьютер: {m}"));
            }
            if !x.lnk_mac.is_empty() {
                ev.push(format!("MAC: {}", x.lnk_mac.join(", ")));
            }
            if let Some(v) = &x.lnk_volume {
                ev.push(format!("Серийный номер тома: {v}"));
            }
            if let Some(p) = &x.lnk_local {
                ev.push(format!("Путь: {p}"));
            }
            f.evidence = ev.join("\n");
            f.pcs = x.lnk_machine.iter().cloned().collect();
            f.fields = vec!["lnk".into()];
            out.push(f);
        }
        if !x.lnk_unc.is_empty() {
            let mut f = base(
                "doc.lnk_unc_path",
                d,
                format!("Ярлык LNK указывает на сетевой ресурс ({})", d.name),
                Severity::Medium,
            );
            f.mitre = "T1135 · Network Share Discovery";
            f.description = "Ярлык ссылается на файл на сетевом ресурсе: раскрываются имя файлового сервера и структура папок.".into();
            f.recommendation = "Не публиковать ярлыки .lnk.";
            f.evidence = x.lnk_unc.join("\n");
            f.fields = vec!["lnk".into()];
            out.push(f);
        }
        if !x.mail_internal.is_empty() {
            let mut f = base(
                "mail.internal_relay",
                d,
                format!(
                    "Внутренние почтовые серверы и адреса в заголовках письма ({})",
                    d.name
                ),
                Severity::High,
            );
            f.mitre = "T1590.005 · Gather Victim Network Information: IP Addresses";
            f.description = "Цепочка Received раскрывает внутренние почтовые релеи, рабочие станции и их частные IP-адреса.".into();
            f.recommendation = "Удалять внутренние заголовки Received на пограничном почтовом шлюзе; не публиковать исходные письма.";
            f.evidence = x
                .mail_internal
                .iter()
                .take(10)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            f.pcs = x
                .mail_internal
                .iter()
                .filter(|h| !h.contains('.'))
                .cloned()
                .collect();
            f.fields = vec!["received".into()];
            out.push(f);
        }
        if !x.mail_origin_ips.is_empty() {
            let mut f = base(
                "mail.originating_ip",
                d,
                format!("IP-адрес отправителя в заголовках письма ({})", d.name),
                if x.mail_origin_internal {
                    Severity::High
                } else {
                    Severity::Medium
                },
            );
            f.description =
                "Заголовок X-Originating-IP раскрывает адрес рабочей станции отправителя.".into();
            f.recommendation = "Отключить добавление X-Originating-IP на почтовом сервере.";
            f.evidence = x.mail_origin_ips.join(", ");
            f.fields = vec!["x-originating-ip".into()];
            out.push(f);
        }
        if let Some(dom) = &x.mail_msgid_domain {
            let mut f = base(
                "mail.internal_domain",
                d,
                format!("Внутренний домен в Message-ID ({})", d.name),
                Severity::Medium,
            );
            f.description = "Идентификатор письма содержит внутреннее имя почтового сервера или домена Active Directory.".into();
            f.recommendation = "Настроить почтовый сервер на внешнее имя в Message-ID.";
            f.evidence = dom.clone();
            f.fields = vec!["message-id".into()];
            out.push(f);
        }
        if let Some(rt) = &x.mail_reply_to {
            let mut f = base(
                "mail.reply_to_mismatch",
                d,
                format!("Reply-To отличается от отправителя ({})", d.name),
                Severity::Medium,
            );
            f.mitre = "T1566 · Phishing";
            f.description = "Ответы на письмо уходят на другой адрес, чем адрес отправителя: типичный признак фишинга или личного ящика сотрудника.".into();
            f.recommendation =
                "Проверить адрес Reply-To; не использовать личные ящики для служебной переписки.";
            f.evidence = rt.clone();
            f.fields = vec!["reply-to".into()];
            out.push(f);
        }
        if !x.mail_x500.is_empty() {
            let mut f = base(
                "mail.exchange_x500",
                d,
                format!("Структура Exchange (X.500) в письме ({})", d.name),
                Severity::Medium,
            );
            f.description = "Адреса X.500 Exchange раскрывают название организации, административной группы и учётные записи.".into();
            f.recommendation = "Не публиковать исходные файлы .msg.";
            f.evidence = x
                .mail_x500
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            f.fields = vec!["x500".into()];
            out.push(f);
        }
        if let Some(t) = &x.mail_tenant {
            let mut f = base(
                "mail.m365_tenant",
                d,
                format!(
                    "Идентификатор арендатора Microsoft 365 в письме ({})",
                    d.name
                ),
                Severity::Low,
            );
            f.description =
                "Заголовки письма содержат идентификатор арендатора Microsoft 365 организации."
                    .into();
            f.recommendation = "Учитывать при оценке поверхности атаки облачной инфраструктуры.";
            f.evidence = t.clone();
            f.fields = vec!["x-ms-exchange-crosstenant-id".into()];
            out.push(f);
        }
        if !x.meeting_links.is_empty() {
            let mut f = base(
                "cal.meeting_link",
                d,
                format!("Ссылки на онлайн-встречи в календаре ({})", d.name),
                Severity::Medium,
            );
            f.description = "Приглашение содержит ссылки подключения к Teams/Zoom (иногда с паролем): посторонний может войти на встречу.".into();
            f.recommendation = "Не публиковать приглашения; включить зал ожидания и пароли встреч.";
            f.evidence = x
                .meeting_links
                .iter()
                .take(5)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            f.fields = vec!["meeting_links".into()];
            out.push(f);
        }
        if !x.contact_pii.is_empty() {
            let mut f = base(
                "pim.contact_pii",
                d,
                format!("Личные контакты в визитных карточках ({})", d.name),
                Severity::Medium,
            );
            f.category = "people";
            f.description = "Файл контактов содержит телефоны, адреса и даты рождения (значения в базе маскированы).".into();
            f.recommendation = "Не публиковать файлы контактов .vcf.";
            f.evidence = x
                .contact_pii
                .iter()
                .take(6)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n");
            f.fields = vec!["vcf".into()];
            out.push(f);
        }
        if let Some(s) = &x.media_serial {
            let mut f = base(
                "media.device_serial",
                d,
                format!("Серийный номер устройства в медиафайле ({})", d.name),
                Severity::Medium,
            );
            f.mitre = "T1592.001 · Gather Victim Host Information: Hardware";
            f.description = "Видео или фото содержит серийный номер камеры/телефона: по нему связываются другие публикации с того же устройства.".into();
            f.recommendation = "Удалять метаданные медиафайлов перед публикацией.";
            f.evidence = s.clone();
            f.fields = vec!["camera".into()];
            out.push(f);
        }
        if !x.zip_unsafe.is_empty() {
            let mut f = base(
                "zip.path_traversal",
                d,
                format!("Архив с опасными путями (Zip-Slip): {}", d.name),
                Severity::High,
            );
            f.mitre = "T1204.002 · User Execution: Malicious File";
            f.description = "Имена файлов в архиве выходят за пределы папки распаковки (../, абсолютные пути): архив враждебен или повреждён.".into();
            f.recommendation = "Не распаковывать архив; проверить источник файла.";
            f.evidence = x.zip_unsafe.join("\n");
            f.fields = vec!["zip:unsafe_names".into()];
            out.push(f);
        }
        for p in &x.pii {
            let kind = p.kind.as_str();
            let title = match kind {
                "rnokpp" => "РНОКПП (ІПН) физлица в документе",
                "edrpou" => "Код ЄДРПОУ в документе",
                "iban" => "Номер счёта IBAN в документе",
                "card" => "Номер банковской карты в документе",
                "passport" => "Серия и номер паспорта в документе",
                "id_card" => "Номер ID-карты в документе",
                "phone" => "Номер телефона в документе",
                "marking" => "Гриф ограничения доступа в документе",
                _ => continue,
            };
            let mut f = Draft::new(
                "pii",
                format!("{}|{kind}", d.key),
                format!("{title} ({})", d.name),
                p.sev,
            );
            f.source = "Персональные данные";
            f.module = "pii";
            f.category = if kind == "marking" { "docs" } else { "people" };
            f.mitre = "T1213 · Data from Information Repositories";
            f.description = if kind == "marking" {
                "Документ с грифом ограничения доступа опубликован в открытом доступе.".into()
            } else {
                format!(
                    "В документе найдено значений: {}. Значения проверены по контрольным суммам, где это возможно; в базе и отчёте хранятся только маски.",
                    p.count
                )
            };
            f.recommendation = if kind == "marking" {
                "Удалить документ из открытого доступа и проверить процедуру публикации документов с грифом."
            } else {
                "Удалить персональные данные из публикуемого документа (обезличить) или убрать документ; оценить уведомление владельцев данных."
            };
            let mut ev: Vec<String> = p.samples.clone();
            if !p.details.is_empty() {
                ev.push(p.details.join(", "));
            }
            f.evidence = ev.join("\n");
            f.docs = vec![d.id];
            f.fields = vec![p.location.clone()];
            f.tags = vec!["pii"];
            out.push(f);
        }
        if !x.links.is_empty() {
            let sev = x.links.iter().map(|l| l.sev).min().unwrap_or(Severity::Low);
            let mut f = base(
                "doc.links",
                d,
                format!(
                    "Ссылки на облачные пространства и URL с токенами в {}",
                    d.name
                ),
                sev,
            );
            f.mitre = "T1213.003 · Data from Information Repositories: Code Repositories";
            f.description = "Документ ссылается на облачные рабочие пространства (Google Drive, SharePoint, Notion, Trello, Jira…) или содержит URL со встроенными токенами доступа (токены маскированы).".into();
            f.recommendation = "Проверить права доступа по ссылкам, отозвать токены и SAS-ссылки, закрыть публичный доступ к рабочим пространствам.";
            f.evidence = x
                .links
                .iter()
                .take(8)
                .map(|l| match l.service {
                    Some(s) => format!("{}: {}", s.label(), l.url),
                    None => l.url.clone(),
                })
                .collect::<Vec<_>>()
                .join("\n");
            f.fields = vec!["links".into()];
            out.push(f);
        }
        for r in &x.rules {
            let mut f = Draft::new(
                "doc.user_rule",
                format!("{}|{}", d.key, r.rule),
                format!("Правило «{}»: совпадения в {}", r.title, d.name),
                r.sev,
            );
            f.source = "Правила поиска";
            f.module = "rules";
            f.description = format!(
                "Пользовательское правило поиска сработало в документе (совпадений: {}).",
                r.count
            );
            f.recommendation =
                "Проверить совпадения и при необходимости удалить данные из документа.";
            f.evidence = r.samples.join("\n");
            f.docs = vec![d.id];
            f.fields = vec![r.rule.clone()];
            out.push(f);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn day_difference() {
        let a = day_number("2024-03-01T10:00:00Z").unwrap();
        let b = day_number("2024-02-28").unwrap();
        assert_eq!(a - b, 2);
    }

    #[test]
    fn suspicious_scan_name() {
        let mut m = Metadata::new(DocFormat::Pdf);
        m.scan_without_text = true;
        assert!(facts(&m, "Паспорт_Петренко.pdf", None, None).scan_suspicious_name);
        assert!(!facts(&m, "brochure.pdf", None, None).scan_suspicious_name);
    }
}
