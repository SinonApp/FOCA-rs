//! Report strings in Russian, Ukrainian and English loaded from
//! `locales/{en,ru,uk}/report.json` (headings, labels, severity terms, diagrams, templates,
//! forensics, ports and Chain of Custody).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use foca_core::{FindingStatus, Severity};
use serde::Deserialize;

use crate::opts::Lang;

pub(crate) fn leak(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

fn leak_arr<const N: usize>(v: [String; N]) -> [&'static str; N] {
    v.map(leak)
}

macro_rules! static_str_struct {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $($fvis:vis $field:ident),+ $(,)?
        }
    ) => {
        $(#[$meta])*
        $vis struct $name {
            $($fvis $field: &'static str,)+
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                #[derive(Deserialize)]
                struct Raw {
                    $($field: String,)+
                }
                let r = Raw::deserialize(d)?;
                Ok(Self {
                    $($field: leak(r.$field),)+
                })
            }
        }
    };
}

/// Strings of one language.
#[derive(Debug, Clone, Copy)]
pub struct Strings {
    pub title: &'static str,
    pub conf: &'static str,
    pub project: &'static str,
    pub client: &'static str,
    pub by: &'static str,
    pub date: &'static str,
    pub tz: &'static str,
    pub page: &'static str,
    pub toc: &'static str,
    // Sections.
    pub summary: &'static str,
    pub period: &'static str,
    pub scope: &'static str,
    pub findings: &'static str,
    pub fixed: &'static str,
    pub people: &'static str,
    pub infra: &'static str,
    pub docs: &'static str,
    pub log: &'static str,
    pub appx: &'static str,
    // Executive summary.
    pub risk: &'static str,
    pub risk_by: &'static str,
    pub by_sev: &'static str,
    pub docs_by_type: &'static str,
    pub top_people: &'static str,
    pub top_software: &'static str,
    pub host_software: &'static str,
    pub eol_software: &'static str,
    pub infra_found: &'static str,
    /// The "found on site" subsection (forgotten file findings from the `fuzz` module).
    pub site_found: &'static str,
    pub none: &'static str,
    pub no_data: &'static str,
    pub oos_caveat: &'static str,
    pub log_shown: &'static str,
    pub summary_text_n: &'static str,
    pub summary_text_c: &'static str,
    pub summary_fixed: &'static str,
    pub summary_top: &'static str,
    pub summary_crit_advice: &'static str,
    // Scope.
    pub targets: &'static str,
    pub excl: &'static str,
    pub contact: &'static str,
    pub basis: &'static str,
    pub yes: &'static str,
    pub no: &'static str,
    pub kind: &'static str,
    pub active: &'static str,
    // Findings.
    pub sev: &'static str,
    pub status: &'static str,
    pub host: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub evidence: &'static str,
    pub recommendation: &'static str,
    pub mitre: &'static str,
    pub provenance: &'static str,
    pub rule: &'static str,
    pub fields: &'static str,
    pub source_docs: &'static str,
    pub first_seen: &'static str,
    pub fixed_in: &'static str,
    pub notes: &'static str,
    pub url: &'static str,
    pub active_module: &'static str,
    pub finding: &'static str,
    pub secret: &'static str,
    pub hidden: &'static str,
    // Tables.
    pub login: &'static str,
    pub name: &'static str,
    /// Document title column.
    pub doc_title: &'static str,
    pub role: &'static str,
    pub pc: &'static str,
    pub emails: &'static str,
    pub n_docs: &'static str,
    pub n_hosts: &'static str,
    pub service_acc: &'static str,
    pub address: &'static str,
    pub found_in_docs: &'static str,
    pub pattern: &'static str,
    pub hosts: &'static str,
    pub ip: &'static str,
    pub tech: &'static str,
    pub services: &'static str,
    pub internal: &'static str,
    pub scope_col: &'static str,
    pub pcs: &'static str,
    pub users: &'static str,
    pub software: &'static str,
    pub version: &'static str,
    pub eol: &'static str,
    pub cve: &'static str,
    pub paths: &'static str,
    pub path: &'static str,
    pub printers: &'static str,
    pub file: &'static str,
    pub author: &'static str,
    pub created: &'static str,
    pub modified: &'static str,
    pub flags: &'static str,
    pub size_kb: &'static str,
    // Request log.
    pub log_total: &'static str,
    pub log_passive: &'static str,
    pub log_active: &'static str,
    pub log_blocked: &'static str,
    pub log_hosts_target: &'static str,
    pub log_hosts_third: &'static str,
    pub log_by_module: &'static str,
    pub log_active_list: &'static str,
    pub log_blocked_list: &'static str,
    pub log_empty: &'static str,
    pub time: &'static str,
    pub method: &'static str,
    pub code: &'static str,
    pub module: &'static str,
    pub error: &'static str,
    pub size_type: &'static str,
    pub count: &'static str,
    // Appendices.
    pub scans: &'static str,
    pub profile: &'static str,
    pub started: &'static str,
    pub finished: &'static str,
    pub egress: &'static str,
    pub report_params: &'static str,
    pub filters: &'static str,
    pub only_confirmed: &'static str,
    pub min_sev: &'static str,
    pub picked_only: &'static str,
    pub secrets_mode: &'static str,
    pub method_title: &'static str,
    pub method_text: &'static str,
    pub generator: &'static str,
    pub all: &'static str,
    pub secret_modes: [&'static str; 3],
    /// `crit`, `high`, `mid`, `low`, `none`.
    pub risk_levels: [&'static str; 5],
    pub incomplete_banner_title: &'static str,
    pub incomplete_banner_body: &'static str,
}

impl<'de> Deserialize<'de> for Strings {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            title: String,
            conf: String,
            project: String,
            client: String,
            by: String,
            date: String,
            tz: String,
            page: String,
            toc: String,
            summary: String,
            period: String,
            scope: String,
            findings: String,
            fixed: String,
            people: String,
            infra: String,
            docs: String,
            log: String,
            appx: String,
            risk: String,
            risk_by: String,
            by_sev: String,
            docs_by_type: String,
            top_people: String,
            top_software: String,
            host_software: String,
            eol_software: String,
            infra_found: String,
            site_found: String,
            none: String,
            no_data: String,
            oos_caveat: String,
            log_shown: String,
            summary_text_n: String,
            summary_text_c: String,
            summary_fixed: String,
            summary_top: String,
            summary_crit_advice: String,
            targets: String,
            excl: String,
            contact: String,
            basis: String,
            yes: String,
            no: String,
            kind: String,
            active: String,
            sev: String,
            status: String,
            host: String,
            category: String,
            description: String,
            evidence: String,
            recommendation: String,
            mitre: String,
            provenance: String,
            rule: String,
            fields: String,
            source_docs: String,
            first_seen: String,
            fixed_in: String,
            notes: String,
            url: String,
            active_module: String,
            finding: String,
            secret: String,
            hidden: String,
            login: String,
            name: String,
            doc_title: String,
            role: String,
            pc: String,
            emails: String,
            n_docs: String,
            n_hosts: String,
            service_acc: String,
            address: String,
            found_in_docs: String,
            pattern: String,
            hosts: String,
            ip: String,
            tech: String,
            services: String,
            internal: String,
            scope_col: String,
            pcs: String,
            users: String,
            software: String,
            version: String,
            eol: String,
            cve: String,
            paths: String,
            path: String,
            printers: String,
            file: String,
            author: String,
            created: String,
            modified: String,
            flags: String,
            size_kb: String,
            log_total: String,
            log_passive: String,
            log_active: String,
            log_blocked: String,
            log_hosts_target: String,
            log_hosts_third: String,
            log_by_module: String,
            log_active_list: String,
            log_blocked_list: String,
            log_empty: String,
            time: String,
            method: String,
            code: String,
            module: String,
            error: String,
            size_type: String,
            count: String,
            scans: String,
            profile: String,
            started: String,
            finished: String,
            egress: String,
            report_params: String,
            filters: String,
            only_confirmed: String,
            min_sev: String,
            picked_only: String,
            secrets_mode: String,
            method_title: String,
            method_text: String,
            generator: String,
            all: String,
            secret_modes: [String; 3],
            risk_levels: [String; 5],
            incomplete_banner_title: String,
            incomplete_banner_body: String,
        }
        let r = Raw::deserialize(d)?;
        Ok(Self {
            title: leak(r.title),
            conf: leak(r.conf),
            project: leak(r.project),
            client: leak(r.client),
            by: leak(r.by),
            date: leak(r.date),
            tz: leak(r.tz),
            page: leak(r.page),
            toc: leak(r.toc),
            summary: leak(r.summary),
            period: leak(r.period),
            scope: leak(r.scope),
            findings: leak(r.findings),
            fixed: leak(r.fixed),
            people: leak(r.people),
            infra: leak(r.infra),
            docs: leak(r.docs),
            log: leak(r.log),
            appx: leak(r.appx),
            risk: leak(r.risk),
            risk_by: leak(r.risk_by),
            by_sev: leak(r.by_sev),
            docs_by_type: leak(r.docs_by_type),
            top_people: leak(r.top_people),
            top_software: leak(r.top_software),
            host_software: leak(r.host_software),
            eol_software: leak(r.eol_software),
            infra_found: leak(r.infra_found),
            site_found: leak(r.site_found),
            none: leak(r.none),
            no_data: leak(r.no_data),
            oos_caveat: leak(r.oos_caveat),
            log_shown: leak(r.log_shown),
            summary_text_n: leak(r.summary_text_n),
            summary_text_c: leak(r.summary_text_c),
            summary_fixed: leak(r.summary_fixed),
            summary_top: leak(r.summary_top),
            summary_crit_advice: leak(r.summary_crit_advice),
            targets: leak(r.targets),
            excl: leak(r.excl),
            contact: leak(r.contact),
            basis: leak(r.basis),
            yes: leak(r.yes),
            no: leak(r.no),
            kind: leak(r.kind),
            active: leak(r.active),
            sev: leak(r.sev),
            status: leak(r.status),
            host: leak(r.host),
            category: leak(r.category),
            description: leak(r.description),
            evidence: leak(r.evidence),
            recommendation: leak(r.recommendation),
            mitre: leak(r.mitre),
            provenance: leak(r.provenance),
            rule: leak(r.rule),
            fields: leak(r.fields),
            source_docs: leak(r.source_docs),
            first_seen: leak(r.first_seen),
            fixed_in: leak(r.fixed_in),
            notes: leak(r.notes),
            url: leak(r.url),
            active_module: leak(r.active_module),
            finding: leak(r.finding),
            secret: leak(r.secret),
            hidden: leak(r.hidden),
            login: leak(r.login),
            name: leak(r.name),
            doc_title: leak(r.doc_title),
            role: leak(r.role),
            pc: leak(r.pc),
            emails: leak(r.emails),
            n_docs: leak(r.n_docs),
            n_hosts: leak(r.n_hosts),
            service_acc: leak(r.service_acc),
            address: leak(r.address),
            found_in_docs: leak(r.found_in_docs),
            pattern: leak(r.pattern),
            hosts: leak(r.hosts),
            ip: leak(r.ip),
            tech: leak(r.tech),
            services: leak(r.services),
            internal: leak(r.internal),
            scope_col: leak(r.scope_col),
            pcs: leak(r.pcs),
            users: leak(r.users),
            software: leak(r.software),
            version: leak(r.version),
            eol: leak(r.eol),
            cve: leak(r.cve),
            paths: leak(r.paths),
            path: leak(r.path),
            printers: leak(r.printers),
            file: leak(r.file),
            author: leak(r.author),
            created: leak(r.created),
            modified: leak(r.modified),
            flags: leak(r.flags),
            size_kb: leak(r.size_kb),
            log_total: leak(r.log_total),
            log_passive: leak(r.log_passive),
            log_active: leak(r.log_active),
            log_blocked: leak(r.log_blocked),
            log_hosts_target: leak(r.log_hosts_target),
            log_hosts_third: leak(r.log_hosts_third),
            log_by_module: leak(r.log_by_module),
            log_active_list: leak(r.log_active_list),
            log_blocked_list: leak(r.log_blocked_list),
            log_empty: leak(r.log_empty),
            time: leak(r.time),
            method: leak(r.method),
            code: leak(r.code),
            module: leak(r.module),
            error: leak(r.error),
            size_type: leak(r.size_type),
            count: leak(r.count),
            scans: leak(r.scans),
            profile: leak(r.profile),
            started: leak(r.started),
            finished: leak(r.finished),
            egress: leak(r.egress),
            report_params: leak(r.report_params),
            filters: leak(r.filters),
            only_confirmed: leak(r.only_confirmed),
            min_sev: leak(r.min_sev),
            picked_only: leak(r.picked_only),
            secrets_mode: leak(r.secrets_mode),
            method_title: leak(r.method_title),
            method_text: leak(r.method_text),
            generator: leak(r.generator),
            all: leak(r.all),
            secret_modes: leak_arr(r.secret_modes),
            risk_levels: leak_arr(r.risk_levels),
            incomplete_banner_title: leak(r.incomplete_banner_title),
            incomplete_banner_body: leak(r.incomplete_banner_body),
        })
    }
}

static_str_struct! {
    /// Strings of the website and technologies section (site recon, `snapshot.recon`).
    #[derive(Debug, Clone, Copy)]
    pub struct ReconT {
        pub title,
        pub tech,
        pub name,
        pub version,
        pub category,
        pub state,
        pub outdated,
        pub current,
        pub unknown_ver,
        pub favicon,
        pub analytics,
        pub hidden,
        pub sitemap,
        pub security,
        pub endpoints,
        pub secrets,
        pub masked_note,
        pub buckets,
        pub code,
        pub via_archive,
        pub empty,
        pub b_public,
        pub b_closed,
        pub b_not_found,
        pub b_unknown,
        pub b_unchecked,
        pub source,
        pub of,
    }
}

static_str_struct! {
    /// Strings of the infrastructure subsections (certificates, mail, SaaS/clouds, out-of-scope candidates).
    #[derive(Debug, Clone, Copy)]
    pub struct InfraT {
        pub certs,
        pub endpoint,
        pub protocol,
        pub issuer,
        pub valid,
        pub days,
        pub trust,
        pub issues,
        pub trusted,
        pub self_signed,
        pub unknown_ca,
        pub incomplete,
        pub invalid,
        pub no_sni,
        pub mail,
        pub domain,
        pub yes,
        pub no,
        pub saas,
        pub object,
        pub kind,
        pub services,
        pub oos,
        pub oos_note,
        pub via,
        pub k_san,
        pub k_org,
        pub k_tenant,
        pub k_origin,
        pub k_fed,
    }
}

static_str_struct! {
    /// Forensics subsection strings.
    #[derive(Debug, Clone, Copy)]
    pub struct FxT {
        pub title,
        pub sigs,
        pub hidden,
        pub pii,
        pub pii_note,
        pub links,
        pub doc,
        pub finding,
        pub sev,
        pub kind,
        pub count,
    }
}

static_str_struct! {
    /// Open ports subsection strings.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct PortsT {
        pub title,
        pub host,
        pub port,
        pub service,
        pub version,
        pub source,
        pub note,
        pub scan,
        pub cache,
        pub unconfirmed,
        pub sensitive,
        pub outdated,
        pub legend,
        pub unreliable,
    }
}

static_str_struct! {
    /// Chain of Custody labels.
    #[derive(Debug, Clone, Copy)]
    pub(crate) struct CustodyLabels {
        pub title,
        pub subtitle,
        pub generated_at,
        pub generator,
        pub inputs_digest,
        pub findings_docs_reqs,
        pub scans_count,
        pub secrets_policy,
        pub sidecar_label,
        pub verify_hint,
    }
}

/// Diagram labels (`svg`): section titles, layers, kinds, roles, lanes, legends.
#[derive(Debug, Clone, Copy)]
pub struct VizStrings {
    pub graph: &'static str,
    pub netmap: &'static str,
    pub timeline: &'static str,
    pub activity: &'static str,
    /// Graph layers: people, documents, hosts (PC/printer/share), infrastructure.
    pub layers: [&'static str; 4],
    /// Graph node kinds in [`crate::svg::NodeKind`] order: plural forms
    /// `[one, few, many]` (`few` = `many` in English) for cluster labels.
    pub kinds: [[&'static str; 3]; 8],
    /// Network node kinds in [`crate::svg::NetKind`] order.
    pub net_kinds: [&'static str; 6],
    /// Server roles in [`crate::svg::ServerRole`] order.
    pub roles: [&'static str; 8],
    /// Chronology lanes in [`crate::svg::Lane`] order.
    pub lanes: [&'static str; 4],
    pub year: &'static str,
    /// Weekdays starting on Monday.
    pub weekdays: [&'static str; 7],
    pub hour: &'static str,
    pub work_hours: &'static str,
    pub off_hours: &'static str,
    pub less: &'static str,
    pub more_activity: &'static str,
    pub tz: &'static str,
    pub total: &'static str,
    /// `… and N more`.
    pub more: &'static str,
    pub links: &'static str,
    pub shown_of: &'static str,
    pub collapsed: &'static str,
    pub critical: &'static str,
    pub see_html: &'static str,
    pub timestamps: &'static str,
    pub peak: &'static str,
}

impl<'de> Deserialize<'de> for VizStrings {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            graph: String,
            netmap: String,
            timeline: String,
            activity: String,
            layers: [String; 4],
            kinds: [[String; 3]; 8],
            net_kinds: [String; 6],
            roles: [String; 8],
            lanes: [String; 4],
            year: String,
            weekdays: [String; 7],
            hour: String,
            work_hours: String,
            off_hours: String,
            less: String,
            more_activity: String,
            tz: String,
            total: String,
            more: String,
            links: String,
            shown_of: String,
            collapsed: String,
            critical: String,
            see_html: String,
            timestamps: String,
            peak: String,
        }
        let r = Raw::deserialize(d)?;
        Ok(Self {
            graph: leak(r.graph),
            netmap: leak(r.netmap),
            timeline: leak(r.timeline),
            activity: leak(r.activity),
            layers: leak_arr(r.layers),
            kinds: r.kinds.map(leak_arr),
            net_kinds: leak_arr(r.net_kinds),
            roles: leak_arr(r.roles),
            lanes: leak_arr(r.lanes),
            year: leak(r.year),
            weekdays: leak_arr(r.weekdays),
            hour: leak(r.hour),
            work_hours: leak(r.work_hours),
            off_hours: leak(r.off_hours),
            less: leak(r.less),
            more_activity: leak(r.more_activity),
            tz: leak(r.tz),
            total: leak(r.total),
            more: leak(r.more),
            links: leak(r.links),
            shown_of: leak(r.shown_of),
            collapsed: leak(r.collapsed),
            critical: leak(r.critical),
            see_html: leak(r.see_html),
            timestamps: leak(r.timestamps),
            peak: leak(r.peak),
        })
    }
}

/// Texts of the `executive`, `compliance` and `lab` report templates.
#[derive(Debug, Clone, Copy)]
pub struct TplText {
    pub exec_title: &'static str,
    pub exec_lead: &'static str,
    pub exec_top: &'static str,
    pub exec_actions: &'static str,
    pub exec_none: &'static str,
    pub exec_findings_n: &'static str,
    pub comp_title: &'static str,
    pub comp_lead: &'static str,
    pub comp_table: &'static str,
    pub comp_ndtzi: &'static str,
    pub comp_iso: &'static str,
    pub comp_kszi: &'static str,
    pub comp_nist: &'static str,
    pub comp_privacy: &'static str,
    pub comp_legacy: &'static str,
    pub comp_unmapped: &'static str,
    pub comp_disclaimer: &'static str,
    pub col_no: &'static str,
    pub col_finding: &'static str,
    pub col_code: &'static str,
    pub col_service: &'static str,
    pub col_clause: &'static str,
    pub col_control: &'static str,
    pub col_count: &'static str,
    pub col_stage: &'static str,
    pub lab_title: &'static str,
    pub lab_goal: &'static str,
    pub lab_goal_text: &'static str,
    pub lab_method: &'static str,
    pub lab_profile: &'static str,
    pub lab_sources: &'static str,
    pub lab_tool: &'static str,
    pub lab_limits: &'static str,
    pub lab_limits_text: &'static str,
    pub lab_requests: &'static str,
    pub lab_input: &'static str,
    pub lab_object: &'static str,
    pub lab_targets: &'static str,
    pub lab_course: &'static str,
    pub lab_stage_docs: &'static str,
    pub lab_stage_meta: &'static str,
    pub lab_stage_analysis: &'static str,
    pub lab_stage_net: &'static str,
    pub lab_table: &'static str,
    pub lab_conclusions: &'static str,
    pub lab_conclusion_risk: &'static str,
    pub lab_done_by: &'static str,
    pub lab_checked_by: &'static str,
    pub lab_signature: &'static str,
    /// Plain-language explanation and action per finding group (see `templates::group`).
    pub groups: [(&'static str, &'static str); 9],
    pub generic_actions: [&'static str; 2],
}

impl<'de> Deserialize<'de> for TplText {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        struct Raw {
            exec_title: String,
            exec_lead: String,
            exec_top: String,
            exec_actions: String,
            exec_none: String,
            exec_findings_n: String,
            comp_title: String,
            comp_lead: String,
            comp_table: String,
            comp_ndtzi: String,
            comp_iso: String,
            comp_kszi: String,
            comp_nist: String,
            comp_privacy: String,
            comp_legacy: String,
            comp_unmapped: String,
            comp_disclaimer: String,
            col_no: String,
            col_finding: String,
            col_code: String,
            col_service: String,
            col_clause: String,
            col_control: String,
            col_count: String,
            col_stage: String,
            lab_title: String,
            lab_goal: String,
            lab_goal_text: String,
            lab_method: String,
            lab_profile: String,
            lab_sources: String,
            lab_tool: String,
            lab_limits: String,
            lab_limits_text: String,
            lab_requests: String,
            lab_input: String,
            lab_object: String,
            lab_targets: String,
            lab_course: String,
            lab_stage_docs: String,
            lab_stage_meta: String,
            lab_stage_analysis: String,
            lab_stage_net: String,
            lab_table: String,
            lab_conclusions: String,
            lab_conclusion_risk: String,
            lab_done_by: String,
            lab_checked_by: String,
            lab_signature: String,
            groups: [[String; 2]; 9],
            generic_actions: [String; 2],
        }
        let r = Raw::deserialize(d)?;
        Ok(Self {
            exec_title: leak(r.exec_title),
            exec_lead: leak(r.exec_lead),
            exec_top: leak(r.exec_top),
            exec_actions: leak(r.exec_actions),
            exec_none: leak(r.exec_none),
            exec_findings_n: leak(r.exec_findings_n),
            comp_title: leak(r.comp_title),
            comp_lead: leak(r.comp_lead),
            comp_table: leak(r.comp_table),
            comp_ndtzi: leak(r.comp_ndtzi),
            comp_iso: leak(r.comp_iso),
            comp_kszi: leak(r.comp_kszi),
            comp_nist: leak(r.comp_nist),
            comp_privacy: leak(r.comp_privacy),
            comp_legacy: leak(r.comp_legacy),
            comp_unmapped: leak(r.comp_unmapped),
            comp_disclaimer: leak(r.comp_disclaimer),
            col_no: leak(r.col_no),
            col_finding: leak(r.col_finding),
            col_code: leak(r.col_code),
            col_service: leak(r.col_service),
            col_clause: leak(r.col_clause),
            col_control: leak(r.col_control),
            col_count: leak(r.col_count),
            col_stage: leak(r.col_stage),
            lab_title: leak(r.lab_title),
            lab_goal: leak(r.lab_goal),
            lab_goal_text: leak(r.lab_goal_text),
            lab_method: leak(r.lab_method),
            lab_profile: leak(r.lab_profile),
            lab_sources: leak(r.lab_sources),
            lab_tool: leak(r.lab_tool),
            lab_limits: leak(r.lab_limits),
            lab_limits_text: leak(r.lab_limits_text),
            lab_requests: leak(r.lab_requests),
            lab_input: leak(r.lab_input),
            lab_object: leak(r.lab_object),
            lab_targets: leak(r.lab_targets),
            lab_course: leak(r.lab_course),
            lab_stage_docs: leak(r.lab_stage_docs),
            lab_stage_meta: leak(r.lab_stage_meta),
            lab_stage_analysis: leak(r.lab_stage_analysis),
            lab_stage_net: leak(r.lab_stage_net),
            lab_table: leak(r.lab_table),
            lab_conclusions: leak(r.lab_conclusions),
            lab_conclusion_risk: leak(r.lab_conclusion_risk),
            lab_done_by: leak(r.lab_done_by),
            lab_checked_by: leak(r.lab_checked_by),
            lab_signature: leak(r.lab_signature),
            groups: r.groups.map(|[a, b]| (leak(a), leak(b))),
            generic_actions: leak_arr(r.generic_actions),
        })
    }
}

pub(crate) struct ReportBundle {
    pub strings: Strings,
    pub sev: [&'static str; 5],
    pub status: [&'static str; 5],
    pub file_prefix: &'static str,
    pub recon: ReconT,
    pub infra: InfraT,
    pub core_messages: BTreeMap<String, String>,
    pub viz: VizStrings,
    pub tpl: TplText,
    pub template_catalog: [(&'static str, &'static str, &'static str); 4],
    pub sources: BTreeMap<String, String>,
    pub forensics: FxT,
    pub pii_kind: BTreeMap<String, String>,
    pub ports: PortsT,
    pub custody: CustodyLabels,
    /// Incomplete sources table: `title`, `source`, `reason` and one phrase per reason key.
    pub incomplete: BTreeMap<String, String>,
}

impl ReportBundle {
    fn from_json(src: &str) -> Self {
        #[derive(Deserialize)]
        struct RawBundle {
            strings: Strings,
            sev: [String; 5],
            status: [String; 5],
            file_prefix: String,
            recon: ReconT,
            infra: InfraT,
            core_messages: BTreeMap<String, String>,
            viz: VizStrings,
            tpl: TplText,
            template_catalog: [[String; 3]; 4],
            sources: BTreeMap<String, String>,
            forensics: FxT,
            pii_kind: BTreeMap<String, String>,
            ports: PortsT,
            custody: CustodyLabels,
            incomplete: BTreeMap<String, String>,
        }
        let r: RawBundle = serde_json::from_str(src).expect("valid report locale json");
        Self {
            strings: r.strings,
            sev: leak_arr(r.sev),
            status: leak_arr(r.status),
            file_prefix: leak(r.file_prefix),
            recon: r.recon,
            infra: r.infra,
            core_messages: r.core_messages,
            viz: r.viz,
            tpl: r.tpl,
            template_catalog: r
                .template_catalog
                .map(|[id, title, desc]| (leak(id), leak(title), leak(desc))),
            sources: r.sources,
            forensics: r.forensics,
            pii_kind: r.pii_kind,
            ports: r.ports,
            custody: r.custody,
            incomplete: r.incomplete,
        }
    }
}

pub(crate) fn bundle(l: Lang) -> &'static ReportBundle {
    static EN: OnceLock<ReportBundle> = OnceLock::new();
    static RU: OnceLock<ReportBundle> = OnceLock::new();
    static UK: OnceLock<ReportBundle> = OnceLock::new();
    match l {
        Lang::En => EN.get_or_init(|| {
            ReportBundle::from_json(include_str!("../../../locales/en/report.json"))
        }),
        Lang::Ru => RU.get_or_init(|| {
            ReportBundle::from_json(include_str!("../../../locales/ru/report.json"))
        }),
        Lang::Uk => UK.get_or_init(|| {
            ReportBundle::from_json(include_str!("../../../locales/uk/report.json"))
        }),
    }
}

pub fn strings(l: Lang) -> &'static Strings {
    &bundle(l).strings
}

/// Returns the severity term.
pub fn sev(l: Lang, s: Severity) -> &'static str {
    let i = 4 - s.rank() as usize;
    bundle(l).sev[i]
}

/// Returns the finding status label.
pub fn status(l: Lang, s: FindingStatus) -> &'static str {
    let i = match s {
        FindingStatus::New => 0,
        FindingStatus::Confirmed => 1,
        FindingStatus::FalsePositive => 2,
        FindingStatus::Accepted => 3,
        FindingStatus::Fixed => 4,
    };
    bundle(l).status[i]
}

/// Maps a UI risk level (`crit|high|mid|low|none`) to its label.
pub fn risk_level(l: Lang, level: &str) -> &'static str {
    let t = strings(l);
    match level {
        "crit" => t.risk_levels[0],
        "high" => t.risk_levels[1],
        "mid" => t.risk_levels[2],
        "low" => t.risk_levels[3],
        _ => t.risk_levels[4],
    }
}

/// Returns the report file name prefix (like `reportName` in the demo backend).
pub fn file_prefix(l: Lang) -> &'static str {
    bundle(l).file_prefix
}

pub fn recon_strings(l: Lang) -> &'static ReconT {
    &bundle(l).recon
}

pub fn infra_strings(l: Lang) -> &'static InfraT {
    &bundle(l).infra
}

/// Incomplete sources table of the report appendix.
pub(crate) struct IncompleteTable {
    pub title: &'static str,
    /// `[source, reason]`.
    pub head: [&'static str; 2],
    pub rows: Vec<[String; 2]>,
}

/// Incomplete sources of the latest scan with the reason in the report language; `None` when
/// the scan is complete.
pub(crate) fn incomplete_sources(
    l: Lang,
    scans: &[foca_core::api::Scan],
) -> Option<IncompleteTable> {
    let env = scans.last()?.env.as_ref()?;
    if env.incomplete_sources.is_empty() {
        return None;
    }
    let m = &bundle(l).incomplete;
    let txt = |k: &str| -> &'static str { m.get(k).map(String::as_str).unwrap_or("-") };
    let rows = env
        .incomplete_sources
        .iter()
        .map(|id| {
            let why = env.incomplete_reasons.iter().find(|r| &r.id == id);
            let key = match why.map(|r| (r.status.as_str(), r.http)) {
                Some(("blocked", _)) if id == "fuzz" => "blocked_fuzz",
                Some(("limit" | "lost", Some(429))) => "limit_http",
                Some(("error" | "lost", Some(c))) if c >= 500 => "unavailable_http",
                Some(("error", Some(_))) => "error_http",
                Some(("lost", Some(_))) => "lost_http",
                Some((
                    s
                    @ ("error" | "timeout" | "captcha" | "blocked" | "limit" | "skipped" | "lost"),
                    _,
                )) => s,
                _ => "unknown",
            };
            let code = why
                .and_then(|r| r.http)
                .map(|c| c.to_string())
                .unwrap_or_default();
            [id.clone(), txt(key).replace("{code}", &code)]
        })
        .collect();
    Some(IncompleteTable {
        title: txt("title"),
        head: [txt("source"), txt("reason")],
        rows,
    })
}

/// Formats localized title and body for an incomplete-snapshot warning banner, if applicable.
pub(crate) fn incomplete_banner(
    l: Lang,
    scans: &[foca_core::api::Scan],
) -> Option<(&'static str, String)> {
    let env = scans.last()?.env.as_ref().filter(|e| e.incomplete)?;
    let t = strings(l);
    let mut details = Vec::new();
    if !env.incomplete_sources.is_empty() {
        details.push(env.incomplete_sources.join(", "));
    }
    if env.tcp_intercept {
        details.push("TCP intercept".into());
    }
    if env.dns_hijack {
        details.push("DNS hijack".into());
    }
    if env.tls_mitm {
        details.push("TLS MITM".into());
    }
    let body = if details.is_empty() {
        t.incomplete_banner_body.to_string()
    } else {
        format!("{} ({})", t.incomplete_banner_body, details.join("; "))
    };
    Some((t.incomplete_banner_title, body))
}

/// Heading of the optional AI-assisted executive summary section.
pub fn ai_summary_title(l: Lang) -> &'static str {
    match l {
        Lang::En => "Executive summary (AI-assisted)",
        Lang::Ru => "Резюме для руководства (подготовлено с помощью ИИ)",
        Lang::Uk => "Резюме для керівництва (підготовлено за допомогою ШІ)",
    }
}

/// Disclaimer under the AI summary heading; `src` is "provider · model", `date` YYYY-MM-DD
/// (either may be empty).
pub fn ai_summary_note(l: Lang, src: &str, date: &str) -> String {
    let meta = [src, date]
        .iter()
        .filter(|s| !s.trim().is_empty())
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    let meta = if meta.is_empty() {
        String::new()
    } else {
        format!(" ({meta})")
    };
    match l {
        Lang::En => format!(
            "Generated by a cloud AI model{meta} from redacted project data. Not verified by FOCA-rs: check every statement against the findings in this report."
        ),
        Lang::Ru => format!(
            "Сформировано облачной ИИ-моделью{meta} по обезличенным данным проекта. FOCA-rs не проверяет этот текст: сверяйте каждое утверждение с находками отчёта."
        ),
        Lang::Uk => format!(
            "Сформовано хмарною ШІ-моделлю{meta} за знеособленими даними проєкту. FOCA-rs не перевіряє цей текст: звіряйте кожне твердження зі знахідками звіту."
        ),
    }
}

pub const KEY_CANARY_TCP_INTERCEPT: &str = "canary.tcp_intercept";
pub const KEY_CANARY_DNS_HIJACK: &str = "canary.dns_hijack";
pub const KEY_CANARY_TLS_MITM: &str = "canary.tls_mitm";
pub const KEY_LIVENESS_UNRELIABLE: &str = "liveness.unreliable";
pub const KEY_SCAN_INCOMPLETE: &str = "scan.incomplete";

/// Resolves localized diagnostic messages for canonical core warning keys (`RU` / `UK` / `EN`).
pub fn core_message(l: Lang, key: &str) -> Option<&'static str> {
    bundle(l).core_messages.get(key).map(String::as_str)
}

/// Returns the diagram labels.
pub fn viz(l: Lang) -> &'static VizStrings {
    &bundle(l).viz
}

/// Picks the plural form index for `n`: 0 = one, 1 = few, 2 = many (Slavic rules; English
/// uses 0 and 1/2 with the same text).
pub fn plural_idx(l: Lang, n: usize) -> usize {
    match l {
        Lang::En => usize::from(n != 1),
        _ => {
            let (d, h) = (n % 10, n % 100);
            if d == 1 && h != 11 {
                0
            } else if (2..=4).contains(&d) && !(12..=14).contains(&h) {
                1
            } else {
                2
            }
        }
    }
}

pub fn tpl_text(l: Lang) -> &'static TplText {
    &bundle(l).tpl
}

/// Report templates for the `report_templates` command: `(id, title, description)` in the UI
/// language.
pub fn template_catalog(l: Lang) -> [(&'static str, &'static str, &'static str); 4] {
    bundle(l).template_catalog
}

/// Translates a finding source label; unknown labels (`EXIF`, `DNS`, …) are kept.
pub fn source_label(s: &str, l: Lang) -> String {
    bundle(l)
        .sources
        .get(s)
        .cloned()
        .unwrap_or_else(|| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn core_diagnostic_keys_localized_in_all_languages() {
        let keys = [
            KEY_CANARY_TCP_INTERCEPT,
            KEY_CANARY_DNS_HIJACK,
            KEY_CANARY_TLS_MITM,
            KEY_LIVENESS_UNRELIABLE,
            KEY_SCAN_INCOMPLETE,
        ];
        for l in [Lang::Ru, Lang::Uk, Lang::En] {
            for k in keys {
                assert!(
                    core_message(l, k).is_some_and(|s| !s.is_empty()),
                    "{l:?} {k}"
                );
            }
            assert!(core_message(l, "unknown.key").is_none());
        }
    }

    #[test]
    fn report_locales_are_in_sync() {
        let en = bundle(Lang::En);
        let ru = bundle(Lang::Ru);
        let uk = bundle(Lang::Uk);
        assert_eq!(
            en.core_messages.keys().collect::<Vec<_>>(),
            ru.core_messages.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            en.core_messages.keys().collect::<Vec<_>>(),
            uk.core_messages.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            en.sources.keys().collect::<Vec<_>>(),
            ru.sources.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            en.sources.keys().collect::<Vec<_>>(),
            uk.sources.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            en.pii_kind.keys().collect::<Vec<_>>(),
            ru.pii_kind.keys().collect::<Vec<_>>()
        );
        assert_eq!(
            en.pii_kind.keys().collect::<Vec<_>>(),
            uk.pii_kind.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn plural_forms() {
        let f = |l, n| viz(l).kinds[1][plural_idx(l, n)];
        assert_eq!(f(Lang::Ru, 1), "документ");
        assert_eq!(f(Lang::Ru, 3), "документа");
        assert_eq!(f(Lang::Ru, 14), "документов");
        assert_eq!(f(Lang::Ru, 21), "документ");
        assert_eq!(f(Lang::Uk, 22), "документи");
        assert_eq!(f(Lang::En, 1), "document");
        assert_eq!(f(Lang::En, 14), "documents");
    }
}
