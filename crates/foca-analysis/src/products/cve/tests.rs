use super::*;

const TABLE: &str = "# foca-nvd v1 snapshot=2099-06-01 epss=2099-05-31 cves=6 products=4 ranges=7 site=3 plugin=1 doc=2 os=0
C\t2099-0001\t2099\t9.8\t31\t787\tK\t9500
C\t2099-0002\t2099\t5.3\t40\t79\t\t120
C\t2099-0003\t2099\t7.5\t2\t\t\t
C\t2099-0004\t2099\t3.1\t31\t\t\t
C\t2099-0005\t2099\t\t\t\t\t
C\t2099-0006\t2099\t8.8\t31\t\t\t42
P\tf5:nginx\ts
0\t=0.9.7 [1.1.0,1.20.1)
1\t(1.20.1,1.22.0]
1\t*
P\texample_vendor:contact_form_x@wordpress\tp
1\t[,5.4]
P\tmicrosoft:office\td
3\t=2016
1\t=2010
P\tmicrosoft:365_apps\td
5\t*
";

fn db() -> CveDb {
    CveDb::parse_text(TABLE).unwrap()
}

fn q(keys: &[&str], v: Option<&str>) -> CveQuery {
    CveQuery {
        keys: keys.iter().map(|s| s.to_string()).collect(),
        version: v.map(str::to_string),
        ..Default::default()
    }
}

fn ids(s: &CveSummary) -> Vec<&str> {
    s.cves.iter().map(|c| c.id.as_str()).collect()
}

#[test]
fn version_comparison_table() {
    use Ordering::*;
    for (a, b, o) in [
        ("2.4.49", "2.4.50", Less),
        ("2.4", "2.4.0", Equal),
        ("2.4.0.0", "2.4", Equal),
        ("1.0.2k", "1.0.2", Greater),
        ("1.0.2k", "1.0.2l", Less),
        ("5.4-beta1", "5.4", Less),
        ("5.4-rc1", "5.4-beta2", Greater),
        ("5.4-alpha", "5.4-beta", Less),
        ("5.4.1-dev", "5.4.1", Less),
        ("5.4", "5.4-final", Equal),
        ("1.2.3+build.7", "1.2.3", Equal),
        ("v2.1.0", "2.1", Equal),
        ("m120", "120", Equal),
        ("10.0.20348.2582", "10.0.20348.1000", Greater),
        ("2021.007.20099", "2021.007.20100", Less),
        ("15.006.30355", "15.6.30355", Equal),
        ("1.18.0 (Ubuntu)", "1.18.0", Equal),
        ("nginx/1.18.0", "1.18.0", Equal),
        ("8.3.6-1ubuntu2", "8.3.8", Less),
        ("7.4.33", "7.4.4", Greater),
        ("1.10", "1.9", Greater),
        ("2.0", "10.0", Less),
        ("4.9.18", "4.9.18.1", Less),
    ] {
        assert_eq!(cmp_ver(a, b), o, "{a} vs {b}");
    }
    assert_eq!(norm_ver("Apache/2.4.58 (Unix)").as_deref(), Some("2.4.58"));
    assert_eq!(norm_ver("unknown"), None);
}

#[test]
fn ranges_parse_and_contain() {
    let r = VerRange::parse("[1.1.0,1.20.1)").unwrap();
    assert!(r.contains("1.1.0") && r.contains("1.19.9") && !r.contains("1.20.1"));
    assert!(!r.contains("1.0.9"));
    let r = VerRange::parse("(2.0,]").unwrap();
    assert!(!r.contains("2.0") && r.contains("2.0.1") && r.contains("99"));
    let r = VerRange::parse("[,5.4]").unwrap();
    assert!(r.contains("5.4") && r.contains("1") && !r.contains("5.4.1"));
    assert!(r.contains("5.4-beta"));
    assert!(VerRange::parse("=1.2").unwrap().contains("1.2.0"));
    assert!(VerRange::parse("*").unwrap().contains("anything"));
    assert!(VerRange::parse("bogus").is_none());
}

#[test]
fn matcher_ranges_exact_and_all() {
    let d = db();
    assert_eq!(d.meta.snapshot, "2099-06-01");
    assert_eq!(d.meta.cves, 6);
    let s = d
        .lookup(&q(&["cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"], Some("1.18.0")))
        .unwrap();
    // 0001 by range, 0003 by `*` (listed last, not counted into the bands); 0002 starts
    // after 1.20.1.
    assert_eq!(ids(&s), vec!["CVE-2099-0001", "CVE-2099-0003"]);
    assert_eq!((s.known, s.matched, s.critical, s.high), (3, 2, 1, 0));
    assert_eq!(s.unbounded, 1);
    assert!(s.cves[1].unbounded && !s.cves[0].unbounded);
    assert_eq!((s.kev, s.max_cvss, s.max_epss), (1, Some(9.8), Some(0.95)));
    assert!(s.version_known);
    let s = d.lookup(&q(&["f5:nginx"], Some("0.9.7"))).unwrap();
    assert_eq!(ids(&s), vec!["CVE-2099-0001", "CVE-2099-0003"]);
    let s = d.lookup(&q(&["f5:nginx"], Some("1.21.0"))).unwrap();
    assert_eq!(ids(&s), vec!["CVE-2099-0002", "CVE-2099-0003"]);
    assert_eq!((s.medium, s.high), (1, 0));
    let s = d.lookup(&q(&["f5:nginx"], Some("1.22.1"))).unwrap();
    assert_eq!(ids(&s), vec!["CVE-2099-0003"]);
}

#[test]
fn matcher_without_version_counts_only_known() {
    let d = db();
    let s = d.lookup(&q(&["f5:nginx"], None)).unwrap();
    assert!(!s.version_known);
    assert_eq!((s.known, s.matched), (3, 0));
    assert!(s.cves.is_empty() && s.max_cvss.is_none());
    let s = d.lookup(&q(&["f5:nginx"], Some("-"))).unwrap();
    assert!(!s.version_known);
    assert!(d.lookup(&q(&["unknown:product"], Some("1.0"))).is_none());
}

#[test]
fn matcher_plugins_by_slug() {
    let d = db();
    let mut query = q(&[], Some("5.3.2"));
    query.slug = Some(("Contact-Form-X".into(), "WordPress".into()));
    let s = d.lookup(&query).unwrap();
    assert_eq!(s.product, "example_vendor:contact_form_x@wordpress");
    assert_eq!(ids(&s), vec!["CVE-2099-0002"]);
    query.version = Some("5.5".into());
    assert_eq!(d.lookup(&query).unwrap().matched, 0);
    query.slug = Some(("contact-form-x".into(), "drupal".into()));
    assert!(d.lookup(&query).is_none());
}

#[test]
fn office_versions_map_to_marketing_editions() {
    let d = db();
    let keys = ["microsoft:office", "microsoft:word", "microsoft:365_apps"];
    // `16.0` documents: Office 2016 and Microsoft 365 Apps (no version in NVD: unbounded).
    let s = d.lookup(&q(&keys, Some("16"))).unwrap();
    assert_eq!(ids(&s), vec!["CVE-2099-0004", "CVE-2099-0006"]);
    assert_eq!(s.unbounded, 1);
    let s = d.lookup(&q(&keys, Some("2010"))).unwrap();
    assert_eq!(ids(&s), vec!["CVE-2099-0005"]);
    let s = d.lookup(&q(&keys, Some("14"))).unwrap();
    assert_eq!(ids(&s), vec!["CVE-2099-0005"]);
    assert_eq!(d.lookup(&q(&keys, Some("15"))).unwrap().matched, 0);
    assert_eq!(office_editions("16.0000"), vec!["2016"]);
}

#[test]
fn finding_severity_rules() {
    let d = db();
    let s = d.lookup(&q(&["f5:nginx"], Some("1.18.0"))).unwrap();
    assert_eq!(finding_severity(&s, None), Severity::Critical);
    assert_eq!(
        finding_severity(&s, Some(Severity::Medium)),
        Severity::Medium
    );
    let s = d.lookup(&q(&["f5:nginx"], Some("1.21.0"))).unwrap();
    // only 0002 (5.3) is bounded: the unbounded 7.5 does not count
    assert_eq!(finding_severity(&s, None), Severity::Medium);
    let mut kev = s.clone();
    kev.kev = 1;
    assert_eq!(finding_severity(&kev, None), Severity::High);
    let low = CveSummary {
        max_cvss: Some(5.0),
        kev: 1,
        ..Default::default()
    };
    // Medium raised to high by KEV.
    assert_eq!(finding_severity(&low, None), Severity::High);
}

#[test]
fn bad_tables_are_rejected() {
    assert!(CveDb::parse_text("# other\n").is_err());
    assert!(CveDb::parse_text("# foca-nvd v1\nP\tx:y\ts\n0\t*\n").is_err());
    assert!(CveDb::parse(b"not gzip").is_err());
}

#[test]
fn builtin_table_loads_fast_and_finds_real_products() {
    let t = std::time::Instant::now();
    let d = CveDb::parse(NVD_GZ).unwrap();
    let load = t.elapsed();
    assert!(d.meta.cves > 10_000, "{:?}", d.meta);
    assert!(d.meta.plugin > 5_000, "{:?}", d.meta);
    assert!(!d.meta.snapshot.is_empty());
    let t = std::time::Instant::now();
    let mut n = 0;
    for _ in 0..200 {
        n += d
            .lookup(&q(&["f5:nginx"], Some("1.18.0")))
            .map_or(0, |s| s.matched);
        n += d
            .lookup(&q(&["wordpress:wordpress"], Some("5.8.1")))
            .map_or(0, |s| s.matched);
    }
    let per = t.elapsed() / 400;
    assert!(n > 0);
    let s = d
        .lookup(&q(&["apache:http_server"], Some("2.4.49")))
        .unwrap();
    assert!(ids(&s).contains(&"CVE-2021-41773"), "{:?}", ids(&s));
    assert!(s.kev > 0);
    let s = d
        .lookup(&q(&["apache:http_server"], Some("2.4.62")))
        .unwrap();
    assert!(!ids(&s).contains(&"CVE-2021-41773"));
    // Generous bounds for debug builds on a shared box.
    assert!(load.as_secs() < 20, "load {load:?}");
    assert!(per.as_millis() < 200, "lookup {per:?}");
    eprintln!("nvd table: load {load:?}, lookup {per:?}, {:?}", d.meta);
}

#[test]
fn document_software_counts_only_cves_up_to_the_document_year() {
    // Chrome m142 seen in a 2025 document: CVEs fixed later are real for that build but say
    // nothing about the machine today, so only those published up to 2025 count.
    let d = CveDb::parse(NVD_GZ).unwrap();
    let all = d.lookup(&q(&["google:chrome"], Some("m142"))).unwrap();
    let mut dated = q(&["google:chrome"], Some("m142"));
    dated.until_year = Some(2025);
    let s = d.lookup(&dated).unwrap();
    assert!(
        s.matched < all.matched / 4,
        "{} of {}",
        s.matched,
        all.matched
    );
    assert_eq!(s.matched + s.later, all.matched);
    assert!(
        s.cves.iter().all(|c| c.id.as_str() < "CVE-2026"),
        "{:?}",
        ids(&s)
    );
    eprintln!(
        "chrome m142: {} -> {} (later {})",
        all.matched, s.matched, s.later
    );
    // the small fixture: 2099 CVEs vanish for a 2098 document
    let mut old = q(&["f5:nginx"], Some("1.18.0"));
    old.until_year = Some(2098);
    let s = db().lookup(&old).unwrap();
    assert_eq!((s.matched, s.later), (0, 2));
}

/// Small NVD-shaped records: exact, range, unbounded and mixed entries of one product.
const MIXED: &str = "# foca-nvd v1 snapshot=2099-06-01 epss=2099-05-31
C\t2099-0101\t2099\t9.8\t31\t79\t\t100
C\t2099-0102\t2099\t8.1\t31\t\t\t
C\t2099-0103\t2099\t7.5\t31\t\tK\t
C\t2099-0104\t2099\t6.1\t31\t\t\t
C\t2099-0105\t2099\t5.0\t31\t\t\t
P\tapple:mac_os_x\to
0\t=10.15.7 =11.0
2\t*
1\t*
P\tapple:macos\to
0\t=26.0
1\t[,26.1)
1\t[26.0,26.2)
P\tgoogle:chrome\td
4\t[,142.0.7444.59)
";

#[test]
fn exact_entries_never_match_every_version() {
    let d = CveDb::parse_text(MIXED).unwrap();
    // 0101 lists exact builds only: 26.0 hits through the macOS exact entry, 12.1 hits nothing.
    let s = d.lookup(&q(&["apple:mac_os_x"], Some("12.1"))).unwrap();
    assert!(!ids(&s).contains(&"CVE-2099-0101"), "{:?}", ids(&s));
    let s = d.lookup(&q(&["apple:mac_os_x"], Some("10.15.7"))).unwrap();
    assert!(ids(&s).contains(&"CVE-2099-0101"));
    assert!(!s.cves[0].unbounded);
}

#[test]
fn unbounded_entry_counts_only_without_a_bounded_one_for_the_product() {
    let d = CveDb::parse_text(MIXED).unwrap();
    let keys = ["apple:macos", "apple:mac_os_x"];
    // 0103: mac_os_x `*` but macos `[,26.1)` -> bounded wins and 26.0 is inside.
    // 0104: mac_os_x `*`, nothing bounded -> unbounded hit, not counted into the bands or KEV.
    let s = d.lookup(&q(&keys, Some("26.0"))).unwrap();
    assert_eq!(
        ids(&s),
        vec![
            "CVE-2099-0103",
            "CVE-2099-0101",
            "CVE-2099-0102",
            "CVE-2099-0104"
        ]
    );
    assert_eq!((s.matched, s.unbounded, s.kev, s.critical), (4, 1, 1, 1));
    assert!(s.cves.last().unwrap().unbounded);
    // 26.2 leaves every bounded range: 0103 must not come back through the `*` entry.
    let s = d.lookup(&q(&keys, Some("26.2"))).unwrap();
    assert_eq!(ids(&s), vec!["CVE-2099-0104"]);
    assert_eq!(finding_severity(&s, None), Severity::Low);
    assert_eq!(s.fixed_in, None);
}

#[test]
fn fixed_in_is_the_lowest_version_outside_every_matched_range() {
    let d = CveDb::parse_text(MIXED).unwrap();
    let s = d.lookup(&q(&["apple:macos"], Some("26.0"))).unwrap();
    // [,26.1) and [26.0,26.2) -> 26.2 (26.1 is still inside the second range)
    assert_eq!(s.fixed_in.as_deref(), Some("26.2"));
    let s = d.lookup(&q(&["google:chrome"], Some("m142"))).unwrap();
    assert_eq!(
        (s.matched, s.fixed_in.as_deref()),
        (1, Some("142.0.7444.59"))
    );
    let l = d.list(&q(&["google:chrome"], Some("m142")));
    assert_eq!(l[0].1.range.as_deref(), Some("[,142.0.7444.59)"));
    assert_eq!(l[0].1.fixed().as_deref(), Some("142.0.7444.59"));
}

#[test]
fn milestone_prefix_is_stripped() {
    assert_eq!(norm_ver("m142").as_deref(), Some("142"));
    assert_eq!(norm_ver("Skia/PDF m142").as_deref(), Some("142"));
    assert_eq!(norm_ver("v3.3.5").as_deref(), Some("3.3.5"));
}

#[test]
fn list_page_has_ranges_fixed_versions_and_pages() {
    let d = db();
    let p = d
        .list_page(&q(&["f5:nginx"], Some("1.19.0")), 0, 50)
        .unwrap();
    assert!(p.version_specific);
    assert_eq!(p.total, 2, "{p:?}");
    assert_eq!(p.unbounded, 1);
    assert!(
        p.items[1].unbounded && p.items[1].range.is_none(),
        "listed last"
    );
    let r = &p.items[0];
    assert_eq!(r.id, "CVE-2099-0001");
    assert_eq!(r.severity, Some("critical"));
    assert!(r.kev);
    assert_eq!(r.cwe, vec![787]);
    assert_eq!(r.year, 2099);
    assert_eq!(r.range.as_deref(), Some("[1.1.0,1.20.1)"));
    assert_eq!(r.fixed.as_deref(), Some("1.20.1"));
    assert_eq!((p.critical, p.kev), (1, 1));
    assert_eq!(p.fixed_in.as_deref(), Some("1.20.1"));

    // version unknown: every CVE of the product, not version-specific, paginated
    let all = d.list_page(&q(&["f5:nginx"], None), 0, 1).unwrap();
    assert!(!all.version_specific);
    assert_eq!(all.total, 3, "{all:?}");
    assert_eq!(all.items.len(), 1);
    assert_eq!(all.items[0].id, "CVE-2099-0001", "KEV first");
    let next = d.list_page(&q(&["f5:nginx"], None), 1, 1).unwrap();
    assert_ne!(next.items[0].id, "CVE-2099-0001");
    assert_eq!(next.offset, 1);
    assert!(next.fixed_in.is_none());
    let j = serde_json::to_value(&next).unwrap();
    assert!(j["items"][0].get("range").is_none());
}
