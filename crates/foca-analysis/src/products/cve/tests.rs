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
    // 0001 by range, 0003 by `*`; 0002 starts after 1.20.1.
    assert_eq!(ids(&s), vec!["CVE-2099-0001", "CVE-2099-0003"]);
    assert_eq!((s.known, s.matched, s.critical, s.high), (3, 2, 1, 1));
    assert_eq!((s.kev, s.max_cvss, s.max_epss), (1, Some(9.8), Some(0.95)));
    assert!(s.version_known);
    let s = d.lookup(&q(&["f5:nginx"], Some("0.9.7"))).unwrap();
    assert_eq!(ids(&s), vec!["CVE-2099-0001", "CVE-2099-0003"]);
    let s = d.lookup(&q(&["f5:nginx"], Some("1.21.0"))).unwrap();
    assert_eq!(ids(&s), vec!["CVE-2099-0003", "CVE-2099-0002"]);
    assert_eq!((s.medium, s.high), (1, 1));
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
    // `16.0` documents: Office 2016 and Microsoft 365 Apps.
    let s = d.lookup(&q(&keys, Some("16"))).unwrap();
    assert_eq!(ids(&s), vec!["CVE-2099-0006", "CVE-2099-0004"]);
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
    assert_eq!(finding_severity(&s, None), Severity::High);
    let mut kev = s.clone();
    kev.kev = 1;
    assert_eq!(finding_severity(&kev, None), Severity::Critical);
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
