//! Small shared helpers: stable ids, dates, hosts from URLs, IP addresses.

use std::net::IpAddr;

/// Returns a stable id for the parts (FNV-1a 64, truncated to 53 bits to stay exact as a
/// JavaScript number).
pub fn stable_id(parts: &[&str]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for p in parts {
        for b in p.as_bytes() {
            h ^= u64::from(*b);
            h = h.wrapping_mul(0x0100_0000_01b3);
        }
        h ^= 0x1f;
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    let id = h & ((1u64 << 53) - 1);
    if id == 0 {
        1
    } else {
        id
    }
}

/// Converts a metadata date to ISO 8601 without zone or fractional seconds
/// (`2024-03-14T18:42:00`), i.e. the document's local time as the UI shows it. A bare date
/// becomes `T00:00:00`.
pub fn local_iso(raw: &str) -> Option<String> {
    let s = raw.trim();
    let b = s.as_bytes();
    if b.len() < 10
        || !b[..10].is_ascii()
        || !b[..4].iter().all(u8::is_ascii_digit)
        || b[4] != b'-'
        || b[7] != b'-'
    {
        return None;
    }
    let date = &s[..10];
    let year: i32 = date[..4].parse().ok()?;
    let month: u32 = date[5..7].parse().ok()?;
    let day: u32 = date[8..10].parse().ok()?;
    if !(1900..=2200).contains(&year) || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if b.len() >= 16 && b[..16].is_ascii() && (b[10] == b'T' || b[10] == b' ') {
        let hm = &s[11..16];
        let sec = if b.len() >= 19 && b[..19].is_ascii() && b[16] == b':' {
            &s[17..19]
        } else {
            "00"
        };
        if hm.as_bytes()[2] != b':' || !sec.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        return Some(format!("{date}T{hm}:{sec}"));
    }
    Some(format!("{date}T00:00:00"))
}

/// Returns the zone offset in minutes if the date has one (`+02:00`, `-0400`); `Z` is 0.
pub fn offset_minutes(raw: &str) -> Option<i32> {
    let s = raw.trim();
    let tail = s.get(19..)?;
    let tail = tail.trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());
    if tail.eq_ignore_ascii_case("z") {
        return Some(0);
    }
    let sign = match tail.chars().next()? {
        '+' => 1,
        '-' => -1,
        _ => return None,
    };
    let digits: String = tail[1..].chars().filter(char::is_ascii_digit).collect();
    if digits.len() != 4 {
        return None;
    }
    let h: i32 = digits[..2].parse().ok()?;
    let m: i32 = digits[2..].parse().ok()?;
    if h > 14 || m > 59 {
        return None;
    }
    Some(sign * (h * 60 + m))
}

/// `UTC+2`, `UTC-4`, `UTC+5:30`.
pub fn tz_label(min: i32) -> String {
    let sign = if min < 0 { '-' } else { '+' };
    let a = min.abs();
    if a % 60 == 0 {
        format!("UTC{sign}{}", a / 60)
    } else {
        format!("UTC{sign}{}:{:02}", a / 60, a % 60)
    }
}

/// Returns the host of a URL (lowercase, no port or userinfo). A Wayback wrapper
/// (`web.archive.org/web/<ts>/<url>`) is unwrapped to the original host.
pub fn url_host(url: &str) -> Option<String> {
    let u = url.trim();
    let lower = u.to_ascii_lowercase();
    if let Some(p) = lower.find("web.archive.org/web/") {
        let rest = &u[p + "web.archive.org/web/".len()..];
        if let Some(i) = rest.find('/') {
            let inner = &rest[i + 1..];
            if inner.contains("://") || inner.contains('.') {
                let inner = if inner.contains("://") {
                    inner.to_string()
                } else {
                    format!("http://{inner}")
                };
                return url_host(&inner);
            }
        }
    }
    let after = &lower[lower.find("://")? + 3..];
    let auth = after.split(['/', '?', '#']).next().unwrap_or("");
    let auth = auth.rsplit('@').next().unwrap_or(auth);
    let host = if let Some(stripped) = auth.strip_prefix('[') {
        stripped.split(']').next().unwrap_or("")
    } else {
        auth.split(':').next().unwrap_or("")
    };
    let host = host.trim_end_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host.to_string())
    }
}

/// Strips the port from a host name (`SRV-TS01.corp:3389` → `SRV-TS01.corp`).
pub fn strip_port(s: &str) -> &str {
    let s = s.trim();
    if s.starts_with('[') {
        return s.trim_start_matches('[').split(']').next().unwrap_or(s);
    }
    if s.matches(':').count() == 1 {
        s.split(':').next().unwrap_or(s)
    } else {
        s
    }
}

pub fn parse_ip(s: &str) -> Option<IpAddr> {
    s.trim().parse().ok()
}

/// Returns `true` for private or special-purpose addresses (RFC 1918, loopback,
/// link-local, ULA).
pub fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => v.is_private() || v.is_loopback() || v.is_link_local(),
        IpAddr::V6(v) => {
            v.is_loopback()
                || (v.segments()[0] & 0xfe00) == 0xfc00
                || (v.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Internal domain suffixes (Active Directory, home networks).
pub const INTERNAL_SUFFIXES: &[&str] = &[
    ".local",
    ".lan",
    ".corp",
    ".internal",
    ".intranet",
    ".localdomain",
    ".home.arpa",
    ".home",
    ".loc",
    ".priv",
];

/// Extracts the printer host from its name: `\\PRN01\HP` → `PRN01`,
/// `\\ipp://pc3.example.org\S` → `pc3.example.org` (the `ipp://`/`http://` scheme and the
/// port are dropped).
pub fn printer_host(name: &str) -> Option<String> {
    let rest = name.strip_prefix("\\\\")?;
    let rest = match rest.find("://") {
        Some(i) if rest[..i].chars().all(|c| c.is_ascii_alphanumeric()) => &rest[i + 3..],
        _ => rest,
    };
    let h = rest.split(['\\', '/']).next().unwrap_or("");
    let h = match h.rsplit_once(':') {
        Some((a, p)) if !a.contains(':') && p.chars().all(|c| c.is_ascii_digit()) => a,
        _ => h,
    };
    (!h.is_empty()).then(|| h.to_string())
}

pub fn is_internal_fqdn(name: &str) -> bool {
    let l = name.to_ascii_lowercase();
    INTERNAL_SUFFIXES.iter().any(|s| l.ends_with(s)) || l.contains(".corp.")
}

/// Returns year, month, day and hour of a local ISO date.
pub fn ymdh(iso: &str) -> Option<(i32, u32, u32, u32)> {
    let y = iso.get(..4)?.parse().ok()?;
    let m = iso.get(5..7)?.parse().ok()?;
    let d = iso.get(8..10)?.parse().ok()?;
    let h = iso.get(11..13).and_then(|x| x.parse().ok()).unwrap_or(0);
    Some((y, m, d, h))
}

/// Returns the weekday (0 = Monday) in the Gregorian calendar.
pub fn weekday(y: i32, m: u32, d: u32) -> u32 {
    let t = [0, 3, 2, 5, 0, 3, 5, 1, 4, 6, 2, 4];
    let y = if m < 3 { y - 1 } else { y };
    let w = (y + y / 4 - y / 100 + y / 400 + t[(m as usize - 1) % 12] + d as i32).rem_euclid(7);
    // Here w = 0 is Sunday.
    ((w + 6) % 7) as u32
}

/// Days since 1970-01-01 of a Gregorian date (Howard Hinnant's `days_from_civil`).
pub fn days_from_civil(y: i32, m: u32, d: u32) -> i64 {
    let y = i64::from(if m <= 2 { y - 1 } else { y });
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// A metadata date as seconds since the Unix epoch. The flag tells whether the zone was known:
/// without it the value is the document's local time and comparisons need a ±14 h tolerance.
pub fn instant(raw: &str) -> Option<(i64, bool)> {
    let l = local_iso(raw)?;
    let (y, m, d, h) = ymdh(&l)?;
    let mi: i64 = l.get(14..16)?.parse().ok()?;
    let s: i64 = l.get(17..19)?.parse().ok()?;
    let t = days_from_civil(y, m, d) * 86_400 + i64::from(h) * 3_600 + mi * 60 + s;
    match offset_minutes(raw) {
        Some(off) => Some((t - i64::from(off) * 60, true)),
        None => Some((t, false)),
    }
}

/// Splits a UNC path (`\\SRV\Share\Dir\file.docx`, `//srv/share`, `file://srv/share/...`)
/// into host, share and the folders below the share (the file name is dropped when the last
/// component has an extension).
pub fn unc_parts(path: &str) -> Option<(String, Option<String>, Vec<String>)> {
    let mut p = path.trim();
    if let Some(rest) = p.strip_prefix("file:") {
        p = rest.trim_start_matches('/');
        if p.starts_with("\\\\") {
            p = &p[2..];
        } else if p.len() > 1 && p.as_bytes()[1] == b':' {
            return None;
        }
    } else {
        p = p.strip_prefix("\\\\").or_else(|| p.strip_prefix("//"))?;
    }
    let mut parts = p.split(['\\', '/']).filter(|s| !s.is_empty());
    let host = parts.next()?.trim();
    if host.is_empty() || host == "?" || host == "." || (host.contains(':') && !host.contains('.'))
    {
        return None;
    }
    let share = parts.next().map(str::to_string);
    let mut rest: Vec<String> = parts.map(str::to_string).collect();
    if rest.last().is_some_and(|l| {
        l.rsplit_once('.')
            .is_some_and(|(a, e)| !a.is_empty() && (1..=5).contains(&e.len()))
    }) {
        rest.pop();
    }
    Some((host.to_string(), share, rest))
}

/// Severity name, used for ordering and comparison.
pub fn sev_name(s: foca_core::Severity) -> &'static str {
    match s {
        foca_core::Severity::Critical => "crit",
        foca_core::Severity::High => "high",
        foca_core::Severity::Medium => "warn",
        foca_core::Severity::Low => "low",
        foca_core::Severity::Info => "info",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(
            local_iso("2024-03-14T18:42:00+02:00").as_deref(),
            Some("2024-03-14T18:42:00")
        );
        assert_eq!(
            local_iso("2022-05-17T10:11:12.345000000").as_deref(),
            Some("2022-05-17T10:11:12")
        );
        assert_eq!(
            local_iso("2024-03-01T08:15:00Z").as_deref(),
            Some("2024-03-01T08:15:00")
        );
        assert_eq!(
            local_iso("2024-03-01").as_deref(),
            Some("2024-03-01T00:00:00")
        );
        assert_eq!(local_iso("garbage"), None);
        assert_eq!(offset_minutes("2024-03-14T18:42:00+02:00"), Some(120));
        assert_eq!(offset_minutes("2005-07-18T14:30:45-04:00"), Some(-240));
        assert_eq!(offset_minutes("2024-03-01T08:15:00Z"), Some(0));
        assert_eq!(offset_minutes("2024-03-01T08:15:00"), None);
        assert_eq!(tz_label(120), "UTC+2");
        assert_eq!(tz_label(-240), "UTC-4");
        assert_eq!(weekday(2026, 11, 20), 4); // Friday
    }

    #[test]
    fn hosts() {
        assert_eq!(
            url_host("https://Files.Contoso.example:443/x/y.pdf").as_deref(),
            Some("files.contoso.example")
        );
        assert_eq!(
            url_host("https://web.archive.org/web/20240101000000/https://agro.example/a.pdf")
                .as_deref(),
            Some("agro.example")
        );
        assert_eq!(
            url_host("ftp://u:p@10.0.0.1/x").as_deref(),
            Some("10.0.0.1")
        );
        assert_eq!(url_host("no-scheme"), None);
        assert_eq!(strip_port("SRV-TS01.corp:3389"), "SRV-TS01.corp");
        assert!(is_private_ip("10.10.1.40".parse().unwrap()));
        assert!(!is_private_ip("203.0.113.10".parse().unwrap()));
        assert!(is_internal_fqdn("sql02.corp.contoso.local"));
        assert_ne!(stable_id(&["a", "b"]), stable_id(&["ab"]));
        assert!(stable_id(&["x"]) < (1 << 53));
    }
}

#[cfg(test)]
mod printer_tests {
    use super::*;

    #[test]
    fn printer_host_and_internal_zones() {
        assert_eq!(printer_host("\\\\PRN01\\HP 404").as_deref(), Some("PRN01"));
        assert_eq!(
            printer_host("\\\\ipp://pc3.corp.example:631\\S").as_deref(),
            Some("pc3.corp.example")
        );
        assert_eq!(printer_host("HP LaserJet"), None);
        for h in [
            "hq05.wsdot.loc",
            "a.corp",
            "b.home.arpa",
            "c.lan",
            "d.local",
            "e.intranet",
            "f.internal",
            "g.home",
        ] {
            assert!(is_internal_fqdn(h), "{h}");
        }
        assert!(!is_internal_fqdn("example.org"));
    }
}

#[cfg(test)]
mod local_iso_tests {
    use super::*;

    #[test]
    fn non_ascii_does_not_panic() {
        // A multi-byte character on the 10th, 16th or 19th byte boundary must not panic on slicing.
        assert_eq!(local_iso("2024-01-0ё"), None);
        let _ = local_iso("2024-01-01Tё0:00"); // must not panic
        assert_eq!(
            local_iso("2024-01-01T12:00:ё0").as_deref(),
            Some("2024-01-01T12:00:00")
        );
        assert_eq!(offset_minutes("2024-01-01T12:00:0ё+02:00"), None);
        assert!(local_iso("2024-01-01").is_some());
    }
}
