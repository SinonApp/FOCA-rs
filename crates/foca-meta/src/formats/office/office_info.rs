//! Office facts shared by the OLE2 and OOXML parsers: product release from `AppVersion`,
//! Windows language identifiers and code pages, the author's time zone derived from local
//! versus UTC timestamps, and the OS language hinted by localized default user names.

use foca_core::Metadata;

/// Release name of a Microsoft Office major version (`AppVersion` 12 = Office 2007).
/// Version 16 covers 2016, 2019, 2021, 2024 and Microsoft 365, so it stays open-ended.
pub(crate) fn office_release(major: u32) -> Option<&'static str> {
    Some(match major {
        8 => "97",
        9 => "2000",
        10 => "2002 (XP)",
        11 => "2003",
        12 => "2007",
        14 => "2010",
        15 => "2013",
        16 => "2016 or newer",
        _ => return None,
    })
}

/// Adds the release year to a versionless Microsoft Word/Excel/PowerPoint application name
/// (`Microsoft Office Word` + `12.0000` → `Microsoft Office Word 2007`) and records the
/// release in `office:release`. Names that already carry a year are left alone.
pub(crate) fn apply_app_version(meta: &mut Metadata, app_version: &str) {
    let Some(major) = app_version
        .trim()
        .split('.')
        .next()
        .and_then(|m| m.parse::<u32>().ok())
    else {
        return;
    };
    let Some(release) = office_release(major) else {
        return;
    };
    let Some(app) = meta.application.clone() else {
        return;
    };
    let lower = app.to_ascii_lowercase();
    // Office for Mac numbers its releases differently (12 = 2008)
    let ms_app = lower.starts_with("microsoft")
        && !lower.contains("macintosh")
        && ["word", "excel", "powerpoint"]
            .iter()
            .any(|p| lower.contains(p));
    let has_year = app
        .split(|c: char| !c.is_ascii_digit())
        .any(|d| d.len() == 4 && (d.starts_with("19") || d.starts_with("20")));
    if !ms_app || has_year {
        return;
    }
    meta.fields
        .insert("office:release".into(), release.to_string());
    // "2016 or newer" must not read as the single 2016 release to version matchers
    let named = if major == 16 {
        format!("{app} ({release})")
    } else {
        format!("{app} {release}")
    };
    meta.application = Some(named);
    // the software list keeps the numeric form, which signatures map to the right release
    let numeric = format!("{app} {major}.0000");
    let prefix = format!("{app} {major}.");
    if meta.software.iter().any(|s| s.starts_with(&prefix)) {
        meta.software.retain(|s| *s != app);
    } else if let Some(s) = meta.software.iter_mut().find(|s| **s == app) {
        *s = numeric;
    } else {
        Metadata::add_unique(&mut meta.software, &numeric);
    }
}

/// BCP 47 tag of a Windows language identifier (LCID / `lid`).
pub(crate) fn lcid_tag(lid: u16) -> Option<&'static str> {
    Some(match lid {
        0x0402 => "bg",
        0x0405 => "cs",
        0x0406 => "da",
        0x0407 => "de",
        0x0408 => "el",
        0x0409 => "en-US",
        0x0809 => "en-GB",
        0x040A | 0x0C0A => "es",
        0x040B => "fi",
        0x040C => "fr",
        0x040E => "hu",
        0x0410 => "it",
        0x0411 => "ja",
        0x0412 => "ko",
        0x0413 => "nl",
        0x0414 => "nb",
        0x0415 => "pl",
        0x0416 => "pt-BR",
        0x0816 => "pt-PT",
        0x0418 => "ro",
        0x0419 => "ru",
        0x041A => "hr",
        0x041B => "sk",
        0x041D => "sv",
        0x041F => "tr",
        0x0422 => "uk",
        0x0423 => "be",
        0x0425 => "et",
        0x0426 => "lv",
        0x0427 => "lt",
        0x042B => "hy",
        0x042C => "az",
        0x0437 => "ka",
        0x043F => "kk",
        0x0443 => "uz",
        0x0804 => "zh-CN",
        0x0404 => "zh-TW",
        0x0C1A => "sr",
        0x0424 => "sl",
        0x040D => "he",
        0x0401 => "ar",
        _ => return None,
    })
}

/// Name of a Windows code page.
pub(crate) fn codepage_name(cp: u16) -> Option<&'static str> {
    Some(match cp {
        874 => "Thai",
        932 => "Japanese (Shift-JIS)",
        936 => "Simplified Chinese (GBK)",
        949 => "Korean",
        950 => "Traditional Chinese (Big5)",
        1200 => "UTF-16",
        1250 => "Windows Central European",
        1251 => "Windows Cyrillic",
        1252 => "Windows Latin 1",
        1253 => "Windows Greek",
        1254 => "Windows Turkish",
        1255 => "Windows Hebrew",
        1256 => "Windows Arabic",
        1257 => "Windows Baltic",
        1258 => "Windows Vietnamese",
        10000 => "Mac Roman",
        65001 => "UTF-8",
        _ => return None,
    })
}

/// Time zone of the author's machine from pairs of the same moment written in local time
/// and in UTC (minutes since an epoch). Returns `UTC+03:00` only when every pair agrees on
/// a whole quarter-hour offset within the real range and at least two pairs exist.
pub(crate) fn tz_offset(pairs: &[(i64, i64)]) -> Option<String> {
    if pairs.len() < 2 {
        return None;
    }
    let first = pairs[0].0 - pairs[0].1;
    // local DTTM values drop the seconds, so a pair may differ by one minute
    if pairs
        .iter()
        .any(|(l, u)| ((l - u) - first).abs() > 1 || !(-12 * 60..=14 * 60).contains(&(l - u)))
    {
        return None;
    }
    let off = ((first as f64) / 15.0).round() as i64 * 15;
    if (first - off).abs() > 1 {
        return None;
    }
    let sign = if off < 0 { '-' } else { '+' };
    Some(format!(
        "UTC{sign}{:02}:{:02}",
        off.abs() / 60,
        off.abs() % 60
    ))
}

/// Wall-clock minutes since the Unix epoch of a Word DTTM (minute, hour, day, month and
/// year since 1900 packed in 32 bits), read as if it were UTC.
pub(crate) fn dttm_minutes(v: u32) -> Option<i64> {
    if v == 0 {
        return None;
    }
    let minute = (v & 0x3F) as u8;
    let hour = ((v >> 6) & 0x1F) as u8;
    let day = ((v >> 11) & 0x1F) as u8;
    let month = time::Month::try_from(((v >> 16) & 0x0F) as u8).ok()?;
    let year = 1900 + ((v >> 20) & 0x1FF) as i32;
    let date = time::Date::from_calendar_date(year, month, day).ok()?;
    let t = time::Time::from_hms(hour, minute, 0).ok()?;
    Some(date.with_time(t).assume_utc().unix_timestamp() / 60)
}

/// Minutes since the Unix epoch of an RFC 3339 timestamp.
pub(crate) fn iso_minutes(s: &str) -> Option<i64> {
    let t = time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339).ok()?;
    Some(t.unix_timestamp().div_euclid(60))
}

/// Localized names Windows and Office give the default account; the language of the name
/// hints at the language of the author's OS.
const DEFAULT_USERS: &[(&str, &str)] = &[
    ("пользователь", "ru"),
    ("администратор", "ru"),
    ("користувач", "uk"),
    ("адміністратор", "uk"),
    ("карыстальнік", "be"),
    ("benutzer", "de"),
    ("utilisateur", "fr"),
    ("usuario", "es"),
    ("utente", "it"),
    ("użytkownik", "pl"),
    ("uživatel", "cs"),
    ("kullanıcı", "tr"),
];

/// Records `os:locale_hint` when the author or last editor of any document format is a
/// localized default account.
pub(crate) fn locale_hint(meta: &mut Metadata) {
    let names = [meta.author.as_deref(), meta.last_modified_by.as_deref()];
    let hint = names.into_iter().flatten().find_map(|n| {
        let n = n.trim().to_lowercase();
        DEFAULT_USERS
            .iter()
            .find(|(u, _)| n == *u)
            .map(|(_, lang)| *lang)
    });
    if let Some(lang) = hint {
        meta.fields.insert("os:locale_hint".into(), lang.into());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use foca_core::DocFormat;

    #[test]
    fn app_version_adds_release() {
        let mut m = Metadata::new(DocFormat::Doc);
        m.application = Some("Microsoft Office Word".into());
        m.software = vec!["Microsoft Office Word".into()];
        apply_app_version(&mut m, "12.0000");
        assert_eq!(m.application.as_deref(), Some("Microsoft Office Word 2007"));
        assert_eq!(
            m.software,
            vec!["Microsoft Office Word 12.0000".to_string()]
        );
        assert_eq!(
            m.fields.get("office:release").map(String::as_str),
            Some("2007")
        );

        let mut m = Metadata::new(DocFormat::Xlsx);
        m.application = Some("Microsoft Excel".into());
        apply_app_version(&mut m, "16.0300");
        assert_eq!(
            m.application.as_deref(),
            Some("Microsoft Excel (2016 or newer)")
        );
        assert!(m.software.contains(&"Microsoft Excel 16.0000".to_string()));

        // a year already present, other vendors and unknown majors stay untouched
        for (app, v) in [
            ("Microsoft Office Word 2003", "11.0000"),
            ("LibreOffice/7.6", "15.0000"),
            ("Microsoft Macintosh Word", "12.0000"),
            ("Microsoft Office Word", "13.0000"),
            ("Microsoft Office Word", "x"),
        ] {
            let mut m = Metadata::new(DocFormat::Doc);
            m.application = Some(app.into());
            apply_app_version(&mut m, v);
            assert_eq!(m.application.as_deref(), Some(app));
            assert!(!m.fields.contains_key("office:release"));
        }
    }

    #[test]
    fn releases_and_languages() {
        assert_eq!(office_release(8), Some("97"));
        assert_eq!(office_release(10), Some("2002 (XP)"));
        assert_eq!(office_release(14), Some("2010"));
        assert_eq!(office_release(13), None);
        assert_eq!(lcid_tag(0x0419), Some("ru"));
        assert_eq!(lcid_tag(0x0422), Some("uk"));
        assert_eq!(lcid_tag(0x0001), None);
        assert_eq!(codepage_name(1251), Some("Windows Cyrillic"));
    }

    #[test]
    fn time_zone_needs_consistent_pairs() {
        let h = 60;
        assert_eq!(
            tz_offset(&[(1000 + 3 * h, 1000), (5000 + 3 * h, 5000)]).as_deref(),
            Some("UTC+03:00")
        );
        assert_eq!(
            tz_offset(&[(1000 - 5 * h - 30, 1000), (9000 - 5 * h - 31, 9000)]).as_deref(),
            Some("UTC-05:30")
        );
        // one pair, disagreeing pairs, odd offsets and impossible offsets give nothing
        assert_eq!(tz_offset(&[(1000 + 3 * h, 1000)]), None);
        assert_eq!(
            tz_offset(&[(1000 + 3 * h, 1000), (5000 + 2 * h, 5000)]),
            None
        );
        assert_eq!(tz_offset(&[(1007, 1000), (5007, 5000)]), None);
        assert_eq!(
            tz_offset(&[(1000 + 20 * h, 1000), (5000 + 20 * h, 5000)]),
            None
        );
    }

    #[test]
    fn dttm_and_iso() {
        // 2024-03-05 11:22 local
        let v = 22 | (11 << 6) | (5 << 11) | (3 << 16) | (124 << 20);
        let local = dttm_minutes(v).unwrap();
        let utc = iso_minutes("2024-03-05T08:22:41Z").unwrap();
        assert_eq!(local - utc, 180);
        assert_eq!(dttm_minutes(0), None);
        assert_eq!(dttm_minutes(0xFFFF_FFFF), None);
    }

    #[test]
    fn locale_hint_from_default_names() {
        let mut m = Metadata::new(DocFormat::Doc);
        m.author = Some("Пользователь".into());
        locale_hint(&mut m);
        assert_eq!(
            m.fields.get("os:locale_hint").map(String::as_str),
            Some("ru")
        );
        let mut m = Metadata::new(DocFormat::Doc);
        m.author = Some("User".into());
        m.last_modified_by = Some("Olena".into());
        locale_hint(&mut m);
        assert!(!m.fields.contains_key("os:locale_hint"));
    }
}
