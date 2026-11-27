//! Glue between text mentions and the identity resolver: identities to merge, attributes of the
//! merged people (title, unit, masked phones, identifier kinds) and the phone table.

use std::collections::{BTreeMap, BTreeSet};

use foca_core::api::Phone;

use super::{NameForm, TextScan};
use crate::people::{self, IdentSource, Identity, Resolved};

/// Identities of one document's text scan: every mention (role `text` or `signatory`) and every
/// e-mail written next to a single name, linked to that name.
pub fn identities(ts: &TextScan, doc: u64, out: &mut Vec<Identity>) {
    for m in &ts.people {
        let role = if m.signatory {
            "signatory"
        } else if m.cited {
            "cited"
        } else {
            "text"
        };
        out.push(Identity::new(&m.name, doc, IdentSource::Text, role));
        for e in &m.emails {
            out.push(Identity::new(e, doc, IdentSource::Text, "email").with_link(&m.name));
        }
    }
}

/// Masks a phone number: country code kept for E.164 values, last two digits kept
/// (`+38••••••••67`); values already masked at storage stay as they are.
pub fn mask_phone(v: &str) -> String {
    if v.contains('•') {
        return v.to_string();
    }
    let digits: Vec<char> = v.chars().filter(char::is_ascii_digit).collect();
    if digits.len() < 6 {
        return "••••".into();
    }
    let keep_head = if v.starts_with('+') {
        2.min(digits.len() - 4)
    } else {
        0
    };
    let head: String = digits[..keep_head].iter().collect();
    let tail: String = digits[digits.len() - 2..].iter().collect();
    let plus = if v.starts_with('+') { "+" } else { "" };
    format!(
        "{plus}{head}{}{tail}",
        "•".repeat(digits.len() - keep_head - 2)
    )
}

/// Attributes of one merged person collected from text mentions.
#[derive(Debug, Clone, Default)]
pub struct Attrs {
    pub title: Option<String>,
    pub unit: Option<String>,
    pub phones: Vec<String>,
    pub ids: Vec<String>,
    pub signatory: bool,
    /// Every text mention is in a bibliography entry or citation.
    pub cited: bool,
    /// First mention: (document, line).
    pub first: Option<(u64, u32)>,
}

fn most_common(c: &BTreeMap<String, u32>) -> Option<String> {
    c.iter()
        .max_by(|a, b| a.1.cmp(b.1).then(b.0.len().cmp(&a.0.len())))
        .map(|(k, _)| k.clone())
}

/// Text attributes per resolved cluster index.
pub fn attrs<'a>(
    scans: impl Iterator<Item = (u64, &'a TextScan)>,
    resolved: &Resolved,
) -> BTreeMap<usize, Attrs> {
    struct Acc {
        titles: BTreeMap<String, u32>,
        units: BTreeMap<String, u32>,
        phones: BTreeSet<String>,
        ids: BTreeSet<String>,
        signatory: bool,
        cited: bool,
        first: Option<(u64, u32)>,
    }
    let mut acc: BTreeMap<usize, Acc> = BTreeMap::new();
    for (doc, ts) in scans {
        for m in &ts.people {
            let Some(&ci) = resolved.by_key.get(&people::ident_key(&m.name)) else {
                continue;
            };
            let a = acc.entry(ci).or_insert_with(|| Acc {
                titles: BTreeMap::new(),
                units: BTreeMap::new(),
                phones: BTreeSet::new(),
                ids: BTreeSet::new(),
                signatory: false,
                cited: true,
                first: None,
            });
            if let Some(t) = &m.title {
                *a.titles.entry(t.clone()).or_default() += 1;
            }
            if let Some(u) = &m.unit {
                *a.units.entry(u.clone()).or_default() += 1;
            }
            a.phones.extend(m.phones.iter().map(|p| mask_phone(p)));
            a.ids.extend(m.ids.iter().map(|k| k.to_string()));
            a.signatory |= m.signatory;
            a.cited &= m.cited;
            if a.first.is_none() {
                a.first = Some((doc, m.line as u32));
            }
        }
    }
    acc.into_iter()
        .map(|(ci, a)| {
            (
                ci,
                Attrs {
                    title: most_common(&a.titles),
                    unit: most_common(&a.units),
                    phones: a.phones.into_iter().take(10).collect(),
                    ids: a.ids.into_iter().collect(),
                    signatory: a.signatory,
                    cited: a.cited,
                    first: a.first,
                },
            )
        })
        .collect()
}

/// The phone table: one row per number with its document count and the person it was written
/// next to (when the person is kept).
pub fn phones<'a>(
    scans: impl Iterator<Item = (u64, &'a TextScan)>,
    login_of: impl Fn(&str) -> Option<String>,
) -> Vec<Phone> {
    struct Row {
        country: &'static str,
        docs: BTreeSet<u64>,
        login: Option<String>,
    }
    let mut rows: BTreeMap<String, Row> = BTreeMap::new();
    for (doc, ts) in scans {
        for p in &ts.phones {
            let r = rows.entry(p.value.clone()).or_insert_with(|| Row {
                country: p.country,
                docs: BTreeSet::new(),
                login: None,
            });
            r.docs.insert(doc);
        }
        for m in &ts.people {
            for v in &m.phones {
                if let Some(r) = rows.get_mut(v) {
                    if r.login.is_none() {
                        r.login = login_of(&m.name);
                    }
                }
            }
        }
    }
    let mut out: Vec<Phone> = rows
        .into_iter()
        .map(|(v, r)| Phone {
            value: mask_phone(&v),
            country: r.country.to_string(),
            docs: r.docs.len() as u32,
            src_doc: r.docs.iter().next().copied(),
            login: r.login,
        })
        .collect();
    out.sort_by(|a, b| b.docs.cmp(&a.docs).then(a.value.cmp(&b.value)));
    out
}

/// Per-document counts: unique names and contacts / identifiers (addresses and legal-entity
/// codes are not personal contacts).
pub fn doc_counts(ts: &TextScan) -> (u32, u32) {
    let names: BTreeSet<&str> = ts
        .people
        .iter()
        .filter(|m| m.form != NameForm::GivenSurname || m.name.contains(' '))
        .map(|m| m.name.as_str())
        .collect();
    let contacts: u32 = ts
        .counts
        .iter()
        .filter(|(k, _)| !matches!(*k, "address" | "edrpou"))
        .map(|(_, n)| *n)
        .sum();
    (names.len() as u32, contacts)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phone_masks_keep_country_and_tail() {
        let v = format!("+38{}", "0501234567");
        assert_eq!(mask_phone(&v), "+38••••••••67");
        assert_eq!(mask_phone("••••••••67"), "••••••••67");
        assert!(!mask_phone(&v).contains("12345"));
    }
}
