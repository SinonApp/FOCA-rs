//! Slavic morphology: case forms of given names, patronymics and surnames back to the
//! nominative (Ukrainian, Russian, Belarusian, Kazakh patronymic words).

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gender {
    Male,
    Female,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Case {
    Nom,
    Gen,
    Dat,
    Acc,
    Ins,
}

/// Lowercases and folds apostrophe variants to `'`.
pub fn fold(w: &str) -> String {
    w.chars()
        .map(|c| match c {
            '’' | 'ʼ' | '`' | '´' => '\'',
            c => c,
        })
        .flat_map(char::to_lowercase)
        .collect()
}

/// Case forms (lowercase) of a Slavic given name, nominative excluded.
pub fn given_forms(nom: &str, g: Gender, _lang: &str) -> Vec<(String, Case)> {
    let mut forms = Vec::new();
    match g {
        Gender::Female => expand_female(&mut forms, nom),
        _ => expand_male(&mut forms, nom),
    }
    forms
}

fn expand_male(forms: &mut Vec<(String, Case)>, nom: &str) {
    let l = nom.to_lowercase();
    forms.push((l.clone(), Case::Nom));
    let irregular: &[(&str, &str)] = &[("павел", "павл"), ("лев", "льв"), ("пётр", "петр")];
    if let Some((_, stem)) = irregular.iter().find(|(n, _)| *n == l) {
        for (suf, c) in [("а", Case::Gen), ("у", Case::Dat), ("ом", Case::Ins)] {
            forms.push((format!("{stem}{suf}"), c));
        }
        return;
    }
    if let Some(stem) = l.strip_suffix("ій").or_else(|| l.strip_suffix("ей")) {
        for (suf, c) in [
            ("ія", Case::Gen),
            ("ію", Case::Dat),
            ("ієві", Case::Dat),
            ("ієм", Case::Ins),
            ("ея", Case::Gen),
            ("ею", Case::Dat),
            ("еем", Case::Ins),
            ("еєм", Case::Ins),
        ] {
            forms.push((format!("{stem}{suf}"), c));
        }
        return;
    }
    if let Some(stem) = l.strip_suffix("ий") {
        for (suf, c) in [("ия", Case::Gen), ("ию", Case::Dat), ("ием", Case::Ins)] {
            forms.push((format!("{stem}{suf}"), c));
        }
        return;
    }
    if let Some(stem) = l.strip_suffix('ь') {
        for (suf, c) in [
            ("я", Case::Gen),
            ("ю", Case::Dat),
            ("ем", Case::Ins),
            ("еві", Case::Dat),
        ] {
            forms.push((format!("{stem}{suf}"), c));
        }
        return;
    }
    if let Some(stem) = l.strip_suffix("ля") {
        // Ілля: Іллі, Іллю, Іллею.
        for (suf, c) in [("лі", Case::Gen), ("лю", Case::Acc), ("лею", Case::Ins)] {
            forms.push((format!("{stem}{suf}"), c));
        }
        return;
    }
    let stem = l.strip_suffix('о').unwrap_or(&l);
    for (suf, c) in [
        ("а", Case::Gen),
        ("у", Case::Dat),
        ("ові", Case::Dat),
        ("ом", Case::Ins),
        ("я", Case::Gen),
        ("ю", Case::Dat),
        ("еві", Case::Dat),
        ("ем", Case::Ins),
    ] {
        forms.push((format!("{stem}{suf}"), c));
    }
}

fn expand_female(forms: &mut Vec<(String, Case)>, nom: &str) {
    let l = nom.to_lowercase();
    forms.push((l.clone(), Case::Nom));
    if let Some(stem) = l.strip_suffix("ія").or_else(|| l.strip_suffix("ия")) {
        for (suf, c) in [
            ("ії", Case::Gen),
            ("ію", Case::Acc),
            ("ією", Case::Ins),
            ("ии", Case::Gen),
            ("ию", Case::Acc),
            ("ией", Case::Ins),
        ] {
            forms.push((format!("{stem}{suf}"), c));
        }
    } else if let Some(stem) = l.strip_suffix('я') {
        for (suf, c) in [
            ("і", Case::Gen),
            ("ї", Case::Gen),
            ("ю", Case::Acc),
            ("ею", Case::Ins),
            ("єю", Case::Ins),
            ("и", Case::Gen),
            ("ей", Case::Ins),
            ("е", Case::Dat),
        ] {
            forms.push((format!("{stem}{suf}"), c));
        }
    } else if let Some(stem) = l.strip_suffix('а') {
        let dat = match stem.chars().last() {
            Some('г') => format!("{}зі", &stem[..stem.len() - 'г'.len_utf8()]),
            Some('к') => format!("{}ці", &stem[..stem.len() - 'к'.len_utf8()]),
            Some('х') => format!("{}сі", &stem[..stem.len() - 'х'.len_utf8()]),
            _ => format!("{stem}і"),
        };
        forms.push((dat, Case::Dat));
        for (suf, c) in [
            ("и", Case::Gen),
            ("і", Case::Dat),
            ("у", Case::Acc),
            ("ою", Case::Ins),
            ("ы", Case::Gen),
            ("е", Case::Dat),
            ("ой", Case::Ins),
        ] {
            forms.push((format!("{stem}{suf}"), c));
        }
    } else if l.ends_with('ь') || l.ends_with('в') {
        let stem = l.strip_suffix('ь').unwrap_or(&l);
        for (suf, c) in [
            ("і", Case::Gen),
            ("'ю", Case::Ins),
            ("’ю", Case::Ins),
            ("ью", Case::Ins),
        ] {
            forms.push((format!("{stem}{suf}"), c));
        }
    }
}

/// Patronymic endings: (ending, nominative ending, gender, case).
const PATRO_SUFFIXES: &[(&str, &str, Gender, Case)] = &[
    ("авіча", "авіч", Gender::Male, Case::Gen),
    ("евіча", "евіч", Gender::Male, Case::Gen),
    ("авіч", "авіч", Gender::Male, Case::Nom),
    ("евіч", "евіч", Gender::Male, Case::Nom),
    ("аўны", "аўна", Gender::Female, Case::Gen),
    ("оўны", "оўна", Gender::Female, Case::Gen),
    ("оўна", "оўна", Gender::Female, Case::Nom),
    ("еўны", "еўна", Gender::Female, Case::Gen),
    ("аўна", "аўна", Gender::Female, Case::Nom),
    ("еўна", "еўна", Gender::Female, Case::Nom),
    ("ұлы", "ұлы", Gender::Male, Case::Nom),
    ("улы", "улы", Gender::Male, Case::Nom),
    ("қызы", "қызы", Gender::Female, Case::Nom),
    ("кызы", "кызы", Gender::Female, Case::Nom),
    ("овичеві", "ович", Gender::Male, Case::Dat),
    ("евичеві", "евич", Gender::Male, Case::Dat),
    ("овичем", "ович", Gender::Male, Case::Ins),
    ("евичем", "евич", Gender::Male, Case::Ins),
    ("овича", "ович", Gender::Male, Case::Gen),
    ("евича", "евич", Gender::Male, Case::Gen),
    ("овичу", "ович", Gender::Male, Case::Dat),
    ("евичу", "евич", Gender::Male, Case::Dat),
    ("овиче", "ович", Gender::Male, Case::Dat),
    ("евиче", "евич", Gender::Male, Case::Dat),
    ("ович", "ович", Gender::Male, Case::Nom),
    ("евич", "евич", Gender::Male, Case::Nom),
    ("івною", "івна", Gender::Female, Case::Ins),
    ("ївною", "ївна", Gender::Female, Case::Ins),
    ("івни", "івна", Gender::Female, Case::Gen),
    ("ївни", "ївна", Gender::Female, Case::Gen),
    ("івні", "івна", Gender::Female, Case::Dat),
    ("ївні", "ївна", Gender::Female, Case::Dat),
    ("івну", "івна", Gender::Female, Case::Acc),
    ("ївну", "ївна", Gender::Female, Case::Acc),
    ("івна", "івна", Gender::Female, Case::Nom),
    ("ївна", "ївна", Gender::Female, Case::Nom),
    ("овной", "овна", Gender::Female, Case::Ins),
    ("евной", "евна", Gender::Female, Case::Ins),
    ("овны", "овна", Gender::Female, Case::Gen),
    ("евны", "евна", Gender::Female, Case::Gen),
    ("овне", "овна", Gender::Female, Case::Dat),
    ("евне", "евна", Gender::Female, Case::Dat),
    ("овну", "овна", Gender::Female, Case::Acc),
    ("евну", "евна", Gender::Female, Case::Acc),
    ("овна", "овна", Gender::Female, Case::Nom),
    ("евна", "евна", Gender::Female, Case::Nom),
    ("ичною", "ична", Gender::Female, Case::Ins),
    ("ичної", "ична", Gender::Female, Case::Gen),
    ("ичній", "ична", Gender::Female, Case::Dat),
    ("ичну", "ична", Gender::Female, Case::Acc),
    ("ична", "ична", Gender::Female, Case::Nom),
    ("ичной", "ична", Gender::Female, Case::Ins),
    ("ичны", "ична", Gender::Female, Case::Gen),
];

/// Patronymic in any case: (nominative, gender, case). `Васильовичу` → `Васильович`.
pub fn patronymic(word: &str) -> Option<(String, Gender, Case)> {
    let f = fold(word);
    if f.chars().count() < 6 || !f.chars().all(|c| c.is_alphabetic() || c == '\'') {
        return None;
    }
    for (suf, nom_suf, g, c) in PATRO_SUFFIXES {
        let Some(stem) = f.strip_suffix(suf) else {
            continue;
        };
        if stem.chars().count() < 2 {
            return None;
        }
        // Female `-ична` patronymics come only from a few names (Іллічна, Кузьмінична,
        // Саввична); other `-ична` words are adjectives.
        let ichna_ok = ["лл", "ін", "ьм", "вв", "ин"]
            .iter()
            .any(|e| stem.ends_with(e));
        if suf.starts_with("ичн") && !ichna_ok {
            return None;
        }
        return Some((title_case(&format!("{stem}{nom_suf}")), *g, *c));
    }
    None
}

/// `ПЕТРЕНКО` → `Петренко`, `КОВАЛЬ-ЛИСЕНКО` → `Коваль-Лисенко`.
pub fn title_case(w: &str) -> String {
    let mut out = String::with_capacity(w.len());
    let mut start = true;
    for c in w.chars() {
        if start {
            out.extend(c.to_uppercase());
        } else {
            out.extend(c.to_lowercase());
        }
        start = c == '-';
    }
    out
}

/// Replaces a suffix keeping the capitalisation of the stem.
fn swap(w: &str, lower: &str, from: &str, to: &str) -> Option<String> {
    let stem_len = lower.strip_suffix(from)?.len();
    if w[..stem_len].chars().count() < 2 {
        return None;
    }
    Some(format!("{}{to}", &w[..stem_len]))
}

/// Brings a surname to the nominative when gender and case are known. Unknown endings are
/// left as they are (the resolver tolerates small differences in long surnames).
pub fn surname_nom(w: &str, g: Gender, c: Case) -> String {
    let w = &title_case(w);
    let l = fold(w);
    if c == Case::Nom {
        return w.clone();
    }
    let rules: &[(&str, &str)] = match (g, c) {
        (Gender::Male, Case::Gen | Case::Acc) => &[
            ("енка", "енко"),
            ("ського", "ський"),
            ("цького", "цький"),
            ("зького", "зький"),
            ("ского", "ский"),
            ("цкого", "цкий"),
            ("ього", "ій"),
            ("ого", "ий"),
            ("ова", "ов"),
            ("ева", "ев"),
            ("єва", "єв"),
            ("іна", "ін"),
            ("їна", "їн"),
            ("ина", "ин"),
            ("ія", "ій"),
            ("ея", "ей"),
            ("ля", "ль"),
            ("ня", "нь"),
            ("ря", "р"),
            ("а", ""),
        ],
        (Gender::Male, Case::Dat) => &[
            ("енкові", "енко"),
            ("енку", "енко"),
            ("ському", "ський"),
            ("цькому", "цький"),
            ("скому", "ский"),
            ("ьому", "ій"),
            ("ому", "ий"),
            ("ову", "ов"),
            ("еву", "ев"),
            ("іну", "ін"),
            ("ину", "ин"),
            ("ієві", "ій"),
            ("еві", "ь"),
            ("ові", ""),
            ("ію", "ій"),
            ("лю", "ль"),
            ("у", ""),
        ],
        (Gender::Male, Case::Ins) => &[
            ("енком", "енко"),
            ("ським", "ський"),
            ("цьким", "цький"),
            ("ским", "ский"),
            ("овим", "ов"),
            ("евим", "ев"),
            ("іним", "ін"),
            ("иним", "ин"),
            ("овым", "ов"),
            ("евым", "ев"),
            ("иным", "ин"),
            ("ім", "ій"),
            ("им", "ий"),
            ("ієм", "ій"),
            ("лем", "ль"),
            ("ом", ""),
        ],
        (Gender::Female, Case::Gen) => &[
            ("ської", "ська"),
            ("цької", "цька"),
            ("ской", "ская"),
            ("цкой", "цкая"),
            ("ової", "ова"),
            ("евої", "ева"),
            ("іної", "іна"),
            ("иної", "ина"),
            ("овой", "ова"),
            ("евой", "ева"),
            ("иной", "ина"),
            ("ої", "а"),
        ],
        (Gender::Female, Case::Dat) => &[
            ("ській", "ська"),
            ("цькій", "цька"),
            ("ской", "ская"),
            ("овій", "ова"),
            ("евій", "ева"),
            ("іній", "іна"),
            ("овой", "ова"),
            ("иной", "ина"),
        ],
        (Gender::Female, Case::Acc) => &[
            ("ську", "ська"),
            ("цьку", "цька"),
            ("скую", "ская"),
            ("ову", "ова"),
            ("еву", "ева"),
            ("іну", "іна"),
            ("ину", "ина"),
        ],
        (Gender::Female, Case::Ins) => &[
            ("ською", "ська"),
            ("цькою", "цька"),
            ("ской", "ская"),
            ("овою", "ова"),
            ("евою", "ева"),
            ("іною", "іна"),
            ("овой", "ова"),
            ("иной", "ина"),
            ("ою", "а"),
        ],
        _ => &[],
    };
    for (from, to) in rules {
        if let Some(s) = swap(w, &l, from, to) {
            return s;
        }
    }
    w.clone()
}

/// Case-independent normalisation for a surname seen without a given name (`Петренку І.В.`):
/// only endings that no nominative surname has.
pub fn surname_guess(w: &str) -> String {
    let w = &title_case(w);
    let l = fold(w);
    let rules: &[(&str, &str)] = &[
        ("енкові", "енко"),
        ("енка", "енко"),
        ("енку", "енко"),
        ("енком", "енко"),
        ("ського", "ський"),
        ("ському", "ський"),
        ("ським", "ський"),
        ("цького", "цький"),
        ("цькому", "цький"),
        ("цьким", "цький"),
        ("ської", "ська"),
        ("ській", "ська"),
        ("ською", "ська"),
        ("цької", "цька"),
        ("цькій", "цька"),
        ("цькою", "цька"),
        ("ової", "ова"),
        ("овій", "ова"),
        ("овою", "ова"),
        ("евої", "ева"),
        ("евою", "ева"),
        ("івої", "іва"),
        ("іної", "іна"),
        ("іною", "іна"),
        ("ового", "ов"),
        ("ової", "ова"),
        ("ником", "ник"),
        ("никові", "ник"),
        ("чуком", "чук"),
        ("чукові", "чук"),
        ("юком", "юк"),
        ("юкові", "юк"),
    ];
    for (from, to) in rules {
        if let Some(s) = swap(w, &l, from, to) {
            return s;
        }
    }
    w.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn given_names_in_cases() {
        let given = |w: &str| {
            super::super::lang::registry()
                .given(w)
                .map(|g| (g.nom.clone(), g.gender, g.case))
        };
        assert_eq!(given("Івану").map(|g| g.0).as_deref(), Some("Іван"));
        assert_eq!(
            given("Олени").map(|g| (g.0, g.1)),
            Some(("Олена".into(), Gender::Female))
        );
        assert_eq!(given("Сергієм").map(|g| g.0).as_deref(), Some("Сергій"));
        assert_eq!(given("Ользі").map(|g| g.0).as_deref(), Some("Ольга"));
        assert_eq!(given("Марії").map(|g| g.0).as_deref(), Some("Марія"));
        assert_eq!(given("Петра").map(|g| g.0).as_deref(), Some("Петро"));
        assert_eq!(given("Ігоря").map(|g| g.0).as_deref(), Some("Ігор"));
        assert_eq!(given("Мар’яна").map(|g| g.0).as_deref(), Some("Мар'яна"));
        assert!(given("Кафедра").is_none());
    }

    #[test]
    fn patronymics() {
        let p = patronymic("Васильовичу").unwrap();
        assert_eq!(
            (p.0.as_str(), p.1, p.2),
            ("Васильович", Gender::Male, Case::Dat)
        );
        let p = patronymic("ІВАНІВНОЮ").unwrap();
        assert_eq!(
            (p.0.as_str(), p.1, p.2),
            ("Іванівна", Gender::Female, Case::Ins)
        );
        assert_eq!(patronymic("Сергеевна").unwrap().0, "Сергеевна");
        assert!(patronymic("публічна").is_none());
        assert!(patronymic("технічна").is_none());
        assert!(patronymic("Ович").is_none());
    }

    #[test]
    fn surnames_back_to_nominative() {
        use Case::*;
        use Gender::*;
        assert_eq!(surname_nom("Петренка", Male, Gen), "Петренко");
        assert_eq!(surname_nom("Іванову", Male, Dat), "Іванов");
        assert_eq!(surname_nom("Ковальським", Male, Ins), "Ковальський");
        assert_eq!(surname_nom("МЕЛЬНИКА", Male, Gen), "Мельник");
        assert_eq!(surname_nom("Коваля", Male, Gen), "Коваль");
        assert_eq!(surname_nom("Іванової", Female, Gen), "Іванова");
        assert_eq!(surname_nom("Петренко", Female, Dat), "Петренко");
        assert_eq!(surname_nom("Шевчук", Female, Ins), "Шевчук");
        assert_eq!(surname_nom("Лисенко", Male, Nom), "Лисенко");
        assert_eq!(surname_guess("Шевченка"), "Шевченко");
        assert_eq!(surname_guess("Бойко"), "Бойко");
        assert_eq!(title_case("КОВАЛЬ-ЛИСЕНКО"), "Коваль-Лисенко");
    }
}
