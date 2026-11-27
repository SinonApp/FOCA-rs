use super::*;

fn names(t: &str) -> Vec<String> {
    scan(t).people.into_iter().map(|m| m.name).collect()
}

#[test]
fn ukrainian_forms() {
    let t = "Наказ підписав ректор Петренко Іван Васильович.\n\
             Доповідь Олени Миколаївни Коваленко та звіт Сидоренку Андрію Петровичу.\n\
             Керівник: доц. Бондар О.М., рецензент І. В. Мельник.\n";
    let n = names(t);
    assert!(n.contains(&"Петренко Іван Васильович".to_string()), "{n:?}");
    assert!(
        n.contains(&"Коваленко Олена Миколаївна".to_string()),
        "{n:?}"
    );
    assert!(
        n.contains(&"Сидоренко Андрій Петрович".to_string()),
        "{n:?}"
    );
    assert!(n.contains(&"Бондар О.М.".to_string()), "{n:?}");
    assert!(n.contains(&"Мельник І.В.".to_string()), "{n:?}");
}

#[test]
fn bibliography_authors_are_cited_staff_are_not() {
    let t = "Список джерел\n\
             12. Гончаренко Т.В. Адміністративне право : навч. посіб. К.: Вид-во, 2019. 210 с.\n\
             13. Carter E., Novak J. Data rules // Law Review. 2021. Vol. 3. pp. 1-9.\n\
             Завідувач кафедри доц. Мирошник О.П.\n";
    let s = scan(t);
    let cited = |n: &str| {
        s.people
            .iter()
            .find(|m| m.name.contains(n))
            .map(|m| m.cited)
    };
    assert_eq!(cited("Гончаренко"), Some(true));
    assert_eq!(cited("Carter"), Some(true));
    assert_eq!(cited("Мирошник"), Some(false));
}

#[test]
fn abstract_nouns_are_not_surnames() {
    let n = names("Відповідність Ольга Основна\nОрганізація Ірина Петрівна\n");
    assert!(
        n.iter()
            .all(|x| !x.starts_with("Відповідність") && !x.starts_with("Організація")),
        "{n:?}"
    );
}
