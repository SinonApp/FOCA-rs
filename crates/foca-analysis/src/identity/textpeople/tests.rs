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
