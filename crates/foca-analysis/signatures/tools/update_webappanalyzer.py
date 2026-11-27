#!/usr/bin/env python3
"""Ingest enthec/webappanalyzer (GPL-3.0) into `crates/foca-recon/data/webappanalyzer.json.gz`.

Keeps only what FOCA-rs can evaluate without a JS engine: response headers, cookies, `<meta>`,
HTML regexes, `<script src>` and page URL regexes, plus `implies`/`requires`/`excludes`, `cpe`,
`website` and the first category (translated to the category names of `data/tech.json`). DNS
rules (MX/TXT/NS/CNAME/SOA) go to `crates/foca-net/data/saas_dns.json` for `intel::saas`.
Dropped fields: js, dom, xhr, css, text, icon, description, saas, pricing, oss, certIssuer,
probe, robots.

Every regex is compiled with the Rust `regex` crate (`examples/regex_check.rs`); patterns it
rejects (lookarounds, backreferences) are skipped and counted in `sources.lock.json`.

Each pattern is stored as `[regex, version_template, confidence, literal]` (trailing empty items
dropped). `literal` is a lowercase substring every match must contain: the engine looks it up
with one Aho-Corasick pass and compiles/runs the regex only when it is present.

Usage: python3 update_webappanalyzer.py [--repin]
"""

import json
import re

import sigsrc

NAME = "webappanalyzer"
REPO = "enthec/webappanalyzer"
COMMIT = "7dba7bf3e8b4f25c6a5b4b2c9f5e7a0e73e6a1bf"
OUT = sigsrc.REPO / "crates/foca-recon/data/webappanalyzer.json.gz"
OUT_DNS = sigsrc.REPO / "crates/foca-net/data/saas_dns.json"
FILES = [f"src/technologies/{c}.json" for c in "_abcdefghijklmnopqrstuvwxyz"] + [
    "src/categories.json", "LICENSE"]

# webappanalyzer name -> name used by the hand rules in data/tech.json (merged at runtime).
ALIASES = {
    "TYPO3 CMS": "TYPO3",
    "inSales": "InSales",
    "Atlassian Confluence": "Confluence",
    "Atlassian Jira": "Jira",
    "RoundCube": "Roundcube",
    "IIS": "Microsoft IIS",
    "gunicorn": "Gunicorn",
    "Microsoft ASP.NET": "ASP.NET",
    "Matomo Analytics": "Matomo",
    "Liveinternet": "LiveInternet",
    "JivoChat": "Jivo",
    "Azure": "Microsoft Azure",
    "Incapsula": "Imperva Incapsula",
    "Unpkg": "unpkg",
    "Google Font API": "Google Fonts",
    "Yandex.Cloud CDN": "Yandex Cloud CDN",
}

# Category names (Russian, as in data/tech.json; `locales/*/findings.json` `tech_cats` translate).
CATS_RU = {
    "A/B Testing": "A/B-тестирование", "Accessibility": "Доступность", "Accounting": "Бухгалтерия",
    "Advertising": "Реклама", "Affiliate programs": "Партнёрские программы",
    "Analytics": "Аналитика", "Appointment scheduling": "Запись на приём",
    "Artificial Intelligence": "ИИ", "Augmented reality": "Дополненная реальность",
    "Authentication": "Аутентификация", "Blogs": "Блоги",
    "Browser fingerprinting": "Отпечаток браузера", "Buy now pay later": "Рассрочка",
    "CDN": "CDN", "CI": "CI", "CMS": "CMS", "CRM": "CRM", "Caching": "Кэш",
    "Cart abandonment": "Брошенные корзины", "Comment systems": "Комментарии",
    "Containers": "Контейнеры", "Content curation": "Подбор контента",
    "Control systems": "Системы управления", "Cookie compliance": "Cookie-согласие",
    "Cross border ecommerce": "Трансграничная торговля",
    "Cryptominers": "Криптомайнеры", "Customer data platform": "CDP",
    "DMS": "Документооборот", "Database managers": "Администрирование", "Databases": "СУБД",
    "Development": "Разработка", "Digital asset management": "Медиаактивы",
    "Documentation": "Документация", "Domain parking": "Парковка доменов",
    "Drupal themes": "Темы Drupal", "Ecommerce": "E-commerce",
    "Ecommerce frontends": "E-commerce", "Editors": "Редакторы", "Email": "Почта",
    "Feature management": "Фича-флаги", "Feed readers": "Ленты", "Font scripts": "Шрифты",
    "Form builders": "Конструкторы форм", "Fulfilment": "Фулфилмент",
    "Fundraising & donations": "Пожертвования", "Geolocation": "Геолокация",
    "Hosting": "Хостинг", "Hosting panels": "Панели хостинга", "IaaS": "Хостинг",
    "Issue trackers": "Трекер", "JavaScript frameworks": "JS-фреймворк",
    "JavaScript graphics": "JS-графика", "JavaScript libraries": "JS-библиотека",
    "LMS": "LMS", "Live chat": "Чат", "Livestreaming": "Трансляции",
    "Load balancers": "Балансировщик", "Loyalty & rewards": "Лояльность", "Maps": "Карты",
    "Marketing automation": "Маркетинг", "Media servers": "Медиасерверы",
    "Message boards": "Форумы", "Miscellaneous": "Разное",
    "Mobile frameworks": "Мобильные фреймворки", "Network devices": "Сетевые устройства",
    "Network storage": "Хранилище", "Operating systems": "ОС", "PaaS": "Хостинг",
    "Page builders": "Конструктор сайтов", "Payment processors": "Платежи",
    "Performance": "Производительность", "Personalisation": "Персонализация",
    "Photo galleries": "Фотогалереи", "Programming languages": "Язык", "RUM": "Мониторинг",
    "Recruitment & staffing": "Подбор персонала", "Referral marketing": "Маркетинг",
    "Remote access": "Удалённый доступ", "Reservations & delivery": "Бронирование",
    "Retargeting": "Реклама", "Returns": "Возвраты", "Reverse proxies": "Обратный прокси",
    "Reviews": "Отзывы", "Rich text editors": "Редакторы", "SEO": "SEO",
    "SSL/TLS certificate authorities": "Удостоверяющие центры",
    "Search engines": "Поиск", "Security": "Безопасность", "Segmentation": "Маркетинг",
    "Shipping carriers": "Доставка", "Shopify apps": "Приложения Shopify",
    "Shopify themes": "Темы Shopify", "Static site generator": "Генератор сайтов",
    "Surveys": "Опросы", "Tag managers": "Аналитика", "Ticket booking": "Бронирование",
    "Translation": "Перевод", "UI frameworks": "UI-фреймворк",
    "User onboarding": "Онбординг", "Video players": "Видеоплееры",
    "Web frameworks": "Фреймворк", "Web server extensions": "Модули веб-сервера",
    "Web servers": "Веб-сервер", "Webcams": "Веб-камеры", "Webmail": "Веб-почта",
    "Widgets": "Виджеты", "Wikis": "Wiki", "WordPress plugins": "Плагины WordPress",
    "WordPress themes": "Темы WordPress",
}

# Category keys of intel::saas for DNS-detected services (by the first webappanalyzer category).
SAAS_CAT = {
    "Email": "email", "Webmail": "email", "Marketing automation": "marketing",
    "Analytics": "analytics", "CRM": "crm", "Hosting": "cloud", "PaaS": "cloud",
    "IaaS": "cloud", "CDN": "cloud", "Security": "security", "Authentication": "identity",
    "Payment processors": "payments", "Documentation": "docs", "Live chat": "support",
    "Issue trackers": "dev", "CI": "dev", "Development": "dev",
}

def literal(p: str) -> str:
    """Longest run of literal characters every match of `p` must contain (lowercase).

    Conservative: a group or a character class is one opaque atom, a top-level `|` disables
    the prefilter, and an atom followed by `?`, `*` or `{0,..}` is optional.
    """
    atoms, i, n = [], 0, len(p)  # each atom: a literal char or None (opaque)
    while i < n:
        c = p[i]
        if c == "\\" and i + 1 < n:
            nx = p[i + 1]
            atoms.append(None if nx.isalnum() else nx)
            i += 2
        elif c == "[":
            j = i + 1
            if j < n and p[j] == "^":
                j += 1
            if j < n and p[j] == "]":
                j += 1
            while j < n and p[j] != "]":
                j += 2 if p[j] == "\\" else 1
            atoms.append(None)
            i = j + 1
        elif c == "(":
            depth, j = 1, i + 1
            while j < n and depth:
                if p[j] == "\\":
                    j += 1
                elif p[j] == "[":
                    while j < n and p[j] != "]":
                        j += 2 if p[j] == "\\" else 1
                elif p[j] == "(":
                    depth += 1
                elif p[j] == ")":
                    depth -= 1
                j += 1
            atoms.append(None)
            i = j
        elif c == "|":
            return ""
        elif c in "?*":
            if atoms:
                atoms[-1] = None
            atoms.append(None)
            i += 1
        elif c == "+":
            atoms.append(None)
            i += 1
        elif c == "{":
            j = p.find("}", i)
            if j < 0:
                atoms.append("{")
                i += 1
                continue
            if p[i + 1:j].startswith("0") and atoms:
                atoms[-1] = None
            atoms.append(None)
            i = j + 1
        elif c in "^$.":
            atoms.append(None)
            i += 1
        else:
            atoms.append(c if c.isascii() else None)
            i += 1
    best, cur = "", ""
    for a in atoms + [None]:
        if a is None:
            best = max(best, cur, key=len)
            cur = ""
        else:
            cur += a
    return best.lower() if len(best) >= 3 else ""


def split_pat(s: str):
    """`regex\\;version:\\1\\;confidence:50` -> (regex, version, confidence)."""
    parts = s.split("\\;")
    rx, ver, conf = parts[0], "", 0
    for x in parts[1:]:
        if x.startswith("version:"):
            ver = x[8:]
        elif x.startswith("confidence:"):
            try:
                conf = int(x[11:])
            except ValueError:
                pass
    return rx, ver, conf


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def main() -> None:
    opts = sigsrc.args()
    files = {p: sigsrc.raw(REPO, COMMIT, p) for p in FILES}
    inputs = sigsrc.verify_inputs(NAME, files, "--repin" in opts)
    lic = files["LICENSE"].decode()
    assert "GNU GENERAL PUBLIC LICENSE" in lic and "Version 3" in lic, "license changed"
    cats = {int(k): v["name"] for k, v in json.loads(files["src/categories.json"]).items()}
    techs = {}
    for c in "_abcdefghijklmnopqrstuvwxyz":
        techs.update(json.loads(files[f"src/technologies/{c}.json"]))
    rename = lambda n: ALIASES.get(n, n)  # noqa: E731

    # Collect every regex first so one cargo run checks them all.
    pending = []  # (tech, field, key, raw)
    for name, t in techs.items():
        for field in ("headers", "cookies", "meta"):
            for k, v in (t.get(field) or {}).items():
                for s in as_list(v):
                    pending.append((name, field, k, s))
        for field in ("html", "scriptSrc", "url"):
            for s in as_list(t.get(field)):
                pending.append((name, field, None, s))
    regexes = [split_pat(s)[0] for _, _, _, s in pending]
    errs = sigsrc.rust_regex_check(regexes)
    skipped = {}
    out = {}
    for (name, field, key, s), err in zip(pending, errs):
        if err:
            skipped[err] = skipped.get(err, 0) + 1
            continue
        rx, ver, conf = split_pat(s)
        pat = [rx, ver, conf, literal(rx) if field in ("html", "scriptSrc", "url") else ""]
        while pat and pat[-1] in ("", 0):
            pat.pop()
        rec = out.setdefault(rename(name), {})
        short = {"headers": "h", "cookies": "k", "meta": "m", "html": "x", "scriptSrc": "s",
                 "url": "u"}[field]
        if key is None:
            rec.setdefault(short, []).append(pat)
        else:
            k = key.lower() if field in ("headers", "meta") else key
            rec.setdefault(short, {}).setdefault(k, []).append(pat)
    referenced = {rename(split_pat(x)[0]) for t in techs.values()
                  for f in ("implies", "requires") for x in as_list(t.get(f))}
    dns_rules = []
    rows = []
    for name, t in sorted(techs.items(), key=lambda kv: rename(kv[0])):
        first = cats.get((t.get("cats") or [0])[0], "Miscellaneous")
        rec = out.get(rename(name), {})
        for f, short in (("implies", "i"), ("requires", "r"), ("excludes", "e")):
            vals = [rename(split_pat(x)[0]) for x in as_list(t.get(f))]
            if vals:
                rec[short] = vals
        if t.get("dns"):
            dns = {}
            for rt, pats in t["dns"].items():
                ok = [split_pat(p)[0] for p in as_list(pats)]
                if ok:
                    dns[rt.upper()] = ok
            if dns:
                dns_rules.append({"name": rename(name), "cat": SAAS_CAT.get(first, "cloud"),
                                  "dns": dns})
        detectable = any(k in rec for k in ("h", "k", "m", "x", "s", "u", "i"))
        if not detectable and not t.get("cpe") and rename(name) not in referenced:
            continue
        rec = {"n": rename(name), "c": CATS_RU.get(first, "Разное"), **rec}
        if t.get("cpe"):
            rec["cpe"] = t["cpe"]
        if t.get("website"):
            rec["w"] = t["website"]
        rows.append(rec)
    # DNS regexes are compiled by intel::saas: check them too.
    dpats = [p for r in dns_rules for ps in r["dns"].values() for p in ps]
    derr = sigsrc.rust_regex_check(dpats)
    bad = {p for p, e in zip(dpats, derr) if e}
    for r in dns_rules:
        r["dns"] = {k: [p for p in v if p not in bad] for k, v in r["dns"].items()}
        r["dns"] = {k: v for k, v in r["dns"].items() if v}
    dns_rules = [r for r in dns_rules if r["dns"]]
    skipped["dns"] = len(bad)

    doc = {"source": f"{REPO}@{COMMIT[:12]}", "license": "GPL-3.0", "technologies": rows}
    size = sigsrc.write_gz(OUT, json.dumps(doc, ensure_ascii=False, separators=(",", ":")))
    OUT_DNS.parent.mkdir(parents=True, exist_ok=True)
    OUT_DNS.write_text(json.dumps({"source": f"{REPO}@{COMMIT[:12]}", "license": "GPL-3.0",
                                   "rules": dns_rules}, ensure_ascii=False, indent=0) + "\n",
                       "utf-8")
    nolit = sum(1 for r in rows for f in ("x", "s", "u") for p in r.get(f, []) if len(p) < 4)
    stats = {"technologies_upstream": len(techs), "technologies_kept": len(rows),
             "with_cpe": sum(1 for r in rows if "cpe" in r), "dns_rules": len(dns_rules),
             "patterns_total": len(pending), "patterns_skipped": skipped,
             "patterns_without_literal": nolit}
    sigsrc.record(NAME, {
        "repo": f"https://github.com/{REPO}", "commit": COMMIT, "license": "GPL-3.0-only",
        "license_file": "LICENSE", "license_sha256": sigsrc.sha256(files["LICENSE"]),
        "attribution": "Technology fingerprints from webappanalyzer (enthec), GPL-3.0, "
                       "https://github.com/enthec/webappanalyzer",
        "inputs": inputs, "outputs": [sigsrc.out_hash(OUT), sigsrc.out_hash(OUT_DNS)],
        "stats": stats,
    })
    print(f"{OUT.name}: {len(rows)} technologies, {size} bytes gz; {stats}")


if __name__ == "__main__":
    main()
