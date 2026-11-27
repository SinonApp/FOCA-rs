#!/usr/bin/env python3
"""Ingest enthec/webappanalyzer (GPL-3.0) into `crates/foca-recon/data/webappanalyzer.json.gz`.

Static signals (evaluated by the core over data the scan already fetched): response headers,
cookies, `<meta>`, HTML regexes, `<script src>`, page URL, JavaScript file contents (`scripts`),
visible page text (`text`), stylesheets (`css`), the TLS certificate issuer (`certIssuer`) and
robots.txt (`robots`). Browser signals (evaluated only in the hidden Android WebView after a
page render): global JavaScript variables (`js`), DOM selectors (`dom`) and request hosts seen
during the render (`xhr`). Plus `implies`/`requires`/`excludes`, `cpe`, `website`, the first
category (translated to the category names of `data/tech.json`) and, for WordPress plugins and
themes, the directory slug taken from their path patterns (`ps`). DNS rules (MX/TXT/NS/CNAME/SOA)
go to `crates/foca-net/data/saas_dns.json` for `intel::saas`.
Dropped fields: icon, description, saas, pricing, oss, probe (an extra request per technology).

Every regex is compiled with the Rust `regex` crate (`examples/regex_check.rs`); patterns it
rejects (lookarounds, backreferences) are skipped and counted in `sources.lock.json`.

Each pattern is stored as `[regex, version_template, confidence, literal]` (trailing empty items
dropped). Short keys: h headers, k cookies, m meta, x html, s scriptSrc, u url, sc scripts,
t text, y css, ci certIssuer, ro robots, g js (path -> patterns), d dom (list of
`{s: selector, a: {attribute: pattern}, p: {property: pattern}, t: pattern}`), q xhr. `literal` is a lowercase substring every match must contain: the engine looks it up
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


# Upstream list fields -> short key; `LITERAL_FIELDS` get the Aho-Corasick prefilter literal.
LISTS = ("html", "scriptSrc", "url", "scripts", "text", "css", "certIssuer", "robots", "xhr")
SHORT = {"headers": "h", "cookies": "k", "meta": "m", "js": "g", "html": "x", "scriptSrc": "s",
         "url": "u", "scripts": "sc", "text": "t", "css": "y", "certIssuer": "ci",
         "robots": "ro", "xhr": "q"}
LITERAL_FIELDS = ("html", "scriptSrc", "url", "scripts", "text", "css", "robots")
STATIC_KEYS = ("h", "k", "m", "x", "s", "u", "sc", "t", "y", "ci", "ro")
BROWSER_KEYS = ("g", "d", "q")
# Fields evaluated before this ingest learned the new signals (for the before/after stats).
LEGACY_KEYS = ("h", "k", "m", "x", "s", "u")
WP_SLUG = re.compile(r"wp-content(?:\\?/)+(plugins|themes)(?:\\?/)+([a-z0-9][a-z0-9_.-]*[a-z0-9])", re.I)


def dom_rules(d):
    """Upstream `dom` (a selector, a list of selectors or `{selector: conditions}`) as
    `[(selector, conditions)]`."""
    if d is None:
        return []
    if isinstance(d, str):
        return [(d, {})]
    if isinstance(d, list):
        return [(x, {}) for x in d if isinstance(x, str)]
    return [(k, v if isinstance(v, dict) else {}) for k, v in d.items()]


def wp_slugs(t):
    """`[(kind, slug)]` of a WordPress plugin/theme from its path patterns
    (`/wp-content/plugins/<slug>/`), kind `plugin` or `theme`."""
    found = []
    texts = [*as_list(t.get("html")), *as_list(t.get("scriptSrc"))]
    for d in dom_rules(t.get("dom")):
        texts.append(d[0])
        texts.extend(str(v) for v in (d[1].get("attributes") or {}).values())
    for x in texts:
        for m in WP_SLUG.finditer(split_pat(x)[0] if isinstance(x, str) else ""):
            slug = m.group(2).replace("\\", "").lower()
            if re.fullmatch(r"[a-z0-9][a-z0-9_.-]*", slug) and "." not in slug:
                kind = "plugin" if m.group(1).lower() == "plugins" else "theme"
                if (kind, slug) not in found:
                    found.append((kind, slug))
    return found


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
        for field in ("headers", "cookies", "meta", "js"):
            for k, v in (t.get(field) or {}).items():
                for s in as_list(v):
                    pending.append((name, field, k, s))
        for field in LISTS:
            for s in as_list(t.get(field)):
                pending.append((name, field, None, s))
        for i, (sel, cond) in enumerate(dom_rules(t.get("dom"))):
            for kind in ("attributes", "properties"):
                for k, v in (cond.get(kind) or {}).items():
                    pending.append((name, "dom", (i, sel, kind, k), v if isinstance(v, str) else ""))
            if "text" in cond:
                tx = cond["text"]
                pending.append((name, "dom", (i, sel, "text", None), tx if isinstance(tx, str) else ""))
            if not cond.get("attributes") and not cond.get("properties") and "text" not in cond:
                pending.append((name, "dom", (i, sel, "exists", None), ""))
    regexes = [split_pat(s)[0] for _, _, _, s in pending]
    errs = sigsrc.rust_regex_check(regexes)
    skipped = {}
    out = {}
    dom_bad = set()  # (tech, rule index) with a pattern the engine rejects
    for (name, field, key, s), err in zip(pending, errs):
        if err:
            skipped[err] = skipped.get(err, 0) + 1
            if field == "dom":
                dom_bad.add((name, key[0]))
            continue
    for (name, field, key, s), err in zip(pending, errs):
        if err:
            continue
        rx, ver, conf = split_pat(s)
        pat = [rx, ver, conf, literal(rx) if field in LITERAL_FIELDS else ""]
        while pat and pat[-1] in ("", 0):
            pat.pop()
        rec = out.setdefault(rename(name), {})
        if field == "dom":
            i, sel, kind, k = key
            if (name, i) in dom_bad:
                continue
            rules = rec.setdefault("_dom", {})
            r = rules.setdefault(i, {"s": sel})
            if kind == "attributes":
                r.setdefault("a", {})[k] = pat
            elif kind == "properties":
                r.setdefault("p", {})[k] = pat
            elif kind == "text":
                r["t"] = pat
            continue
        short = SHORT[field]
        if key is None:
            rec.setdefault(short, []).append(pat)
        else:
            k = key.lower() if field in ("headers", "meta") else key
            rec.setdefault(short, {}).setdefault(k, []).append(pat)
    for rec in out.values():
        dom = rec.pop("_dom", None)
        if dom:
            rec["d"] = [dom[i] for i in sorted(dom)]
    referenced = {rename(split_pat(x)[0]) for t in techs.values()
                  for f in ("implies", "requires") for x in as_list(t.get(f))}
    dns_rules = []
    rows = []
    legacy = static = browser_only = 0
    per_signal = {}
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
        # any technology whose patterns name exactly one plugin/theme directory (WooCommerce
        # is filed under Ecommerce); themes and plugins of page builders list several
        slugs = wp_slugs(t)
        if slugs and (first in ("WordPress plugins", "WordPress themes") or len(slugs) == 1):
            rec["ps"] = [list(x) for x in slugs]
        detectable = any(k in rec for k in (*STATIC_KEYS, *BROWSER_KEYS, "i"))
        if not detectable and not t.get("cpe") and rename(name) not in referenced:
            continue
        if any(k in rec for k in LEGACY_KEYS):
            legacy += 1
        if any(k in rec for k in STATIC_KEYS):
            static += 1
        elif any(k in rec for k in BROWSER_KEYS):
            browser_only += 1
        for k in (*STATIC_KEYS, *BROWSER_KEYS):
            if k in rec:
                per_signal[k] = per_signal.get(k, 0) + 1
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
    nolit = sum(1 for r in rows for f in ("x", "s", "u", "sc", "t", "y", "ro")
                for p in r.get(f, []) if len(p) < 4)
    stats = {"technologies_upstream": len(techs), "technologies_kept": len(rows),
             "technologies_legacy_signals": legacy, "technologies_static": static,
             "technologies_browser_only": browser_only,
             "technologies_per_signal": dict(sorted(per_signal.items())),
             "wordpress_slugs": sum(len(r.get("ps", [])) for r in rows),
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
