#!/usr/bin/env python3
"""Ingest the gitleaks default rules (MIT) into `secrets_gitleaks.toml` next to `secrets.toml`.

The rules keep the format of `secrets.toml` (see its header) plus gitleaks allowlists:
    allow      : regexes against the secret value (rule allowlists and the global allowlist);
    allow_line : regexes against the line of the match (`regexTarget = "line"` / `"match"`);
    stopwords  : the hit is dropped when the lowercased secret contains one of them.
Our tuned rules in `secrets.toml` win: gitleaks rules for the same services are skipped
(`COVERED`), and at runtime one value is reported once (the first rule in file order wins).

RE2 shorthand classes are rewritten to their ASCII spelling (`ascii_classes`), which keeps the
semantics and the compiled size small. Skipped and counted in `sources.lock.json`: rules covered by ours, path-only rules (documents
have no repository path), rules the Rust `regex` crate rejects, allowlists bound to paths.
Titles are generated as `Ключ или токен <Service>` (one catalog entry translates them all).

Usage: python3 update_gitleaks.py [--repin]
"""

import re
import tomllib

import sigsrc

NAME = "gitleaks"
REPO = "gitleaks/gitleaks"
TAG = "v8.30.1"
COMMIT = "5f6ec56cfa6f8c67648d863582c7ae2f206d5c1c"
OUT = sigsrc.SIG / "secrets_gitleaks.toml"
FILES = ["config/gitleaks.toml", "LICENSE"]

# gitleaks rule -> our rule in secrets.toml that already covers the service.
COVERED = {
    "aws-access-token": "aws-access-key", "gcp-api-key": "gcp-api-key",
    "generic-api-key": "generic-api-key", "github-pat": "github-token",
    "github-oauth": "github-token", "github-app-token": "github-token",
    "github-refresh-token": "github-token", "github-fine-grained-pat": "github-token",
    "gitlab-pat": "gitlab-token", "slack-bot-token": "slack-token",
    "slack-user-token": "slack-token", "slack-legacy-bot-token": "slack-token",
    "slack-legacy-token": "slack-token", "slack-legacy-workspace-token": "slack-token",
    "slack-webhook-url": "slack-webhook", "telegram-bot-api-token": "telegram-bot-token",
    "jwt": "jwt", "stripe-access-token": "stripe-key", "openai-api-key": "openai-key",
    "private-key": "private-key",
}

# Display names of services whose id does not title-case well.
NAMES = {
    "1password": "1Password", "github": "GitHub", "gitlab": "GitLab", "digitalocean": "DigitalOcean",
    "openai": "OpenAI", "hashicorp-tf": "Terraform Cloud", "aws-amazon-bedrock": "Amazon Bedrock",
    "new-relic": "New Relic", "cisco-meraki": "Cisco Meraki", "clickhouse-cloud": "ClickHouse Cloud",
    "droneci": "Drone CI", "travisci": "Travis CI", "launchdarkly": "LaunchDarkly",
    "sendgrid": "SendGrid", "sendinblue": "Sendinblue", "huggingface": "Hugging Face",
    "rubygems": "RubyGems", "npm": "npm", "nuget": "NuGet", "jfrog": "JFrog", "flyio": "Fly.io",
    "frameio": "Frame.io", "planetscale": "PlanetScale", "rapidapi": "RapidAPI", "readme": "ReadMe",
    "privateai": "Private AI", "settlemint": "SettleMint", "sourcegraph": "Sourcegraph",
    "sumologic": "Sumo Logic", "nytimes": "New York Times", "easypost": "EasyPost",
    "gocardless": "GoCardless", "messagebird": "MessageBird", "mailchimp": "Mailchimp",
    "linkedin": "LinkedIn", "microsoft-teams": "Microsoft Teams", "intra42": "42 Intra",
    "freshbooks": "FreshBooks", "maxmind": "MaxMind", "octopus-deploy": "Octopus Deploy",
    "authress": "Authress", "azure-ad": "Azure AD", "kubernetes": "Kubernetes",
    "curl": "cURL", "jwt": "JWT", "age": "age", "defined-networking": "Defined Networking",
    "openshift": "OpenShift", "youtube": "YouTube", "squarespace": "Squarespace",
}
# Rules whose finding is not a service key.
TITLES = {
    "curl-auth-user": "Учётные данные в команде curl",
    "curl-auth-header": "Учётные данные в команде curl",
}
GENERIC = {"api", "key", "token", "secret", "access", "client", "id", "pat", "oauth", "app",
           "personal", "personnal", "service", "account", "admin", "private", "public", "pub",
           "auth", "header", "user", "global", "origin", "ca", "long", "short", "lived",
           "refresh", "encryption", "signing", "license", "delivery", "insert", "browser",
           "organization", "reference", "identity", "webhook", "url", "bot", "config",
           "custom", "shared", "sensitive", "test", "password", "file", "yaml", "routable",
           "cicd", "job", "deploy", "feature", "flag", "feed", "incoming", "mail", "agent",
           "runner", "authentication", "scim", "session", "cookie", "ptt", "rrt", "batch",
           "bearer", "v2", "legacy", "workspace", "base64", "application", "org", "cloud"}


def service(rule_id: str) -> str:
    words = rule_id.split("-")
    keep = []
    for w in words:
        if w in GENERIC and keep:
            break
        keep.append(w)
    for n in range(len(keep), 0, -1):
        k = "-".join(keep[:n])
        if k in NAMES:
            return " ".join([NAMES[k]] + [w.capitalize() for w in keep[n:]])
    return " ".join(w.capitalize() for w in keep)


def name_group(rx: str, n: int) -> str:
    """Turns the n-th capturing group of `rx` into `(?P<s>...)`."""
    i, k, in_class = 0, 0, False
    while i < len(rx):
        c = rx[i]
        if c == "\\":
            i += 2
            continue
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
            if rx[i + 1:i + 2] == "]":
                i += 1
        elif c == "(" and rx[i + 1:i + 2] != "?":
            k += 1
            if k == n:
                return rx[:i] + "(?P<s>" + rx[i + 1:]
        i += 1
    return rx


def ascii_classes(rx: str) -> str:
    """RE2 (Go) `\\w`, `\\d`, `\\s` and `\\b` are ASCII-only; Rust's are Unicode-aware and make the
    gitleaks patterns exceed the compiled size limit. Spell the ASCII classes out instead."""
    w, sp, d = "0-9A-Za-z_", "\\t\\n\\x0B\\f\\r ", "0-9"
    inner = {"w": w, "s": sp, "d": d}
    outer = {"w": f"[{w}]", "s": f"[{sp}]", "d": f"[{d}]", "W": f"[^{w}]", "S": f"[^{sp}]",
             "D": f"[^{d}]", "b": "(?-u:\\b)", "B": "(?-u:\\B)"}
    out, i, in_class = [], 0, False
    while i < len(rx):
        c = rx[i]
        if c == "\\" and i + 1 < len(rx):
            rep = (inner if in_class else outer).get(rx[i + 1])
            out.append(rep or rx[i:i + 2])
            i += 2
            continue
        if in_class:
            in_class = c != "]"
        elif c == "[":
            in_class = True
            out.append(c)
            i += 1
            for lead in ("^", "]"):
                if rx[i:i + 1] == lead:
                    out.append(lead)
                    i += 1
            continue
        out.append(c)
        i += 1
    return "".join(out)


def groups(rx: str) -> int:
    return len(re.findall(r"(?<!\\)\((?!\?)", rx))


def toml_str(s: str) -> str:
    if "'''" not in s and not s.endswith("'"):
        return "'''" + s + "'''" if ("'" in s or "\n" in s) else "'" + s + "'"
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main() -> None:
    opts = sigsrc.args()
    files = {p: sigsrc.raw(REPO, COMMIT, p) for p in FILES}
    inputs = sigsrc.verify_inputs(NAME, files, "--repin" in opts)
    lic = files["LICENSE"].decode()
    assert lic.startswith("MIT License"), "license changed"
    cfg = tomllib.loads(files["config/gitleaks.toml"].decode())
    skipped = {"covered": 0, "path_only": 0, "regex": 0, "allowlist_paths": 0}
    cand = []
    for r in cfg["rules"]:
        if r["id"] in COVERED:
            skipped["covered"] += 1
            continue
        if "regex" not in r or "path" in r:
            skipped["path_only"] += 1
            continue
        rx = ascii_classes(r["regex"])
        n = int(r.get("secretGroup") or (1 if groups(rx) else 0))
        if n:
            rx = name_group(rx, n)
        allow, allow_line, stop = [], [], []
        for a in r.get("allowlists", []):
            if a.get("paths"):
                skipped["allowlist_paths"] += 1
                continue
            target = a.get("regexTarget", "secret")
            pats = [ascii_classes(x) for x in a.get("regexes", [])]
            (allow_line if target in ("line", "match") else allow).extend(pats)
            stop.extend(a.get("stopwords", []))
        cand.append((r, rx, allow, allow_line, stop))
    # Compile the rule regexes (case-sensitive: gitleaks flags are inline) and the allowlists.
    errs = sigsrc.rust_regex_check([c[1] for c in cand], case_insensitive=False)
    glob = [ascii_classes(x) for x in cfg.get("allowlist", {}).get("regexes", [])]
    pool = sorted({x for c in cand for x in c[2] + c[3]} | set(glob))
    bad_allow = {p for p, e in zip(pool, sigsrc.rust_regex_check(pool, False)) if e}
    lines = [
        "# GENERATED by tools/update_gitleaks.py from gitleaks " + TAG + " (" + COMMIT[:12] + "),",
        "# MIT License, Copyright (c) 2019 Zachary Rice. Do not edit: change the script and rerun.",
        "# Format: see secrets.toml; allow / allow_line / stopwords are gitleaks allowlists.",
        "",
        "[allowlist]",
        "regexes = [" + ", ".join(toml_str(x) for x in glob if x not in bad_allow) + "]",
        "",
    ]
    kept = 0
    for (r, rx, allow, allow_line, stop), err in zip(cand, errs):
        if err:
            skipped["regex"] += 1
            continue
        kept += 1
        lines += [
            "[[rule]]",
            f'id = "gl-{r["id"]}"',
            f'title = "{TITLES.get(r["id"]) or "Ключ или токен " + service(r["id"])}"',
            'type = "api"',
            'sev = "high"',
            f"re = {toml_str(rx)}",
        ]
        if r.get("keywords"):
            lines.append("keywords = [" + ", ".join(toml_str(k.lower()) for k in r["keywords"]) + "]")
        if r.get("entropy"):
            lines.append(f"entropy = {float(r['entropy'])}")
        allow = [x for x in allow if x not in bad_allow]
        allow_line = [x for x in allow_line if x not in bad_allow]
        if allow:
            lines.append("allow = [" + ", ".join(toml_str(x) for x in allow) + "]")
        if allow_line:
            lines.append("allow_line = [" + ", ".join(toml_str(x) for x in allow_line) + "]")
        if stop:
            lines.append("stopwords = [" + ", ".join(toml_str(x) for x in stop) + "]")
        lines.append("")
    OUT.write_text("\n".join(lines), "utf-8")
    tomllib.loads(OUT.read_text("utf-8"))  # the output must parse
    stats = {"rules_upstream": len(cfg["rules"]), "rules_kept": kept, "skipped": skipped,
             "allowlist_regexes_dropped": len(bad_allow)}
    sigsrc.record(NAME, {
        "repo": f"https://github.com/{REPO}", "tag": TAG, "commit": COMMIT, "license": "MIT",
        "license_file": "LICENSE", "license_sha256": sigsrc.sha256(files["LICENSE"]),
        "attribution": "Secret detection rules from gitleaks, Copyright (c) 2019 Zachary Rice, "
                       "MIT License, https://github.com/gitleaks/gitleaks",
        "inputs": inputs, "outputs": [sigsrc.out_hash(OUT)], "stats": stats,
    })
    print(f"{OUT.name}: {kept} rules; {stats}")


if __name__ == "__main__":
    main()
