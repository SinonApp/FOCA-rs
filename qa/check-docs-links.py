#!/usr/bin/env python3
"""Checks relative links and anchors in every .md file of the repository.

    python3 qa/check-docs-links.py [--root DIR] [--all]

By default only .md files tracked by git (`git ls-files`) are checked, so drafts outside git
do not break the shared run. `--all` also includes untracked (but not ignored) files.

Checks [text](path), [text](path#anchor), [text](#anchor), reference definitions `[x]: path`
and <a href>/<img src> inside .md. External links (http/https/mailto) are not checked. Anchors
follow GitHub rules (lowercase, space → "-", punctuation removed, duplicates → -1, -2, …), plus
explicit <a id="…"> / <a name="…"> and id="…" in HTML. Code in ``` blocks and `…` is skipped.
Exit code: 0 if nothing is broken, 1 otherwise (prints "file:line: link: reason" for each).
"""
import os
import re
import sys
import unicodedata

SKIP_DIRS = {".git", "node_modules", "target", "build", ".gradle", "dist", "shots"}
# Generated run artifacts and third-party data are not documentation.
SKIP_PREFIXES = ("qa/out/", "tests/corpus/real/", "src-tauri/gen/android/app/build/")

LINK_RE = re.compile(r"(!?)\[((?:[^\[\]]|\[[^\]]*\])*)\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
REFDEF_RE = re.compile(r"^\s{0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+.*)?$")
HTML_RE = re.compile(r"<(?:a|img)\b[^>]*?\s(?:href|src)=\"([^\"]+)\"", re.I)
ID_RE = re.compile(r"<[^>]+\s(?:id|name)=\"([^\"]+)\"", re.I)
HEAD_RE = re.compile(r"^(#{1,6})\s+(.*?)\s*#*\s*$")


def slug(text):
    t = re.sub(r"`([^`]*)`", r"\1", text)
    t = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", t)
    t = re.sub(r"<[^>]+>", "", t)
    t = t.strip().lower()
    out = []
    for ch in t:
        cat = unicodedata.category(ch)
        if ch in " -_" or cat[0] in "LMN" or cat == "Pc":
            out.append(ch)
    return "".join(out).replace(" ", "-")


def strip_code(lines):
    """Returns the lines with ``` block and inline code contents removed (line numbers are preserved)."""
    res, fence = [], None
    for ln in lines:
        m = re.match(r"^\s*(```+|~~~+)", ln)
        if m:
            tok = m.group(1)[0] * 3
            if fence is None:
                fence = tok
            elif ln.strip().startswith(fence):
                fence = None
            res.append("")
            continue
        res.append("" if fence else re.sub(r"`[^`]*`", "", ln))
    return res


_anchor_cache = {}


def anchors(path):
    if path in _anchor_cache:
        return _anchor_cache[path]
    try:
        lines = open(path, encoding="utf-8", errors="replace").read().split("\n")
    except OSError:
        _anchor_cache[path] = set()
        return set()
    seen, res, fence = {}, set(), False
    for ln in lines:
        if re.match(r"^\s*(```|~~~)", ln):
            fence = not fence
            continue
        if fence:
            continue
        for i in ID_RE.findall(ln):
            res.add(i)
        m = HEAD_RE.match(ln)
        if m:
            s = slug(m.group(2))
            n = seen.get(s, 0)
            res.add(s if n == 0 else f"{s}-{n}")
            seen[s] = n + 1
    _anchor_cache[path] = res
    return res


def md_files(root, all_files=False):
    import subprocess
    args = ["git", "-C", root, "ls-files", "-z", "--cached"]
    if all_files:
        args += ["--others", "--exclude-standard"]
    try:
        out = subprocess.run(args + ["--", "*.md"], capture_output=True, check=True).stdout.decode("utf-8")
        for rel in sorted(set(x for x in out.split("\0") if x)):
            if rel.startswith(SKIP_PREFIXES) or any(p in SKIP_DIRS for p in rel.split("/")[:-1]):
                continue
            if os.path.isfile(os.path.join(root, rel)):
                yield os.path.join(root, rel)
        return
    except (OSError, subprocess.CalledProcessError):
        pass # not a git repository: walk the directories
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d not in SKIP_DIRS]
        rel = os.path.relpath(dp, root).replace(os.sep, "/")
        rel = "" if rel == "." else rel + "/"
        if rel.startswith(SKIP_PREFIXES):
            dns[:] = []
            continue
        for f in fns:
            if f.endswith(".md"):
                yield os.path.join(dp, f)


def check(root, all_files=False):
    bad, total = [], 0
    for f in sorted(md_files(root, all_files)):
        lines = open(f, encoding="utf-8", errors="replace").read().split("\n")
        for no, ln in enumerate(strip_code(lines), 1):
            targets = [m.group(3) for m in LINK_RE.finditer(ln)]
            targets += HTML_RE.findall(ln)
            m = REFDEF_RE.match(ln)
            if m:
                targets.append(m.group(1))
            for t in targets:
                if re.match(r"^[a-z][a-z0-9+.-]*:", t, re.I) or t.startswith("//"):
                    continue  # http:, https:, mailto:, file: …
                total += 1
                path, _, frag = t.partition("#")
                path = re.sub(r"\?.*$", "", path)
                from urllib.parse import unquote
                path, frag = unquote(path), unquote(frag)
                dest = f if not path else os.path.normpath(os.path.join(os.path.dirname(f), path))
                rel = os.path.relpath(f, root)
                if not os.path.exists(dest):
                    bad.append(f"{rel}:{no}: {t}: file not found")
                    continue
                if frag and dest.endswith(".md") and os.path.isfile(dest):
                    if frag not in anchors(dest) and frag.lower() not in anchors(dest):
                        bad.append(f"{rel}:{no}: {t}: anchor not found: {frag}")
    return bad, total


def main():
    root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if "--root" in sys.argv:
        root = os.path.abspath(sys.argv[sys.argv.index("--root") + 1])
    bad, total = check(root, "--all" in sys.argv)
    for b in bad:
        print(b)
    print(f"links checked: {total}, broken: {len(bad)}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
