"""Shared helpers for the signature ingest scripts (`update_*.py` in this directory).

Every script downloads one upstream source at a PINNED version (a git commit or a dated
snapshot), checks the sha256 of every input file against `sources.lock.json` (unless
`--repin` is given, which records new hashes), converts the data into a compact table that is
committed to the repo and records the outcome (counts, skipped items, output hashes, license
and attribution) in the same lock file. `qa/gen-licenses.py` reads the lock file for the
third-party notices.

Downloads are cached in `$FOCA_SIG_CACHE` (default `~/.cache/foca-sig`), so a re-run is offline.
"""

import gzip
import hashlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tarfile
import urllib.request

TOOLS = pathlib.Path(__file__).resolve().parent
SIG = TOOLS.parent
REPO = SIG.parents[2]
LOCK = SIG / "sources.lock.json"
CACHE = pathlib.Path(os.environ.get("FOCA_SIG_CACHE", pathlib.Path.home() / ".cache" / "foca-sig"))
UA = "foca-rs-signature-ingest (+https://github.com/SinonApp/FOCA-rs)"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fetch(url: str) -> bytes:
    """Downloads `url` once and serves it from the cache afterwards."""
    CACHE.mkdir(parents=True, exist_ok=True)
    path = CACHE / sha256(url.encode())[:32]
    if path.is_file():
        return path.read_bytes()
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=120) as r:
        data = r.read()
    path.write_bytes(data)
    return data


def raw(repo: str, commit: str, path: str) -> bytes:
    return fetch(f"https://raw.githubusercontent.com/{repo}/{commit}/{path}")


def tarball(repo: str, commit: str) -> dict:
    """Returns `{path inside the repo: bytes}` of the source tarball at `commit`."""
    data = fetch(f"https://codeload.github.com/{repo}/tar.gz/{commit}")
    out = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as t:
        for m in t.getmembers():
            if m.isfile():
                rel = m.name.split("/", 1)[1] if "/" in m.name else m.name
                f = t.extractfile(m)
                if f is not None:
                    out[rel] = f.read()
    return out


def load_lock() -> dict:
    if LOCK.is_file():
        return json.loads(LOCK.read_text("utf-8"))
    return {"_about": "Pinned upstream versions of the ingested signature sources", "sources": {}}


def save_lock(lock: dict) -> None:
    lock["sources"] = dict(sorted(lock["sources"].items()))
    LOCK.write_text(json.dumps(lock, ensure_ascii=False, indent=1) + "\n", "utf-8")


def digest(files: dict) -> str:
    """One sha256 over many input files: sha256 of the sorted `path sha256` lines."""
    lines = "".join(f"{p} {sha256(files[p])}\n" for p in sorted(files))
    return sha256(lines.encode())


def verify_inputs(name: str, files: dict, repin: bool) -> dict:
    """Checks the sha256 of every input file (or of the file set) against the lock."""
    lock = load_lock()
    prev = lock["sources"].get(name, {}).get("inputs", {})
    now = {p: sha256(b) for p, b in files.items()} if len(files) <= 40 else {"*": digest(files)}
    if prev and not repin and prev != now:
        bad = sorted(k for k in set(prev) | set(now) if prev.get(k) != now.get(k))
        sys.exit(f"{name}: input hash mismatch for {bad[:5]} (upstream changed? use --repin)")
    return now


def record(name: str, entry: dict) -> None:
    lock = load_lock()
    lock["sources"][name] = entry
    save_lock(lock)


def write_gz(path: pathlib.Path, text: str) -> int:
    """Deterministic gzip (mtime 0, no file name). Returns the compressed size."""
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb", compresslevel=9, mtime=0, filename="") as g:
        g.write(text.encode("utf-8"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(buf.getvalue())
    return len(buf.getvalue())


def out_hash(path: pathlib.Path) -> dict:
    data = path.read_bytes()
    return {"path": str(path.relative_to(REPO)), "bytes": len(data), "sha256": sha256(data)}


def rust_regex_check(patterns: list, case_insensitive: bool = True) -> list:
    """Compiles every pattern with the Rust `regex` crate the app uses.

    Returns one entry per pattern: `None` when it compiles, else a short error class
    (`lookaround`, `backref`, `other`). Runs `cargo run --example regex_check -p foca-analysis`.
    """
    env = dict(os.environ)
    inp = "".join(json.dumps({"p": p, "ci": case_insensitive}) + "\n" for p in patterns)
    r = subprocess.run(
        ["cargo", "run", "-q", "-p", "foca-analysis", "--example", "regex_check"],
        input=inp.encode(), capture_output=True, cwd=REPO, env=env, check=False,
    )
    if r.returncode != 0:
        sys.exit("regex_check failed: " + r.stderr.decode()[-2000:])
    out = []
    for line in r.stdout.decode().splitlines():
        out.append(None if line == "ok" else line.split(" ", 1)[1])
    if len(out) != len(patterns):
        sys.exit("regex_check: output length mismatch")
    return out


def args() -> set:
    return set(sys.argv[1:])
