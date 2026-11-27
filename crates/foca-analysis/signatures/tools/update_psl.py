#!/usr/bin/env python3
"""Ship the Public Suffix List (MPL-2.0) unmodified as `crates/foca-net/data/public_suffix_list.dat.gz`.

The file is stored byte for byte (only gzip-compressed), which keeps the MPL-2.0 obligations to
shipping the source form with its license notice; `foca-net::dns::psl` parses it at runtime
(ICANN and private sections, wildcards and exceptions).

Usage: python3 update_psl.py [--repin]
"""

import sigsrc

NAME = "psl"
REPO = "publicsuffix/list"
COMMIT = "88b076a1fb2ae58cd2a6959d570f075e04d21867"
OUT = sigsrc.REPO / "crates/foca-net/data/public_suffix_list.dat.gz"
FILES = ["public_suffix_list.dat", "LICENSE"]


def main() -> None:
    opts = sigsrc.args()
    files = {p: sigsrc.raw(REPO, COMMIT, p) for p in FILES}
    inputs = sigsrc.verify_inputs(NAME, files, "--repin" in opts)
    assert files["LICENSE"].decode().startswith("Mozilla Public License Version 2.0")
    text = files["public_suffix_list.dat"].decode("utf-8")
    assert "Incompatible With Secondary Licenses" not in text, "MPL secondary license blocked"
    rules = [l for l in text.splitlines() if l and not l.startswith("//")]
    size = sigsrc.write_gz(OUT, text)
    stats = {"rules": len(rules), "bytes_raw": len(files["public_suffix_list.dat"])}
    sigsrc.record(NAME, {
        "repo": f"https://github.com/{REPO}", "commit": COMMIT, "license": "MPL-2.0",
        "license_file": "LICENSE", "license_sha256": sigsrc.sha256(files["LICENSE"]),
        "attribution": "Public Suffix List, Mozilla Foundation and contributors, MPL-2.0, "
                       "https://publicsuffix.org (shipped unmodified)",
        "inputs": inputs, "outputs": [sigsrc.out_hash(OUT)], "stats": stats,
    })
    print(f"{OUT.name}: {size} bytes gz; {stats}")


if __name__ == "__main__":
    main()
