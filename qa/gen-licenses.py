#!/usr/bin/env python3
"""Generate and verify `crates/foca-engine/data/licenses.json` from Cargo.lock, Android Gradle,
assets and THIRD_PARTY.md, enforcing GPL-3.0 compatibility and Android `foss` purity.

Usage:
    python qa/gen-licenses.py          # regenerate crates/foca-engine/data/licenses.json
    python qa/gen-licenses.py --check  # fail if out-of-date, GPL-3.0 incompatible, or foss dirty
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT_PATH = ROOT / "crates" / "foca-engine" / "data" / "licenses.json"
GRADLE_PATH = ROOT / "src-tauri" / "gen" / "android" / "app" / "build.gradle.kts"
ANDROID_SRC = ROOT / "src-tauri" / "gen" / "android" / "app" / "src"

# Atomic SPDX license identifiers compatible with GNU GPL v3.0 (outbound license of FOCA-rs).
GPL3_COMPATIBLE_ATOMS = {
    "0BSD",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSL-1.0",
    "CC0-1.0",
    "CDLA-Permissive-2.0",
    "GPL-3.0",
    "GPL-3.0-only",
    "GPL-3.0-or-later",
    "ISC",
    "LGPL-2.1-or-later",
    "LGPL-3.0-or-later",
    "MIT",
    "MIT-0",
    "MPL-2.0",
    "OFL-1.1",
    "Unicode-3.0",
    "Unlicense",
    "Zlib",
}


def tokenize_spdx(expr: str) -> list[str]:
    # Normalize legacy Cargo slash syntax (`MIT/Apache-2.0`) to `OR`.
    norm = re.sub(r"\s*/\s*", " OR ", expr.strip())
    tokens: list[str] = []
    i = 0
    n = len(norm)
    while i < n:
        if norm[i].isspace():
            i += 1
        elif norm[i] in "()":
            tokens.append(norm[i])
            i += 1
        else:
            j = i
            while j < n and not norm[j].isspace() and norm[j] not in "()":
                j += 1
            tokens.append(norm[i:j])
            i = j
    # Merge `X WITH Y` into a single atom token.
    merged: list[str] = []
    k = 0
    while k < len(tokens):
        if k + 2 < len(tokens) and tokens[k + 1] == "WITH":
            merged.append(f"{tokens[k]} WITH {tokens[k + 2]}")
            k += 3
        else:
            merged.append(tokens[k])
            k += 1
    return merged


def is_gpl3_compatible(expr: str | None) -> bool:
    """Evaluates an SPDX boolean expression (OR / AND / parentheses) for GPL-3.0 compatibility."""
    if not expr or not expr.strip():
        return False
    toks = tokenize_spdx(expr)
    pos = 0

    def parse_or() -> bool:
        nonlocal pos
        val = parse_and()
        while pos < len(toks) and toks[pos] == "OR":
            pos += 1
            rhs = parse_and()
            val = val or rhs
        return val

    def parse_and() -> bool:
        nonlocal pos
        val = parse_atom()
        while pos < len(toks) and toks[pos] == "AND":
            pos += 1
            rhs = parse_atom()
            val = val and rhs
        return val

    def parse_atom() -> bool:
        nonlocal pos
        if pos >= len(toks):
            return False
        tok = toks[pos]
        if tok == "(":
            pos += 1
            val = parse_or()
            if pos < len(toks) and toks[pos] == ")":
                pos += 1
            return val
        pos += 1
        return tok in GPL3_COMPATIBLE_ATOMS

    try:
        ok = parse_or()
        return ok and pos == len(toks)
    except Exception:
        return False


def collect_rust_crates() -> tuple[list[dict], list[str]]:
    env = os.environ.copy()
    if Path(r"Y:\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin").exists():
        env.setdefault("RUSTUP_HOME", r"Y:\.rustup")
        env.setdefault("CARGO_HOME", r"Y:\.cargo")
        env["PATH"] = r"Y:\.rustup\toolchains\stable-x86_64-pc-windows-msvc\bin;" + env.get("PATH", "")

    raw = subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1"],
        cwd=ROOT,
        env=env,
        text=True,
        encoding="utf-8",
    )
    meta = json.loads(raw)
    ws_ids = set(meta["workspace_members"])
    direct_names: set[str] = set()
    for pkg in meta["packages"]:
        if pkg["id"] in ws_ids:
            for dep in pkg.get("dependencies", []):
                if dep.get("kind") in (None, "build"):
                    direct_names.add(dep["name"])

    crates: list[dict] = []
    incompatible: list[str] = []
    seen: set[tuple[str, str]] = set()
    for pkg in meta["packages"]:
        if pkg["id"] in ws_ids:
            continue
        key = (pkg["name"], pkg["version"])
        if key in seen:
            continue
        seen.add(key)
        lic = pkg.get("license") or pkg.get("license_file") or "UNKNOWN"
        if not is_gpl3_compatible(lic):
            incompatible.append(f"{pkg['name']} {pkg['version']}: {lic}")
        crates.append(
            {
                "name": pkg["name"],
                "version": pkg["version"],
                "license": lic,
                "direct": pkg["name"] in direct_names,
                "repository": pkg.get("repository") or pkg.get("homepage") or "",
            }
        )

    crates.sort(key=lambda c: (not c["direct"], c["name"].lower(), c["version"]))
    return crates, incompatible


ANDROID_KNOWN_META = {
    "androidx.webkit:webkit": ("Apache-2.0", "WebView proxy & X-Requested-With configuration"),
    "androidx.appcompat:appcompat": ("Apache-2.0", "Android AppCompat UI support"),
    "androidx.activity:activity-ktx": ("Apache-2.0", "Predictive back & ActivityResult APIs"),
    "com.google.android.material:material": ("Apache-2.0", "Material Components for Android"),
    "androidx.lifecycle:lifecycle-process": ("Apache-2.0", "Process lifecycle observer"),
    "androidx.core:core-ktx": ("Apache-2.0", "Core AndroidX Kotlin extensions"),
    "androidx.biometric:biometric": ("Apache-2.0", "System BiometricPrompt integration"),
    "androidx.work:work-runtime": ("Apache-2.0", "Scheduled background monitoring via WorkManager"),
    "com.google.mlkit:text-recognition": (
        "Google APIs ToS (play flavor only)",
        "Optional offline OCR in the `play` build flavor (completely excluded from `foss` / F-Droid)",
    ),
}


def collect_android_libs() -> tuple[list[dict], list[str]]:
    text = GRADLE_PATH.read_text(encoding="utf-8")
    # Both `playImplementation(...)` and the string form `"playImplementation"(...)` (needed for
    # dynamically created flavors, whose configuration accessors are not generated).
    pattern = re.compile(
        r'^\s*"?(implementation|fossImplementation|playImplementation)"?\("([^"]+)"\)', re.M
    )
    libs: list[dict] = []
    errors: list[str] = []
    for cfg, coord in pattern.findall(text):
        parts = coord.split(":")
        if len(parts) < 3:
            continue
        group_art = f"{parts[0]}:{parts[1]}"
        version = parts[2]
        flavor = "play" if cfg == "playImplementation" else ("foss" if cfg == "fossImplementation" else "both")
        proprietary = group_art.startswith("com.google.mlkit:")
        if proprietary and flavor != "play":
            errors.append(f"Proprietary Android dependency {coord} must use playImplementation, not {cfg}")
        lic, purpose = ANDROID_KNOWN_META.get(group_art, ("Apache-2.0", "Android runtime dependency"))
        libs.append(
            {
                "name": group_art,
                "version": version,
                "license": lic,
                "flavor": flavor,
                "proprietary": proprietary,
                "purpose": purpose,
            }
        )

    # Verify zero ML Kit imports in `main` and `foss` Kotlin/Java sources.
    for src_dir in (ANDROID_SRC / "main", ANDROID_SRC / "foss"):
        if not src_dir.exists():
            continue
        for kt in src_dir.rglob("*.kt"):
            body = kt.read_text(encoding="utf-8", errors="replace")
            if "com.google.mlkit" in body:
                errors.append(f"Forbidden ML Kit reference in {kt.relative_to(ROOT)}")

    libs.sort(key=lambda x: (x["flavor"] == "play", x["name"]))
    # Guard against a silently missed dependency line (the play-only ML Kit entry vanished once
    # when the Gradle syntax changed).
    declared = sum(
        1
        for prefix in re.findall(r'^\s*"?([A-Za-z]*?)[Ii]mplementation"?\s*\(', text, re.M)
        if not prefix.lower().startswith(("test", "androidtest"))
    )
    if declared != len(libs):
        errors.append(f"build.gradle.kts declares {declared} runtime dependencies, parsed {len(libs)}")
    return libs, errors


def collect_data_and_assets() -> list[dict]:
    return [
        {
            "name": "FOCA-rs",
            "category": "Application",
            "license": "GPL-3.0",
            "url": "https://github.com/SinonApp/FOCA-rs",
            "notes": "Open-source mobile OSINT, document metadata & forensics engine (GNU GPL v3.0).",
        },
        {
            "name": "Inter Font",
            "category": "Font",
            "license": "SIL OFL 1.1",
            "url": "https://rsms.me/inter/",
            "notes": "Embedded UI typeface (`ui/fonts/Inter-Regular.ttf`, `Inter-SemiBold.ttf`), © Rasmus Andersson.",
        },
        {
            "name": "Fluent Emoji (App Icon)",
            "category": "Artwork",
            "license": "MIT",
            "url": "https://github.com/microsoft/fluentui-emoji",
            "notes": "Application icon artwork, © Microsoft Corporation.",
        },
        {
            "name": "Natural Earth 1:110m & 1:50m",
            "category": "Dataset",
            "license": "Public Domain",
            "url": "https://www.naturalearthdata.com/",
            "notes": "Offline world country boundaries for the 3D GPS globe (`ui/data/ne110.js`, `ne50.js`).",
        },
        {
            "name": "SecLists (pinned commit 1a89b46)",
            "category": "Wordlists",
            "license": "MIT",
            "url": "https://github.com/danielmiessler/SecLists",
            "notes": "Embedded gzipped path/subdomain discovery wordlists (`crates/foca-fuzz/wordlists`, `crates/foca-net/wordlists`), © Daniel Miessler.",
        },
        {
            "name": "CISA Known Exploited Vulnerabilities (KEV)",
            "category": "Dataset",
            "license": "Public Domain (U.S. Gov)",
            "url": "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            "notes": "Filtered offline snapshot (`crates/foca-analysis/signatures/kev.tsv.gz`, 17 U.S.C. § 105). CISA does not endorse FOCA-rs.",
        },
        {
            "name": "Cloud & CDN IP Prefix Lists",
            "category": "Dataset",
            "license": "Published Network Facts",
            "url": "https://www.cloudflare.com/ips/",
            "notes": "Aggregated public CIDR prefixes (Cloudflare, AWS, Azure, GCP, Fastly, DigitalOcean, Akamai, Hetzner) in `crates/foca-net/data/cloud_ranges.txt.gz`.",
        },
        {
            "name": "Security Standards Identifiers",
            "category": "Reference",
            "license": "Facts / CC BY-SA 4.0 (OWASP)",
            "url": "https://attack.mitre.org/",
            "notes": "Rule-to-identifier mapping only (`standards.toml`): MITRE ATT&CK v20, CWE (2025 Top 25 flag), OWASP Top 10:2025 & WSTG v4.2, ISO/IEC 27001:2022 Annex A, NIST SP 800-53 Rev. 5 / НД ТЗІ 3.6-006-24 control ids and titles, GDPR and Law of Ukraine No. 2297-VI article numbers, НД ТЗІ 2.5-004-99, НД ТЗІ 3.7-003-05.",
        },
        {
            "name": "FOCA (ElevenPaths / Telefónica Tech)",
            "category": "Algorithm / Concept",
            "license": "GPL-3.0",
            "url": "https://github.com/ElevenPaths/FOCA",
            "notes": "Inspiration for document OSINT & backups fuzzing workflows; clean-room Rust implementation.",
        },
        {
            "name": "ffuf / gau / waymore / subfinder / go-dork / ds_store / Wappalyzer",
            "category": "Algorithm / Concept",
            "license": "MIT / GPL-3.0",
            "url": "https://github.com/SinonApp/FOCA-rs/blob/main/THIRD_PARTY.md",
            "notes": "Algorithmic concepts (soft-404 auto-calibration, CDX pagination, passive subdomain endpoints, DS_Store & tech fingerprinting); clean-room Rust code.",
        },
        {
            "name": "MurmurHash3",
            "category": "Algorithm",
            "license": "Public Domain",
            "url": "https://github.com/aappleby/smhasher",
            "notes": "Clean-room Rust implementation of MurmurHash3 x86_32 for Shodan/FOFA favicon hashing.",
        },
    ]


SOURCES_LOCK = ROOT / "crates/foca-analysis/signatures/sources.lock.json"
NOTICE_PATH = ROOT / "NOTICE"
THIRD_PARTY_PATH = ROOT / "THIRD_PARTY.md"
# Licenses of ingested signature data that may ship in the GPL-3.0 app (see the ingest scripts).
SIGNATURE_LICENSES = {
    "GPL-3.0-only": "GPL-3.0",
    "MIT": "MIT",
    "Apache-2.0": "Apache-2.0",
    "BSD-2-Clause": "BSD-2-Clause",
    "MPL-2.0": "MPL-2.0",
    "CC0-1.0": "CC0-1.0",
    "CC-BY-4.0": "CC-BY-4.0",
    "FIRST-EPSS-terms": "EPSS (attribution requested)",
}


def collect_signature_sources() -> tuple[list[dict], list[str]]:
    """Data assets for the pinned upstream sources in `sources.lock.json`.

    Every source must carry an allowed license and attribution text, its attribution must appear in
    NOTICE and its repository or URL in THIRD_PARTY.md.
    """
    lock = json.loads(SOURCES_LOCK.read_text(encoding="utf-8"))["sources"]
    notice = NOTICE_PATH.read_text(encoding="utf-8") if NOTICE_PATH.exists() else ""
    third = THIRD_PARTY_PATH.read_text(encoding="utf-8")
    items, errors = [], []
    for key, src in sorted(lock.items()):
        lic = src.get("license", "")
        if lic not in SIGNATURE_LICENSES:
            errors.append(f"signature source {key}: license {lic!r} is not allowed")
            continue
        url = src.get("repo") or src.get("url", "")
        pin = src.get("tag") or src.get("version") or src.get("commit", "")[:12]
        attribution = src.get("attribution", "")
        if not attribution:
            errors.append(f"signature source {key}: no attribution text")
        elif attribution not in notice:
            errors.append(f"signature source {key}: attribution missing from NOTICE")
        if url.split("://")[-1] not in third:
            errors.append(f"signature source {key}: {url} missing from THIRD_PARTY.md")
        outputs = ", ".join(f"`{o['path']}`" for o in src.get("outputs", []))
        items.append({
            "name": f"{key} (pinned {pin})",
            "category": "Dataset",
            "license": SIGNATURE_LICENSES[lic],
            "url": url,
            "notes": f"{attribution}. Signature data in {outputs}.",
        })
    return items, errors


def load_license_texts() -> list[dict]:
    gpl3 = (ROOT / "LICENSE").read_text(encoding="utf-8").strip()
    mit = """MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE."""

    apache2 = """Apache License
Version 2.0, January 2004
http://www.apache.org/licenses/

TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

1. Definitions.
"License" shall mean the terms and conditions for use, reproduction, and distribution as defined by Sections 1 through 9 of this document.
"Licensor" shall mean the copyright owner or entity authorized by the copyright owner that is granting the License.
"Legal Entity" shall mean the union of the acting entity and all other entities that control, are controlled by, or are under common control with that entity.
"You" (or "Your") shall mean an individual or Legal Entity exercising permissions granted by this License.
"Source" form shall mean the preferred form for making modifications, including but not limited to software source code, documentation source, and configuration files.
"Object" form shall mean any form resulting from mechanical transformation or translation of a Source form.
"Work" shall mean the work of authorship made available under the License.
"Derivative Works" shall mean any work based on (or derived from) the Work.
"Contribution" shall mean any work of authorship intentionally submitted to the Licensor for inclusion in the Work.

2. Grant of Copyright License.
Subject to the terms and conditions of this License, each Contributor hereby grants to You a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable copyright license to reproduce, prepare Derivative Works of, publicly display, publicly perform, sublicense, and distribute the Work and such Derivative Works in Source or Object form.

3. Grant of Patent License.
Subject to the terms and conditions of this License, each Contributor hereby grants to You a perpetual, worldwide, non-exclusive, no-charge, royalty-free, irrevocable patent license to make, have made, use, offer to sell, sell, import, and otherwise transfer the Work. If You institute patent litigation against any entity alleging that the Work constitutes patent infringement, then any patent licenses granted to You under this License for that Work shall terminate as of the date such litigation is filed.

4. Redistribution.
You may reproduce and distribute copies of the Work or Derivative Works thereof in any medium, with or without modifications, and in Source or Object form, provided that You meet the following conditions:
(a) You must give any other recipients of the Work or Derivative Works a copy of this License; and
(b) You must cause any modified files to carry prominent notices stating that You changed the files; and
(c) You must retain, in the Source form of any Derivative Works that You distribute, all copyright, patent, trademark, and attribution notices from the Source form of the Work; and
(d) If the Work includes a "NOTICE" text file, You must include a readable copy of the attribution notices contained within such NOTICE file.

5. Submission of Contributions.
Unless You explicitly state otherwise, any Contribution intentionally submitted for inclusion in the Work by You to the Licensor shall be under the terms and conditions of this License.

6. Trademarks.
This License does not grant permission to use the trade names, trademarks, service marks, or product names of the Licensor.

7. Disclaimer of Warranty.
Unless required by applicable law or agreed to in writing, Licensor provides the Work on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

8. Limitation of Liability.
In no event and under no legal theory, whether in tort (including negligence), contract, or otherwise, shall any Contributor be liable to You for damages, including any direct, indirect, special, incidental, or consequential damages of any character arising as a result of this License or out of the use or inability to use the Work.

9. Accepting Warranty or Additional Liability.
While redistributing the Work or Derivative Works thereof, You may choose to offer acceptance of support, warranty, indemnity, or other liability obligations consistent with this License."""

    bsd2 = """BSD 2-Clause "Simplified" License

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."""

    bsd3 = """BSD 3-Clause "New" or "Revised" License

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.
3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software without
   specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."""

    isc = """ISC License

Permission to use, copy, modify, and/or distribute this software for any purpose
with or without fee is hereby granted, provided that the above copyright notice
and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS
OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
THIS SOFTWARE."""

    mpl2 = """Mozilla Public License Version 2.0
https://www.mozilla.org/en-US/MPL/2.0/

1. Definitions: "Covered Software" means Source Code Form to which the initial Contributor has attached the notice in Exhibit A, the Executable Form of such Source Code Form, and Modifications of such Source Code Form.
2. License Grants and Conditions: Each Contributor hereby grants You a world-wide, royalty-free, non-exclusive copyright and patent license to use, reproduce, make available, modify, display, perform, distribute, and otherwise exploit its Contributions on an unmodified basis, with Modifications, or as part of a Larger Work.
3. Responsibilities: All distribution of Covered Software in Source Code Form must be under the terms of this License. If You distribute Covered Software in Executable Form, such Covered Software must also be made available in Source Code Form, and You must inform recipients how they can obtain a copy of such Source Code Form by reasonable means in a timely manner. Under Section 3.3, Covered Software may be combined with a Secondary License (including GNU GPL v3.0).
4. Inability to Comply Due to Statute or Regulation: If it is impossible for You to comply with any of the terms of this License due to statute, judicial order, or regulation, You must describe the limitations and the code they affect.
5. Termination: The rights granted under this License will terminate automatically if You fail to comply with any of its terms (with 30-day cure period for first breach).
6. Disclaimer of Warranty: Covered Software is provided under this License on an "as is" basis, without warranty of any kind, either expressed, implied, or statutory.
7. Limitation of Liability: Under no circumstances and under no legal theory shall any Contributor be liable for any direct, indirect, special, incidental, or consequential damages of any character.
8. Litigation: Any litigation relating to this License may be brought only in the courts of a jurisdiction where the defendant maintains its principal place of business.
10. Versions of the License: Mozilla Foundation is the license steward."""

    ofl11 = """SIL OPEN FONT LICENSE Version 1.1 - 26 February 2007

PREAMBLE
The goals of the Open Font License (OFL) are to stimulate worldwide development of collaborative font projects, to support the font creation efforts of academic and linguistic communities, and to provide a free and open framework in which fonts may be shared and improved in partnership with others.

PERMISSION & CONDITIONS
Permission is hereby granted, free of charge, to any person obtaining a copy of the Font Software, to use, study, copy, merge, embed, modify, redistribute, and sell modified and unmodified copies of the Font Software, subject to the following conditions:
1) Neither the Font Software nor any of its individual components, in Original or Modified Versions, may be sold by itself.
2) Original or Modified Versions of the Font Software may be bundled, redistributed and/or sold with any software, provided that each copy contains the above copyright notice and this license.
3) No Modified Version of the Font Software may use the Reserved Font Name(s) unless explicit written permission is granted by the corresponding Copyright Holder.
4) The name(s) of the Copyright Holder(s) or the Author(s) of the Font Software shall not be used to promote, endorse or advertise any Modified Version, except to acknowledge the contribution(s).
5) The Font Software, modified or unmodified, in part or in whole, must be distributed entirely under this license, and must not be distributed under any other license.

TERMINATION
This license becomes null and void if any of the above conditions are not met.

DISCLAIMER
THE FONT SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF COPYRIGHT, PATENT, TRADEMARK, OR OTHER RIGHT."""

    cdla2 = """Community Data License Agreement – Permissive – Version 2.0
https://cdla.dev/permissive-2-0/

This is the Community Data License Agreement – Permissive, Version 2.0 ("Agreement"). Data is provided to You under this Agreement by each of the Data Providers. Your exercise of any of the rights and permissions granted below constitutes Your acceptance and agreement to be bound by the terms and conditions of this Agreement.

1. Rights Granted: Subject to the terms of this Agreement, each Data Provider hereby grants You a worldwide, non-exclusive, irrevocable, royalty-free right to Use, Publish, and modify Data, and to create and Publish Results.
2. No Restrictions on Results: This Agreement does not impose any restriction with respect to the Use or Publication of Results.
3. Redistribution of Data: You may Publish Data received under this Agreement, provided that You retain all copyright, attribution, and license notices associated with the Data and identify that the Data is made available under CDLA-Permissive-2.0.
4. No Warranty / Limitation of Liability: EXCEPT AS EXPRESSLY SET FORTH IN THIS AGREEMENT, THE DATA IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED."""

    unicode3 = """UNICODE LICENSE V3

COPYRIGHT AND PERMISSION NOTICE
Copyright © 1991-2024 Unicode, Inc.

NOTICE TO USER: Carefully read the following legal agreement. BY DOWNLOADING, INSTALLING, COPYING OR OTHERWISE USING DATA FILES, AND/OR SOFTWARE, YOU UNEQUIVOCALLY ACCEPT, AND AGREE TO BE BOUND BY, ALL OF THE TERMS AND CONDITIONS OF THIS AGREEMENT.

Permission is hereby granted, free of charge, to any person obtaining a copy of data files and any associated documentation (the "Data Files") or software and any associated documentation (the "Software") to deal in the Data Files or Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, and/or sell copies of the Data Files or Software, and to permit persons to whom the Data Files or Software are furnished to do so, provided that either (a) this copyright and permission notice appear with all copies of the Data Files or Software, or (b) this copyright and permission notice appear in associated Documentation.

THE DATA FILES AND SOFTWARE ARE PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT OF THIRD PARTY RIGHTS."""

    ccby4 = """Creative Commons Attribution 4.0 International (CC BY 4.0)

Legal code: https://creativecommons.org/licenses/by/4.0/legalcode

You are free to share (copy and redistribute the material in any medium or format) and adapt
(remix, transform, and build upon the material) for any purpose, even commercially, under the
following terms: Attribution: you must give appropriate credit, provide a link to the license, and
indicate if changes were made. No additional restrictions: you may not apply legal terms or
technological measures that legally restrict others from doing anything the license permits.

FOCA-rs uses the can-i-take-over-xyz fingerprints (EdOverflow and contributors) under this license;
the fields were reduced and renamed (see NOTICE)."""
    cc0 = """Creative Commons Zero v1.0 Universal (CC0 1.0), public domain dedication

Legal code: https://creativecommons.org/publicdomain/zero/1.0/legalcode

The person who associated a work with this deed has dedicated the work to the public domain by
waiving all of their rights to the work worldwide under copyright law, including all related and
neighboring rights, to the extent allowed by law. You can copy, modify, distribute and perform the
work, even for commercial purposes, all without asking permission."""
    epss = """FIRST Exploit Prediction Scoring System (EPSS)

EPSS scores are published daily by FIRST (https://www.first.org/epss) and are free to use. FIRST asks
users to credit the data: "EPSS scores from FIRST.org", with the model version or score date.
FOCA-rs shows this attribution in the licenses screen, in NOTICE and in the footer of reports that
display EPSS values. FIRST does not endorse FOCA-rs."""
    return [
        {"id": "GPL-3.0", "name": "GNU General Public License v3.0", "text": gpl3},
        {"id": "MIT", "name": "MIT License", "text": mit},
        {"id": "Apache-2.0", "name": "Apache License 2.0", "text": apache2},
        {"id": "BSD-2-Clause", "name": "BSD 2-Clause License", "text": bsd2},
        {"id": "BSD-3-Clause", "name": "BSD 3-Clause License", "text": bsd3},
        {"id": "ISC", "name": "ISC License", "text": isc},
        {"id": "MPL-2.0", "name": "Mozilla Public License 2.0", "text": mpl2},
        {"id": "SIL OFL 1.1", "name": "SIL Open Font License 1.1", "text": ofl11},
        {"id": "CDLA-Permissive-2.0", "name": "Community Data License Agreement – Permissive 2.0", "text": cdla2},
        {"id": "Unicode-3.0", "name": "Unicode License v3", "text": unicode3},
        {"id": "CC-BY-4.0", "name": "Creative Commons Attribution 4.0 International", "text": ccby4},
        {"id": "CC0-1.0", "name": "Creative Commons Zero v1.0 Universal", "text": cc0},
        {"id": "EPSS (attribution requested)", "name": "FIRST EPSS usage terms", "text": epss},
    ]


def build_payload() -> tuple[dict, list[str]]:
    rust_crates, rust_errors = collect_rust_crates()
    android_libs, android_errors = collect_android_libs()
    sig_assets, sig_errors = collect_signature_sources()
    data_assets = collect_data_and_assets() + sig_assets
    texts = load_license_texts()
    errors = rust_errors + android_errors + sig_errors
    payload = {
        "schema": "foca-licenses/v1",
        "app_license": "GPL-3.0",
        "repository": "https://github.com/SinonApp/FOCA-rs",
        "counts": {
            "data_assets": len(data_assets),
            "rust_total": len(rust_crates),
            "rust_direct": sum(1 for c in rust_crates if c["direct"]),
            "android_total": len(android_libs),
            "android_play_only": sum(1 for a in android_libs if a["flavor"] == "play"),
            "license_texts": len(texts),
        },
        "data_assets": data_assets,
        "rust_crates": rust_crates,
        "android_libs": android_libs,
        "license_texts": texts,
    }
    return payload, errors


def main() -> int:
    check = "--check" in sys.argv[1:]
    payload, errors = build_payload()
    if errors:
        print("LICENSE COMPLIANCE ERRORS:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    serialized = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    if check:
        if not OUT_PATH.exists():
            print(f"MISSING {OUT_PATH.relative_to(ROOT)}: run `python qa/gen-licenses.py`", file=sys.stderr)
            return 1
        current = OUT_PATH.read_text(encoding="utf-8")
        if current != serialized:
            print(
                f"OUT-OF-DATE {OUT_PATH.relative_to(ROOT)}: run `python qa/gen-licenses.py` to refresh",
                file=sys.stderr,
            )
            return 1
        c = payload["counts"]
        print(
            f"licenses.json OK: {c['rust_total']} Rust crates ({c['rust_direct']} direct), "
            f"{c['android_total']} Android libs ({c['android_play_only']} play-only), "
            f"{c['data_assets']} data/assets, {c['license_texts']} license texts: 100% GPL-3.0 / foss clean"
        )
        return 0

    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUT_PATH.write_text(serialized, encoding="utf-8", newline="\n")
    c = payload["counts"]
    print(
        f"Generated {OUT_PATH.relative_to(ROOT)}: {c['rust_total']} Rust crates ({c['rust_direct']} direct), "
        f"{c['android_total']} Android libs ({c['android_play_only']} play-only), "
        f"{c['data_assets']} data/assets, {c['license_texts']} license texts"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
