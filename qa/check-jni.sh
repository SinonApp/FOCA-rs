#!/usr/bin/env bash
# Verifies the Android package and the JNI symbols.
#  1) identifier in src-tauri/tauri.conf.json == namespace/applicationId in build.gradle.kts,
#     app/src/{main,test}/java/<pkg> exists, and no other package directories contain Kotlin;
#  2) class name strings in Rust ("<pkg>.platform.X" for JNI/the plugin) point to existing Kotlin classes;
#  3) Java_<pkg>_* functions exported from libfoca_rs_lib.so <-> `external fun` in Kotlin (both ways).
# If the .so has not been built yet, step 3 is skipped (SKIP); if it predates a package rename, it FAILs.
# Usage: bash qa/check-jni.sh [path/to/libfoca_rs_lib.so]
set -uo pipefail
cd "$(dirname "$0")/.."
python3 - "$@" <<'PY'
import glob, json, os, re, shutil, subprocess, sys

fails = []
def fail(m): fails.append(m); print("FAIL", m)

pkg = json.load(open("src-tauri/tauri.conf.json"))["identifier"]
gradle = open("src-tauri/gen/android/app/build.gradle.kts").read()
for key in ("namespace", "applicationId"):
    m = re.search(key + r'\s*=\s*"([^"]+)"', gradle)
    if not m or m.group(1) != pkg:
        fail(f"{key} in build.gradle.kts = {m and m.group(1)!r}, but identifier = {pkg!r}")
pdir = pkg.replace(".", "/")
root = "src-tauri/gen/android/app/src"
if not os.path.isdir(f"{root}/main/java/{pdir}"):
    fail(f"missing directory {root}/main/java/{pdir} (tauri android build will refuse: identifier changed)")
for kt in glob.glob(f"{root}/*/java/**/*.kt", recursive=True):
    rel = kt.split("/java/", 1)[1]
    if not rel.startswith(pdir + "/"):
        fail(f"Kotlin outside package {pkg}: {kt} (leftover of an old package or a duplicate of generated?)")
    m = re.search(r"^package\s+([\w.]+)", open(kt, encoding="utf-8").read(), re.M)
    if m and not m.group(1).startswith(pkg):
        fail(f"{kt}: package {m.group(1)} is not under {pkg}")

# Kotlin sources: ours plus generated ones (before the first generation, the wry templates from the cargo registry).
srcs = {kt: open(kt, encoding="utf-8").read() for kt in glob.glob(f"{root}/main/java/**/*.kt", recursive=True)}
if not glob.glob(f"{root}/main/java/{pdir}/generated/*.kt"):
    home = os.environ.get("CARGO_HOME", os.path.expanduser("~/.cargo"))
    tpl = sorted(glob.glob(f"{home}/registry/src/*/wry-*/src/android/kotlin/*.kt"))
    for t in tpl:
        srcs[t] = open(t, encoding="utf-8").read().replace("{{package}}", pkg)
    print(f"note: no generated/, using wry templates ({len(tpl)} files)")

classes = set() # fully qualified class/object names
for path, s in srcs.items():
    m = re.search(r"^package\s+([\w.]+)", s, re.M)
    p = m.group(1) if m else ""
    for c in re.findall(r"^\s*(?:(?:private|internal|public|open|abstract|data|sealed|enum)\s+)*(?:class|object|interface)\s+(\w+)", s, re.M):
        classes.add(f"{p}.{c}")

# 2) class name strings in Rust
for rs in glob.glob("src-tauri/src/**/*.rs", recursive=True):
    s = open(rs, encoding="utf-8").read()
    for cls in re.findall(r'"(' + re.escape(pkg) + r'(?:\.\w+)+)"', s):
        if cls not in classes and not any(c.startswith(cls + ".") for c in classes):
            fail(f"{rs}: class/package {cls} not found in Kotlin")
    for m in re.finditer(r'register_android_plugin\(\s*"([\w.]+)"\s*,\s*"(\w+)"', s):
        if f"{m.group(1)}.{m.group(2)}" not in classes:
            fail(f"{rs}: plugin {m.group(1)}.{m.group(2)} not found in Kotlin")
    for old in re.findall(r'"((?:[a-z]+\.){2,}\w+)"', s):
        if old.count(".") >= 2 and old.split(".")[0] in ("dev", "com", "org") and "focars" in old:
            fail(f"{rs}: string with the old package {old}")

# 3) external fun -> expected JNI names
def mangle(x): return x.replace("_", "_1").replace(".", "_")
want = set()
for path, s in srcs.items():
    m = re.search(r"^package\s+([\w.]+)", s, re.M)
    p = m.group(1) if m else ""
    cur = None
    for line in s.splitlines():
        cm = re.match(r"^\s*(?:(?:private|internal|public|open|abstract|data)\s+)*(?:class|object)\s+(\w+)", line)
        if cm and not line.lstrip().startswith("companion"):
            cur = cm.group(1)
        fm = re.search(r"\bexternal\s+fun\s+(\w+)", line)
        if fm and cur:
            want.add(f"Java_{mangle(p)}_{mangle(cur)}_{mangle(fm.group(1))}")
print(f"external fun in Kotlin: {len(want)}")
if not want:
    fail("no external fun found (is the parser broken?)")

so = sys.argv[1] if len(sys.argv) > 1 else None
if not so:
    tgt = os.environ.get("CARGO_TARGET_DIR", "target")
    cands = [c for c in glob.glob(f"{tgt}/aarch64-linux-android/*/libfoca_rs_lib.so")]
    so = max(cands, key=os.path.getmtime) if cands else None
if not so or not os.path.exists(so):
    print("SKIP JNI symbols: libfoca_rs_lib.so is not built (cargo build --target aarch64-linux-android -p foca-rs)")
else:
    nm = shutil.which("llvm-nm") or next(iter(sorted(glob.glob(
        os.environ.get("ANDROID_HOME", os.environ.get("ANDROID_SDK_ROOT", "")) + "/ndk/*/toolchains/llvm/prebuilt/*/bin/llvm-nm"))), None) or shutil.which("nm")
    out = subprocess.run([nm, "-D", "--defined-only", so], capture_output=True, text=True).stdout
    have = {l.split()[-1] for l in out.splitlines() if " Java_" in l}
    ours = "Java_" + mangle(pkg) + "_"
    print(f"{so}: Java_* = {len(have)}")
    for h in sorted(have):
        if h.startswith("Java_app_tauri_"):
            continue # classes from the Tauri plugin AAR, not our package
        if not h.startswith(ours):
            fail(f"symbol {h} is not from package {pkg} (.so built with an old identifier?)")
        elif h not in want:
            fail(f"symbol {h} has no external fun in Kotlin")
    for w in sorted(want - have):
        fail(f"external fun without a symbol in the .so: {w}")

print(f"check-jni: {'OK' if not fails else str(len(fails)) + ' FAIL'} (package {pkg})")
sys.exit(1 if fails else 0)
PY
