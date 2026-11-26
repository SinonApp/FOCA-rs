#!/usr/bin/env bash
# Kotlin check of the Android app through Gradle: compiles both product flavors (foss, play;
# release variants, no APK and no .so) and runs the JVM unit tests (app/src/test, shared by the
# flavors, so the foss debug variant runs them). A plain kotlinc run cannot see flavor sources,
# string resources or android/print/*.java, hence Gradle.
#
# The Tauri-generated Gradle files (tauri.settings.gradle, app/tauri.build.gradle.kts,
# generated/*.kt …) are gitignored; when they are missing (clean checkout) they are created by
# `qa/android-build.sh kotlin` (cargo check for aarch64, then the same flavor compile).
#
# Usage: bash qa/check-kotlin.sh   → "OK (N tests)" on success.
# Environment: ANDROID_HOME, JDK 17+; GRADLE_USER_HOME is honoured.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/.." && pwd)
GEN=$ROOT/src-tauri/gen/android
[ -f /etc/profile.d/android.sh ] && . /etc/profile.d/android.sh
PKG=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["identifier"])' "$ROOT/src-tauri/tauri.conf.json")
KT_OUT=$GEN/app/src/main/java/${PKG//.//}/generated

missing=0
for f in tauri.settings.gradle app/tauri.build.gradle.kts app/proguard-tauri.pro app/tauri.properties; do
  [ -f "$GEN/$f" ] || missing=1
done
[ -f "$KT_OUT/TauriActivity.kt" ] || missing=1

cd "$GEN"
ABI=(-PtargetList=aarch64 -ParchList=arm64 -PabiList=arm64-v8a)
if [ $missing = 1 ]; then
  echo "Tauri-generated Android files missing: running qa/android-build.sh kotlin"
  bash "$ROOT/qa/android-build.sh" kotlin
else
  ./gradlew --no-daemon -q "${ABI[@]}" -x rustBuildArm64Release -x rustBuildUniversalRelease \
    :app:compileUniversalFossReleaseKotlin :app:compileUniversalPlayReleaseKotlin
fi
echo "COMPILE foss+play ok"

RES=app/build/test-results/testUniversalFossDebugUnitTest
rm -rf "$RES"
./gradlew --no-daemon -q "${ABI[@]}" -x rustBuildArm64Debug -x rustBuildUniversalDebug \
  :app:testUniversalFossDebugUnitTest || { echo "FAIL: unit tests (see $GEN/app/build/reports/tests)"; exit 1; }
python3 - "$RES" <<'PY'
import glob, sys, xml.etree.ElementTree as ET
n = bad = 0
for f in glob.glob(sys.argv[1] + "/*.xml"):
    r = ET.parse(f).getroot()
    n += int(r.get("tests", 0))
    bad += int(r.get("failures", 0)) + int(r.get("errors", 0))
if n == 0 or bad:
    print("FAIL (%d tests, %d failed)" % (n, bad)); sys.exit(1)
print("OK (%d tests)" % n)
PY
