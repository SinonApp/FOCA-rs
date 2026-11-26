# Build & Test Guide

↑ [Developer Guide](README.md) · [Documentation](../README.md)

- [Prerequisites](#prerequisites)
- [Environment](#environment)
- [Desktop Core Checks](#desktop-core-checks)
- [License & Flavor Purity Check](#license--flavor-purity-check)
- [Browser UI QA](#browser-ui-qa)
- [Real-Core E2E Harness](#real-core-e2e-harness)
- [APK (`foss` vs `play`)](#apk)
- [APK Signing](#apk-signing)
- [Version Bump](#version-bump)
- [Release Process](#release-process)
- [CI](#ci)

## Prerequisites

- **Rust stable** (`rustup`) plus the Android target. Releases ship arm64 only; add the other targets if you build them locally:
  ```sh
  rustup target add aarch64-linux-android                                  # release APKs
  rustup target add armv7-linux-androideabi x86_64-linux-android           # optional
  ```
- **Android SDK**: platform 37 (`compileSdk 37`, `targetSdk 36`, `minSdk 24`), `build-tools`, `platform-tools`; NDK 29 (`29.0.14206865`, matching CI); JDK 21
- **Node.js 20+** (`npm ci` installs `@tauri-apps/cli`, Prettier, and ESLint); for browser screenshot QA: Playwright (`playwright-core` + Chromium)
- **Python 3.10+** (used by `qa/gen-licenses.py`, `qa/check-docs-links.py`, and `qa/make_demo_case.py`)

## Environment

```sh
export ANDROID_HOME=$HOME/Android/Sdk              # path to Android SDK
export NDK_HOME=$ANDROID_HOME/ndk/29.0.14206865     # NDK for Rust Android cross-compilation
export JAVA_HOME=/path/to/jdk-21
export CARGO_TARGET_DIR=$PWD/target                 # shared target/ for core crates and src-tauri
```

- **Low-memory machines**: cap Cargo parallelism with `CARGO_BUILD_JOBS=2`; configure Gradle `org.gradle.workers.max` and `-Xmx` in `$GRADLE_USER_HOME/gradle.properties` (a full `org.gradle.jvmargs=…` line overrides `src-tauri/gen/android/gradle.properties`). Never commit machine-local Gradle settings.
- **Temp directory mounted `noexec`**: pass `-Djava.io.tmpdir=…` inside `org.gradle.jvmargs`.
- **Live checks**: copy the CLI binary out of `target/` (`cp target/debug/foca <scratch-dir>/foca-<tag>`) so subsequent builds do not overwrite the binary under test.
- **Cargo `Fresh` cache edge case**: if Cargo fails to notice a change in a crate, run `touch crates/<crate>/src/*.rs` and rebuild.

## Desktop Core Checks

```sh
cargo test                                                # default-members = crates/* (src-tauri needs webkit2gtk on Linux)
cargo test --workspace --exclude foca-rs --no-fail-fast   # all core crates, release-gate style
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p foca-rs --lib                                                            # bridge: policy, recovery, headless resume
bash qa/check-kotlin.sh                                                                # Kotlin compile (foss+play) + JUnit tests
cargo check -p foca-rs --target aarch64-linux-android     # Android bridge check (requires NDK CC/AR/LINKER)
cargo run -p foca-cli -- extract tests/corpus/ooxml/contract.docx --json
cargo run -p foca-cli -- run scenarios/passive-osint.toml --dry-run
```

## License & Flavor Purity Check

FOCA-rs embeds an offline third-party license catalog (`crates/foca-engine/data/licenses.json`) served to `/settings/licenses` via IPC `licenses_get {}`. Regenerate or verify it with:

```sh
python qa/gen-licenses.py          # regenerate crates/foca-engine/data/licenses.json
python qa/gen-licenses.py --check  # fail if out-of-date, GPL-3.0 incompatible, or foss flavor dirty
```

`--check` verifies three invariants:
1. `crates/foca-engine/data/licenses.json` matches `Cargo.lock` (`cargo metadata --locked`), `src-tauri/gen/android/app/build.gradle.kts`, and asset metadata in `THIRD_PARTY.md`.
2. Every transitive Rust crate SPDX license expression is compatible with GNU GPL v3.0.
3. Proprietary `com.google.mlkit:*` dependencies use `playImplementation(...)` only, and zero `com.google.mlkit` imports appear in `src/main/` or `src/foss/`.

## Browser UI QA

```sh
npm run format:check
npm run lint
node qa/data-invariants.mjs
python3 qa/check-docs-links.py
qa/shoot.sh --routes "/projects,/p/overview" --out qa/out/tmp --w 393 --fs 1.3 --theme light
qa/run-all.sh            # demo backend: static checks, routes × 4 configs, UI scenarios (~15 min)
qa/run-all.sh --real     # full demo suite + qa/real-e2e.sh (real Rust engine)
```

Details: [docs/testing/README.md](../testing/README.md).

## Real-Core E2E Harness

```sh
foca testnet --port 8788 --write-config stand/net.json       # offline "internet": CDX, crt.sh, tests/corpus documents
foca serve --data stand/data --port 8787 --test-net stand/net.json [--pick-dir dir]   # Engine::invoke over HTTP
qa/shoot.sh --real http://127.0.0.1:8787 --routes "/projects,/p/overview" --out qa/out/tmp
```

- `foca serve`: `POST /invoke {cmd, args}` → `Engine::invoke` (errors return HTTP 400 `{error: {code, message, targets}}`), `GET /events` streams SSE `{event, payload}`, `GET /…` serves static `ui/`; `platform_*` calls return desktop stubs.
- `qa/tauri-shim.js` exposes `window.__TAURI__` on top of `foca serve`; `qa/e2e-serve.sh start|stop|kill|restart|delay` manages the harness inside scenarios.
- Engine logs live in `<data>/logs/foca.log` (1 MB × 3 rotation) and are exposed via `logs_get`.

## APK

Android builds use two product flavors under `flavorDimensions += "distribution"` ([android.md](android.md)):

- **`foss`**: 100% open-source GPL-3.0 / F-Droid build without Google ML Kit (`OcrEngine.kt` stub in `src/foss/`).
- **`play`**: full Android build adding `com.google.mlkit:text-recognition:16.0.1` (`OcrEngine.kt` in `src/play/`) for optional offline OCR.

`npx tauri android build` does not know the flavors, and the Tauri `rustBuild*` Gradle tasks only run inside a live `tauri android build` (they fail with "`cli-options-server.json` … must be running" otherwise). `qa/android-build.sh` does the CLI's part itself: it builds `libfoca_rs_lib.so` with the environment that makes the tauri/wry build scripts write the generated Android files (`tauri.settings.gradle`, `app/tauri.build.gradle.kts`, `app/proguard-tauri.pro`, `generated/*.kt`), writes `app/tauri.properties` and `assets/tauri.conf.json`, copies the `.so` into `jniLibs/arm64-v8a` and runs Gradle with the Tauri Rust tasks excluded:

```sh
bash qa/android-build.sh kotlin   # cargo check + Kotlin compile of both flavors (no APK)
bash qa/android-build.sh apk      # unsigned arm64 universal{Foss,Play}Release APKs
# → src-tauri/gen/android/app/build/outputs/apk/universal{Foss,Play}/release/*-unsigned.apk
```

The Gradle step alone (after the `.so` is in `jniLibs`), from `src-tauri/gen/android/`:

```sh
./gradlew assembleUniversalFossRelease assembleUniversalPlayRelease \
  -PtargetList=aarch64 -ParchList=arm64 -PabiList=arm64-v8a \
  -x rustBuildArm64Release -x rustBuildUniversalRelease
```

Notes:
- `src-tauri` is a member of the root Cargo workspace: `.so` libraries and build artifacts live under the root `target/`, and the release profile (`lto = "thin"`, `opt-level = "s"`, `strip = true`, `panic = "unwind"`: [ADR-0005](../adr/0005-panic-strategy.md)) is configured in the root `Cargo.toml`.
- Building a subset of ABIs can leave stale `.so` files for other ABIs in `src-tauri/gen/android/app/src/main/jniLibs/`: clean stale ABI folders before packaging a release APK.
- Signed release APKs are placed in `dist/` (gitignored): e.g., `dist/FOCA-rs-<version>-foss-arm64.apk` and `dist/FOCA-rs-<version>-play-arm64.apk`.

<a id="подпись-apk"></a>
## APK Signing

The release keystore `focars.jks` lives in the working tree root (gitignored via `*.jks`), and its password is stored in a file outside the repository. Never pass keystore passwords on the command line or write them into docs or logs.

```sh
zipalign -f -p 4 app-foss-arm64-release-unsigned.apk aligned.apk
apksigner sign --ks focars.jks --ks-pass file:<password-file> --out dist/FOCA-rs-<ver>-foss-arm64.apk aligned.apk
rm -f dist/*.idsig
apksigner verify --print-certs dist/FOCA-rs-<ver>-foss-arm64.apk   # must match previous releases
aapt2 dump badging dist/FOCA-rs-<ver>-foss-arm64.apk | head -1      # verify versionName / versionCode
```

Starting with 2.0.0-beta.1, releases are signed with a new key (certificate DN `CN=FOCA-rs, O=FOCA-rs`). The certificate SHA-256 is published in the release notes. Builds signed with the old key (1.x, 2.0.0 previews and rc) cannot be updated in place: users uninstall them first.

Signing with a different certificate prevents in-place upgrades over previous installations ("package conflict").

## Version Bump

Update all copies in a single commit:

- `src-tauri/tauri.conf.json` → `version`. `versionCode` is derived as `major·1000000 + minor·1000 + patch` (`2.0.0` → `2000000`) and ignores the pre-release part, so a pre-release sets `bundle.android.versionCode` explicitly (`2.0.0-beta.1` → `2000001`, `2.0.0-beta.2` → `2000002`; `qa/android-build.sh` honours it). It must grow with every build that users install;
- Root `Cargo.toml` (`workspace.package.version`), `src-tauri/Cargo.toml`, `package.json` and `package-lock.json` (then `cargo update -w` for `Cargo.lock`);
- Fallback version string in `CrashLog.kt`, the version fallbacks and the first `CHANGES` entry in `ui/screens/settings.js`, and `app_version` in `ui/js/demo-backend.js`;
- `generator: "FOCA-rs <ver>"` in `crates/foca-report/tests/golden/*` and `examples/out/*` (`UPDATE_GOLDEN=1 cargo test -p foca-report --test report`).

Check for stale references with `grep -rn "<old-version>" crates ui src-tauri/gen/android/app/src`.

Release gate:
- `npm run format:check && npm run lint`
- `cargo fmt --all -- --check && cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace --exclude foca-rs --no-fail-fast`
- `python qa/gen-licenses.py --check`
- `python3 qa/check-docs-links.py`
- `cargo build -p foca-cli && bash qa/run-all.sh --real` (`RESULT: ALL GREEN`)

## Release Process

2.0 ships as a beta first. The steps for `v2.0.0-beta.2`:

1. Finish on `develop`: version bump (above), `CHANGELOG.md` section with the date, release gate green.
2. Build both flavors (`bash qa/android-build.sh apk`), align and sign them (see [APK Signing](#apk-signing)), name them `FOCA-rs-<ver>-foss-arm64.apk` and `FOCA-rs-<ver>-play-arm64.apk`.
3. Merge `develop` into `main` and tag the merge commit: `git tag -a v2.0.0-beta.2 -m "FOCA-rs 2.0.0-beta.2"`, then push the tag.
4. Create a GitHub release from the tag and mark it Pre-release. Attach both APKs and their SHA-256 sums; paste the changelog section, the certificate SHA-256 and the install note (beta.1 needed an uninstall because of the new key; later betas install over it).
5. Link `/releases`, not `/releases/latest`, for betas: GitHub's "latest" skips pre-releases.

A final `2.0.0` repeats the same steps without the pre-release suffix, without `bundle.android.versionCode` overrides that would go backwards, and without the Pre-release mark.

## CI

`.github/workflows/ci.yml` runs on every push and pull request:
- **core**: installs `webkit2gtk`, runs `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --no-fail-fast`, standalone `rustc --test src-tauri/src/policy.rs`, and `python3 qa/gen-licenses.py --check`.
- **ui**: `npm ci`, `node --check` on `ui/js/*.js`, `ui/screens/*.js` and `qa/*.mjs`, `npm run format:check` (Prettier), `npm run lint` (ESLint), `node qa/data-invariants.mjs`, and `python3 qa/check-docs-links.py`.
- **android-kotlin** (every push and pull request): JDK 21, Android SDK + NDK `29.0.14206865`, `bash qa/android-build.sh kotlin` (Kotlin compile of `foss` and `play`), then `bash qa/check-jni.sh`.
- **android-apk** (pushes to `main`/`develop` and manual runs): `bash qa/android-build.sh apk`, `qa/check-jni.sh` against the built `.so` (JNI symbols both ways), uploads the unsigned arm64 `foss` and `play` APKs as `apk-unsigned-arm64`. Signing stays out of CI.
