# src-tauri/: мост Tauri и Android-приложение

↑ [Корень](../README.md) · [Android и Kotlin](../docs/dev/android.md)

| Путь | Что |
|---|---|
| `src/` | Rust-мост (крейт `foca-rs`): `bridge.rs` (команда `foca`, события), `native.rs` (Kotlin/JNI), `policy.rs` (пауза), `recovery.rs` (фон), `monitor.rs`, `applog.rs` |
| `tauri.conf.json` | Версия приложения, CSP, окно |
| `capabilities/` | Разрешения: только `allow-foca` и события |
| `gen/android/` | Android-проект Gradle; Kotlin: `app/src/main/java/app/sinon/focars/` (`platform/`), JUnit: `app/src/test/` |
| `icons/` | Иконки приложения |

Описание моста и Kotlin-части: [docs/dev/android.md](../docs/dev/android.md), решения: [ADR-0006](../docs/adr/0006-native-bridge.md),
сборка и подпись APK: [docs/dev/build.md](../docs/dev/build.md). На ПК без webkit2gtk крейт не собирается; логику моста
проверяют `rustc --test src-tauri/src/policy.rs` и `recovery.rs`.
