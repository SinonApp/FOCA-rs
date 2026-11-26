# ADR-0003: System Bar Insets from Kotlin

↑ [Decisions (ADR)](README.md) · [Documentation](../README.md)

- Status: accepted
- Context: `env(safe-area-inset-*)` behaved unreliably on Xiaomi HyperOS, causing the header to overlap the status bar.
- Decision: `MainActivity` reads `WindowInsets` and exposes them as CSS variables via `JavascriptInterface`,
  synchronizing system bar colors with the active theme; `textZoom` is capped at 130%.
