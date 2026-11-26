# ADR-0002: Vanilla JS UI Without a Bundler

↑ [Decisions (ADR)](README.md) · [Documentation](../README.md)

- Status: accepted
- Decision: `ui/` consists of plain ES scripts, with the router and components in `ui/js/core.js` and screens in
  `ui/screens/`.
- Why: Zero build toolchain overhead on low-spec machines, fast "edit → screenshot test" cycle, and small APK size.
- Consequences: Strict UI core API discipline ([docs/dev/ui.md](../dev/ui.md)), with all data access routed exclusively
  through `ui/js/api.js`.
