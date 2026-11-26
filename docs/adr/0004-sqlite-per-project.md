# ADR-0004: One SQLite File per Project

↑ [Decisions (ADR)](README.md) · [Documentation](../README.md)

- Status: accepted (from spec, F-2)
- Decision: `rusqlite` with `bundled`, storing a `<id>.foca` file in private app storage; schema migrations live in
  `foca-store`.
- Why: No external database server (original FOCA required SQL Server), and a project can be exported or deleted as a
  single self-contained file.
