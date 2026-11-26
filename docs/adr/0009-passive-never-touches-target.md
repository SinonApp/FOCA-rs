# ADR-0009: Passive Access Never Contacts Target or Excluded Hosts

↑ [Decisions (ADR)](README.md) · [Documentation](../README.md)

- Status: accepted (2026-11-21, from security review finding)
- Context: The "Passive" profile promises the user and client that zero requests will touch the target site. A security
  review revealed that a passive request to a third-party service could follow a redirect onto a target host or even
  an excluded host: the `Access::Passive` label had only been checked for the initial URL.
- Decision:
  - `foca_net::NetClient::passive_access()` computes the actual access class for every hop: an excluded host is
    always denied (in any profile); a target host is denied at the passive tier and otherwise classified as
    `TouchesTarget` (scope-checked and logged as a request to the target); all other hosts remain `Passive`.
  - The passive guard is enabled globally for the scan (`set_passive_guard`) rather than relying on individual sources.
  - Under the Passive profile, target site documents are fetched as Wayback copies (`id_`), and site recon inspects
    archived copies.
- Consequences: The guarantee is enforced at the network layer rather than by source-author discipline; testbench
  verification checks that a passive scan's `request_log` has no `active=1` entries. Limitation: `request_log` stores
  only `active`; there is no separate access-class column. Code: `crates/foca-net/src/client.rs`,
  `crates/foca-engine/src/scan/mod.rs`.
