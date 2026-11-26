# ADR-0008: Ports: Rootless TCP Connect, Custom Probes, VPN Canaries

↑ [Decisions (ADR)](README.md) · [Documentation](../README.md)

- Status: accepted (2026-11-21; amended in 1.0.1)
- Context: The client needs a list of open services on in-scope hosts. Android has no root access: SYN scans and ICMP
  are unavailable. nmap's service probes and port list (`nmap-service-probes`, `nmap-services`) are licensed under NPSL,
  which is incompatible with GPL-3.0. On a real phone, AdGuard/v2rayNG running in local VPN mode accepts TCP connections
  on every port: early reports falsely showed "all 100 ports open".
- Decision:
  - `foca_net::ports` implements a TCP connect scanner modeled after RustScan: adaptive batch sizes, rate limiting,
    per-port timeouts, cancellation, and logging of every attempt; active tier only ("Full"), in-scope non-excluded
    hosts, up to 20 hosts, one scan per unique IP.
  - Top-100 / top-1000 port lists are self-authored based on common service prevalence; banner grabbing uses custom
    probes (SSH/FTP/SMTP/POP3/IMAP/MySQL greetings, Redis `PING`, `HEAD /`, TLS detection and CN/SAN, Docker
    `GET /version`, RDP X.224, SMB negotiate, PostgreSQL SSLRequest…). nmap probes are not used.
  - Canaries: 3 known-closed ports probed before each host, a once-per-stage TEST-NET check (`192.0.2.1`,
    `198.51.100.1`), and a heuristic ("> 40% open, almost all silent"). When triggered, the stage reports `unreliable`,
    no ports are stored, and no findings are created.
  - High/Critical findings are emitted only when the protocol is confirmed; otherwise "Info / unconfirmed".
- Consequences: Scanning is slower than SYN and visible in target logs (intentional: authorized active phase); behind
  a local VPN, the result is honestly reported as "unreliable" instead of generating false findings. Live testing
  targets only `scanme.nmap.org`. Code: `crates/foca-net/src/ports.rs`, `crates/foca-engine/src/scan/ports.rs`.
