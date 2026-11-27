# Upgrade fixture: a 2.0.0-beta.4 data directory

`beta4-data.tar.gz` is the data directory the released 2.0.0-beta.4 `foca` binary wrote through
`foca serve`. The test `tests/data/upgrade_b4.rs` opens it with the current engine and checks that
nothing a user entered is lost. Only synthetic data is inside: five corpus files from
`tests/corpus`, the reserved domain `example.com`, a fake AI endpoint on `127.0.0.1`.

What the binary did (see `make_fixture.py`):

- accepted the terms, created the project "Upgrade fixture" (client "Example Org", target
  `example.com`);
- changed settings: `net.rps` 3, `net.timeout` 17, mobile data limit on at 321 MB, Wi-Fi only off,
  AI provider `custom`;
- imported `contract.docx`, `report.pdf`, `legacy.doc`, `schedule.xlsx`, `scan.pdf`;
- set one finding to confirmed with a note and another to false positive;
- made one AI summary against the fake endpoint;
- checked the published signature bundle (`signatures/last_check.json`);
- exported an encrypted bundle (`exports/*.foca.enc`, password `upgrade-pass`, with files).

The SQLite WAL files are kept as the process left them (the app is often killed on Android), the
`-shm` files, logs and the engine lock are not. Paths stored in the project point to
`/tmp/foca-upgrade-b4/data`, a place that does not exist on the test machine, like a data
directory restored to another path.

Regenerate (only when a new released version needs its own fixture):

```sh
git worktree add /tmp/foca-old v2.0.0-beta.4
CARGO_TARGET_DIR=/tmp/foca-old-target cargo build -p foca-cli --manifest-path /tmp/foca-old/Cargo.toml
SIG_UPDATE=1 python3 make_fixture.py /tmp/foca-old-target/debug/foca /tmp/foca-upgrade-b4/data 8951 /tmp/foca-old/tests/corpus
cd /tmp/foca-upgrade-b4 && rm -rf data/logs data/engine.lock data/*-shm
tar --format=ustar --owner=0 --group=0 --numeric-owner --sort=name -czf beta4-data.tar.gz data
```
