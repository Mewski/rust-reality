# Evidence harness (not a product binary)

- Crate: `tools/rr-evidence-observe-server`
- Product source measured: `d6a9ea0` (`src/` unchanged on the audit branch)
- Rebuild: `RUST_REALITY_GIT_COMMIT=d6a9ea0b0b646f426a89b83ecb7537a13f8fea1c cargo build --release -p rr-evidence-observe-server` from `tools/`
- Twin deploy: byte-identical copies; sibling `observe.hz` is `0` (Idle) or `1` (Observed @ 1 Hz)
- Why not the freeze ELF: `TransportTelemetry::snapshot` is in-process only; no product observe IPC / `--observe-hz` (verified via CLI). `#270` Control API out of scope.
