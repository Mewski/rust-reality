# Idle vs Observed — setup-rate on product source `d6a9ea0` (schedstat)

**Date:** 2026-10-12 ~19:37–19:40 PT  
**Verdict:** **KEEP-AS-IS** (Observed/Idle CI contains 1.0; no PR-B)  
**Comparison dimension:** `observe.hz` sidecar `0` vs `1` on **byte-identical** evidence harness ELFs  
**Harness runKind (sha equal):** `control` (expected — same bytes; factor is observation rate)  
**PR:** [#286](https://github.com/jacek4yang/rust-reality/pull/286)

## Why a harness (not the freeze ELF)

`TransportTelemetry::snapshot()` is an **in-process** library API (`ProductionServer::telemetry()`).
The freeze product ELF has **no** observe IPC and **no** `--observe-hz` (verified via `cargo dev` / product CLI).
`#270` Control API is out of scope. Per task escape hatch: smallest evidence harness that drives
`snapshot()` without changing production hot-path semantics.

- Crate: `tools/rr-evidence-observe-server`
- Links `src/` identical to `d6a9ea0` (docs/audit branch; no product `src/` delta)
- Speaks `run --config` + `--version` (`rust-reality 2.0.2` / `commit: d6a9ea0…`)
- Idle copy: sibling `observe.hz=0` → zero `snapshot()` calls
- Observed copy: sibling `observe.hz=1` → tokio task calls `snapshot()` at **1 Hz** (off data plane)
- Slot `server.log` first line: `rr-evidence-observe-server: observe_hz=0|1`

Freeze ELF A/A on the same host remains the noise-floor reference:
[`v2.0.3-aa-setup-rate-d6a9ea0/`](../v2.0.3-aa-setup-rate-d6a9ea0/).

## Identity

| Item | Value |
| --- | --- |
| Product source commit | `d6a9ea0b0b646f426a89b83ecb7537a13f8fea1c` |
| Harness worktree HEAD | `73daaed7e9aa4291cfc96368ca9aed3aaca96ed2` |
| Harness ELF SHA-256 | `4377b7ffa58155c8c478c4b441ddfe57283356dfe08a38637a6deed86c572aee` |
| Harness Build ID | `b9915a72137b469ce0096ef20d3319d0422364b2` |
| Baseline | Idle (`observe.hz=0`) |
| Candidate | Observed (`observe.hz=1`) |
| Measure mode | `schedstat` |
| Blocks | 12 |
| Concurrencies | 1 8 32 |
| Failures | 0 |
| Host | same KVM VM as A/A |

## Results (Observed / Idle)

| Cell | median ratio | bootstrap95 | width | includes 1.0? | A/A width (same host) |
| --- | ---: | --- | ---: | --- | ---: |
| setup-rate c=1 | 0.990785 | [0.983928, 1.022157] | 3.82% | **yes** | 7.48% |
| setup-rate c=8 | 1.014163 | [0.983354, 1.056039] | 7.27% | **yes** | 9.80% |
| setup-rate c=32 | 0.989928 | [0.957210, 1.029074] | 7.19% | **yes** | 12.84% |
| serverCpuPerConnection | 0.993730 | [0.972790, 1.017933] | 4.51% | **yes** | 3.80% |

`performanceVerdict`: `NOT_EVALUATED` (harness equal-sha control label; interpretation is Idle vs Observed).  
`status`: `COMPLETE`.

## Gate application (user task)

1. Observed/Idle bootstrap95 **contains 1.0** on every cell → **keep-as-is**.
2. No cell shows CPU/conn ≥1% credible worse **outside** A/A noise (CPU CI contains 1.0; median ≈0.994).
3. Samples: 12 blocks — sufficient (≥ ADR 0022 floor).

**PR-B:** **No** — do not open telemetry lock-hold / try_snapshot product change.

## Warm-checkout microbench

**Not separately run.** Setup-rate already drives warm-pool checkout on the connection-setup path while Observed polls `snapshot()` at 1 Hz; that is the contention surface named in the audit. A standalone micro would not change the keep-as-is gate given these intervals.

## What this does / does not prove

| Claim | Status |
| --- | --- |
| 1 Hz `snapshot()` moves setup-rate beyond host A/A noise | **Falsified on this host** (all CI contain 1.0) |
| Per-byte / per-record data-plane cost from observer | Still **absent** by code review |
| Production #253 root cause | **NOT_PROVEN** |
| Freeze ELF itself under 1 Hz observe | **NOT_RUN** (no in-process hook without product change) |

## Artifacts

- `summary.json`, `environment.json`, `completion.json`, `order.json`, `raw-samples.jsonl`
- `harness/` identity + observe.hz copies + rebuild notes
- `sample-slot-idle/` / `sample-slot-observed/` — `observe_hz=` proof lines
- Full 48-slot tree on executor: `/workspace/evidence-v203-observe/idle-vs-observed-setup-rate/slots/` (not committed)
