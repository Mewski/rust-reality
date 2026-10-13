# Observability Performance Audit (PR-A) — baseline `d6a9ea0`

**SHA:** `d6a9ea0b0b646f426a89b83ecb7537a13f8fea1c`  
**Date:** 2026-10-12 PDT  
**Scope:** code-path audit of `TransportTelemetry` + `AdaptiveTcpPool` locks/atomics vs data plane.  
**Product change:** **none** this PR — evidence only.

Principles: Correctness First; Zero Additional Data-Plane Cost; Evidence-Driven Optimization; No Performance Regression.

---

## 1. Call graph (observation path)

```
TransportTelemetry::snapshot()                    # telemetry.rs:39
  Weak<RuntimeStore>::upgrade                     # fails → None after drop
  runtime.load() → current generation             # store.rs Acquire generation
  cover_pool_snapshot() once                      # reality/fallback → AdaptiveTcpPool::snapshot
  outbounds.visit_warm_pool_snapshots(|s| …)      # outbound.rs:408 — no intermediate Vec
    AdaptiveTcpPool::snapshot()                   # warm_pool.rs:523
```

Documented contract (`telemetry.rs:35–37`): no network activity, task, or intermediate vector; briefly takes each pool’s existing state lock; **callers must not poll on the per-packet path**.

---

## 2. Data-plane boundary (Zero Additional Data-Plane Cost)

| Path | Telemetry / pool metric work? |
| --- | --- |
| TLS record decrypt/encrypt, Vision framing, splice, TCP relay byte copy | **None** — no hooks in I/O poll paths from this observer |
| Warm checkout on new session setup | Existing pool Mutex + atomics (pre-#282); observer adds work **only** when `snapshot()` is called |
| Per-byte / per-record atomics | **Absent** |
| Background sampler | **Absent** |
| Public HTTP metrics endpoint | **Absent** |

**Verdict (code review):** observer design already satisfies “no additional data-plane cost.” Remaining question is whether infrequent `snapshot()` contends with `checkout`/`reconcile` enough to move setup latency — **measurement required**.

---

## 3. Mutex acquisition map (`Mutex<PoolState>`)

| Site | File:line | Hold purpose | Concurrent with checkout? |
| --- | --- | --- | --- |
| `checkout` | `warm_pool.rs:464–476` | `arrivals_window` / `last_demand`; `ready.pop()`; publish `ready` gauge | self |
| inactive checkout | `:454–457` | arrival accounting only | rare |
| `record_miss` | `:564–566` | `misses_window++` | yes, brief |
| **`snapshot`** | **`:524–556`** | read `failures` / `failure_streak` / `backoff_until` / EWMAs; also loads atomics **while still holding** lock | **yes** |
| `reconcile` / adapt / dial completion | `:713+`, `:815+`, `:858+` | ownership of ready/connecting/backoff | yes |
| `stop` | `:438+` | drain | shutdown |

**Checkout design note (good):** stale/idle checks (`idle_healthy`, timeouts) run **after** releasing the mutex (`:480–488`). Lock is not held across syscalls for health.

**Snapshot design note (candidate surface):** lock is held across `Instant::now()` for `backoff_remaining_ms` (`:540–546`) **and** across many atomic loads that do not need the mutex. Hold time is still O(fields), not O(pool depth), but unnecessary coupling exists.

**Decision:** do **not** change product code until A/A and Idle vs Observed show the lock above noise. If measured, preferred micro-change order:

1. Under lock: copy only `DialFailureCounts`, streak, backoff deadline, EWMA floats; drop guard.  
2. Then load atomics and compute `backoff_remaining_ms`.  
3. Only if still hot: consider atomic mirrors for failure classes (must prove dial-completion updates stay consistent with streak/backoff).

**Explicitly rejected without evidence:** `RwLock`, parking_lot, DashMap, ArcSwap pool state, busy-spin.

---

## 4. Atomic ordering inventory (`PoolMetrics` + lifecycle)

### Pure cumulative stats — `Relaxed` OK (already)

`checkout_total`, `checkout_hit`, `checkout_miss`, `cold_fallback`, `connect_failure`, `stale_discard`, `refill`, `growth`, `shrink` — `fetch_add`/`load` with `Ordering::Relaxed` (`warm_pool.rs` ~451–563, 734–838). No other thread uses these for publication or ownership.

### Lifecycle / ownership — keep `Acquire`/`Release`/`AcqRel`

| Field | Ordering | Why keep |
| --- | --- | --- |
| `lifecycle` | AcqRel / Acquire / Release | start/stop vs checkout/controller |
| `ready`, `connecting`, `target_ready` | Release store / Acquire load | gauge publication with pool ownership |
| `in_use` | AcqRel fetch_add / Acquire load / AcqRel fetch_update on drop | WarmUsePermit lifetime |
| `ConnectingPermit::used` | AcqRel / Acquire | FD/connect budget |
| `RuntimeStore::generation` | Acquire load / Release store (`store.rs`) | generation binding for telemetry |

**Verdict:** **no ordering downgrade** in this train. Relaxed≠“free”; cache-line contention remains; correctness risk dominates.

---

## 5. `DialFailureCounts` under mutex

Introduced with `#281`: timeout/resource/policy/io live inside `PoolState` (`warm_pool.rs:247–275`), updated on dial completion under the same lock as backoff/streak. Snapshot must lock to read them. Moving to atomics is a **correctness+perf** change, not a free win — defer to PR-B only with proof.

---

## 6. Planned measurement commands (not executed this turn)

Environment: this executor box may lack host lock / `perf` / KVM. Commands are **contracts**, not claimed results.

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export RUSTUP_TOOLCHAIN=1.96.0
export CARGO_TARGET_DIR=/workspace/cargo-target-v203
cd /path/to/rust-reality   # at d6a9ea0

# Identity-bound freeze (baseline = candidate for A/A)
cargo dev perf freeze --commit d6a9ea0b0b646f426a89b83ecb7537a13f8fea1c

# Same-binary A/A (runKind=control expected in archive)
cargo dev bench run --suite setup-rate \
  --blocks 12 \
  --measure-mode schedstat \
  --baseline-bin <frozen-elf> \
  --baseline-identity <sidecar> \
  --baseline-commit d6a9ea0b0b646f426a89b83ecb7537a13f8fea1c \
  --rust-bin <same-frozen-elf>

# Later: Idle vs Observed requires an external snapshot poller at fixed Hz
# against a ProductionServer; do not bake benchmark-only shortcuts into the binary.
```

Criterion benches under `benches/` (vless_decode, vision, relay_backends, …) do **not** cover pool Mutex — do not misuse them as telemetry proof.

---

## 7. Reliability linkage (#253 / W1–W5)

- Issue [#253](https://github.com/jacek4yang/rust-reality/issues/253) body = phase goal; **does not define W1–W5 by name** on GitHub.
- Lab W1–W5 discriminator table + results: companion local notes and `#283` harness under `benchmarks/evidence/issue-253/phase-two/` + archived OS probes.
- Production RCA: **NOT_RUN**. Observability PRs `#281`/`#282`/`#284` enable attribution; they are **not** a claimed intermittent-refuse fix.

---

## 8. Audit verdict

| Question | Answer |
| --- | --- |
| Hot-path telemetry violation? | **No** (code review) |
| Worth product change now? | **No** — keep-as-is |
| Candidate micro-change if measured hot? | Shorten `snapshot` lock (copy then drop) |
| RC impact of this PR | Docs/evidence only; Frozen tip unchanged |

**Evidence tier:** code-review conclusions = review PASS for design invariants; performance claim of “no regression from observer” for setup-rate under load = **NOT_RUN** until paired cells exist.
