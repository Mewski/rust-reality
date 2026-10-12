# LINE → LANDING staged failure diagnosis harness

Isolated probes for Issue #253. **No production hosts. No gate weakening.**

## What this is

- Loopback OS errno atlas for stages that operators lump as `outbound_failed`.
- LANDING listen-flap race that reproduces intermittent `ECONNREFUSED` while
  established sockets may still send.
- Focused `cargo test --lib` filters proving warm stale discard, cold fallback,
  refusal permit release, and FailureStage distinctions already on main.

## What this is not

- Not a Frozen Qualification substitute.
- Not netns/netem (this box lacks `CAP_NET_ADMIN`; those remain NOT_RUN here).
- Not a production transport behavior change.

## Run

```bash
export CARGO_TARGET_DIR=/workspace/cargo-target-diag
./tools/line-landing-diag/run_all.sh
```

Evidence lands in `tools/line-landing-diag/evidence/`.
