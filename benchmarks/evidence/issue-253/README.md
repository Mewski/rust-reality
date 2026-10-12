# Issue #253 — LINE → LANDING staged failure diagnosis (phase two)

Durable, compact evidence for intermittent `ECONNREFUSED` attribution.
**Diagnosis only — no production transport behavior change.**

## Findings (summary)

| Hypothesis | Verdict | Note |
| --- | --- | --- |
| H1 LANDING listen-down / restart window | **Leading** | New dials refuse; established may continue |
| H2 Accept backlog overflow | Weak for refuse | This kernel (`tcp_abort_on_overflow=0`) → timeout, not refuse |
| H3 Warm FIN/RST stale → cold | Proven | Existing library tests |
| H4 Silent blackhole warm | Gap | `idle_healthy` stays true (`WouldBlock`) until write |

## Layout

- `phase-two/` — loopback OS probe results, listen-flap race summary, focused library filter summary.
- Historical probe **sources** (immutable, non-executable) live under
  `benchmarks/evidence/objects/sha256/<digest>/` as
  `landing_flap_race.py` and `stage_os_probes.py`. They are archived evidence,
  not active repository policy; do not reintroduce active shell/Python under
  `tools/`.

## Library evidence (regenerate)

```bash
export CARGO_TARGET_DIR=/workspace/cargo-target-diag   # or any isolated dir
cargo test --lib -- \
  checkout_discards_a_peer_closed_idle_socket \
  stale_warm \
  a_failed_dial_releases_its_permit \
  idle_admission_limit_rejects_excess \
  landing_errno_and_line_rejection \
  pressure_reclaims_ready_state \
  unused_handoff_socket_expires
```

Related: PR that landed this tree; Issue #253; observability PRs #281 / #282.
