# #253 H1–H4 causal attribution (v2.0.3 round)

**When:** 2026-10-12 ~19:43 PT  
**main tip:** `d6a9ea0b0b646f426a89b83ecb7537a13f8fea1c`  
**Branch:** `docs/v203-observability-audit` (Draft [#286](https://github.com/jacek4yang/rust-reality/pull/286))  
**Boundaries:** no warm-pool ping / blind backoff / retries (ADR 0007); no CAP_NET_ADMIN / staging / prod; no product code change this round.

---

## Connection-stage state diagram

```text
 Client                LINE                         LANDING
   |                     |                             |
   |-- TCP+REALITY ----->|                             |
   |   Auth / Vision     |                             |
   |                     |-- Pool checkout ------------>|
   |                     |   (warm hit | cold dial)    |
   |                     |                             |
   |                     |   [TCP Dial / Connect] ----->| Listen
   |                     |        errno / timeout       |   |
   |                     |                             |   v
   |                     |                        Accept / Admission
   |                     |                             |   |
   |                     |   Handoff/NXR Auth <-------->| Auth
   |                     |                             |   |
   |                     |                        Dest dial / Relay
   |                     |                             |
   |<======= thin ciphertext splice (Handoff) ========>|
   |         or NXR plaintext relay                    |
```

Stage IDs used below (mandate + `#284` failure stages):

| ID | Stage | Primary locus | #281 / #284 discriminators |
| --- | --- | --- | --- |
| S1 | Client→LINE setup | REALITY / Vision accept | Not LINE→LANDING refuse |
| S2 | LINE TCP dial / Pool | `AdaptiveTcpPool` checkout → cold `connect` | `#281` `connect_io` / timeout / resource / policy |
| S3 | LANDING Listen→Accept | kernel listen; `pre_auth` idle admit | OS `ECONNREFUSED` **before** auth; `#284` `landing_pre_auth`+`admission` |
| S4 | Auth | Handoff/NXR verify | `#284` `landing_authenticate` (not outbound lump) |
| S5 | Dest | LANDING egress dial | `#284` `landing_destination` + dest errno |
| S6 | Relay | Vision / splice / NXR | IO / timeout; established may survive S3 listen-down |

---

## Failure taxonomy (errno / timeout / log projections)

| Symptom class | Typical errno / cause | Likely stage | Established flows | Notes |
| --- | --- | --- | --- | --- |
| New dial refuse, listen down | `ECONNREFUSED` (111) | S2/S3 | **May survive** | **H1** signature |
| New dial refuse + peer/process exit | 111 + FIN/RST on established | S2/S3 + teardown | **Die** | Process-restart discriminator vs H1 |
| Accept backlog (this kernel `tcp_abort_on_overflow=0`) | client **timeout** / SYN drop | S3 | N/A | **Not** literal refuse without sysctl proof |
| Warm FIN/RST then cold miss | `stale_discard`↑ then dial class | S2/S4 warm | N/A | **H3** mechanism (proven in lab) |
| Silent blackhole (no FIN/RST) | `idle_healthy` true until write fail | S2 gap | May stall | **H4** gap; ADR 0007 forbids checkout ping |
| Auth reject | Protocol / LandingRejected | S4 | N/A | Distinct when `#284` detail present |
| Dest refuse | dest errno on `landing_destination` | S5 | N/A | Not LINE connect refuse |
| Admission pressure | `landing_pre_auth`+`admission` | S3 | Sessions kept; ready reclaim | Not `ECONNREFUSED` |

**Listen-down vs process exit (must not conflate):**

| Mode | New dial | Established | Lab probe |
| --- | --- | --- | --- |
| Listen-only down (process conceptually alive) | `ECONNREFUSED` | may still send/recv | `landing_stop_listen_established_survives` |
| Peer/process teardown | `ECONNREFUSED` | die (FIN/RST / failed send) | `peer_teardown_terminates_established_and_new_dials_refuse` |

---

## H1–H4 status table

| ID | Hypothesis | Lab status | Production field RCA | What would prove field |
| --- | --- | --- | --- | --- |
| **H1** | LANDING not listening / bind flap / restart **window** (listen down) | **PASS** (mechanism): OS + lib + prior flap race | **NOT_PROVEN** / staging **NOT_RUN** | Co-log: refuse time aligns with listen/`ss -ltn` down or socket replace; `#281` `connect_io`↑; established may stay up; PID may be stable |
| **H2** | Accept backlog overflow → refuse | **FAIL as refuse cause** on this kernel (overflow → timeout) | **NOT_PROVEN** | Host `tcp_abort_on_overflow` + backlog census at incident; without that, do not attribute refuse to H2 |
| **H3** | Warm stale (FIN/RST) → cold miss compounds refuse | **PASS** (mechanism) | **NOT_PROVEN** | Same window: `stale_discard`/`cold_fallback`↑ with `#281` dial class; complements H1 if cold hits down window |
| **H4** | Silent path drop (no FIN/RST); `idle_healthy` blind | **PASS as gap** (WouldBlock) | **NOT_PROVEN** | Write-path fail without prior stale; **not** expected as pure `ECONNREFUSED` unless cold also refuses |

**Explicit non-actions this round:** no warm-pool checkout ping; no blind backoff retune; no retries; no PR-C product fix (no proven code defect beyond documented H4 gap, which needs ADR — not a silent v2.0.3 pool knob).

---

## Cheap local discriminators (this pass)

### Library (`d6a9ea0`, `CARGO_TARGET_DIR=/workspace/cargo-target-diag`)

See [`library_discriminators.tsv`](./library_discriminators.tsv) — **9/9 ok**.

### OS loopback (no CAP_NET_ADMIN)

See [`os_loopback_probes.json`](./os_loopback_probes.json) — all four scenarios **PASS**.

### Still NOT_RUN (capability / auth)

| Item | Why |
| --- | --- |
| Dual-LINE netns / netem | no `CAP_NET_ADMIN` |
| Staging/prod LANDING co-log with `#281`/`#284` build | ops authorization |
| Full binary SIGTERM LANDING + crypto soak | optional; lib+OS already discriminate listen-down vs teardown |
| Checkout ping / keepalive for H4 | **forbidden** by ADR 0007 without new ADR |

---

## Conclusion for RC / #253

- Lab: **H1 is the leading mechanism** for the reported symptom class (intermittent new-dial refuse; established may continue).
- Field: production which-of-H1–H4 remains **NOT_PROVEN** until co-log.
- **No PR-C** this round (no new proven product defect requiring a code fix).
- Observability cost gate already cleared on [#286](https://github.com/jacek4yang/rust-reality/pull/286) (A/A + Idle vs Observed → keep-as-is / no PR-B).

