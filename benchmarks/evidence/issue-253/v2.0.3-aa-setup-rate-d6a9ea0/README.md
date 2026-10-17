# Same-binary A/A — setup-rate on `d6a9ea0` (schedstat)

**Date:** 2026-10-12 ~19:05–19:08 PT  
**Verdict:** **PASS** (noise-floor / control)  
**runKind:** `control` (baseline ELF ≡ candidate ELF)  
**PR:** [#286](https://github.com/jacek4yang/rust-reality/pull/286)

## Identity

| Item | Value |
| --- | --- |
| Source commit | `d6a9ea0b0b646f426a89b83ecb7537a13f8fea1c` |
| Freeze ELF SHA-256 | `257d71fd9318090885a720f718306ac24e97a9079226088542cd79bf651d63e8` |
| Freeze Build ID | `6302ae650e09071c8fc26d5720c324c39ec0e8e7` |
| Freeze bytes | 7627192 |
| Worktree HEAD during run | `d6a9ea0…` (clean) |
| Measure mode | `schedstat` (no `perf` on host) |
| Blocks | 12 (ADR 0022 floor) |
| Concurrencies | 1 8 32 |
| Connections / sample | 96 |
| Failures | 0 |
| Slots | 48 |
| Raw samples | 1296 |
| Host | KVM VM `grok-bot-vm-446725139`, 8× Xeon vCPU, Linux 6.12.94+, no swap |
| Xray SOCKS client | upstream `v26.9.9` `Xray-linux-64.zip` (`1eb9175d…`); stock ELF has **0** GNU Build IDs — injected `NT_GNU_BUILD_ID=c4ae6798c38e0e5343b192406746333cd0ba7ff3` (= sha256(upstream)[:20]) **only** so the harness can attest the SOCKS client. Client is not under test. |

## Command (real CLI; verified via `cargo dev … --help`)

```bash
export PATH="$HOME/.cargo/bin:$PATH"
export RUSTUP_TOOLCHAIN=1.96.0
# freeze requires: clean worktree at exact commit; --out-dir absolute and non-existent
cargo dev perf freeze --commit d6a9ea0b0b646f426a89b83ecb7537a13f8fea1c \
  --out-dir /abs/path/freeze-d6a9ea0

# identity sidecar schema (attest.rs): sourceCommit + binarySha256 + sha256sumsVerified
# OUT_DIR must not exist beforehand
cargo dev bench run --suite setup-rate --blocks 12 --measure-mode schedstat \
  --baseline-bin "$ELF" --baseline-identity "$SIDECAR" \
  --baseline-commit d6a9ea0b0b646f426a89b83ecb7537a13f8fea1c \
  --rust-bin "$ELF" --xray-bin "$XRAY_WITH_BUILDID" \
  --out-dir /abs/path/aa-out
```

## Results (candidate/baseline; same ELF ⇒ expect ~1.0)

| Cell | median ratio | bootstrap95 | width | includes 1.0? |
| --- | ---: | --- | ---: | --- |
| setup-rate c=1 | 0.993325 | [0.959170, 1.033952] | 7.48% | **yes** |
| setup-rate c=8 | 0.989590 | [0.960782, 1.058772] | 9.80% | **yes** |
| setup-rate c=32 | 1.035916 | [0.951762, 1.080189] | 12.84% | **yes** |
| serverCpuPerConnection | 0.997212 | [0.971147, 1.009134] | 3.80% | **yes** |

`performanceVerdict`: `NOT_EVALUATED` (control run; evaluator not claiming product delta).  
`status`: `COMPLETE`.

### Interpretation vs lab i5-1240P ADR 0022 ladder

On the laboratory i5-1240P, 12-block A/A setup-rate `serverCpuPerConnection` interval width settled near **~0.7%**. This **KVM shared VM** shows **~3.8%** CPU width and **~7–13%** setup-rate width. **Noise floor is host-specific.** A future product A/B on *this* host must beat these widths; do not cite the i5 ladder widths as this VM's floor.

**No false significant difference:** zero cells exclude 1.0 at 12 blocks.

## What this does / does not prove

| Claim | Status |
| --- | --- |
| Observer adds per-byte data-plane cost | **Not tested here** (code review already: none) |
| `snapshot()` vs `checkout` contention under load | **Measured** — [`../v2.0.3-idle-vs-observed-d6a9ea0/`](../v2.0.3-idle-vs-observed-d6a9ea0/); all Observed/Idle CI contain 1.0 |
| PR-B (shorten snapshot lock) justified | **No** — keep-as-is (Observed ≤ host A/A noise) |
| Production #253 root cause | **NOT_PROVEN** |

## Artifacts in this directory

- `summary.json`, `environment.json`, `completion.json`, `order.json`, `raw-samples.jsonl`
- `freeze/{freeze.json,identity.json,SHA256SUMS}` (ELF not vendored; rebuild via `perf freeze`)
- `agent-meta/machine-env.txt`, console/exit
- `sample-slot/` — one schedstat + identity for format proof
- Full 48-slot tree (~12 MiB) retained on executor box under `/workspace/evidence-v203-aa/aa-setup-rate-d6a9ea0/slots/` (not committed)

## Idle vs Observed — executed

See [`../v2.0.3-idle-vs-observed-d6a9ea0/`](../v2.0.3-idle-vs-observed-d6a9ea0/). Evidence harness (in-process `snapshot` @ 1 Hz vs idle); **keep-as-is / no PR-B**.
