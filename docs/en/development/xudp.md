# XUDP and Vision UDP/443

Authority: stock Xray-core v26.7.28 (`5ca6f4b7d4dc20a881d4330e498892697627ec0c`).

## Two different names

| Name | What it is |
| --- | --- |
| `xtls-rprx-vision-udp443` | Client **config policy** that permits UDP/443. Wire Addons still carry `xtls-rprx-vision`. |
| **XUDP** | VLESS Mux command `0x03` to synthetic `v1.mux.cool:666`, plus Mux-shaped datagram framing (`common/xudp`). |

See Issue [#254](https://github.com/jacek4yang/rust-reality/issues/254) for pin line citations.

## Supported routes (server)

| Outbound | UDP via XUDP |
| --- | --- |
| Direct | Supported (this implementation) |
| NXR | **Not supported** — session fails closed with an explicit error |
| Handoff | **Not supported** — session fails closed with an explicit error |
| Block | Rejected by routing as usual |


## Keep destination rewrites

A Keep frame may embed a new UDP destination (multi-address association). Each
rewrite is re-evaluated through the same canonical routing table, DNS strategy,
and Direct-only outbound authorization as the opening New frame. A destination
that previously routed to Direct does **not** authorize a later Block, Handoff,
or NXR target — the session fails closed.

NXR and Handoff today are TCP continuation transports. Extending them for UDP is out of scope for the first unified-client UDP release; unsupported routes must not silently fall back to Direct.

## Carrier

XUDP datagrams ride inside the existing REALITY + Vision stream. This is not a second public wire protocol and not native QUIC transport.

## Client SOCKS5 UDP ASSOCIATE

The unified client accepts loopback SOCKS5 UDP ASSOCIATE and carries datagrams
as XUDP over one committed REALITY + Vision LINE (Mux command `0x03`).

- Multi-address sessions: each SOCKS5 UDP datagram may name a different
  destination; the first opens XUDP (`New`), later packets use `Keep` (with
  destination rewrite when the target changes).
- LINE ownership: selection commits before the ASSOCIATE success reply; the
  association never migrates mid-session.
- UDP/443: permitted only when the LINE sets `allowUdp443: true` (stock
  `xtls-rprx-vision-udp443` policy). Wire flow remains `xtls-rprx-vision`.

## Qualification (unified-client UDP series)

PR4 adds process-level evidence on top of the unit framing/auth/server Direct
tests from earlier PRs:

| Evidence | What it proves |
| --- | --- |
| SOCKS5 UDP ASSOCIATE E2E | Loopback client → REALITY entry → Direct UDP echo with byte-exact payload |
| UDP/443 policy | Without `allowUdp443`, UDP/443 fails closed; with it, XUDP may carry 443 |
| Framing fuzz | `fuzz_decode_xudp_packet` remains in the wire-parser fuzz shard |
| Route fail-closed | NXR / Handoff / Block remain explicit errors (no silent Direct fallback) |

This is **not** native QUIC transport. QUIC/443 traffic, when permitted, is still
UDP datagrams inside Vision/XUDP over the existing REALITY LINE.

Cancellation and association teardown: closing the SOCKS5 TCP control connection
ends the XUDP association; idle associations expire per `XUDP_ASSOCIATION_IDLE`.

## Cross-implementation notes

- **TCP Vision / REALITY** interoperability with unmodified Xray-core (pinned
  tag) continues to be exercised by Exact-head Native qualification.
- **UDP via XUDP** against stock Xray as peer is desirable follow-on evidence;
  this tree first proves our client ASSOCIATE ↔ our server Direct path and
  framing golden vectors against the pinned `common/xudp` layout. A stock-Xray
  UDP peer harness may land once the Direct path is on `main`.
- Constrained-resource behaviour reuses existing association limits
  (`XUDP_MAX_ASSOCIATIONS`, idle expire) and process FD budgets; association
  teardown on control EOF is the cancellation path for SOCKS5 UDP ASSOCIATE.
