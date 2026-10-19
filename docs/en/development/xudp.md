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

NXR and Handoff today are TCP continuation transports. Extending them for UDP is out of scope for the first unified-client UDP release; unsupported routes must not silently fall back to Direct.

## Carrier

XUDP datagrams ride inside the existing REALITY + Vision stream. This is not a second public wire protocol and not native QUIC transport.
