#!/usr/bin/env python3
"""OS-level stage signature probes for LINE→LANDING diagnosis.

Does not talk to production hosts. Uses loopback TCP only.
Records typed errno / idle-health outcomes that the rust-reality warm pool
and FailureCause taxonomy must distinguish.
"""
from __future__ import annotations

import errno
import json
import socket
import struct
import sys
import time
from pathlib import Path


def classify(err: BaseException) -> dict:
    e = getattr(err, "errno", None)
    return {
        "errno": e,
        "code": errno.errorcode.get(e, None) if e is not None else None,
        "exc": type(err).__name__,
        "msg_safe": type(err).__name__,  # never retain raw OS message text in artifacts meant for logs
    }


def probe_nothing_listens() -> dict:
    s = socket.socket()
    s.settimeout(1)
    try:
        s.connect(("127.0.0.1", 1))
        return {"verdict": "FAIL", "note": "unexpected connect ok"}
    except OSError as e:
        c = classify(e)
        ok = c.get("errno") == errno.ECONNREFUSED
        return {
            "stage": "S2_line_tcp_connect",
            "scenario": "landing_not_listening",
            "verdict": "PASS" if ok else "FAIL",
            "expected": "ECONNREFUSED",
            **c,
        }
    finally:
        s.close()


def probe_listen_close_new_vs_established() -> dict:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(8)
    keep = socket.socket()
    keep.connect(("127.0.0.1", port))
    peer, _ = srv.accept()
    srv.close()
    established_ok = False
    try:
        keep.send(b"alive")
        established_ok = True
    except OSError as e:
        est = classify(e)
    else:
        est = {"send": "OK"}
    new = socket.socket()
    new.settimeout(1)
    try:
        new.connect(("127.0.0.1", port))
        new_c = {"verdict_part": "UNEXPECTED_OK"}
        refused = False
    except OSError as e:
        new_c = classify(e)
        refused = new_c.get("errno") == errno.ECONNREFUSED
    finally:
        new.close()
        keep.close()
        peer.close()
    ok = established_ok and refused
    return {
        "stage": "S2_vs_S9",
        "scenario": "landing_stop_listen_established_survives",
        "verdict": "PASS" if ok else "FAIL",
        "established": est,
        "new_connect": new_c,
        "matches_issue_253_symptom": ok,
        "note": "new ECONNREFUSED while established send may still OK — classic intermittent pattern",
    }


def probe_peer_fin_idle_healthy() -> dict:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(8)
    c = socket.socket()
    c.connect(("127.0.0.1", port))
    peer, _ = srv.accept()
    peer.shutdown(socket.SHUT_RDWR)
    peer.close()
    time.sleep(0.05)
    c.setblocking(False)
    try:
        n = c.recv(1)
        readable = n
    except OSError as e:
        c.close()
        srv.close()
        return {"stage": "S4_warm_stale", "scenario": "peer_fin", "verdict": "FAIL", **classify(e)}
    c.close()
    srv.close()
    # rust idle_healthy: Ok(_) => false (stale discard)
    idle_healthy = False if readable == b"" or readable else True
    return {
        "stage": "S4_warm_checkout_stale",
        "scenario": "peer_fin",
        "verdict": "PASS",
        "recv": repr(readable),
        "idle_healthy_would_be": idle_healthy,
        "pool_path": "stale_discard then cold_fallback",
    }


def probe_peer_rst() -> dict:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(8)
    c = socket.socket()
    c.connect(("127.0.0.1", port))
    peer, _ = srv.accept()
    peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    peer.close()
    time.sleep(0.05)
    c.setblocking(False)
    recv_out = None
    try:
        recv_out = c.recv(1)
        recv_c = {"recv": repr(recv_out)}
    except OSError as e:
        recv_c = classify(e)
    c.setblocking(True)
    c.settimeout(1)
    try:
        c.send(b"x")
        send_c = {"send": "OK unexpected"}
    except OSError as e:
        send_c = classify(e)
    c.close()
    srv.close()
    return {
        "stage": "S4_warm_first_use",
        "scenario": "peer_rst",
        "verdict": "PASS",
        "recv_probe": recv_c,
        "first_write": send_c,
        "typed_causes": "FailureCause::ConnectionReset / Io(EPIPE)",
    }


def probe_silent_blackhole() -> dict:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(8)
    c = socket.socket()
    c.connect(("127.0.0.1", port))
    peer, _ = srv.accept()
    # Peer stays open but sends nothing — models undetectable middlebox drop
    # until a write path fails (cannot fully simulate blackhole on loopback).
    c.setblocking(False)
    try:
        c.recv(1)
        state = "UNEXPECTED_DATA"
        idle = False
    except BlockingIOError:
        state = "WouldBlock"
        idle = True
    except OSError as e:
        c.close()
        peer.close()
        srv.close()
        return {"stage": "S4_warm_stale", "scenario": "silent_blackhole", "verdict": "FAIL", **classify(e)}
    c.close()
    peer.close()
    srv.close()
    return {
        "stage": "S4_warm_checkout_stale",
        "scenario": "silent_blackhole_undetectable_by_try_read",
        "verdict": "PASS",
        "idle_probe": state,
        "idle_healthy_would_be": idle,
        "gap": "GAP: AdaptiveTcpPool.idle_healthy cannot see silent drops without RST/FIN",
    }


def probe_backlog_pressure() -> dict:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", 0))
    port = srv.getsockname()[1]
    srv.listen(1)
    fillers = []
    for _ in range(64):
        c = socket.socket()
        c.setblocking(False)
        try:
            c.connect(("127.0.0.1", port))
        except (BlockingIOError, InterruptedError):
            pass
        except ConnectionRefusedError:
            c.close()
            break
        fillers.append(c)
    probe = socket.socket()
    probe.settimeout(0.4)
    try:
        probe.connect(("127.0.0.1", port))
        outcome = {"result": "CONNECTED"}
        refused = False
        timed_out = False
    except OSError as e:
        outcome = classify(e)
        refused = outcome.get("errno") == errno.ECONNREFUSED
        timed_out = isinstance(e, TimeoutError) or outcome.get("exc") == "TimeoutError"
    finally:
        probe.close()
        for c in fillers:
            c.close()
        srv.close()
    abort = Path("/proc/sys/net/ipv4/tcp_abort_on_overflow").read_text().strip()
    return {
        "stage": "S3_landing_accept_backlog",
        "scenario": "accept_queue_pressure",
        "verdict": "PASS",
        "fillers": len(fillers),
        "extra_connect": outcome,
        "tcp_abort_on_overflow": abort,
        "note": (
            "On this kernel with tcp_abort_on_overflow=0, overflow tends toward "
            "client timeout / SYN drop, NOT ECONNREFUSED. Do not equate backlog "
            "pressure with connection_refused without host sysctl evidence."
        ),
        "refused": refused,
        "timed_out_or_other": timed_out or not refused,
    }


def main() -> int:
    out_dir = Path(__file__).resolve().parent / "evidence"
    out_dir.mkdir(parents=True, exist_ok=True)
    results = [
        probe_nothing_listens(),
        probe_listen_close_new_vs_established(),
        probe_peer_fin_idle_healthy(),
        probe_peer_rst(),
        probe_silent_blackhole(),
        probe_backlog_pressure(),
    ]
    path = out_dir / "stage_os_probes.json"
    path.write_text(json.dumps(results, indent=2) + "\n")
    # human table
    lines = ["scenario\tverdict\tstage\tnotes"]
    for r in results:
        lines.append(
            f"{r.get('scenario')}\t{r.get('verdict')}\t{r.get('stage')}\t{r.get('note') or r.get('gap') or ''}"
        )
    (out_dir / "stage_os_probes.tsv").write_text("\n".join(lines) + "\n")
    print(path)
    for line in lines:
        print(line)
    bad = [r for r in results if r.get("verdict") == "FAIL"]
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
