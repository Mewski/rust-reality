#!/usr/bin/env python3
"""Reproduce intermittent ECONNREFUSED under LANDING listen flap (restart window).

Models: LANDING briefly stops accepting while some ESTABLISHED peers may still
send. Clients dial continuously → mix of connect_ok and ECONNREFUSED.
"""
from __future__ import annotations

import collections
import json
import socket
import sys
import threading
import time
from pathlib import Path

stats: collections.Counter = collections.Counter()
port_holder: list[int] = []
stop = threading.Event()


def landing_flapper() -> None:
    while not stop.is_set():
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]
        port_holder[:] = [port]
        srv.listen(8)
        srv.settimeout(0.05)
        up_until = time.monotonic() + 0.15
        accepted: list[socket.socket] = []
        while time.monotonic() < up_until and not stop.is_set():
            try:
                c, _ = srv.accept()
                accepted.append(c)
            except socket.timeout:
                continue
            except OSError:
                break
        keep = accepted[:1]
        for c in accepted[1:]:
            c.close()
        srv.close()
        time.sleep(0.12)
        for c in keep:
            try:
                c.send(b"k")
                stats["established_send_ok"] += 1
            except OSError as e:
                stats[f"established_send_err_{e.errno}"] += 1
            c.close()


def client_worker(n_attempts: int = 150) -> None:
    for _ in range(n_attempts):
        if stop.is_set():
            break
        if not port_holder:
            time.sleep(0.01)
            continue
        port = port_holder[0]
        s = socket.socket()
        s.settimeout(0.2)
        try:
            s.connect(("127.0.0.1", port))
            stats["connect_ok"] += 1
            try:
                s.send(b"x")
                stats["post_connect_send_ok"] += 1
            except OSError as e:
                stats[f"post_connect_send_err_{e.errno}"] += 1
        except ConnectionRefusedError:
            stats["connect_ECONNREFUSED"] += 1
        except TimeoutError:
            stats["connect_ETIMEDOUT"] += 1
        except OSError as e:
            stats[f"connect_err_{e.errno}"] += 1
        finally:
            s.close()
        time.sleep(0.005)


def main() -> int:
    out_dir = Path(__file__).resolve().parent / "evidence"
    out_dir.mkdir(parents=True, exist_ok=True)
    t = threading.Thread(target=landing_flapper, daemon=True)
    t.start()
    time.sleep(0.05)
    clients = [
        threading.Thread(target=client_worker, args=(150,), daemon=True) for _ in range(4)
    ]
    for c in clients:
        c.start()
    for c in clients:
        c.join()
    stop.set()
    time.sleep(0.2)
    connect_keys = [k for k in stats if k.startswith("connect_")]
    total = sum(stats[k] for k in connect_keys)
    refused = stats["connect_ECONNREFUSED"]
    ok = stats["connect_ok"]
    if refused == 0:
        verdict = "FAIL"
    elif ok == 0:
        verdict = "INVALID"
    else:
        verdict = "PASS"
    report = {
        "scenario": "landing_listen_flap_race",
        "verdict": verdict,
        "hypothesis": "LANDING restart/not-listening window while ESTABLISHED may continue",
        "issue": 253,
        "stats": dict(stats),
        "connect_total": total,
        "refused_ratio": f"{refused}/{total}",
    }
    path = out_dir / "intermittent_refused_race.json"
    path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))
    return 0 if verdict == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
