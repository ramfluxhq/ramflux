# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Real authenticated pooled peers used by configured shutdown regressions."""
import http.client
import json
import socket
import ssl
import sys
import subprocess
import time
from pathlib import Path

root, address, mode, service, pid = sys.argv[1:]
root = Path(root)
host, port = address.rsplit(":", 1)
context = ssl.create_default_context(cafile=str(root / "ca.pem"))
context.load_cert_chain(str(root / "peer.pem"), str(root / "peer.key"))


def connect():
    peer = context.wrap_socket(socket.create_connection((host, int(port)), timeout=3), server_hostname="localhost")
    peer.settimeout(4)
    return peer


def request(peer, path="/healthz", body=None):
    data = b"" if body is None else json.dumps(body).encode()
    peer.sendall((f"{'GET' if body is None else 'POST'} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\nContent-Length: {len(data)}\r\n\r\n").encode() + data)


def probe(peer):
    if service == "ramflux-federation":
        request(peer, "/internal/retention/gc_sweep", {"owner_service": "federation", "sweep_id": "shutdown-probe", "now": 1, "dry_run": True})
    else:
        request(peer)


def response(peer):
    reply = http.client.HTTPResponse(peer)
    reply.begin()
    body = reply.read()
    return reply.status, body.decode()


if mode == "raw":
    peer = socket.create_connection((host, int(port)), timeout=3)
elif mode == "handshake":
    peer = connect()
elif mode == "churn":
    def stats():
        with connect() as probe:
            request(probe, "/__itest/shutdown-connections")
            status, body = response(probe)
            assert status == 200, (status, body)
            return json.loads(body)

    def threads():
        if sys.platform == "linux":
            return len(list(Path(f"/proc/{pid}/task").iterdir()))
        return len(subprocess.check_output(["ps", "-M", "-p", pid], text=True).splitlines()) - 1

    # Warm TLS/runtime thread caches before measuring.
    for _ in range(32):
        with connect() as peer:
            request(peer)
            response(peer)
    time.sleep(0.1)
    baseline = stats()
    baseline_threads = threads()
    for _ in range(2000):
        with connect() as peer:
            request(peer)
            status, _ = response(peer)
            assert status == 200, status
    deadline = time.monotonic() + 5
    while True:
        after = stats()
        current_threads = threads()
        if after["other_connections"] == 0 and current_threads <= baseline_threads:
            break
        assert time.monotonic() < deadline, (baseline, after, baseline_threads, current_threads)
        time.sleep(0.02)
    assert after["root_workers"] == baseline["root_workers"], (baseline, after)
    print("churn-complete", flush=True)
    sys.exit(0)
elif mode == "request":
    # Another normally pooled peer remains connected throughout the real request.
    idle_peer = connect()
    peer = connect()
    if service == "ramflux-router":
        request(peer, "/s1/session/upsert", {
            "target_delivery_id": "shutdown-target", "device_id": "shutdown-device",
            "gateway_id": "shutdown-gateway", "session_id": "shutdown-session",
            "device_epoch": 1, "session_seq": 1, "last_cursor": None,
            "push_alias_hash": None, "lifecycle": "Live",
        })
    elif service == "ramflux-retention":
        request(peer, "/retention/v1/object_relay_ttl", {"record": {
            "record_id": "shutdown-record", "subject_hash": "shutdown-subject",
            "metadata_class": "object_relay_ttl", "source_service_id": "ramflux-relay",
            "retention_policy_id": "relay-cache", "created_at": 1,
            "expires_at": 4102444800, "legal_hold": False, "metadata_hash": "shutdown-hash",
        }})
    else:
        request(peer, "/internal/retention/gc_sweep", {"owner_service": "federation", "sweep_id": "shutdown-sweep", "now": 200, "dry_run": False})
    status, body = response(peer)
    assert status in (200, 503), (status, body)
    (root / "response.json").write_text(json.dumps({"status": status, "body": body}))
    print("response-complete", flush=True)
    sys.exit(0)
else:
    peer = connect()
    probe(peer)
    status, _ = response(peer)
    assert status in (200, 404, 403), status
if mode in ("handshake", "raw"):
    with connect() as barrier:
        probe(barrier)
        status, _ = response(barrier)
        assert status in (200, 403, 404), status
print("peer-ready", flush=True)
sys.stdin.read()
peer.close()
