# SPDX-License-Identifier: BSD-3-Clause
# Copyright (c) 2026 Span Brain
"""Real authenticated pooled peers used by configured shutdown regressions."""
import collections
import os
import http.client
import json
import socket
import ssl
import sys
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


if mode.startswith("http-"):
    peer = socket.create_connection((host, int(port)), timeout=3)
    peer.settimeout(4)
    if mode.endswith("-request"):
        request(peer)
        status, body = response(peer)
        assert status == 200, (status, body)
        print("response-complete", flush=True)
        sys.exit(0)
    peer.sendall(b"G")
    # A later response proves the earlier partial reader was accepted and registered.
    with socket.create_connection((host, int(port)), timeout=3) as barrier:
        barrier.settimeout(4)
        request(barrier)
        status, body = response(barrier)
        assert status == 200, (status, body)
elif mode.startswith("failure-"):
    try:
        with connect() as rejected:
            probe(rejected)
            status, _ = response(rejected)
            assert status in (200, 403, 404), status
    except (OSError, ssl.SSLError):
        pass
    peer = connect()
    probe(peer)
    status, _ = response(peer)
    assert status in (200, 403, 404), status
elif mode == "raw":
    peer = socket.create_connection((host, int(port)), timeout=3)
elif mode == "handshake":
    peer = connect()
elif mode == "descriptors":
    peers = [connect() for _ in range(16)]
    for peer in peers:
        request(peer)
        status, _ = response(peer)
        assert status == 200, status
    if sys.platform == "linux":
        sockets = collections.Counter()
        for descriptor in Path(f"/proc/{pid}/fd").iterdir():
            try:
                target = os.readlink(descriptor)
            except FileNotFoundError:
                continue
            if target.startswith("socket:"):
                sockets[target] += 1
        assert sum(count == 2 for count in sockets.values()) >= 16, sockets
        assert max(sockets.values()) <= 2, sockets
elif mode == "churn":
    def stats():
        with connect() as probe:
            request(probe, "/__itest/shutdown-connections")
            status, body = response(probe)
            assert status == 200, (status, body)
            return json.loads(body)

    baseline = stats()
    for _ in range(2000):
        with connect() as peer:
            request(peer)
            status, _ = response(peer)
            assert status == 200, status
    # Prove the registry observes a live connection before waiting for its release.
    # Membership drops after the socket and service context, unlike runtime thread caches.
    with connect() as held:
        request(held)
        status, _ = response(held)
        assert status == 200, status
        after = stats()
        assert after["other_connections"] >= 1, after
    deadline = time.monotonic() + 5
    while after["other_connections"] != 0:
        assert time.monotonic() < deadline, (baseline, after)
        after = stats()
        if after["other_connections"] != 0:
            time.sleep(0.02)
    assert after["other_connections"] == 0, ("connections did not drain", after)
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
