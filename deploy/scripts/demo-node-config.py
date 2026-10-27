#!/usr/bin/env python3
"""Render an isolated production demo project; never contact a container runtime."""
import json
import os
from pathlib import Path
import secrets
import sys

repo, state = map(Path, sys.argv[1:3])
command = sys.argv[3] if len(sys.argv) > 3 else "up"
project = os.environ["DEMO_PROJECT"]
settings = {key: os.environ[key] for key in (
    "DEMO_PROJECT", "DEMO_HOST", "DEMO_NODE_ID", "DEMO_GATEWAY_PORT",
    "DEMO_RELAY_PORT", "DEMO_HTTP_PORT", "DEMO_TURN_PORT", "DEMO_MESH_PORT",
    "DEMO_BIND_ADDR", "DEMO_VERSION",
)}
marker = state / "owner.json"
if marker.exists():
    owner = json.loads(marker.read_text())
    if owner["settings"] != settings or owner["directory"] != str(state):
        sys.exit("demo settings changed: restore the original env file or use a fresh data directory/project")
else:
    if any(state.iterdir()):
        sys.exit("refusing to adopt a nonempty, unowned data directory")
    owner = {"settings": settings, "directory": str(state), "token": secrets.token_hex(16)}
    marker.write_text(json.dumps(owner, indent=2) + "\n")

# Maintenance commands must use voice settings already written by up, not a new opt-in.
voice_port = os.environ.get("RAMFLUX_DEMO_VOICE_UDP_PORT", "")
if command != "up" and voice_port:
    runtime = state / "runtime.env"
    values = dict(line.split("=", 1) for line in runtime.read_text().splitlines()
                  if "=" in line) if runtime.is_file() else {}
    expected = {
        "RAMFLUX_RELAY_VOICE_PUBLIC_ENDPOINT": f"{settings['DEMO_HOST']}:{voice_port}",
        "RAMFLUX_RELAY_VOICE_UDP_PORT": f"{settings['DEMO_BIND_ADDR']}:{voice_port}",
    }
    if not (state / "compose.voice.yml").is_file() or any(
        values.get(key) != value for key, value in expected.items()
    ):
        sys.exit("voice configuration was not applied by the last up; run up first "
                 "before status, logs, down or down --purge (or restore the last applied selection)")

services = ("gateway", "router", "notify", "federation", "relay", "signaling", "retention")
label = {"org.ramflux.demo.owner": owner["token"]}
override = {
    "services": {f"ramflux-{name}": {
        "build": {"context": str(repo)}, "restart": "unless-stopped", "labels": label,
    } for name in services},
    "volumes": {f"{name}-redb": {"labels": label} for name in services},
    "networks": {"default": {"labels": label}},
}
(state / "demo-override.json").write_text(json.dumps(override, indent=2) + "\n")
# Freeze the base compose with the project so later down uses exactly this deployment.
compose = state / "compose.yml"
if not compose.exists():
    compose.write_text((repo / "deploy/docker-compose.yml").read_text())
(state / "owner.token").write_text(owner["token"] + "\n")

# Freeze the opt-in overlay alongside the base without changing legacy ownership settings.
# Selection remains explicit in the operator env/CLI for every invocation.
voice = state / "compose.voice.yml"
if command == "up" and voice_port and not voice.exists():
    voice.write_text((repo / "deploy/docker-compose.voice.yml").read_text())
