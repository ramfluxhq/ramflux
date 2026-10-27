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
pending_marker = state / "owner.json.pending"
if marker.exists():
    owner = json.loads(marker.read_text())
    if owner["directory"] != str(state):
        sys.exit("demo settings changed: restore the original env file or use a fresh data directory/project")
    if command in ("upgrade", "rollback"):
        current = owner["settings"]
        changed = [key for key in settings if key != "DEMO_VERSION" and settings[key] != current[key]]
        if changed:
            sys.exit("demo settings changed beyond DEMO_VERSION: restore every other original setting")
        history = list(owner.get("version_history", []))
        if command == "upgrade":
            if settings["DEMO_VERSION"] == current["DEMO_VERSION"]:
                sys.exit("upgrade requires a changed DEMO_VERSION")
            history.append(current["DEMO_VERSION"])
        else:
            if not history:
                sys.exit("no previous demo version is available for rollback")
            settings["DEMO_VERSION"] = history.pop()
        owner = {**owner, "settings": settings, "version_history": history}
        temporary = pending_marker.with_suffix(".tmp")
        temporary.write_text(json.dumps(owner, indent=2) + "\n")
        temporary.replace(pending_marker)
    elif owner["settings"] != settings:
        sys.exit("demo settings changed: use upgrade for DEMO_VERSION only, or restore the original env file")
else:
    if command != "up":
        sys.exit("upgrade and rollback require an existing owned demo data directory")
    if any(state.iterdir()):
        sys.exit("refusing to adopt a nonempty, unowned data directory")
    owner = {"settings": settings, "version_history": [], "directory": str(state),
             "token": secrets.token_hex(16)}
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
# Refresh shipped definitions only on up; maintenance uses the last frozen deployment.
refreshed = []
for filename, source, selected in (
    ("compose.yml", "docker-compose.yml", True),
    ("compose.voice.yml", "docker-compose.voice.yml", bool(voice_port)),
    ("compose.admin.yml", "docker-compose.admin.yml", bool(os.environ.get("DEMO_ADMIN_LOOPBACK_PORT"))),
):
    frozen = state / filename
    if command in ("up", "upgrade", "rollback") and (selected or frozen.exists()):
        content = (repo / "deploy" / source).read_bytes()
        if not frozen.exists() or frozen.read_bytes() != content:
            existed = frozen.exists()
            temporary = frozen.with_suffix(frozen.suffix + ".tmp")
            temporary.write_bytes(content)
            temporary.replace(frozen)
            if existed:
                refreshed.append(filename)
    elif filename == "compose.yml" and not frozen.exists():
        sys.exit("saved compose.yml missing; run up before maintenance")
if refreshed:
    print("demo configuration refreshed: " + ", ".join(refreshed))
(state / "owner.token").write_text(owner["token"] + "\n")

admin_port = os.environ.get("DEMO_ADMIN_LOOPBACK_PORT", "")
if command != "up" and admin_port:
    runtime = state / "runtime.env"
    values = dict(line.split("=", 1) for line in runtime.read_text().splitlines() if "=" in line)
    if not (state / "compose.admin.yml").is_file() or values.get("RAMFLUX_FEDERATION_ADMIN_LOOPBACK_PORT") != admin_port:
        sys.exit("admin loopback configuration was not applied by the last up; run up first")
