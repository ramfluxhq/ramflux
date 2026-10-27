#!/usr/bin/env python3
"""Validate, render, snapshot, and restore an isolated production demo project."""
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sys

SERVICES = ("gateway", "router", "notify", "federation", "relay", "signaling", "retention")
SNAPSHOT_FILES = (
    "compose.yml", "compose.voice.yml", "compose.admin.yml", "runtime.env",
    "owner.json", "demo-override.json", "deploy-tree.version",
)


def atomic_bytes(path, content):
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(content)
    temporary.chmod(0o600)
    temporary.replace(path)


def atomic_json(path, value):
    atomic_bytes(path, (json.dumps(value, indent=2) + "\n").encode())


def safe_snapshot_path(state, reference):
    parts = reference.split("/")
    if len(parts) != 2 or any(not part or part in (".", "..") for part in parts):
        sys.exit("invalid demo snapshot reference")
    root = state / "version-snapshots"
    target = root.joinpath(*parts)
    if target.parent.parent != root:
        sys.exit("invalid demo snapshot reference")
    return target


def capture_snapshot(state, reference, owner_source=None):
    target = safe_snapshot_path(state, reference)
    if target.exists():
        sys.exit("refusing to overwrite immutable demo snapshot")
    required_sources = {
        "compose.yml": state / "compose.yml",
        "runtime.env": state / "runtime.env",
        "owner.json": owner_source or state / "owner.json",
        "demo-override.json": state / "demo-override.json",
        "deploy-tree.version": state / "deploy-tree.version",
    }
    missing = [name for name, source in required_sources.items() if not source.is_file()]
    if missing:
        sys.exit("cannot snapshot incomplete demo state: " + ", ".join(missing))
    target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = target.with_name(target.name + ".pending")
    temporary.mkdir(mode=0o700)
    files = [name for name in SNAPSHOT_FILES
             if (owner_source if name == "owner.json" and owner_source else state / name).is_file()]
    for name in files:
        source = owner_source if name == "owner.json" and owner_source else state / name
        shutil.copyfile(source, temporary / name)
        (temporary / name).chmod(0o400)
    atomic_json(temporary / "manifest.json", {"files": files})
    (temporary / "manifest.json").chmod(0o400)
    temporary.chmod(0o700)
    temporary.replace(target)


def restore_snapshot(state, reference):
    source = safe_snapshot_path(state, reference)
    try:
        manifest = json.loads((source / "manifest.json").read_text())
    except (OSError, ValueError, TypeError) as error:
        sys.exit(f"cannot read demo snapshot manifest: {error}")
    files = manifest.get("files")
    if not isinstance(files, list) or any(name not in SNAPSHOT_FILES for name in files):
        sys.exit("invalid demo snapshot manifest")
    required = {"compose.yml", "runtime.env", "owner.json", "demo-override.json", "deploy-tree.version"}
    if not required.issubset(files) or any(not (source / name).is_file() for name in files):
        sys.exit("incomplete demo snapshot")
    for name in SNAPSHOT_FILES:
        destination = state / name
        if name in files:
            atomic_bytes(destination, (source / name).read_bytes())
        elif destination.exists():
            destination.unlink()


def deploy_tree_version(repo):
    digest = hashlib.sha256()
    deploy = repo / "deploy"
    for path in sorted(item for item in deploy.rglob("*")
                       if item.is_file() and "__pycache__" not in item.parts
                       and item.suffix not in (".pyc", ".pyo")):
        digest.update(str(path.relative_to(deploy)).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest() + "\n"


def runtime_values(state):
    runtime = state / "runtime.env"
    if not runtime.is_file():
        return {}
    return dict(line.split("=", 1) for line in runtime.read_text().splitlines() if "=" in line)


def selected_overlays():
    return {
        "RAMFLUX_DEMO_VOICE_UDP_PORT": bool(os.environ.get("RAMFLUX_DEMO_VOICE_UDP_PORT")),
        "DEMO_ADMIN_LOOPBACK_PORT": bool(os.environ.get("DEMO_ADMIN_LOOPBACK_PORT")),
    }


def validate_maintenance_overlays(state):
    values = runtime_values(state)
    applied = {
        "RAMFLUX_DEMO_VOICE_UDP_PORT": bool((state / "compose.voice.yml").is_file()
            and values.get("RAMFLUX_RELAY_VOICE_UDP_PORT")),
        "DEMO_ADMIN_LOOPBACK_PORT": bool((state / "compose.admin.yml").is_file()
            and values.get("RAMFLUX_FEDERATION_ADMIN_LOOPBACK_PORT")),
    }
    selected = selected_overlays()
    changed = [key for key in selected if selected[key] != applied[key]]
    if changed:
        sys.exit("demo overlay selection changed: " + ", ".join(changed))


def validate_selected_overlay_values(state):
    values = runtime_values(state)
    voice_port = os.environ.get("RAMFLUX_DEMO_VOICE_UDP_PORT", "")
    if voice_port:
        expected = {
            "RAMFLUX_RELAY_VOICE_PUBLIC_ENDPOINT": f"{os.environ['DEMO_HOST']}:{voice_port}",
            "RAMFLUX_RELAY_VOICE_UDP_PORT": f"{os.environ['DEMO_BIND_ADDR']}:{voice_port}",
        }
        if not (state / "compose.voice.yml").is_file() or any(
                values.get(key) != value for key, value in expected.items()):
            sys.exit("voice configuration was not applied by the last up; run up first "
                     "before maintenance (or restore the last applied selection)")
    admin_port = os.environ.get("DEMO_ADMIN_LOOPBACK_PORT", "")
    if admin_port and (not (state / "compose.admin.yml").is_file()
                       or values.get("RAMFLUX_FEDERATION_ADMIN_LOOPBACK_PORT") != admin_port):
        sys.exit("admin loopback configuration was not applied by the last up; run up first")


def render_files(repo, state, owner):
    selected = selected_overlays()
    label = {"org.ramflux.demo.owner": owner["token"]}
    override = {
        "services": {f"ramflux-{name}": {
            "build": {"context": str(repo)}, "restart": "unless-stopped", "labels": label,
        } for name in SERVICES},
        "volumes": {f"{name}-redb": {"labels": label} for name in SERVICES},
        "networks": {"default": {"labels": label}},
    }
    atomic_json(state / "demo-override.json", override)
    refreshed = []
    for filename, source, enabled in (
        ("compose.yml", "docker-compose.yml", True),
        ("compose.voice.yml", "docker-compose.voice.yml", selected["RAMFLUX_DEMO_VOICE_UDP_PORT"]),
        ("compose.admin.yml", "docker-compose.admin.yml", selected["DEMO_ADMIN_LOOPBACK_PORT"]),
    ):
        frozen = state / filename
        if enabled or frozen.exists():
            content = (repo / "deploy" / source).read_bytes()
            if not frozen.exists() or frozen.read_bytes() != content:
                existed = frozen.exists()
                atomic_bytes(frozen, content)
                if existed:
                    refreshed.append(filename)
    atomic_bytes(state / "deploy-tree.version", deploy_tree_version(repo).encode())
    atomic_bytes(state / "owner.token", (owner["token"] + "\n").encode())
    if refreshed:
        print("demo configuration refreshed: " + ", ".join(refreshed))


def new_snapshot_reference(version):
    return f"{version}/{secrets.token_hex(16)}"


def normalize_history(owner, previous_snapshot):
    current_version = owner["settings"]["DEMO_VERSION"]
    versions = list(owner.get("version_history", []))
    if not versions or versions[-1] != current_version:
        versions.append(current_version)
    snapshots = list(owner.get("snapshot_history", []))
    if not snapshots or snapshots[-1] != previous_snapshot:
        snapshots.append(previous_snapshot)
    return versions, snapshots


def prepare(repo, state, command):
    settings = {key: os.environ[key] for key in (
        "DEMO_PROJECT", "DEMO_HOST", "DEMO_NODE_ID", "DEMO_GATEWAY_PORT",
        "DEMO_RELAY_PORT", "DEMO_HTTP_PORT", "DEMO_TURN_PORT", "DEMO_MESH_PORT",
        "DEMO_BIND_ADDR", "DEMO_VERSION",
    )}
    marker = state / "owner.json"
    pending_marker = state / "owner.json.pending"
    transaction_marker = state / "transaction.pending"
    if transaction_marker.exists():
        sys.exit("unfinished demo transaction detected; restore the last snapshot before retrying")
    if marker.exists():
        owner = json.loads(marker.read_text())
        if owner["directory"] != str(state):
            sys.exit("demo settings changed: restore the original env file or use a fresh data directory/project")
        current = owner["settings"]
        if command in ("upgrade", "rollback"):
            changed = [key for key in settings if key != "DEMO_VERSION" and settings[key] != current[key]]
            if changed:
                sys.exit("demo settings changed beyond DEMO_VERSION: restore every other original setting")
            validate_maintenance_overlays(state)
            validate_selected_overlay_values(state)
        elif owner["settings"] != settings:
            sys.exit("demo settings changed: use upgrade for DEMO_VERSION only, or restore the original env file")
    else:
        if command != "up":
            sys.exit("upgrade and rollback require an existing owned demo data directory")
        if any(state.iterdir()):
            sys.exit("refusing to adopt a nonempty, unowned data directory")
        owner = {"settings": settings, "version_history": [], "snapshot_history": [],
                 "directory": str(state), "token": secrets.token_hex(16)}

    if command not in ("up", "upgrade", "rollback"):
        if not (state / "compose.yml").is_file():
            sys.exit("saved compose.yml missing; run up before maintenance")
        validate_selected_overlay_values(state)
        return

    if command == "upgrade" and settings["DEMO_VERSION"] == owner["settings"]["DEMO_VERSION"]:
        sys.exit("upgrade requires a changed DEMO_VERSION")
    if command == "rollback" and len(owner.get("snapshot_history", [])) < 2:
        sys.exit("no previous demo snapshot is available for rollback")

    previous_snapshot = owner.get("current_snapshot")
    capture_legacy_snapshot = bool(
        marker.exists() and not previous_snapshot and "snapshot_history" not in owner
    )
    if capture_legacy_snapshot:
        previous_snapshot = new_snapshot_reference(owner["settings"]["DEMO_VERSION"])

    if command == "upgrade":
        versions, snapshots = normalize_history(owner, previous_snapshot)
        target_snapshot = new_snapshot_reference(settings["DEMO_VERSION"])
        target_owner = {**owner, "settings": settings,
                        "version_history": versions + [settings["DEMO_VERSION"]],
                        "snapshot_history": snapshots + [target_snapshot],
                        "current_snapshot": target_snapshot}
    elif command == "rollback":
        snapshots = list(owner.get("snapshot_history", []))
        target_snapshot = snapshots[-2]
        target_owner = owner
    else:
        versions = list(owner.get("version_history", [])) or [settings["DEMO_VERSION"]]
        snapshots = list(owner.get("snapshot_history", []))
        target_snapshot = new_snapshot_reference(settings["DEMO_VERSION"])
        if snapshots:
            snapshots[-1] = target_snapshot
        else:
            snapshots = [target_snapshot]
        target_owner = {**owner, "settings": settings, "version_history": versions,
                        "snapshot_history": snapshots, "current_snapshot": target_snapshot}

    atomic_json(pending_marker, target_owner)
    atomic_json(state / "transaction.pending", {
        "command": command, "previous_snapshot": previous_snapshot, "target_snapshot": target_snapshot,
    })
    if capture_legacy_snapshot:
        if not (state / "deploy-tree.version").exists():
            atomic_bytes(state / "deploy-tree.version", b"legacy:unknown\n")
        capture_snapshot(state, previous_snapshot)
    if command == "rollback":
        restore_snapshot(state, target_snapshot)
    else:
        render_files(repo, state, target_owner)


def commit(state, command):
    transaction = json.loads((state / "transaction.pending").read_text())
    if transaction["command"] != command:
        sys.exit("demo transaction command changed")
    if command in ("up", "upgrade"):
        pending = state / "owner.json.pending"
        capture_snapshot(state, transaction["target_snapshot"], owner_source=pending)
        atomic_bytes(state / "owner.json", pending.read_bytes())
    (state / "owner.json.pending").unlink(missing_ok=True)
    (state / "transaction.pending").unlink()


def recover(state):
    transaction = json.loads((state / "transaction.pending").read_text())
    previous = transaction.get("previous_snapshot")
    if not previous:
        sys.exit("failed initial up has no previous snapshot to restore")
    restore_snapshot(state, previous)
    (state / "owner.json.pending").unlink(missing_ok=True)
    owner = json.loads((state / "owner.json").read_text())
    changed = [key for key, value in owner["settings"].items()
               if key != "DEMO_VERSION" and os.environ.get(key) != value]
    if changed:
        sys.exit("demo settings changed during recovery: restore every original setting")
    validate_maintenance_overlays(state)
    print(owner["settings"]["DEMO_VERSION"])


def main():
    if len(sys.argv) < 4:
        sys.exit("usage: demo-node-config.py REPO STATE ACTION [COMMAND]")
    repo, state = map(Path, sys.argv[1:3])
    action = sys.argv[3]
    if action == "prepare":
        prepare(repo, state, sys.argv[4])
    elif action == "commit":
        commit(state, sys.argv[4])
    elif action == "recover":
        recover(state)
    elif action == "finish-recovery":
        (state / "owner.json.pending").unlink(missing_ok=True)
        (state / "transaction.pending").unlink()
    elif action == "abort-initial":
        transaction = json.loads((state / "transaction.pending").read_text())
        if transaction.get("previous_snapshot") is not None:
            sys.exit("refusing to abort a transaction with a previous snapshot")
        pending = json.loads((state / "owner.json.pending").read_text())
        pending.pop("current_snapshot", None)
        pending["version_history"] = []
        pending["snapshot_history"] = []
        atomic_json(state / "owner.json", pending)
        (state / "owner.json.pending").unlink()
        (state / "transaction.pending").unlink()
    else:
        sys.exit("invalid demo configuration action")


if __name__ == "__main__":
    main()
