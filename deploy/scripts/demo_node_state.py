# SPDX-License-Identifier: BSD-3-Clause
"""Closed-list, stopped-volume backup and reset for the demo lifecycle."""
import hashlib
import json
import os
import subprocess
import sys

# Never derive a target from user input. Keys, accounts and routing are excluded.
RESETTABLE_STATES = {"relay": "relay-redb"}
ENGINE_TIMEOUT_SECONDS = 300


def selected(command, owner, transaction=None):
    requested = os.environ.get("DEMO_RESET_SERVICE", "")
    if requested and (command != "upgrade" or requested not in RESETTABLE_STATES):
        sys.exit("--reset-service accepts only relay, on upgrade only")
    if command == "upgrade":
        return requested
    record = (transaction or {}).get("service_state") if command == "recover" else (
        owner.get("state_reset") if command == "rollback" else None)
    if record:
        if record.get("service") not in RESETTABLE_STATES:
            sys.exit("refusing unsupported stored service-state selection")
        return record["service"]
    return ""


def engine_run(engine, *args, **kwargs):
    return subprocess.run([engine, *args], check=True, timeout=ENGINE_TIMEOUT_SECONDS, **kwargs)


def volume_name(owner, service):
    return owner["settings"]["DEMO_PROJECT"] + "_" + RESETTABLE_STATES[service]


def inspect_volume(engine, owner, service, allow_missing=False):
    name = volume_name(owner, service)
    names = engine_run(engine, "volume", "ls", "-q", capture_output=True, text=True).stdout.splitlines()
    if name not in names:
        if allow_missing:
            return False
        sys.exit(f"required service-state volume is missing: {name}")
    rows = json.loads(engine_run(engine, "volume", "inspect", name,
                                 capture_output=True, text=True).stdout)
    labels = rows[0].get("Labels") or {}
    if (rows[0].get("Name") != name or labels.get("org.ramflux.demo.owner") != owner["token"]
            or labels.get("com.docker.compose.project") != owner["settings"]["DEMO_PROJECT"]):
        sys.exit(f"refusing foreign service-state volume: {name}")
    return True


def archive_path(config, state, reference):
    snapshot = config.safe_snapshot_path(state, reference)
    config.read_snapshot_manifest(state, reference)
    directory = snapshot / "service-state"
    if directory.is_symlink() or (directory.exists() and not directory.is_dir()):
        raise config.SnapshotError("unsafe service-state backup directory")
    return directory / "relay.tar"


def archive_digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def verify_archive(config, state, reference):
    archive = archive_path(config, state, reference)
    manifest = archive.with_suffix(".json")
    if (archive.is_symlink() or not archive.is_file() or manifest.is_symlink()
            or not manifest.is_file()):
        raise config.SnapshotError("missing or unsafe relay state backup")
    metadata = json.loads(manifest.read_text())
    if (metadata.get("service") != "relay" or metadata.get("sha256") != archive_digest(archive)):
        raise config.SnapshotError("relay state backup checksum mismatch")
    return archive


def plan(config, state, command, engine):
    owner = json.loads((state / "owner.json").read_text()) if (state / "owner.json").exists() else {}
    transaction = json.loads((state / "transaction.pending").read_text()) if command == "recover" else {}
    service = selected(command, owner, transaction)
    if not service:
        return
    # Recovery can run after the selected volume was removed but before Compose recreated it.
    inspect_volume(engine, owner, service, allow_missing=command == "recover")
    if command == "rollback":
        reference = owner["state_reset"]["backup_snapshot"]
        if reference != owner["snapshot_history"][-2]:
            sys.exit("reset backup does not match the rollback target")
        verify_archive(config, state, reference)
    elif command == "recover":
        record = transaction["service_state"]
        if record.get("backup_ready"):
            verify_archive(config, state, record["backup_snapshot"])
    # Resolve the already-installed image now; never pull a helper or run a service entrypoint.
    image = transaction["service_state"]["image"] if command == "recover" else (
        config.image_name("relay", owner["settings"]["DEMO_VERSION"]))
    engine_run(engine, "image", "inspect", image, stdout=subprocess.DEVNULL)
    print(service)


def checkpoint(config, state, command, owner):
    service = selected(command, owner)
    if not service:
        return None
    reference = config.new_snapshot_reference(owner["settings"]["DEMO_VERSION"])
    checkpoint_owner = {**owner, "current_snapshot": reference,
                        "snapshot_history": [*owner["snapshot_history"][:-1], reference]}
    temporary_owner = state / ".state-checkpoint-owner"
    config.atomic_json(temporary_owner, checkpoint_owner)
    try:
        config.capture_snapshot(state, reference, owner_source=temporary_owner)
    finally:
        config.durable_unlink(temporary_owner)
    record = {"service": service, "backup_snapshot": reference,
              "image": config.image_name("relay", owner["settings"]["DEMO_VERSION"])}
    if command == "rollback":
        record["restore_snapshot"] = owner["state_reset"]["backup_snapshot"]
    return record


def tar_command(engine, owner, record, readonly):
    name = volume_name(owner, record["service"])
    mount = f"type=volume,src={name},dst=/state" + (",readonly" if readonly else "")
    return [engine, "run", *([] if readonly else ["--interactive"]),
            "--rm", "--pull=never", "--network=none", "--read-only",
            "--user=0:0", "--label", f"org.ramflux.demo.owner={owner['token']}",
            "--mount", mount, "--entrypoint=tar", record["image"],
            "-C", "/state", "-cpf" if readonly else "-xpf", "-", "."]


def capture_archive(config, state, engine, owner, record):
    archive = archive_path(config, state, record["backup_snapshot"])
    config.ensure_directory(archive.parent)
    temporary = archive.with_suffix(".pending")
    # A retry before backup_ready never follows an incomplete archive.
    if temporary.is_symlink():
        raise config.SnapshotError("unsafe partial relay state backup")
    temporary.unlink(missing_ok=True)
    with temporary.open("xb") as output:
        subprocess.run(tar_command(engine, owner, record, True), check=True,
                       stdout=output, timeout=ENGINE_TIMEOUT_SECONDS)
        output.flush()
        os.fsync(output.fileno())
    temporary.chmod(0o400)
    os.replace(temporary, archive)
    config.fsync_directory(archive.parent)
    config.atomic_bytes(archive.with_suffix(".json"), (json.dumps({
        "service": record["service"], "volume": volume_name(owner, record["service"]),
        "sha256": archive_digest(archive),
    }) + "\n").encode(), mode=0o400)


def replace_volume(config, state, engine, owner, record, restore_reference=None):
    archive = verify_archive(config, state, restore_reference) if restore_reference else None
    name = volume_name(owner, record["service"])
    present = inspect_volume(engine, owner, record["service"], allow_missing=True)
    # Read and act on this exact closed list, without wildcards or force removal.
    print(f"service-state target: {name}; action: {'restore' if archive else 'reset'}", flush=True)
    if present:
        engine_run(engine, "volume", "rm", name)
    if archive:
        engine_run(engine, "volume", "create", "--label", f"org.ramflux.demo.owner={owner['token']}",
                   "--label", f"com.docker.compose.project={owner['settings']['DEMO_PROJECT']}",
                   "--label", "com.docker.compose.volume=relay-redb", name)
        with archive.open("rb") as source:
            subprocess.run(tar_command(engine, owner, record, False), check=True,
                           stdin=source, timeout=ENGINE_TIMEOUT_SECONDS)


def apply(config, state, engine, command):
    transaction = json.loads((state / "transaction.pending").read_text())
    record = transaction.get("service_state")
    if not record:
        return
    owner = json.loads((state / "owner.json").read_text())
    selected("recover", owner, transaction)
    project = owner["settings"]["DEMO_PROJECT"]
    remaining = engine_run(engine, "ps", "-aq", "--filter",
                           f"label=com.docker.compose.project={project}",
                           capture_output=True, text=True).stdout.strip()
    if remaining:
        sys.exit("refusing service-state operation while project containers still exist")
    if command == "recover":
        if record.get("backup_ready"):
            replace_volume(config, state, engine, owner, record, record["backup_snapshot"])
        return
    inspect_volume(engine, owner, record["service"])
    capture_archive(config, state, engine, owner, record)
    verify_archive(config, state, record["backup_snapshot"])
    record["backup_ready"] = True
    config.atomic_json(state / "transaction.pending", transaction)
    replace_volume(config, state, engine, owner, record, record.get("restore_snapshot"))
