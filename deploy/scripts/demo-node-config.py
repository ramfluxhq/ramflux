#!/usr/bin/env python3
"""Validate, render, snapshot, and restore an isolated production demo project."""
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import stat
import subprocess
import sys
from urllib.parse import urlsplit

SERVICES = ("gateway", "router", "notify", "federation", "relay", "signaling", "retention")
SNAPSHOT_ROOT_FILES = (
    "compose.yml", "compose.voice.yml", "compose.admin.yml", "compose.router-admin.yml", "runtime.env",
    "owner.json", "owner.token", "demo-override.json", "deploy-tree.version",
    "identity.env", ".env",
)
PAIRING_KEY_PATH = "/etc/ramflux/pairing/node-signing.key"
SNAPSHOT_DIRECTORIES = ("config", "certs", "secrets")
SNAPSHOT_REQUIRED = {
    "compose.yml", "runtime.env", "owner.json", "demo-override.json",
    *(f"config/{service}.toml" for service in SERVICES),
}
SNAPSHOT_PREVIOUS_RETENTION = 3
MANUAL_RECOVERY = (
    "manual recovery required: restore the complete demo data directory from the "
    "operator backup, verify owner.json, then remove transaction.pending"
)


class SnapshotError(Exception):
    """A snapshot cannot be safely captured or restored."""


def federation_bind():
    """Host address that publishes the federation HTTP port.

    A configured public origin means a reverse proxy on this host fronts the node, so the port
    is published on loopback only, always. A direct (origin-less) demo keeps DEMO_BIND_ADDR.
    """
    explicit = os.environ.get("DEMO_FEDERATION_BIND_ADDR", "")
    if os.environ.get("DEMO_PUBLIC_ORIGIN", ""):
        if explicit not in ("", "127.0.0.1"):
            sys.exit("DEMO_FEDERATION_BIND_REFUSED: with DEMO_PUBLIC_ORIGIN the federation HTTP "
                     "port is published on 127.0.0.1 only (DEMO_FEDERATION_BIND_ADDR must be unset "
                     "or 127.0.0.1)")
        return "127.0.0.1"
    return explicit or os.environ.get("DEMO_BIND_ADDR", "0.0.0.0")


# The compose network is the /24 around the federation address. Its upper half is the only range
# the runtime may allocate dynamically, so addresses .2-.127 can never be taken by another container.
STATIC_RANGE_END = 128


def reject_obsolete_inputs():
    """Refuse operator inputs that are now derived, in every mode (pairing on or off)."""
    if os.environ.get("RAMFLUX_FEDERATION_TRUSTED_PROXIES", ""):
        sys.exit("DEMO_PAIRING_TRUSTED_PROXIES_OBSOLETE: RAMFLUX_FEDERATION_TRUSTED_PROXIES is derived "
                 "from DEMO_FEDERATION_STATIC_IP and must not be set")


def pairing_network_ipam(static_ip):
    """The compose network's /24 and its dynamic range (upper half), which excludes the pin."""
    subnet = ipaddress.ip_network(f"{static_ip}/24", strict=False)
    dynamic = ipaddress.ip_network(f"{str(subnet.network_address).rsplit('.', 1)[0]}.{STATIC_RANGE_END}/25")
    return str(subnet), str(dynamic)


def verify_existing_network():
    """Refuse an existing compose network whose applied IPAM is not the generated one.

    Compose creates a network only when it is absent and never reconfigures an existing one, so a
    network created before the address reservation keeps an unrestricted allocation pool. The shell
    passes the engine's inspection JSON (Docker or Podman shape) in DEMO_EXISTING_NETWORK_INSPECT
    only when the network exists. Nothing is mutated or adopted; the operator recreates it.
    """
    raw = os.environ.get("DEMO_EXISTING_NETWORK_INSPECT", "")
    if not raw or os.environ.get("RAMFLUX_DEVICE_PAIRING_ENABLED", "0") != "1" \
            or not os.environ.get("DEMO_FEDERATION_STATIC_IP"):
        return  # a missing address is refused later by the generator's own input checks
    subnet, dynamic = pairing_network_ipam(pairing_federation_ip())
    first, last = ipaddress.ip_network(dynamic)[1], ipaddress.ip_network(dynamic)[-1]
    found = []
    try:
        entry = json.loads(raw)[0]
        for item in entry.get("subnets") or []:  # Podman: lease range as host addresses
            lease = item.get("lease_range") or {}
            found.append((item.get("subnet"), (lease.get("start_ip"), lease.get("end_ip"))))
        for item in (entry.get("IPAM") or {}).get("Config") or []:  # Docker: the CIDR
            found.append((item.get("Subnet"), item.get("IPRange")))
    except (ValueError, IndexError, AttributeError, TypeError):
        found = []
    if (subnet, dynamic) in [(a, b) for a, b in found if isinstance(b, str)] or \
            (subnet, (str(first), str(last))) in [(a, b) for a, b in found if isinstance(b, tuple)]:
        return
    sys.exit(f"DEMO_NETWORK_IPAM_MISMATCH: the existing compose network does not have subnet {subnet} "
             f"with dynamic range {dynamic}, so the pinned federation address is not reserved. It is "
             "never modified here: stop the node, remove the compose network, and run up again to "
             "recreate it")


def pairing_federation_ip():
    """The federation's pinned compose-network address, the only proxy peer pairing trusts.

    Rootless port publishing makes every connection to the federation HTTP port arrive from the
    federation container's own address, and an unpinned address changes on every recreate. The
    operator names a private IPv4 inside the compose network; the generator pins the federation
    to it and trusts exactly it.
    """
    raw = os.environ.get("DEMO_FEDERATION_STATIC_IP", "")
    try:
        if not raw or raw != raw.strip() or not raw.isascii() or "/" in raw or "%" in raw:
            raise ValueError(raw)
        address = ipaddress.IPv4Address(raw)
    except ValueError:
        sys.exit("DEMO_FEDERATION_STATIC_IP_REQUIRED: pairing needs DEMO_FEDERATION_STATIC_IP, one "
                 "private IPv4 address inside the compose network (for example 10.89.1.110)")
    last = int(address) & 0xFF
    if not address.is_private or address.is_loopback or address.is_link_local or last in (0, 1, 255):
        sys.exit(f"DEMO_FEDERATION_STATIC_IP_INVALID: {raw} must be a private host address "
                 "(not the network, gateway or broadcast address)")
    if last >= STATIC_RANGE_END:
        sys.exit(f"DEMO_FEDERATION_STATIC_IP_INVALID: {raw} must be in the reserved static part of "
                 f"its /24 (host .2 to .{STATIC_RANGE_END - 1}); .{STATIC_RANGE_END} and above is the "
                 "dynamic allocation range of the other services")
    return str(address)


def public_origin():
    """Resolve an optional public HTTPS origin before any managed state is written."""
    value = os.environ.get("DEMO_PUBLIC_ORIGIN", "")
    if not value:
        return f"http://{os.environ['DEMO_HOST']}:{os.environ['DEMO_HTTP_PORT']}"
    try:
        if any(character.isspace() or ord(character) < 32 or ord(character) == 127
               for character in value) or any(character in value for character in "\\?#"):
            raise ValueError("forbidden URL characters")
        url = urlsplit(value)
        if (url.scheme != "https" or not url.netloc or url.path
                or url.username is not None or url.password is not None):
            raise ValueError("expected an HTTPS origin without credentials or a path")
        host = url.hostname or ""
        if len(host) > 253 or not all(
            re.fullmatch(r"[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?", label)
            for label in host.split(".")
        ):
            raise ValueError("expected a DNS name or IPv4 address")
        if url.netloc.endswith(":") or (url.port is not None and not 1 <= url.port <= 65535):
            raise ValueError("invalid HTTPS port")
    except ValueError as error:
        raise SnapshotError(f"DEMO_PUBLIC_ORIGIN_INVALID: {error}") from error
    return value


def client_runtime():
    """Render the advertised client configuration used by demo-node.sh."""
    host = os.environ["DEMO_HOST"]
    values = {
        "RAMFLUX_CLIENT_GATEWAY_QUIC_ADDR": f"{host}:{os.environ['DEMO_GATEWAY_PORT']}",
        "RAMFLUX_CLIENT_GATEWAY_TCP_ADDR": f"{host}:{os.environ['DEMO_GATEWAY_PORT']}",
        "RAMFLUX_CLIENT_GATEWAY_SERVER_NAME": "ramflux-gateway",
        "RAMFLUX_CLIENT_RELAY_QUIC_ADDR": f"{host}:{os.environ['DEMO_RELAY_PORT']}",
        "RAMFLUX_CLIENT_RELAY_SERVER_NAME": "ramflux-relay",
        "RAMFLUX_CLIENT_PREKEY_HTTP_URL": public_origin(),
        "RAMFLUX_CLIENT_SIGNALING_TURN_ADDR": f"{host}:{os.environ['DEMO_TURN_PORT']}",
    }
    return "".join(f"{key}={value}\n" for key, value in values.items())


def fsync_directory(path):
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def ensure_directory(path, mode=0o700):
    missing = []
    current = path
    while not current.exists():
        missing.append(current)
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        raise SnapshotError(f"refusing unsafe snapshot directory: {current}")
    for directory in reversed(missing):
        directory.mkdir(mode=mode)
        fsync_directory(directory.parent)
        fsync_directory(directory)


def atomic_bytes(path, content, mode=0o600):
    ensure_directory(path.parent)
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
        fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def atomic_json(path, value):
    atomic_bytes(path, (json.dumps(value, indent=2) + "\n").encode())


def durable_unlink(path):
    try:
        path.unlink()
    except FileNotFoundError:
        return
    fsync_directory(path.parent)


def safe_snapshot_path(state, reference):
    parts = reference.split("/")
    if len(parts) != 2 or any(not part or part in (".", "..") for part in parts):
        raise SnapshotError("invalid demo snapshot reference")
    root = state / "version-snapshots"
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise SnapshotError("refusing symlinked or non-directory version-snapshots path")
    target = root.joinpath(*parts)
    if target.parent.parent != root:
        raise SnapshotError("invalid demo snapshot reference")
    if target.parent.is_symlink() or target.is_symlink():
        raise SnapshotError("refusing symlinked demo snapshot path")
    return target


def snapshot_source_files(state, owner_source=None):
    sources = {}
    for name in SNAPSHOT_ROOT_FILES:
        source = owner_source if name == "owner.json" and owner_source else state / name
        if source.is_symlink():
            raise SnapshotError(f"refusing symlinked managed file: {name}")
        if source.is_file():
            sources[name] = source
    for dirname in SNAPSHOT_DIRECTORIES:
        root = state / dirname
        if root.is_symlink():
            raise SnapshotError(f"refusing symlinked managed directory: {dirname}")
        if not root.exists():
            continue
        if not root.is_dir():
            raise SnapshotError(f"refusing non-directory managed path: {dirname}")
        for directory, dirnames, filenames in os.walk(root, followlinks=False):
            base = Path(directory)
            for entry in list(dirnames):
                path = base / entry
                if path.is_symlink():
                    raise SnapshotError(
                        f"refusing symlinked managed directory: {path.relative_to(state)}"
                    )
            for filename in filenames:
                source = base / filename
                relative = source.relative_to(state).as_posix()
                if source.is_symlink() or not source.is_file():
                    raise SnapshotError(f"refusing non-regular managed file: {relative}")
                sources[relative] = source
    return sources


def validate_snapshot_name(name):
    path = Path(name)
    if path.is_absolute() or ".." in path.parts or "." in path.parts or not path.parts:
        return False
    return name in SNAPSHOT_ROOT_FILES or (
        len(path.parts) >= 2 and path.parts[0] in SNAPSHOT_DIRECTORIES
    )


def read_snapshot_manifest(state, reference):
    source = safe_snapshot_path(state, reference)
    manifest_path = source / "manifest.json"
    if manifest_path.is_symlink():
        raise SnapshotError("refusing symlinked demo snapshot manifest")
    try:
        manifest = json.loads(manifest_path.read_text())
    except (OSError, ValueError, TypeError) as error:
        raise SnapshotError(f"cannot read demo snapshot manifest: {error}") from error
    files = manifest.get("files")
    modes = manifest.get("modes", {})
    if (not isinstance(files, list) or len(set(files)) != len(files)
            or any(not isinstance(name, str) or not validate_snapshot_name(name) for name in files)
            or not isinstance(modes, dict)
            or any(name not in files or not isinstance(mode, int) or mode < 0 or mode > 0o777
                   for name, mode in modes.items())):
        raise SnapshotError("invalid demo snapshot manifest")
    if not SNAPSHOT_REQUIRED.issubset(files):
        raise SnapshotError("incomplete demo snapshot")
    for name in files:
        member = source / name
        if member.is_symlink() or not member.is_file():
            raise SnapshotError("incomplete or unsafe demo snapshot")
    return source, files, modes


def capture_snapshot(state, reference, owner_source=None):
    target = safe_snapshot_path(state, reference)
    if target.exists():
        raise SnapshotError("refusing to overwrite immutable demo snapshot")
    sources = snapshot_source_files(state, owner_source)
    missing = sorted(SNAPSHOT_REQUIRED - sources.keys())
    if missing:
        raise SnapshotError("cannot snapshot incomplete demo state: " + ", ".join(missing))
    ensure_directory(target.parent)
    temporary = target.with_name(target.name + ".pending")
    if temporary.exists() or temporary.is_symlink():
        raise SnapshotError("refusing existing partial demo snapshot")
    temporary.mkdir(mode=0o700)
    fsync_directory(temporary.parent)
    modes = {}
    for name, source in sorted(sources.items()):
        modes[name] = stat.S_IMODE(source.stat().st_mode)
        atomic_bytes(temporary / name, source.read_bytes(), mode=0o400)
    atomic_bytes(
        temporary / "manifest.json",
        (json.dumps({"files": sorted(sources), "modes": modes}, indent=2) + "\n").encode(),
        mode=0o400,
    )
    fsync_directory(temporary)
    os.replace(temporary, target)
    fsync_directory(target.parent)


def restore_snapshot(state, reference):
    source, files, modes = read_snapshot_manifest(state, reference)
    wanted = set(files)
    current = snapshot_source_files(state)
    for name in sorted(set(current) - wanted, reverse=True):
        durable_unlink(state / name)
    for name in files:
        atomic_bytes(state / name, (source / name).read_bytes(), mode=modes.get(name, 0o600))
    for pattern in (".runtime.env.pending.*", ".*.tmp"):
        for temporary in state.glob(pattern):
            if temporary.is_file() and not temporary.is_symlink():
                durable_unlink(temporary)
    for dirname in SNAPSHOT_DIRECTORIES:
        root = state / dirname
        if root.is_dir() and not root.is_symlink():
            for directory, _, _ in os.walk(root, topdown=False, followlinks=False):
                path = Path(directory)
                if path != root:
                    try:
                        path.rmdir()
                        fsync_directory(path.parent)
                    except OSError:
                        pass


def snapshot_runtime_values(state, reference):
    source, files, _ = read_snapshot_manifest(state, reference)
    if "runtime.env" not in files:
        raise SnapshotError("incomplete demo snapshot")
    return dict(line.split("=", 1) for line in (source / "runtime.env").read_text().splitlines()
                if "=" in line)


def validate_snapshot_overlays(state, reference):
    values = snapshot_runtime_values(state, reference)
    voice_value = values.get("RAMFLUX_RELAY_VOICE_UDP_PORT", "")
    target_voice_port = voice_value.rsplit(":", 1)[-1] if voice_value else ""
    target_admin_port = values.get("RAMFLUX_FEDERATION_ADMIN_LOOPBACK_PORT", "")
    router_enabled = values.get("RAMFLUX_ROUTER_ADMIN_ENABLED", "0") == "1"
    applied = {
        "RAMFLUX_DEMO_VOICE_UDP_PORT": target_voice_port,
        "DEMO_ADMIN_LOOPBACK_PORT": target_admin_port,
        "RAMFLUX_ROUTER_ADMIN_ENABLED": router_enabled,
        "RAMFLUX_ROUTER_ADMIN_PORT": values.get("RAMFLUX_ROUTER_ADMIN_PORT", "59488") if router_enabled else "",
    }
    selected = {
        "RAMFLUX_DEMO_VOICE_UDP_PORT": os.environ.get("RAMFLUX_DEMO_VOICE_UDP_PORT", ""),
        "DEMO_ADMIN_LOOPBACK_PORT": os.environ.get("DEMO_ADMIN_LOOPBACK_PORT", ""),
        "RAMFLUX_ROUTER_ADMIN_ENABLED": os.environ.get("RAMFLUX_ROUTER_ADMIN_ENABLED", "0") == "1",
        "RAMFLUX_ROUTER_ADMIN_PORT": os.environ.get("RAMFLUX_ROUTER_ADMIN_PORT", "59488") if os.environ.get("RAMFLUX_ROUTER_ADMIN_ENABLED", "0") == "1" else "",
    }
    changed = [key for key in selected if selected[key] != applied[key]]
    if changed:
        sys.exit("rollback overlay selection differs from its snapshot: " + ", ".join(changed))


def prune_snapshots(state, owner):
    root = state / "version-snapshots"
    if not root.exists():
        return
    if root.is_symlink() or not root.is_dir():
        raise SnapshotError("refusing symlinked or non-directory version-snapshots path")
    history = list(owner.get("snapshot_history", []))
    current = owner.get("current_snapshot")
    keep = set(history[-(SNAPSHOT_PREVIOUS_RETENTION + 1):])
    if current:
        keep.add(current)
    for version in root.iterdir():
        if version.is_symlink() or not version.is_dir():
            raise SnapshotError("refusing unsafe entry in version-snapshots")
        for snapshot in version.iterdir():
            reference = f"{version.name}/{snapshot.name}"
            if snapshot.is_symlink() or not snapshot.is_dir():
                raise SnapshotError("refusing unsafe entry in version-snapshots")
            if reference not in keep:
                shutil.rmtree(snapshot)
                fsync_directory(version)
        try:
            version.rmdir()
            fsync_directory(root)
        except OSError:
            pass


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


def custody_inputs(state):
    """Retain configured custody inputs without generating a receiving-node trust pin."""
    keys = (
        "RAMFLUX_CUSTODY_NODE_PUBLIC_KEY", "RAMFLUX_CUSTODY_NODE_RECORD_FILE",
        "RAMFLUX_CUSTODY_PROXY_SIGNING_SEED", "RAMFLUX_CUSTODY_HANDSHAKE_POOL",
        "RAMFLUX_CUSTODY_AUTHENTICATED_POOL", "RAMFLUX_CUSTODY_AUTH_TIMEOUT_MS",
        "RAMFLUX_CUSTODY_PREAUTH_HANDSHAKES_PER_SOURCE",
        "RAMFLUX_CUSTODY_CHALLENGES_PER_IP_PER_MINUTE",
        "RAMFLUX_CUSTODY_CHALLENGES_PER_PREFIX_PER_MINUTE",
        "RAMFLUX_CUSTODY_CHALLENGES_PER_NODE_PER_MINUTE",
        "RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_DAY",
        "RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_MINUTE",
        "RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_PREFIX_PER_DAY",
    )
    previous = runtime_values(state)
    values = {key: os.environ.get(key, previous.get(key, "")) for key in keys}
    changed = [key for key in (keys[0], keys[2])
               if previous.get(key) and values[key] != previous[key]]
    if changed:
        sys.exit("DEMO_CUSTODY_INPUT_CHANGED: " + ", ".join(changed))
    identity_keys = keys[:3]
    if any(values[key] for key in identity_keys):
        missing = [key for key in identity_keys if not values[key]]
        if missing:
            sys.exit("DEMO_CUSTODY_INPUT_MISSING: " + ", ".join(missing))
    for key in keys:
        value = values[key]
        if any(char in value for char in "\n\r\x00$'\"\\"):
            sys.exit("DEMO_CUSTODY_INPUT_INVALID: " + key)
    for key in (keys[0], keys[2]):
        if values[key] and not re.fullmatch(r"[A-Za-z0-9_-]+", values[key]):
            sys.exit("DEMO_CUSTODY_INPUT_INVALID: " + key)
    pool_key = "RAMFLUX_CUSTODY_AUTHENTICATED_POOL"
    if pool_key not in os.environ and previous.get(pool_key):
        print("WARN: retained finite RAMFLUX_CUSTODY_AUTHENTICATED_POOL=" + values[pool_key] +
              "; set RAMFLUX_CUSTODY_AUTHENTICATED_POOL= explicitly empty to return to unlimited",
              file=sys.stderr)
    record = None
    if values[keys[1]]:
        source = Path(values[keys[1]])
        if str(source) == "/etc/ramflux/custody/node-record.json":
            source = state / "secrets/custody/node-record.json"
        try:
            if not source.is_absolute() or source.is_symlink():
                raise ValueError("unsafe record path")
            with source.open("rb") as stream:
                record = stream.read(512 * 1024 + 1)
            if not record or len(record) > 512 * 1024:
                raise ValueError("record size")
        except (OSError, ValueError):
            sys.exit("DEMO_CUSTODY_INPUT_INVALID: " + keys[1])
        values[keys[1]] = "/etc/ramflux/custody/node-record.json"
    return {key: value for key, value in values.items() if value}, record


def custody_status(state):
    _, record = custody_inputs(state)
    if record is None:
        return "absent"
    if runtime_values(state).get("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY"):
        try:
            with (state / "secrets/custody/node-record.json").open("rb") as stream:
                previous_record = stream.read(512 * 1024 + 1)
        except OSError:
            previous_record = None
        if previous_record != record:
            return "record-changed"
    return "configured"


def append_custody_runtime(state, path):
    values, _ = custody_inputs(state)
    with path.open("a") as output:
        output.writelines(f"{key}={value}\n" for key, value in values.items())


def selected_overlays():
    return {
        "RAMFLUX_DEMO_VOICE_UDP_PORT": bool(os.environ.get("RAMFLUX_DEMO_VOICE_UDP_PORT")),
        "DEMO_ADMIN_LOOPBACK_PORT": bool(os.environ.get("DEMO_ADMIN_LOOPBACK_PORT")),
        "RAMFLUX_ROUTER_ADMIN_ENABLED": os.environ.get("RAMFLUX_ROUTER_ADMIN_ENABLED", "0") == "1",
    }


def validate_maintenance_overlays(state):
    values = runtime_values(state)
    applied = {
        "RAMFLUX_DEMO_VOICE_UDP_PORT": bool((state / "compose.voice.yml").is_file()
            and values.get("RAMFLUX_RELAY_VOICE_UDP_PORT")),
        "DEMO_ADMIN_LOOPBACK_PORT": bool((state / "compose.admin.yml").is_file()
            and values.get("RAMFLUX_FEDERATION_ADMIN_LOOPBACK_PORT")),
        "RAMFLUX_ROUTER_ADMIN_ENABLED": bool((state / "compose.router-admin.yml").is_file()
            and values.get("RAMFLUX_ROUTER_ADMIN_ENABLED", "0") == "1"),
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
    if os.environ.get("RAMFLUX_ROUTER_ADMIN_ENABLED", "0") == "1" and (
            not (state / "compose.router-admin.yml").is_file()
            or values.get("RAMFLUX_ROUTER_ADMIN_ENABLED", "0") != "1"
            or values.get("RAMFLUX_ROUTER_ADMIN_PORT", "59488") != os.environ.get("RAMFLUX_ROUTER_ADMIN_PORT", "59488")):
        sys.exit("router admin configuration was not applied by the last up; run up first")


def render_files(repo, state, owner):
    selected = selected_overlays()
    label = {"org.ramflux.demo.owner": owner["token"]}
    override = {
        "services": {f"ramflux-{name}": {
            "build": {"context": str(repo)}, "restart": "unless-stopped", "labels": label,
        } for name in SERVICES},
        "volumes": {**{f"{name}-redb": {"labels": label} for name in SERVICES},
                    "node-privacy": {"labels": label}},
        "networks": {"default": {"labels": label}},
    }
    custody, record = custody_inputs(state)
    if record is not None:
        directory = state / "secrets/custody"
        ensure_directory(directory, mode=0o755)
        directory.chmod(0o755)
        atomic_bytes(directory / "node-record.json", record, mode=0o644)
        override["services"]["ramflux-router"]["volumes"] = [
            "./secrets/custody:/etc/ramflux/custody:ro",
        ]
    for service, keys in (
        ("gateway", ("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY", "RAMFLUX_CUSTODY_PROXY_SIGNING_SEED")),
        ("router", ("RAMFLUX_CUSTODY_NODE_PUBLIC_KEY", "RAMFLUX_CUSTODY_NODE_RECORD_FILE",
                    "RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_DAY",
                    "RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_MINUTE",
                    "RAMFLUX_CUSTODY_NEW_PRINCIPALS_PER_PREFIX_PER_DAY")),
    ):
        environment = {key: "${RF_COMPOSE_" + key.removeprefix("RAMFLUX_") + "}"
                       for key in keys if key in custody}
        if environment:
            override["services"][f"ramflux-{service}"]["environment"] = environment
    reject_obsolete_inputs()
    if os.environ.get("RAMFLUX_DEVICE_PAIRING_ENABLED", "0") == "1":
        if record is None:
            sys.exit("DEMO_PAIRING_REQUIRES_CUSTODY: RAMFLUX_CUSTODY_NODE_RECORD_FILE is required")
        # Tickets and invitations are signed by the pinned node identity key. The router gets
        # that one file read-only, through the restricted secret group; the key bytes never
        # enter the environment, this JSON or logs.
        # `prepare` runs before certificates exist on a first up, so only an existing key is
        # checked here; a missing key makes the router refuse to start with a typed error.
        node_key = state / "certs/node-identity/node-signing.key"
        if node_key.is_symlink() or (node_key.exists() and node_key.stat().st_mode & 0o7137):
            sys.exit("DEMO_PAIRING_NODE_KEY_MODE: node-signing.key must be a regular file, 0640 or stricter")
        for service in ("router", "federation"):
            environment = override["services"][f"ramflux-{service}"].setdefault("environment", {})
            environment["RAMFLUX_DEVICE_PAIRING_ENABLED"] = "1"
        # Pairing HTTP is accepted only as TLS: the public reverse proxy terminates it and asserts
        # X-Forwarded-Proto, which the federation trusts only from the one pinned address it has
        # on the compose network (never a prefix, never a wildcard).
        origin = public_origin()
        if not origin.startswith("https://"):
            sys.exit("DEMO_PAIRING_REQUIRES_HTTPS_ORIGIN: DEMO_PUBLIC_ORIGIN must be an https origin")
        if federation_bind() != "127.0.0.1":
            sys.exit("DEMO_PAIRING_TRUSTED_PROXIES_NEED_LOOPBACK: trusting proxy addresses requires "
                     "the federation HTTP port to be published on 127.0.0.1 only")
        static_ip = pairing_federation_ip()
        for service in ("router", "federation"):
            override["services"][f"ramflux-{service}"]["environment"][
                "RAMFLUX_FEDERATION_PUBLIC_ORIGIN"] = origin
        federation = override["services"]["ramflux-federation"]
        federation["environment"]["RAMFLUX_FEDERATION_TRUSTED_PROXIES"] = static_ip
        federation["networks"] = {"default": {"ipv4_address": static_ip}}
        subnet, dynamic = pairing_network_ipam(static_ip)
        override["networks"]["default"]["ipam"] = {"config": [{"subnet": subnet, "ip_range": dynamic}]}
        router = override["services"]["ramflux-router"]
        router["environment"]["RAMFLUX_ROUTER_PAIRING_NODE_SIGNING_SEED_FILE"] = PAIRING_KEY_PATH
        router.setdefault("volumes", []).append(f"./certs/node-identity/node-signing.key:{PAIRING_KEY_PATH}:ro")
        router["group_add"] = ["${RAMFLUX_SECRET_GID:-0}"]
    atomic_json(state / "demo-override.json", override)
    refreshed = []
    for filename, source, enabled in (
        ("compose.yml", "docker-compose.yml", True),
        ("compose.voice.yml", "docker-compose.voice.yml", selected["RAMFLUX_DEMO_VOICE_UDP_PORT"]),
        ("compose.admin.yml", "docker-compose.admin.yml", selected["DEMO_ADMIN_LOOPBACK_PORT"]),
        ("compose.router-admin.yml", "docker-compose.router-admin.yml", selected["RAMFLUX_ROUTER_ADMIN_ENABLED"]),
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


def check_pending(state):
    marker = state / "transaction.pending"
    if marker.exists():
        transaction = json.loads(marker.read_text())
        identifier = transaction["target_snapshot"]
        instruction = "run `demo-node.sh recover` (or `rollback`)"
        if not transaction.get("previous_snapshot"):
            instruction = "initial setup failed: run `demo-node.sh recover` to undo it"
        print(f"pending upgrade transaction {identifier}: {instruction}", file=sys.stderr)
        sys.exit(3)


def prepare(repo, state, command, validate_only=False):
    public_origin()
    settings = {key: os.environ[key] for key in (
        "DEMO_PROJECT", "DEMO_HOST", "DEMO_NODE_ID", "DEMO_GATEWAY_PORT",
        "DEMO_RELAY_PORT", "DEMO_HTTP_PORT", "DEMO_TURN_PORT", "DEMO_MESH_PORT",
        "DEMO_BIND_ADDR", "DEMO_VERSION",
    )}
    settings["DEMO_PUBLIC_ORIGIN"] = os.environ.get("DEMO_PUBLIC_ORIGIN", "")
    marker = state / "owner.json"
    pending_marker = state / "owner.json.pending"
    check_pending(state)
    if marker.exists():
        owner = json.loads(marker.read_text())
        if owner["directory"] != str(state):
            sys.exit("demo settings changed: restore the original env file or use a fresh data directory/project")
        current = owner["settings"]
        if command in ("upgrade", "rollback"):
            changed = [key for key in settings if key != "DEMO_VERSION" and settings[key] != current.get(key)]
            if changed:
                sys.exit("demo settings changed beyond DEMO_VERSION: restore every other original setting")
        if command == "upgrade":
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
        return owner

    if command == "upgrade" and settings["DEMO_VERSION"] == owner["settings"]["DEMO_VERSION"]:
        sys.exit("upgrade requires a changed DEMO_VERSION")
    if command == "rollback" and len(owner.get("snapshot_history", [])) < 2:
        sys.exit("no previous demo snapshot is available for rollback")

    if command in ("up", "upgrade"):
        custody_inputs(state)

    previous_snapshot = owner.get("current_snapshot")
    if marker.exists() and not previous_snapshot and "snapshot_history" not in owner:
        sys.exit("obsolete data directory layout (no snapshot history); no adoption before v1, redeploy into a fresh directory")

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
        validate_snapshot_overlays(state, target_snapshot)
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

    verify_existing_network()
    if validate_only:
        return owner
    atomic_json(pending_marker, target_owner)
    transaction = {
        "command": command, "previous_snapshot": previous_snapshot, "target_snapshot": target_snapshot,
    }
    if not previous_snapshot:
        transaction["initial_owner"] = owner
        transaction["initial_mode"] = stat.S_IMODE(state.stat().st_mode)
    atomic_json(state / "transaction.pending", transaction)
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
    prune_snapshots(state, json.loads((state / "owner.json").read_text()))
    durable_unlink(state / "owner.json.pending")
    durable_unlink(state / "transaction.pending")


def maintenance_snapshot(state, command):
    if command == "recover":
        transaction = json.loads((state / "transaction.pending").read_text())
        reference = transaction.get("previous_snapshot")
        if not reference:
            sys.exit("failed initial up has no previous snapshot to restore")
    else:
        owner = json.loads((state / "owner.json").read_text())
        reference = owner["snapshot_history"][-2]
    read_snapshot_manifest(state, reference)
    return reference


def image_version(state, command):
    source, _, _ = read_snapshot_manifest(state, maintenance_snapshot(state, command))
    owner = json.loads((source / "owner.json").read_text())
    print(owner["settings"]["DEMO_VERSION"])


def router_admin_settings(state, command):
    reference = maintenance_snapshot(state, command)
    values = snapshot_runtime_values(state, reference)
    source, _, _ = read_snapshot_manifest(state, reference)
    token = json.loads((source / "owner.json").read_text())["token"]
    port = values.get("RAMFLUX_ROUTER_ADMIN_PORT", "59488")
    admin = values.get("RAMFLUX_FEDERATION_ADMIN_LOOPBACK_PORT", "")
    voice = values.get("RAMFLUX_RELAY_VOICE_UDP_PORT", "").rsplit(":", 1)[-1]
    print(values.get("RAMFLUX_ROUTER_ADMIN_ENABLED", "0"), port or "-", admin or "-", voice or "-", token)


def initial_recovery_owner(state):
    transaction = json.loads((state / "transaction.pending").read_text())
    if transaction.get("previous_snapshot"):
        return None
    owner = transaction.get("initial_owner")
    if owner is None:
        # Initial transactions made by older tooling retain the pending owner.
        owner = json.loads((state / "owner.json.pending").read_text())
    if owner["directory"] != str(state) or any(
            os.environ.get(key) != value for key, value in owner["settings"].items()
            if key != "DEMO_VERSION"):
        sys.exit("demo settings changed during recovery: restore every original setting")
    return owner


def finish_initial_recovery(state):
    owner = initial_recovery_owner(state)
    if owner is None:
        sys.exit("initial recovery requires a failed first up")
    marker = state / "transaction.pending"
    transaction = json.loads(marker.read_text())
    if "initial_owner" not in transaction:
        # Preserve recovery authority if cleanup is interrupted after deleting the pending owner.
        transaction["initial_owner"] = owner
        atomic_json(marker, transaction)
    # A first up only accepts an empty directory. Keep the marker until all its
    # generated files (including partial snapshots and temporary files) are gone.
    for path in state.iterdir():
        if path == marker:
            continue
        if path.is_dir() and not path.is_symlink():
            shutil.rmtree(path)
        else:
            path.unlink()
        fsync_directory(state)
    state.chmod(transaction.get("initial_mode", 0o700))
    durable_unlink(marker)


def recover(state):
    transaction = json.loads((state / "transaction.pending").read_text())
    previous = transaction.get("previous_snapshot")
    if not previous:
        sys.exit("failed initial up has no previous snapshot to restore")
    restore_snapshot(state, previous)
    durable_unlink(state / "owner.json.pending")
    owner = json.loads((state / "owner.json").read_text())
    changed = [key for key, value in owner["settings"].items()
               if key != "DEMO_VERSION" and os.environ.get(key) != value]
    if changed:
        sys.exit("demo settings changed during recovery: restore every original setting")
    print(owner["settings"]["DEMO_VERSION"])


def normalize_product_sha(raw):
    """First 12 characters of a lowercase hex commit, or None when it is not one."""
    value = raw.strip()
    if len(value) < 12 or any(character not in "0123456789abcdef" for character in value):
        return None
    return value[:12]


def workspace_product_version(cargo_toml):
    """Numeric X.Y.Z from [workspace.package], the version compiled into every binary."""
    section = ""
    version = None
    try:
        lines = Path(cargo_toml).read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as error:
        sys.exit(f"cannot read workspace package version: {error}")
    for raw in lines:
        line = raw.split("#", 1)[0].strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip()
            continue
        if section != "workspace.package":
            continue
        match = re.fullmatch(r'version\s*=\s*"([^"]*)"', line)
        if match:
            version = match.group(1)
    if version is None or re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version) is None:
        sys.exit("workspace package version is not numeric X.Y.Z")
    return version


def product_sha(repo):
    """Build commit the same way the binaries do: override, then git, else unknown."""
    override = os.environ.get("RAMFLUX_GIT_SHA", "")
    if override.strip():
        sha = normalize_product_sha(override)
        if sha is None:
            sys.exit("RAMFLUX_GIT_SHA must be lowercase hexadecimal of at least 12 characters")
        return sha
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "HEAD"],
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    if result.returncode != 0:
        return "unknown"
    return normalize_product_sha(result.stdout) or "unknown"


def product_identity(repo):
    """Env lines for the product version and commit, distinct from the image tag."""
    version = workspace_product_version(Path(repo) / "Cargo.toml")
    sha = product_sha(repo)
    print(f"RAMFLUX_EXPECTED_PRODUCT_VERSION={version}")
    print(f"RAMFLUX_EXPECTED_PRODUCT_SHA={sha}")


def set_node_id(state, node_id):
    for config in sorted((state / "config").glob("*.toml")):
        content = config.read_text().replace(
            'node_id = "localhost"', f'node_id = "{node_id}"'
        ).encode()
        atomic_bytes(config, content, mode=0o644)


def main():
    if len(sys.argv) < 4:
        sys.exit("usage: demo-node-config.py REPO STATE ACTION [COMMAND]")
    repo, state = map(Path, sys.argv[1:3])
    action = sys.argv[3]
    try:
        if action == "public-origin":
            print(public_origin())
        elif action == "federation-bind":
            public_origin()
            print(federation_bind())
        elif action == "client-runtime":
            print(client_runtime(), end="")
        elif action == "check-pending":
            check_pending(state)
        elif action == "validate":
            owner = prepare(repo, state, sys.argv[4], validate_only=True)
            print(owner["token"])
        elif action == "initial-recovery-owner":
            owner = initial_recovery_owner(state)
            if owner is not None:
                print(owner["token"])
        elif action == "finish-initial-recovery":
            finish_initial_recovery(state)
        elif action == "image-version":
            image_version(state, sys.argv[4])
        elif action == "router-admin-settings":
            router_admin_settings(state, sys.argv[4])
        elif action == "prepare":
            prepare(repo, state, sys.argv[4])
        elif action == "commit":
            commit(state, sys.argv[4])
        elif action == "recover":
            recover(state)
        elif action == "finish-recovery":
            prune_snapshots(state, json.loads((state / "owner.json").read_text()))
            durable_unlink(state / "owner.json.pending")
            durable_unlink(state / "transaction.pending")
        elif action == "set-node-id":
            set_node_id(state, sys.argv[4])
        elif action == "append-custody-runtime":
            append_custody_runtime(state, Path(sys.argv[4]))
        elif action == "custody-status":
            print(custody_status(state))
        elif action == "product-identity":
            product_identity(repo)
        else:
            sys.exit("invalid demo configuration action")
    except SnapshotError as error:
        if action == "recover" or (action in ("image-version", "router-admin-settings") and sys.argv[4] == "recover"):
            sys.exit(f"cannot recover last-good snapshot: {error}; {MANUAL_RECOVERY}")
        sys.exit(str(error))


if __name__ == "__main__":
    main()
