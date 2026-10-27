#!/usr/bin/env python3
"""Reject unsafe Compose configuration before a provider can start containers."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys

MAPPING = json.loads((Path(__file__).resolve().parents[1] / "compose-inputs.json").read_text())
PUBLIC_SECRET = "ramflux-local-admin-token"
DOTENV_EXPRESSION = re.compile(r"\$\$|\$([A-Za-z_][A-Za-z0-9_]*)|\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:-|-|:\?|\?|:\+|\+)([^{}]*))?\}")
RENDERED_EXPRESSION = re.compile(r"\$\{[^{}]*\}")
ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
REQUIRED_SECURITY_INPUTS = {
    "RAMFLUX_FEDERATION_ADMIN_TOKEN",
    "RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE",
    "RAMFLUX_FEDERATION_PROVIDER_KEYRING_FILE",
    "RAMFLUX_FEDERATION_PROVIDER_OFFLINE_ROOT_PUBLIC_KEY",
    "RAMFLUX_FEDERATION_TRUST_ISSUER_NODE_ID",
    "RAMFLUX_FEDERATION_TRUST_SNAPSHOT_FILE",
    "RAMFLUX_FEDERATION_TRUST_ENDPOINT",
    "RAMFLUX_GATEWAY_V3_ISSUER_CERT_FILE",
    "RAMFLUX_GATEWAY_V3_ISSUER_SEED",
    "RAMFLUX_NODE_SERVICE_SIGNING_SEED_B64URL",
    "RAMFLUX_NOTIFY_ROUTE_KEY_FILE",
    "RAMFLUX_RELAY_TRUST_SNAPSHOT_CACHE_FILE",
    "RAMFLUX_ROUTER_ADMIN_TOKEN",
    "RAMFLUX_ROUTER_FEDERATION_FORWARD_TOKEN",
}


class InputError(Exception):
    """Contains only a setting name, never an input value."""


def expand(value, values, key):
    def replace(match):
        if match.group() == "$$":
            return "$"
        name = match[1] or match[2]
        current = values.get(name)
        operator = match[3]
        absent = current is None or (operator and operator.startswith(":") and not current)
        if operator in (":?", "?") and absent:
            raise InputError(key)
        if operator in (":-", "-"):
            return match[4] if absent else current
        if operator in (":+", "+"):
            return "" if absent else match[4]
        return current or ""
    result = DOTENV_EXPRESSION.sub(replace, value)
    if "${" in result:
        raise InputError(key)
    return result


def read_env(path, earlier, process):
    """Read Compose-style dotenv input for best-effort legacy-name detection."""
    try:
        values = dict(earlier)
        lines = iter(path.read_text().splitlines())
        for line in lines:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.fullmatch(r"(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)", line)
            if not match:
                raise InputError("ENV_FILE")
            key, value = match.groups()
            quoted = value.startswith(("'", '"'))
            single = value.startswith("'")
            if quoted:
                quote = value[0]
                value = value[1:]
                while True:
                    closing = None
                    escaped = False
                    for index, character in enumerate(value):
                        if character == quote and not escaped:
                            closing = index
                            break
                        escaped = not escaped if character == "\\" else False
                    if closing is not None:
                        tail = value[closing + 1:].strip()
                        if tail and not tail.startswith("#"):
                            raise InputError(key)
                        value = value[:closing]
                        break
                    try:
                        value += "\n" + next(lines)
                    except StopIteration:
                        raise InputError(key) from None
                if single:
                    value = value.replace("\\'", "'")
                else:
                    escapes = {'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r',
                               't': '\t', 'v': '\v', '\\': '\\', '"': '"'}
                    value = re.sub(r'\\([abfnrtv\\"])', lambda match: escapes[match[1]], value)
            else:
                value = re.split(r"\s+#", value, maxsplit=1)[0].rstrip()
            values[key] = value if single else expand(value, {**values, **process}, key)
        return values
    except (OSError, UnicodeError):
        raise InputError("ENV_FILE") from None


def absolute(path, base):
    return path if path.is_absolute() else base / path


def path_list(value, separator, key):
    paths = value.split(separator)
    if not value or not separator or any(not path for path in paths):
        raise InputError(key)
    return [Path(path) for path in paths]


def first_compose_file(files, process, cwd):
    if files:
        return next((path for path in files if str(path) != "-"), None)
    value = process.get("COMPOSE_FILE")
    if value is not None:
        separator = process.get("COMPOSE_PATH_SEPARATOR", os.pathsep)
        return path_list(value, separator, "COMPOSE_FILE")[0]
    for directory in (cwd, *cwd.parents):
        for name in ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"):
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def project_directory(files, explicit, process, cwd):
    if explicit is not None:
        return absolute(explicit, cwd)
    first = first_compose_file(files, process, cwd)
    if first is None:
        return cwd
    if "://" in str(first) or str(first).startswith("git@"):
        raise InputError("COMPOSE_FILE")
    return absolute(first, cwd).parent


def default_env_files(files, explicit_project, process, cwd):
    configured = process.get("COMPOSE_ENV_FILES")
    if configured is not None:
        return [absolute(path, cwd) for path in path_list(configured, ",", "COMPOSE_ENV_FILES")]
    disabled = process.get("COMPOSE_DISABLE_ENV_FILE", "0").lower()
    if disabled in ("1", "true"):
        return []
    if disabled not in ("0", "false"):
        raise InputError("COMPOSE_DISABLE_ENV_FILE")
    primary = project_directory(files, explicit_project, process, cwd) / ".env"
    return [primary] if primary.is_file() else []


def legacy_env_files(arguments):
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--env-file", action="append", type=Path, default=[])
    parser.add_argument("-f", "--file", action="append", type=Path, default=[])
    parser.add_argument("--project-directory", type=Path)
    options, _unknown = parser.parse_known_args(arguments)
    cwd = Path.cwd()
    if options.env_file:
        return [absolute(path, cwd) for path in options.env_file]
    return default_env_files(options.file, options.project_directory, os.environ, cwd)


def validate_legacy_inputs(arguments):
    """Best-effort migration check; rendered provider output is authoritative."""
    values = {}
    for path in legacy_env_files(arguments):
        values = read_env(path, values, os.environ)
    values.update(os.environ)
    invalid = set()
    for old, new in MAPPING.items():
        if old in values and (new not in values or values[old] != values[new]):
            invalid.update((old, new))
    return invalid


def provider_command(provider):
    if provider == "docker":
        return ["docker", "compose"]
    if provider == "podman":
        return ["podman", "compose"]
    return ["podman-compose"]


def render_config(provider, arguments):
    command = [*provider_command(provider), *arguments, "config"]
    if provider == "docker":
        command.extend(["--format", "json"])
    try:
        rendered = subprocess.run(command, text=True, capture_output=True, check=False)
    except OSError:
        raise InputError("COMPOSE_PROVIDER") from None
    if rendered.returncode != 0:
        raise InputError("CONFIG_RENDER")
    return rendered.stdout


def docker_environments(rendered):
    try:
        services = json.loads(rendered).get("services", {})
    except (AttributeError, json.JSONDecodeError):
        raise InputError("CONFIG_RENDER") from None
    if not isinstance(services, dict):
        raise InputError("CONFIG_RENDER")
    environments = []
    for service in services.values():
        if not isinstance(service, dict):
            raise InputError("CONFIG_RENDER")
        environment = service.get("environment", {})
        if isinstance(environment, dict):
            environments.append({str(key): "" if value is None else str(value)
                                 for key, value in environment.items()})
        elif isinstance(environment, list):
            environments.append(environment_list(environment))
        else:
            raise InputError("CONFIG_RENDER")
    return environments


def environment_list(items):
    environment = {}
    for item in items:
        if not isinstance(item, str) or "=" not in item:
            raise InputError("CONFIG_RENDER")
        key, value = item.split("=", 1)
        if not ENV_NAME.fullmatch(key):
            raise InputError("CONFIG_RENDER")
        environment[key] = value
    return environment


def yaml_scalar(value):
    value = value.strip()
    if not value or value in {"null", "Null", "NULL", "~"}:
        return ""
    if value.startswith('"'):
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError:
            raise InputError("CONFIG_RENDER") from None
        if not isinstance(parsed, str):
            raise InputError("CONFIG_RENDER")
        return parsed
    if value.startswith("'"):
        if len(value) < 2 or not value.endswith("'"):
            raise InputError("CONFIG_RENDER")
        return value[1:-1].replace("''", "'")
    return value


def podman_environments(rendered):
    """Safely scan only environment mappings/lists from podman-compose YAML."""
    if not any(re.fullmatch(r"services:\s*", line.strip()) for line in rendered.splitlines()):
        raise InputError("CONFIG_RENDER")
    environments = []
    current = None
    environment_indent = None
    for line in rendered.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip())
        if environment_indent is not None and indent <= environment_indent:
            environments.append(current)
            current = None
            environment_indent = None
        if re.fullmatch(r"environment:\s*", stripped):
            current = {}
            environment_indent = indent
            continue
        if stripped.startswith("environment:"):
            raise InputError("CONFIG_RENDER")
        if current is None:
            continue
        mapping = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_]*):(?:\s*(.*))?", stripped)
        listed = re.fullmatch(r"-\s+([A-Za-z_][A-Za-z0-9_]*)=(.*)", stripped)
        if mapping:
            current[mapping[1]] = yaml_scalar(mapping[2] or "")
        elif listed:
            current[listed[1]] = yaml_scalar(listed[2])
        else:
            raise InputError("CONFIG_RENDER")
    if current is not None:
        environments.append(current)
    return environments


def validate_rendered(environments):
    invalid = set()
    for environment in environments:
        for key, value in environment.items():
            if value.strip() == PUBLIC_SECRET or RENDERED_EXPRESSION.search(value):
                invalid.add(key)
            if key in REQUIRED_SECURITY_INPUTS and not value.strip():
                invalid.add(key)
    return invalid


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--provider", choices=("docker", "podman", "podman-compose"), required=True)
    options, compose_arguments = parser.parse_known_args(argv)
    try:
        invalid = validate_legacy_inputs(compose_arguments)
        if not invalid:
            rendered = render_config(options.provider, compose_arguments)
            environments = (docker_environments(rendered) if options.provider == "docker"
                            else podman_environments(rendered))
            invalid.update(validate_rendered(environments))
    except InputError as error:
        invalid = {str(error)}
    if invalid:
        print("Compose preflight refused settings: " + ", ".join(sorted(invalid)), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
