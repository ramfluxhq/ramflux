#!/usr/bin/env python3
"""Reject unsafe Compose input migrations before invoking any Compose provider."""
import argparse
import json
import os
from pathlib import Path
import re
import sys

MAPPING = json.loads((Path(__file__).resolve().parents[1] / "compose-inputs.json").read_text())
PUBLIC_SECRET = "ramflux-local-admin-token"
EXPRESSION = re.compile(r"\$\$|\$([A-Za-z_][A-Za-z0-9_]*)|\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:-|-|:\?|\?|:\+|\+)([^{}]*))?\}")


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
    result = EXPRESSION.sub(replace, value)
    if "${" in result:
        raise InputError(key)
    return result


def read_env(path, earlier, process):
    """Compose dotenv quoting/export/comments, ordered files, process-first interpolation."""
    try:
        lines = iter(path.read_text().splitlines())
        values = dict(earlier)
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
                # Quoted dotenv values may span lines. Closing quotes may be escaped.
                while True:
                    closing = None
                    escaped = False
                    for i, char in enumerate(value):
                        if char == quote and not escaped:
                            closing = i
                            break
                        escaped = not escaped if char == '\\' else False
                    if closing is not None:
                        tail = value[closing + 1:].strip()
                        if tail and not tail.startswith('#'):
                            raise InputError(key)
                        value = value[:closing]
                        break
                    try:
                        value += '\n' + next(lines)
                    except StopIteration:
                        raise InputError(key) from None
                if single:
                    value = value.replace("\\'", "'")
                else:
                    escapes = {'a': '\a', 'b': '\b', 'f': '\f', 'n': '\n', 'r': '\r',
                               't': '\t', 'v': '\v', '\\': '\\', '"': '"'}
                    value = re.sub(r'\\([abfnrtv\\"])', lambda m: escapes[m[1]], value)
            else:
                value = re.split(r"\s+#", value, maxsplit=1)[0].rstrip()
            values[key] = value if single else expand(value, {**values, **process}, key)
        return values
    except (OSError, UnicodeError):
        raise InputError("ENV_FILE") from None


def validate(values):
    invalid = set()
    for old, new in MAPPING.items():
        if old in values and (new not in values or values[old] != values[new]):
            invalid.update((old, new))
    for key, value in values.items():
        if key.startswith(("RAMFLUX_", "RF_COMPOSE_")):
            if value.strip() == PUBLIC_SECRET or "${" in value:
                invalid.add(key)
    return sorted(invalid)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--env-file', action='append', type=Path, default=[])
    args = parser.parse_args(argv)
    files = args.env_file or ([Path('.env')] if Path('.env').is_file() else [])
    try:
        values = {}
        for path in files:
            values = read_env(path, values, os.environ)
        invalid = validate({**values, **os.environ})
    except InputError as error:
        invalid = [str(error)]
    if invalid:
        print('Compose input migration required: ' + ', '.join(invalid), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
