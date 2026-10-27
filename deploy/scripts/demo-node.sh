#!/usr/bin/env sh
# Persistent, project-scoped production demo deployment.
set -eu
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }
usage() { fail 'usage: demo-node.sh {up|upgrade|rollback|recover|down|status|logs} ENV_FILE [--purge|--remote] [--voice-udp-port PORT]'; }
[ "$#" -ge 2 ] || usage
command=$1
env_file=$2
shift 2
flag=
voice_cli=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --purge|--remote) [ -z "$flag" ] || usage; flag=$1; shift ;;
    --voice-udp-port)
      [ "$#" -ge 2 ] && [ -z "$voice_cli" ] && [ -n "$2" ] || usage
      voice_cli=$2; shift 2 ;;
    *) usage ;;
  esac
done
case "$command:$flag" in up:|upgrade:|rollback:|recover:|down:|down:--purge|status:|status:--remote|logs:) ;; *) usage ;; esac
case "$env_file" in /*) ;; *) env_file="$PWD/$env_file" ;; esac
[ -f "$env_file" ] || fail 'an existing operator env file is required'
# The operator file is trusted shell configuration, never downloaded or committed.
set -a
# shellcheck disable=SC1090
. "$env_file"
set +a
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH='' cd -- "$script_dir/../.." && pwd)
: "${DEMO_DATA_DIR:?absolute private data directory required}"
case "$command" in
  recover|rollback) ;;
  *) python3 "$script_dir/demo-node-config.py" "$repo" "$DEMO_DATA_DIR" check-pending ;;
esac
: "${DEMO_HOST:?advertised DNS name or IPv4 address required}"
: "${DEMO_PROJECT:?dedicated compose project required}"
: "${DEMO_DATA_DIR:?absolute private data directory required}"
: "${DEMO_TOOL:?absolute path to demo-node-tool required}"
DEMO_NODE_ID=${DEMO_NODE_ID:-demo.invalid}
DEMO_GATEWAY_PORT=${DEMO_GATEWAY_PORT:-59443}
DEMO_RELAY_PORT=${DEMO_RELAY_PORT:-59447}
DEMO_HTTP_PORT=${DEMO_HTTP_PORT:-59482}
DEMO_TURN_PORT=${DEMO_TURN_PORT:-59478}
DEMO_MESH_PORT=${DEMO_MESH_PORT:-59453}
DEMO_BIND_ADDR=${DEMO_BIND_ADDR:-0.0.0.0}
DEMO_VERSION=${DEMO_VERSION:-$DEMO_PROJECT}
DEMO_PREBUILT_IMAGES=${DEMO_PREBUILT_IMAGES:-0}
DEMO_HEALTH_TIMEOUT_SECONDS=${DEMO_HEALTH_TIMEOUT_SECONDS:-180}
DEMO_HEALTH_POLL_SECONDS=${DEMO_HEALTH_POLL_SECONDS:-2}
for seconds in "$DEMO_HEALTH_TIMEOUT_SECONDS" "$DEMO_HEALTH_POLL_SECONDS"; do
  case "$seconds" in ''|0*|*[!0-9]*) fail 'health timeout and poll interval must be positive integers' ;; esac
  [ "$seconds" -ge 1 ] && [ "$seconds" -le 3600 ] || fail 'health timeout and poll interval must be 1..3600 seconds'
done
export DEMO_NODE_ID DEMO_GATEWAY_PORT DEMO_RELAY_PORT DEMO_HTTP_PORT DEMO_TURN_PORT
export DEMO_MESH_PORT DEMO_BIND_ADDR DEMO_VERSION
DEMO_ADMIN_LOOPBACK_PORT=${DEMO_ADMIN_LOOPBACK_PORT:-}
export DEMO_ADMIN_LOOPBACK_PORT
case "$DEMO_HOST" in ''|*[!a-zA-Z0-9.-]*|-*) fail 'DEMO_HOST must be a DNS name or IPv4 address' ;; esac
case "$DEMO_NODE_ID" in ''|*[!a-zA-Z0-9.-]*|-*) fail 'invalid DEMO_NODE_ID' ;; esac
case "$DEMO_PROJECT" in [a-z0-9]*) ;; *) fail 'invalid DEMO_PROJECT' ;; esac
case "$DEMO_PROJECT" in *[!a-z0-9_-]*) fail 'invalid DEMO_PROJECT' ;; esac
case "$DEMO_VERSION" in ''|*[!a-zA-Z0-9_.-]*|.*|-*) fail 'invalid DEMO_VERSION image tag' ;; esac
case "$DEMO_PREBUILT_IMAGES" in 0|1) ;; *) fail 'DEMO_PREBUILT_IMAGES must be 0 or 1' ;; esac
case "$DEMO_BIND_ADDR" in ''|*[!0-9.]*) fail 'DEMO_BIND_ADDR must be an IPv4 bind address' ;; esac
for port in "$DEMO_GATEWAY_PORT" "$DEMO_RELAY_PORT" "$DEMO_HTTP_PORT" "$DEMO_TURN_PORT" "$DEMO_MESH_PORT"; do
  case "$port" in ''|*[!0-9]*) fail 'ports must be integers' ;; esac
  [ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || fail 'ports must be between 1024 and 65535'
done
if [ -n "$DEMO_ADMIN_LOOPBACK_PORT" ]; then
  case "$DEMO_ADMIN_LOOPBACK_PORT" in 0*|*[!0-9]*) fail 'admin loopback port must be an integer' ;; esac
  [ "$DEMO_ADMIN_LOOPBACK_PORT" -ge 1024 ] && [ "$DEMO_ADMIN_LOOPBACK_PORT" -le 65535 ] || fail 'admin loopback port must be 1024..65535'
  for tcp_port in "$DEMO_GATEWAY_PORT" "$DEMO_RELAY_PORT" "$DEMO_HTTP_PORT" "$DEMO_TURN_PORT" "$DEMO_MESH_PORT"; do
    [ "$DEMO_ADMIN_LOOPBACK_PORT" -ne "$tcp_port" ] || fail 'admin loopback port conflicts with another demo port'
  done
fi
RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS=${RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS-64}
case "$RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS" in ''|0*|*[!0-9]*) fail 'public max connections must be an integer in 1..4096' ;; esac
[ "${#RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS}" -le 4 ] && [ "$RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS" -le 4096 ] || fail 'public max connections must be 1..4096'
# Validate before creating state, invoking tools, or asking the engine to recreate services.
validate_federation_limit() {
  limit_key=$1
  limit_value=$2
  limit_max=$3
  case "$limit_value" in ''|0*|*[!0-9]*) fail "$limit_key must be an integer in 1..$limit_max" ;; esac
  [ "${#limit_value}" -le "${#limit_max}" ] && [ "$limit_value" -le "$limit_max" ] || fail "$limit_key must be 1..$limit_max"
}
RAMFLUX_FEDERATION_ADMIN_MAX_CONNECTIONS=${RAMFLUX_FEDERATION_ADMIN_MAX_CONNECTIONS-64}
validate_federation_limit RAMFLUX_FEDERATION_ADMIN_MAX_CONNECTIONS "$RAMFLUX_FEDERATION_ADMIN_MAX_CONNECTIONS" 4096
RAMFLUX_FEDERATION_PUBLIC_MAX_HEADER_BYTES=${RAMFLUX_FEDERATION_PUBLIC_MAX_HEADER_BYTES-8192}
validate_federation_limit RAMFLUX_FEDERATION_PUBLIC_MAX_HEADER_BYTES "$RAMFLUX_FEDERATION_PUBLIC_MAX_HEADER_BYTES" 65536
RAMFLUX_FEDERATION_PUBLIC_MAX_BODY_BYTES=${RAMFLUX_FEDERATION_PUBLIC_MAX_BODY_BYTES-65536}
validate_federation_limit RAMFLUX_FEDERATION_PUBLIC_MAX_BODY_BYTES "$RAMFLUX_FEDERATION_PUBLIC_MAX_BODY_BYTES" 67108864
RAMFLUX_FEDERATION_PUBLIC_REQUEST_TIMEOUT_SECONDS=${RAMFLUX_FEDERATION_PUBLIC_REQUEST_TIMEOUT_SECONDS-10}
validate_federation_limit RAMFLUX_FEDERATION_PUBLIC_REQUEST_TIMEOUT_SECONDS "$RAMFLUX_FEDERATION_PUBLIC_REQUEST_TIMEOUT_SECONDS" 3600
RAMFLUX_FEDERATION_ADMIN_MAX_HEADER_BYTES=${RAMFLUX_FEDERATION_ADMIN_MAX_HEADER_BYTES-65536}
validate_federation_limit RAMFLUX_FEDERATION_ADMIN_MAX_HEADER_BYTES "$RAMFLUX_FEDERATION_ADMIN_MAX_HEADER_BYTES" 65536
RAMFLUX_FEDERATION_ADMIN_MAX_BODY_BYTES=${RAMFLUX_FEDERATION_ADMIN_MAX_BODY_BYTES-1048576}
validate_federation_limit RAMFLUX_FEDERATION_ADMIN_MAX_BODY_BYTES "$RAMFLUX_FEDERATION_ADMIN_MAX_BODY_BYTES" 67108864
RAMFLUX_FEDERATION_ADMIN_REQUEST_TIMEOUT_SECONDS=${RAMFLUX_FEDERATION_ADMIN_REQUEST_TIMEOUT_SECONDS-30}
validate_federation_limit RAMFLUX_FEDERATION_ADMIN_REQUEST_TIMEOUT_SECONDS "$RAMFLUX_FEDERATION_ADMIN_REQUEST_TIMEOUT_SECONDS" 3600
source_limits_operator_set=0
if [ "${RAMFLUX_FEDERATION_PER_SOURCE_LIMITS+x}" = x ]; then
  case "$RAMFLUX_FEDERATION_PER_SOURCE_LIMITS" in on|off) ;; *) fail 'per-source federation limits must be on or off' ;; esac
  source_limits_operator_set=1
fi
RAMFLUX_DEMO_VOICE_UDP_PORT=${voice_cli:-${RAMFLUX_DEMO_VOICE_UDP_PORT:-}}
if [ -n "$RAMFLUX_DEMO_VOICE_UDP_PORT" ]; then
  case "$RAMFLUX_DEMO_VOICE_UDP_PORT" in
    0*|*[!0-9]*) fail 'voice UDP port must be an integer between 1024 and 65535' ;;
  esac
  [ "$RAMFLUX_DEMO_VOICE_UDP_PORT" -ge 1024 ] && [ "$RAMFLUX_DEMO_VOICE_UDP_PORT" -le 65535 ] || fail 'voice UDP port must be between 1024 and 65535'
  for udp_port in "$DEMO_GATEWAY_PORT" "$DEMO_RELAY_PORT" "$DEMO_TURN_PORT" "$DEMO_MESH_PORT"; do
    [ "$RAMFLUX_DEMO_VOICE_UDP_PORT" -ne "$udp_port" ] || fail 'voice UDP port conflicts with another demo UDP port'
  done
fi
export RAMFLUX_DEMO_VOICE_UDP_PORT
case "$DEMO_DATA_DIR" in /*) ;; *) fail 'DEMO_DATA_DIR must be absolute' ;; esac
case "$DEMO_TOOL" in /*) ;; *) fail 'DEMO_TOOL must be absolute' ;; esac
[ -x "$DEMO_TOOL" ] || fail 'DEMO_TOOL must be an executable demo-node-tool'
origin="http://$DEMO_HOST:$DEMO_HTTP_PORT"
if [ "$flag" = --remote ]; then
  : "${DEMO_EXPECTED_NODE_PUBLIC_KEY:?copy the public pin from the QA identity.env over a trusted channel}"
  exec "$DEMO_TOOL" verify "$origin" "$DEMO_EXPECTED_NODE_PUBLIC_KEY"
fi
# Canonicalize before checking ownership or allowing recursive deletion.
case "$command" in
  up|upgrade)
    # Partial custody inputs must not even create an initial data directory.
    python3 "$script_dir/demo-node-config.py" "$repo" "$DEMO_DATA_DIR" custody-status >/dev/null
    ;;
esac
case "$command" in up) mkdir -p "$DEMO_DATA_DIR" ;; esac
[ -d "$DEMO_DATA_DIR" ] || fail 'demo data directory does not exist'
state=$(CDPATH='' cd -- "$DEMO_DATA_DIR" && pwd -P)
[ "$state" != / ] && [ "$state" != "$HOME" ] && [ "$state" != "$repo" ] || fail 'unsafe data directory'
mkdir "$state.lock" 2>/dev/null || fail 'demo operation already running (check adjacent .lock directory)'
cleanup() {
  result=$?
  trap - EXIT
  set +e
  [ -f "$state/transaction.pending" ] || rm -f -- "$state/owner.json.pending"
  rmdir "$state.lock" || printf 'warning: could not release demo operation lock %s.lock\n' "$state" >&2
  exit "$result"
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
# Recheck under the lock: another invocation may have published a marker since entry.
case "$command" in
  recover) ;;
  rollback) [ ! -f "$state/transaction.pending" ] || command=recover ;;
  *) python3 "$script_dir/demo-node-config.py" "$repo" "$state" check-pending ;;
esac
if [ "$command" = recover ]; then
  [ -f "$state/transaction.pending" ] || fail 'no unfinished demo transaction is available for recovery'
  initial_owner=$(python3 "$script_dir/demo-node-config.py" "$repo" "$state" initial-recovery-owner)
else
  owner=$(python3 "$script_dir/demo-node-config.py" "$repo" "$state" validate "$command")
fi
custody_state=
case "$command" in
  up|upgrade)
    custody_state=$(python3 "$script_dir/demo-node-config.py" "$repo" "$state" custody-status)
    if [ "$command" = up ] && [ "$custody_state" = absent ]; then
      printf 'WARNING: custody is not configured; accounts remain networking_pending\n' >&2
    fi
    ;;
esac
# Even a matching project name is insufficient: every existing resource must carry our owner token.
clean_env() {
  # Rootless Podman needs the user's runtime directory; ignore inherited compose/remote overrides.
  if [ -n "${XDG_RUNTIME_DIR:-}" ]; then
    env -i PATH="$PATH" HOME="$HOME" XDG_RUNTIME_DIR="$XDG_RUNTIME_DIR" "$@"
  else
    env -i PATH="$PATH" HOME="$HOME" "$@"
  fi
}
container_engine=
compose_provider=
docker_version=$(clean_env docker --version 2>/dev/null) || docker_version=
case "$docker_version" in
  *[Pp]odman*) ;;
  ?*)
    if clean_env docker compose version >/dev/null 2>&1; then
      container_engine=docker
      compose_provider=docker-v2
    fi
    ;;
esac
if [ -z "$compose_provider" ]; then
  if command -v podman >/dev/null 2>&1 && clean_env podman-compose version >/dev/null 2>&1; then
    container_engine=podman
    compose_provider=podman-compose
  elif clean_env podman compose version >/dev/null 2>&1; then
    container_engine=podman
    compose_provider=podman-wrapper
  elif [ -n "$docker_version" ] && clean_env docker compose version >/dev/null 2>&1; then
    container_engine=docker
    compose_provider=docker-wrapper
  else
    fail 'Docker Compose v2 or Podman with a compose provider is required'
  fi
fi
runtime() { clean_env "$container_engine" "$@"; }
check_prebuilt_images() {
  clean_env python3 "$script_dir/demo-image-check.py" "$container_engine" "${1:-$DEMO_VERSION}"
}
source_address_mode=$(runtime info --format json 2>/dev/null | python3 -c '
import json
import sys
data = json.load(sys.stdin)
host = data.get("host") or data.get("Host") or {}
security = host.get("security") or host.get("Security") or {}
remote = host.get("serviceIsRemote", host.get("ServiceIsRemote"))
rootless = security.get("rootless", security.get("Rootless"))
host_os = str(host.get("os") or host.get("Os") or "").lower()
if remote is True:
    print("machine")
elif rootless is True:
    print("rootless-bridge")
elif rootless is False and host_os == "linux":
    print("rootful-linux")
elif not host:
    options = [str(value).lower() for value in data.get("SecurityOptions", [])]
    operating_system = str(data.get("OperatingSystem", "")).lower()
    os_type = str(data.get("OSType", "")).lower()
    if any("rootless" in value for value in options):
        print("rootless-bridge")
    elif "desktop" in operating_system or "machine" in operating_system:
        print("machine")
    elif os_type == "linux":
        print("rootful-linux")
    else:
        print("unknown")
else:
    print("unknown")
') || source_address_mode=unknown
case "$source_address_mode" in
  rootful-linux) detected_source_limits=on ;;
  rootless-bridge|machine) detected_source_limits=off ;;
  *)
    source_address_mode=unknown
    detected_source_limits=off
    ;;
esac
if [ "$source_limits_operator_set" -eq 0 ]; then
  RAMFLUX_FEDERATION_PER_SOURCE_LIMITS=$detected_source_limits
  if [ "$detected_source_limits" = off ]; then
    printf 'warning: per-source federation limits disabled because %s port publishing may collapse client source addresses\n' "$source_address_mode" >&2
  fi
elif [ "$RAMFLUX_FEDERATION_PER_SOURCE_LIMITS" = on ] && [ "$detected_source_limits" = off ]; then
  printf 'warning: operator kept per-source federation limits on although %s port publishing may collapse client source addresses\n' "$source_address_mode" >&2
fi
check_resources() {
  for kind in container volume network; do
    case "$kind" in
      container) ids=$(runtime ps -aq --filter "label=com.docker.compose.project=$DEMO_PROJECT") ;;
      volume)
        ids=$(runtime volume ls -q --filter "label=com.docker.compose.project=$DEMO_PROJECT")
        # Include name collisions without compose labels: compose may otherwise adopt these volumes.
        all_names=$(runtime volume ls -q)
        for name in $all_names; do
          case "$name" in
            "${DEMO_PROJECT}_gateway-redb"|"${DEMO_PROJECT}_router-redb"|"${DEMO_PROJECT}_notify-redb"|"${DEMO_PROJECT}_federation-redb"|"${DEMO_PROJECT}_relay-redb"|"${DEMO_PROJECT}_signaling-redb"|"${DEMO_PROJECT}_retention-redb") ids="$ids $name" ;;
          esac
        done
        ;;
      network)
        ids=$(runtime network ls -q --filter "label=com.docker.compose.project=$DEMO_PROJECT")
        all_names=$(runtime network ls --format '{{.Name}}')
        for name in $all_names; do
          [ "$name" != "${DEMO_PROJECT}_default" ] || ids="$ids $name"
        done
        ;;
    esac
    for id in $ids; do
      case "$kind" in
        container) actual=$(runtime inspect --format '{{index .Config.Labels "org.ramflux.demo.owner"}}' "$id") ;;
        *) actual=$(runtime "$kind" inspect --format '{{index .Labels "org.ramflux.demo.owner"}}' "$id") ;;
      esac
      [ "$actual" = "$owner" ] || fail "refusing foreign $kind in project $DEMO_PROJECT"
    done
  done
}

# Initial setup may fail before any Compose input exists. Select only this
# project's labelled resources, verify their owner, and remove them directly.
if [ "$command" = recover ] && [ -n "$initial_owner" ]; then
  owner=$initial_owner
  check_resources
  containers=$(runtime ps -aq --filter "label=com.docker.compose.project=$DEMO_PROJECT")
  # Podman refuses a dependency until its dependent containers have been removed.
  # Retry only the already verified project IDs, and stop if no removal succeeds.
  while [ -n "$containers" ]; do
    remaining=
    progress=0
    removal_errors=
    for container in $containers; do
      if removal_error=$(runtime rm -f "$container" 2>&1); then
        progress=1
      else
        remaining="${remaining}${remaining:+ }$container"
        removal_errors="${removal_errors}${removal_errors:+
}$removal_error"
      fi
    done
    containers=$remaining
    [ -z "$containers" ] || [ "$progress" = 1 ] || fail "$removal_errors"
  done
  # First up cannot adopt existing volumes: these belong to the failed setup.
  volumes=$(runtime volume ls -q --filter "label=com.docker.compose.project=$DEMO_PROJECT")
  for volume in $volumes; do runtime volume rm "$volume" >/dev/null; done
  networks=$(runtime network ls -q --filter "label=com.docker.compose.project=$DEMO_PROJECT")
  for network in $networks; do runtime network rm "$network" >/dev/null; done
  python3 "$script_dir/demo-node-config.py" "$repo" "$state" finish-initial-recovery
  # The recovery command is literal operator guidance.
  # shellcheck disable=SC2016
  printf 'initial setup rolled back; run `up` again\n'
  exit 0
fi
printf 'compose provider: %s (runtime: %s)\n' "$compose_provider" "$container_engine"
compose() (
  cd "$state"
  set -- -f "$state/demo-override.json" "$@"
  if [ -n "$DEMO_ADMIN_LOOPBACK_PORT" ]; then
    set -- -f "$state/compose.admin.yml" "$@"
  fi
  if [ -n "$RAMFLUX_DEMO_VOICE_UDP_PORT" ]; then
    set -- -f "$state/compose.voice.yml" "$@"
  fi
  set -- --env-file "$state/runtime.env" -p "$DEMO_PROJECT" -f "$state/compose.yml" "$@"
  clean_env python3 "$script_dir/compose-preflight.py" --env-file "$state/runtime.env"
  case "$compose_provider" in
    docker-v2|docker-wrapper) clean_env docker compose "$@" ;;
    podman-compose) clean_env podman-compose "$@" ;;
    podman-wrapper) clean_env podman compose "$@" ;;
  esac
)

compose_up() {
  case "$1" in
    build) compose up -d --build ;;
    no-build) compose up -d --no-build ;;
    *) fail 'internal error: invalid compose build mode' ;;
  esac
}

# Do not use compose ps -q SERVICE: podman-compose 1.3.0 does not filter it by service.
# Return 1 for a service still starting; 2 for a terminal failure or invalid inspection.
inspect_services() {
  health_problem=
  for service in gateway router notify federation relay signaling retention; do
    service_ids=$(runtime ps -aq \
      --filter "label=com.docker.compose.project=$DEMO_PROJECT" \
      --filter "label=com.docker.compose.service=ramflux-$service") || {
        health_problem="cannot list ramflux-$service"; return 2;
      }
    if [ -z "$service_ids" ]; then
      health_problem="ramflux-$service is missing"; return 1
    fi
    case "$service_ids" in
      *[!a-zA-Z0-9_-]*)
        health_problem="multiple or invalid containers for ramflux-$service"; return 2 ;;
    esac
    service_state=$(runtime inspect "$service_ids" | python3 -c '
import json
import sys
item = json.load(sys.stdin)[0]
labels = (item.get("Config") or {}).get("Labels") or {}
if labels.get("org.ramflux.demo.owner") != sys.argv[1]:
    sys.exit("refusing foreign container during health inspection")
state = item["State"]
health = state.get("Health") or state.get("Healthcheck") or {}
if sys.argv[3] and state["Status"] == "running" and health.get("Status") == "healthy":
    environment = dict(value.split("=", 1) for value in (item.get("Config") or {}).get("Env", []))
    if sys.argv[2] == "gateway":
        expected = {"RAMFLUX_RELAY_VOICE_CONTROL_ENDPOINT": "ramflux-relay:17450"}
    elif sys.argv[2] == "relay":
        expected = {
            "RAMFLUX_RELAY_VOICE_UDP_ADDR": "0.0.0.0:17449",
            "RAMFLUX_RELAY_VOICE_CONTROL_ADDR": "0.0.0.0:17450",
            "RAMFLUX_RELAY_VOICE_PUBLIC_ENDPOINT": sys.argv[4],
        }
        ports = (item.get("NetworkSettings") or {}).get("Ports") or {}
        mappings = ports.get("17449/udp") or []
        if not any(str(row.get("HostPort")) == sys.argv[3]
                   and (row.get("HostIp") or "0.0.0.0") == sys.argv[5] for row in mappings):
            sys.exit("relay voice UDP mapping differs from the selected demo port/bind address")
    else:
        expected = {}
    if any(environment.get(key) != value for key, value in expected.items()):
        sys.exit("voice environment differs from the selected demo configuration; run up first")
print(state["Status"], health.get("Status", "missing"))
' "$owner" "$service" "$RAMFLUX_DEMO_VOICE_UDP_PORT" "$DEMO_HOST:$RAMFLUX_DEMO_VOICE_UDP_PORT" "$DEMO_BIND_ADDR") || { health_problem="cannot inspect ramflux-$service"; return 2; }
    case "$service_state" in
      'running healthy')
        if [ "$health_verbose" = 1 ]; then printf 'ramflux-%s: %s\n' "$service" "$service_state"; fi
        ;;
      'created '*|'configured '*|'restarting '*|'running starting')
        health_problem="ramflux-$service: $service_state"; return 1 ;;
      *) health_problem="ramflux-$service: $service_state"; return 2 ;;
    esac
  done
  if [ "$health_verbose" = 1 ] && [ -n "$RAMFLUX_DEMO_VOICE_UDP_PORT" ]; then
    printf 'voice UDP mapping: %s:%s (configuration check only)\n' "$DEMO_HOST" "$RAMFLUX_DEMO_VOICE_UDP_PORT"
  fi
}

wait_for_services() {
  health_verbose=0
  health_deadline=$(( $(date +%s) + DEMO_HEALTH_TIMEOUT_SECONDS ))
  while :; do
    if inspect_services; then
      printf 'all seven demo services are healthy\n'
      return 0
    else
      health_result=$?
    fi
    if [ "$health_result" -eq 2 ] || [ "$(date +%s)" -ge "$health_deadline" ]; then
      printf 'demo health wait failed: %s\n' "$health_problem" >&2
      compose ps >&2 || true
      compose logs --tail 50 >&2 || true
      return 1
    fi
    printf 'waiting for demo health: %s\n' "$health_problem"
    health_now=$(date +%s)
    health_delay=$DEMO_HEALTH_POLL_SECONDS
    health_remaining=$((health_deadline - health_now))
    [ "$health_delay" -le "$health_remaining" ] || health_delay=$health_remaining
    [ "$health_delay" -le 0 ] || sleep "$health_delay"
  done
}
verify_public_endpoints() {
  # shellcheck disable=SC1091
  . "$state/identity.env"
  "$DEMO_TOOL" verify "$origin" "$DEMO_EXPECTED_NODE_PUBLIC_KEY"
}
load_applied_overlays() {
  RAMFLUX_DEMO_VOICE_UDP_PORT=$(sed -n 's/^RAMFLUX_RELAY_VOICE_UDP_PORT=.*://p' "$state/runtime.env" | tail -n 1)
  DEMO_ADMIN_LOOPBACK_PORT=$(sed -n 's/^RAMFLUX_FEDERATION_ADMIN_LOOPBACK_PORT=//p' "$state/runtime.env" | tail -n 1)
  export RAMFLUX_DEMO_VOICE_UDP_PORT DEMO_ADMIN_LOOPBACK_PORT
}
# Inspect the intended images before prepare/recover can write any managed state.
case "$command" in
  rollback|recover)
    image_version=$(python3 "$script_dir/demo-node-config.py" "$repo" "$state" image-version "$command")
    check_prebuilt_images "$image_version"
    ;;
  up|upgrade)
    [ "$DEMO_PREBUILT_IMAGES" != 1 ] || check_prebuilt_images
    ;;
esac
if [ "$command" != recover ]; then
  # Refused resource adoption must leave every managed file and marker untouched.
  check_resources
fi
if [ "$command" = recover ]; then
  [ -f "$state/transaction.pending" ] || fail 'no unfinished demo transaction is available for recovery'
  DEMO_VERSION=$(python3 "$script_dir/demo-node-config.py" "$repo" "$state" recover)
  export DEMO_VERSION
elif [ "$command" = up ]; then
  python3 "$script_dir/demo-node-config.py" "$repo" "$state" prepare "$command"
else
  [ -f "$state/owner.json" ] || fail 'data directory is not owned by this demo tooling'
  python3 "$script_dir/demo-node-config.py" "$repo" "$state" prepare "$command"
fi
if [ "$command" = upgrade ] || [ "$command" = rollback ]; then
  version_marker="$state/owner.json.pending"
  [ "$command" != rollback ] || version_marker="$state/owner.json"
  DEMO_VERSION=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["settings"]["DEMO_VERSION"])' "$version_marker")
  export DEMO_VERSION
fi
owner=$(cat "$state/owner.token")
if [ "$command" = rollback ] || [ "$command" = recover ]; then
  load_applied_overlays
fi
check_resources
case "$command" in
  up|upgrade|rollback|recover)
    chmod 700 "$state"
    if [ "$command" != rollback ] && [ "$command" != recover ]; then
      RAMFLUX_DEPLOY_DIR="$state" sh "$script_dir/bootstrap-ca.sh"
      RAMFLUX_DEPLOY_DIR="$state" RAMFLUX_NODE_ID="$DEMO_NODE_ID" sh "$script_dir/issue-certs.sh"
      RAMFLUX_DEPLOY_DIR="$state" sh "$script_dir/provision-node.sh"
    # Service identities and certificate SPIFFE identities must use the same node id.
      python3 "$script_dir/demo-node-config.py" "$repo" "$state" set-node-id "$DEMO_NODE_ID"
      "$DEMO_TOOL" init "$state" "$DEMO_NODE_ID"
    # The signing seed has its own mount, shared only by federation and retention.
      legacy_seed="$state/certs/federation/node-signing.key"
      seed="$state/certs/node-identity/node-signing.key"
      if [ -e "$legacy_seed" ] && [ ! -e "$seed" ]; then
      mkdir -p "$state/certs/node-identity"
      mv "$legacy_seed" "$seed"
      elif [ -e "$legacy_seed" ]; then
      # Two different seeds: never guess which identity is real.
      cmp -s "$legacy_seed" "$seed" || fail "$legacy_seed and $seed differ; keep the seed matching the identity pin"
      rm -f "$legacy_seed"
      fi
      chmod 755 "$state/certs/node-identity"
    # Containers need to traverse their read-only mounts; the containing state directory stays private.
      chmod 755 "$state/certs" "$state/config" "$state/secrets" "$state/secrets/gateway-v3" "$state/secrets/federation"
      for service in gateway router notify federation relay signaling retention; do
        chmod 755 "$state/certs/$service"
      done
      chmod 644 "$state"/config/*.toml "$state"/secrets/gateway-v3/*.json "$state"/secrets/federation/*.json
    # Preserve daemon/helper inputs and supply the separate Compose interpolation names.
    # The keyring is read-only trust material; the relay owns its durable cache in relay-redb.
      runtime_pending="$state/.runtime.env.pending.$$"
      cat "$state/identity.env" > "$runtime_pending"
      cat >> "$runtime_pending" <<ENV
RAMFLUX_NOTIFY_ROUTE_KEY_FILE=/etc/ramflux/mesh/route.key
RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE=/etc/ramflux/node-identity/node-signing.key
RAMFLUX_SECRET_GID=$(id -g)
RAMFLUX_VERSION=$DEMO_VERSION
RAMFLUX_GATEWAY_V3_ISSUER_CERT_FILE=/etc/ramflux/gateway-v3/issuer-cert.json
RAMFLUX_RELAY_CLIENT_QUIC_ADDR=0.0.0.0:17447
RAMFLUX_FEDERATION_TRUST_ENDPOINT=ramflux-federation:7443
RAMFLUX_FEDERATION_PROVIDER_KEYRING_FILE=/etc/ramflux/federation/provider-keyring.json
RAMFLUX_RELAY_TRUST_SNAPSHOT_CACHE_FILE=/var/lib/ramflux/relay/trust-snapshot.json
RAMFLUX_RELAY_TRUST_SNAPSHOT_REFRESH_INTERVAL_SECONDS=30
RAMFLUX_FEDERATION_TRUST_ISSUER_NODE_ID=$DEMO_NODE_ID
RAMFLUX_FEDERATION_NODE_ID=$DEMO_NODE_ID
RAMFLUX_FEDERATION_PUBLIC_ENDPOINT=ramflux-federation:7443
RAMFLUX_FEDERATION_TRUST_SNAPSHOT_FILE=/etc/ramflux/federation/trust-snapshot.json
RAMFLUX_FEDERATION_FORCE_TCP_MESH=0
RAMFLUX_FEDERATION_DISABLE_TCP_FALLBACK=0
RAMFLUX_GATEWAY_TCP_PORT=$DEMO_BIND_ADDR:$DEMO_GATEWAY_PORT
RAMFLUX_GATEWAY_QUIC_PORT=$DEMO_BIND_ADDR:$DEMO_GATEWAY_PORT
RAMFLUX_RELAY_CLIENT_QUIC_PORT=$DEMO_BIND_ADDR:$DEMO_RELAY_PORT
RAMFLUX_FEDERATION_PUBLIC_MAX_HEADER_BYTES=$RAMFLUX_FEDERATION_PUBLIC_MAX_HEADER_BYTES
RAMFLUX_FEDERATION_PUBLIC_MAX_BODY_BYTES=$RAMFLUX_FEDERATION_PUBLIC_MAX_BODY_BYTES
RAMFLUX_FEDERATION_PUBLIC_REQUEST_TIMEOUT_SECONDS=$RAMFLUX_FEDERATION_PUBLIC_REQUEST_TIMEOUT_SECONDS
RAMFLUX_FEDERATION_ADMIN_MAX_HEADER_BYTES=$RAMFLUX_FEDERATION_ADMIN_MAX_HEADER_BYTES
RAMFLUX_FEDERATION_ADMIN_MAX_BODY_BYTES=$RAMFLUX_FEDERATION_ADMIN_MAX_BODY_BYTES
RAMFLUX_FEDERATION_ADMIN_REQUEST_TIMEOUT_SECONDS=$RAMFLUX_FEDERATION_ADMIN_REQUEST_TIMEOUT_SECONDS
RAMFLUX_FEDERATION_PUBLIC_PORT=$DEMO_BIND_ADDR:$DEMO_HTTP_PORT
RAMFLUX_FEDERATION_ADMIN_LOOPBACK_PORT=$DEMO_ADMIN_LOOPBACK_PORT
RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS=$RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS
RAMFLUX_FEDERATION_ADMIN_MAX_CONNECTIONS=$RAMFLUX_FEDERATION_ADMIN_MAX_CONNECTIONS
RAMFLUX_FEDERATION_PER_SOURCE_LIMITS=$RAMFLUX_FEDERATION_PER_SOURCE_LIMITS
RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS_PER_SOURCE=${RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS_PER_SOURCE:-8}
RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS_PER_PREFIX=${RAMFLUX_FEDERATION_PUBLIC_MAX_CONNECTIONS_PER_PREFIX:-16}
RAMFLUX_FEDERATION_PUBLIC_CONNECTION_RATE_PER_SECOND=${RAMFLUX_FEDERATION_PUBLIC_CONNECTION_RATE_PER_SECOND:-20}
RAMFLUX_FEDERATION_PUBLIC_CONNECTION_BURST=${RAMFLUX_FEDERATION_PUBLIC_CONNECTION_BURST:-40}
RAMFLUX_FEDERATION_PUBLIC_REQUEST_RATE_PER_SECOND=${RAMFLUX_FEDERATION_PUBLIC_REQUEST_RATE_PER_SECOND:-20}
RAMFLUX_FEDERATION_PUBLIC_REQUEST_BURST=${RAMFLUX_FEDERATION_PUBLIC_REQUEST_BURST:-40}
RAMFLUX_FEDERATION_PUBLIC_SOURCE_TABLE_CAPACITY=${RAMFLUX_FEDERATION_PUBLIC_SOURCE_TABLE_CAPACITY:-4096}
RAMFLUX_FEDERATION_PUBLIC_SOURCE_IDLE_SECONDS=${RAMFLUX_FEDERATION_PUBLIC_SOURCE_IDLE_SECONDS:-300}
RAMFLUX_FEDERATION_MESH_PORT=127.0.0.1:$DEMO_MESH_PORT
RAMFLUX_SIGNALING_TURN_UDP_PORT=$DEMO_BIND_ADDR:$DEMO_TURN_PORT
RAMFLUX_SIGNALING_TURN_TCP_PORT=$DEMO_BIND_ADDR:$DEMO_TURN_PORT
RAMFLUX_CLIENT_GATEWAY_QUIC_ADDR=$DEMO_HOST:$DEMO_GATEWAY_PORT
RAMFLUX_CLIENT_GATEWAY_TCP_ADDR=$DEMO_HOST:$DEMO_GATEWAY_PORT
RAMFLUX_CLIENT_GATEWAY_SERVER_NAME=ramflux-gateway
RAMFLUX_CLIENT_RELAY_QUIC_ADDR=$DEMO_HOST:$DEMO_RELAY_PORT
RAMFLUX_CLIENT_RELAY_SERVER_NAME=ramflux-relay
RAMFLUX_CLIENT_PREKEY_HTTP_URL=$origin
RAMFLUX_CLIENT_SIGNALING_TURN_ADDR=$DEMO_HOST:$DEMO_TURN_PORT
ENV
      if [ -n "$RAMFLUX_DEMO_VOICE_UDP_PORT" ]; then
        cat >> "$runtime_pending" <<ENV
RAMFLUX_RELAY_VOICE_UDP_ADDR=0.0.0.0:17449
RAMFLUX_RELAY_VOICE_CONTROL_ADDR=0.0.0.0:17450
RAMFLUX_RELAY_VOICE_PUBLIC_ENDPOINT=$DEMO_HOST:$RAMFLUX_DEMO_VOICE_UDP_PORT
RAMFLUX_RELAY_VOICE_UDP_PORT=$DEMO_BIND_ADDR:$RAMFLUX_DEMO_VOICE_UDP_PORT
RAMFLUX_RELAY_VOICE_CONTROL_ENDPOINT=ramflux-relay:17450
ENV
      fi
      python3 "$script_dir/demo-node-config.py" "$repo" "$state" append-custody-runtime "$runtime_pending"
      python3 - "$runtime_pending" "$state/runtime.env" <<'PY'
import os
from pathlib import Path
import sys

temporary = Path(sys.argv[1])
destination = Path(sys.argv[2])
with temporary.open("rb") as source:
    os.fsync(source.fileno())
temporary.chmod(0o600)
os.replace(temporary, destination)
directory = os.open(destination.parent, os.O_RDONLY)
try:
    os.fsync(directory)
finally:
    os.close(directory)
PY
      python3 "$script_dir/compose-env.py" "$state/runtime.env"
    fi
    if [ "$command" = rollback ] || [ "$command" = recover ] || [ "$DEMO_PREBUILT_IMAGES" = 1 ]; then
      compose_up no-build
    else
      sh "$script_dir/build-prod-images.sh"
      compose_up build
    fi
    if [ "$command" = up ] && [ "$custody_state" = record-changed ]; then
      printf 'custody record changed; restarting ramflux-router\n'
      compose restart ramflux-router
    fi
    wait_for_services
    verify_public_endpoints
    if [ "$command" = recover ]; then
      python3 "$script_dir/demo-node-config.py" "$repo" "$state" finish-recovery
    else
      python3 "$script_dir/demo-node-config.py" "$repo" "$state" commit "$command"
    fi
    printf 'demo URL: %s\n' "$origin"
    if [ "$command" = upgrade ]; then
      printf 'rollback command: %s/demo-node.sh rollback %s\n' "$script_dir" "$env_file"
    elif [ "$command" = rollback ]; then
      printf 'rolled back demo images to version %s\n' "$DEMO_VERSION"
    elif [ "$command" = recover ]; then
      printf 'recovered demo version %s\n' "$DEMO_VERSION"
    fi
    ;;
  status)
    compose ps
    # Compose ps alone exits zero even when services are stopped.
    health_verbose=1
    if inspect_services; then :; else fail "$health_problem"; fi
    # shellcheck disable=SC1091
    . "$state/identity.env"
    "$DEMO_TOOL" verify "$origin" "$DEMO_EXPECTED_NODE_PUBLIC_KEY"
    ;;
  logs) compose logs --tail 200 ;;
  down)
    if [ "$flag" = --purge ]; then
      compose down --volumes
      rm -rf -- "$state"
    else
      compose down
    fi
    ;;
esac
