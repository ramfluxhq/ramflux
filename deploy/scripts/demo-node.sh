#!/usr/bin/env sh
# Persistent, project-scoped production demo deployment.
set -eu
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }
usage() { fail 'usage: demo-node.sh {up|down|status|logs} ENV_FILE [--purge|--remote]'; }
[ "$#" -ge 2 ] && [ "$#" -le 3 ] || usage
command=$1
env_file=$2
flag=${3:-}
case "$command:$flag" in up:|down:|down:--purge|status:|status:--remote|logs:) ;; *) usage ;; esac
case "$env_file" in /*) ;; *) env_file="$PWD/$env_file" ;; esac
[ -f "$env_file" ] || fail 'an existing operator env file is required'
# The operator file is trusted shell configuration, never downloaded or committed.
set -a
# shellcheck disable=SC1090
. "$env_file"
set +a
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
DEMO_HEALTH_TIMEOUT_SECONDS=${DEMO_HEALTH_TIMEOUT_SECONDS:-180}
DEMO_HEALTH_POLL_SECONDS=${DEMO_HEALTH_POLL_SECONDS:-2}
for seconds in "$DEMO_HEALTH_TIMEOUT_SECONDS" "$DEMO_HEALTH_POLL_SECONDS"; do
  case "$seconds" in ''|0*|*[!0-9]*) fail 'health timeout and poll interval must be positive integers' ;; esac
  [ "$seconds" -ge 1 ] && [ "$seconds" -le 3600 ] || fail 'health timeout and poll interval must be 1..3600 seconds'
done
export DEMO_NODE_ID DEMO_GATEWAY_PORT DEMO_RELAY_PORT DEMO_HTTP_PORT DEMO_TURN_PORT
export DEMO_MESH_PORT DEMO_BIND_ADDR DEMO_VERSION
case "$DEMO_HOST" in ''|*[!a-zA-Z0-9.-]*|-*) fail 'DEMO_HOST must be a DNS name or IPv4 address' ;; esac
case "$DEMO_NODE_ID" in ''|*[!a-zA-Z0-9.-]*|-*) fail 'invalid DEMO_NODE_ID' ;; esac
case "$DEMO_PROJECT" in [a-z0-9]*) ;; *) fail 'invalid DEMO_PROJECT' ;; esac
case "$DEMO_PROJECT" in *[!a-z0-9_-]*) fail 'invalid DEMO_PROJECT' ;; esac
case "$DEMO_VERSION" in ''|*[!a-zA-Z0-9_.-]*|.*|-*) fail 'invalid DEMO_VERSION image tag' ;; esac
case "$DEMO_BIND_ADDR" in ''|*[!0-9.]*) fail 'DEMO_BIND_ADDR must be an IPv4 bind address' ;; esac
for port in "$DEMO_GATEWAY_PORT" "$DEMO_RELAY_PORT" "$DEMO_HTTP_PORT" "$DEMO_TURN_PORT" "$DEMO_MESH_PORT"; do
  case "$port" in ''|*[!0-9]*) fail 'ports must be integers' ;; esac
  [ "$port" -ge 1024 ] && [ "$port" -le 65535 ] || fail 'ports must be between 1024 and 65535'
done
case "$DEMO_DATA_DIR" in /*) ;; *) fail 'DEMO_DATA_DIR must be absolute' ;; esac
case "$DEMO_TOOL" in /*) ;; *) fail 'DEMO_TOOL must be absolute' ;; esac
[ -x "$DEMO_TOOL" ] || fail 'DEMO_TOOL must be an executable demo-node-tool'
origin="http://$DEMO_HOST:$DEMO_HTTP_PORT"
if [ "$flag" = --remote ]; then
  : "${DEMO_EXPECTED_NODE_PUBLIC_KEY:?copy the public pin from the QA identity.env over a trusted channel}"
  exec "$DEMO_TOOL" verify "$origin" "$DEMO_EXPECTED_NODE_PUBLIC_KEY"
fi
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo=$(CDPATH= cd -- "$script_dir/../.." && pwd)
# Canonicalize before checking ownership or allowing recursive deletion.
[ "$command" != up ] || mkdir -p "$DEMO_DATA_DIR"
[ -d "$DEMO_DATA_DIR" ] || fail 'demo data directory does not exist'
state=$(CDPATH= cd -- "$DEMO_DATA_DIR" && pwd -P)
[ "$state" != / ] && [ "$state" != "$HOME" ] && [ "$state" != "$repo" ] || fail 'unsafe data directory'
mkdir "$state.lock" 2>/dev/null || fail 'demo operation already running (check adjacent .lock directory)'
trap 'rmdir "$state.lock"' EXIT
trap 'exit 1' HUP INT TERM
if [ "$command" = up ]; then
  python3 "$script_dir/demo-node-config.py" "$repo" "$state"
else
  [ -f "$state/owner.json" ] || fail 'data directory is not owned by this demo tooling'
  python3 "$script_dir/demo-node-config.py" "$repo" "$state"
fi
owner=$(cat "$state/owner.token")
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
printf 'compose provider: %s (runtime: %s)\n' "$compose_provider" "$container_engine"
runtime() { clean_env "$container_engine" "$@"; }
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
compose() (
  cd "$state"
  set -- --env-file "$state/runtime.env" -p "$DEMO_PROJECT" \
    -f "$state/compose.yml" -f "$state/demo-override.json" "$@"
  case "$compose_provider" in
    docker-v2|docker-wrapper) clean_env docker compose "$@" ;;
    podman-compose) clean_env podman-compose "$@" ;;
    podman-wrapper) clean_env podman compose "$@" ;;
  esac
)

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
    set -- $service_ids
    if [ "$#" -eq 0 ]; then
      health_problem="ramflux-$service is missing"; return 1
    fi
    if [ "$#" -ne 1 ]; then
      health_problem="multiple containers for ramflux-$service"; return 2
    fi
    service_state=$(runtime inspect "$1" | python3 -c '
import json
import sys
item = json.load(sys.stdin)[0]
labels = (item.get("Config") or {}).get("Labels") or {}
if labels.get("org.ramflux.demo.owner") != sys.argv[1]:
    sys.exit("refusing foreign container during health inspection")
state = item["State"]
health = state.get("Health") or state.get("Healthcheck") or {}
print(state["Status"], health.get("Status", "missing"))
' "$owner") || { health_problem="cannot inspect ramflux-$service"; return 2; }
    case "$service_state" in
      'running healthy')
        if [ "$health_verbose" = 1 ]; then printf 'ramflux-%s: %s\n' "$service" "$service_state"; fi
        ;;
      'created '*|'configured '*|'restarting '*|'running starting')
        health_problem="ramflux-$service: $service_state"; return 1 ;;
      *) health_problem="ramflux-$service: $service_state"; return 2 ;;
    esac
  done
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
check_resources
case "$command" in
  up)
    chmod 700 "$state"
    RAMFLUX_DEPLOY_DIR="$state" sh "$script_dir/bootstrap-ca.sh"
    RAMFLUX_DEPLOY_DIR="$state" RAMFLUX_NODE_ID="$DEMO_NODE_ID" sh "$script_dir/issue-certs.sh"
    RAMFLUX_DEPLOY_DIR="$state" sh "$script_dir/provision-node.sh"
    # Service identities and certificate SPIFFE identities must use the same node id.
    python3 - "$state" "$DEMO_NODE_ID" <<'PY'
from pathlib import Path
import sys
for config in Path(sys.argv[1], "config").glob("*.toml"):
    config.write_text(config.read_text().replace('node_id = "localhost"', f'node_id = "{sys.argv[2]}"'))
PY
    "$DEMO_TOOL" init "$state" "$DEMO_NODE_ID"
    # Containers need to traverse their read-only mounts; the containing state directory stays private.
    chmod 755 "$state/certs" "$state/config" "$state/secrets" "$state/secrets/gateway-v3" "$state/secrets/federation"
    for service in gateway router notify federation relay signaling retention; do
      chmod 755 "$state/certs/$service"
    done
    chmod 644 "$state"/config/*.toml "$state"/secrets/gateway-v3/*.json "$state"/secrets/federation/*.json
    # Concrete outer values avoid podman-compose 1.3.0's self-referential default interpolation.
    # The keyring is read-only trust material; the relay owns its durable cache in relay-redb.
    cat "$state/identity.env" > "$state/runtime.env"
    cat >> "$state/runtime.env" <<ENV
RAMFLUX_VERSION=$DEMO_VERSION
RAMFLUX_FEDERATION_TRUST_ENDPOINT=ramflux-federation:7443
RAMFLUX_FEDERATION_PROVIDER_KEYRING_FILE=/etc/ramflux/federation/provider-keyring.json
RAMFLUX_RELAY_TRUST_SNAPSHOT_CACHE_FILE=/var/lib/ramflux/relay/trust-snapshot.json
RAMFLUX_FEDERATION_TRUST_ISSUER_NODE_ID=$DEMO_NODE_ID
RAMFLUX_FEDERATION_NODE_ID=$DEMO_NODE_ID
RAMFLUX_GATEWAY_TCP_PORT=$DEMO_BIND_ADDR:$DEMO_GATEWAY_PORT
RAMFLUX_GATEWAY_QUIC_PORT=$DEMO_BIND_ADDR:$DEMO_GATEWAY_PORT
RAMFLUX_RELAY_CLIENT_QUIC_PORT=$DEMO_BIND_ADDR:$DEMO_RELAY_PORT
RAMFLUX_FEDERATION_ADMIN_PORT=$DEMO_BIND_ADDR:$DEMO_HTTP_PORT
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
    sh "$script_dir/build-prod-images.sh"
    compose up -d --build
    wait_for_services
    printf 'demo URL: %s\n' "$origin"
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
