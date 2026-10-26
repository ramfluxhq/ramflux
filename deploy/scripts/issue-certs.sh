#!/usr/bin/env sh
set -eu

if ! command -v openssl >/dev/null 2>&1; then
  printf 'openssl is required to issue local mesh certificates\n' >&2
  exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
deploy_dir="${RAMFLUX_DEPLOY_DIR:-$(CDPATH= cd -- "${script_dir}/.." && pwd)}"
cert_dir="${deploy_dir}/certs"
ca_cert="${cert_dir}/ca.pem"
ca_key="${cert_dir}/ca-key.pem"

if [ ! -f "${ca_cert}" ] || [ ! -f "${ca_key}" ]; then
  printf 'missing CA material; run %s/scripts/bootstrap-ca.sh first\n' "${deploy_dir}" >&2
  exit 1
fi

services='gateway router notify federation relay signaling retention'
node_id="${RAMFLUX_NODE_ID:-localhost}"

normalize_service_mesh_permissions() {
  for _service in ${services}; do
    _cert="${cert_dir}/${_service}/${_service}.pem"
    _key="${cert_dir}/${_service}/${_service}-key.pem"
    _ca="${cert_dir}/${_service}/ca.pem"
    if [ -f "${_cert}" ]; then
      chmod 644 "${_cert}"
    fi
    if [ -f "${_key}" ]; then
      chmod 644 "${_key}"
    fi
    if [ -f "${_ca}" ]; then
      chmod 644 "${_ca}"
    fi
  done
}

# A service is complete only when its key/cert pair is internally consistent
# (matching public keys) AND the cert verifies against the *current* CA. If the
# CA was just regenerated, the old leaves fail verification and are reissued.
service_is_complete() {
  for _service in ${services}; do
    _sd="${cert_dir}/${_service}"
    [ -s "${_sd}/${_service}-key.pem" ] && [ -s "${_sd}/${_service}.pem" ] \
      && [ -s "${_sd}/ca.pem" ] || return 1
    _kpub=$(openssl pkey -in "${_sd}/${_service}-key.pem" -pubout 2>/dev/null) || return 1
    _cpub=$(openssl x509 -in "${_sd}/${_service}.pem" -pubkey -noout 2>/dev/null) || return 1
    [ "${_kpub}" = "${_cpub}" ] || return 1
    openssl verify -CAfile "${ca_cert}" "${_sd}/${_service}.pem" >/dev/null 2>&1 || return 1
  done
  return 0
}

issue_one_service() {
  _service="$1"
  _service_dir="${cert_dir}/${_service}"
  mkdir -p "${_service_dir}"
  _key="${_service_dir}/${_service}-key.pem"
  _cert="${_service_dir}/${_service}.pem"
  _tmp_key=$(mktemp "${_service_dir}/.key.XXXXXX")
  _tmp_csr=$(mktemp "${_service_dir}/.csr.XXXXXX")
  _tmp_ext=$(mktemp "${_service_dir}/.ext.XXXXXX")
  _tmp_cert=$(mktemp "${_service_dir}/.cert.XXXXXX")
  openssl genpkey -algorithm ED25519 -out "${_tmp_key}"
  cat > "${_tmp_ext}" <<EOF
subjectAltName = DNS:ramflux-${_service}, DNS:${_service}, DNS:localhost, URI:spiffe://${node_id}/ramflux-${_service}
extendedKeyUsage = serverAuth, clientAuth
keyUsage = digitalSignature
EOF
  openssl req \
    -new \
    -key "${_tmp_key}" \
    -out "${_tmp_csr}" \
    -subj "/CN=ramflux-${_service}"
  openssl x509 \
    -req \
    -in "${_tmp_csr}" \
    -CA "${ca_cert}" \
    -CAkey "${ca_key}" \
    -CAcreateserial \
    -out "${_tmp_cert}" \
    -days 825 \
    -extfile "${_tmp_ext}"
  chmod 644 "${_tmp_key}"
  chmod 644 "${_tmp_cert}"
  # Publish the matched key/cert pair atomically so a concurrent reader never
  # sees a key from one issuance with a cert from another.
  mv -f "${_tmp_key}" "${_key}"
  mv -f "${_tmp_cert}" "${_cert}"
  cp "${ca_cert}" "${_service_dir}/ca.pem"
  chmod 644 "${_service_dir}/ca.pem"
  rm -f "${_tmp_csr}" "${_tmp_ext}"
}

# Node secrets live in their own directories, so each container mounts only the secret it
# needs: federation and retention share node-identity/, notify reads notify/route.key.
# Mode 0640: never world-readable. Containers drop every capability, so container root
# reads these through the group named by RAMFLUX_SECRET_GID (compose group_add); see
# docs/server-data.md for rootful Docker and rootless Podman.
#
# The group is RAMFLUX_SECRET_GROUP when set (recommended: a dedicated group whose only
# members are the operators), otherwise the invoking operator's primary group. Its id is
# recorded as RAMFLUX_SECRET_GID in deploy/.env, which compose reads, unless that file
# already sets it.
migrate_signing_seed() {
  _legacy="${cert_dir}/federation/node-signing.key"
  _identity="${cert_dir}/node-identity/node-signing.key"
  [ -e "${_legacy}" ] || return 0
  if [ ! -e "${_identity}" ]; then
    # Preserve an existing identity when moving it out of the mesh directory.
    mkdir -p "$(dirname "${_identity}")"
    mv "${_legacy}" "${_identity}"
  elif cmp -s "${_legacy}" "${_identity}"; then
    rm -f "${_legacy}"
  else
    printf 'refusing to continue: %s and %s hold different node signing seeds.\n' \
      "${_legacy}" "${_identity}" >&2
    printf 'Keep the seed that matches the federation identity pin, remove the other, and rerun.\n' >&2
    return 1
  fi
}

# Resolves a group name to its id without assuming getent (absent on macOS).
group_id_of() {
  _gid=""
  if command -v getent >/dev/null 2>&1; then
    _gid=$(getent group "$1" 2>/dev/null | cut -d: -f3)
  fi
  if [ -z "${_gid}" ] && command -v dscl >/dev/null 2>&1; then
    _gid=$(dscl . -read "/Groups/$1" PrimaryGroupID 2>/dev/null | awk '{print $2}')
  fi
  if [ -z "${_gid}" ] && [ -r /etc/group ]; then
    _gid=$(awk -F: -v name="$1" '$1 == name { print $3; exit }' /etc/group)
  fi
  [ -n "${_gid}" ] || return 1
  printf '%s\n' "${_gid}"
}

secret_group_id() {
  if [ -n "${RAMFLUX_SECRET_GROUP:-}" ]; then
    group_id_of "${RAMFLUX_SECRET_GROUP}" \
      || { printf 'unknown RAMFLUX_SECRET_GROUP %s\n' "${RAMFLUX_SECRET_GROUP}" >&2; return 1; }
  else
    id -g
  fi
}

record_secret_gid() {
  _env="${deploy_dir}/.env"
  if [ -f "${_env}" ] && grep -q '^RAMFLUX_SECRET_GID=' "${_env}"; then
    _recorded=$(sed -n 's/^RAMFLUX_SECRET_GID=//p' "${_env}" | tail -n 1)
    if [ "${_recorded}" != "$1" ]; then
      printf 'warning: %s sets RAMFLUX_SECRET_GID=%s but the node secrets belong to group %s;\n' \
        "${_env}" "${_recorded}" "$1" >&2
      printf 'warning: the services cannot read them until RAMFLUX_SECRET_GID=%s is set there.\n' \
        "$1" >&2
    fi
    return 0
  fi
  # Keep the appended assignment on its own line even if the file lacks a final newline.
  if [ -s "${_env}" ] && [ -n "$(tail -c 1 "${_env}")" ]; then
    printf '\n' >> "${_env}"
  fi
  printf 'RAMFLUX_SECRET_GID=%s\n' "$1" >> "${_env}"
}

ensure_node_secrets() {
  migrate_signing_seed
  _gid=$(secret_group_id)
  [ -n "${_gid}" ] || { printf 'cannot resolve the node secret group\n' >&2; return 1; }
  for _secret in node-identity/node-signing.key notify/route.key; do
    _path="${cert_dir}/${_secret}"
    if [ ! -e "${_path}" ]; then
      mkdir -p "$(dirname "${_path}")"
      _temp=$(mktemp "${_path}.XXXXXX")
      openssl rand -base64 32 | tr '+/' '-_' | tr -d '=\n' > "${_temp}"
      chmod 640 "${_temp}"
      mv "${_temp}" "${_path}"
    fi
    chmod 640 "${_path}"
    if [ -n "${RAMFLUX_SECRET_GROUP:-}" ]; then
      chgrp "${RAMFLUX_SECRET_GROUP}" "${_path}"
    fi
  done
  chmod 755 "${cert_dir}/node-identity"
  record_secret_gid "${_gid}"
}

issue_certs_locked() {
  ensure_node_secrets
  if service_is_complete; then
    normalize_service_mesh_permissions
    return 0
  fi
  for _service in ${services}; do
    issue_one_service "${_service}"
  done
  normalize_service_mesh_permissions
}

# Share the certs-dir lock with bootstrap-ca.sh so issuance can never run while
# the CA is being regenerated, and so concurrent issuers serialize instead of
# interleaving key/cert halves on the shared deploy/certs directory.
lock_file="${cert_dir}/.certs.lock"
if command -v flock >/dev/null 2>&1; then
  exec 9>"${lock_file}"
  flock 9
  issue_certs_locked
  flock -u 9
else
  lock_dir="${cert_dir}/.certs.lock.d"
  _waited=0
  while ! mkdir "${lock_dir}" 2>/dev/null; do
    if [ "${_waited}" -ge 120 ]; then
      rmdir "${lock_dir}" 2>/dev/null || true
    fi
    sleep 1
    _waited=$((_waited + 1))
  done
  trap 'rmdir "${lock_dir}" 2>/dev/null || true' EXIT INT TERM
  issue_certs_locked
  rmdir "${lock_dir}" 2>/dev/null || true
  trap - EXIT INT TERM
fi

printf 'issue-certs complete: %s\n' "${cert_dir}"
