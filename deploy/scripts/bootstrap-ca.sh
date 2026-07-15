#!/usr/bin/env sh
set -eu

if ! command -v openssl >/dev/null 2>&1; then
  printf 'openssl is required to bootstrap the local mesh CA\n' >&2
  exit 1
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
deploy_dir="${RAMFLUX_DEPLOY_DIR:-$(CDPATH= cd -- "${script_dir}/.." && pwd)}"
cert_dir="${deploy_dir}/certs"
mkdir -p "${cert_dir}"

ca_key="${cert_dir}/ca-key.pem"
ca_cert="${cert_dir}/ca.pem"

# True only when both halves of the CA exist AND the certificate's public key
# matches the private key. A torn/interleaved pair (the concurrency bug this
# guards against) fails this check and is regenerated as a unit.
ca_is_complete() {
  [ -s "${ca_key}" ] && [ -s "${ca_cert}" ] || return 1
  _kpub=$(openssl pkey -in "${ca_key}" -pubout 2>/dev/null) || return 1
  _cpub=$(openssl x509 -in "${ca_cert}" -pubkey -noout 2>/dev/null) || return 1
  [ -n "${_kpub}" ] && [ "${_kpub}" = "${_cpub}" ]
}

# Generate the CA into private temp files, then publish each half with an
# atomic rename. Only ever called while holding the certs-dir lock, so two
# concurrent callers can never interleave ca-key.pem from one run with ca.pem
# from another.
generate_ca() {
  _tmp_key=$(mktemp "${cert_dir}/.ca-key.XXXXXX")
  _tmp_cert=$(mktemp "${cert_dir}/.ca-cert.XXXXXX")
  openssl genpkey -algorithm ED25519 -out "${_tmp_key}"
  openssl req \
    -new \
    -x509 \
    -key "${_tmp_key}" \
    -out "${_tmp_cert}" \
    -days 3650 \
    -subj "/CN=Ramflux Local Mesh CA"
  chmod 600 "${_tmp_key}"
  chmod 644 "${_tmp_cert}"
  # Stale serial belongs to the old CA; drop it so issue-certs starts fresh.
  rm -f "${cert_dir}/ca.srl"
  mv -f "${_tmp_key}" "${ca_key}"
  mv -f "${_tmp_cert}" "${ca_cert}"
}

bootstrap_ca_locked() {
  if ca_is_complete; then
    return 0
  fi
  rm -f "${ca_key}" "${ca_cert}" "${cert_dir}/ca.srl"
  generate_ca
}

# Serialize the check-and-generate across processes that share this certs dir
# (full-suite itest runs bootstrap many nodes concurrently against the same
# deploy/certs). flock auto-releases on exit where available; otherwise fall
# back to an atomic mkdir lock that is portable to hosts without util-linux.
lock_file="${cert_dir}/.certs.lock"
if command -v flock >/dev/null 2>&1; then
  exec 9>"${lock_file}"
  flock 9
  bootstrap_ca_locked
  flock -u 9
else
  lock_dir="${cert_dir}/.certs.lock.d"
  _waited=0
  while ! mkdir "${lock_dir}" 2>/dev/null; do
    # Steal an obviously-dead lock so a crashed run cannot wedge the suite.
    if [ "${_waited}" -ge 120 ]; then
      rmdir "${lock_dir}" 2>/dev/null || true
    fi
    sleep 1
    _waited=$((_waited + 1))
  done
  trap 'rmdir "${lock_dir}" 2>/dev/null || true' EXIT INT TERM
  bootstrap_ca_locked
  rmdir "${lock_dir}" 2>/dev/null || true
  trap - EXIT INT TERM
fi

chmod 600 "${ca_key}"
chmod 644 "${ca_cert}"
printf 'bootstrap-ca complete: %s\n' "${ca_cert}"
