# Username centre artefact (K7)

Status: the centre runs OUR `ramflux-federation` image under Podman Quadlet (plan
`NN-CENTRAL-OVERNIGHT-PLAN-2026-11-26` section 1). The centre writes its own units; `quadlet/`
holds reference units only. Digest and commit are filled in by the lead when the image is built.

## (a) Image
- Source: a full core commit (record it: `git rev-parse HEAD` of the branch that carries this file).
- Recipe: `Containerfile.username` (FROM debian trixie-slim; libssl3t64 and ca-certificates;
  `ramflux-federation` and `username-start.sh`; ENTRYPOINT `username-start.sh`).
- Build context: a directory with the release binary `ramflux-federation` (built from that commit)
  and `username-start.sh`.
- Run exactly one digest: `ghcr.io/ramfluxhq/ramflux-federation@sha256:<DIGEST>` in all three units.

## (b) Configuration (`RAMFLUX_USERNAME_*`, from `publish-username-pin.py`)
Files: `/etc/ramflux-username/witness.env` and `center.env` (per role; the federation refuses keys of
the other role), `home.env` for home nodes. Common keys: `RAMFLUX_USERNAME_CENTER_URL`, `_ID`
(= centre DNS name = node_id), `_PUBLIC_KEY`, `_TLS_SERVER_NAME` (`ramflux-federation`),
`_CA_FILE`, `TRUST_GENERATION`, `WITNESS_SOCKET`, `CENTER_UID=10001`, `WITNESS_UID=10002`.
Witness only: `ROLE=witness`, `LISTEN_ADDR=0.0.0.0:8443`, `WITNESS_DB`, and
`RAMFLUX_FEDERATION_NODE_SIGNING_SEED_FILE` (the centre's own Ed25519 key, plan section 1.3).
Centre only: `ROLE=center`, `PRIMARY_DB`.

## (c) Mounted files
Host (read only, source of the init copy):
- `/etc/ramflux-username/witness/` : `node.key` (node signing seed, 0600), `ca.pem`, `service.pem`,
  `service.key`, `federation.toml`
- `/etc/ramflux-username/center/` : `ca.pem`, `service.pem`, `service.key`, `federation.toml`
Container, after init (owned by the role UID, mode 0600 inside `<role>/etc`):
- `/var/lib/ramflux/username/witness` (witness volume), `/var/lib/ramflux/username/center`
  (centre volume), `/var/lib/ramflux/username/socket` (shared volume, group 10003; `witness.sock`).
- `/run/username-secrets/<role>` read only during init.

## (d) Init command
`username-start.sh prepare` (root, no network, one shot). It prepares the three volumes, sets
first-start markers and copies the role secrets into `<role>/etc`. Then `witness` and `center`
start. A marker (`<role>/.initialize`) passes `--username-initialize` (witness) or
`--username-rebuild` (centre) only while the role's store (`WITNESS_DB` / `PRIMARY_DB`) does not
exist; the first start that finds the store removes the marker. So a start that fails before the
store is written keeps the marker and the restart retries; once the store exists, a restart never
reconstructs it. A store left by an interrupted rebuild is refused by the product on resume; the
operator then removes that store file and recreates the marker (`touch`, role UID, mode 0600).
The centre's rebuild also needs the witness to be in recovery (started with the marker, or with
`--username-recovery`).

Witness and centre run in separate containers, so each sees the other's SO_PEERCRED pid as 0
(different PID namespaces). Only the peer UID is checked; it is mapped identically because both
containers run in the same rootless user namespace.

## Provisioning and the pin
    python3 deploy/central/publish-username-pin.py --dir ~/rf-username \
      --centre-id <dns-name> --public-url https://<dns-name>:8443 [--ca-cert CA --ca-key KEY]
Output: `username-pin.json` = the `username` member of the `rfc-centre-pin-1` bundle
(`url`, `id`, `public_key`, `generation`, `tls_server_name`, `ca_pem`). Without `--ca-cert` a
throwaway CA is made: scratch runs only. Production uses the centre's CA (plan section 1.4).
The bundle is delivered out of band (plan section 0; production publication is owner decision O1).

## Gaps against the plan (for the controller)
- Plan section 1.2 puts the TCP listener on the centre unit. The code puts it on the witness, and
  the code is authoritative: `username_directory/witness.rs` binds `RAMFLUX_USERNAME_LISTEN_ADDR`
  (TCP and QUIC) and the centre role refuses `LISTEN_ADDR`; `mod.rs`: "Witness owns every public
  response writer". The centre (primary) has no listener and runs with `Network=none`. Plan 1.2
  should read: witness unit = public listener; centre unit = no network.
- The centre's signing key and the TLS certificate come from the centre's own CA. Provisioning
  here does not create them in production.
