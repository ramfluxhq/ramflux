#!/usr/bin/env python3
"""Independent SAS v3 oracle: Python JSON/framing/hashlib only, no Ramflux imports.

All strings are ASCII and all numbers safe integers, so sorted compact JSON is
identical to JCS for this fixture. Run here to regenerate vectors.json.
"""
import base64
import copy
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
legacy = json.loads((HERE.parent / "pairing_v2/vectors.json").read_text())["transcript"]
transcript = copy.deepcopy(legacy)
transcript.update(schema="ramflux.pairing.Transcript.v3", version=3)
for name, key in [("initiator", 91), ("responder", 92)]:
    role = transcript[name]
    role.update(schema="ramflux.pairing.RoleContext.v3", version=3,
                transfer_profile="full_account_data_v1",
                hpke_key=base64.urlsafe_b64encode(bytes([key]) * 32).decode().rstrip("="))
    common = role["common"]
    common.update(schema="ramflux.pairing.Common.v3", version=3,
                  purpose="primary_transfer", requested_role="primary",
                  transfer_id=common["invitation_id"],
                  hpke_suite="ramflux.identity.transfer.hpke_suite.v1",
                  data_selection={"full_account_data_v1": {}})

def jcs(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()

def vector(domain, body):
    preimage = domain.encode() + b"\x00" + body
    return {"preimage_hex": preimage.hex(), "sha256": hashlib.sha256(preimage).hexdigest()}

vectors = {"transcript": transcript, "legacy_transcript": legacy, "vectors": {}}
for version, value in [(2, legacy), (3, transcript)]:
    vectors["vectors"][f"v{version}_transcript"] = vector(
        f"ramflux.identity.pairing_transcript.v{version}", jcs(value))
    for name, role_byte, salt in [("initiator", 0, 11), ("responder", 1, 12)]:
        vectors["vectors"][f"v{version}_{name}"] = vector(
            f"ramflux.identity.pairing.context_commitment.v{version}",
            bytes([role_byte]) + bytes([salt]) * 32 + jcs(value[name]))
# Deliberately invalid context: this preimage is an attack input, never a context
# accepted by the closed decoder. Removing profile must alter the committed hash.
changed = copy.deepcopy(transcript)
del changed["responder"]["transfer_profile"]
vectors["vectors"]["missing_profile_transcript"] = vector(
    "ramflux.identity.pairing_transcript.v3", jcs(changed))
vectors["vectors"]["missing_profile_responder"] = vector(
    "ramflux.identity.pairing.context_commitment.v3", bytes([1]) + bytes([12]) * 32 + jcs(changed["responder"]))
(HERE / "vectors.json").write_text(json.dumps(vectors, indent=2) + "\n")
