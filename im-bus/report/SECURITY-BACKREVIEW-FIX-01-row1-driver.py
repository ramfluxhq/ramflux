#!/usr/bin/env python3
# SECURITY-BACKREVIEW-FIX-01 row 1: account deletion lifecycle through the gateway itest
# proxy (the legitimate caller of /mvp7/lifecycle/* on the router, peer ramflux-gateway).
# Run on the QA host against a local-stack run dir. Prints one JSON line per step.
import json, sys, time, urllib.request

gw = sys.argv[1]  # e.g. http://127.0.0.1:18931
principal = "secrev-principal-row1"

def post(path, body):
    req = urllib.request.Request(gw + path, data=json.dumps(body).encode(),
                                 headers={"content-type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=20) as resp:
        return resp.status, json.loads(resp.read() or b"null")

def get(path):
    with urllib.request.urlopen(gw + path, timeout=20) as resp:
        return resp.status, json.loads(resp.read() or b"null")

def step(name, status, body):
    print(json.dumps({"step": name, "http": status, "body": body}, sort_keys=True), flush=True)
    return body

now = int(time.time())
step("start_delete", *post("/mvp7/lifecycle/event", {
    "principal_id": principal, "event_id": "row1-delete-1", "event_type": "identity.deleted",
    "actor_device_id": "row1-device", "lifecycle_epoch": 1, "now": now,
    "reason_code": "user_request", "timelock_seconds": 0}))
step("get_after_start", *get("/mvp7/lifecycle/" + principal))
step("cancel", *post("/mvp7/lifecycle/cancel", {"principal_id": principal, "now": now + 1}))
step("get_after_cancel", *get("/mvp7/lifecycle/" + principal))
step("start_delete_again", *post("/mvp7/lifecycle/event", {
    "principal_id": principal, "event_id": "row1-delete-2", "event_type": "identity.deleted",
    "actor_device_id": "row1-device", "lifecycle_epoch": 2, "now": now + 2,
    "reason_code": "user_request", "timelock_seconds": 0}))
step("finalize", *post("/mvp7/lifecycle/finalize", {"principal_id": principal, "now": now + 3}))
step("get_after_finalize", *get("/mvp7/lifecycle/" + principal))
