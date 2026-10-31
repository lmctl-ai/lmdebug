#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
import json, os, subprocess, time
base = os.environ["LMMOCK_URL"]; lmconn = os.environ["LMCONN_BIN"]
def request(args):
    r = subprocess.run([lmconn, "http", "request", *args], capture_output=True, text=True, timeout=20)
    if r.returncode: raise RuntimeError(r.stdout + r.stderr)
    value = json.loads(r.stdout)
    return value.get("result", value)
health = request([base + "/health"])
assert health["status"] == 200 and "LMDEBUG_LOOPBACK_HEALTH_V1" in health.get("bodyText", json.dumps(health))
for i in range(12):
    sentinel = json.dumps({"sentinel":"LMDEBUG_LOOPBACK_SENTINEL_V1", "n":i})
    result = request([base + "/echo", "--method", "POST", "--data", sentinel, "--header", "Content-Type: application/json"])
    payload = result.get("bodyText", "") + json.dumps(result.get("bodyJson", {}))
    if not (result.get("status") == 200 and "LMDEBUG_LOOPBACK_SENTINEL_V1" in payload):
        raise RuntimeError("unexpected lmconn echo response: " + json.dumps(result))
    time.sleep(.05)
print("PASS lmmock/lmconn HTTP sentinel traffic")
