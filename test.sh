#!/usr/bin/env bash
# Offline integration-runner contracts. Real released-host tests are separate.
set -euo pipefail
cd "$(dirname "$0")"
python_bin=${PYTHON:-python3}
command -v "$python_bin" >/dev/null || python_bin=python
"$python_bin" -B tests/integration-test.py
"$python_bin" -m py_compile scripts/integration-run.py scripts/released-hosts.py scripts/traffic-check.py integration/traffic-client.py
