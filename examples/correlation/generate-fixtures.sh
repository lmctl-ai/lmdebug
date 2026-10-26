#!/usr/bin/env bash
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
exec python3 "$HERE/correlate_https.py" --generate-fixture --fixture-dir "$HERE/fixtures" "$@"
