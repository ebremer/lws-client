#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Starts the mock LWS server in the background on port 8787 and waits until it answers.
set -euo pipefail
port="${1:-8787}"
nohup node testing/mock-server/server.mjs --port "$port" > mock-server.log 2>&1 &
for _ in $(seq 1 30); do
  if curl -sf "http://localhost:${port}/" > /dev/null; then
    echo "mock LWS server is up on port ${port}"
    exit 0
  fi
  sleep 1
done
echo "mock LWS server did not start" >&2
cat mock-server.log >&2
exit 1
