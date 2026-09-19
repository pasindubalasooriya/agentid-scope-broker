#!/usr/bin/env bash
# Start the three services, run the before and after comparison, then stop them.
#
# This is the one command version of run-local.sh plus demo.sh, for when you just
# want to see the result rather than keep the services running.
#
#   source .env.demo
#   ./setup/demo-all.sh
#
# Pass --keep to leave the services running afterwards.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

KEEP=0
[[ "${1:-}" == "--keep" ]] && KEEP=1

if [[ -z "${THUNDER_BASE_URL:-}" ]] && [[ -f .env.demo ]]; then
  set -a
  # shellcheck disable=SC1091
  source .env.demo
  set +a
fi

: "${THUNDER_BASE_URL:?source .env.demo first, or run setup/register-thunder.sh}"

# Prefer virtualenvs on the local filesystem. A repo on a Windows drive mounted
# into WSL cannot host a working one, so they are usually elsewhere.
for agent in specialist coordinator; do
  var="$(echo "$agent" | tr '[:lower:]' '[:upper:]')_PYTHON"
  if [[ -z "${!var:-}" ]] && [[ -x "$HOME/.agentid-venvs/$agent/bin/python" ]]; then
    export "$var"="$HOME/.agentid-venvs/$agent/bin/python"
  fi
done

mkdir -p .run

echo "### starting services"
setsid ./setup/run-local.sh > .run/run-local.log 2>&1 &
RUNNER=$!
sleep 2
RUNNER_PGID=$(ps -o pgid= -p "$RUNNER" 2>/dev/null | tr -d ' ')

stop() {
  [[ "$KEEP" == 1 ]] && return
  echo
  echo "### stopping services"
  [[ -n "${RUNNER_PGID:-}" ]] && kill -TERM -- "-${RUNNER_PGID}" 2>/dev/null
  sleep 1
  pkill -f "agents/specialist" 2>/dev/null
  pkill -f "broker-linux-amd64" 2>/dev/null
}
trap stop EXIT

echo "### waiting for health"
ready=0
for _ in $(seq 1 60); do
  if curl -sf "${SPECIALIST_URL:-http://localhost:8000}/healthz" >/dev/null 2>&1 \
     && curl -sf "${BROKER_URL:-http://localhost:8081}/healthz" >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done

if [[ "$ready" != 1 ]]; then
  echo "services did not come up"
  for log in run-local specialist broker coordinator; do
    [[ -f ".run/${log}.log" ]] && { echo "--- ${log}.log ---"; tail -20 ".run/${log}.log"; }
  done
  exit 1
fi
echo "### specialist, broker and coordinator are up"

./setup/demo.sh
DEMO_RC=$?

if [[ "$KEEP" == 1 ]]; then
  echo
  echo "services left running. Stop them with:"
  echo "  pkill -f broker-linux-amd64; pkill -f agents/specialist"
fi

exit $DEMO_RC
