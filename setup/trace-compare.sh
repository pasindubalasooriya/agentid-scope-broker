#!/usr/bin/env bash
# Produce the two traces the before and after comparison needs.
#
# Runs the same delegated task twice, once with the coordinator calling the
# specialist directly and once through the broker, with tracing on for both.
# The spans carry the same attribute names either way, so the two traces line up
# side by side in Agent Manager's trace view.
#
#   source .env.demo
#   source .env.trace          # AMP_OTEL_ENDPOINT and AMP_AGENT_API_KEY
#   ./setup/trace-compare.sh
#
# The only attributes that differ are agentid.broker.enabled, and
# agentid.scope.derived, which the baseline has no value for.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT" || exit 1

for f in .env.demo .env.trace; do
  if [[ -f "$f" ]]; then
    set -a
    # shellcheck disable=SC1090
    source "$f"
    set +a
  fi
done

: "${THUNDER_BASE_URL:?run setup/register-thunder.sh first}"
: "${AMP_OTEL_ENDPOINT:?set AMP_OTEL_ENDPOINT, for example http://localhost:22893/otel}"
: "${AMP_AGENT_API_KEY:?set AMP_AGENT_API_KEY from the Agent Manager console}"

export AMP_OTEL_ENDPOINT AMP_AGENT_API_KEY

COORDINATOR_URL="http://localhost:8002"
TASK='summarise record 42 for the support ticket'

for agent in specialist coordinator; do
  var="$(echo "$agent" | tr '[:lower:]' '[:upper:]')_PYTHON"
  if [[ -z "${!var:-}" ]] && [[ -x "$HOME/.agentid-venvs/$agent/bin/python" ]]; then
    export "$var"="$HOME/.agentid-venvs/$agent/bin/python"
  fi
done

mkdir -p .run

stop_all() {
  pkill -f "broker-linux-amd64" 2>/dev/null
  pkill -f "agents/specialist" 2>/dev/null
  pkill -f "uvicorn" 2>/dev/null
  sleep 2
}

# run_one <mode> <label>
run_one() {
  local mode="$1" label="$2"

  echo
  echo "=============================================="
  echo "  ${label}  (DELEGATION_MODE=${mode})"
  echo "=============================================="

  stop_all

  DELEGATION_MODE="$mode" setsid ./setup/run-local.sh > ".run/run-${mode}.log" 2>&1 &
  local pgid
  sleep 2
  pgid=$(ps -o pgid= -p $! 2>/dev/null | tr -d ' ')

  local ready=0
  for _ in $(seq 1 60); do
    if curl -sf "${COORDINATOR_URL}/healthz" >/dev/null 2>&1; then
      ready=1
      break
    fi
    sleep 1
  done

  if [[ "$ready" != 1 ]]; then
    echo "coordinator did not come up in ${mode} mode"
    tail -20 ".run/run-${mode}.log"
    [[ -n "$pgid" ]] && kill -TERM -- "-${pgid}" 2>/dev/null
    return 1
  fi

  echo "coordinator is up in ${mode} mode, delegating"
  local response
  response=$(curl -sS -X POST "${COORDINATOR_URL}/delegate" \
    -H "Content-Type: application/json" \
    -d "{\"task\":\"${TASK}\",\"capability\":\"records.summarise\",\"depth\":0,\"payload\":{\"recordId\":\"42\"}}")

  # Show the raw body when it is not JSON, rather than letting jq fail with a
  # parse error that says nothing about what went wrong.
  if ! jq -e '{mode, capability, status, scopeSent, scopeDerived}' <<<"$response" 2>/dev/null; then
    echo "the coordinator did not return JSON:"
    echo "$response"
    echo "--- broker.log ---"
    tail -5 .run/broker.log 2>/dev/null
    return 1
  fi

  # Give the batch span processor time to flush before the process is killed.
  echo "flushing spans"
  sleep 8

  [[ -n "$pgid" ]] && kill -TERM -- "-${pgid}" 2>/dev/null
  sleep 2
}

run_one baseline "BEFORE. The coordinator's full authority travels to the specialist"
run_one broker   "AFTER. The broker narrows the token for this one call"

stop_all

echo
echo "=============================================="
echo "  Both traces sent to ${AMP_OTEL_ENDPOINT}"
echo "=============================================="
echo
echo "Find them in the console at http://localhost:3000 under the agent's"
echo "Observability, Traces view, or query the traces observer directly."
echo
echo "The two spans to compare are named:"
echo "  coordinator.delegate.baseline"
echo "  coordinator.delegate.broker"
echo
echo "Attributes to look at:"
echo "  agentid.scope.original     what the caller held, the same in both"
echo "  agentid.scope.derived      only present on the broker path"
echo "  agentid.broker.enabled     false, then true"
