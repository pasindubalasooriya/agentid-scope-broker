#!/usr/bin/env bash
# Start the specialist, the broker and the coordinator on one machine.
#
#   source .env.demo
#   ./setup/run-local.sh
#
# Logs go to .run/*.log. Stop everything with Ctrl-C.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RUN_DIR="${ROOT}/.run"
mkdir -p "$RUN_DIR"

# Scratch space on the local filesystem, for anything that needs an execute bit
# the repo's filesystem cannot provide.
STAGE_DIR=$(mktemp -d)

: "${THUNDER_BASE_URL:?source .env.demo first}"
: "${BROKER_CLIENT_ID:?source .env.demo first}"
: "${BROKER_CLIENT_SECRET:?source .env.demo first}"

export THUNDER_ISSUER="${THUNDER_ISSUER:-$THUNDER_BASE_URL}"
export SPECIALIST_RESOURCE="${SPECIALIST_RESOURCE:-https://specialist.agentid.local}"
export SPECIALIST_URL="${SPECIALIST_URL:-http://localhost:8000}"
export BROKER_URL="${BROKER_URL:-http://localhost:8081}"
export BROKER_ADDR="${BROKER_ADDR:-:8081}"

# Explicit interpreter overrides. Useful when the repo sits on a filesystem that
# cannot host a working virtualenv, so the venvs live elsewhere.
SPECIALIST_PYTHON="${SPECIALIST_PYTHON:-}"
COORDINATOR_PYTHON="${COORDINATOR_PYTHON:-}"

PIDS=()

cleanup() {
  echo
  echo "stopping"
  rm -rf "$STAGE_DIR"
  for pid in "${PIDS[@]:-}"; do
    [[ -n "$pid" ]] && kill "$pid" 2>/dev/null
  done
  wait 2>/dev/null
}
trap cleanup EXIT INT TERM

# python_for picks the interpreter for an agent directory.
#
# .venv-linux comes first because the repo may sit on a Windows filesystem with
# a Windows .venv in it, whose Scripts/python.exe cannot run under WSL.
python_for() {
  local dir="$1"
  if [[ -x "${dir}/.venv-linux/bin/python" ]]; then
    echo "${dir}/.venv-linux/bin/python"
  elif [[ -x "${dir}/.venv/bin/python" ]]; then
    echo "${dir}/.venv/bin/python"
  elif [[ "$OSTYPE" != linux* ]] && [[ -x "${dir}/.venv/Scripts/python.exe" ]]; then
    echo "${dir}/.venv/Scripts/python.exe"
  else
    echo "python3"
  fi
}

# broker_cmd prefers a prebuilt binary, so the machine running the demo does not
# need a Go toolchain. Cross-compile one with:
#   GOOS=linux GOARCH=amd64 go build -o bin/broker-linux-amd64 ./broker
broker_cmd() {
  local bin="${ROOT}/bin/broker-linux-amd64"

  if [[ -f "$bin" ]]; then
    if [[ -x "$bin" ]]; then
      echo "$bin"
      return
    fi
    # A Windows drive mounted into WSL cannot carry the execute bit, and chmod
    # on it is a no-op. Stage a copy on the Linux filesystem instead.
    local staged="${STAGE_DIR}/broker"
    if cp "$bin" "$staged" 2>/dev/null && chmod +x "$staged"; then
      echo "$staged"
      return
    fi
  fi

  if command -v go >/dev/null 2>&1; then
    echo "go run ./broker"
    return
  fi

  echo ""
}

# ---------------------------------------------------------------------------
echo "starting the specialist on :8000"
# ---------------------------------------------------------------------------
(
  cd "${ROOT}/agents/specialist"
  AGENT_NAME=specialist "${SPECIALIST_PYTHON:-$(python_for "${ROOT}/agents/specialist")}" main.py
) > "${RUN_DIR}/specialist.log" 2>&1 &
PIDS+=($!)

# ---------------------------------------------------------------------------
echo "starting the broker on ${BROKER_ADDR}"
# ---------------------------------------------------------------------------
BROKER_CMD="$(broker_cmd)"
if [[ -z "$BROKER_CMD" ]]; then
  echo "  no broker binary and no Go toolchain."
  echo "  Build one with: GOOS=linux GOARCH=amd64 go build -o bin/broker-linux-amd64 ./broker"
  exit 1
fi
(
  cd "$ROOT"
  $BROKER_CMD
) > "${RUN_DIR}/broker.log" 2>&1 &
PIDS+=($!)

# ---------------------------------------------------------------------------
echo "starting the coordinator on :8002 in ${DELEGATION_MODE:-broker} mode"
# ---------------------------------------------------------------------------
(
  cd "${ROOT}/agents/coordinator"
  AGENT_NAME=coordinator \
  DELEGATION_MODE="${DELEGATION_MODE:-broker}" \
  "${COORDINATOR_PYTHON:-$(python_for "${ROOT}/agents/coordinator")}" -c \
    "import uvicorn; from app import app; uvicorn.run(app, host='0.0.0.0', port=8002)"
) > "${RUN_DIR}/coordinator.log" 2>&1 &
PIDS+=($!)

# ---------------------------------------------------------------------------
echo "waiting for the services to come up"
# ---------------------------------------------------------------------------
for name_url in "specialist ${SPECIALIST_URL}/healthz" "broker ${BROKER_URL}/healthz" "coordinator http://localhost:8002/healthz"; do
  name="${name_url%% *}"
  url="${name_url#* }"
  for attempt in $(seq 1 30); do
    if curl -sf "$url" >/dev/null 2>&1; then
      echo "  ${name} is up"
      break
    fi
    if [[ "$attempt" == 30 ]]; then
      echo "  ${name} did not come up. See ${RUN_DIR}/${name}.log"
      tail -20 "${RUN_DIR}/${name}.log"
    fi
    sleep 1
  done
done

echo
echo "all three are running. In another shell:"
echo "  source .env.demo && ./setup/demo.sh"
echo
echo "logs: ${RUN_DIR}/{specialist,broker,coordinator}.log"
echo "Ctrl-C to stop."

wait
