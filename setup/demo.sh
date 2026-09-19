#!/usr/bin/env bash
# The before and after demonstration.
#
# Runs the same delegated task twice, once the way it works today and once
# through the broker, and prints what the specialist received each time.
#
#   source .env.demo
#   ./setup/demo.sh
#
# Expects the specialist on SPECIALIST_URL and the broker on BROKER_URL.

set -uo pipefail

THUNDER_BASE_URL="${THUNDER_BASE_URL:?source .env.demo first}"
COORDINATOR_CLIENT_ID="${COORDINATOR_CLIENT_ID:?source .env.demo first}"
COORDINATOR_CLIENT_SECRET="${COORDINATOR_CLIENT_SECRET:?source .env.demo first}"
BROKER_CLIENT_ID="${BROKER_CLIENT_ID:?source .env.demo first}"
BROKER_CLIENT_SECRET="${BROKER_CLIENT_SECRET:?source .env.demo first}"
SPECIALIST_URL="${SPECIALIST_URL:-http://localhost:8000}"
BROKER_URL="${BROKER_URL:-http://localhost:8081}"
SPECIALIST_RESOURCE="${SPECIALIST_RESOURCE:-https://specialist.agentid.local}"
COORDINATOR_SCOPES="${COORDINATOR_SCOPES:-records:read records:list records:write}"

BOLD=$'\033[1m'; DIM=$'\033[2m'; GREEN=$'\033[0;32m'; RED=$'\033[0;31m'; BLUE=$'\033[0;34m'; OFF=$'\033[0m'

heading() { printf '\n%s== %s ==%s\n' "$BOLD" "$1" "$OFF"; }
note()    { printf '%s%s%s\n' "$DIM" "$1" "$OFF"; }
good()    { printf '%s%s%s\n' "$GREEN" "$1" "$OFF"; }
bad()     { printf '%s%s%s\n' "$RED" "$1" "$OFF"; }

command -v jq >/dev/null || { echo "jq is required"; exit 1; }

# scope_of <jwt> prints the scope claim of a token without verifying it.
scope_of() {
  local payload="${1#*.}"; payload="${payload%%.*}"
  # Restore the base64 padding that JWTs strip. A base64 payload is never one
  # character past a multiple of four, so this adds nothing, one or two.
  local pad=$(( (4 - ${#payload} % 4) % 4 )) padding="" i
  for (( i = 0; i < pad; i++ )); do padding+="="; done
  printf '%s%s' "$payload" "$padding" \
    | tr '_-' '/+' | base64 -d 2>/dev/null | jq -r '.scope // ""'
}

count() { printf '%s' "$1" | wc -w | tr -d ' '; }

# ---------------------------------------------------------------------------
heading "Step 0. The coordinator's standing authority"
# ---------------------------------------------------------------------------
WIDE_TOKEN=$(curl -sS -X POST "${THUNDER_BASE_URL}/oauth2/token" \
  -u "${COORDINATOR_CLIENT_ID}:${COORDINATOR_CLIENT_SECRET}" \
  -d "grant_type=client_credentials" \
  -d "scope=${COORDINATOR_SCOPES}" \
  -d "resource=${SPECIALIST_RESOURCE}" | jq -r '.access_token // empty')

if [[ -z "$WIDE_TOKEN" ]]; then
  bad "could not get a coordinator token. Is ThunderID reachable and registered?"
  exit 1
fi

WIDE_SCOPE=$(scope_of "$WIDE_TOKEN")
printf 'The coordinator holds %s%s scopes%s:\n' "$BOLD" "$(count "$WIDE_SCOPE")" "$OFF"
printf '  %s\n' $WIDE_SCOPE

# Reset the record the demo writes to, so a previous run's damage does not show
# up in this run's output.
curl -sS -o /dev/null -X POST "${SPECIALIST_URL}/capabilities/records.write" \
  -H "Authorization: Bearer ${WIDE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"recordId":"42","status":"open","subject":"Printer will not connect to wifi"}'

# ---------------------------------------------------------------------------
heading "Step 1. Baseline. Delegating without the broker"
# ---------------------------------------------------------------------------
note "The coordinator calls the specialist directly, carrying everything it has."

BASELINE=$(curl -sS -o /tmp/baseline.json -w '%{http_code}' \
  -X POST "${SPECIALIST_URL}/capabilities/records.summarise" \
  -H "Authorization: Bearer ${WIDE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"recordId":"42"}')

printf 'summarise -> HTTP %s\n' "$BASELINE"
jq -c . /tmp/baseline.json 2>/dev/null || cat /tmp/baseline.json

note "The task only needed to read. But the same token can also write:"
BASELINE_WRITE=$(curl -sS -o /tmp/baseline-write.json -w '%{http_code}' \
  -X POST "${SPECIALIST_URL}/capabilities/records.write" \
  -H "Authorization: Bearer ${WIDE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"recordId":"42","status":"closed-by-baseline-token"}')

if [[ "$BASELINE_WRITE" == "200" ]]; then
  bad "write -> HTTP 200. A read task carried write authority. This is the problem."
else
  printf 'write -> HTTP %s\n' "$BASELINE_WRITE"
fi

# ---------------------------------------------------------------------------
heading "Step 2. With the broker"
# ---------------------------------------------------------------------------
note "The same task, routed through the broker, which narrows the token first."

BROKER_STATUS=$(curl -sS -o /tmp/broker.json -D /tmp/broker.headers -w '%{http_code}' \
  -X POST "${BROKER_URL}/delegate" \
  -H "Authorization: Bearer ${WIDE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"task":"summarise record 42 for the support ticket",
       "capability":"records.summarise",
       "depth":0,
       "payload":{"recordId":"42"}}')

ORIGINAL=$(grep -i '^x-broker-original-scope:' /tmp/broker.headers | cut -d' ' -f2- | tr -d '\r')
DERIVED=$(grep -i '^x-broker-derived-scope:' /tmp/broker.headers | cut -d' ' -f2- | tr -d '\r')

printf 'summarise -> HTTP %s\n' "$BROKER_STATUS"
jq -c . /tmp/broker.json 2>/dev/null || cat /tmp/broker.json

printf '\n%sScope carried in:%s  %s (%s)\n' "$BLUE" "$OFF" "$ORIGINAL" "$(count "$ORIGINAL")"
printf '%sScope sent onward:%s %s (%s)\n' "$BLUE" "$OFF" "$DERIVED" "$(count "$DERIVED")"

# ---------------------------------------------------------------------------
heading "Step 3. Proving the narrowed token is actually enforced"
# ---------------------------------------------------------------------------
note "Mint the same narrowed token by hand, then try to write with it."

NARROW_TOKEN=$(curl -sS -X POST "${THUNDER_BASE_URL}/oauth2/token" \
  -u "${BROKER_CLIENT_ID}:${BROKER_CLIENT_SECRET}" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=${WIDE_TOKEN}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token" \
  -d "scope=${DERIVED:-records:read}" \
  -d "resource=${SPECIALIST_RESOURCE}" | jq -r '.access_token // empty')

if [[ -z "$NARROW_TOKEN" ]]; then
  bad "token exchange failed. Does the broker client have the token-exchange grant?"
  exit 1
fi

printf 'Narrowed token scope: %s\n' "$(scope_of "$NARROW_TOKEN")"

DENIED=$(curl -sS -o /tmp/denied.json -w '%{http_code}' \
  -X POST "${SPECIALIST_URL}/capabilities/records.write" \
  -H "Authorization: Bearer ${NARROW_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"recordId":"42","status":"closed-by-narrowed-token"}')

if [[ "$DENIED" == "403" ]]; then
  good "write -> HTTP 403. The narrowed token cannot write. The narrowing is enforced."
  jq -c '.detail' /tmp/denied.json 2>/dev/null
else
  bad "write -> HTTP ${DENIED}, expected 403. The narrowing is not being enforced."
  cat /tmp/denied.json
fi

ALLOWED=$(curl -sS -o /tmp/allowed.json -w '%{http_code}' \
  -X POST "${SPECIALIST_URL}/capabilities/records.read" \
  -H "Authorization: Bearer ${NARROW_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"recordId":"42"}')

if [[ "$ALLOWED" == "200" ]]; then
  good "read -> HTTP 200. The legitimate action still works."
else
  bad "read -> HTTP ${ALLOWED}, expected 200. The narrowing went too far."
fi

# ---------------------------------------------------------------------------
heading "Summary"
# ---------------------------------------------------------------------------
printf '  %-28s %s\n' "Baseline scope"  "$WIDE_SCOPE"
printf '  %-28s %s\n' "Broker derived scope" "${DERIVED:-none}"
printf '  %-28s %s -> %s\n' "Scope count" "$(count "$WIDE_SCOPE")" "$(count "$DERIVED")"
echo
