#!/usr/bin/env bash
# Register everything the demo needs in ThunderID.
#
# Creates:
#   - a "specialist" resource server defining the records read, list and write
#     permission scopes
#   - a role carrying all three
#   - a coordinator OAuth client holding that role, which is the wide standing
#     authority the broker narrows down
#   - a broker OAuth client with the token-exchange grant
#
# The payload shapes follow Agent Manager's own Thunder bootstrap scripts, which
# are known to work against the pinned Thunder version.
#
# Run it against a local Agent Manager install:
#
#   THUNDER_BASE_URL=http://thunder.amp.localhost:8080 ./setup/register-thunder.sh
#
# It is idempotent. Running it twice is safe.

set -euo pipefail

THUNDER_BASE_URL="${THUNDER_BASE_URL:-http://thunder.amp.localhost:8080}"
SYSTEM_CLIENT_ID="${THUNDER_CLIENT_ID:-amp-system-client}"
SYSTEM_CLIENT_SECRET="${THUNDER_CLIENT_SECRET:-amp-system-client-secret}"

COORDINATOR_CLIENT_ID="${COORDINATOR_CLIENT_ID:-coordinator-agent}"
COORDINATOR_CLIENT_SECRET="${COORDINATOR_CLIENT_SECRET:-coordinator-agent-secret}"
BROKER_CLIENT_ID="${BROKER_CLIENT_ID:-agentid-scope-broker}"
BROKER_CLIENT_SECRET="${BROKER_CLIENT_SECRET:-agentid-scope-broker-secret}"

# The handle names the resource server. It does not prefix the scopes: Thunder
# builds a permission from the resource handle and the action handle only, so
# the scopes below are "records:read", not "specialist:records:read". Sending
# the qualified form yields a token with no scope at all, silently.
RESOURCE_HANDLE="specialist"

# The identifier must be an absolute URI. Thunder accepts a bare handle as the
# resource indicator on client_credentials, but rejects it on token exchange
# with "Invalid resource parameter: must be an absolute URI". This value also
# becomes the `aud` of every token issued for the specialist.
RESOURCE_IDENTIFIER="${SPECIALIST_RESOURCE:-https://specialist.agentid.local}"

ROLE_NAME="Specialist Delegate"

SCOPES=(
  "records:read"
  "records:list"
  "records:write"
)

ENV_FILE="${ENV_FILE:-.env.demo}"

# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------
info()    { printf '\033[0;34m[info]\033[0m %s\n'  "$*" >&2; }
ok()      { printf '\033[0;32m[ok]\033[0m %s\n'    "$*" >&2; }
warn()    { printf '\033[0;33m[warn]\033[0m %s\n'  "$*" >&2; }
fail()    { printf '\033[0;31m[fail]\033[0m %s\n'  "$*" >&2; exit 1; }

command -v jq >/dev/null 2>&1 || fail "jq is required. Install it with: sudo apt-get install -y jq"
command -v curl >/dev/null 2>&1 || fail "curl is required"

# ---------------------------------------------------------------------------
# api <METHOD> <PATH> [BODY]
# Calls the Thunder admin API and prints the response body. Read the status
# with http_code.
#
# The status goes to a temp file rather than a variable on purpose. Most calls
# here are wrapped in a command substitution to capture the body, and that runs
# api in a subshell, where an assignment to a plain variable is discarded. A
# file is the one channel that survives.
# ---------------------------------------------------------------------------
STATUS_FILE=$(mktemp)
trap 'rm -f "$STATUS_FILE"' EXIT

api() {
  local method="$1" path="$2" body="${3:-}"
  local response

  if [[ -n "$body" ]]; then
    response=$(curl -sS -w '%{http_code}' -X "$method" "${THUNDER_BASE_URL}${path}" \
      -H "Authorization: Bearer ${SYSTEM_TOKEN}" \
      -H "Content-Type: application/json" \
      -d "$body")
  else
    response=$(curl -sS -w '%{http_code}' -X "$method" "${THUNDER_BASE_URL}${path}" \
      -H "Authorization: Bearer ${SYSTEM_TOKEN}" \
      -H "Accept: application/json")
  fi

  printf '%s' "${response: -3}" > "$STATUS_FILE"
  printf '%s' "${response%???}"
}

# http_code prints the status of the most recent api call.
http_code() { cat "$STATUS_FILE" 2>/dev/null; }

# ---------------------------------------------------------------------------
# 1. Authenticate as the Thunder admin client
# ---------------------------------------------------------------------------
info "Getting a system token from ${THUNDER_BASE_URL}"

TOKEN_RESPONSE=$(curl -sS -X POST "${THUNDER_BASE_URL}/oauth2/token" \
  -u "${SYSTEM_CLIENT_ID}:${SYSTEM_CLIENT_SECRET}" \
  -d "grant_type=client_credentials" \
  -d "scope=system") || fail "could not reach ${THUNDER_BASE_URL}"

SYSTEM_TOKEN=$(jq -r '.access_token // empty' <<<"$TOKEN_RESPONSE")
[[ -n "$SYSTEM_TOKEN" ]] || fail "no system token. Response was: ${TOKEN_RESPONSE}"
ok "system token acquired"

# ---------------------------------------------------------------------------
# 2. Look up the default organization unit and auth flow
# ---------------------------------------------------------------------------
OU_ID=$(api GET "/organization-units/tree/default" | jq -r '.id // empty')
[[ -n "$OU_ID" ]] || fail "could not read the default organization unit"
info "organization unit ${OU_ID}"

AUTH_FLOW_ID=$(api GET "/flows?flowType=AUTHENTICATION&limit=200" \
  | jq -r '[.. | objects | select(.handle == "default-basic-flow") | .id] | first // empty')
[[ -n "$AUTH_FLOW_ID" ]] || fail "could not find the default-basic-flow authentication flow"
info "auth flow ${AUTH_FLOW_ID}"

# ---------------------------------------------------------------------------
# 3. The specialist resource server, with one resource and three actions
# ---------------------------------------------------------------------------
info "Registering the '${RESOURCE_HANDLE}' resource server"

RS_BODY=$(api POST "/resource-servers" "$(jq -nc \
  --arg handle "$RESOURCE_HANDLE" --arg id "$RESOURCE_IDENTIFIER" --arg ou "$OU_ID" \
  '{name:"Specialist Agent", handle:$handle, identifier:$id,
    description:"Capabilities the specialist agent exposes", ouId:$ou}')")

if [[ "$(http_code)" == "409" ]]; then
  warn "resource server already exists, looking it up"
  RS_ID=$(api GET "/resource-servers" \
    | jq -r --arg i "$RESOURCE_IDENTIFIER" '[.. | objects | select(.identifier == $i) | .id] | first // empty')
else
  RS_ID=$(jq -r '.id // empty' <<<"$RS_BODY")
fi
[[ -n "$RS_ID" ]] || fail "could not create or find the resource server"
ok "resource server ${RS_ID}"

RES_BODY=$(api POST "/resource-servers/${RS_ID}/resources" \
  '{"name":"Records","handle":"records","description":"The specialist record store"}')

if [[ "$(http_code)" == "409" ]]; then
  RES_ID=$(api GET "/resource-servers/${RS_ID}/resources" \
    | jq -r '[.. | objects | select(.handle == "records") | .id] | first // empty')
else
  RES_ID=$(jq -r '.id // empty' <<<"$RES_BODY")
fi
[[ -n "$RES_ID" ]] || fail "could not create or find the records resource"
ok "records resource ${RES_ID}"

for action in read list write; do
  api POST "/resource-servers/${RS_ID}/resources/${RES_ID}/actions" \
    "$(jq -nc --arg a "$action" '{name:($a|ascii_upcase), handle:$a, description:("Records " + $a)}')" >/dev/null
  case "$(http_code)" in
    200|201) ok "action ${action} created" ;;
    409)     warn "action ${action} already exists" ;;
    *)       fail "creating action ${action} returned HTTP $(http_code)" ;;
  esac
done

# ---------------------------------------------------------------------------
# 4. A role carrying all three scopes
#
# This is deliberately wide. It is the coordinator's standing authority, the
# thing the broker exists to narrow.
# ---------------------------------------------------------------------------
info "Creating the '${ROLE_NAME}' role"

ROLE_BODY=$(api POST "/roles" "$(jq -nc --arg n "$ROLE_NAME" --arg ou "$OU_ID" \
  '{name:$n, ouId:$ou, description:"Full access to the specialist record store"}')")

if [[ "$(http_code)" == "409" ]]; then
  warn "role already exists, looking it up"
  ROLE_ID=$(api GET "/roles" \
    | jq -r --arg n "$ROLE_NAME" '[.. | objects | select(.name == $n) | .id] | first // empty')
else
  ROLE_ID=$(jq -r '.id // empty' <<<"$ROLE_BODY")
fi
[[ -n "$ROLE_ID" ]] || fail "could not create or find the role"

PERMISSIONS_JSON=$(printf '%s\n' "${SCOPES[@]}" | jq -R . | jq -sc .)
ROLE_PERM_BODY=$(api PUT "/roles/${ROLE_ID}" "$(jq -nc \
  --arg n "$ROLE_NAME" --arg ou "$OU_ID" --arg rs "$RS_ID" --argjson perms "$PERMISSIONS_JSON" \
  '{name:$n, ouId:$ou, description:"Full access to the specialist record store",
    permissions:[{resourceServerId:$rs, permissions:$perms}]}')")
if [[ "$(http_code)" != "200" ]]; then
  # ROL-1012 here means a permission string does not exist on the resource
  # server. The usual cause is qualifying a scope with the resource server
  # handle, for example "specialist:records:read" instead of "records:read".
  fail "attaching permissions to the role returned HTTP $(http_code): ${ROLE_PERM_BODY}"
fi
ok "role ${ROLE_ID} carries ${#SCOPES[@]} scopes"

# ---------------------------------------------------------------------------
# 5. The two OAuth clients
# ---------------------------------------------------------------------------
SCOPES_JSON=$(printf '%s\n' "${SCOPES[@]}" | jq -R . | jq -sc .)

# create_app <name> <clientId> <clientSecret> <grantTypesJson> <description>
# Echoes the application id.
create_app() {
  local name="$1" client_id="$2" client_secret="$3" grants="$4" description="$5"

  local payload
  payload=$(jq -nc \
    --arg name "$name" --arg desc "$description" --arg ou "$OU_ID" --arg flow "$AUTH_FLOW_ID" \
    --arg cid "$client_id" --arg secret "$client_secret" \
    --argjson grants "$grants" --argjson scopes "$SCOPES_JSON" \
    '{name:$name, description:$desc, ouId:$ou, authFlowId:$flow,
      inboundAuthConfig:[{type:"oauth2", config:{
        clientId:$cid, clientSecret:$secret, grantTypes:$grants,
        tokenEndpointAuthMethod:"client_secret_basic",
        pkceRequired:false, publicClient:false,
        scopes:$scopes,
        token:{accessToken:{validityPeriod:3600}}}}]}')

  local existing
  existing=$(api GET "/applications" \
    | jq -r --arg cid "$client_id" '[.. | objects | select(.clientId == $cid) | .id] | first // empty')

  if [[ -n "$existing" ]]; then
    warn "application ${client_id} exists, updating it"
    api PUT "/applications/${existing}" "$payload" >/dev/null
    [[ "$(http_code)" == "200" ]] || fail "updating ${client_id} returned HTTP $(http_code)"
    printf '%s' "$existing"
    return
  fi

  local body
  body=$(api POST "/applications" "$payload")
  case "$(http_code)" in
    200|201) jq -r '.id' <<<"$body" ;;
    *)       fail "creating ${client_id} returned HTTP $(http_code): ${body}" ;;
  esac
}

info "Registering the coordinator client"
COORDINATOR_APP_ID=$(create_app \
  "Coordinator Agent" "$COORDINATOR_CLIENT_ID" "$COORDINATOR_CLIENT_SECRET" \
  '["client_credentials"]' \
  "The delegating agent. Holds wide standing authority.")
ok "coordinator application ${COORDINATOR_APP_ID}"

# The broker must hold the token-exchange grant itself, because Thunder checks
# the grant against the client authenticating at the token endpoint, not against
# the subject token.
info "Registering the broker client with the token-exchange grant"
BROKER_APP_ID=$(create_app \
  "AgentID Scope Broker" "$BROKER_CLIENT_ID" "$BROKER_CLIENT_SECRET" \
  '["client_credentials","urn:ietf:params:oauth:grant-type:token-exchange"]' \
  "Derives a per request scope and exchanges tokens down to it.")
ok "broker application ${BROKER_APP_ID}"

# ---------------------------------------------------------------------------
# 6. Give both clients the role
#
# Thunder grants permission scopes through role and group assignments, so an
# application with the scopes merely listed in its config still gets nothing.
# ---------------------------------------------------------------------------
# Adding an assignment that already exists makes Thunder answer 500, not 409,
# so check the current list first rather than trying and interpreting the error.
ASSIGNED=$(api GET "/roles/${ROLE_ID}/assignments" | jq -r '[.assignments[]?.id] | join(" ")')

for app_id in "$COORDINATOR_APP_ID" "$BROKER_APP_ID"; do
  if [[ " ${ASSIGNED} " == *" ${app_id} "* ]]; then
    warn "role already assigned to ${app_id}"
    continue
  fi

  ASSIGN_BODY=$(api POST "/roles/${ROLE_ID}/assignments/add" \
    "$(jq -nc --arg id "$app_id" '{assignments:[{id:$id, type:"app"}]}')")
  case "$(http_code)" in
    200|201|204) ok "role assigned to ${app_id}" ;;
    *)           fail "assigning the role to ${app_id} returned HTTP $(http_code): ${ASSIGN_BODY}" ;;
  esac
done

# ---------------------------------------------------------------------------
# 7. Write the environment file the demo scripts read
# ---------------------------------------------------------------------------
cat > "$ENV_FILE" <<EOF
# Written by setup/register-thunder.sh. Safe to regenerate.
export THUNDER_BASE_URL="${THUNDER_BASE_URL}"
export THUNDER_ISSUER="${THUNDER_BASE_URL}"

export COORDINATOR_CLIENT_ID="${COORDINATOR_CLIENT_ID}"
export COORDINATOR_CLIENT_SECRET="${COORDINATOR_CLIENT_SECRET}"
export COORDINATOR_SCOPES="${SCOPES[*]}"

export BROKER_CLIENT_ID="${BROKER_CLIENT_ID}"
export BROKER_CLIENT_SECRET="${BROKER_CLIENT_SECRET}"

export SPECIALIST_RESOURCE="${RESOURCE_IDENTIFIER}"
export SPECIALIST_URL="\${SPECIALIST_URL:-http://localhost:8000}"
export BROKER_URL="\${BROKER_URL:-http://localhost:8081}"
EOF

ok "wrote ${ENV_FILE}"
echo >&2
info "Next: source ${ENV_FILE} then run ./setup/demo.sh"
