# AgentID Scope Derivation Broker

A broker that gives an AI agent only the access one request needs, instead of the standing authority it was issued with.

It sits between two agents. When a coordinator agent delegates work to a specialist agent, the broker works out the smallest scope that particular task needs, exchanges the coordinator's token for one carrying only that scope, and forwards the call. Neither agent contains any scope logic.

Built against WSO2 Agent Manager and ThunderID, running locally.

## Why

Agent Manager issues each agent an identity per environment, and that identity does not vary with the work being done. In fact the starting point is sharper than over privileged. The agent API key Agent Manager mints today is a self signed JWT with no `scope` claim at all, and the AI Gateway policy in front of agents checks only the issuer and audience. Nothing in the path says what the holder may do, and nothing checks.

The derivation logic comes from the ICARC 2027 work on per request OAuth2 scope derivation for AI agents.

## How it works

```
coordinator                broker                    ThunderID          specialist
     |                       |                           |                   |
     |-- delegate ---------->|                           |                   |
     |   wide token          |-- verify (JWKS) --------->|                   |
     |                       |                           |                   |
     |                       |   derive(capability,      |                   |
     |                       |          depth, held)     |                   |
     |                       |                           |                   |
     |                       |-- token exchange -------->|                   |
     |                       |<-- narrowed token --------|                   |
     |                       |                           |                   |
     |                       |-- forward, narrow token ------------------>   |
     |                       |                           |    require_scope  |
     |<-- response ----------|<------------------------------------------    |
```

Four things worth knowing about the implementation.

- **The narrowing is a real RFC 8693 token exchange**, not a fresh client credentials token. An exchange is bounded by the subject token, so the result can never exceed what the caller held.
- **ThunderID drops over-requested scopes silently** and still answers 200. The broker compares the issued scope against what it asked for and fails the call when they differ, because otherwise a partial narrowing looks exactly like success.
- **Derivation needs no external state.** It uses the delegation request plus a static capability to scope map, intersected with what the caller actually holds. No policy store, no classifier, no network call.
- **Enforcement lives in the specialist**, as a FastAPI dependency. The product gateway has no scope concept today, so putting the check in the callee is the honest way to show the narrowing is real.

## Layout

| Path | What it is |
| --- | --- |
| [derivation/](derivation/) | The scope derivation library. Pure Go, standard library only. |
| [derivation/policy.json](derivation/policy.json) | The capability to scope map. |
| [broker/](broker/) | The broker service. Token verification, exchange, forwarding, tracing. |
| [agents/coordinator/](agents/coordinator/) | The delegating agent. |
| [agents/specialist/](agents/specialist/) | The receiving agent, and the scope enforcement. |
| [setup/](setup/) | ThunderID registration and the demo scripts. |
| [docs/traces/](docs/traces/) | A real trace export from a local run. The before and after evidence. |

## Running the demo

### Prerequisites

- A local WSO2 Agent Manager install, which brings ThunderID with it. On Windows this needs a Linux Docker host, so run the installer from WSL2.
- Go 1.24 or newer, Python 3.11 or newer, `jq` and `curl`.

### 1. Bring up Agent Manager

From a WSL2 shell:

```bash
docker run --rm -it --name amp-quick-start \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --network=host ghcr.io/wso2/amp-quick-start:v0.14.0
./install.sh
```

Takes 15 to 20 minutes and needs 8 GB RAM, 4 CPU and around 10 GB of disk. When it finishes, the Console is at `http://localhost:3000` with `admin` / `admin`, and ThunderID is at `http://thunder.amp.localhost:8080`.

### 2. Register the identities

```bash
THUNDER_BASE_URL=http://thunder.amp.localhost:8080 ./setup/register-thunder.sh
```

This creates the `specialist` resource server and its three scopes, a role carrying all three, a coordinator client holding that role, and a broker client with the token exchange grant. It is idempotent, and it writes `.env.demo` with everything the other scripts need.

The client secrets in this script are placeholder defaults for a throwaway local install, and `.env.demo` is gitignored. Override `COORDINATOR_CLIENT_SECRET` and `BROKER_CLIENT_SECRET` in the environment if you are running this anywhere that is not your own machine.

### 3. Start the three services

```bash
source .env.demo
python3 -m venv agents/specialist/.venv
agents/specialist/.venv/bin/pip install -r agents/specialist/requirements.txt
python3 -m venv agents/coordinator/.venv
agents/coordinator/.venv/bin/pip install -r agents/coordinator/requirements.txt

./setup/run-local.sh
```

### 4. Run the comparison

In another shell:

```bash
source .env.demo
./setup/demo.sh
```

It runs the same task twice, once direct and once through the broker, then proves the narrowed token is refused when it tries to write and accepted when it reads.

## Tests

```bash
# The derivation library and the broker, no cluster needed
go test ./...

# Scope enforcement in the specialist
cd agents/specialist && .venv/bin/pytest -q
```

The Go tests stand up a stubbed ThunderID and a stubbed specialist, sign real RS256 tokens and exercise the whole request path, including the case where Thunder silently drops a scope. The Python tests verify real signatures against a stubbed JWKS and cover both Phase 6 scenarios: a narrowed token refused for writing, and accepted for reading.

## Tracing

The broker and the coordinator tag their spans with the same attribute names, so the baseline trace and the broker trace can be read side by side.

| Attribute | Meaning |
| --- | --- |
| `agentid.scope.original` | What the caller held |
| `agentid.scope.derived` | What was actually issued for this call |
| `agentid.capability` | The capability that was derived for |
| `agentid.delegation.depth` | Hops so far |
| `agentid.broker.enabled` | False on the baseline path, true through the broker |

Set `AMP_OTEL_ENDPOINT` and `AMP_AGENT_API_KEY` to export into Agent Manager's collector. Without them, tracing is skipped rather than failing.

## Status and scope of the work

This is a demonstration and a portfolio artifact, not a production component. It is a standalone project and contains no changes to `wso2/agent-manager` or `thunder-id/thunderid`.

Known limits. One coordinator and one specialist, a single hop. The derivation policy is static. The depth ratchet is implemented and tested but a longer chain has not been run end to end.
