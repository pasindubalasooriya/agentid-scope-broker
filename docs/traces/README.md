# Trace evidence

`traces-export.json` is a real export from Agent Manager's trace view, taken on 2026-09-18 against a local install. It is the evidence behind the before and after comparison, and it can be read without standing up the stack.

Seven traces, exported from the coordinator agent's Observability view.

## The two that matter

| Trace | Spans | What it shows |
| --- | --- | --- |
| `70eddc4eca0eace603bd580404363887` | 1 | **Before.** The coordinator calls the specialist directly. |
| `40a61dec5a21c0e9ee662555dbb0db3b` | 2 | **After.** The same call through the broker. |

Same task, same caller, same standing authority. Compare the `agentid.*` attributes.

Before, on `coordinator.delegate.baseline`:

```json
"agentid.broker.enabled": false,
"agentid.scope.original": "records:read records:list records:write",
"agentid.scope.original.count": 3
```

After, on `coordinator.delegate.broker`:

```json
"agentid.broker.enabled": true,
"agentid.scope.original": "records:read records:list records:write",
"agentid.scope.original.count": 3,
"agentid.scope.derived": "records:read",
"agentid.scope.derived.count": 1
```

The narrowing is the two attributes that exist on one side and not the other. The caller held the same three scopes either way. Only what reached the specialist changed.

The after trace also carries a child span, `broker.delegate`, from `service.name: agentid-scope-broker`. That span adds two things the parent cannot know:

```json
"agentid.subject": "coordinator-agent",
"agentid.specialist.status": 200
```

The broker naming the principal it acted for, and the specialist accepting the narrowed token. The nesting itself matters too. The baseline trace is one span with no children, because nothing sits between the two agents. The broker trace is a parent of 444ms containing a child of 386ms, which is the broker sitting in the request path.

## The other five

They are earlier runs, kept because they record two real defects rather than a clean result.

`9f4dd86fd9858da1` has `errorCount: 1`. That is the broker crashing at startup on an OpenTelemetry schema URL conflict between `resource.Default()` and a pinned semconv version. The coordinator's span records the failure because the broker never came up to answer. Two fixes came out of it. The resource is now built with `resource.NewSchemaless`, and a tracing setup failure no longer takes the broker down, it degrades to no tracing.

`122cf92511d81a97` and `3a31dffa9a0a7a5b` were recorded seconds apart and belong to the same delegation, but they have different trace ids and one span each. The broker was injecting trace context on the way out but never extracting it on the way in, so it started its own root span instead of joining the caller's trace. Compare them with `40a61dec`, which is the same delegation after the fix, as one trace of two spans.

Both were only findable by running the thing. Neither shows up in a unit test.

## Reproducing

```bash
source .env.demo
source .env.trace          # AMP_OTEL_ENDPOINT and AMP_AGENT_API_KEY
./setup/trace-compare.sh
```

Then open the coordinator agent in the console, go to Observability and Traces, and export.

## A note on what is in here

The export carries cluster identifiers: `openchoreo.dev/component-uid`, `environment-uid`, `project-uid`, and Kubernetes pod and node names. They are identifiers from a local throwaway cluster and are not credentials.

No token ever appears in a span attribute. The broker records scope strings, never the tokens carrying them. That is deliberate, and the export was scanned before being committed.
