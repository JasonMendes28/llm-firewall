# ADR-004: DistilBERT is loaded in-process at startup

**Status:** Accepted

## Context

The classifier could live in a separate service (torchserve, Triton, a
FastAPI sidecar) or in the firewall process itself.

## Decision

In-process. Loaded once at startup, held in memory, called synchronously from
the pipeline.

Artifact integrity: an optional SHA-256 pin (`CLASSIFIER_MODEL_SHA256`) makes
the classifier refuse to load an artifact whose hash doesn't match.

## Consequences

Positive:
- One fewer service in `docker-compose`, one fewer network hop, one fewer
  failure mode.
- Predictable latency: the classifier is on the local process's Python stack,
  not a network away.
- Simpler operational story for a portfolio project.

Negative:
- Scaling the ML layer independently is not possible; scale-out means more
  copies of the entire firewall (each with its own model in memory).
- Torch loads a lot of memory. Cold start is slow (multiple seconds). Not a
  problem for a long-running service, but every restart pays it.

## Future work

For deployments where the classifier is significantly heavier or is shared
across multiple firewalls, a v2 ADR would cover moving to a dedicated
inference service with a defined RPC boundary. The `Classifier` class already
has a clean interface (`predict(text) -> float`) that would map trivially to
a network call.
