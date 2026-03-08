# Example Capsules

Real-world Capsule records showing the 6-section model in practice. Each file is the JSON output of `capsule.to_dict()` — the exact representation used for hashing and storage.

## Examples

| File | Type | Scenario |
|---|---|---|
| [deploy-to-production.json](./deploy-to-production.json) | AGENT | Production deployment with structured reasoning, human approval, and tool calls |
| [file-read-tool.json](./file-read-tool.json) | TOOL | Simple tool invocation by an agent |
| [kill-switch-activation.json](./kill-switch-activation.json) | KILL | Emergency stop triggered by anomaly detection |
| [chat-with-rag.json](./chat-with-rag.json) | CHAT | RAG query with source attribution and model metadata |
| [policy-denied-action.json](./policy-denied-action.json) | TOOL | Destructive action blocked by safety policy |
| [multi-step-workflow.json](./multi-step-workflow.json) | WORKFLOW | Three linked Capsules showing parent-child hierarchy |

## Structure

Every Capsule has six sections:

1. **Trigger** — What initiated this action
2. **Context** — System state at the time
3. **Reasoning** — Why this decision was made (captured before execution)
4. **Authority** — Who or what approved it
5. **Execution** — What tools were called
6. **Outcome** — What happened

Plus identity fields (`id`, `type`, `domain`) and chain fields (`sequence`, `previous_hash`).

Seal fields (`hash`, `signature`, `signature_pq`, `signed_at`, `signed_by`) are not shown — they are added by `Seal.seal()` and are not part of the canonical content.

## Generating Capsules

```python
from qp_capsule import Capsule, CapsuleType, TriggerSection
import json

capsule = Capsule(
    type=CapsuleType.AGENT,
    trigger=TriggerSection(source="my-agent", request="Do something"),
)

print(json.dumps(capsule.to_dict(), indent=2))
```

## Related

- [CPS Specification](../spec/) — Protocol rules and golden test vectors
- [Conformance Suite](../conformance/) — 16 golden test vectors
- [Python Reference](../reference/python/) — Python quickstart and API reference
