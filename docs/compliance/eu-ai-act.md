# EU AI Act

The EU AI Act (Regulation 2024/1689) establishes requirements for AI systems operating in the EU.

**Dates, corrected 2026-09-19.** Regulation (EU) 2026/1744, in force 27 July 2026, deferred the
high-risk regime. Annex III obligations apply from **2 December 2027** and Annex I embedded
high-risk from **2 August 2028**. Article 50 transparency and the Chapter V general-purpose AI
obligations were not deferred and apply now. Two new Article 5 prohibitions apply from
2 December 2026. The previous text here said obligations take effect August 2, 2026, which was
the pre-amendment date. See `documentation/research/ai-regulation/01-eu.md` for the article-level
map and `09-verification-log.md` for the primary-source check.

---

## Article 12: Record-keeping

*High-risk AI systems shall be designed with logging capabilities that record events relevant to the functioning of the AI system.*

| Requirement | How Capsule Addresses It |
|---|---|
| Automatic logging of events | Every AI action produces a Capsule (the axiom: for all actions, there exists a Capsule) |
| Traceability of results | Execution section records tool calls; Outcome section records results and side effects |
| Monitoring of operation | Chain provides temporal ordering; session_id groups related interactions |
| Identification of risks | Reasoning section captures risk assessment in `ReasoningOption.risks` |

## Article 13: Transparency

*High-risk AI systems shall be designed to ensure their operation is sufficiently transparent.*

| Requirement | How Capsule Addresses It |
|---|---|
| Understandable output | Outcome section includes human-readable `summary` field |
| Explanation of decisions | Reasoning section captures analysis, options, and rationale *before* execution |
| Information for deployers | Capsules are queryable via storage backends; all fields are machine-readable |

## Article 14: Human Oversight

*High-risk AI systems shall be designed to be effectively overseen by natural persons.*

| Requirement | How Capsule Addresses It |
|---|---|
| Human-in-the-loop capability | Authority section supports `human_approved` type with `approver` identity |
| Ability to intervene | Kill switch Capsules (`CapsuleType.KILL`) record intervention events |
| Override capability | Authority section's `escalation_reason` documents why human override occurred |

---

[Back to Compliance Overview](./README.md)
