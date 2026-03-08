# NIST RFI Submission

**Docket**: NIST-2025-0035 | Document 2026-00206
**Submitted**: March 2026
**Spec Version**: CPS v1.0

---

## Contents

| File | Type | Description |
|------|------|-------------|
| `comment.txt` | Normative | Cover letter submitted via regulations.gov |
| `Attachment1_CPS-RFI-Response.pdf` | Normative | Full RFI response (questions 1a, 1d, 2a, 2e, 3a, 3b, 4a, 4b, 4d, 5a, 5b) |
| `Attachment2_CPS-Specification-v1.0.txt` | Normative | CPS v1.0 protocol specification as submitted |
| `Attachment3_CPS-Golden-Test-Vectors.txt` | Normative | 15 golden test vectors for cross-implementation conformance |
| `checksums.txt` | Informative | SHA-256 hashes of all submission artifacts |

## Integrity Verification

```bash
cd nist-submission/
shasum -a 256 -c checksums.txt
```

All files in this directory are the exact artifacts submitted to NIST. They reflect the protocol state at the time of submission (CPS v1.0, 15 golden vectors). The repository has since evolved — see [CHANGELOG.md](../CHANGELOG.md) for differences.

## Repository Evolution

These files reflect the protocol at the time of submission. The repository continues to evolve — see [CHANGELOG.md](../CHANGELOG.md) for all changes since submission.
