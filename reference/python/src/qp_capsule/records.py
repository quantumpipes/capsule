# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0

"""Bounded raw evidence, separate from parsing, signature trust and authorization."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum
from typing import Protocol, runtime_checkable
from uuid import UUID

from qp_capsule.exceptions import StorageError

DEFAULT_CONTENT_BYTES = 64 * 1024
MAX_CONTENT_BYTES = 1024 * 1024

# Names are internal SQL identifiers, never caller input. Each envelope component
# has a separate ceiling so an oversized signature cannot bypass the content cap.
RECORD_FIELDS = (
    ("id", 36, False),
    ("data", DEFAULT_CONTENT_BYTES, False),
    ("hash", 64, False),
    ("signature", 128, False),
    ("signature_pq", 6618, True),
    ("signed_at", 64, True),
    ("signed_by", 256, True),
)


class RecordReadCode(StrEnum):
    """Finite raw-read errors; absence is represented by None, never an error."""

    INVALID_ID = "invalid_id"
    INVALID_SCOPE = "invalid_scope"
    INVALID_LIMIT = "invalid_limit"
    UNSUPPORTED = "unsupported"
    UNAVAILABLE = "unavailable"
    SCHEMA_UNSUPPORTED = "schema_unsupported"
    TOO_LARGE = "too_large"
    INVALID_RECORD = "invalid_record"
    BUSY = "busy"
    DEADLINE = "deadline"
    OVERLOADED = "overloaded"


class RecordReadError(StorageError):
    """A finite error containing no document, key, database path or driver message."""

    def __init__(self, code: RecordReadCode) -> None:
        self.code = code
        super().__init__(code.value)


@dataclass(frozen=True, slots=True)
class RawCapsuleRecord:
    """Owned bytes from one database snapshot, with no claim of cryptographic trust.

    Content remains unparsed so a strict consumer can reject duplicate members,
    excessive nesting and malformed UTF-8 before constructing a Capsule. The
    consumer must compare the signed ID and scope with its trusted request.
    """

    capsule_id: UUID
    content: bytes
    hash: bytes
    signature: bytes
    signature_pq: bytes
    signed_at: bytes | None
    signed_by: bytes | None


@runtime_checkable
class CapsuleRecordReader(Protocol):
    """Optional additive capability; the legacy storage protocol stays unchanged."""

    async def read_record(
        self,
        capsule_id: UUID,
        *,
        tenant_id: str | None,
        max_content_bytes: int = DEFAULT_CONTENT_BYTES,
    ) -> RawCapsuleRecord | None:
        """Read an exact bounded record without application data/schema writes.

        Args:
            capsule_id: Full UUID, not a prefix or a coercible string.
            tenant_id: Exact storage partition, with None meaning the global partition.
            max_content_bytes: Trusted caller's content ceiling, at most one MiB.
        Returns:
            One raw snapshot, or None only when an available store lacks that ID.
        Raises:
            RecordReadError: Invalid input, unavailable store or bounded-read failure.
        """
        ...


def validate_read(capsule_id: UUID, max_content_bytes: int) -> None:
    """Reject ambiguous identifiers and invalid caller limits before any I/O."""
    if type(capsule_id) is not UUID:
        raise RecordReadError(RecordReadCode.INVALID_ID)
    if type(max_content_bytes) is not int or not 1 <= max_content_bytes <= MAX_CONTENT_BYTES:
        raise RecordReadError(RecordReadCode.INVALID_LIMIT)


def record_from_columns(capsule_id: UUID, columns: Sequence[bytes | None]) -> RawCapsuleRecord:
    """Own an already bounded column snapshot, retaining content bytes unchanged."""
    row_id, content, digest, signature, pq, signed_at, signed_by = columns
    if (
        row_id != str(capsule_id).encode("ascii")
        or content is None
        or digest is None
        or signature is None
    ):
        raise RecordReadError(RecordReadCode.INVALID_RECORD)
    return RawCapsuleRecord(capsule_id, content, digest, signature, pq or b"", signed_at, signed_by)
