# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Patent Pending — See PATENTS.md for details.
# Licensed under the Apache License, Version 2.0 with patent grant (Section 3).

"""
CLI: Command-line interface for Capsule verification, inspection, and key management.

Usage::

    capsule verify chain.json                     # Structural check
    capsule verify --full chain.json              # + content hashes
    capsule verify --signatures --db capsules.db  # + Ed25519 sigs
    capsule inspect --db capsules.db --seq 2      # Show capsule #2
    capsule keys info                             # Key metadata
    capsule keys rotate                           # Rotate to new epoch
    capsule keys export-public                    # Export public key
    capsule hash document.pdf                     # SHA3-256

Exit codes: 0 = pass, 1 = fail, 2 = error
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, TextIO

from qp_capsule.capsule import Capsule
from qp_capsule.keyring import Keyring
from qp_capsule.seal import Seal, compute_hash

_NO_COLOR = False


# ---------------------------------------------------------------------------
# ANSI helpers (stdlib only -- no rich, no click)
# ---------------------------------------------------------------------------


def _supports_color(stream: TextIO) -> bool:
    """Check if the stream supports ANSI escape codes."""
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


def _c(code: str, text: str) -> str:
    if _NO_COLOR:
        return text
    return f"\033[{code}m{text}\033[0m"


def _green(t: str) -> str:
    return _c("32", t)


def _red(t: str) -> str:
    return _c("31", t)


def _bold(t: str) -> str:
    return _c("1", t)


def _dim(t: str) -> str:
    return _c("2", t)


def _yellow(t: str) -> str:
    return _c("33", t)


# ---------------------------------------------------------------------------
# Verification result types
# ---------------------------------------------------------------------------


@dataclass
class VerifyError:
    """A single verification error."""

    sequence: int
    capsule_id: str
    error: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "sequence": self.sequence,
            "capsule_id": self.capsule_id,
            "error": self.error,
        }


@dataclass
class VerifyResult:
    """Complete chain verification result."""

    valid: bool
    level: str
    capsules_verified: int
    total_capsules: int
    errors: list[VerifyError] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "valid": self.valid,
            "level": self.level,
            "capsules_verified": self.capsules_verified,
            "total_capsules": self.total_capsules,
            "errors": [e.to_dict() for e in self.errors],
        }


# ---------------------------------------------------------------------------
# Capsule loading helpers
# ---------------------------------------------------------------------------


def _capsule_from_full_dict(data: dict[str, Any]) -> Capsule:
    """Reconstruct a Capsule from a dict that includes seal metadata."""
    capsule = Capsule.from_dict(data)
    capsule.hash = data.get("hash", "")
    capsule.signature = data.get("signature", "")
    capsule.signature_pq = data.get("signature_pq", "")
    signed_at = data.get("signed_at")
    if signed_at:
        capsule.signed_at = datetime.fromisoformat(signed_at)
    capsule.signed_by = data.get("signed_by", "")
    return capsule


def _capsule_to_full_dict(capsule: Capsule) -> dict[str, Any]:
    """Serialize a Capsule to a dict including seal metadata."""
    d = capsule.to_dict()
    d["hash"] = capsule.hash
    d["signature"] = capsule.signature
    d["signature_pq"] = capsule.signature_pq
    d["signed_at"] = capsule.signed_at.isoformat() if capsule.signed_at else None
    d["signed_by"] = capsule.signed_by
    return d


def _load_capsules_from_json(path: Path) -> list[Capsule]:
    """Load capsules from a JSON file (array of dicts or single dict)."""
    data = json.loads(path.read_text("utf-8"))
    if isinstance(data, dict):
        data = [data]
    if not isinstance(data, list):
        raise ValueError(f"Expected JSON array or object, got {type(data).__name__}")
    return [_capsule_from_full_dict(d) for d in data]


async def _load_capsules_from_db(db_path: str) -> list[Capsule]:
    """Load all capsules from SQLite, ordered by sequence."""
    from qp_capsule.storage import CapsuleStorage

    storage = CapsuleStorage(db_path=Path(db_path))
    try:
        return list(await storage.get_all_ordered())
    finally:
        await storage.close()


async def _load_capsules_from_pg(pg_url: str) -> list[Capsule]:  # pragma: no cover
    """Load all capsules from PostgreSQL, ordered by sequence."""
    from qp_capsule.storage_pg import PostgresCapsuleStorage

    storage = PostgresCapsuleStorage(pg_url)
    try:
        return list(await storage.get_all_ordered())
    finally:
        await storage.close()


# ---------------------------------------------------------------------------
# Core verification logic (pure, no I/O)
# ---------------------------------------------------------------------------


def verify_chain(
    capsules: list[Capsule],
    *,
    level: str = "structural",
    seal: Seal | None = None,
) -> VerifyResult:
    """
    Verify a chain of capsules.

    Levels:
        structural: sequence + previous_hash linkage
        full:       structural + recompute SHA3-256
        signatures: full + Ed25519 verification
    """
    total = len(capsules)
    errors: list[VerifyError] = []

    if not capsules:
        return VerifyResult(valid=True, level=level, capsules_verified=0, total_capsules=0)

    do_content = level in ("full", "signatures")
    do_sigs = level == "signatures"

    for i, capsule in enumerate(capsules):
        if capsule.sequence != i:
            msg = f"Sequence gap: expected {i}, got {capsule.sequence}"
            errors.append(VerifyError(i, str(capsule.id), msg))
            break

        if i == 0:
            if capsule.previous_hash is not None:
                msg = "Genesis capsule has previous_hash (should be null)"
                errors.append(VerifyError(0, str(capsule.id), msg))
                break
        else:
            if capsule.previous_hash != capsules[i - 1].hash:
                msg = f"Chain broken: previous_hash mismatch at sequence {i}"
                errors.append(VerifyError(i, str(capsule.id), msg))
                break

        if do_content:
            computed = compute_hash(capsule.to_dict())
            if computed != capsule.hash:
                errors.append(
                    VerifyError(i, str(capsule.id), f"Content hash mismatch at sequence {i}")
                )
                break

        if do_sigs and seal is not None:
            if not seal.verify(capsule):
                msg = f"Signature verification failed at sequence {i}"
                errors.append(VerifyError(i, str(capsule.id), msg))
                break

    return VerifyResult(
        valid=len(errors) == 0,
        level=level,
        capsules_verified=total if not errors else errors[0].sequence,
        total_capsules=total,
        errors=errors,
    )


# ---------------------------------------------------------------------------
# Output formatting
# ---------------------------------------------------------------------------


_LEVEL_DESCRIPTIONS: dict[str, str] = {
    "structural": "sequence + hash linkage",
    "full": "structural + SHA3-256 recomputation",
    "signatures": "full + Ed25519 verification",
}


def _print_verify_result(result: VerifyResult, capsules: list[Capsule]) -> None:
    """Print colored verification result to terminal."""
    print()
    print(_bold("Capsule Chain Verification"))
    print("=" * 50)
    desc = _LEVEL_DESCRIPTIONS.get(result.level, "")
    print(f"  Level: {result.level}" + (f" ({desc})" if desc else ""))
    print()

    for i, capsule in enumerate(capsules):
        h = capsule.hash[:12] + "..." if capsule.hash else "no hash"
        if i < result.capsules_verified:
            label = "genesis" if i == 0 else f"seq {i}"
            print(f"  {_green('✓')} Capsule #{i} ({label})  {_dim(h)}")
        elif result.errors and result.errors[0].sequence == i:
            print(f"  {_red('✗')} Capsule #{i}: {result.errors[0].error}")
        else:
            print(f"  {_dim('·')} Capsule #{i}  {_dim('(skipped)')}")

    print()
    if result.valid:
        print(f"  {_green('PASS')} -- {result.capsules_verified} capsules verified")
    else:
        print(
            f"  {_red('FAIL')} -- {result.capsules_verified} of "
            f"{result.total_capsules} capsules verified"
        )
    print()


def _print_inspect(capsule: Capsule) -> None:
    """Print full 6-section capsule inspection."""
    print()
    print(_bold("Capsule Inspection"))
    print("=" * 50)

    print(f"  ID:       {capsule.id}")
    print(f"  Type:     {capsule.type.value}")
    print(f"  Domain:   {capsule.domain}")
    print(f"  Sequence: {capsule.sequence}")
    pid = str(capsule.parent_id) if capsule.parent_id else "none"
    print(f"  Parent:   {pid}")

    _section_bar("Seal")
    print(f"  Hash:     {capsule.hash or 'not sealed'}")
    print(f"  Signed:   {capsule.signed_at.isoformat() if capsule.signed_at else 'n/a'}")
    print(f"  Key:      {capsule.signed_by or 'n/a'}")

    t = capsule.trigger
    _section_bar("1. Trigger")
    print(f"  Type:     {t.type}")
    print(f"  Source:   {t.source}")
    print(f"  Request:  {t.request}")
    print(f"  Time:     {t.timestamp.isoformat()}")

    c = capsule.context
    _section_bar("2. Context")
    print(f"  Agent:    {c.agent_id or 'n/a'}")
    print(f"  Session:  {c.session_id or 'n/a'}")

    r = capsule.reasoning
    _section_bar("3. Reasoning")
    print(f"  Analysis:   {r.analysis or 'n/a'}")
    n_opts = len(r.options)
    n_sel = sum(1 for o in r.options if o.selected)
    print(f"  Options:    {n_opts} considered, {n_sel} selected")
    print(f"  Selected:   {r.selected_option or 'n/a'}")
    print(f"  Confidence: {r.confidence}")
    print(f"  Model:      {r.model or 'n/a'}")

    a = capsule.authority
    _section_bar("4. Authority")
    print(f"  Type:     {a.type}")
    print(f"  Approver: {a.approver or 'n/a'}")

    e = capsule.execution
    _section_bar("5. Execution")
    print(f"  Tool Calls: {len(e.tool_calls)}")
    print(f"  Duration:   {e.duration_ms}ms")

    o = capsule.outcome
    _section_bar("6. Outcome")
    print(f"  Status:  {o.status}")
    print(f"  Summary: {o.summary or 'n/a'}")
    if o.error:
        print(f"  Error:   {o.error}")
    print()


def _section_bar(title: str) -> None:
    bar_width = 50
    label = f" {title} "
    dashes = bar_width - len(label) - 2
    print(f"  {_dim('──' + label + '─' * max(dashes, 0))}")


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------


def cmd_verify(args: argparse.Namespace) -> int:
    """Execute the ``verify`` command."""
    has_db = bool(getattr(args, "db", None))
    has_pg = bool(getattr(args, "pg", None))
    sources = sum([bool(args.source), has_db, has_pg])
    if sources == 0:
        print("Error: specify a source (JSON file, --db, or --pg)", file=sys.stderr)
        return 2
    if sources > 1:
        print("Error: specify only one source", file=sys.stderr)
        return 2

    try:
        if args.source:
            capsules = _load_capsules_from_json(Path(args.source))
        elif args.db:
            capsules = asyncio.run(_load_capsules_from_db(args.db))
        else:  # pragma: no cover
            capsules = asyncio.run(_load_capsules_from_pg(args.pg))
    except Exception as e:
        print(f"Error loading capsules: {e}", file=sys.stderr)
        return 2

    seal = None
    if args.level == "signatures":
        keyring = Keyring()
        seal = Seal(keyring=keyring)

    result = verify_chain(capsules, level=args.level, seal=seal)

    if getattr(args, "json_output", False):
        print(json.dumps(result.to_dict(), indent=2))
    elif not getattr(args, "quiet", False):
        _print_verify_result(result, capsules)

    return 0 if result.valid else 1


def cmd_inspect(args: argparse.Namespace) -> int:
    """Execute the ``inspect`` command."""
    try:
        if args.source:
            capsules = _load_capsules_from_json(Path(args.source))
        elif getattr(args, "db", None):
            capsules = asyncio.run(_load_capsules_from_db(args.db))
        elif getattr(args, "pg", None):  # pragma: no cover
            capsules = asyncio.run(_load_capsules_from_pg(args.pg))
        else:
            print(
                "Error: specify a source (JSON file, --db, or --pg)",
                file=sys.stderr,
            )
            return 2
    except Exception as e:
        print(f"Error loading capsules: {e}", file=sys.stderr)
        return 2

    target: Capsule | None = None
    seq = getattr(args, "seq", None)
    cid = getattr(args, "id", None)

    if seq is not None:
        for c in capsules:
            if c.sequence == seq:
                target = c
                break
        if target is None:
            print(f"Error: no capsule with sequence {seq}", file=sys.stderr)
            return 2
    elif cid is not None:
        for c in capsules:
            if str(c.id) == cid:
                target = c
                break
        if target is None:
            print(f"Error: no capsule with id {cid}", file=sys.stderr)
            return 2
    elif len(capsules) == 1:
        target = capsules[0]
    else:
        print("Error: multiple capsules found, use --seq or --id", file=sys.stderr)
        return 2

    _print_inspect(target)
    return 0


def cmd_keys(args: argparse.Namespace) -> int:
    """Execute the ``keys`` subcommand."""
    sub = getattr(args, "keys_command", None)
    if sub is None:
        print("Error: specify a keys subcommand (info, rotate, export-public)", file=sys.stderr)
        return 2

    keyring = Keyring()

    if sub == "info":
        return _keys_info(keyring)
    if sub == "rotate":
        return _keys_rotate(keyring)
    if sub == "export-public":
        return _keys_export(keyring)
    return 2  # pragma: no cover


def _keys_info(keyring: Keyring) -> int:
    """Display keyring metadata and epoch history."""
    print()
    print(_bold("Key Management Info"))
    print("=" * 50)
    print(f"  Keyring: {keyring.path}")

    epochs = keyring.epochs
    if not epochs:
        print(f"  Status:  {_yellow('No keys')}")
        print()
        print("  Run 'capsule keys rotate' to generate a key pair.")
        print()
        return 0

    active = keyring.get_active()
    print(f"  Version: {Keyring.KEYRING_VERSION}")
    print(f"  Active:  Epoch {keyring.active_epoch}")
    print()

    for ep in epochs:
        status_str = _green("active") if ep.status == "active" else _dim("retired")
        start = ep.created_at[:19]
        end = ep.rotated_at[:19] if ep.rotated_at else "present"
        print(
            f"    Epoch {ep.epoch}  {ep.algorithm}  "
            f"{ep.fingerprint}  {status_str}  ({start} to {end})"
        )

    if active:
        print()
        print(f"  Public key: {_dim(active.public_key_hex)}")
    print()
    return 0


def _keys_rotate(keyring: Keyring) -> int:
    """Rotate to a new key epoch."""
    old_active = keyring.get_active()
    new_epoch = keyring.rotate()

    print()
    print(_bold("Key Rotation"))
    print("=" * 50)
    if old_active:
        print(
            f"  Previous: Epoch {old_active.epoch} "
            f"({old_active.fingerprint}) {_dim('→ retired')}"
        )
    print(
        f"  New:      Epoch {new_epoch.epoch} "
        f"({new_epoch.fingerprint}) {_green('→ active')}"
    )
    print()
    print(f"  Private key: {keyring.key_path}")
    print(f"  Keyring:     {keyring.path}")
    print()
    return 0


def _keys_export(keyring: Keyring) -> int:
    """Export the active public key (hex, pipeable)."""
    pub = keyring.export_public_key()
    if pub is None:
        print("Error: no active key. Run 'capsule keys rotate' first.", file=sys.stderr)
        return 2
    print(pub)
    return 0


def cmd_hash(args: argparse.Namespace) -> int:
    """Execute the ``hash`` command."""
    path = Path(args.file)
    if not path.exists():
        print(f"Error: file not found: {path}", file=sys.stderr)
        return 2

    data = path.read_bytes()
    print(hashlib.sha3_256(data).hexdigest())
    return 0


# ---------------------------------------------------------------------------
# Parser and entry point
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="capsule",
        description="Capsule Protocol -- verify, inspect, and manage cryptographic audit chains.",
    )
    parser.add_argument(
        "--version", action="version",
        version=f"capsule {__import__('qp_capsule').__version__}",
    )
    sub = parser.add_subparsers(dest="command")

    # -- verify --
    vp = sub.add_parser("verify", help="Verify chain integrity")
    vp.add_argument("source", nargs="?", default=None, help="JSON file path")
    vp.add_argument("--db", metavar="PATH", default=None, help="SQLite database path")
    vp.add_argument("--pg", metavar="URL", default=None, help="PostgreSQL connection URL")
    lvl = vp.add_mutually_exclusive_group()
    lvl.add_argument(
        "--structural", action="store_const", const="structural", dest="level",
        help="Sequence + hash linkage (default)",
    )
    lvl.add_argument(
        "--full", action="store_const", const="full", dest="level",
        help="Structural + recompute SHA3-256 from content",
    )
    lvl.add_argument(
        "--signatures", action="store_const", const="signatures", dest="level",
        help="Full + verify Ed25519 signatures via keyring",
    )
    vp.set_defaults(level="structural")
    vp.add_argument(
        "--json", action="store_true", dest="json_output",
        help="Machine-readable JSON output",
    )
    vp.add_argument(
        "--quiet", action="store_true",
        help="Exit code only (0=pass, 1=fail, 2=error)",
    )

    # -- inspect --
    ip = sub.add_parser("inspect", help="Inspect a single capsule")
    ip.add_argument("source", nargs="?", default=None, help="JSON file path")
    ip.add_argument("--db", metavar="PATH", default=None, help="SQLite database path")
    ip.add_argument("--pg", metavar="URL", default=None, help="PostgreSQL connection URL")
    ip.add_argument("--seq", type=int, default=None, help="Select by sequence number")
    ip.add_argument("--id", default=None, help="Select by capsule UUID")

    # -- keys --
    kp = sub.add_parser("keys", help="Key management")
    ks = kp.add_subparsers(dest="keys_command")
    ks.add_parser("info", help="Show key metadata and epoch history")
    ks.add_parser("rotate", help="Rotate to a new key epoch")
    ks.add_parser("export-public", help="Export the active public key (hex)")

    # -- hash --
    hp = sub.add_parser("hash", help="Compute SHA3-256 of a file")
    hp.add_argument("file", help="File to hash")

    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point. Returns exit code (0=pass, 1=fail, 2=error)."""
    global _NO_COLOR  # noqa: PLW0603
    _NO_COLOR = not _supports_color(sys.stdout)

    parser = _build_parser()
    args = parser.parse_args(argv)

    dispatch: dict[str | None, Any] = {
        "verify": cmd_verify,
        "inspect": cmd_inspect,
        "keys": cmd_keys,
        "hash": cmd_hash,
    }

    handler = dispatch.get(args.command)
    if handler is None:
        parser.print_help()
        return 2

    result: int = handler(args)
    return result


def _entry() -> None:  # pragma: no cover
    """Console script entry point (installed as ``capsule``)."""
    sys.exit(main())
