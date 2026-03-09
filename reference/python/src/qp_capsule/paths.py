# Copyright 2026 Quantum Pipes Technologies, LLC
# SPDX-License-Identifier: Apache-2.0
#
# Patent Pending — See PATENTS.md for details.
# Licensed under the Apache License, Version 2.0 with patent grant (Section 3).

"""
Shared path utilities for Capsule.

Provides validated default paths for key storage and database files.
"""

from __future__ import annotations

import os
from pathlib import Path

from qp_capsule.exceptions import CapsuleError


def resolve_data_dir(data_dir: str) -> Path:
    """
    Validate and resolve a data directory path.

    Rejects paths containing '..' to prevent directory traversal.
    Returns the resolved (absolute, symlink-free) path.

    Args:
        data_dir: The directory path to validate.

    Returns:
        Resolved Path object.

    Raises:
        CapsuleError: If the path contains '..' components.
    """
    if ".." in Path(data_dir).parts:
        raise CapsuleError(
            "Data directory must not contain '..' components"
        )
    return Path(data_dir).resolve()


def default_key_path() -> Path:
    """Get default key path from environment or home directory."""
    data_dir = os.environ.get("QUANTUMPIPES_DATA_DIR")
    if data_dir:
        return resolve_data_dir(data_dir) / "key"
    return Path.home() / ".quantumpipes" / "key"


def default_keyring_path() -> Path:
    """Get default keyring path from environment or home directory."""
    data_dir = os.environ.get("QUANTUMPIPES_DATA_DIR")
    if data_dir:
        return resolve_data_dir(data_dir) / "keyring.json"
    return Path.home() / ".quantumpipes" / "keyring.json"


def default_db_path() -> Path:
    """Get default database path from environment or home directory."""
    data_dir = os.environ.get("QUANTUMPIPES_DATA_DIR")
    if data_dir:
        return resolve_data_dir(data_dir) / "capsules.db"
    return Path.home() / ".quantumpipes" / "capsules.db"
