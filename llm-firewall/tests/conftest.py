"""Shared pytest fixtures.

We keep imports here light — pulling in torch here would slow every test file's
collection. Torch-dependent fixtures live in the specific tests that need them.
"""

from __future__ import annotations

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(scope="session")
def rules_path() -> Path:
    """Absolute path to the shipped default rules file."""
    return REPO_ROOT / "rules" / "default_rules.yaml"
