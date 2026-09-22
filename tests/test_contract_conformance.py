"""Shared seam: the provider's served capabilities must match the canonical
connect-contracts manifest object, byte-for-byte.

connect-contracts is the single source of truth for capability shape. The runtime
provider defines its manifest in `capabilities.py`; this test asserts the two do
not drift. It is skip-if-absent (like the host-integration test's importorskip):
it needs the sibling connect-contracts checkout, located via `CONNECT_CONTRACTS_DIR`
or a known sibling path, and skips when neither is present (e.g. in this repo's own
CI, which has no sibling).
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from eom_connect_provider import capabilities

_MANIFEST_REL = "fixtures/v2/valid/manifest-eom-funnel-provider.json"


def _canonical_manifest_path() -> Path | None:
    candidates = []
    env = os.environ.get("CONNECT_CONTRACTS_DIR")
    if env:
        candidates.append(Path(env))
    # Known sibling layouts.
    candidates.append(Path("/home/user/canfieldjuan/connect-contracts"))
    candidates.append(Path(__file__).resolve().parents[2] / "connect-contracts")
    candidates.append(Path(__file__).resolve().parents[2] / "canfieldjuan" / "connect-contracts")
    for root in candidates:
        manifest = root / _MANIFEST_REL
        if manifest.is_file():
            return manifest
    return None


def _canonical_capability(manifest_path: Path, capability_id: str) -> dict:
    manifest = json.loads(manifest_path.read_text())
    for capability in manifest["capabilities"]:
        if capability["id"] == capability_id:
            return capability
    raise AssertionError(f"{capability_id} not in canonical manifest {manifest_path}")


@pytest.mark.parametrize("capability_id", sorted(capabilities.REGISTRY))
def test_served_capability_matches_canonical_manifest(capability_id):
    """Every capability the provider serves is byte-identical to its canonical
    connect-contracts manifest object. Covers new capabilities automatically as they
    are added to the registry, so the served manifest cannot drift from the contract."""
    manifest_path = _canonical_manifest_path()
    if manifest_path is None:
        pytest.skip("connect-contracts checkout not found; set CONNECT_CONTRACTS_DIR")
    canonical = _canonical_capability(manifest_path, capability_id)
    served = capabilities.REGISTRY[capability_id].definition
    # Round-trip the served object through JSON so bool/list types compare exactly
    # as the wire form the provider serves.
    served_wire = json.loads(json.dumps(served))
    assert served_wire == canonical
