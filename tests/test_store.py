from __future__ import annotations

import os
import stat

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eom_connect_provider import store


def test_save_and_load_round_trip(tmp_path):
    private_key = Ed25519PrivateKey.generate()
    credential = store.DeviceCredential(device_id="dev-round-trip", private_key=private_key)
    path = store.save_credential(tmp_path, credential)
    assert path.exists()

    loaded = store.load_credential(tmp_path)
    assert loaded is not None
    assert loaded.device_id == "dev-round-trip"
    # Same key: identical raw private bytes.
    assert store._private_key_raw(loaded.private_key) == store._private_key_raw(private_key)


def test_missing_store_returns_none(tmp_path):
    assert store.load_credential(tmp_path) is None


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
def test_record_and_dir_are_owner_private(tmp_path):
    sub = tmp_path / "nested" / "LocalConnect"
    credential = store.DeviceCredential(
        device_id="dev-mode", private_key=Ed25519PrivateKey.generate()
    )
    path = store.save_credential(sub, credential)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(sub.stat().st_mode) == 0o700


def test_default_store_dir_uses_localconnect_namespace(monkeypatch):
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(store.os, "name", "posix")
    got = store.default_store_dir()
    assert got.name == "local-connect"
