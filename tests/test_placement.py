"""The provider registers exactly where the Automate host discovers providers.

The host's resolution (``connect_automate.connect._providers_directory``) is the
source of truth; these tests pin the provider's mirror of it so the two cannot
drift. The Windows branch cannot run on this CI (it needs Windows DACL APIs), so its
path is checked against the host's literal and the host source is checked for that
same literal.
"""

from __future__ import annotations

import inspect
from pathlib import Path

import pytest

from eom_connect_provider import placement

connect = pytest.importorskip("connect_automate.connect")


def test_explicit_runtime_dir_matches_host(tmp_path):
    assert placement.providers_directory(tmp_path) == connect._providers_directory(
        tmp_path, placement.PROTOCOL_VERSION
    )


def test_default_xdg_root_matches_host(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(tmp_path))
    assert placement.providers_directory(None, os_name="posix") == connect._providers_directory(
        None, placement.PROTOCOL_VERSION
    )


def test_missing_xdg_root_is_an_explicit_error(monkeypatch):
    # The host cannot discover anything without it (its resolution returns None),
    # so starting the provider must fail loudly instead of registering nowhere.
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    assert connect._providers_directory(None, placement.PROTOCOL_VERSION) is None
    with pytest.raises(placement.PlacementError):
        placement.providers_directory(None, os_name="posix")


def test_windows_default_is_the_host_localappdata_runtime_root(tmp_path, monkeypatch):
    monkeypatch.setattr(placement, "_windows_root", lambda: tmp_path)
    root, providers = placement.providers_directory(None, os_name="nt")
    assert root == tmp_path
    assert providers == tmp_path / Path("LocalConnect/runtime/v2/providers")
    # Drift guard: the host still resolves Windows discovery to this same path.
    assert "LocalConnect/runtime/v{protocol_version}/providers" in inspect.getsource(
        connect._providers_directory
    )


def test_windows_root_failure_is_a_placement_error(monkeypatch):
    def unsafe():
        raise OSError("LOCALAPPDATA is not a safe directory")

    monkeypatch.setattr(placement, "_windows_root", unsafe)
    with pytest.raises(placement.PlacementError):
        placement.providers_directory(None, os_name="nt")


def test_posix_directories_are_owner_private(tmp_path):
    root = tmp_path / "xdg"
    _, providers = placement.providers_directory(root)
    placement.ensure_providers_directory(root, providers)
    for directory in (root, root / "local-connect", root / "local-connect/v2", providers):
        assert directory.is_dir()
        assert directory.stat().st_mode & 0o777 == 0o700
