"""Where this provider registers itself on the PC, per OS.

The location is fixed by the host, not chosen here: the Automate host only discovers
providers under its own per-OS root (``connect_automate.connect._providers_directory``,
ADR-0005). This module mirrors that resolution exactly, and a test asserts the two
agree, so a provider started with no explicit ``runtime_dir`` always lands where the
host looks:

- an explicit ``runtime_dir`` (tests, a custom host root): ``<dir>/local-connect/v2/providers``;
- Windows: ``%LOCALAPPDATA%\\LocalConnect\\runtime\\v2\\providers``, created and written
  through the host's owner-private DACL helpers (``connect_automate.connect_windows``),
  because the host refuses a registration whose directory or file is not private;
- other OSes: ``$XDG_RUNTIME_DIR/local-connect/v2/providers`` (mode 0o700).
"""

from __future__ import annotations

import os
from pathlib import Path

PROTOCOL_VERSION = 2
MAX_REGISTRATION_BYTES = 64 * 1024


class PlacementError(RuntimeError):
    """The host's discovery root is unavailable on this PC."""


def _windows_root() -> Path:
    from connect_automate.connect_windows import local_app_data_root

    return local_app_data_root()


def providers_directory(
    runtime_dir: Path | None = None, *, os_name: str | None = None
) -> tuple[Path, Path]:
    """Return ``(root, providers_dir)`` exactly as the host resolves it."""
    name = os.name if os_name is None else os_name
    if runtime_dir is not None:
        root = Path(runtime_dir)
        return root, root / f"local-connect/v{PROTOCOL_VERSION}/providers"
    if name == "nt":
        try:
            root = _windows_root()
        except OSError as error:
            raise PlacementError(f"Local AppData is not usable: {error}") from error
        return root, root / f"LocalConnect/runtime/v{PROTOCOL_VERSION}/providers"
    value = os.environ.get("XDG_RUNTIME_DIR")
    if not value:
        raise PlacementError(
            "XDG_RUNTIME_DIR is not set, so the host cannot discover this provider."
        )
    root = Path(value)
    return root, root / f"local-connect/v{PROTOCOL_VERSION}/providers"


def ensure_providers_directory(root: Path, providers: Path) -> None:
    """Create the providers directory chain as the host requires it (owner-private).

    Matches the pre-existing POSIX behavior: the root and every component below it
    are 0o700. On Windows the host's helper creates each component with a protected,
    owner-only DACL and refuses an unsafe root.
    """
    if os.name == "nt":
        from connect_automate.connect_windows import ensure_private_directory

        ensure_private_directory(providers, root=root)
        return
    current = root
    for part in ("", *providers.relative_to(root).parts):
        current = current / part if part else current
        current.mkdir(mode=0o700, exist_ok=True)
        current.chmod(0o700)
