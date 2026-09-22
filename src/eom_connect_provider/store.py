"""Owner-private, atomic on-disk store for the per-PC device credential.

The only secret this provider holds is the Ed25519 device private key. There is no
Atlas token and no operator bearer on the PC (see the credential contract in the
tracker repo, `CONNECT_LOCAL_PROVIDER_CREDENTIAL_CONTRACT.md`). The key lives in
the same per-user private ``LocalConnect`` / ``local-connect`` namespace the host
entitlement uses, so the two agree on placement:

- Windows: ``%LOCALAPPDATA%\\LocalConnect``.
- Unix: ``$XDG_CONFIG_HOME/local-connect`` or ``~/.config/local-connect``.

The directory is created 0o700 and the record written 0o600 through a temp file
and ``os.replace`` so a crash never leaves a torn or world-readable key.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .proof import b64u

STORE_FILE_NAME = "eom-connect-device.json"
_RECORD_VERSION = 1


def default_store_dir() -> Path:
    """The per-user private directory the device record lives in."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
        return root / "LocalConnect"
    xdg = os.environ.get("XDG_CONFIG_HOME")
    root = Path(xdg) if xdg else Path.home() / ".config"
    return root / "local-connect"


def _ensure_private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.name != "nt":
        path.chmod(0o700)


@dataclass(frozen=True)
class DeviceCredential:
    device_id: str
    private_key: Ed25519PrivateKey

    def public_key_b64u(self) -> str:
        from cryptography.hazmat.primitives.serialization import (
            Encoding,
            PublicFormat,
        )

        raw = self.private_key.public_key().public_bytes(
            Encoding.Raw, PublicFormat.Raw
        )
        return b64u(raw)


def _private_key_raw(private_key: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives.serialization import (
        Encoding,
        NoEncryption,
        PrivateFormat,
    )

    return private_key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


def save_credential(store_dir: Path, credential: DeviceCredential) -> Path:
    """Atomically persist ``{device_id, private_key}`` 0o600 in ``store_dir``.

    In steady state the record holds exactly the current credential. (The
    ``pending_rotation`` block the credential contract describes is a later
    slice; this writer keeps a single record.)
    """
    _ensure_private_dir(store_dir)
    record = {
        "version": _RECORD_VERSION,
        "device_id": credential.device_id,
        "private_key_b64u": b64u(_private_key_raw(credential.private_key)),
    }
    path = store_dir / STORE_FILE_NAME
    temporary = path.with_name(f".{path.name}.{uuid4()}.tmp")
    try:
        with temporary.open("xb") as stream:
            if os.name != "nt":
                os.fchmod(stream.fileno(), 0o600)
            stream.write(json.dumps(record, separators=(",", ":"), sort_keys=True).encode())
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return path


def load_credential(store_dir: Path) -> DeviceCredential | None:
    """Return the stored credential, or ``None`` when the PC is not enrolled."""
    path = store_dir / STORE_FILE_NAME
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return None
    record = json.loads(raw)
    if not isinstance(record, dict) or record.get("version") != _RECORD_VERSION:
        raise ValueError("Unsupported device credential record")
    device_id = record.get("device_id")
    key_b64u = record.get("private_key_b64u")
    if not isinstance(device_id, str) or not isinstance(key_b64u, str):
        raise ValueError("Malformed device credential record")
    key_bytes = _b64u_decode(key_b64u)
    private_key = Ed25519PrivateKey.from_private_bytes(key_bytes)
    return DeviceCredential(device_id=device_id, private_key=private_key)


def _b64u_decode(value: str) -> bytes:
    import base64

    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)
