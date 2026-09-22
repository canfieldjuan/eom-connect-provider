"""Local EOM Connect provider.

Fronts the EOM funnel over a per-PC Ed25519 device key that authenticates to the
tracker per request. No Atlas token or operator bearer ever lives on the PC.
"""

from __future__ import annotations

from .capabilities import (
    APP_ID,
    REVIEW_QUEUE_LIST_CAPABILITY_ID,
    REVIEW_QUEUE_MEDIA_TYPE,
    manifest,
)
from .enrollment import enroll
from .provider import EomFunnelProvider
from .store import (
    DeviceCredential,
    default_store_dir,
    load_credential,
    save_credential,
)
from .tracker_client import TrackerAuthError, TrackerClient, TrackerError

__all__ = [
    "APP_ID",
    "REVIEW_QUEUE_LIST_CAPABILITY_ID",
    "REVIEW_QUEUE_MEDIA_TYPE",
    "manifest",
    "enroll",
    "EomFunnelProvider",
    "DeviceCredential",
    "default_store_dir",
    "load_credential",
    "save_credential",
    "TrackerClient",
    "TrackerAuthError",
    "TrackerError",
]
