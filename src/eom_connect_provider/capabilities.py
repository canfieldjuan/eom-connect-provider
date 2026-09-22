"""Connect v2 capability definitions this provider advertises.

The app id matches the EOM funnel provider manifest in connect-contracts
(``fixtures/v2/valid/manifest-eom-funnel-provider.json``) so the provider's served
manifest and the canonical contract fixtures agree. This first slice advertises
one read capability, the funnel review-queue poll; the money paths are added as
later slices, each mapping to its existing device endpoint on the tracker.
"""

from __future__ import annotations

APP_ID = "eom-funnel-provider"
APP_NAME = "EOM Funnel Local Connect Provider"
APP_VERSION = "0.1.0"

# Read: the device work-queue poll. Maps to GET /api/connect/device/funnel/leads.
REVIEW_QUEUE_LIST_CAPABILITY_ID = "lead.review-queue.list"
REVIEW_QUEUE_MEDIA_TYPE = "application/vnd.eom.funnel-review-queue+json"

# The query artifact is a small JSON object: {"limit"?: int, "cursor"?: str}.
MAX_QUERY_BYTES = 64 * 1024


def review_queue_capability() -> dict[str, object]:
    return {
        "id": REVIEW_QUEUE_LIST_CAPABILITY_ID,
        "version": "1.0",
        "action": {
            "label": "List funnel review queue",
            "description": (
                "Poll the EOM funnel review work-queue on the bound operator's "
                "behalf. Read-only; performs no mutation and needs no confirmation."
            ),
        },
        "accepts": [{"media_type": "application/json", "max_bytes": MAX_QUERY_BYTES}],
        "produces": [REVIEW_QUEUE_MEDIA_TYPE],
        "parameters": [],
        "effects": {"external": False, "confirmation_required": False},
    }


def capabilities() -> list[dict[str, object]]:
    return [review_queue_capability()]


def manifest(instance_id: str) -> dict[str, object]:
    return {
        "protocol_version": 2,
        "instance_id": instance_id,
        "app": {"id": APP_ID, "name": APP_NAME, "version": APP_VERSION},
        "capabilities": capabilities(),
    }
