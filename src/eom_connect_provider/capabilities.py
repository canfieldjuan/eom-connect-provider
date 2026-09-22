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

# The query artifact is empty; limit/cursor are job parameters, matching the
# canonical read convention (connect-contracts `onboarding.public-link.list`).
READ_MAX_INPUT_BYTES = 1024


def review_queue_capability() -> dict[str, object]:
    return {
        "id": REVIEW_QUEUE_LIST_CAPABILITY_ID,
        "version": "1.0",
        "action": {
            "label": "List funnel review queue",
            # Kept byte-identical to the connect-contracts canonical manifest object
            # (see test_contract_conformance): the fixture is the source of truth.
            "description": (
                "Poll the funnel review work-queue on the bound operator's behalf: "
                "new leads, working leads, and pending handoffs. Read-only "
                "projection; alters no lead, booking, or handoff state."
            ),
        },
        "accepts": [{"media_type": "application/json", "max_bytes": READ_MAX_INPUT_BYTES}],
        "produces": [REVIEW_QUEUE_MEDIA_TYPE],
        "parameters": [
            {
                "name": "limit",
                "value_type": "integer",
                "required": False,
                "label": "Limit",
                "description": "Maximum number of leads to return in one page.",
            },
            {
                "name": "cursor",
                "value_type": "string",
                "required": False,
                "label": "Cursor",
                "description": "Opaque pagination cursor returned by a prior page.",
            },
        ],
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
