"""Connect v2 capability definitions this provider advertises.

The app id matches the EOM funnel provider manifest in connect-contracts
(``fixtures/v2/valid/manifest-eom-funnel-provider.json``) so the provider's served
manifest and the canonical contract fixtures agree. Each capability object here is
kept byte-identical to its canonical manifest object (asserted by
``test_contract_conformance``); connect-contracts is the source of truth for shape.

The ``REGISTRY`` is the provider's single source of truth: both ``manifest()`` (what
is served) and the provider's validate/dispatch path consult it, so the advertised
manifest and the accepted job envelope cannot drift. Each entry pairs the wire
capability object with the small amount of envelope metadata the provider needs to
validate an incoming job and shape the outgoing status (input media type, size cap,
produced media type, output name) and the dispatch ``kind`` (a read vs a money path).
"""

from __future__ import annotations

from dataclasses import dataclass

APP_ID = "eom-funnel-provider"
APP_NAME = "EOM Funnel Local Connect Provider"
APP_VERSION = "0.1.0"

# Read: the device work-queue poll. Maps to GET /api/connect/device/funnel/leads.
REVIEW_QUEUE_LIST_CAPABILITY_ID = "lead.review-queue.list"
REVIEW_QUEUE_MEDIA_TYPE = "application/vnd.eom.funnel-review-queue+json"

# Read: the issued onboarding links poll. Maps to
# GET /api/connect/device/funnel/public-onboarding/issued-links.
PUBLIC_LINK_LIST_CAPABILITY_ID = "onboarding.public-link.list"
PUBLIC_LINK_LIST_MEDIA_TYPE = "application/vnd.eom.onboarding.issued-link-list+json"

# Money: approve-and-send an onboarding draft. Maps to the tracker device money path
# POST /api/connect/device/funnel/onboarding-drafts/{draft_id}/approve-send.
APPROVE_SEND_CAPABILITY_ID = "onboarding.draft.approve-send"
APPROVE_SEND_INPUT_MEDIA_TYPE = "application/vnd.eom.onboarding-draft-approval+json"
APPROVE_SEND_RECEIPT_MEDIA_TYPE = "application/vnd.eom.onboarding-draft-send-receipt+json"

# Money: book an estimate or a first clean for a lead. Map to the tracker device
# booking money paths POST /api/connect/device/funnel/leads/{contact_id}/{...}-bookings.
ESTIMATE_BOOKING_CAPABILITY_ID = "lead.estimate-booking"
ESTIMATE_BOOKING_INPUT_MEDIA_TYPE = "application/vnd.eom.estimate-booking+json"
ESTIMATE_BOOKING_RECEIPT_MEDIA_TYPE = "application/vnd.eom.estimate-booking-receipt+json"
FIRST_CLEAN_BOOKING_CAPABILITY_ID = "lead.first-clean-booking"
FIRST_CLEAN_BOOKING_INPUT_MEDIA_TYPE = "application/vnd.eom.first-clean-booking+json"
FIRST_CLEAN_BOOKING_RECEIPT_MEDIA_TYPE = "application/vnd.eom.first-clean-booking-receipt+json"

# Money: finalize one tracker-created Customer/Site against a lead. Maps to the
# tracker device money path POST /api/connect/device/funnel/leads/{contact_id}/customer-handoffs.
CUSTOMER_HANDOFF_CAPABILITY_ID = "lead.customer-handoff"
CUSTOMER_HANDOFF_INPUT_MEDIA_TYPE = "application/vnd.eom.customer-handoff+json"
CUSTOMER_HANDOFF_RECEIPT_MEDIA_TYPE = "application/vnd.eom.customer-handoff-receipt+json"

# Money: claim a review-queue lead as being worked. Maps to the tracker device money
# path POST /api/connect/device/funnel/leads/{contact_id}/working.
MARK_WORKING_CAPABILITY_ID = "lead.mark-working"
MARK_WORKING_INPUT_MEDIA_TYPE = "application/vnd.eom.mark-working+json"
MARK_WORKING_RECEIPT_MEDIA_TYPE = "application/vnd.eom.mark-working-receipt+json"

# Reads carry an empty artifact (limit/cursor ride in job parameters, matching the
# canonical read convention). Money paths carry a small opaque vendor JSON artifact;
# bookings carry the appointment window, so they get the larger canonical cap.
READ_MAX_INPUT_BYTES = 1024
MONEY_MAX_INPUT_BYTES = 1024
BOOKING_MAX_INPUT_BYTES = 8192

# Dispatch kinds.
KIND_READ = "read"
KIND_MONEY = "money"


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


def public_link_list_capability() -> dict[str, object]:
    return {
        "id": PUBLIC_LINK_LIST_CAPABILITY_ID,
        "version": "1.0",
        "action": {
            "label": "List issued onboarding links",
            # Byte-identical to the connect-contracts canonical manifest object.
            "description": (
                "List durable public-onboarding tokens that remain issued for office "
                "follow-up. Read-only projection; alters no handoff, delivery, or "
                "token state."
            ),
        },
        "accepts": [{"media_type": "application/json", "max_bytes": READ_MAX_INPUT_BYTES}],
        "produces": [PUBLIC_LINK_LIST_MEDIA_TYPE],
        "parameters": [
            {
                "name": "limit",
                "value_type": "integer",
                "required": False,
                "label": "Limit",
                "description": "Maximum number of issued links to return in one page.",
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


def approve_send_capability() -> dict[str, object]:
    return {
        "id": APPROVE_SEND_CAPABILITY_ID,
        "version": "1.0",
        "action": {
            "label": "Approve and send onboarding draft",
            # Byte-identical to the connect-contracts canonical manifest object
            # (see test_contract_conformance): the fixture is the source of truth.
            "description": (
                "Claim the pending onboarding draft, send it, and confirm delivery. "
                "The draft's status machine is the idempotency mechanism; an "
                "already-sent draft replays without a second send. This dispatches "
                "the onboarding email, so it requires a fresh operator approval."
            ),
        },
        "accepts": [
            {"media_type": APPROVE_SEND_INPUT_MEDIA_TYPE, "max_bytes": MONEY_MAX_INPUT_BYTES}
        ],
        "produces": [APPROVE_SEND_RECEIPT_MEDIA_TYPE],
        "parameters": [],
        "effects": {"external": True, "confirmation_required": True},
    }


def estimate_booking_capability() -> dict[str, object]:
    return {
        "id": ESTIMATE_BOOKING_CAPABILITY_ID,
        "version": "1.0",
        "action": {
            "label": "Book estimate appointment",
            # Byte-identical to the connect-contracts canonical manifest object.
            "description": (
                "Book an estimate appointment for a lead without converting it to a "
                "customer. Creates a durable booking and calendar event, and requires "
                "a fresh operator approval."
            ),
        },
        "accepts": [
            {"media_type": ESTIMATE_BOOKING_INPUT_MEDIA_TYPE, "max_bytes": BOOKING_MAX_INPUT_BYTES}
        ],
        "produces": [ESTIMATE_BOOKING_RECEIPT_MEDIA_TYPE],
        "parameters": [],
        "effects": {"external": True, "confirmation_required": True},
    }


def first_clean_booking_capability() -> dict[str, object]:
    return {
        "id": FIRST_CLEAN_BOOKING_CAPABILITY_ID,
        "version": "1.0",
        "action": {
            "label": "Book first cleaning",
            # Byte-identical to the connect-contracts canonical manifest object.
            "description": (
                "Book the first cleaning for a lead: the lead becomes won and an "
                "onboarding email draft is enqueued for office approval. Nothing is "
                "sent. Creates durable CRM state and a calendar event, and requires a "
                "fresh operator approval."
            ),
        },
        "accepts": [
            {
                "media_type": FIRST_CLEAN_BOOKING_INPUT_MEDIA_TYPE,
                "max_bytes": BOOKING_MAX_INPUT_BYTES,
            }
        ],
        "produces": [FIRST_CLEAN_BOOKING_RECEIPT_MEDIA_TYPE],
        "parameters": [],
        "effects": {"external": True, "confirmation_required": True},
    }


def customer_handoff_capability() -> dict[str, object]:
    return {
        "id": CUSTOMER_HANDOFF_CAPABILITY_ID,
        "version": "1.0",
        "action": {
            "label": "Hand off customer",
            # Byte-identical to the connect-contracts canonical manifest object.
            "description": (
                "Finalize exactly one tracker-created Customer/Site against an EOM "
                "lead. Creates durable CRM state and requires a fresh operator "
                "approval."
            ),
        },
        "accepts": [
            {"media_type": CUSTOMER_HANDOFF_INPUT_MEDIA_TYPE, "max_bytes": BOOKING_MAX_INPUT_BYTES}
        ],
        "produces": [CUSTOMER_HANDOFF_RECEIPT_MEDIA_TYPE],
        "parameters": [],
        "effects": {"external": True, "confirmation_required": True},
    }


def mark_working_capability() -> dict[str, object]:
    return {
        "id": MARK_WORKING_CAPABILITY_ID,
        "version": "1.0",
        "action": {
            "label": "Mark lead working",
            # Byte-identical to the connect-contracts canonical manifest object.
            "description": (
                "Claim a review-queue lead as being worked, so it is no longer "
                "offered to another operator. Optimistic on the lead's state token; "
                "a stale token conflicts. Creates durable state and requires a fresh "
                "operator approval."
            ),
        },
        "accepts": [
            {"media_type": MARK_WORKING_INPUT_MEDIA_TYPE, "max_bytes": MONEY_MAX_INPUT_BYTES}
        ],
        "produces": [MARK_WORKING_RECEIPT_MEDIA_TYPE],
        "parameters": [],
        "effects": {"external": True, "confirmation_required": True},
    }


@dataclass(frozen=True)
class CapabilitySpec:
    """A served capability plus the envelope metadata the provider validates against.

    ``definition`` is the exact wire object advertised in the manifest; the remaining
    fields are what the provider needs to validate an incoming job and shape the
    outgoing status without re-hardcoding any of it per capability.
    """

    definition: dict[str, object]
    kind: str
    input_media_type: str
    max_input_bytes: int
    produces_media_type: str
    output_display_name: str

    @property
    def capability_id(self) -> str:
        return str(self.definition["id"])

    @property
    def version(self) -> str:
        return str(self.definition["version"])


def _specs() -> list[CapabilitySpec]:
    return [
        CapabilitySpec(
            definition=review_queue_capability(),
            kind=KIND_READ,
            input_media_type="application/json",
            max_input_bytes=READ_MAX_INPUT_BYTES,
            produces_media_type=REVIEW_QUEUE_MEDIA_TYPE,
            output_display_name="funnel-review-queue.json",
        ),
        CapabilitySpec(
            definition=public_link_list_capability(),
            kind=KIND_READ,
            input_media_type="application/json",
            max_input_bytes=READ_MAX_INPUT_BYTES,
            produces_media_type=PUBLIC_LINK_LIST_MEDIA_TYPE,
            output_display_name="issued-onboarding-links.json",
        ),
        CapabilitySpec(
            definition=approve_send_capability(),
            kind=KIND_MONEY,
            input_media_type=APPROVE_SEND_INPUT_MEDIA_TYPE,
            max_input_bytes=MONEY_MAX_INPUT_BYTES,
            produces_media_type=APPROVE_SEND_RECEIPT_MEDIA_TYPE,
            output_display_name="onboarding-draft-send-receipt.json",
        ),
        CapabilitySpec(
            definition=estimate_booking_capability(),
            kind=KIND_MONEY,
            input_media_type=ESTIMATE_BOOKING_INPUT_MEDIA_TYPE,
            max_input_bytes=BOOKING_MAX_INPUT_BYTES,
            produces_media_type=ESTIMATE_BOOKING_RECEIPT_MEDIA_TYPE,
            output_display_name="estimate-booking-receipt.json",
        ),
        CapabilitySpec(
            definition=first_clean_booking_capability(),
            kind=KIND_MONEY,
            input_media_type=FIRST_CLEAN_BOOKING_INPUT_MEDIA_TYPE,
            max_input_bytes=BOOKING_MAX_INPUT_BYTES,
            produces_media_type=FIRST_CLEAN_BOOKING_RECEIPT_MEDIA_TYPE,
            output_display_name="first-clean-booking-receipt.json",
        ),
        CapabilitySpec(
            definition=customer_handoff_capability(),
            kind=KIND_MONEY,
            input_media_type=CUSTOMER_HANDOFF_INPUT_MEDIA_TYPE,
            max_input_bytes=BOOKING_MAX_INPUT_BYTES,
            produces_media_type=CUSTOMER_HANDOFF_RECEIPT_MEDIA_TYPE,
            output_display_name="customer-handoff-receipt.json",
        ),
        CapabilitySpec(
            definition=mark_working_capability(),
            kind=KIND_MONEY,
            input_media_type=MARK_WORKING_INPUT_MEDIA_TYPE,
            max_input_bytes=MONEY_MAX_INPUT_BYTES,
            produces_media_type=MARK_WORKING_RECEIPT_MEDIA_TYPE,
            output_display_name="mark-working-receipt.json",
        ),
    ]


# Single source of truth: both the served manifest and the provider's validate/dispatch
# path read from here, keyed by capability id.
REGISTRY: dict[str, CapabilitySpec] = {spec.capability_id: spec for spec in _specs()}


def capabilities() -> list[dict[str, object]]:
    return [spec.definition for spec in REGISTRY.values()]


def manifest(instance_id: str) -> dict[str, object]:
    return {
        "protocol_version": 2,
        "instance_id": instance_id,
        "app": {"id": APP_ID, "name": APP_NAME, "version": APP_VERSION},
        "capabilities": capabilities(),
    }
