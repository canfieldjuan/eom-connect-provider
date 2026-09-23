"""Device-signed HTTP client for the tracker's Connect device endpoints.

Every call here is authenticated purely by a per-request Ed25519 device proof
(`proof.access_proof_headers`); the tracker holds the Atlas token and relays on
the bound operator's behalf. This client signs the exact path and raw query it
sends, so the proof the tracker reconstructs matches byte-for-byte.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

from .proof import access_proof_headers
from .store import DeviceCredential

_DEFAULT_TIMEOUT_S = 30
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024

FUNNEL_LEADS_PATH = "/api/connect/device/funnel/leads"
ISSUED_LINKS_PATH = "/api/connect/device/funnel/public-onboarding/issued-links"
OPERATION_CHALLENGE_PATH = "/api/connect/device/operations/challenge"
APPROVE_SEND_PATH = "/api/connect/device/funnel/onboarding-drafts/{draft_id}/approve-send"
PUBLIC_LINK_REVOKE_PATH = "/api/connect/device/funnel/onboarding-drafts/{draft_id}/revoke-link"
ESTIMATE_BOOKING_PATH = "/api/connect/device/funnel/leads/{contact_id}/estimate-bookings"
FIRST_CLEAN_BOOKING_PATH = "/api/connect/device/funnel/leads/{contact_id}/first-clean-bookings"
CUSTOMER_HANDOFF_PATH = "/api/connect/device/funnel/leads/{contact_id}/customer-handoffs"
MARK_WORKING_PATH = "/api/connect/device/funnel/leads/{contact_id}/working"
LEAD_LOST_PATH = "/api/connect/device/funnel/leads/{contact_id}/lost"
LEAD_REOPEN_PATH = "/api/connect/device/funnel/leads/{contact_id}/reopen"


class TrackerError(Exception):
    """A tracker call failed. ``retryable`` steers the Connect error mapping."""

    def __init__(self, message: str, *, status: int | None = None, retryable: bool = False):
        super().__init__(message)
        self.status = status
        self.retryable = retryable


class TrackerAuthError(TrackerError):
    """The device or its bound operator is no longer authorized (401/403)."""


@dataclass
class TrackerClient:
    base_url: str
    credential: DeviceCredential
    timeout_s: int = _DEFAULT_TIMEOUT_S

    def _root(self) -> str:
        return self.base_url.rstrip("/")

    def get_funnel_leads(
        self, *, limit: int = 100, cursor: str | None = None
    ) -> dict[str, object]:
        """Device work-queue poll: relays the tracker's funnel review overlay.

        Read-only; carries no confirmation. Returns the tracker's JSON body
        (``success, leads, workingLeads, pendingHandoffs, cursor, hasMore,
        nextCursor, capabilities, capabilitiesDeclared``).
        """
        return self._paged_read(FUNNEL_LEADS_PATH, limit=limit, cursor=cursor)

    def list_issued_links(
        self, *, limit: int = 100, cursor: str | None = None
    ) -> dict[str, object]:
        """Device poll of the current issued-onboarding-link evidence.

        Read-only; carries no confirmation. Returns the tracker's JSON body
        (``success, links, limit, cursor, hasMore, nextCursor``).
        """
        return self._paged_read(ISSUED_LINKS_PATH, limit=limit, cursor=cursor)

    def _paged_read(
        self, path: str, *, limit: int, cursor: str | None
    ) -> dict[str, object]:
        """Shared device-signed GET for a limit/cursor read: sign the exact path and
        raw query we send so the proof the tracker reconstructs matches byte-for-byte.
        """
        params: list[tuple[str, str]] = [("limit", str(int(limit)))]
        if cursor:
            params.append(("cursor", cursor))
        query = urllib.parse.urlencode(params)
        headers = access_proof_headers(
            self.credential.private_key,
            self.credential.device_id,
            method="GET",
            path=path,
            query=query,
            body=b"",
        )
        url = f"{self._root()}{path}?{query}"
        return self._request("GET", url, headers=headers, body=None)

    def mint_operation_challenge(self) -> dict[str, object]:
        """Mint a single-use, short-lived anti-replay challenge for a money path.

        The device references the returned ``challengeId`` in the body of the money
        mutation its next proof signs, so dispatch consumes it exactly once. The
        request carries no body; the proof still binds the method and path.
        """
        headers = access_proof_headers(
            self.credential.private_key,
            self.credential.device_id,
            method="POST",
            path=OPERATION_CHALLENGE_PATH,
            query="",
            body=b"",
        )
        url = f"{self._root()}{OPERATION_CHALLENGE_PATH}"
        return self._request("POST", url, headers=headers, body=b"")

    def approve_send(
        self, draft_id: str, challenge_id: str, confirmation_id: str
    ) -> dict[str, object]:
        """Approve-and-send one onboarding draft on the bound operator's behalf.

        Confirmation-gated money path: carries the single-use ``challengeId`` and the
        operator's ``confirmationId`` for this exact draft. The draft id is the path
        parameter and its status machine is the tracker/Atlas idempotency mechanism,
        so an already-sent draft replays without a second send. Returns the tracker's
        sent receipt (``success, draftId, status, sentAt, idempotent``).
        """
        return self._draft_money_post(
            APPROVE_SEND_PATH, draft_id, challenge_id, confirmation_id
        )

    def revoke_public_link(
        self, draft_id: str, challenge_id: str, confirmation_id: str
    ) -> dict[str, object]:
        """Revoke one draft's issued public onboarding link for the bound operator.

        Confirmation-gated, keyed by the draft id like approve-send. Atlas's link state
        machine is the idempotency mechanism: an already-revoked link replays and a
        completed link conflicts (409). Returns the tracker's revocation receipt
        (``success, draftId, status, idempotent``).
        """
        return self._draft_money_post(
            PUBLIC_LINK_REVOKE_PATH, draft_id, challenge_id, confirmation_id
        )

    def _draft_money_post(
        self, path_template: str, draft_id: str, challenge_id: str, confirmation_id: str
    ) -> dict[str, object]:
        """Shared device-signed POST for a draft-keyed, confirmation-gated operation:
        the draft id is the path parameter and the body carries only the challenge and
        confirmation, so every draft operation signs identically."""
        return self._signed_json_post(
            path_template.format(draft_id=draft_id),
            {"challengeId": challenge_id, "confirmationId": confirmation_id},
        )

    def mark_lead_lost(
        self,
        contact_id: str,
        challenge_id: str,
        confirmation_id: str,
        reason_code: str,
        idempotency_key: str,
        note: str | None = None,
    ) -> dict[str, object]:
        """Disposition a lead as lost on the bound operator's behalf.

        Confirmation-gated: the operator's ``confirmationId`` is bound to this contact,
        reason code, and ``idempotencyKey`` (the note is not bound). The key is the
        durable identity Atlas dedupes a retry against. The note is omitted when
        absent. Returns the tracker's ``{success, lead}`` body.
        """
        fields: dict[str, object] = {
            "challengeId": challenge_id,
            "confirmationId": confirmation_id,
            "reasonCode": reason_code,
            "idempotencyKey": idempotency_key,
        }
        if note is not None:
            fields["note"] = note
        return self._signed_json_post(LEAD_LOST_PATH.format(contact_id=contact_id), fields)

    def reopen_lead(
        self, contact_id: str, challenge_id: str, confirmation_id: str, idempotency_key: str
    ) -> dict[str, object]:
        """Return a lost lead to its pre-loss active stage for the bound operator.

        Confirmation-gated: the ``confirmationId`` is bound to this contact and
        ``idempotencyKey``. A lead that is not lost conflicts (409). Returns the
        tracker's ``{success, lead}`` body.
        """
        return self._signed_json_post(
            LEAD_REOPEN_PATH.format(contact_id=contact_id),
            {
                "challengeId": challenge_id,
                "confirmationId": confirmation_id,
                "idempotencyKey": idempotency_key,
            },
        )

    def _signed_json_post(self, path: str, fields: dict[str, object]) -> dict[str, object]:
        """Device-signed JSON POST: serialize ``fields`` canonically, sign the exact
        method, path, empty query, and body bytes, and send those same bytes, so the
        proof the tracker reconstructs matches byte-for-byte."""
        body = json.dumps(fields, separators=(",", ":"), sort_keys=True).encode()
        headers = access_proof_headers(
            self.credential.private_key,
            self.credential.device_id,
            method="POST",
            path=path,
            query="",
            body=body,
        )
        url = f"{self._root()}{path}"
        return self._request("POST", url, headers=headers, body=body)

    def submit_booking(
        self,
        booking_path: str,
        contact_id: str,
        challenge_id: str,
        confirmation_id: str,
        scheduled_start: str,
        scheduled_end: str,
        idempotency_key: str,
    ) -> dict[str, object]:
        """Book an estimate or first clean for a lead on the bound operator's behalf.

        Confirmation-gated money path shared by both bookings (``booking_path`` picks
        which). Carries the single-use ``challengeId``, the operator's
        ``confirmationId``, the appointment window, and the client ``idempotencyKey``
        that is the durable identity a retry replays against, so Atlas does not
        double-book. Returns the tracker's booking receipt.
        """
        path = booking_path.format(contact_id=contact_id)
        body = json.dumps(
            {
                "challengeId": challenge_id,
                "confirmationId": confirmation_id,
                "scheduledStart": scheduled_start,
                "scheduledEnd": scheduled_end,
                "idempotencyKey": idempotency_key,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        headers = access_proof_headers(
            self.credential.private_key,
            self.credential.device_id,
            method="POST",
            path=path,
            query="",
            body=body,
        )
        url = f"{self._root()}{path}"
        return self._request("POST", url, headers=headers, body=body)

    def submit_customer_handoff(
        self,
        contact_id: str,
        challenge_id: str,
        confirmation_id: str,
        handoff: dict[str, object],
    ) -> dict[str, object]:
        """Finalize one tracker-created Customer/Site against a lead.

        Confirmation-gated money path on the shared money seam. ``handoff`` is the
        opaque office customer/site payload (the tracker validates it); this adds the
        provider-minted ``challengeId`` and the operator's ``confirmationId`` and
        posts to the device handoff route for ``contact_id`` (the payload's
        ``atlasContactId``, which the tracker requires to match the path). The
        tracker owns the durable reservation and 202-pending reconciliation; a 202 is
        surfaced as a retryable pending outcome (see ``_request``) so a re-POST
        replays the reservation rather than creating a second Customer/Site.
        """
        path = CUSTOMER_HANDOFF_PATH.format(contact_id=contact_id)
        body = json.dumps(
            {**handoff, "challengeId": challenge_id, "confirmationId": confirmation_id},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        headers = access_proof_headers(
            self.credential.private_key,
            self.credential.device_id,
            method="POST",
            path=path,
            query="",
            body=body,
        )
        url = f"{self._root()}{path}"
        return self._request("POST", url, headers=headers, body=body)

    def mark_lead_working(
        self, contact_id: str, challenge_id: str, confirmation_id: str, expected_state_token: str
    ) -> dict[str, object]:
        """Claim a review-queue lead as being worked on the bound operator's behalf.

        Confirmation-gated mutation on the shared money seam. Optimistic on the
        lead's ``expectedStateToken`` (read from the review queue); the tracker
        returns 409 if that token is stale. Returns the tracker's workingLead receipt.
        """
        path = MARK_WORKING_PATH.format(contact_id=contact_id)
        body = json.dumps(
            {
                "challengeId": challenge_id,
                "confirmationId": confirmation_id,
                "expectedStateToken": expected_state_token,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        headers = access_proof_headers(
            self.credential.private_key,
            self.credential.device_id,
            method="POST",
            path=path,
            query="",
            body=body,
        )
        url = f"{self._root()}{path}"
        return self._request("POST", url, headers=headers, body=body)

    def _request(
        self,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
    ) -> dict[str, object]:
        request = urllib.request.Request(url=url, method=method, data=body)
        for key, value in headers.items():
            request.add_header(key, value)
        if body is not None:
            request.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout_s) as response:
                status = response.status
                raw = response.read(_MAX_RESPONSE_BYTES + 1)
        except urllib.error.HTTPError as error:
            raw = error.read(_MAX_RESPONSE_BYTES + 1) if error.fp else b""
            detail = _error_detail(raw) or error.reason or "tracker request failed"
            status = int(error.code)
            if status in (401, 403):
                raise TrackerAuthError(detail, status=status, retryable=False) from error
            # 5xx and 429 are transient; other 4xx are caller errors.
            retryable = status >= 500 or status == 429
            raise TrackerError(detail, status=status, retryable=retryable) from error
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            # No HTTP response reached us: the effect is unknown, so retryable.
            raise TrackerError(
                f"tracker unreachable: {error}", status=None, retryable=True
            ) from error
        # 202 Accepted: the tracker reserved the operation but its external
        # finalization is still pending (e.g. an ambiguous Atlas result). It is not a
        # completed result, so surface it as retryable; a re-POST replays the
        # tracker's durable reservation rather than treating pending as done or
        # creating a second effect.
        if status == 202:
            raise TrackerError("tracker operation is pending", status=202, retryable=True)
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise TrackerError("tracker response too large", status=None, retryable=False)
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as error:
            raise TrackerError("tracker returned invalid JSON", status=None) from error
        if not isinstance(parsed, dict):
            raise TrackerError("tracker returned a non-object body", status=None)
        return parsed


def _error_detail(raw: bytes) -> str | None:
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    if isinstance(parsed, dict):
        for key in ("detail", "error", "message"):
            value = parsed.get(key)
            if isinstance(value, str) and value:
                return value
    return None
