from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from eom_connect_provider import proof


def _tracker_signing_string(device_id, method, path, query, body, timestamp):
    # Byte-for-byte replica of the tracker's _connect_device_access_signing_string.
    return "\n".join(
        [
            "connect-device-access-v1",
            device_id,
            method.upper(),
            path,
            query,
            hashlib.sha256(body).hexdigest(),
            str(timestamp),
        ]
    ).encode("utf-8")


def test_signing_string_matches_tracker_construction():
    got = proof.access_signing_string(
        device_id="dev-1",
        method="get",
        path="/api/connect/device/funnel/leads",
        query="limit=100",
        body=b"",
        timestamp=1_700_000_000,
    )
    assert got == _tracker_signing_string(
        "dev-1", "GET", "/api/connect/device/funnel/leads", "limit=100", b"", 1_700_000_000
    )


def test_proof_headers_verify_against_public_key():
    private_key = Ed25519PrivateKey.generate()
    headers = proof.access_proof_headers(
        private_key,
        "dev-9",
        method="GET",
        path="/api/connect/device/funnel/leads",
        query="limit=50",
        body=b"",
        timestamp=1_700_000_123,
    )
    assert headers[proof.DEVICE_HEADER] == "dev-9"
    assert headers[proof.TIMESTAMP_HEADER] == "1700000123"
    signing_string = _tracker_signing_string(
        "dev-9", "GET", "/api/connect/device/funnel/leads", "limit=50", b"", 1_700_000_123
    )
    # A verifier (the tracker) reconstructs the same string and checks the sig.
    signature = _b64u_decode(headers[proof.SIGNATURE_HEADER])
    private_key.public_key().verify(signature, signing_string)


def _b64u_decode(value: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
