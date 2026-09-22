from __future__ import annotations

import pytest
from stub_tracker import StubTracker

from eom_connect_provider import enrollment, store
from eom_connect_provider.tracker_client import TrackerAuthError, TrackerClient


@pytest.fixture
def tracker():
    stub = StubTracker.start()
    yield stub
    stub.stop()


def test_enroll_stores_credential_and_registers_device(tracker, tmp_path):
    credential = enrollment.enroll(
        base_url=tracker.base_url,
        office_bearer="office-session-token",
        label="Automation PC",
        store_dir=tmp_path,
    )
    # The credential is persisted and reloadable.
    loaded = store.load_credential(tmp_path)
    assert loaded is not None
    assert loaded.device_id == credential.device_id

    # The tracker registered exactly this device's public key, so a device-signed
    # read now authenticates end-to-end (proves the enrolled key is usable).
    assert tracker.state.public_keys[credential.device_id] == _raw_public(credential)
    tracker.set_queue({"success": True, "leads": [], "workingLeads": []})
    body = TrackerClient(tracker.base_url, loaded).get_funnel_leads(limit=25)
    assert body["success"] is True


def test_enroll_on_unreachable_tracker_raises_retryable(tmp_path):
    # A closed port yields a network error before any key is stored, mapped to a
    # retryable TrackerError so the caller can retry without a half-written store.
    from eom_connect_provider.tracker_client import TrackerError

    with pytest.raises(TrackerError) as excinfo:
        enrollment.enroll(
            base_url="http://127.0.0.1:1",
            office_bearer="s",
            label="PC",
            store_dir=tmp_path,
            timeout_s=2,
        )
    assert excinfo.value.retryable is True
    assert store.load_credential(tmp_path) is None


def test_device_read_with_wrong_key_is_rejected(tracker, tmp_path):
    # A credential whose public key the tracker does not know must be rejected,
    # proving the tracker verifies the proof rather than trusting the header.
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    stranger = store.DeviceCredential(
        device_id="00000000-0000-4000-8000-000000000000",
        private_key=Ed25519PrivateKey.generate(),
    )
    tracker.set_queue({"success": True, "leads": []})
    with pytest.raises(TrackerAuthError):
        TrackerClient(tracker.base_url, stranger).get_funnel_leads()


def _raw_public(credential):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return credential.private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
