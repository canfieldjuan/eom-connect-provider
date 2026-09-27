"""Browser enrollment: the portal page and this listener hand off by top-level navigation.

Each test plays the portal page's part exactly as ``connect-enroll.js`` does it: read
the fragment, request a challenge with the office session, navigate to ``/sign``,
follow the redirect back, register the device with the tracker, navigate to
``/done``. The stub tracker verifies the challenge signature against the public key,
so a wrong key or signature fails here as it would in production.
"""

from __future__ import annotations

import io
import json
import threading
import urllib.error
import urllib.parse
import urllib.request

import pytest
from stub_tracker import StubTracker

from eom_connect_provider import browser_enrollment, cli, store
from eom_connect_provider.tracker_client import TrackerClient

_PORTAL = "https://portal.example.test"
_OFFICE_TOKEN = "office-session-token-stays-in-the-browser"


@pytest.fixture
def tracker():
    stub = StubTracker.start()
    yield stub
    stub.stop()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def _get(url: str) -> tuple[int, dict[str, str], str]:
    try:
        with _opener.open(url, timeout=10) as response:
            return response.status, dict(response.headers), response.read().decode()
    except urllib.error.HTTPError as error:
        return error.code, dict(error.headers), error.read().decode()


def _fragment(url: str) -> dict[str, str]:
    assert url.startswith(f"{_PORTAL}{browser_enrollment.ENROLL_PAGE_PATH}#"), url
    return dict(urllib.parse.parse_qsl(urllib.parse.urlsplit(url).fragment))


def _post_json(url: str, body: dict | None) -> dict:
    data = json.dumps(body).encode() if body is not None else b""
    request = urllib.request.Request(url, data=data, method="POST")
    request.add_header("Authorization", f"Bearer {_OFFICE_TOKEN}")
    request.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read())


def _loopback(params: dict[str, str], path: str, **query: str) -> str:
    return f"http://127.0.0.1:{params['port']}{path}?" + urllib.parse.urlencode(query)


def _portal_authorizes(tracker: StubTracker, page_url: str, seen: dict) -> None:
    """Play the portal page: challenge, /sign, register, /done."""
    params = _fragment(page_url)
    seen["params"] = params
    challenge = _post_json(
        f"{tracker.base_url}/api/admin/connect/devices/enrollment-challenge", None
    )["challenge"]
    status, headers, _ = _get(
        _loopback(params, "/sign", state=params["state"], challenge=challenge)
    )
    assert status == 303
    registration = _fragment(headers["Location"])
    seen["registration"] = registration
    assert registration["step"] == "register"
    assert registration["key"] == params["key"]
    device = _post_json(
        f"{tracker.base_url}/api/admin/connect/devices",
        {
            "label": registration["label"],
            "publicKey": registration["key"],
            "challenge": registration["challenge"],
            "signature": registration["signature"],
        },
    )
    seen["done"] = _get(
        _loopback(params, "/done", state=params["state"], deviceId=device["deviceId"])
    )


def _in_background(action):
    def open_browser(url: str) -> None:
        threading.Thread(target=action, args=(url,), daemon=True).start()

    return open_browser


def test_browser_enrollment_via_cli_stores_the_device_key(tracker, tmp_path):
    seen: dict = {}
    stdout = io.StringIO()
    code = cli.main(
        [
            "enroll",
            "--label",
            "Office desk",
            "--portal-url",
            _PORTAL,
            "--tracker-url",
            tracker.base_url,
            "--store-dir",
            str(tmp_path),
        ],
        stdin=io.StringIO(""),
        stdout=stdout,
        stderr=io.StringIO(),
        open_browser=_in_background(lambda url: _portal_authorizes(tracker, url, seen)),
    )
    assert code == cli.EXIT_OK
    credential = store.load_credential(tmp_path)
    assert credential is not None
    # The tracker registered exactly this PC's key, so device-signed calls work.
    assert credential.device_id in tracker.state.public_keys
    assert credential.public_key_b64u() == seen["params"]["key"]
    tracker.set_queue({"success": True, "leads": [], "workingLeads": []})
    assert TrackerClient(tracker.base_url, credential).get_funnel_leads(limit=1)["success"]
    # The operator is shown the fingerprint to compare with the page.
    fingerprint = browser_enrollment.key_fingerprint(seen["params"]["key"])
    assert fingerprint in stdout.getvalue()
    assert seen["params"]["label"] == "Office desk"
    assert seen["done"][0] == 200
    # The office session token never reached this process or its disk.
    for path in tmp_path.iterdir():
        assert _OFFICE_TOKEN not in path.read_text()


def test_wrong_state_is_refused_and_nothing_is_stored(tmp_path):
    seen: dict = {}

    def forged(url: str) -> None:
        params = _fragment(url)
        seen["sign"] = _get(_loopback(params, "/sign", state="x" * 43, challenge="c.1"))
        seen["done"] = _get(
            _loopback(
                params, "/done", state="x" * 43, deviceId="11111111-1111-4111-8111-111111111111"
            )
        )

    with pytest.raises(browser_enrollment.BrowserEnrollmentError, match="timed out"):
        browser_enrollment.enroll_via_browser(
            portal_url=_PORTAL,
            label="PC",
            store_dir=tmp_path,
            open_browser=_in_background(forged),
            timeout_s=1.5,
        )
    assert seen["sign"][0] == 403
    assert seen["done"][0] == 403
    assert store.load_credential(tmp_path) is None


def test_cancel_in_the_browser_stores_nothing(tmp_path):
    def cancel(url: str) -> None:
        params = _fragment(url)
        _get(_loopback(params, "/cancel", state=params["state"]))

    with pytest.raises(browser_enrollment.BrowserEnrollmentError, match="cancelled"):
        browser_enrollment.enroll_via_browser(
            portal_url=_PORTAL,
            label="PC",
            store_dir=tmp_path,
            open_browser=_in_background(cancel),
            timeout_s=10,
        )
    assert store.load_credential(tmp_path) is None


def test_malformed_values_are_rejected_without_finishing(tmp_path):
    seen: dict = {}

    def malformed_then_cancel(url: str) -> None:
        params = _fragment(url)
        seen["challenge"] = _get(
            _loopback(params, "/sign", state=params["state"], challenge="<script>")
        )
        seen["device"] = _get(
            _loopback(params, "/done", state=params["state"], deviceId="not-a-uuid")
        )
        _get(_loopback(params, "/cancel", state=params["state"]))

    with pytest.raises(browser_enrollment.BrowserEnrollmentError):
        browser_enrollment.enroll_via_browser(
            portal_url=_PORTAL,
            label="PC",
            store_dir=tmp_path,
            open_browser=_in_background(malformed_then_cancel),
            timeout_s=10,
        )
    assert seen["challenge"][0] == 400
    assert seen["device"][0] == 400
    assert store.load_credential(tmp_path) is None


def test_listener_binds_loopback_only_and_the_page_url_uses_the_fragment(tmp_path):
    seen: dict = {}

    def inspect(url: str) -> None:
        seen["url"] = url
        _get(_loopback(_fragment(url), "/cancel", state=_fragment(url)["state"]))

    with pytest.raises(browser_enrollment.BrowserEnrollmentError):
        browser_enrollment.enroll_via_browser(
            portal_url=_PORTAL,
            label="PC",
            store_dir=tmp_path,
            open_browser=_in_background(inspect),
            timeout_s=10,
        )
    split = urllib.parse.urlsplit(seen["url"])
    # Secrets ride in the fragment, which the browser never sends to the portal host.
    assert split.query == ""
    assert "state=" in split.fragment
    assert len(_fragment(seen["url"])["state"]) >= 43


@pytest.mark.parametrize("url", ["http://portal.example.com", "javascript:alert(1)"])
def test_insecure_portal_url_is_refused(url, tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(
            ["enroll", "--label", "PC", "--portal-url", url, "--store-dir", str(tmp_path)],
            stdin=io.StringIO(""),
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
    assert excinfo.value.code == 2
