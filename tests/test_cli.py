"""The provider command line: enroll this PC once, then run where the host finds it."""

from __future__ import annotations

import io
import json
import threading
import time

import pytest
from stub_tracker import StubTracker

from eom_connect_provider import capabilities, cli, store

connect = pytest.importorskip("connect_automate.connect")

_TOKEN = "office-session-token-not-to-be-stored"


@pytest.fixture
def tracker():
    stub = StubTracker.start()
    yield stub
    stub.stop()


@pytest.fixture(autouse=True)
def _active_entitlement(monkeypatch):
    monkeypatch.setattr(
        connect.entitlement,
        "connect_entitlement_decision",
        lambda: connect.entitlement.EntitlementDecision.ACTIVE,
    )


def _enroll(tracker, store_dir, token=_TOKEN):
    stdout, stderr = io.StringIO(), io.StringIO()
    code = cli.main(
        [
            "enroll",
            "--paste-token",
            "--label",
            "Office desk",
            "--tracker-url",
            tracker.base_url,
            "--store-dir",
            str(store_dir),
        ],
        stdin=io.StringIO(token + "\n"),
        stdout=stdout,
        stderr=stderr,
    )
    return code, stdout.getvalue(), stderr.getvalue()


def test_paste_token_enroll_stores_only_the_device_key(tracker, tmp_path):
    code, out, err = _enroll(tracker, tmp_path)
    assert code == cli.EXIT_OK, err
    credential = store.load_credential(tmp_path)
    assert credential is not None
    assert credential.device_id in out
    assert credential.device_id in tracker.state.public_keys
    # The office session token is used for enrollment only; it is never persisted.
    for path in tmp_path.iterdir():
        assert _TOKEN not in path.read_text()


def test_enroll_refuses_a_second_enrollment(tracker, tmp_path):
    assert _enroll(tracker, tmp_path)[0] == cli.EXIT_OK
    enrolled = len(tracker.state.public_keys)
    code, _, err = _enroll(tracker, tmp_path)
    assert code == cli.EXIT_USAGE
    assert "already enrolled" in err
    # No second device row was created on the tracker.
    assert len(tracker.state.public_keys) == enrolled


def test_enroll_without_a_token_stores_nothing(tracker, tmp_path):
    code, _, err = _enroll(tracker, tmp_path, token="")
    assert code == cli.EXIT_USAGE
    assert "No office session token" in err
    assert store.load_credential(tmp_path) is None


@pytest.mark.parametrize(
    "url", ["http://tracker.example.com", "ftp://127.0.0.1", "not a url"]
)
def test_enroll_refuses_an_insecure_tracker_url(url, tmp_path):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(
            [
                "enroll",
                "--paste-token",
                "--label",
                "PC",
                "--tracker-url",
                url,
                "--store-dir",
                str(tmp_path),
            ],
            stdin=io.StringIO(_TOKEN + "\n"),
            stdout=io.StringIO(),
            stderr=io.StringIO(),
        )
    assert excinfo.value.code == 2


def test_run_without_enrollment_explains_what_to_do(tmp_path):
    stderr = io.StringIO()
    code = cli.main(
        ["run", "--store-dir", str(tmp_path), "--runtime-dir", str(tmp_path / "rt")],
        stop=threading.Event(),
        stdout=io.StringIO(),
        stderr=stderr,
    )
    assert code == cli.EXIT_USAGE
    assert "not enrolled" in stderr.getvalue()


def test_run_registers_where_the_host_discovers_and_serves_until_stopped(
    tracker, tmp_path, monkeypatch
):
    # Enroll, then run with NO explicit runtime dir: the provider must register at
    # the host's default discovery root, found by the host with no path hint.
    store_dir = tmp_path / "store"
    assert _enroll(tracker, store_dir)[0] == cli.EXIT_OK
    xdg = tmp_path / "xdg"
    xdg.mkdir(mode=0o700)
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(xdg))
    tracker.set_queue({"success": True, "leads": [{"contactId": "c1"}], "workingLeads": []})

    stop = threading.Event()
    stdout = io.StringIO()
    outcome: dict[str, int] = {}
    runner = threading.Thread(
        target=lambda: outcome.setdefault(
            "code",
            cli.main(
                ["run", "--tracker-url", tracker.base_url, "--store-dir", str(store_dir)],
                stop=stop,
                stdout=stdout,
                stderr=io.StringIO(),
            ),
        )
    )
    runner.start()
    try:
        providers = xdg / "local-connect/v2/providers"
        deadline = time.monotonic() + 10
        while not list(providers.glob("*.json")) and time.monotonic() < deadline:
            time.sleep(0.05)
        catalog = connect.discover_capabilities()
        items = {
            item.capability_id: item
            for item in catalog.items
            if item.app_id == capabilities.APP_ID
        }
        assert set(items) == set(capabilities.REGISTRY)
        capability = items[capabilities.REVIEW_QUEUE_LIST_CAPABILITY_ID]
        job = connect.prepare_capability_job(
            capability, b"", "application/json", "query.json", parameters={"limit": 5}
        )
        completed = connect.ConnectV2Client(capability).submit(job, b"")
        assert completed.status == "completed"
        assert json.loads(completed.result.outputs[0].payload)["leads"] == [
            {"contactId": "c1"}
        ]
    finally:
        stop.set()
        runner.join(timeout=10)
    assert outcome.get("code") == cli.EXIT_OK
    assert "Provider running" in stdout.getvalue()
    # Stopping removes the registration, so the host no longer discovers it.
    assert not list(providers.glob("*.json"))
