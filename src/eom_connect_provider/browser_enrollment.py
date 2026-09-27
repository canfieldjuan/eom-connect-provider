"""Enroll this PC by signing in through the browser, like an OAuth installed-app flow.

The office session token never leaves the operator's browser. This mirrors how the
other local apps authorize (the email watcher's Gmail and Microsoft sign-in open the
system browser and receive the result on a loopback listener), applied to the
tracker's existing proof-of-possession enrollment:

1. The provider generates the device keypair locally, starts a one-shot listener on
   ``127.0.0.1`` (random port), and opens the portal's ``/connect-enroll`` page with
   the port, a random ``state``, the label, and the public key in the URL fragment
   (never sent to any server).
2. The operator, signed in to the portal, checks the key fingerprint against the one
   printed here and clicks Authorize. The page requests an enrollment challenge with
   the operator's session and navigates the tab to ``/sign`` on the listener.
3. The listener checks ``state``, signs the challenge with the device key, and
   redirects back to the page with the signature (again in the fragment).
4. The page registers the device with the tracker and navigates to ``/done`` with the
   new device id; the listener checks ``state`` and stores ``{device_id, key}``.

Every hand-off is a top-level navigation, not a cross-origin request, so no browser
private-network or CORS rule is involved. ``state`` is a 256-bit secret known only to
this process and the page it opened, so another site cannot drive the listener.
"""

from __future__ import annotations

import hmac
import html
import re
import secrets
import threading
import urllib.parse
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TextIO
from uuid import UUID

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from .proof import b64u
from .store import DeviceCredential, default_store_dir, save_credential

ENROLL_PAGE_PATH = "/connect-enroll"
DEFAULT_TIMEOUT_S = 600
# The tracker's enrollment challenge is ASCII base64url + '.' + hex; bound it the
# same way the tracker's request model does (max 512).
_CHALLENGE_PATTERN = re.compile(r"[A-Za-z0-9_.\-]{1,512}")


class BrowserEnrollmentError(RuntimeError):
    """Browser enrollment did not complete (cancelled, timed out, or refused)."""


def key_fingerprint(public_key_b64u: str) -> str:
    """A short, human-comparable fingerprint of the device public key."""
    return f"{public_key_b64u[:4]}-{public_key_b64u[4:8]}-{public_key_b64u[8:12]}"


@dataclass
class _Session:
    private_key: Ed25519PrivateKey
    public_key_b64u: str
    state: str
    label: str
    portal_url: str
    done: threading.Event = field(default_factory=threading.Event)
    device_id: str | None = None
    error: str | None = None

    def page_url(self, port: int, **extra: str) -> str:
        fragment = urllib.parse.urlencode(
            {
                "port": str(port),
                "state": self.state,
                "label": self.label,
                "key": self.public_key_b64u,
                **extra,
            }
        )
        return f"{self.portal_url}{ENROLL_PAGE_PATH}#{fragment}"


class _Listener(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, session: _Session) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.session = session

    @property
    def port(self) -> int:
        return int(self.server_address[1])


class _Handler(BaseHTTPRequestHandler):
    server: _Listener

    def log_message(self, format: str, *args: object) -> None:
        return

    def _page(self, status: int, title: str, body: str) -> None:
        payload = (
            "<!doctype html><meta charset=utf-8>"
            f"<title>{html.escape(title)}</title>"
            f"<h1>{html.escape(title)}</h1><p>{html.escape(body)}</p>"
        ).encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        session = self.server.session
        parsed = urllib.parse.urlsplit(self.path)
        query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        state = query.get("state", "")
        if not hmac.compare_digest(state.encode(), session.state.encode()):
            self._page(403, "Not authorized", "This link does not belong to this enrollment.")
            return
        if session.done.is_set():
            self._page(409, "Already finished", "This enrollment has already finished.")
            return
        if parsed.path == "/sign":
            challenge = query.get("challenge", "")
            if not _CHALLENGE_PATTERN.fullmatch(challenge):
                self._page(400, "Invalid challenge", "The enrollment challenge is malformed.")
                return
            signature = b64u(session.private_key.sign(challenge.encode("ascii")))
            location = session.page_url(
                self.server.port, step="register", challenge=challenge, signature=signature
            )
            self.send_response(303)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        if parsed.path == "/done":
            device_id = query.get("deviceId", "")
            try:
                UUID(device_id)
            except ValueError:
                self._page(400, "Invalid device", "The device id returned is malformed.")
                return
            session.device_id = device_id
            session.done.set()
            self._page(200, "PC authorized", "This PC is enrolled. You can close this tab.")
            return
        if parsed.path == "/cancel":
            session.error = "enrollment was cancelled in the browser"
            session.done.set()
            self._page(200, "Enrollment cancelled", "Nothing was changed. You can close this tab.")
            return
        self._page(404, "Not found", "Unknown enrollment step.")


def enroll_via_browser(
    *,
    portal_url: str,
    label: str,
    store_dir: Path | None = None,
    open_browser: Callable[[str], object] = webbrowser.open,
    timeout_s: float = DEFAULT_TIMEOUT_S,
    stdout: TextIO | None = None,
) -> DeviceCredential:
    """Run the browser sign-in and persist the device credential; return it.

    Nothing is stored unless the browser completes ``/done`` with a device id for this
    exact ``state``; a cancel, a timeout, or a refused sign-in leaves the PC unenrolled.
    """
    private_key = Ed25519PrivateKey.generate()
    public_raw = private_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    session = _Session(
        private_key=private_key,
        public_key_b64u=b64u(public_raw),
        state=secrets.token_urlsafe(32),
        label=label,
        portal_url=portal_url.rstrip("/"),
    )
    listener = _Listener(session)
    thread = threading.Thread(target=listener.serve_forever, daemon=True)
    thread.start()
    try:
        url = session.page_url(listener.port)
        if stdout is not None:
            print(
                "Opening your browser to authorize this PC. Confirm the page shows key "
                f"fingerprint {key_fingerprint(session.public_key_b64u)}.\n"
                f"If the browser does not open, visit:\n{url}",
                file=stdout,
                flush=True,
            )
        open_browser(url)
        if not session.done.wait(timeout_s):
            raise BrowserEnrollmentError("timed out waiting for the browser to authorize this PC")
        if session.error is not None or session.device_id is None:
            raise BrowserEnrollmentError(session.error or "enrollment did not complete")
    finally:
        listener.shutdown()
        listener.server_close()
        thread.join(timeout=5)
    credential = DeviceCredential(device_id=session.device_id, private_key=private_key)
    save_credential(store_dir if store_dir is not None else default_store_dir(), credential)
    return credential
