"""Command line for the local EOM Connect provider: enroll this PC once, then run.

``eom-connect-provider enroll --label NAME`` binds this PC to an operator. By default
it opens the portal in the browser, where the signed-in operator authorizes the PC;
the office session token never leaves the browser (``browser_enrollment``). With
``--paste-token`` it instead reads the token from standard input (a hidden prompt when
run in a terminal; never a command-line argument, so it does not land in shell history
or the process list), uses it for the two enrollment calls, and drops it. Either way
only the device key is stored (credential contract, "Acquire").

``eom-connect-provider run`` loads the stored device key, serves the provider on
loopback, and registers it where the Automate host discovers providers, until
interrupted (Ctrl+C or SIGTERM), then removes its registration.
"""

from __future__ import annotations

import argparse
import getpass
import signal
import sys
import threading
import urllib.parse
import webbrowser
from collections.abc import Callable
from pathlib import Path
from typing import TextIO

from . import browser_enrollment, enrollment, placement, store
from .provider import EomFunnelProvider
from .tracker_client import TrackerAuthError, TrackerClient, TrackerError

DEFAULT_TRACKER_URL = "https://eom-timetracker.onrender.com"
DEFAULT_PORTAL_URL = "https://effinghamofficemaids.com"
_LOOPBACK_HOSTS = frozenset({"127.0.0.1", "localhost", "::1"})

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2


def _tracker_url(value: str) -> str:
    """Accept https, or plain http only to a loopback tracker (local testing).

    The office session token and every device-signed request travel to this URL,
    so a non-loopback plain-http URL is refused rather than risk sending them in
    the clear.
    """
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme == "https" and parsed.hostname:
        return value.rstrip("/")
    if parsed.scheme == "http" and parsed.hostname in _LOOPBACK_HOSTS:
        return value.rstrip("/")
    raise argparse.ArgumentTypeError(
        "URL must be https (plain http is allowed only for a loopback host)"
    )


def _label(value: str) -> str:
    """The tracker accepts a 1..128 character device label."""
    stripped = value.strip()
    if not 1 <= len(stripped) <= 128:
        raise argparse.ArgumentTypeError("label must be 1 to 128 characters")
    return stripped


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="eom-connect-provider",
        description="Local EOM Connect provider for the Automate host.",
    )
    commands = parser.add_subparsers(dest="command", required=True)

    enroll = commands.add_parser(
        "enroll", help="Bind this PC to your office account (one time)."
    )
    enroll.add_argument(
        "--label", type=_label, required=True, help="A name for this PC, e.g. 'Office desk'."
    )
    enroll.add_argument(
        "--paste-token",
        action="store_true",
        help="Read the office session token from a prompt instead of signing in "
        "through the browser.",
    )
    enroll.add_argument("--portal-url", type=_tracker_url, default=DEFAULT_PORTAL_URL)
    enroll.add_argument("--tracker-url", type=_tracker_url, default=DEFAULT_TRACKER_URL)
    enroll.add_argument("--store-dir", type=Path, default=None, help=argparse.SUPPRESS)

    run = commands.add_parser("run", help="Serve the provider until stopped.")
    run.add_argument("--tracker-url", type=_tracker_url, default=DEFAULT_TRACKER_URL)
    run.add_argument("--runtime-dir", type=Path, default=None, help=argparse.SUPPRESS)
    run.add_argument("--store-dir", type=Path, default=None, help=argparse.SUPPRESS)
    return parser


def _read_office_token(stdin: TextIO, stderr: TextIO) -> str:
    if stdin.isatty():
        return getpass.getpass("Office session token (hidden): ", stream=stderr).strip()
    return stdin.readline().strip()


def _enroll(
    args: argparse.Namespace,
    stdin: TextIO,
    stdout: TextIO,
    stderr: TextIO,
    open_browser: Callable[[str], object] | None,
) -> int:
    store_dir = args.store_dir if args.store_dir is not None else store.default_store_dir()
    existing = store.load_credential(store_dir)
    if existing is not None:
        # A second enrollment creates a second active device row rather than
        # replacing this one (credential contract, "Rotate"), so refuse instead of
        # silently leaving the old key active.
        print(
            f"This PC is already enrolled as device {existing.device_id}. "
            "Revoke it in the office portal before enrolling again.",
            file=stderr,
        )
        return EXIT_USAGE
    if not args.paste_token:
        try:
            credential = browser_enrollment.enroll_via_browser(
                portal_url=args.portal_url,
                label=args.label,
                store_dir=store_dir,
                open_browser=open_browser or webbrowser.open,
                stdout=stdout,
            )
        except browser_enrollment.BrowserEnrollmentError as error:
            print(f"Enrollment did not complete: {error}", file=stderr)
            return EXIT_FAILED
        print(f"Enrolled this PC as device {credential.device_id}.", file=stdout)
        return EXIT_OK
    office_token = _read_office_token(stdin, stderr)
    if not office_token:
        print("No office session token was provided.", file=stderr)
        return EXIT_USAGE
    try:
        credential = enrollment.enroll(
            base_url=args.tracker_url,
            office_bearer=office_token,
            label=args.label,
            store_dir=store_dir,
        )
    except TrackerAuthError as error:
        print(f"Enrollment was not authorized: {error}", file=stderr)
        return EXIT_FAILED
    except TrackerError as error:
        print(f"Enrollment failed: {error}", file=stderr)
        return EXIT_FAILED
    print(f"Enrolled this PC as device {credential.device_id}.", file=stdout)
    return EXIT_OK


def _run(
    args: argparse.Namespace,
    stop: threading.Event,
    stdout: TextIO,
    stderr: TextIO,
) -> int:
    store_dir = args.store_dir if args.store_dir is not None else store.default_store_dir()
    credential = store.load_credential(store_dir)
    if credential is None:
        print(
            "This PC is not enrolled. Run: eom-connect-provider enroll --label <name>",
            file=stderr,
        )
        return EXIT_USAGE
    client = TrackerClient(args.tracker_url, credential)
    try:
        provider = EomFunnelProvider.start(args.runtime_dir, client)
    except placement.PlacementError as error:
        print(f"Cannot register with the Automate host: {error}", file=stderr)
        return EXIT_USAGE
    try:
        print(
            f"Provider running as {provider.instance_id} "
            f"(registered at {provider.registration_path}). Press Ctrl+C to stop.",
            file=stdout,
            flush=True,
        )
        stop.wait()
    finally:
        provider.stop()
    print("Provider stopped.", file=stdout)
    return EXIT_OK


def main(
    argv: list[str] | None = None,
    *,
    stop: threading.Event | None = None,
    stdin: TextIO | None = None,
    stdout: TextIO | None = None,
    stderr: TextIO | None = None,
    open_browser: Callable[[str], object] | None = None,
) -> int:
    args = _parser().parse_args(argv)
    stdin = sys.stdin if stdin is None else stdin
    stdout = sys.stdout if stdout is None else stdout
    stderr = sys.stderr if stderr is None else stderr
    if args.command == "enroll":
        return _enroll(args, stdin, stdout, stderr, open_browser)
    if stop is None:
        stop = threading.Event()
        for signum in (signal.SIGINT, signal.SIGTERM):
            signal.signal(signum, lambda *_: stop.set())
    return _run(args, stop, stdout, stderr)
