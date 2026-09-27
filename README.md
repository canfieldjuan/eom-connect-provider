# eom-connect-provider

The local EOM Connect provider: a per-PC Connect v2 provider that fronts the EOM
funnel for the Automate host, authenticating to the tracker with a per-request
Ed25519 device key. No Atlas service token and no operator bearer ever live on the
buyer PC.

## Where it sits

```
Automate host (Connect consumer, buyer PC)
   |  connect.invoke  (same-PC loopback, ADR-0005)
   v
Local EOM Connect provider (this package)
   |  outbound HTTPS, per-request Ed25519 device proof (no Atlas token)
   v
Tracker device endpoints  (hold the Atlas service token)
   |  Authorization: Bearer + operator vouching headers
   v
Atlas funnel API
```

The design is pinned by the tracker's
`CONNECT_LOCAL_PROVIDER_CREDENTIAL_CONTRACT.md`. The tracker keeps the Atlas
credential server-side and vouches for the bound operator; the provider only ever
holds a revocable device key.

## This slice

The first provider slice wires ONE capability end to end: the funnel review-queue
poll (`lead.review-queue.list`), a read that maps to the tracker's
`GET /api/connect/device/funnel/leads`. It exercises the whole loop -- enrollment,
the owner-private key store, per-request device-proof signing, loopback
registration, `job_id` idempotent submission -- with no money-path risk. The money
capabilities (approve-send, bookings, customer handoff) are later slices that reuse
this substrate, each mapping to its existing device endpoint on the tracker.

## Modules

- `proof` -- the per-request Ed25519 proof, byte-identical to the tracker verifier.
- `store` -- owner-private, atomic on-disk device credential.
- `enrollment` -- one-time office-session enrollment; stores only the device key.
- `tracker_client` -- device-signed calls to the tracker device endpoints.
- `capabilities` -- the Connect v2 capability manifest this provider advertises.
- `provider` -- the loopback Connect v2 provider process.
- `placement` -- where the provider registers, mirroring the host's discovery root.
- `cli` -- the `eom-connect-provider` command.

## Use on a PC

```
eom-connect-provider enroll --label "Office desk"   # once; opens the browser to authorize
eom-connect-provider run                            # serve until Ctrl+C
```

`enroll` opens the staff portal's `/connect-enroll` page, where a signed-in admin
checks the key fingerprint against the one printed in the terminal and clicks
Authorize. The browser and a one-shot `127.0.0.1` listener hand the challenge,
signature, and device id back and forth by top-level navigation, so the staff session
token never leaves the browser (the same browser-plus-loopback pattern the email
watcher's Gmail and Microsoft sign-in use). `--paste-token` instead reads the token
from a hidden prompt. Either way only the device key is stored, and a PC that is
already enrolled is refused. `run` registers where the Automate host
discovers providers: `%LOCALAPPDATA%\LocalConnect\runtime\v2\providers` on Windows,
`$XDG_RUNTIME_DIR/local-connect/v2/providers` elsewhere. Both default to the live
tracker; `--tracker-url` overrides it (https only, or http to a loopback tracker).

## Develop

```
pip install -e '.[dev]'
pytest -q
ruff check src tests
```

Requires Python 3.13. The Automate host package (`connect-automate`) is a pinned
runtime dependency: the provider reuses its discovery root and, on Windows, its
owner-private file helpers.
