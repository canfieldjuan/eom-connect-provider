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

## Develop

```
pip install -e '.[dev]'   # plus the Automate host for the integration test
pytest -q
ruff check src tests
```

The host-integration test imports `connect_automate` (a dev/test dependency, not a
runtime one) and is skipped when it is not installed.
