<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# Root Node

Trust anchor for local OpenAgenet deployments and the authorization hub of the
reference implementation.

## Role

Root Node observes infrastructure governance state, issues Root authorization
VCs for eligible infrastructure participants, verifies Registrar-submitted
resource packages, appends signed bulletin events, archives verified `did:oan`
DID Document versions, and coordinates CDN publishing plus Discovery
notification.

## Governance and VC Boundary

Root distinguishes governance state from protocol credentials. The on-chain
governance layer records whether a Registrar, Discovery, or future third-party
VC issuer is active, suspended, revoked, or unknown. Root consumes that state
through a local read-side view and does not need to query it for every request.

A service node is effectively authorized only when its governance state is
active and it also holds a valid Root-issued infrastructure authorization VC.
When governance state is inactive, stale, or revoked, Root must refuse new
service to that node even if it previously received a VC. When governance state
is active but no VC has been issued, the node is known to governance but is not
yet authorized at the protocol layer.

Root-issued VCs are therefore the protocol credentials used by services, while
the governance state is the lifecycle source that bounds whether those
credentials should be issued or honored.

## Root-to-CDN Publication

Root publishes CDN work through NATS JetStream events consumed by the Root-side
`cdn-publisher` worker. The earlier Root-internal database worker publication
path is intentionally not supported.

Root still persists the accepted ResourcePackage and a CDN publication job in
its own repository as authoritative state. The same acceptance transaction also
writes a `cdn_publish_requested` outbox row. An independent Root outbox relay
publishes that row to JetStream and marks it succeeded only after the event
publisher accepts it. JetStream is workflow transport, not authoritative
resource state; the CDN publication job remains as the completion ledger that
`cdn-publisher` clears through the internal mark-published API after CDN
accepts the ResourcePackage.

The Root `/root/status` response includes `eventRuntime` counters for event
publishing success, failure, stream, subject, and last error. It also includes
`cdnOutboxCount`, `cdnOutboxReadyCount`, and `cdnOutboxActiveCount` so operators
can tell whether Root has accepted resources that have not yet been emitted to
the publication stream.

## Local Run

```powershell
cargo run -p root-node
```

The default local API listens on port `8000` when using the sample
configuration and demo scripts.

