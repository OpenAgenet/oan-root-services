<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# CDN Publisher

Root-side worker for event-driven ResourcePackage publication.

## Role

`cdn-publisher` consumes Root-emitted NATS JetStream
`cdn_publish_requested` events, fetches the Root-approved ResourcePackage from
Root, verifies the event hashes against the fetched package, and publishes one
bounded batch to CDN through `/cdn/resources/batch`.

It is not an OAN infrastructure role. It does not have a service-node DID, does
not participate in chain-governed authorization, and does not change the CDN
public API. Operators normally run it beside Root or in the same operational
trust domain as Root.

## Local Run

Start NATS with JetStream enabled:

```powershell
nats-server -js
```

Then run:

```powershell
cargo run -p cdn-publisher -- services/cdn-publisher/config.example.toml
```

The worker exposes:

- `GET /health`
- `GET /status`

Messages are acknowledged only after CDN confirms publication. Duplicate
delivery is tolerated by stable resource DID, package version, and CDN
idempotence.
