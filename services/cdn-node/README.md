<!-- Copyright (c) 2026 OpenAgenet contributors -->
<!--
Initial author: JINLIANG XU
Email: jlxufly@gmail.com
-->

# CDN Service

Single local distribution service for Root-verified resource packages and their
resource catalog.

This service is not a `did:oan` authorized infrastructure node. It represents a
traditional CDN/object-storage service that may be operated by the Root
operator or outsourced.

## Role

CDN stores and serves Root-verified resource packages under `/cdn/resources`
and `/cdn/resources/index`. Relying parties still verify Root proofs, hashes,
and bulletin state instead of trusting CDN directly.

CDN is outside the infrastructure authorization flow. It is not a governance
subject, does not receive a Root-issued infrastructure authorization VC, and
does not decide whether Registrar, Discovery, or third-party VC issuer nodes
are authorized. Its security boundary is Root-authenticated publish and purge
operations plus content verification by consumers.

## Local Run

```powershell
cargo run -p cdn-node
```

The default local API listens on port `8003` when using the sample
configuration and demo scripts.
