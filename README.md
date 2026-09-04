# OAN Root Services

Root-side service workspace for OpenAgenet (OAN), an open infrastructure
project for the Internet of Agents (IoA). This repository implements the Root,
CDN, and publication worker services that turn Registrar-accepted resources into
Root-approved, distributed, and Discovery-indexable OAN resource packages.

This repository owns:

- `root-node`
- `cdn-node`
- `cdn-publisher`

Shared protocol, crypto, storage, service-security, and publication event
crates live in the sibling `oan-protocol-common` repository.

## Service Roles

- `root-node`: the OAN authorization, data distribution, and semantic
  governance hub. It verifies Registrar-submitted resource packages, records
  versions, maintains publication queues, exposes Registrar and Discovery node
  authorization views, and serves the capability tree used by registration and
  discovery assistance.
- `cdn-node`: stores and serves Root-approved resource packages, DID documents,
  metadata, resource indexes, and publish history for Discovery nodes and public
  clients.
- `cdn-publisher`: worker process that fetches prepared publication jobs from
  Root and publishes package batches into CDN.

Key public or service-facing routes include:

- Root:
  - `GET /health`
  - `GET /root/did`
  - `GET /bulletin`
  - `GET /root/status`
  - `GET /root/registrars`
  - `GET /root/discovery-nodes`
  - `GET /root/resources/{did}`
  - `GET /root/resources/{did}/versions`
  - `GET /root/capability-tree`
  - `GET /root/bulletin/events`
- CDN:
  - `GET /health`
  - `GET /cdn/status`
  - `GET /cdn/resources/{did}`
  - `POST /cdn/resources/batch-get`
  - `GET /cdn/resources/index`
  - `GET /cdn/documents/{did}`
  - `GET /cdn/metadata/{did}`
  - `GET /cdn/catalog/resources`
  - `GET /cdn/catalog/resources/stats`
- Publisher:
  - `GET /health`
  - `GET /status`

For public browser workflows, selected Root/CDN status and resource routes are
exposed through the official website gateway at `https://www.openagenet.xyz`.

## Local Checks

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace -j 1
```

Full-network integration tests, deployment gates, and benchmarks are maintained
separately by official operators. Service-node identity material should be
provided by the operator for each deployment; this repository does not own
private node identity material.

## License

This core service repository is licensed under `Apache-2.0`. Brand and
official-node identity rights are reserved separately.
