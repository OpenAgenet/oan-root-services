// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use anyhow::{anyhow, Result};
use axum::{extract::State, routing::get, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use futures::StreamExt;
use oan_core::CryptoSuite;
use oan_crypto::{signing_key_from_bytes, SigningKey};
use oan_package::ResourcePackage;
use oan_protocol::{
    HealthResponse, ResourceCdnBatchPublishRequest, ResourceCdnPublishBatchItem,
    OAN_RESOURCE_PROTOCOL_VERSION, PATH_CDN_RESOURCES_BATCH, PURPOSE_CDN_PUBLISH,
};
use oan_publication_events::CdnPublishRequestedEvent;
#[cfg(test)]
use oan_publication_events::CdnPublishRequestedEventInput;
use oan_service_security::{
    create_signed_request_envelope, request_id, request_nonce, SignedRequestEnvelopeInput,
};
use oan_storage::JsonStore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::{
    task::JoinSet,
    time::{sleep, Duration as TokioDuration},
};
use url::Url;

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    events: EventConfig,
    root: RootConfig,
    cdn: CdnConfig,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerConfig {
    host: String,
    port: u16,
}

#[derive(Clone, Debug, Deserialize)]
struct EventConfig {
    endpoint: String,
    stream: String,
    subject: String,
    durable_consumer: String,
    #[serde(default = "default_batch_size")]
    batch_size: usize,
    #[serde(default = "default_fetch_timeout_ms")]
    fetch_timeout_ms: u64,
    #[serde(default = "default_max_in_flight")]
    max_in_flight: usize,
}

#[derive(Clone, Debug, Deserialize)]
struct RootConfig {
    endpoint: String,
    keys_dir: PathBuf,
    #[serde(default)]
    admin_token: Option<String>,
    #[serde(default = "default_package_batch_path")]
    package_batch_path: String,
    #[serde(default = "default_mark_published_path")]
    mark_published_path: String,
}

#[derive(Clone, Debug, Deserialize)]
struct CdnConfig {
    endpoint: String,
    publish_batch_path: String,
    #[serde(default = "default_http_timeout_seconds")]
    http_timeout_seconds: u64,
}

#[derive(Clone)]
struct AppState {
    config: Config,
    root_did: String,
    signing_key: SigningKey,
    client: reqwest::Client,
    runtime: Arc<Mutex<PublisherRuntime>>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct PublisherRuntime {
    stream: String,
    subject: String,
    durable_consumer: String,
    last_fetched_count: usize,
    last_acked_count: usize,
    last_failed_count: usize,
    total_acked_count: u64,
    total_failed_count: u64,
    last_elapsed_ms: u128,
    last_error: Option<String>,
    updated_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Clone, Debug, Deserialize)]
struct DevKeyFile {
    did: String,
    algorithm: String,
    #[serde(rename = "privateKeyJwk")]
    private_key_jwk: PrivateKeyJwk,
}

#[derive(Clone, Debug, Deserialize)]
struct PrivateKeyJwk {
    d: String,
}

fn default_batch_size() -> usize {
    200
}

fn default_fetch_timeout_ms() -> u64 {
    1_000
}

fn default_max_in_flight() -> usize {
    200
}

fn default_http_timeout_seconds() -> u64 {
    30
}

fn default_mark_published_path() -> String {
    "/root/internal/cdn-publication-jobs/mark-published".to_owned()
}

fn default_package_batch_path() -> String {
    "/root/internal/cdn-publication-jobs/packages".to_owned()
}

fn crypto_suite_from_algorithm(value: &str) -> Result<CryptoSuite> {
    match value {
        "Ed25519" => Ok(CryptoSuite::Ed25519Sha256),
        "SM2" => Ok(CryptoSuite::Sm2Sm3),
        other => Err(anyhow!("unsupported_algorithm: {other}")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "services/cdn-publisher/config.example.toml".to_owned());
    let config = load_config(config_path)?;
    let key: DevKeyFile = JsonStore::new(".").read(config.root.keys_dir.join("keypair.json"))?;
    let crypto_suite = crypto_suite_from_algorithm(&key.algorithm)?;
    let signing_key = signing_key_from_bytes(
        crypto_suite,
        &URL_SAFE_NO_PAD.decode(key.private_key_jwk.d)?,
    )?;
    let client = reqwest::Client::builder()
        .timeout(TokioDuration::from_secs(config.cdn.http_timeout_seconds))
        .build()?;
    let state = AppState {
        runtime: Arc::new(Mutex::new(PublisherRuntime {
            stream: config.events.stream.clone(),
            subject: config.events.subject.clone(),
            durable_consumer: config.events.durable_consumer.clone(),
            ..Default::default()
        })),
        root_did: key.did,
        signing_key,
        client,
        config: config.clone(),
    };

    let worker_state = state.clone();
    tokio::spawn(async move {
        if let Err(err) = run_publisher_loop(worker_state).await {
            eprintln!("cdn-publisher loop stopped: {err}");
        }
    });

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .with_state(state);
    println!("cdn-publisher listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_config(path: impl AsRef<Path>) -> Result<Config> {
    let path = path.as_ref();
    let value = std::fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&value)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.root.keys_dir = resolve_relative(base, &config.root.keys_dir);
    Ok(config)
}

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
        node_type: "cdn-publisher".to_owned(),
        did: Some(state.root_did),
    })
}

async fn status(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "nodeType": "cdn-publisher",
        "rootDid": state.root_did,
        "runtime": runtime_json(&state)
    }))
}

fn runtime_json(state: &AppState) -> Value {
    state
        .runtime
        .lock()
        .map(|runtime| serde_json::to_value(&*runtime).unwrap_or_else(|_| json!({})))
        .unwrap_or_else(|_| json!({"status": "unavailable"}))
}

async fn run_publisher_loop(state: AppState) -> Result<()> {
    let client = async_nats::connect(&state.config.events.endpoint).await?;
    let context = async_nats::jetstream::new(client);
    let stream = context
        .get_or_create_stream(async_nats::jetstream::stream::Config {
            name: state.config.events.stream.clone(),
            subjects: vec![state.config.events.subject.clone()],
            ..Default::default()
        })
        .await?;
    let consumer = stream
        .get_or_create_consumer(
            &state.config.events.durable_consumer,
            async_nats::jetstream::consumer::pull::Config {
                durable_name: Some(state.config.events.durable_consumer.clone()),
                ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
                ..Default::default()
            },
        )
        .await?;

    loop {
        let started = std::time::Instant::now();
        let mut fetched = 0usize;
        let mut acked = 0usize;
        let mut failed = 0usize;
        let fetch_limit = state
            .config
            .events
            .batch_size
            .min(state.config.events.max_in_flight.max(1))
            .max(1);
        let mut messages = consumer
            .fetch()
            .max_messages(fetch_limit)
            .expires(TokioDuration::from_millis(
                state.config.events.fetch_timeout_ms.max(1),
            ))
            .messages()
            .await?;

        let mut batch = Vec::new();
        while let Some(message) = messages.next().await {
            fetched += 1;
            let message = match message {
                Ok(message) => message,
                Err(err) => {
                    failed += 1;
                    record_cycle(
                        &state,
                        fetched,
                        acked,
                        failed,
                        started.elapsed().as_millis(),
                        Some(err.to_string()),
                    );
                    continue;
                }
            };
            let decoded = decode_event_payload(&message.payload);
            batch.push((message, decoded));
        }
        let mut prepared = Vec::new();
        if !batch.is_empty() {
            match prepare_publish_batch(&state, batch).await {
                Ok(items) => prepared = items,
                Err(err) => {
                    failed += fetched.saturating_sub(acked);
                    eprintln!("cdn-publisher failed to prepare batch: {err}");
                }
            }
        }
        if !prepared.is_empty() {
            let items = prepared
                .iter()
                .map(|(_, publication_cursor, package)| (*publication_cursor, package.clone()))
                .collect::<Vec<_>>();
            match publish_packages_to_cdn(&state, items).await {
                Ok(()) => {
                    let messages = prepared
                        .into_iter()
                        .map(|(message, _, _)| message)
                        .collect::<Vec<_>>();
                    acked +=
                        ack_messages(messages, state.config.events.max_in_flight.max(1)).await?;
                }
                Err(err) => {
                    failed += prepared.len();
                    eprintln!("cdn-publisher batch failed: {err}");
                }
            }
        }
        record_cycle(
            &state,
            fetched,
            acked,
            failed,
            started.elapsed().as_millis(),
            None,
        );
        if fetched == 0 {
            sleep(TokioDuration::from_millis(
                state.config.events.fetch_timeout_ms.max(100),
            ))
            .await;
        }
    }
}

async fn ack_messages(
    messages: Vec<async_nats::jetstream::Message>,
    concurrency: usize,
) -> Result<usize> {
    if messages.is_empty() {
        return Ok(0);
    }
    let mut acked = 0usize;
    let mut in_flight = JoinSet::new();
    let mut iter = messages.into_iter();
    let concurrency = concurrency.max(1);
    loop {
        while in_flight.len() < concurrency {
            let Some(message) = iter.next() else {
                break;
            };
            in_flight
                .spawn(async move { message.ack().await.map_err(|err| anyhow!(err.to_string())) });
        }
        if in_flight.is_empty() {
            break;
        }
        let Some(result) = in_flight.join_next().await else {
            break;
        };
        result.map_err(|err| anyhow!("cdn_publisher_ack_task_failed:{err}"))??;
        acked += 1;
    }
    Ok(acked)
}

fn decode_event_payload(payload: &[u8]) -> Result<CdnPublishRequestedEvent> {
    let event: CdnPublishRequestedEvent = serde_json::from_slice(payload)?;
    event.validate().map_err(|err| anyhow!(err))?;
    Ok(event)
}

async fn prepare_publish_batch(
    state: &AppState,
    batch: Vec<(
        async_nats::jetstream::Message,
        Result<CdnPublishRequestedEvent>,
    )>,
) -> Result<Vec<(async_nats::jetstream::Message, i64, ResourcePackage)>> {
    let mut decoded = Vec::new();
    for (message, event) in batch {
        match event {
            Ok(event) => decoded.push((message, event)),
            Err(err) => {
                eprintln!("cdn-publisher failed to decode task: {err}");
            }
        }
    }
    if decoded.is_empty() {
        return Ok(Vec::new());
    }
    let events = decoded
        .iter()
        .map(|(_, event)| event.clone())
        .collect::<Vec<_>>();
    let packages = prepare_packages_for_events(state, &events).await?;
    let mut prepared = Vec::new();
    for (message, event) in decoded {
        let job_key = format!("{}:{}", event.resource_did, event.package_version);
        let Some((publication_cursor, package)) = packages.get(&job_key) else {
            return Err(anyhow!("root_package_missing:{job_key}"));
        };
        validate_package_matches_event(package, &event)?;
        prepared.push((message, *publication_cursor, package.clone()));
    }
    Ok(prepared)
}

async fn prepare_packages_for_events(
    state: &AppState,
    events: &[CdnPublishRequestedEvent],
) -> Result<std::collections::BTreeMap<String, (i64, ResourcePackage)>> {
    let event_refs = events.iter().collect::<Vec<_>>();
    let packages = fetch_resource_packages_batch(state, event_refs.as_slice()).await?;
    for event in events {
        let job_key = format!("{}:{}", event.resource_did, event.package_version);
        let Some((_, package)) = packages.get(&job_key) else {
            return Err(anyhow!("root_package_missing:{job_key}"));
        };
        validate_package_matches_event(package, event)?;
    }
    Ok(packages)
}

fn validate_package_matches_event(
    package: &ResourcePackage,
    event: &CdnPublishRequestedEvent,
) -> Result<()> {
    if package.resource_did != event.resource_did {
        return Err(anyhow!("resource_did_mismatch"));
    }
    if package.package_version != event.package_version {
        return Err(anyhow!("package_version_mismatch"));
    }
    if package.package_hash != event.package_hash {
        return Err(anyhow!("package_hash_mismatch"));
    }
    if package.did_document_hash != event.did_document_hash {
        return Err(anyhow!("did_document_hash_mismatch"));
    }
    if package.metadata_hash != event.metadata_hash {
        return Err(anyhow!("metadata_hash_mismatch"));
    }
    Ok(())
}

async fn fetch_resource_packages_batch(
    state: &AppState,
    events: &[&CdnPublishRequestedEvent],
) -> Result<std::collections::BTreeMap<String, (i64, ResourcePackage)>> {
    if events.is_empty() {
        return Ok(std::collections::BTreeMap::new());
    }
    let Some(admin_token) = state.config.root.admin_token.as_ref() else {
        return Err(anyhow!("root_admin_token_required_for_package_batch"));
    };
    let url = root_package_batch_url(
        &state.config.root.endpoint,
        &state.config.root.package_batch_path,
    )?;
    let jobs = events
        .iter()
        .map(|event| {
            json!({
                "resource_did": event.resource_did,
                "package_version": event.package_version
            })
        })
        .collect::<Vec<_>>();
    let response = state
        .client
        .post(url)
        .bearer_auth(admin_token)
        .json(&json!({ "jobs": jobs }))
        .send()
        .await?;
    let status = response.status();
    let value = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    if !status.is_success() {
        return Err(anyhow!("root_package_batch_failed:{status}:{value}"));
    }
    let mut packages = std::collections::BTreeMap::new();
    for item in value
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("root_package_batch_items_missing"))?
    {
        let job_key = item
            .get("jobKey")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("root_package_batch_job_key_missing"))?
            .to_owned();
        let publication_cursor = item
            .get("publicationCursor")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("root_package_batch_cursor_missing"))?;
        let package = serde_json::from_value::<ResourcePackage>(
            item.get("package")
                .ok_or_else(|| anyhow!("root_package_batch_package_missing"))?
                .clone(),
        )?;
        packages.insert(job_key, (publication_cursor, package));
    }
    Ok(packages)
}

#[cfg(test)]
fn root_version_detail_url(root_endpoint: &str, did: &str, version: &str) -> Result<Url> {
    let mut url = Url::parse(root_endpoint)?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("root_endpoint_cannot_be_base"))?;
        segments
            .pop_if_empty()
            .push("root")
            .push("resources")
            .push(did)
            .push("versions")
            .push(version);
    }
    Ok(url)
}

fn root_package_batch_url(root_endpoint: &str, path: &str) -> Result<Url> {
    let mut url = Url::parse(root_endpoint)?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("root_endpoint_cannot_be_base"))?;
        segments.pop_if_empty();
        for segment in path.trim_start_matches('/').split('/') {
            if !segment.is_empty() {
                segments.push(segment);
            }
        }
    }
    Ok(url)
}

async fn publish_packages_to_cdn(
    state: &AppState,
    packages: Vec<(i64, ResourcePackage)>,
) -> Result<()> {
    if packages.is_empty() {
        return Ok(());
    }
    let request = build_cdn_batch_publish_request(state, packages)?;
    let url = cdn_publish_batch_url(
        &state.config.cdn.endpoint,
        &state.config.cdn.publish_batch_path,
    )?;
    let response = state.client.post(url).json(&request).send().await?;
    let status = response.status();
    let value = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    if !status.is_success() {
        return Err(anyhow!("cdn_publish_failed:{status}:{value}"));
    }
    if value
        .get("failedCount")
        .and_then(Value::as_u64)
        .unwrap_or(0)
        > 0
    {
        return Err(anyhow!("cdn_publish_partial:{value}"));
    }
    mark_root_jobs_published(state, &request.items).await?;
    Ok(())
}

async fn mark_root_jobs_published(
    state: &AppState,
    items: &[ResourceCdnPublishBatchItem],
) -> Result<()> {
    let Some(admin_token) = state.config.root.admin_token.as_ref() else {
        return Err(anyhow!("root_admin_token_required_for_mark_published"));
    };
    let url = root_mark_published_url(
        &state.config.root.endpoint,
        &state.config.root.mark_published_path,
    )?;
    let jobs = build_mark_published_jobs(items);
    let response = state
        .client
        .post(url)
        .bearer_auth(admin_token)
        .json(&json!({ "jobs": jobs }))
        .send()
        .await?;
    let status = response.status();
    let value = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    if !status.is_success() {
        return Err(anyhow!("root_mark_published_failed:{status}:{value}"));
    }
    Ok(())
}

fn build_mark_published_jobs(items: &[ResourceCdnPublishBatchItem]) -> Vec<Value> {
    items
        .iter()
        .map(|item| {
            json!({
                "resource_did": item.package.resource_did,
                "package_version": item.package.package_version
            })
        })
        .collect()
}

fn root_mark_published_url(root_endpoint: &str, path: &str) -> Result<Url> {
    let mut url = Url::parse(root_endpoint)?;
    let path = path.trim_start_matches('/');
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("root_endpoint_cannot_be_base"))?;
        segments.pop_if_empty();
        for segment in path.split('/') {
            segments.push(segment);
        }
    }
    Ok(url)
}

fn cdn_publish_batch_url(cdn_endpoint: &str, path: &str) -> Result<Url> {
    let mut url = Url::parse(cdn_endpoint)?;
    let path = path.trim_start_matches('/');
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("cdn_endpoint_cannot_be_base"))?;
        segments.pop_if_empty();
        for segment in path.split('/') {
            segments.push(segment);
        }
    }
    Ok(url)
}

fn build_cdn_batch_publish_request(
    state: &AppState,
    packages: Vec<(i64, ResourcePackage)>,
) -> Result<ResourceCdnBatchPublishRequest> {
    let items = packages
        .into_iter()
        .map(
            |(publication_cursor, package)| ResourceCdnPublishBatchItem {
                publication_cursor,
                package,
            },
        )
        .collect::<Vec<_>>();
    let verification_method = format!("{}#key-1", state.root_did);
    let envelope = create_signed_request_envelope(SignedRequestEnvelopeInput {
        request_id: request_id("resource-cdn-batch-publish"),
        protocol_version: OAN_RESOURCE_PROTOCOL_VERSION.to_owned(),
        purpose: PURPOSE_CDN_PUBLISH.to_owned(),
        method: "POST".to_owned(),
        path: PATH_CDN_RESOURCES_BATCH.to_owned(),
        aud: state.root_did.clone(),
        payload: &items,
        creator: state.root_did.clone(),
        verification_method,
        signing_key: &state.signing_key,
        nonce: request_nonce("resource-cdn-batch-publish"),
    })?;
    Ok(ResourceCdnBatchPublishRequest {
        items,
        upstream_auth: envelope,
    })
}

fn record_cycle(
    state: &AppState,
    fetched: usize,
    acked: usize,
    failed: usize,
    elapsed_ms: u128,
    error: Option<String>,
) {
    if let Ok(mut runtime) = state.runtime.lock() {
        runtime.last_fetched_count = fetched;
        runtime.last_acked_count = acked;
        runtime.last_failed_count = failed;
        runtime.total_acked_count = runtime.total_acked_count.saturating_add(acked as u64);
        runtime.total_failed_count = runtime.total_failed_count.saturating_add(failed as u64);
        runtime.last_elapsed_ms = elapsed_ms;
        if error.is_some() {
            runtime.last_error = error;
        }
        runtime.updated_at = Some(Utc::now());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oan_core::{DidDocument, ResourceType};
    use oan_crypto::{generate_keypair, SigningKey as OanSigningKey};
    use oan_package::{ResourceMetadata, RootProof};
    use oan_publication_events::CDN_PUBLISH_REQUESTED_EVENT_TYPE;

    fn test_state() -> AppState {
        let keypair = generate_keypair(CryptoSuite::Ed25519Sha256).unwrap();
        let signing_key = match keypair.signing_key {
            OanSigningKey::Ed25519 { .. } | OanSigningKey::Sm2 { .. } => keypair.signing_key,
        };
        AppState {
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 0,
                },
                events: EventConfig {
                    endpoint: "nats://127.0.0.1:4222".to_owned(),
                    stream: "OAN_RESOURCE_PUBLICATION".to_owned(),
                    subject: "oan.resource.cdn.publish.requested".to_owned(),
                    durable_consumer: "oan-cdn-publisher".to_owned(),
                    batch_size: 10,
                    fetch_timeout_ms: 100,
                    max_in_flight: 2,
                },
                root: RootConfig {
                    endpoint: "http://127.0.0.1:8000".to_owned(),
                    keys_dir: PathBuf::new(),
                    admin_token: None,
                    package_batch_path: default_package_batch_path(),
                    mark_published_path: default_mark_published_path(),
                },
                cdn: CdnConfig {
                    endpoint: "http://127.0.0.1:8003".to_owned(),
                    publish_batch_path: "/cdn/resources/batch".to_owned(),
                    http_timeout_seconds: 5,
                },
            },
            root_did: "did:oan:AGRT:root".to_owned(),
            signing_key,
            client: reqwest::Client::new(),
            runtime: Arc::new(Mutex::new(PublisherRuntime::default())),
        }
    }

    fn sample_package() -> ResourcePackage {
        ResourcePackage {
            package_version: "1.0.0".to_owned(),
            resource_did: "did:oan:AGUS:test".to_owned(),
            resource_type: ResourceType::AgentService,
            did_document: DidDocument {
                context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
                id: "did:oan:AGUS:test".to_owned(),
                verification_method: vec![],
                authentication: vec![],
                assertion_method: vec![],
                service: vec![],
                oan_metadata: None,
            },
            did_document_hash: "sha256:document".to_owned(),
            metadata_hash: "sha256:metadata".to_owned(),
            package_hash: "sha256:package".to_owned(),
            hash_algorithm: "sha256".to_owned(),
            metadata: ResourceMetadata {
                resource_did: "did:oan:AGUS:test".to_owned(),
                resource_type: ResourceType::AgentService,
                name: "Sample".to_owned(),
                description: "Sample resource".to_owned(),
                capability_tags: vec![],
                protocol_bindings: vec![],
                services: vec![],
                publisher_did: Some("did:oan:AGRG:registrar".to_owned()),
                subject_type: ResourceType::AgentService,
                subject_did: Some("did:oan:AGUS:test".to_owned()),
                updated_at: Utc::now(),
                metadata_hash: "sha256:metadata".to_owned(),
                package_hash: "sha256:package".to_owned(),
                lifecycle_state: "active".to_owned(),
                package_version: "1.0.0".to_owned(),
                hash_algorithm: "sha256".to_owned(),
            },
            root_proof: RootProof {
                root_did: "did:oan:AGRT:root".to_owned(),
                bulletin_event_hash: None,
                signature: None,
                package_claims: None,
                proof: None,
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                hash_algorithm: Some("sha256".to_owned()),
            },
            created_at: Utc::now(),
        }
    }

    fn sample_event() -> CdnPublishRequestedEvent {
        CdnPublishRequestedEvent::new(CdnPublishRequestedEventInput {
            job_key: "did:oan:AGUS:test:1.0.0".to_owned(),
            resource_did: "did:oan:AGUS:test".to_owned(),
            package_version: "1.0.0".to_owned(),
            publication_cursor: 42,
            root_did: "did:oan:AGRT:root".to_owned(),
            package_hash: "sha256:package".to_owned(),
            did_document_hash: "sha256:document".to_owned(),
            metadata_hash: "sha256:metadata".to_owned(),
            created_at: Utc::now(),
        })
    }

    #[test]
    fn root_and_cdn_urls_encode_did_path_segments() {
        let root_url =
            root_version_detail_url("http://127.0.0.1:8000", "did:oan:AGUS:abc", "1.0.0").unwrap();
        assert_eq!(
            root_url.as_str(),
            "http://127.0.0.1:8000/root/resources/did:oan:AGUS:abc/versions/1.0.0"
        );
        let cdn_url =
            cdn_publish_batch_url("http://127.0.0.1:8003", "/cdn/resources/batch").unwrap();
        assert_eq!(
            cdn_url.as_str(),
            "http://127.0.0.1:8003/cdn/resources/batch"
        );
        let mark_url = root_mark_published_url(
            "http://127.0.0.1:8000",
            "/root/internal/cdn-publication-jobs/mark-published",
        )
        .unwrap();
        assert_eq!(
            mark_url.as_str(),
            "http://127.0.0.1:8000/root/internal/cdn-publication-jobs/mark-published"
        );
        let package_batch_url = root_package_batch_url(
            "http://127.0.0.1:8000",
            "/root/internal/cdn-publication-jobs/packages",
        )
        .unwrap();
        assert_eq!(
            package_batch_url.as_str(),
            "http://127.0.0.1:8000/root/internal/cdn-publication-jobs/packages"
        );
    }

    #[test]
    fn builds_signed_cdn_batch_request() {
        let state = test_state();
        let request =
            build_cdn_batch_publish_request(&state, vec![(42, sample_package())]).unwrap();
        assert_eq!(request.items.len(), 1);
        assert_eq!(request.items[0].publication_cursor, 42);
        assert_eq!(request.upstream_auth.path, PATH_CDN_RESOURCES_BATCH);
        assert_eq!(request.upstream_auth.purpose, PURPOSE_CDN_PUBLISH);
    }

    #[test]
    fn builds_multi_item_cdn_batch_request() {
        let state = test_state();
        let mut second = sample_package();
        second.resource_did = "did:oan:AGUS:test2".to_owned();
        second.metadata.resource_did = second.resource_did.clone();
        let request =
            build_cdn_batch_publish_request(&state, vec![(42, sample_package()), (43, second)])
                .unwrap();
        assert_eq!(request.items.len(), 2);
        assert_eq!(request.items[0].publication_cursor, 42);
        assert_eq!(request.items[1].publication_cursor, 43);
        assert_eq!(request.upstream_auth.path, PATH_CDN_RESOURCES_BATCH);
    }

    #[test]
    fn builds_mark_published_jobs_for_each_batch_item() {
        let state = test_state();
        let mut second = sample_package();
        second.resource_did = "did:oan:AGUS:test2".to_owned();
        second.metadata.resource_did = second.resource_did.clone();
        second.package_version = "2.0.0".to_owned();
        second.metadata.package_version = second.package_version.clone();
        let request =
            build_cdn_batch_publish_request(&state, vec![(42, sample_package()), (43, second)])
                .unwrap();

        let jobs = build_mark_published_jobs(&request.items);

        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0]["resource_did"], "did:oan:AGUS:test");
        assert_eq!(jobs[0]["package_version"], "1.0.0");
        assert_eq!(jobs[1]["resource_did"], "did:oan:AGUS:test2");
        assert_eq!(jobs[1]["package_version"], "2.0.0");
    }

    #[test]
    fn default_in_flight_limit_matches_default_batch_size() {
        assert_eq!(default_batch_size(), 200);
        assert_eq!(default_max_in_flight(), default_batch_size());
    }

    #[test]
    fn decodes_and_validates_event_payload() {
        let payload = serde_json::to_vec(&sample_event()).unwrap();
        let event = decode_event_payload(&payload).unwrap();
        assert_eq!(event.event_type, CDN_PUBLISH_REQUESTED_EVENT_TYPE);
        assert_eq!(event.publication_cursor, 42);

        let mut invalid = sample_event();
        invalid.publication_cursor = 0;
        let payload = serde_json::to_vec(&invalid).unwrap();
        let err = decode_event_payload(&payload).unwrap_err().to_string();
        assert!(err.contains("invalid_publication_cursor"));
    }

    #[test]
    fn rejects_package_that_does_not_match_event_reference_or_hashes() {
        let event = sample_event();
        let package = sample_package();
        validate_package_matches_event(&package, &event).unwrap();

        let mut mismatched = package.clone();
        mismatched.resource_did = "did:oan:AGUS:other".to_owned();
        let err = validate_package_matches_event(&mismatched, &event)
            .unwrap_err()
            .to_string();
        assert!(err.contains("resource_did_mismatch"));

        let mut mismatched = package.clone();
        mismatched.package_version = "2.0.0".to_owned();
        let err = validate_package_matches_event(&mismatched, &event)
            .unwrap_err()
            .to_string();
        assert!(err.contains("package_version_mismatch"));

        let mut mismatched = package;
        mismatched.package_hash = "sha256:changed".to_owned();
        let err = validate_package_matches_event(&mismatched, &event)
            .unwrap_err()
            .to_string();
        assert!(err.contains("package_hash_mismatch"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn prepares_packages_with_root_batch_endpoint() {
        async fn package_batch_handler() -> Json<Value> {
            Json(json!({
                "status": "ok",
                "requestedCount": 1,
                "foundCount": 1,
                "items": [{
                    "jobKey": "did:oan:AGUS:test:1.0.0",
                    "publicationCursor": 42,
                    "package": sample_package()
                }]
            }))
        }

        let app = Router::new().route(
            "/root/internal/cdn-publication-jobs/packages",
            axum::routing::post(package_batch_handler),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let mut state = test_state();
        state.config.root.endpoint = format!("http://{addr}");
        state.config.root.admin_token = Some("test-admin".to_owned());
        let event = sample_event();
        let packages = prepare_packages_for_events(&state, &[event]).await.unwrap();

        let (cursor, package) = packages.get("did:oan:AGUS:test:1.0.0").unwrap();
        assert_eq!(*cursor, 42);
        assert_eq!(package.resource_did, "did:oan:AGUS:test");
    }

    #[tokio::test]
    async fn mark_published_requires_root_admin_token() {
        let state = test_state();
        let request =
            build_cdn_batch_publish_request(&state, vec![(42, sample_package())]).unwrap();
        let err = mark_root_jobs_published(&state, &request.items)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("root_admin_token_required_for_mark_published"));
    }

    #[test]
    fn record_cycle_updates_runtime_counters() {
        let state = test_state();
        record_cycle(&state, 3, 2, 1, 12, Some("err".to_owned()));
        let runtime = state.runtime.lock().unwrap().clone();
        assert_eq!(runtime.last_fetched_count, 3);
        assert_eq!(runtime.total_acked_count, 2);
        assert_eq!(runtime.total_failed_count, 1);
        assert_eq!(runtime.last_error.as_deref(), Some("err"));
    }

    #[test]
    fn load_config_resolves_root_keys_dir_relative_to_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config").join("cdn-publisher.toml");
        std::fs::create_dir_all(config_path.parent().unwrap()).unwrap();
        std::fs::write(
            &config_path,
            r#"
[server]
host = "127.0.0.1"
port = 0

[events]
endpoint = "nats://127.0.0.1:4222"
stream = "OAN_RESOURCE_PUBLICATION"
subject = "oan.resource.cdn.publish.requested"
durable_consumer = "oan-cdn-publisher"

[root]
endpoint = "http://127.0.0.1:8000"
keys_dir = "../root/keys"
admin_token = "local-dev-admin-token"

[cdn]
endpoint = "http://127.0.0.1:8003"
publish_batch_path = "/cdn/resources/batch"
"#,
        )
        .unwrap();
        let config = load_config(&config_path).unwrap();
        assert!(config.root.keys_dir.is_absolute());
        assert!(config
            .root
            .keys_dir
            .ends_with(Path::new("root").join("keys")));
    }
}
