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
    collections::{BTreeMap, BTreeSet},
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::{task::JoinSet, time::Duration as TokioDuration};
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
    pending_callbacks: Arc<Mutex<PendingCallbackBatch>>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct PublisherStageRuntime {
    last_batch_size: usize,
    last_concurrency: usize,
    last_success_count: usize,
    last_failure_count: usize,
    last_elapsed_ms: u128,
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
    last_fetch_elapsed_ms: u128,
    last_prepare_elapsed_ms: u128,
    last_publish_elapsed_ms: u128,
    last_callback_elapsed_ms: u128,
    last_ack_elapsed_ms: u128,
    last_effective_batch_size: usize,
    last_ack_concurrency: usize,
    fetch_stage: PublisherStageRuntime,
    root_fetch_stage: PublisherStageRuntime,
    binding_stage: PublisherStageRuntime,
    cdn_publish_stage: PublisherStageRuntime,
    root_callback_stage: PublisherStageRuntime,
    ack_stage: PublisherStageRuntime,
    last_error: Option<String>,
    updated_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Clone, Debug, Default)]
struct PublisherCycleMetrics {
    fetch_elapsed_ms: u128,
    root_fetch_elapsed_ms: u128,
    binding_elapsed_ms: u128,
    publish_elapsed_ms: u128,
    callback_elapsed_ms: u128,
    ack_elapsed_ms: u128,
    effective_batch_size: usize,
    ack_concurrency: usize,
    fetch_stage: PublisherStageRuntime,
    root_fetch_stage: PublisherStageRuntime,
    binding_stage: PublisherStageRuntime,
    cdn_publish_stage: PublisherStageRuntime,
    root_callback_stage: PublisherStageRuntime,
    ack_stage: PublisherStageRuntime,
}

#[derive(Clone, Debug, Default)]
struct CdnBatchPublishOutcome {
    published_cursors: BTreeSet<i64>,
    failed_cursors: BTreeSet<i64>,
    published_count: usize,
    retry_count: usize,
    publish_elapsed_ms: u128,
}

struct FetchedEventTask {
    message: async_nats::jetstream::Message,
    event: CdnPublishRequestedEvent,
}

struct PreparedPublishTask {
    message: async_nats::jetstream::Message,
    publication_cursor: i64,
    package: ResourcePackage,
}

struct ChunkPublishSuccess {
    item: ResourceCdnPublishBatchItem,
    message: async_nats::jetstream::Message,
}

#[derive(Default)]
struct PendingCallbackBatch {
    items: Vec<ChunkPublishSuccess>,
    first_buffered_at: Option<std::time::Instant>,
}

struct TerminalFailureTask {
    message: async_nats::jetstream::Message,
}

#[derive(Clone, Debug, Default)]
struct PreparedBatchClassification {
    prepared: Vec<(String, i64, ResourcePackage)>,
    root_fetch_failures: usize,
    binding_failures: usize,
    terminal_job_keys: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct RootBatchPackageItem {
    #[serde(rename = "jobKey")]
    job_key: String,
    #[serde(rename = "publicationCursor")]
    publication_cursor: i64,
    #[serde(rename = "resourceDid")]
    resource_did: String,
    #[serde(rename = "packageVersion")]
    package_version: String,
    #[serde(rename = "packageHash")]
    package_hash: String,
    #[serde(rename = "didDocumentHash")]
    did_document_hash: String,
    #[serde(rename = "metadataHash")]
    metadata_hash: String,
    package: ResourcePackage,
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

fn pipeline_chunk_size(batch_size: usize, max_in_flight: usize, prepared_len: usize) -> usize {
    let upper = prepared_len.max(1);
    let configured = batch_size.min(max_in_flight.max(1)).max(1);
    configured.min(32).min(upper).max(1)
}

fn completion_flush_size(batch_size: usize, prepared_len: usize) -> usize {
    batch_size.max(192).min(prepared_len.max(1))
}

fn completion_flush_max_wait_ms(fetch_timeout_ms: u64) -> u64 {
    fetch_timeout_ms.clamp(250, 1_500)
}

fn completion_buffer_max_items(batch_size: usize, max_in_flight: usize) -> usize {
    batch_size
        .max(max_in_flight.max(1))
        .saturating_mul(8)
        .clamp(384, 6_144)
}

fn should_flush_callback_buffer(
    buffered_count: usize,
    flush_size: usize,
    max_items: usize,
    cycle_fetched: usize,
    oldest_age_ms: Option<u128>,
    max_wait_ms: u64,
) -> bool {
    if buffered_count == 0 {
        return false;
    }
    if buffered_count >= max_items {
        return true;
    }
    if buffered_count >= flush_size {
        return true;
    }
    if cycle_fetched == 0 {
        return true;
    }
    oldest_age_ms.unwrap_or(0) >= u128::from(max_wait_ms)
}

fn should_force_flush_at_cycle_tail(
    buffered_count: usize,
    cycle_fetched: usize,
    fetch_limit: usize,
) -> bool {
    buffered_count > 0 && cycle_fetched > 0 && cycle_fetched < fetch_limit.max(1)
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
        pending_callbacks: Arc::new(Mutex::new(PendingCallbackBatch::default())),
        root_did: key.did,
        signing_key,
        client,
        config: config.clone(),
    };

    let worker_state = state.clone();
    tokio::spawn(async move {
        if let Err(err) = run_publisher_loop(worker_state).await {
            eprintln!("cdn-publisher loop stopped: {err}");
            std::process::exit(1);
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
        let mut cycle_metrics = PublisherCycleMetrics::default();
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
        let fetch_started = std::time::Instant::now();

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
                        cycle_metrics.clone(),
                        Some(err.to_string()),
                    );
                    continue;
                }
            };
            let decoded = decode_event_payload(&message.payload);
            batch.push((message, decoded));
        }
        cycle_metrics.fetch_elapsed_ms = fetch_started.elapsed().as_millis();
        cycle_metrics.effective_batch_size = batch.len();
        cycle_metrics.fetch_stage = PublisherStageRuntime {
            last_batch_size: batch.len(),
            last_concurrency: 1,
            last_success_count: batch.iter().filter(|(_, event)| event.is_ok()).count(),
            last_failure_count: batch.iter().filter(|(_, event)| event.is_err()).count(),
            last_elapsed_ms: cycle_metrics.fetch_elapsed_ms,
        };

        let (decoded, decode_failures) = decode_fetched_batch(batch);
        let fetch_failures = decode_failures.len();
        failed += fetch_failures;
        let mut terminal_ack_messages = decode_failures
            .into_iter()
            .map(|item| item.message)
            .collect::<Vec<_>>();
        let (decoded, duplicate_tasks) = dedupe_fetched_tasks_by_job_key(decoded);
        let duplicate_ack_count = duplicate_tasks.len();
        terminal_ack_messages.extend(duplicate_tasks.into_iter().map(|item| item.message));

        let (prepared, terminal_prepared_failures, root_fetch_metrics, binding_metrics) =
            if decoded.is_empty() {
                (
                    Vec::new(),
                    Vec::new(),
                    PublisherStageRuntime::default(),
                    PublisherStageRuntime::default(),
                )
            } else {
                match prepare_publish_batch(&state, decoded).await {
                    Ok(result) => result,
                    Err(err) => {
                        record_cycle(
                            &state,
                            fetched,
                            acked,
                            failed,
                            started.elapsed().as_millis(),
                            cycle_metrics,
                            Some(err.to_string()),
                        );
                        continue;
                    }
                }
            };
        terminal_ack_messages.extend(
            terminal_prepared_failures
                .into_iter()
                .map(|item| item.message),
        );
        cycle_metrics.root_fetch_elapsed_ms = root_fetch_metrics.last_elapsed_ms;
        cycle_metrics.binding_elapsed_ms = binding_metrics.last_elapsed_ms;
        cycle_metrics.root_fetch_stage = root_fetch_metrics;
        let binding_failure_count = binding_metrics.last_failure_count;
        cycle_metrics.binding_stage = binding_metrics;
        failed += cycle_metrics.root_fetch_stage.last_failure_count;
        failed += cycle_metrics.binding_stage.last_failure_count;

        if !prepared.is_empty() {
            let ack_concurrency = state.config.events.max_in_flight.max(1);
            cycle_metrics.ack_concurrency = ack_concurrency;
            let chunk_size = pipeline_chunk_size(
                state.config.events.batch_size,
                state.config.events.max_in_flight,
                prepared.len(),
            );
            let total_prepared = prepared.len();
            let mut publish_success_count = 0usize;
            let mut publish_failure_count = 0usize;
            let mut callback_success_count = 0usize;
            let mut ack_success_count = 0usize;
            let mut ack_target_count = fetch_failures + binding_failure_count + duplicate_ack_count;
            let mut chunk = Vec::with_capacity(chunk_size);
            let mut chunk_error: Option<String> = None;
            let callback_flush_size =
                completion_flush_size(state.config.events.batch_size, total_prepared);
            let callback_flush_max_wait_ms =
                completion_flush_max_wait_ms(state.config.events.fetch_timeout_ms);
            let callback_buffer_max_items = completion_buffer_max_items(
                state.config.events.batch_size,
                state.config.events.max_in_flight,
            );

            for item in prepared.into_iter() {
                chunk.push(item);
                if chunk.len() < chunk_size {
                    continue;
                }
                let (publish_success, publish_failure, chunk_successes, publish_elapsed_ms) =
                    match process_publish_chunk(&state, std::mem::take(&mut chunk)).await {
                        Ok(value) => value,
                        Err(err) => {
                            chunk_error = Some(err.to_string());
                            break;
                        }
                    };
                publish_success_count += publish_success;
                publish_failure_count += publish_failure;
                cycle_metrics.publish_elapsed_ms += publish_elapsed_ms;
                buffer_callback_successes(&state, chunk_successes, callback_buffer_max_items);
                if should_flush_pending_callbacks(
                    &state,
                    callback_flush_size,
                    callback_buffer_max_items,
                    fetched,
                    callback_flush_max_wait_ms,
                ) {
                    let (flushed_callbacks, acked_batch, callback_elapsed_ms) =
                        match flush_published_callback_batch(&state, ack_concurrency).await {
                            Ok(value) => value,
                            Err(err) => {
                                chunk_error = Some(err.to_string());
                                break;
                            }
                        };
                    callback_success_count += flushed_callbacks;
                    ack_target_count += flushed_callbacks;
                    ack_success_count += acked_batch;
                    acked += acked_batch;
                    cycle_metrics.callback_elapsed_ms += callback_elapsed_ms;
                }
            }
            if chunk_error.is_none() && !chunk.is_empty() {
                let (publish_success, publish_failure, chunk_successes, publish_elapsed_ms) =
                    match process_publish_chunk(&state, chunk).await {
                        Ok(value) => value,
                        Err(err) => {
                            chunk_error = Some(err.to_string());
                            (0, 0, Vec::new(), 0)
                        }
                    };
                publish_success_count += publish_success;
                publish_failure_count += publish_failure;
                cycle_metrics.publish_elapsed_ms += publish_elapsed_ms;
                buffer_callback_successes(&state, chunk_successes, callback_buffer_max_items);
            }
            if chunk_error.is_none()
                && should_flush_pending_callbacks(
                    &state,
                    callback_flush_size,
                    callback_buffer_max_items,
                    fetched,
                    callback_flush_max_wait_ms,
                )
            {
                let (flushed_callbacks, acked_batch, callback_elapsed_ms) =
                    match flush_published_callback_batch(&state, ack_concurrency).await {
                        Ok(value) => value,
                        Err(err) => {
                            chunk_error = Some(err.to_string());
                            (0, 0, 0)
                        }
                    };
                callback_success_count += flushed_callbacks;
                ack_target_count += flushed_callbacks;
                ack_success_count += acked_batch;
                acked += acked_batch;
                cycle_metrics.callback_elapsed_ms += callback_elapsed_ms;
            }
            if chunk_error.is_none() {
                let (buffered_count, _) = pending_callback_state(&state);
                if should_force_flush_at_cycle_tail(buffered_count, fetched, fetch_limit) {
                    let (flushed_callbacks, acked_batch, callback_elapsed_ms) =
                        match flush_published_callback_batch(&state, ack_concurrency).await {
                            Ok(value) => value,
                            Err(err) => {
                                chunk_error = Some(err.to_string());
                                (0, 0, 0)
                            }
                        };
                    callback_success_count += flushed_callbacks;
                    ack_target_count += flushed_callbacks;
                    ack_success_count += acked_batch;
                    acked += acked_batch;
                    cycle_metrics.callback_elapsed_ms += callback_elapsed_ms;
                }
            }
            if let Some(err) = chunk_error {
                record_cycle(
                    &state,
                    fetched,
                    acked,
                    failed,
                    started.elapsed().as_millis(),
                    cycle_metrics,
                    Some(err),
                );
                continue;
            }
            failed += publish_failure_count;

            if !terminal_ack_messages.is_empty() {
                let ack_started = std::time::Instant::now();
                let acked_batch = match ack_messages(terminal_ack_messages, ack_concurrency).await {
                    Ok(value) => value,
                    Err(err) => {
                        record_cycle(
                            &state,
                            fetched,
                            acked,
                            failed,
                            started.elapsed().as_millis(),
                            cycle_metrics,
                            Some(err.to_string()),
                        );
                        continue;
                    }
                };
                acked += acked_batch;
                ack_success_count += acked_batch;
                cycle_metrics.ack_elapsed_ms += ack_started.elapsed().as_millis();
                if acked_batch < fetch_failures + binding_failure_count + duplicate_ack_count {
                    failed += (fetch_failures + binding_failure_count + duplicate_ack_count)
                        - acked_batch;
                }
            }

            cycle_metrics.cdn_publish_stage = PublisherStageRuntime {
                last_batch_size: total_prepared,
                last_concurrency: 1,
                last_success_count: publish_success_count,
                last_failure_count: publish_failure_count,
                last_elapsed_ms: cycle_metrics.publish_elapsed_ms,
            };
            cycle_metrics.root_callback_stage = PublisherStageRuntime {
                last_batch_size: callback_success_count,
                last_concurrency: 1,
                last_success_count: callback_success_count,
                last_failure_count: 0,
                last_elapsed_ms: cycle_metrics.callback_elapsed_ms,
            };
            cycle_metrics.ack_stage = PublisherStageRuntime {
                last_batch_size: ack_target_count,
                last_concurrency: ack_concurrency,
                last_success_count: ack_success_count,
                last_failure_count: ack_target_count.saturating_sub(ack_success_count),
                last_elapsed_ms: cycle_metrics.ack_elapsed_ms,
            };
        } else if !terminal_ack_messages.is_empty() {
            let ack_concurrency = state.config.events.max_in_flight.max(1);
            cycle_metrics.ack_concurrency = ack_concurrency;
            let ack_started = std::time::Instant::now();
            let acked_batch = match ack_messages(terminal_ack_messages, ack_concurrency).await {
                Ok(value) => value,
                Err(err) => {
                    record_cycle(
                        &state,
                        fetched,
                        acked,
                        failed,
                        started.elapsed().as_millis(),
                        cycle_metrics,
                        Some(err.to_string()),
                    );
                    continue;
                }
            };
            acked += acked_batch;
            cycle_metrics.ack_elapsed_ms = ack_started.elapsed().as_millis();
            let ack_target_count = fetch_failures + binding_failure_count + duplicate_ack_count;
            cycle_metrics.ack_stage = PublisherStageRuntime {
                last_batch_size: ack_target_count,
                last_concurrency: ack_concurrency,
                last_success_count: acked_batch,
                last_failure_count: ack_target_count.saturating_sub(acked_batch),
                last_elapsed_ms: cycle_metrics.ack_elapsed_ms,
            };
            if acked_batch < ack_target_count {
                failed += ack_target_count - acked_batch;
            }
        }
        if fetched == 0 {
            let callback_flush_size = completion_flush_size(state.config.events.batch_size, 1);
            let callback_flush_max_wait_ms =
                completion_flush_max_wait_ms(state.config.events.fetch_timeout_ms);
            let callback_buffer_max_items = completion_buffer_max_items(
                state.config.events.batch_size,
                state.config.events.max_in_flight,
            );
            if should_flush_pending_callbacks(
                &state,
                callback_flush_size,
                callback_buffer_max_items,
                0,
                callback_flush_max_wait_ms,
            ) {
                let ack_concurrency = state.config.events.max_in_flight.max(1);
                let (flushed_callbacks, acked_batch, callback_elapsed_ms) =
                    match flush_published_callback_batch(&state, ack_concurrency).await {
                        Ok(value) => value,
                        Err(err) => {
                            record_cycle(
                                &state,
                                fetched,
                                acked,
                                failed,
                                started.elapsed().as_millis(),
                                cycle_metrics,
                                Some(err.to_string()),
                            );
                            tokio::task::yield_now().await;
                            continue;
                        }
                    };
                acked += acked_batch;
                cycle_metrics.callback_elapsed_ms += callback_elapsed_ms;
                cycle_metrics.root_callback_stage = PublisherStageRuntime {
                    last_batch_size: flushed_callbacks,
                    last_concurrency: 1,
                    last_success_count: flushed_callbacks,
                    last_failure_count: 0,
                    last_elapsed_ms: cycle_metrics.callback_elapsed_ms,
                };
                cycle_metrics.ack_stage = PublisherStageRuntime {
                    last_batch_size: flushed_callbacks,
                    last_concurrency: ack_concurrency,
                    last_success_count: acked_batch,
                    last_failure_count: flushed_callbacks.saturating_sub(acked_batch),
                    last_elapsed_ms: cycle_metrics.ack_elapsed_ms,
                };
                if acked_batch < flushed_callbacks {
                    failed += flushed_callbacks - acked_batch;
                }
            }
        }
        record_cycle(
            &state,
            fetched,
            acked,
            failed,
            started.elapsed().as_millis(),
            cycle_metrics,
            None,
        );
        if fetched == 0 {
            tokio::task::yield_now().await;
        }
    }
}

async fn process_publish_chunk(
    state: &AppState,
    chunk: Vec<PreparedPublishTask>,
) -> Result<(usize, usize, Vec<ChunkPublishSuccess>, u128)> {
    if chunk.is_empty() {
        return Ok((0, 0, Vec::new(), 0));
    }
    let publish_started = std::time::Instant::now();
    let publish_outcome = publish_packages_to_cdn(
        state,
        chunk
            .iter()
            .map(|item| (item.publication_cursor, item.package.clone()))
            .collect(),
    )
    .await?;

    let mut successful = Vec::new();
    let mut unknown_publish_failures = 0usize;
    for item in chunk {
        if publish_outcome
            .published_cursors
            .contains(&item.publication_cursor)
        {
            successful.push(ChunkPublishSuccess {
                item: ResourceCdnPublishBatchItem {
                    publication_cursor: item.publication_cursor,
                    package: item.package.clone(),
                },
                message: item.message,
            });
        } else if !publish_outcome
            .failed_cursors
            .contains(&item.publication_cursor)
        {
            unknown_publish_failures = unknown_publish_failures.saturating_add(1);
        }
    }

    Ok((
        publish_outcome.published_count,
        publish_outcome.retry_count + unknown_publish_failures,
        successful,
        publish_outcome
            .publish_elapsed_ms
            .max(publish_started.elapsed().as_millis()),
    ))
}

async fn flush_published_callback_batch(
    state: &AppState,
    ack_concurrency: usize,
) -> Result<(usize, usize, u128)> {
    let drained = take_pending_callback_batch(state);
    if drained.is_empty() {
        return Ok((0, 0, 0));
    }
    let items = drained
        .iter()
        .map(|item| item.item.clone())
        .collect::<Vec<_>>();
    let messages = drained
        .into_iter()
        .map(|item| item.message)
        .collect::<Vec<_>>();
    let callback_started = std::time::Instant::now();
    mark_root_jobs_published(state, &items).await?;
    let callback_elapsed_ms = callback_started.elapsed().as_millis();
    let acked_batch = ack_messages(messages, ack_concurrency).await?;
    Ok((items.len(), acked_batch, callback_elapsed_ms))
}

fn buffer_callback_successes(
    state: &AppState,
    successes: Vec<ChunkPublishSuccess>,
    _max_items: usize,
) {
    if successes.is_empty() {
        return;
    }
    if let Ok(mut pending) = state.pending_callbacks.lock() {
        if pending.first_buffered_at.is_none() {
            pending.first_buffered_at = Some(std::time::Instant::now());
        }
        pending.items.extend(successes);
    }
}

fn pending_callback_state(state: &AppState) -> (usize, Option<u128>) {
    state.pending_callbacks.lock().map_or((0, None), |pending| {
        (
            pending.items.len(),
            pending
                .first_buffered_at
                .map(|started| started.elapsed().as_millis()),
        )
    })
}

fn should_flush_pending_callbacks(
    state: &AppState,
    flush_size: usize,
    max_items: usize,
    cycle_fetched: usize,
    max_wait_ms: u64,
) -> bool {
    let (buffered_count, oldest_age_ms) = pending_callback_state(state);
    should_flush_callback_buffer(
        buffered_count,
        flush_size,
        max_items,
        cycle_fetched,
        oldest_age_ms,
        max_wait_ms,
    )
}

fn take_pending_callback_batch(state: &AppState) -> Vec<ChunkPublishSuccess> {
    if let Ok(mut pending) = state.pending_callbacks.lock() {
        pending.first_buffered_at = None;
        return std::mem::take(&mut pending.items);
    }
    Vec::new()
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

fn decode_fetched_batch(
    batch: Vec<(
        async_nats::jetstream::Message,
        Result<CdnPublishRequestedEvent>,
    )>,
) -> (Vec<FetchedEventTask>, Vec<TerminalFailureTask>) {
    let mut decoded = Vec::new();
    let mut failures = Vec::new();
    for (message, event) in batch {
        match event {
            Ok(event) => decoded.push(FetchedEventTask { message, event }),
            Err(err) => {
                eprintln!("cdn-publisher failed to decode task: {err}");
                failures.push(TerminalFailureTask { message });
            }
        }
    }
    (decoded, failures)
}

fn decode_event_payload(payload: &[u8]) -> Result<CdnPublishRequestedEvent> {
    let event: CdnPublishRequestedEvent = serde_json::from_slice(payload)?;
    event.validate().map_err(|err| anyhow!(err))?;
    Ok(event)
}

fn dedupe_fetched_tasks_by_job_key(
    tasks: Vec<FetchedEventTask>,
) -> (Vec<FetchedEventTask>, Vec<FetchedEventTask>) {
    split_duplicate_tasks_by_key(tasks, |task| task.event.job_key.as_str())
}

fn split_duplicate_tasks_by_key<T, F>(tasks: Vec<T>, key: F) -> (Vec<T>, Vec<T>)
where
    F: Fn(&T) -> &str,
{
    let mut seen = BTreeSet::new();
    let mut unique = Vec::new();
    let mut duplicates = Vec::new();
    for task in tasks {
        if seen.insert(key(&task).to_owned()) {
            unique.push(task);
        } else {
            duplicates.push(task);
        }
    }
    (unique, duplicates)
}

async fn prepare_publish_batch(
    state: &AppState,
    decoded: Vec<FetchedEventTask>,
) -> Result<(
    Vec<PreparedPublishTask>,
    Vec<TerminalFailureTask>,
    PublisherStageRuntime,
    PublisherStageRuntime,
)> {
    if decoded.is_empty() {
        return Ok((
            Vec::new(),
            Vec::new(),
            PublisherStageRuntime::default(),
            PublisherStageRuntime::default(),
        ));
    }
    let input_batch_size = decoded.len();
    let root_fetch_started = std::time::Instant::now();
    let event_refs = decoded.iter().map(|item| &item.event).collect::<Vec<_>>();
    let packages = fetch_resource_packages_batch(state, event_refs.as_slice()).await?;
    let root_fetch_elapsed_ms = root_fetch_started.elapsed().as_millis();

    let binding_started = std::time::Instant::now();
    let events = decoded
        .iter()
        .map(|item| item.event.clone())
        .collect::<Vec<_>>();
    let classification = classify_prepared_packages(&events, &packages);
    let mut classified_by_job = classification
        .prepared
        .into_iter()
        .map(|(job_key, publication_cursor, package)| (job_key, (publication_cursor, package)))
        .collect::<BTreeMap<_, _>>();
    let mut prepared = Vec::new();
    let mut terminal_failures = Vec::new();
    for item in decoded {
        if let Some((publication_cursor, package)) = classified_by_job.remove(&item.event.job_key) {
            prepared.push(PreparedPublishTask {
                message: item.message,
                publication_cursor,
                package,
            });
        } else if classification
            .terminal_job_keys
            .contains(&item.event.job_key)
        {
            eprintln!(
                "cdn-publisher dropped terminal invalid task for job: {}",
                item.event.job_key
            );
            terminal_failures.push(TerminalFailureTask {
                message: item.message,
            });
        } else if !packages.contains_key(&item.event.job_key) {
            eprintln!(
                "cdn-publisher will retry missing root package for job: {}",
                item.event.job_key
            );
        } else {
            eprintln!(
                "cdn-publisher will retry unresolved task for {}",
                item.event.job_key
            );
        }
    }
    let binding_elapsed_ms = binding_started.elapsed().as_millis();
    Ok((
        prepared,
        terminal_failures,
        PublisherStageRuntime {
            last_batch_size: input_batch_size,
            last_concurrency: 1,
            last_success_count: input_batch_size.saturating_sub(classification.root_fetch_failures),
            last_failure_count: classification.root_fetch_failures,
            last_elapsed_ms: root_fetch_elapsed_ms,
        },
        PublisherStageRuntime {
            last_batch_size: input_batch_size.saturating_sub(classification.root_fetch_failures),
            last_concurrency: 1,
            last_success_count: input_batch_size.saturating_sub(
                classification.root_fetch_failures + classification.binding_failures,
            ),
            last_failure_count: classification.binding_failures,
            last_elapsed_ms: binding_elapsed_ms,
        },
    ))
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
    Ok(())
}

fn classify_prepared_packages(
    events: &[CdnPublishRequestedEvent],
    packages: &BTreeMap<String, (i64, ResourcePackage)>,
) -> PreparedBatchClassification {
    let mut classification = PreparedBatchClassification::default();
    for event in events {
        let job_key = event.job_key.clone();
        let Some((publication_cursor, package)) = packages.get(&job_key).cloned() else {
            classification.root_fetch_failures += 1;
            continue;
        };
        if validate_package_matches_event(&package, event).is_err() {
            classification.binding_failures += 1;
            classification.terminal_job_keys.insert(job_key);
            continue;
        }
        classification
            .prepared
            .push((job_key, publication_cursor, package));
    }
    classification
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
                "jobKey": event.job_key
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
    let items = serde_json::from_value::<Vec<RootBatchPackageItem>>(
        value
            .get("items")
            .cloned()
            .ok_or_else(|| anyhow!("root_package_batch_items_missing"))?,
    )?;
    let mut packages = BTreeMap::new();
    for item in items {
        if item.job_key.trim().is_empty() {
            return Err(anyhow!("root_package_batch_job_key_missing"));
        }
        if item.publication_cursor <= 0 {
            return Err(anyhow!("root_package_batch_cursor_missing"));
        }
        if item.resource_did != item.package.resource_did {
            return Err(anyhow!("root_package_batch_resource_did_mismatch"));
        }
        if item.package_version != item.package.package_version {
            return Err(anyhow!("root_package_batch_package_version_mismatch"));
        }
        if item.package_hash != item.package.package_hash {
            return Err(anyhow!("root_package_batch_package_hash_mismatch"));
        }
        if item.did_document_hash != item.package.did_document_hash {
            return Err(anyhow!("root_package_batch_did_document_hash_mismatch"));
        }
        if item.metadata_hash != item.package.metadata_hash {
            return Err(anyhow!("root_package_batch_metadata_hash_mismatch"));
        }
        packages.insert(item.job_key, (item.publication_cursor, item.package));
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
) -> Result<CdnBatchPublishOutcome> {
    if packages.is_empty() {
        return Ok(CdnBatchPublishOutcome::default());
    }
    let request = build_cdn_batch_publish_request(state, packages)?;
    let url = cdn_publish_batch_url(
        &state.config.cdn.endpoint,
        &state.config.cdn.publish_batch_path,
    )?;
    let publish_started = std::time::Instant::now();
    let response = state.client.post(url).json(&request).send().await?;
    let publish_elapsed_ms = publish_started.elapsed().as_millis();
    let status = response.status();
    let value = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    if !status.is_success() {
        return Err(anyhow!("cdn_publish_failed:{status}:{value}"));
    }
    let published_cursors = extract_publish_cursors(&value, "items")?;
    let failed_cursors = extract_publish_cursors(&value, "failed").unwrap_or_default();
    let retry_count = value
        .get("failedCount")
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    if published_cursors.len() + retry_count != request.items.len() {
        return Err(anyhow!(
            "cdn_publish_response_count_mismatch:accepted={} failed={} requested={}",
            published_cursors.len(),
            retry_count,
            request.items.len()
        ));
    }
    Ok(CdnBatchPublishOutcome {
        published_count: published_cursors.len(),
        retry_count,
        failed_cursors,
        published_cursors,
        publish_elapsed_ms,
    })
}

fn extract_publish_cursors(value: &Value, field: &str) -> Result<BTreeSet<i64>> {
    let mut cursors = BTreeSet::new();
    let items = value
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("cdn_publish_items_missing"))?;
    for item in items {
        let cursor = item
            .get("publicationCursor")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("cdn_publish_item_cursor_missing"))?;
        cursors.insert(cursor);
    }
    Ok(cursors)
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
                "jobKey": format!("{}:{}", item.package.resource_did, item.package.package_version)
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
    metrics: PublisherCycleMetrics,
    error: Option<String>,
) {
    if let Ok(mut runtime) = state.runtime.lock() {
        runtime.last_fetched_count = fetched;
        runtime.last_acked_count = acked;
        runtime.last_failed_count = failed;
        runtime.total_acked_count = runtime.total_acked_count.saturating_add(acked as u64);
        runtime.total_failed_count = runtime.total_failed_count.saturating_add(failed as u64);
        runtime.last_elapsed_ms = elapsed_ms;
        runtime.last_fetch_elapsed_ms = metrics.fetch_elapsed_ms;
        runtime.last_prepare_elapsed_ms = metrics
            .root_fetch_elapsed_ms
            .saturating_add(metrics.binding_elapsed_ms);
        runtime.last_publish_elapsed_ms = metrics.publish_elapsed_ms;
        runtime.last_callback_elapsed_ms = metrics.callback_elapsed_ms;
        runtime.last_ack_elapsed_ms = metrics.ack_elapsed_ms;
        runtime.last_effective_batch_size = metrics.effective_batch_size;
        runtime.last_ack_concurrency = metrics.ack_concurrency;
        runtime.fetch_stage = metrics.fetch_stage;
        runtime.root_fetch_stage = metrics.root_fetch_stage;
        runtime.binding_stage = metrics.binding_stage;
        runtime.cdn_publish_stage = metrics.cdn_publish_stage;
        runtime.root_callback_stage = metrics.root_callback_stage;
        runtime.ack_stage = metrics.ack_stage;
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
            pending_callbacks: Arc::new(Mutex::new(PendingCallbackBatch::default())),
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
                authorized_domains: vec![],
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
        assert_eq!(jobs[0]["jobKey"], "did:oan:AGUS:test:1.0.0");
        assert_eq!(jobs[1]["jobKey"], "did:oan:AGUS:test2:2.0.0");
        assert_eq!(jobs[0].as_object().map(|value| value.len()), Some(1));
        assert_eq!(jobs[1].as_object().map(|value| value.len()), Some(1));
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
    fn split_duplicate_tasks_by_key_keeps_first_item_for_each_job() {
        let tasks = vec![
            ("job-a".to_owned(), 1),
            ("job-b".to_owned(), 2),
            ("job-a".to_owned(), 3),
        ];

        let (unique, duplicates) =
            split_duplicate_tasks_by_key(tasks, |task| task.0.as_str());

        assert_eq!(
            unique,
            vec![("job-a".to_owned(), 1), ("job-b".to_owned(), 2)]
        );
        assert_eq!(duplicates, vec![("job-a".to_owned(), 3)]);
    }

    #[test]
    fn rejects_package_that_does_not_match_event_reference() {
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
        validate_package_matches_event(&mismatched, &event).unwrap();
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
                    "resourceDid": "did:oan:AGUS:test",
                    "packageVersion": "1.0.0",
                    "packageHash": "sha256:package",
                    "didDocumentHash": "sha256:document",
                    "metadataHash": "sha256:metadata",
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
        let packages = fetch_resource_packages_batch(&state, &[&event])
            .await
            .unwrap();
        let classified = classify_prepared_packages(&[event], &packages);

        assert_eq!(classified.root_fetch_failures, 0);
        assert_eq!(classified.binding_failures, 0);
        assert!(classified.terminal_job_keys.is_empty());
        assert_eq!(classified.prepared.len(), 1);
        assert_eq!(classified.prepared[0].1, 42);
        assert_eq!(classified.prepared[0].2.resource_did, "did:oan:AGUS:test");
    }

    #[test]
    fn classify_prepared_packages_splits_valid_missing_and_terminal_invalid_items() {
        let valid_event = sample_event();
        let mut invalid_event = sample_event();
        invalid_event.job_key = "did:oan:AGUS:invalid:1.0.0".to_owned();
        invalid_event.resource_did = "did:oan:AGUS:invalid".to_owned();
        invalid_event.package_version = "9.9.9".to_owned();
        let mut invalid_package = sample_package();
        invalid_package.resource_did = invalid_event.resource_did.clone();
        invalid_package.metadata.resource_did = invalid_event.resource_did.clone();
        invalid_package.package_version = "1.0.0".to_owned();
        invalid_package.metadata.package_version = invalid_package.package_version.clone();

        let mut packages = BTreeMap::new();
        packages.insert(valid_event.job_key.clone(), (42, sample_package()));
        packages.insert(invalid_event.job_key.clone(), (43, invalid_package));

        let classified =
            classify_prepared_packages(&[valid_event.clone(), invalid_event.clone()], &packages);

        assert_eq!(classified.prepared.len(), 1);
        assert_eq!(classified.prepared[0].0, valid_event.job_key);
        assert_eq!(classified.root_fetch_failures, 0);
        assert_eq!(classified.binding_failures, 1);
        assert!(classified
            .terminal_job_keys
            .contains(&invalid_event.job_key));
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
        record_cycle(
            &state,
            3,
            2,
            1,
            12,
            PublisherCycleMetrics {
                fetch_elapsed_ms: 2,
                root_fetch_elapsed_ms: 3,
                binding_elapsed_ms: 4,
                publish_elapsed_ms: 4,
                callback_elapsed_ms: 5,
                ack_elapsed_ms: 1,
                effective_batch_size: 3,
                ack_concurrency: 2,
                fetch_stage: PublisherStageRuntime {
                    last_batch_size: 3,
                    last_concurrency: 1,
                    last_success_count: 2,
                    last_failure_count: 1,
                    last_elapsed_ms: 2,
                },
                root_fetch_stage: PublisherStageRuntime {
                    last_batch_size: 2,
                    last_concurrency: 1,
                    last_success_count: 2,
                    last_failure_count: 0,
                    last_elapsed_ms: 3,
                },
                binding_stage: PublisherStageRuntime {
                    last_batch_size: 2,
                    last_concurrency: 1,
                    last_success_count: 1,
                    last_failure_count: 1,
                    last_elapsed_ms: 4,
                },
                cdn_publish_stage: PublisherStageRuntime {
                    last_batch_size: 1,
                    last_concurrency: 1,
                    last_success_count: 1,
                    last_failure_count: 0,
                    last_elapsed_ms: 4,
                },
                root_callback_stage: PublisherStageRuntime {
                    last_batch_size: 1,
                    last_concurrency: 1,
                    last_success_count: 1,
                    last_failure_count: 0,
                    last_elapsed_ms: 5,
                },
                ack_stage: PublisherStageRuntime {
                    last_batch_size: 1,
                    last_concurrency: 2,
                    last_success_count: 1,
                    last_failure_count: 0,
                    last_elapsed_ms: 1,
                },
            },
            Some("err".to_owned()),
        );
        let runtime = state.runtime.lock().unwrap().clone();
        assert_eq!(runtime.last_fetched_count, 3);
        assert_eq!(runtime.total_acked_count, 2);
        assert_eq!(runtime.total_failed_count, 1);
        assert_eq!(runtime.last_fetch_elapsed_ms, 2);
        assert_eq!(runtime.last_prepare_elapsed_ms, 7);
        assert_eq!(runtime.last_publish_elapsed_ms, 4);
        assert_eq!(runtime.last_callback_elapsed_ms, 5);
        assert_eq!(runtime.last_ack_elapsed_ms, 1);
        assert_eq!(runtime.last_effective_batch_size, 3);
        assert_eq!(runtime.last_ack_concurrency, 2);
        assert_eq!(runtime.fetch_stage.last_failure_count, 1);
        assert_eq!(runtime.root_fetch_stage.last_success_count, 2);
        assert_eq!(runtime.binding_stage.last_failure_count, 1);
        assert_eq!(runtime.cdn_publish_stage.last_success_count, 1);
        assert_eq!(runtime.root_callback_stage.last_batch_size, 1);
        assert_eq!(runtime.ack_stage.last_concurrency, 2);
        assert_eq!(runtime.last_error.as_deref(), Some("err"));
    }

    #[test]
    fn extracts_published_cursors_from_partial_cdn_response() {
        let value = json!({
            "status": "partial",
            "acceptedCount": 2,
            "failedCount": 1,
            "items": [
                { "resourceDid": "did:oan:AGUS:test", "publicationCursor": 42, "status": "published" },
                { "resourceDid": "did:oan:AGUS:test2", "publicationCursor": 43, "status": "published" }
            ],
            "failed": [
                { "resourceDid": "did:oan:AGUS:test3", "publicationCursor": 44, "error": "bad_hash" }
            ]
        });

        let cursors = extract_publish_cursors(&value, "items").unwrap();

        assert_eq!(cursors.len(), 2);
        assert!(cursors.contains(&42));
        assert!(cursors.contains(&43));
    }

    #[test]
    fn completion_flush_size_prefers_coarser_root_callback_batches() {
        assert_eq!(completion_flush_size(10, 8), 8);
        assert_eq!(completion_flush_size(10, 200), 192);
        assert_eq!(completion_flush_size(128, 200), 192);
    }

    #[test]
    fn pipeline_chunk_size_can_use_larger_batches_under_load() {
        assert_eq!(pipeline_chunk_size(200, 200, 200), 32);
        assert_eq!(pipeline_chunk_size(512, 512, 512), 32);
        assert_eq!(pipeline_chunk_size(64, 200, 80), 32);
    }

    #[test]
    fn cycle_tail_flushes_when_fetch_returns_partial_batch() {
        assert!(should_force_flush_at_cycle_tail(12, 80, 200));
        assert!(!should_force_flush_at_cycle_tail(0, 80, 200));
        assert!(!should_force_flush_at_cycle_tail(12, 200, 200));
        assert!(!should_force_flush_at_cycle_tail(12, 0, 200));
    }

    #[test]
    fn callback_flush_policy_waits_for_size_or_idle_or_timeout() {
        assert!(!should_flush_callback_buffer(0, 128, 512, 12, None, 500));
        assert!(!should_flush_callback_buffer(
            64,
            128,
            512,
            12,
            Some(100),
            500
        ));
        assert!(should_flush_callback_buffer(
            128,
            128,
            512,
            12,
            Some(100),
            500
        ));
        assert!(should_flush_callback_buffer(
            64,
            128,
            512,
            0,
            Some(100),
            500
        ));
        assert!(should_flush_callback_buffer(
            64,
            128,
            512,
            12,
            Some(800),
            500
        ));
        assert!(should_flush_callback_buffer(
            512,
            128,
            512,
            12,
            Some(100),
            500
        ));
    }

    #[test]
    fn completion_buffer_max_items_has_reasonable_bounds() {
        assert_eq!(completion_buffer_max_items(10, 8), 384);
        assert_eq!(completion_buffer_max_items(128, 16), 1024);
        assert_eq!(completion_buffer_max_items(1024, 512), 6144);
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
