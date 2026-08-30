// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use anyhow::{anyhow, Result};
use axum::{
    extract::{Path as AxumPath, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use bytes::Bytes;
use chrono::Utc;
use oan_bulletin::{Bulletin, BulletinEvent, BulletinEventCore, BulletinEventType};
use oan_core::{CapabilityTag, CapabilityTagTree, CryptoSuite, DidDocument, ResourceType};
use oan_crypto::{
    build_data_integrity_proof, hash_json_with_suite, sign_bytes, signature_input,
    signing_key_from_bytes, SigningKey,
};
use oan_package::{
    hash_resource_metadata_with_suite, ResourceMetadata, ResourcePackage, ResourcePackageClaims,
    RootProof,
};
#[cfg(test)]
use oan_protocol::OAN_RESOURCE_PROTOCOL_VERSION;
use oan_protocol::{
    HealthResponse, InfrastructureAuthorizationVcIssuePayload,
    InfrastructureAuthorizationVcIssueRequest, ResourceVerifyAndPublishRequest,
    RootAuthorizeRequest, PATH_ROOT_INFRASTRUCTURE_AUTHORIZATION_VCS_ISSUE,
    PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH, PURPOSE_INFRASTRUCTURE_AUTHORIZATION_VC_ISSUE,
    PURPOSE_VERIFY_AND_PUBLISH,
};
use oan_publication_events::{CdnPublishRequestedEvent, CdnPublishRequestedEventInput};
use oan_service_security::{
    bearer_token_from_header, request_id, verify_admin_token, verify_signed_request_envelope,
    AdminAuthConfig, AdminAuthMode, AdminPrincipal, TrustedUpstreamPolicy,
};
#[cfg(test)]
use oan_service_security::{
    create_signed_request_envelope, request_nonce, SignedRequestEnvelopeInput,
};
use oan_storage::{
    did_to_file_name, DatabaseBackend, DatabaseConfig, JsonStore, PostgresJsonStore,
    SqliteJsonStore,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{QueryBuilder, Row, Sqlite};
use std::{
    collections::BTreeMap,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration as StdDuration, Instant},
};
use tokio::time::{sleep, Duration as TokioDuration};
use tokio::{
    sync::{Notify, Semaphore},
    task::JoinSet,
};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

mod repository;

const ROOT_CDN_JOB_TABLE: &str = "root_cdn_publish_jobs";
const ROOT_CDN_OUTBOX_TABLE: &str = "root_cdn_publish_outbox";
const ROOT_DISCOVERY_TARGET_TABLE: &str = "root_discovery_target_notifications";
const ROOT_DISCOVERY_ITEM_TABLE: &str = "root_discovery_notification_items";
const ROOT_BULLETIN_EVENT_TABLE: &str = "root_bulletin_events";
const ROOT_SUBJECT_LATEST_TABLE: &str = "root_subject_latest";
const ROOT_SUBJECT_VERSION_TABLE: &str = "root_subject_versions";
const ROOT_PACKAGE_JOB_TABLE: &str = "root_verified_package_jobs";
const ROOT_DEBUG_EXPORT_INTERVAL_MS: u64 = 2_000;
const ROOT_STATUS_CACHE_TTL_MS: u64 = 500;

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    #[serde(default)]
    cors: CorsConfig,
    #[serde(default)]
    debug: DebugConfig,
    #[serde(default)]
    events: EventStreamConfig,
    #[serde(default)]
    security: SecurityConfig,
    paths: PathConfig,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerConfig {
    host: String,
    port: u16,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct CorsConfig {
    #[serde(default)]
    allowed_origins: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct DebugConfig {
    #[serde(default)]
    export_snapshots: bool,
    #[serde(default = "default_debug_export_interval_ms")]
    export_interval_ms: u64,
}

impl Default for DebugConfig {
    fn default() -> Self {
        Self {
            export_snapshots: false,
            export_interval_ms: default_debug_export_interval_ms(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct EventStreamConfig {
    #[serde(default = "default_event_enabled")]
    enabled: bool,
    #[serde(default = "default_event_backend")]
    backend: String,
    #[serde(default = "default_event_endpoint")]
    endpoint: String,
    #[serde(default = "default_event_stream")]
    stream: String,
    #[serde(default = "default_cdn_publish_subject")]
    cdn_publish_subject: String,
    #[serde(default = "default_event_publish_timeout_ms")]
    publish_timeout_ms: u64,
    #[serde(default = "default_event_failure_mode")]
    failure_mode: String,
}

impl Default for EventStreamConfig {
    fn default() -> Self {
        Self {
            enabled: default_event_enabled(),
            backend: default_event_backend(),
            endpoint: default_event_endpoint(),
            stream: default_event_stream(),
            cdn_publish_subject: default_cdn_publish_subject(),
            publish_timeout_ms: default_event_publish_timeout_ms(),
            failure_mode: default_event_failure_mode(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize)]
struct SecurityConfig {
    #[serde(default)]
    admin: AdminSecurityConfig,
    #[serde(default)]
    trusted_upstream: TrustedUpstreamSecurityConfig,
    #[serde(default)]
    workers: WorkerSecurityConfig,
    #[serde(default)]
    trust_indexer: TrustIndexerConfig,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct AdminSecurityConfig {
    #[serde(default = "default_admin_mode")]
    mode: String,
    #[serde(default)]
    static_tokens: Vec<String>,
    #[serde(default)]
    trusted_admin_dids: Vec<String>,
    #[serde(default = "default_clock_skew_seconds")]
    max_clock_skew_seconds: i64,
    #[serde(default = "default_nonce_ttl_seconds")]
    nonce_ttl_seconds: i64,
    #[serde(default = "default_admin_nonce_file")]
    nonce_store_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize)]
struct TrustedUpstreamSecurityConfig {
    #[serde(default = "default_clock_skew_seconds")]
    max_clock_skew_seconds: i64,
    #[serde(default = "default_nonce_ttl_seconds")]
    nonce_ttl_seconds: i64,
}

impl Default for TrustedUpstreamSecurityConfig {
    fn default() -> Self {
        Self {
            max_clock_skew_seconds: default_clock_skew_seconds(),
            nonce_ttl_seconds: default_nonce_ttl_seconds(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct TrustIndexerConfig {
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default = "default_trust_indexer_fail_mode")]
    fail_mode: String,
    #[serde(default = "default_trust_indexer_timeout_ms")]
    timeout_ms: u64,
    #[serde(default = "default_trust_indexer_poll_interval_ms")]
    poll_interval_ms: u64,
}

impl Default for TrustIndexerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: Some("http://127.0.0.1:8088".to_owned()),
            fail_mode: default_trust_indexer_fail_mode(),
            timeout_ms: default_trust_indexer_timeout_ms(),
            poll_interval_ms: default_trust_indexer_poll_interval_ms(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct WorkerSecurityConfig {
    #[serde(default = "default_worker_enabled")]
    enabled: bool,
    #[serde(default = "default_cdn_worker_interval_ms")]
    cdn_interval_ms: u64,
    #[serde(default = "default_discovery_worker_interval_ms")]
    discovery_interval_ms: u64,
    #[serde(default = "default_cdn_worker_batch_size")]
    cdn_batch_size: usize,
    #[serde(default = "default_discovery_worker_batch_size")]
    discovery_batch_size: usize,
    #[serde(default = "default_cdn_worker_concurrency")]
    cdn_concurrency: usize,
    #[serde(default = "default_discovery_worker_concurrency")]
    discovery_concurrency: usize,
    #[serde(default = "default_root_admission_concurrency")]
    admission_concurrency: usize,
    #[serde(default = "default_worker_lease_seconds")]
    lease_seconds: i64,
    #[serde(default = "default_worker_retry_backoff_seconds")]
    retry_backoff_seconds: i64,
    #[serde(default = "default_worker_http_timeout_seconds")]
    http_timeout_seconds: u64,
}

impl Default for WorkerSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: default_worker_enabled(),
            cdn_interval_ms: default_cdn_worker_interval_ms(),
            discovery_interval_ms: default_discovery_worker_interval_ms(),
            cdn_batch_size: default_cdn_worker_batch_size(),
            discovery_batch_size: default_discovery_worker_batch_size(),
            cdn_concurrency: default_cdn_worker_concurrency(),
            discovery_concurrency: default_discovery_worker_concurrency(),
            admission_concurrency: default_root_admission_concurrency(),
            lease_seconds: default_worker_lease_seconds(),
            retry_backoff_seconds: default_worker_retry_backoff_seconds(),
            http_timeout_seconds: default_worker_http_timeout_seconds(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct PathConfig {
    data_dir: PathBuf,
    keys_dir: PathBuf,
    bulletin_file: PathBuf,
    #[serde(default = "default_authorization_state_file")]
    authorization_state_file: PathBuf,
    #[serde(default = "default_request_nonce_file")]
    request_nonce_file: PathBuf,
    #[serde(default = "default_capability_tree_file")]
    capability_tree_file: PathBuf,
    #[serde(default)]
    database_url: Option<String>,
}

fn default_authorization_state_file() -> PathBuf {
    PathBuf::from("../../data/root/authorization-state.json")
}

fn default_request_nonce_file() -> PathBuf {
    PathBuf::from("../../data/root/request-nonces.json")
}

fn default_admin_nonce_file() -> PathBuf {
    PathBuf::from("../../data/root/admin-request-nonces.json")
}

fn default_capability_tree_file() -> PathBuf {
    PathBuf::from("../../docs/capability-tree-v1.json")
}

fn default_admin_mode() -> String {
    "static-token".to_owned()
}

fn default_event_backend() -> String {
    "nats-jetstream".to_owned()
}

fn default_event_endpoint() -> String {
    "nats://127.0.0.1:4222".to_owned()
}

fn default_event_stream() -> String {
    "OAN_RESOURCE_PUBLICATION".to_owned()
}

fn default_cdn_publish_subject() -> String {
    "oan.resource.cdn.publish.requested".to_owned()
}

fn default_event_enabled() -> bool {
    true
}

fn default_event_publish_timeout_ms() -> u64 {
    1_000
}

fn default_event_failure_mode() -> String {
    "fallback".to_owned()
}

fn default_worker_enabled() -> bool {
    true
}

fn default_cdn_worker_interval_ms() -> u64 {
    1_000
}

fn default_discovery_worker_interval_ms() -> u64 {
    1_500
}

fn default_cdn_worker_batch_size() -> usize {
    200
}

fn default_discovery_worker_batch_size() -> usize {
    100
}

fn default_cdn_worker_concurrency() -> usize {
    16
}

fn default_discovery_worker_concurrency() -> usize {
    8
}

fn default_root_admission_concurrency() -> usize {
    64
}

fn default_worker_lease_seconds() -> i64 {
    60
}

fn default_worker_retry_backoff_seconds() -> i64 {
    15
}

fn default_worker_http_timeout_seconds() -> u64 {
    10
}

fn default_debug_export_interval_ms() -> u64 {
    ROOT_DEBUG_EXPORT_INTERVAL_MS
}

fn default_trust_indexer_fail_mode() -> String {
    "closed".to_owned()
}

fn default_trust_indexer_timeout_ms() -> u64 {
    500
}

fn default_trust_indexer_poll_interval_ms() -> u64 {
    3_000
}

fn default_clock_skew_seconds() -> i64 {
    300
}

fn default_nonce_ttl_seconds() -> i64 {
    300
}

fn crypto_suite_from_algorithm(value: &str) -> Result<CryptoSuite> {
    match value {
        "Ed25519" => Ok(CryptoSuite::Ed25519Sha256),
        "SM2" => Ok(CryptoSuite::Sm2Sm3),
        other => Err(anyhow!("unsupported_algorithm: {other}")),
    }
}

#[derive(Clone)]
struct AppState {
    data: JsonStore,
    config: Config,
    root_did: String,
    signing_key: SigningKey,
    tag_tree: CapabilityTagTree,
    sqlite: Option<SqliteJsonStore>,
    postgres: Option<PostgresJsonStore>,
    authorization_state: Arc<Mutex<AuthorizationState>>,
    client: reqwest::Client,
    trust_indexer_client: reqwest::Client,
    event_publisher: EventPublisher,
    worker_runtime: Arc<Mutex<WorkerRuntimeState>>,
    event_runtime: Arc<Mutex<EventRuntimeState>>,
    admission_runtime: Arc<Mutex<AdmissionRuntimeState>>,
    status_counts_cache: Arc<Mutex<Option<CachedRootStatusCounts>>>,
    worker_wake_state: Arc<Mutex<WorkerWakeState>>,
    admission_semaphore: Arc<Semaphore>,
    cdn_worker_notify: Arc<Notify>,
    discovery_worker_notify: Arc<Notify>,
}

#[derive(Clone, Debug, Default)]
struct WorkerWakeState {
    cdn_last_event_signal_at: Option<Instant>,
    discovery_last_event_signal_at: Option<Instant>,
    cdn_pending_event_signal_count: u64,
    discovery_pending_event_signal_count: u64,
}

#[derive(Clone, Debug)]
struct CachedRootStatusCounts {
    captured_at: Instant,
    counts: RootStatusCounts,
}

#[derive(Clone, Debug, Default, Serialize)]
struct WorkerRuntimeState {
    cdn_last_elapsed_ms: u128,
    cdn_last_success_count: usize,
    cdn_last_failed_count: usize,
    cdn_last_progress_elapsed_ms: u128,
    cdn_last_progress_success_count: usize,
    cdn_last_progress_failed_count: usize,
    cdn_last_progress_trigger_type: Option<String>,
    cdn_last_claim_elapsed_ms: u128,
    cdn_last_publish_elapsed_ms: u128,
    cdn_last_mark_published_elapsed_ms: u128,
    cdn_last_mark_retry_elapsed_ms: u128,
    cdn_effective_batch_size: usize,
    cdn_effective_concurrency: usize,
    cdn_last_trigger_type: Option<String>,
    cdn_last_event_to_cycle_start_ms: u128,
    cdn_oldest_pending_age_ms: u128,
    cdn_event_trigger_count: u64,
    cdn_timer_trigger_count: u64,
    cdn_noop_cycle_count: u64,
    discovery_last_elapsed_ms: u128,
    discovery_last_success_count: usize,
    discovery_last_failed_count: usize,
    discovery_last_progress_elapsed_ms: u128,
    discovery_last_progress_success_count: usize,
    discovery_last_progress_failed_count: usize,
    discovery_last_progress_trigger_type: Option<String>,
    discovery_last_claim_elapsed_ms: u128,
    discovery_last_prepare_elapsed_ms: u128,
    discovery_last_notify_elapsed_ms: u128,
    discovery_effective_batch_size: usize,
    discovery_effective_item_batch_size: usize,
    discovery_effective_concurrency: usize,
    discovery_last_trigger_type: Option<String>,
    discovery_last_event_to_cycle_start_ms: u128,
    discovery_oldest_pending_age_ms: u128,
    discovery_event_trigger_count: u64,
    discovery_timer_trigger_count: u64,
    discovery_noop_cycle_count: u64,
    discovery_last_claimed_target_count: usize,
    discovery_last_carry_forward_count: usize,
    discovery_last_ready_queue_depth_after: usize,
    discovery_last_pending_queue_depth_after: usize,
    discovery_last_claimed_cursor_lag: i64,
    mark_published_last_fetch_elapsed_ms: u128,
    mark_published_last_fetch_sql_elapsed_ms: u128,
    mark_published_last_watermark_match_elapsed_ms: u128,
    mark_published_last_update_elapsed_ms: u128,
    mark_published_last_watermark_elapsed_ms: u128,
    mark_published_last_store_items_elapsed_ms: u128,
    mark_published_last_upsert_targets_elapsed_ms: u128,
    mark_published_last_delete_jobs_elapsed_ms: u128,
    mark_published_last_total_elapsed_ms: u128,
    mark_published_last_job_count: usize,
    mark_published_total_call_count: u64,
    mark_published_max_update_elapsed_ms: u128,
    mark_published_max_total_elapsed_ms: u128,
    updated_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug)]
enum WorkerTriggerType {
    Event,
    Timer,
}

#[derive(Clone, Copy, Debug, Default)]
struct CdnWorkerStageMetrics {
    claim_elapsed_ms: u128,
    publish_elapsed_ms: u128,
    mark_published_elapsed_ms: u128,
    mark_retry_elapsed_ms: u128,
}

#[derive(Clone, Copy, Debug, Default)]
struct DiscoveryWorkerStageMetrics {
    claim_elapsed_ms: u128,
    prepare_elapsed_ms: u128,
    notify_elapsed_ms: u128,
}

#[derive(Clone, Copy, Debug, Default)]
struct DiscoveryWorkerOutcomeMetrics {
    claimed_target_count: usize,
    carry_forward_count: usize,
    ready_queue_depth_after: usize,
    pending_queue_depth_after: usize,
    claimed_cursor_lag: i64,
    item_batch_size: usize,
}

struct DiscoveryWorkerRuntimeSample {
    elapsed_ms: u128,
    success_count: usize,
    failed_count: usize,
    batch_size: usize,
    concurrency: usize,
    stage_metrics: DiscoveryWorkerStageMetrics,
    outcome_metrics: DiscoveryWorkerOutcomeMetrics,
}

struct MarkPublishedRuntimeSample {
    job_count: usize,
    fetch_elapsed_ms: u128,
    fetch_sql_elapsed_ms: u128,
    watermark_match_elapsed_ms: u128,
    update_elapsed_ms: u128,
    watermark_elapsed_ms: u128,
    store_items_elapsed_ms: u128,
    upsert_targets_elapsed_ms: u128,
    delete_jobs_elapsed_ms: u128,
    total_elapsed_ms: u128,
}

#[derive(Clone, Debug, Default, Serialize)]
struct EventRuntimeState {
    enabled: bool,
    backend: String,
    stream: String,
    cdn_publish_subject: String,
    publish_success_count: u64,
    publish_failure_count: u64,
    last_error: Option<String>,
    updated_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GovernanceSubjectType {
    Registrar,
    Discovery,
    VcIssuer,
}

#[derive(Clone)]
enum EventPublisher {
    NatsJetStream(NatsJetStreamPublisher),
    #[cfg(test)]
    Succeed,
    #[cfg(test)]
    Failing(String),
}

#[derive(Clone)]
struct NatsJetStreamPublisher {
    context: async_nats::jetstream::Context,
    subject: String,
    publish_timeout_ms: u64,
}

impl EventPublisher {
    async fn from_config(config: &EventStreamConfig) -> Result<Self> {
        validate_event_failure_mode(&config.failure_mode)?;
        if !config.enabled {
            return Err(anyhow!(
                "root_cdn_event_stream_required: Root-to-CDN publication requires events.enabled=true"
            ));
        }
        if config.backend != "nats-jetstream" {
            return Err(anyhow!("unsupported_event_backend: {}", config.backend));
        }
        let client = async_nats::connect(&config.endpoint).await?;
        let context = async_nats::jetstream::new(client);
        context
            .get_or_create_stream(async_nats::jetstream::stream::Config {
                name: config.stream.clone(),
                subjects: vec![config.cdn_publish_subject.clone()],
                ..Default::default()
            })
            .await?;
        Ok(Self::NatsJetStream(NatsJetStreamPublisher {
            context,
            subject: config.cdn_publish_subject.clone(),
            publish_timeout_ms: config.publish_timeout_ms,
        }))
    }

    async fn publish_cdn_requested(&self, event: &CdnPublishRequestedEvent) -> Result<bool> {
        event.validate().map_err(|err| anyhow!(err))?;
        match self {
            Self::NatsJetStream(publisher) => publisher.publish_cdn_requested(event).await,
            #[cfg(test)]
            Self::Succeed => Ok(true),
            #[cfg(test)]
            Self::Failing(message) => Err(anyhow!(message.clone())),
        }
    }
}

fn validate_event_failure_mode(value: &str) -> Result<()> {
    match value {
        "fallback" | "closed" => Ok(()),
        other => Err(anyhow!("unsupported_event_failure_mode: {other}")),
    }
}

impl NatsJetStreamPublisher {
    async fn publish_cdn_requested(&self, event: &CdnPublishRequestedEvent) -> Result<bool> {
        let payload = serde_json::to_vec(event)?;
        tokio::time::timeout(
            TokioDuration::from_millis(self.publish_timeout_ms.max(1)),
            async {
                self.context
                    .publish(self.subject.clone(), Bytes::from(payload))
                    .await?
                    .await?;
                Ok::<(), anyhow::Error>(())
            },
        )
        .await
        .map_err(|_| anyhow!("event_publish_timeout"))??;
        Ok(true)
    }
}

impl GovernanceSubjectType {
    fn code(self) -> u8 {
        match self {
            Self::Registrar => 1,
            Self::Discovery => 2,
            Self::VcIssuer => 3,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Self::Registrar => "registrar",
            Self::Discovery => "discovery",
            Self::VcIssuer => "vc_issuer",
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GovernanceDecision {
    #[serde(default)]
    governance_active: bool,
    #[serde(default)]
    authorized: bool,
    #[serde(default)]
    reason: String,
    #[serde(default)]
    subject_type: String,
    #[serde(default)]
    subject_type_code: u8,
    #[serde(default)]
    subject_did: String,
    #[serde(default)]
    status: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct GovernanceSubjectRecord {
    subject_type: u8,
    #[serde(default)]
    subject_type_label: String,
    subject_did: String,
    status: u8,
    #[serde(default)]
    status_label: String,
    #[serde(default)]
    authorized_domains: Vec<String>,
    #[serde(default)]
    policy_hash: String,
    #[serde(default)]
    metadata_hash: String,
    #[serde(default)]
    effective_from_ms: u64,
    #[serde(default)]
    expires_at_ms: u64,
    #[serde(default)]
    version: u64,
    #[serde(default)]
    updated_at_ms: u64,
    #[serde(default)]
    last_sequence: u64,
    #[serde(default)]
    last_event_digest: String,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
struct TrustIndexerStatus {
    package_id: Option<String>,
    bulletin_object_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InfrastructureAuthorizationCredential {
    #[serde(rename = "@context")]
    context: Vec<String>,
    id: String,
    #[serde(rename = "type")]
    credential_type: Vec<String>,
    issuer: String,
    #[serde(rename = "issuanceDate")]
    issuance_date: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "credentialSubject")]
    credential_subject: InfrastructureAuthorizationCredentialSubject,
    #[serde(rename = "credentialStatus")]
    credential_status: InfrastructureAuthorizationCredentialStatus,
    proof: InfrastructureAuthorizationProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InfrastructureAuthorizationCredentialSubject {
    id: String,
    role: String,
    #[serde(rename = "subjectType")]
    subject_type: u8,
    #[serde(skip_serializing_if = "Option::is_none")]
    endpoint: Option<String>,
    #[serde(rename = "authorizedDomains", alias = "authorized_domains", default)]
    authorized_domains: Vec<String>,
    #[serde(rename = "didDocumentFile")]
    did_document_file: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InfrastructureAuthorizationCredentialStatus {
    #[serde(rename = "type")]
    status_type: String,
    status: String,
    #[serde(rename = "chainGovernanceNoticeFile")]
    chain_governance_notice_file: String,
    #[serde(rename = "packageId", skip_serializing_if = "Option::is_none")]
    package_id: Option<String>,
    #[serde(rename = "bulletinObjectId", skip_serializing_if = "Option::is_none")]
    bulletin_object_id: Option<String>,
    #[serde(rename = "expectedGovernanceState")]
    expected_governance_state: String,
    #[serde(rename = "eventSequence", skip_serializing_if = "Option::is_none")]
    event_sequence: Option<u64>,
    #[serde(
        rename = "eventDigest",
        skip_serializing_if = "String::is_empty",
        default
    )]
    event_digest: String,
    #[serde(
        rename = "latestAction",
        skip_serializing_if = "String::is_empty",
        default
    )]
    latest_action: String,
    #[serde(rename = "didDocumentStableHash")]
    did_document_stable_hash: String,
    #[serde(
        rename = "policyHash",
        skip_serializing_if = "String::is_empty",
        default
    )]
    policy_hash: String,
    #[serde(rename = "effectiveFromMs", skip_serializing_if = "Option::is_none")]
    effective_from_ms: Option<u64>,
    #[serde(rename = "expiresAtMs", skip_serializing_if = "Option::is_none")]
    expires_at_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct InfrastructureAuthorizationProof {
    #[serde(rename = "type")]
    proof_type: String,
    cryptosuite: String,
    #[serde(rename = "proofPurpose")]
    proof_purpose: String,
    #[serde(rename = "verificationMethod")]
    verification_method: String,
    created: chrono::DateTime<chrono::Utc>,
    #[serde(rename = "canonicalizationAlgorithm")]
    canonicalization_algorithm: String,
    #[serde(rename = "proofValue")]
    proof_value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DiscoveryNotifyTargetState {
    #[serde(rename = "discoveryDid")]
    discovery_did: String,
    #[serde(rename = "pendingCursor")]
    pending_cursor: i64,
    #[serde(rename = "deliveredCursor")]
    delivered_cursor: i64,
    status: String,
    #[serde(rename = "attemptCount")]
    attempt_count: i64,
    #[serde(rename = "leaseOwner")]
    lease_owner: Option<String>,
    #[serde(rename = "leaseExpiresAt")]
    lease_expires_at: Option<String>,
    #[serde(rename = "nextAttemptAt")]
    next_attempt_at: String,
    #[serde(rename = "lastError")]
    last_error: Option<String>,
    #[serde(rename = "updatedAt")]
    updated_at: String,
}

#[derive(Clone, Debug)]
struct DiscoveryNotifyTargetLease {
    discovery_did: String,
    target_cursor: i64,
    delivered_cursor: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct AuthorizationState {
    registrars: BTreeMap<String, NodeAuthorizationState>,
    discovery_nodes: BTreeMap<String, DiscoveryAuthorizationState>,
    vc_issuers: BTreeMap<String, NodeAuthorizationState>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NodeAuthorizationState {
    status: String,
    updated_at: chrono::DateTime<chrono::Utc>,
    did_document_hash: String,
    #[serde(
        rename = "didDocumentSnapshot",
        skip_serializing_if = "Option::is_none"
    )]
    did_document_snapshot: Option<DidDocument>,
    #[serde(rename = "authorizedDomains", alias = "authorized_domains", default)]
    authorized_domains: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DiscoveryAuthorizationState {
    status: String,
    updated_at: chrono::DateTime<chrono::Utc>,
    did_document_hash: String,
    #[serde(
        rename = "didDocumentSnapshot",
        skip_serializing_if = "Option::is_none"
    )]
    did_document_snapshot: Option<DidDocument>,
    #[serde(alias = "authorizedDomains", default)]
    authorized_domains: Vec<String>,
    tag_tree_version: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
struct AdmissionRuntimeState {
    last_wait_ms: u128,
    max_wait_ms: u128,
    accepted_count: u64,
    busy_rejected_count: u64,
    last_error: Option<String>,
    updated_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn internal(error: impl Into<anyhow::Error>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.into().to_string(),
        }
    }

    fn forbidden(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: message.into(),
        }
    }

    fn busy(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            message: message.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

type ApiResult<T> = std::result::Result<Json<T>, ApiError>;

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

#[derive(Clone, Debug, Deserialize)]
struct CdnPublicationJobRef {
    #[serde(rename = "jobKey")]
    job_key: String,
}

#[derive(Clone, Debug, Deserialize)]
struct CdnPublicationJobCompletionRef {
    #[serde(rename = "jobKey", default)]
    job_key: String,
    #[serde(rename = "publicationCursor", default)]
    publication_cursor: Option<i64>,
    #[serde(rename = "resourceDid", default)]
    resource_did: Option<String>,
    #[serde(rename = "packageVersion", default)]
    package_version: Option<String>,
    #[serde(rename = "packageHash", default)]
    package_hash: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct MarkCdnPublicationJobsPublishedRequest {
    jobs: Vec<CdnPublicationJobCompletionRef>,
}

#[derive(Clone, Debug, Deserialize)]
struct CdnPublicationJobsPackageRequest {
    jobs: Vec<CdnPublicationJobRef>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct DiscoveryNotificationItem {
    #[serde(rename = "resourceDid")]
    resource_did: String,
    #[serde(rename = "packageVersion")]
    package_version: String,
    #[serde(rename = "publicationCursor")]
    publication_cursor: i64,
    #[serde(rename = "packageHash")]
    package_hash: String,
    #[serde(rename = "metadataHash")]
    metadata_hash: String,
    #[serde(rename = "didDocumentHash")]
    did_document_hash: String,
    #[serde(rename = "resourceType")]
    resource_type: String,
    #[serde(rename = "capabilityTags")]
    capability_tags: Vec<String>,
    #[serde(rename = "authorizedDomains", default)]
    authorized_domains: Vec<String>,
}

#[derive(Clone, Debug)]
struct DiscoveryNotificationTargetItem {
    discovery_did: String,
    item: DiscoveryNotificationItem,
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "services/root-node/config.example.toml".to_owned());
    let config = load_config(config_path)?;
    let data = JsonStore::new(&config.paths.data_dir);
    let key: DevKeyFile = JsonStore::new(".").read(config.paths.keys_dir.join("keypair.json"))?;
    let crypto_suite = crypto_suite_from_algorithm(&key.algorithm)?;
    let signing_key = signing_key_from_bytes(
        crypto_suite,
        &URL_SAFE_NO_PAD.decode(key.private_key_jwk.d)?,
    )?;
    let authorization_state = load_authorization_state(&config.paths.authorization_state_file)?;
    let (sqlite, postgres) = match config.paths.database_url.as_deref() {
        Some(url) if !url.is_empty() => {
            let database = DatabaseConfig::parse(url)?;
            match database.backend() {
                DatabaseBackend::Sqlite => {
                    let sqlite = SqliteJsonStore::connect(url).await?;
                    initialize_root_sqlite(&sqlite).await?;
                    (Some(sqlite), None)
                }
                DatabaseBackend::Postgres => {
                    let postgres = PostgresJsonStore::connect(url).await?;
                    initialize_root_postgres(&postgres).await?;
                    (None, Some(postgres))
                }
            }
        }
        _ => (None, None),
    };
    let event_publisher = EventPublisher::from_config(&config.events).await?;
    let state = AppState {
        data,
        config: config.clone(),
        root_did: key.did,
        signing_key,
        tag_tree: oan_core::CapabilityTagTree::load_from_path(&config.paths.capability_tree_file)
            .unwrap_or_else(|_| default_tag_tree()),
        sqlite,
        postgres,
        authorization_state: Arc::new(Mutex::new(authorization_state)),
        client: reqwest::Client::builder()
            .timeout(TokioDuration::from_secs(
                config.security.workers.http_timeout_seconds,
            ))
            .build()?,
        trust_indexer_client: reqwest::Client::builder()
            .timeout(TokioDuration::from_millis(
                config.security.trust_indexer.timeout_ms,
            ))
            .build()?,
        event_publisher,
        worker_runtime: Arc::new(Mutex::new(WorkerRuntimeState::default())),
        event_runtime: Arc::new(Mutex::new(EventRuntimeState {
            enabled: config.events.enabled,
            backend: config.events.backend.clone(),
            stream: config.events.stream.clone(),
            cdn_publish_subject: config.events.cdn_publish_subject.clone(),
            ..Default::default()
        })),
        admission_runtime: Arc::new(Mutex::new(AdmissionRuntimeState::default())),
        status_counts_cache: Arc::new(Mutex::new(None)),
        worker_wake_state: Arc::new(Mutex::new(WorkerWakeState::default())),
        admission_semaphore: Arc::new(Semaphore::new(
            config.security.workers.admission_concurrency.max(1),
        )),
        cdn_worker_notify: Arc::new(Notify::new()),
        discovery_worker_notify: Arc::new(Notify::new()),
    };

    bootstrap_root_bulletin_from_json(&state).await?;
    if state.config.security.trust_indexer.enabled {
        reconcile_governance_state(&state).await?;
    }
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/root/did", get(root_did_document))
        .route("/bulletin", get(bulletin))
        .route("/root/status", get(api_status))
        .route("/root/registrars", get(api_registrars))
        .route("/root/registrars/{did}", get(api_registrar_detail))
        .route("/root/discovery-nodes", get(api_discovery_nodes))
        .route("/root/discovery-nodes/{did}", get(api_discovery_detail))
        .route(
            "/root/infrastructure/authorization-vcs/issue",
            post(issue_infrastructure_authorization_vc),
        )
        .route("/root/resources/{did}", get(api_resource_detail))
        .route("/root/resources/{did}/versions", get(api_resource_versions))
        .route(
            "/root/resources/{did}/versions/{version}",
            get(api_resource_version_detail),
        )
        .route(
            "/root/internal/cdn-publication-jobs/mark-published",
            post(api_mark_cdn_publication_jobs_published),
        )
        .route(
            "/root/internal/cdn-publication-jobs/packages",
            post(api_cdn_publication_jobs_packages),
        )
        .route("/root/queues/cdn-publish", get(api_cdn_publish_queue))
        .route(
            "/root/queues/discovery-notify",
            get(api_discovery_notify_queue),
        )
        .route("/root/capability-tree", get(api_capability_tree))
        .route(
            "/root/capability-tree/validate-tags",
            post(api_validate_tags),
        )
        .route("/root/bulletin/events", get(api_bulletin_events))
        .route(
            "/root/bulletin/events/{sequence}",
            get(api_bulletin_event_detail),
        )
        .layer(build_cors_layer(&config.cors)?);

    let admin_routes = Router::new()
        .route("/root/registrars/authorize", post(authorize_registrar))
        .route("/root/discovery-nodes/authorize", post(authorize_discovery))
        .route(
            "/root/discovery-nodes/{did}/domains",
            post(update_discovery_domains),
        )
        .route("/root/nodes/{did}/revoke", post(revoke_node))
        .route(
            "/root/resources/verify-and-publish",
            post(verify_resource_and_publish),
        );

    let app = Router::new()
        .merge(public_routes)
        .merge(admin_routes)
        .with_state(state.clone());

    spawn_cdn_outbox_relay(state.clone());
    if state.config.security.workers.enabled {
        spawn_root_background_workers(state.clone());
    }
    if state.config.security.trust_indexer.enabled {
        spawn_trust_indexer_watcher(state.clone());
    }

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    println!("root-node listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_config(path: String) -> Result<Config> {
    let path = PathBuf::from(path);
    let text = std::fs::read_to_string(&path)?;
    let mut config: Config = toml::from_str(&text)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.paths.data_dir = resolve_relative(base, &config.paths.data_dir);
    config.paths.keys_dir = resolve_relative(base, &config.paths.keys_dir);
    config.paths.bulletin_file = resolve_relative(base, &config.paths.bulletin_file);
    config.paths.authorization_state_file =
        resolve_relative(base, &config.paths.authorization_state_file);
    config.paths.request_nonce_file = resolve_relative(base, &config.paths.request_nonce_file);
    config.security.admin.nonce_store_file =
        resolve_relative(base, &config.security.admin.nonce_store_file);
    if !config.paths.capability_tree_file.as_os_str().is_empty() {
        config.paths.capability_tree_file =
            resolve_relative(base, &config.paths.capability_tree_file);
    }
    if let Some(database_url) = config.paths.database_url.as_mut() {
        *database_url = resolve_database_url(base, database_url);
    }
    if !config.events.enabled {
        return Err(anyhow!(
            "root_cdn_event_stream_required: Root-to-CDN publication no longer supports the legacy Root DB worker path; set [events].enabled=true"
        ));
    }
    Ok(config)
}

fn admin_auth_config(state: &AppState) -> AdminAuthConfig {
    match state.config.security.admin.mode.as_str() {
        "signed-did" => {
            let trusted_admin_documents = state
                .config
                .security
                .admin
                .trusted_admin_dids
                .iter()
                .filter_map(|did| load_authorized_registrar_document(state, did).ok())
                .collect::<Vec<_>>();
            AdminAuthConfig {
                mode: AdminAuthMode::SignedDid {
                    trusted_admin_documents,
                    max_clock_skew_seconds: state.config.security.admin.max_clock_skew_seconds,
                    nonce_ttl_seconds: state.config.security.admin.nonce_ttl_seconds,
                    nonce_store_path: state.config.security.admin.nonce_store_file.clone(),
                    audience: state.root_did.clone(),
                },
            }
        }
        _ => AdminAuthConfig {
            mode: AdminAuthMode::StaticToken {
                tokens: state.config.security.admin.static_tokens.clone(),
            },
        },
    }
}

fn trusted_upstream_policy(state: &AppState, expected_path: &str) -> TrustedUpstreamPolicy {
    TrustedUpstreamPolicy {
        expected_purpose: PURPOSE_VERIFY_AND_PUBLISH.to_owned(),
        expected_method: "POST".to_owned(),
        expected_path: expected_path.to_owned(),
        expected_audience: state.root_did.clone(),
        max_clock_skew_seconds: state
            .config
            .security
            .trusted_upstream
            .max_clock_skew_seconds,
        nonce_ttl_seconds: state.config.security.trusted_upstream.nonce_ttl_seconds,
        nonce_store_path: state.config.paths.request_nonce_file.clone(),
    }
}

fn require_admin(
    headers: &HeaderMap,
    state: &AppState,
) -> std::result::Result<AdminPrincipal, ApiError> {
    let config = admin_auth_config(state);
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| bearer_token_from_header(Some(value)));
    verify_admin_token(token, &config).map_err(|err| ApiError {
        status: StatusCode::UNAUTHORIZED,
        message: err.to_string(),
    })
}

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn build_cors_layer(config: &CorsConfig) -> Result<CorsLayer> {
    let origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter()
        .map(|origin| HeaderValue::from_str(origin))
        .collect::<std::result::Result<_, _>>()?;
    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        .allow_headers(AllowHeaders::any()))
}

fn spawn_root_background_workers(state: AppState) {
    let discovery_state = state.clone();
    tokio::spawn(async move {
        root_discovery_worker_loop(discovery_state).await;
    });
    if (state.sqlite.is_some() || state.postgres.is_some()) && state.config.debug.export_snapshots {
        tokio::spawn(async move {
            root_debug_export_loop(state).await;
        });
    }
}

fn spawn_cdn_outbox_relay(state: AppState) {
    tokio::spawn(async move {
        root_cdn_outbox_relay_loop(state).await;
    });
}

fn spawn_trust_indexer_watcher(state: AppState) {
    tokio::spawn(async move {
        let interval_ms = state
            .config
            .security
            .trust_indexer
            .poll_interval_ms
            .max(500);
        loop {
            if let Err(err) = reconcile_governance_state(&state).await {
                eprintln!("trust indexer reconciliation failed: {err}");
            }
            sleep(TokioDuration::from_millis(interval_ms)).await;
        }
    });
}

async fn root_cdn_outbox_relay_loop(state: AppState) {
    let interval_ms = state.config.security.workers.cdn_interval_ms.max(100);
    loop {
        let _ = consume_pending_worker_signal_trigger(&state, true);
        let cycle = match run_cdn_outbox_relay_cycle(&state).await {
            Ok(result) => Some(result),
            Err(err) => {
                eprintln!("root cdn outbox relay cycle failed: {err}");
                None
            }
        };
        let made_progress = cycle.as_ref().map(cdn_cycle_made_progress).unwrap_or(false);
        let should_continue_immediately = cycle
            .as_ref()
            .map(cdn_cycle_should_continue_immediately)
            .unwrap_or(false);
        if should_continue_immediately {
            tokio::task::yield_now().await;
            continue;
        }
        if made_progress {
            continue;
        }
        record_worker_noop_cycle(&state, true);
        tokio::select! {
            _ = state.cdn_worker_notify.notified() => {
                record_worker_trigger(&state, true, WorkerTriggerType::Event);
                if let Some(delay_ms) = take_worker_event_delay_ms(&state, true) {
                    record_worker_event_delay(&state, true, delay_ms);
                }
            }
            _ = sleep(TokioDuration::from_millis(interval_ms)) => {
                record_worker_trigger(&state, true, WorkerTriggerType::Timer);
            }
        }
    }
}

async fn root_discovery_worker_loop(state: AppState) {
    let interval_ms = state.config.security.workers.discovery_interval_ms.max(100);
    loop {
        let _ = consume_pending_worker_signal_trigger(&state, false);
        let cycle = match run_discovery_notify_cycle(&state).await {
            Ok(result) => Some(result),
            Err(err) => {
                eprintln!("root discovery worker cycle failed: {err}");
                None
            }
        };
        let made_progress = cycle
            .as_ref()
            .map(discovery_cycle_made_progress)
            .unwrap_or(false);
        let should_continue_immediately = cycle
            .as_ref()
            .map(discovery_cycle_should_continue_immediately)
            .unwrap_or(false);
        if should_continue_immediately {
            tokio::task::yield_now().await;
            continue;
        }
        if made_progress {
            continue;
        }
        record_worker_noop_cycle(&state, false);
        tokio::select! {
            _ = state.discovery_worker_notify.notified() => {
                record_worker_trigger(&state, false, WorkerTriggerType::Event);
                if let Some(delay_ms) = take_worker_event_delay_ms(&state, false) {
                    record_worker_event_delay(&state, false, delay_ms);
                }
            }
            _ = sleep(TokioDuration::from_millis(interval_ms)) => {
                record_worker_trigger(&state, false, WorkerTriggerType::Timer);
            }
        }
    }
}

async fn root_debug_export_loop(state: AppState) {
    loop {
        if let Err(err) = export_root_debug_snapshot(&state).await {
            eprintln!("root debug export failed: {err}");
        }
        sleep(TokioDuration::from_millis(
            state.config.debug.export_interval_ms.max(100),
        ))
        .await;
    }
}

async fn reconcile_governance_state(state: &AppState) -> Result<()> {
    if !state.config.security.trust_indexer.enabled {
        return Ok(());
    }
    let authorization_state = current_authorization_state(state);

    for did in authorization_state.registrars.keys() {
        match ensure_governance_active(state, GovernanceSubjectType::Registrar, did).await {
            Ok(_) => restore_local_governance_active(state, GovernanceSubjectType::Registrar, did)?,
            Err(reason) => {
                mark_local_governance_inactive(
                    state,
                    GovernanceSubjectType::Registrar,
                    did,
                    &reason,
                )?;
            }
        }
    }
    for did in authorization_state.discovery_nodes.keys() {
        match ensure_governance_active(state, GovernanceSubjectType::Discovery, did).await {
            Ok(_) => restore_local_governance_active(state, GovernanceSubjectType::Discovery, did)?,
            Err(reason) => {
                mark_local_governance_inactive(
                    state,
                    GovernanceSubjectType::Discovery,
                    did,
                    &reason,
                )?;
            }
        }
    }
    for did in authorization_state.vc_issuers.keys() {
        match ensure_governance_active(state, GovernanceSubjectType::VcIssuer, did).await {
            Ok(_) => restore_local_governance_active(state, GovernanceSubjectType::VcIssuer, did)?,
            Err(reason) => {
                mark_local_governance_inactive(
                    state,
                    GovernanceSubjectType::VcIssuer,
                    did,
                    &reason,
                )?;
            }
        }
    }
    Ok(())
}

async fn ensure_governance_active(
    state: &AppState,
    subject_type: GovernanceSubjectType,
    did: &str,
) -> std::result::Result<GovernanceDecision, String> {
    if !state.config.security.trust_indexer.enabled {
        return Ok(GovernanceDecision {
            governance_active: true,
            authorized: true,
            reason: "trust_indexer_disabled".to_owned(),
            subject_type: subject_type.label().to_owned(),
            subject_type_code: subject_type.code(),
            subject_did: did.to_owned(),
            status: Some("not_checked".to_owned()),
        });
    }
    let endpoint = state
        .config
        .security
        .trust_indexer
        .endpoint
        .as_deref()
        .ok_or_else(|| "trust_indexer_endpoint_missing".to_owned())?
        .trim_end_matches('/')
        .to_owned();
    let encoded_did = url::form_urlencoded::byte_serialize(did.as_bytes()).collect::<String>();
    let url = format!(
        "{endpoint}/v1/subjects/{}/{encoded_did}/governance-active",
        subject_type.code()
    );
    let response = match state.trust_indexer_client.get(url).send().await {
        Ok(response) => response,
        Err(err) => {
            return governance_unavailable_decision(state, subject_type, did, err.to_string());
        }
    };
    if !response.status().is_success() {
        return governance_unavailable_decision(
            state,
            subject_type,
            did,
            format!("trust_indexer_status_{}", response.status().as_u16()),
        );
    }
    let decision = match response.json::<GovernanceDecision>().await {
        Ok(decision) => decision,
        Err(err) => {
            return governance_unavailable_decision(state, subject_type, did, err.to_string());
        }
    };
    if decision.governance_active {
        Ok(decision)
    } else {
        Err(format!(
            "governance_inactive:{}",
            if decision.reason.is_empty() {
                "not_active"
            } else {
                decision.reason.as_str()
            }
        ))
    }
}

async fn fetch_governance_subject_record(
    state: &AppState,
    subject_type: GovernanceSubjectType,
    did: &str,
) -> std::result::Result<GovernanceSubjectRecord, String> {
    if !state.config.security.trust_indexer.enabled {
        return Ok(GovernanceSubjectRecord {
            subject_type: subject_type.code(),
            subject_type_label: subject_type.label().to_owned(),
            subject_did: did.to_owned(),
            status: 1,
            status_label: "active".to_owned(),
            authorized_domains: Vec::new(),
            policy_hash: String::new(),
            metadata_hash: String::new(),
            effective_from_ms: 0,
            expires_at_ms: 0,
            version: 0,
            updated_at_ms: 0,
            last_sequence: 0,
            last_event_digest: String::new(),
        });
    }
    let endpoint = state
        .config
        .security
        .trust_indexer
        .endpoint
        .as_deref()
        .ok_or_else(|| "trust_indexer_endpoint_missing".to_owned())?
        .trim_end_matches('/')
        .to_owned();
    let encoded_did = url::form_urlencoded::byte_serialize(did.as_bytes()).collect::<String>();
    let url = format!(
        "{endpoint}/v1/subjects/{}/{encoded_did}",
        subject_type.code()
    );
    let response = state
        .trust_indexer_client
        .get(url)
        .send()
        .await
        .map_err(|err| format!("trust_indexer_subject_unavailable:{err}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "trust_indexer_subject_status_{}",
            response.status().as_u16()
        ));
    }
    response
        .json::<GovernanceSubjectRecord>()
        .await
        .map_err(|err| format!("trust_indexer_subject_decode_failed:{err}"))
}

async fn fetch_trust_indexer_status(
    state: &AppState,
) -> std::result::Result<TrustIndexerStatus, String> {
    if !state.config.security.trust_indexer.enabled {
        return Ok(TrustIndexerStatus::default());
    }
    let endpoint = state
        .config
        .security
        .trust_indexer
        .endpoint
        .as_deref()
        .ok_or_else(|| "trust_indexer_endpoint_missing".to_owned())?
        .trim_end_matches('/')
        .to_owned();
    let url = format!("{endpoint}/v1/status");
    let response = state
        .trust_indexer_client
        .get(url)
        .send()
        .await
        .map_err(|err| format!("trust_indexer_status_unavailable:{err}"))?;
    if !response.status().is_success() {
        return Err(format!(
            "trust_indexer_status_status_{}",
            response.status().as_u16()
        ));
    }
    response
        .json::<TrustIndexerStatus>()
        .await
        .map_err(|err| format!("trust_indexer_status_decode_failed:{err}"))
}

fn validate_governance_subject_binding(
    subject_type: GovernanceSubjectType,
    payload: &InfrastructureAuthorizationVcIssuePayload,
    did_document_stable_hash: &str,
    subject: &GovernanceSubjectRecord,
) -> std::result::Result<(), String> {
    if subject.subject_type != subject_type.code() {
        return Err("governance_subject_type_mismatch".to_owned());
    }
    if subject.subject_did != payload.subject_did {
        return Err("governance_subject_did_mismatch".to_owned());
    }
    if subject.status_label != "active" && subject.status != 1 {
        return Err(format!(
            "governance_subject_not_active:{}",
            subject.status_label
        ));
    }
    let chain_hash = normalize_chain_metadata_hash(&subject.metadata_hash);
    if chain_hash.is_empty() {
        return Err("governance_subject_metadata_hash_missing".to_owned());
    }
    if chain_hash != did_document_stable_hash {
        return Err("governance_subject_metadata_hash_mismatch".to_owned());
    }
    if matches!(
        subject_type,
        GovernanceSubjectType::Registrar | GovernanceSubjectType::Discovery
    ) {
        let mut payload_domains = payload.authorized_domains.clone();
        let mut chain_domains = subject.authorized_domains.clone();
        payload_domains.sort();
        chain_domains.sort();
        if payload_domains != chain_domains {
            return Err("governance_authorized_domains_mismatch".to_owned());
        }
    }
    Ok(())
}

fn governance_unavailable_decision(
    state: &AppState,
    subject_type: GovernanceSubjectType,
    did: &str,
    detail: String,
) -> std::result::Result<GovernanceDecision, String> {
    match state.config.security.trust_indexer.fail_mode.as_str() {
        "open" | "fail-open" => Ok(GovernanceDecision {
            governance_active: true,
            authorized: true,
            reason: format!("trust_indexer_unavailable_fail_open:{detail}"),
            subject_type: subject_type.label().to_owned(),
            subject_type_code: subject_type.code(),
            subject_did: did.to_owned(),
            status: Some("unknown".to_owned()),
        }),
        _ => Err(format!("trust_indexer_unavailable:{detail}")),
    }
}

fn mark_local_governance_inactive(
    state: &AppState,
    subject_type: GovernanceSubjectType,
    did: &str,
    reason: &str,
) -> Result<()> {
    if reason.starts_with("trust_indexer_unavailable_fail_open") {
        return Ok(());
    }
    let mut authorization_state = current_authorization_state(state);
    match subject_type {
        GovernanceSubjectType::Registrar => {
            if let Some(entry) = authorization_state.registrars.get_mut(did) {
                if entry.status == "active" {
                    entry.status = "governance_inactive".to_owned();
                    entry.updated_at = Utc::now();
                }
            }
        }
        GovernanceSubjectType::Discovery => {
            if let Some(entry) = authorization_state.discovery_nodes.get_mut(did) {
                if entry.status == "active" {
                    entry.status = "governance_inactive".to_owned();
                    entry.updated_at = Utc::now();
                }
            }
            if state.sqlite.is_some() || state.postgres.is_some() {
                sync_discovery_target_state(state, did, "governance_inactive")?;
            }
        }
        GovernanceSubjectType::VcIssuer => {
            if let Some(entry) = authorization_state.vc_issuers.get_mut(did) {
                if entry.status == "active" {
                    entry.status = "governance_inactive".to_owned();
                    entry.updated_at = Utc::now();
                }
            }
        }
    }
    JsonStore::new(".").write(
        &state.config.paths.authorization_state_file,
        &authorization_state,
    )?;
    eprintln!(
        "marked {} {} as governance_inactive: {}",
        subject_type.label(),
        did,
        reason
    );
    Ok(())
}

fn restore_local_governance_active(
    state: &AppState,
    subject_type: GovernanceSubjectType,
    did: &str,
) -> Result<()> {
    let mut authorization_state = current_authorization_state(state);
    let mut changed = false;
    match subject_type {
        GovernanceSubjectType::Registrar => {
            if let Some(entry) = authorization_state.registrars.get_mut(did) {
                if entry.status == "governance_inactive" {
                    entry.status = "active".to_owned();
                    entry.updated_at = Utc::now();
                    changed = true;
                }
            }
        }
        GovernanceSubjectType::Discovery => {
            if let Some(entry) = authorization_state.discovery_nodes.get_mut(did) {
                if entry.status == "governance_inactive" {
                    entry.status = "active".to_owned();
                    entry.updated_at = Utc::now();
                    changed = true;
                }
            }
            if changed && (state.sqlite.is_some() || state.postgres.is_some()) {
                sync_discovery_target_state(state, did, "active")?;
            }
        }
        GovernanceSubjectType::VcIssuer => {
            if let Some(entry) = authorization_state.vc_issuers.get_mut(did) {
                if entry.status == "governance_inactive" {
                    entry.status = "active".to_owned();
                    entry.updated_at = Utc::now();
                    changed = true;
                }
            }
        }
    }
    if changed {
        JsonStore::new(".").write(
            &state.config.paths.authorization_state_file,
            &authorization_state,
        )?;
    }
    Ok(())
}

fn resolve_database_url(base: &Path, url: &str) -> String {
    let Some(raw_path) = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
    else {
        return url.to_owned();
    };
    let resolved = resolve_relative(base, Path::new(raw_path));
    format!("sqlite:{}", resolved.display())
}

async fn initialize_root_sqlite(sqlite: &SqliteJsonStore) -> Result<()> {
    sqlite
        .execute_batch(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {ROOT_BULLETIN_EVENT_TABLE} (
                sequence INTEGER PRIMARY KEY,
                event_type TEXT NOT NULL,
                subject_did TEXT NOT NULL,
                actor_did TEXT NOT NULL,
                payload_json TEXT NOT NULL,
                previous_hash TEXT,
                event_hash TEXT NOT NULL UNIQUE,
                event_json TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {ROOT_SUBJECT_LATEST_TABLE} (
                subject_did TEXT PRIMARY KEY,
                current_version TEXT NOT NULL,
                did_document_hash TEXT NOT NULL,
                metadata_hash TEXT NOT NULL,
                operation TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {ROOT_SUBJECT_VERSION_TABLE} (
                publication_cursor INTEGER UNIQUE,
                subject_did TEXT NOT NULL,
                version TEXT NOT NULL,
                did_document_hash TEXT NOT NULL,
                metadata_hash TEXT NOT NULL,
                package_json TEXT NOT NULL,
                archive_path TEXT NOT NULL,
                accepted_at TEXT NOT NULL,
                PRIMARY KEY(subject_did, version)
            );
            CREATE TABLE IF NOT EXISTS {ROOT_PACKAGE_JOB_TABLE} (
                job_key TEXT PRIMARY KEY,
                subject_did TEXT NOT NULL,
                version TEXT NOT NULL,
                package_json TEXT NOT NULL,
                status TEXT NOT NULL,
                operation TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {ROOT_DISCOVERY_TARGET_TABLE} (
                discovery_did TEXT PRIMARY KEY,
                pending_cursor INTEGER NOT NULL DEFAULT 0,
                delivered_cursor INTEGER NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'ready',
                attempt_count INTEGER NOT NULL DEFAULT 0,
                lease_owner TEXT,
                lease_expires_at TEXT,
                next_attempt_at TEXT NOT NULL,
                last_error TEXT,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {ROOT_DISCOVERY_ITEM_TABLE} (
                discovery_did TEXT NOT NULL,
                publication_cursor INTEGER NOT NULL,
                resource_did TEXT NOT NULL,
                package_version TEXT NOT NULL,
                package_hash TEXT NOT NULL,
                metadata_hash TEXT NOT NULL,
                did_document_hash TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                capability_tags_json TEXT NOT NULL,
                authorized_domains_json TEXT NOT NULL DEFAULT '[]',
                PRIMARY KEY(discovery_did, publication_cursor)
            );
            "#
        ))
        .await?;
    sqlite
        .execute_batch(&format!(
            r#"
            ALTER TABLE {ROOT_SUBJECT_VERSION_TABLE}
                ADD COLUMN publication_cursor INTEGER;
            ALTER TABLE {ROOT_DISCOVERY_ITEM_TABLE}
                ADD COLUMN authorized_domains_json TEXT NOT NULL DEFAULT '[]';
            "#
        ))
        .await
        .ok();
    sqlite.ensure_leased_job_table(ROOT_CDN_JOB_TABLE).await?;
    sqlite
        .ensure_leased_job_table(ROOT_CDN_OUTBOX_TABLE)
        .await?;
    Ok(())
}

async fn initialize_root_postgres(postgres: &PostgresJsonStore) -> Result<()> {
    postgres
        .execute_batch(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {ROOT_BULLETIN_EVENT_TABLE} (
                sequence BIGINT PRIMARY KEY,
                event_type TEXT NOT NULL,
                subject_did TEXT NOT NULL,
                actor_did TEXT NOT NULL,
                payload_json JSONB NOT NULL,
                previous_hash TEXT,
                event_hash TEXT NOT NULL UNIQUE,
                event_json JSONB NOT NULL,
                created_at TIMESTAMPTZ NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {ROOT_SUBJECT_LATEST_TABLE} (
                subject_did TEXT PRIMARY KEY,
                current_version TEXT NOT NULL,
                did_document_hash TEXT NOT NULL,
                metadata_hash TEXT NOT NULL,
                operation TEXT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {ROOT_SUBJECT_VERSION_TABLE} (
                publication_cursor BIGSERIAL UNIQUE,
                subject_did TEXT NOT NULL,
                version TEXT NOT NULL,
                did_document_hash TEXT NOT NULL,
                metadata_hash TEXT NOT NULL,
                package_hash TEXT NOT NULL DEFAULT '',
                resource_type TEXT NOT NULL DEFAULT 'unknown',
                capability_tags_json JSONB NOT NULL DEFAULT '[]'::jsonb,
                package_json JSONB NOT NULL,
                archive_path TEXT NOT NULL,
                accepted_at TIMESTAMPTZ NOT NULL,
                PRIMARY KEY(subject_did, version)
            );
            CREATE TABLE IF NOT EXISTS {ROOT_PACKAGE_JOB_TABLE} (
                job_key TEXT PRIMARY KEY,
                subject_did TEXT NOT NULL,
                version TEXT NOT NULL,
                package_json JSONB NOT NULL,
                status TEXT NOT NULL,
                operation TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {ROOT_DISCOVERY_TARGET_TABLE} (
                discovery_did TEXT PRIMARY KEY,
                pending_cursor BIGINT NOT NULL DEFAULT 0,
                delivered_cursor BIGINT NOT NULL DEFAULT 0,
                status TEXT NOT NULL DEFAULT 'ready',
                attempt_count BIGINT NOT NULL DEFAULT 0,
                lease_owner TEXT,
                lease_expires_at TIMESTAMPTZ,
                next_attempt_at TIMESTAMPTZ NOT NULL,
                last_error TEXT,
                updated_at TIMESTAMPTZ NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {ROOT_DISCOVERY_ITEM_TABLE} (
                discovery_did TEXT NOT NULL,
                publication_cursor BIGINT NOT NULL,
                resource_did TEXT NOT NULL,
                package_version TEXT NOT NULL,
                package_hash TEXT NOT NULL,
                metadata_hash TEXT NOT NULL,
                did_document_hash TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                capability_tags_json JSONB NOT NULL,
                authorized_domains_json JSONB NOT NULL DEFAULT '[]'::jsonb,
                PRIMARY KEY(discovery_did, publication_cursor)
            );
            CREATE INDEX IF NOT EXISTS idx_root_subject_versions_subject_version
            ON {ROOT_SUBJECT_VERSION_TABLE}(subject_did, accepted_at DESC);
            CREATE INDEX IF NOT EXISTS idx_root_subject_versions_cursor
            ON {ROOT_SUBJECT_VERSION_TABLE}(publication_cursor);
            CREATE INDEX IF NOT EXISTS idx_root_subject_versions_notification_projection
            ON {ROOT_SUBJECT_VERSION_TABLE}(publication_cursor, subject_did, version);
            CREATE INDEX IF NOT EXISTS idx_root_bulletin_events_sequence
            ON {ROOT_BULLETIN_EVENT_TABLE}(sequence);
            CREATE INDEX IF NOT EXISTS idx_root_discovery_target_schedule
            ON {ROOT_DISCOVERY_TARGET_TABLE}(status, pending_cursor, delivered_cursor, next_attempt_at);
            CREATE INDEX IF NOT EXISTS idx_root_discovery_target_active_ready
            ON {ROOT_DISCOVERY_TARGET_TABLE}(next_attempt_at, lease_expires_at, pending_cursor DESC, discovery_did)
            WHERE status = 'active' AND pending_cursor > delivered_cursor;
            CREATE INDEX IF NOT EXISTS idx_root_discovery_target_delivery_progress
            ON {ROOT_DISCOVERY_TARGET_TABLE}(discovery_did, delivered_cursor, pending_cursor);
            CREATE INDEX IF NOT EXISTS idx_root_discovery_items_target_cursor
            ON {ROOT_DISCOVERY_ITEM_TABLE}(discovery_did, publication_cursor);
            CREATE INDEX IF NOT EXISTS idx_root_discovery_items_gc
            ON {ROOT_DISCOVERY_ITEM_TABLE}(discovery_did, publication_cursor DESC);
            "#
        ))
        .await?;
    postgres.ensure_leased_job_table(ROOT_CDN_JOB_TABLE).await?;
    postgres
        .ensure_leased_job_table(ROOT_CDN_OUTBOX_TABLE)
        .await?;
    postgres
        .execute_batch(&format!(
            r#"
            ALTER TABLE {ROOT_SUBJECT_VERSION_TABLE}
                ADD COLUMN IF NOT EXISTS package_hash TEXT NOT NULL DEFAULT '';
            ALTER TABLE {ROOT_SUBJECT_VERSION_TABLE}
                ADD COLUMN IF NOT EXISTS resource_type TEXT NOT NULL DEFAULT 'unknown';
            ALTER TABLE {ROOT_SUBJECT_VERSION_TABLE}
                ADD COLUMN IF NOT EXISTS capability_tags_json JSONB NOT NULL DEFAULT '[]'::jsonb;
            ALTER TABLE {ROOT_SUBJECT_VERSION_TABLE}
                ADD COLUMN IF NOT EXISTS authorized_domains_json JSONB NOT NULL DEFAULT '[]'::jsonb;
            ALTER TABLE {ROOT_CDN_JOB_TABLE}
                ADD COLUMN IF NOT EXISTS publication_cursor BIGINT;
            ALTER TABLE {ROOT_CDN_JOB_TABLE}
                ADD COLUMN IF NOT EXISTS resource_did TEXT;
            ALTER TABLE {ROOT_CDN_JOB_TABLE}
                ADD COLUMN IF NOT EXISTS package_version TEXT;
            ALTER TABLE {ROOT_CDN_JOB_TABLE}
                ADD COLUMN IF NOT EXISTS package_hash TEXT;
            ALTER TABLE {ROOT_CDN_JOB_TABLE}
                ADD COLUMN IF NOT EXISTS metadata_hash TEXT;
            ALTER TABLE {ROOT_CDN_JOB_TABLE}
                ADD COLUMN IF NOT EXISTS did_document_hash TEXT;
            ALTER TABLE {ROOT_CDN_JOB_TABLE}
                ADD COLUMN IF NOT EXISTS resource_type TEXT;
            ALTER TABLE {ROOT_CDN_JOB_TABLE}
                ADD COLUMN IF NOT EXISTS capability_tags_json JSONB;
            ALTER TABLE {ROOT_CDN_JOB_TABLE}
                ADD COLUMN IF NOT EXISTS authorized_domains_json JSONB;
            ALTER TABLE {ROOT_DISCOVERY_ITEM_TABLE}
                ADD COLUMN IF NOT EXISTS authorized_domains_json JSONB NOT NULL DEFAULT '[]'::jsonb;
            CREATE INDEX IF NOT EXISTS idx_root_cdn_jobs_job_projection
            ON {ROOT_CDN_JOB_TABLE}(job_key, publication_cursor);
            CREATE INDEX IF NOT EXISTS idx_root_cdn_jobs_ready_projection
            ON {ROOT_CDN_JOB_TABLE}(status, next_attempt_at, lease_expires_at, publication_cursor, job_key);
            CREATE INDEX IF NOT EXISTS idx_root_cdn_jobs_publication_projection
            ON {ROOT_CDN_JOB_TABLE}(publication_cursor, job_key, resource_did, package_version);
            "#
        ))
        .await?;
    Ok(())
}

async fn bootstrap_root_bulletin_from_json(state: &AppState) -> Result<()> {
    repository::bootstrap_root_bulletin_from_json_impl(state).await
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
        node_type: "root".to_owned(),
        did: Some(state.root_did),
    })
}

fn block_on_sqlite<F, T>(future: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>> + Send,
    T: Send,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        tokio::task::block_in_place(|| handle.block_on(future))
    } else {
        let runtime = tokio::runtime::Runtime::new()?;
        runtime.block_on(future)
    }
}

async fn root_did_document(State(state): State<AppState>) -> ApiResult<DidDocument> {
    state
        .data
        .read("did-document.json")
        .map(Json)
        .map_err(ApiError::internal)
}

async fn bulletin(State(state): State<AppState>) -> ApiResult<Bulletin> {
    read_bulletin(&state).map(Json).map_err(ApiError::internal)
}

async fn verify_resource_and_publish(
    State(state): State<AppState>,
    Json(request): Json<ResourceVerifyAndPublishRequest>,
) -> ApiResult<Value> {
    let admission_started = Instant::now();
    let _admission_permit = tokio::time::timeout(
        TokioDuration::from_secs(state.config.security.workers.http_timeout_seconds.max(1)),
        state.admission_semaphore.clone().acquire_owned(),
    )
    .await
    .map_err(|_| {
        record_admission_busy(&state, admission_started.elapsed().as_millis());
        ApiError::busy("root_admission_busy")
    })?
    .map_err(ApiError::internal)?;
    record_admission_accepted(&state, admission_started.elapsed().as_millis());
    verify_resource_request(&state, &request).map_err(ApiError::bad_request)?;
    ensure_governance_active(
        &state,
        GovernanceSubjectType::Registrar,
        &request.registrar_did,
    )
    .await
    .map_err(ApiError::forbidden)?;
    let registrar_entry = load_authorized_registrar_entry(&state, &request.registrar_did)
        .map_err(ApiError::forbidden)?;

    let mut metadata = build_resource_metadata(&request.submission)
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    validate_resource_authorized_domains(
        &metadata.authorized_domains,
        &registrar_entry.authorized_domains,
    )
    .map_err(ApiError::bad_request)?;
    let root_suite = state.signing_key.crypto_suite();
    let did_document_hash =
        hash_json_with_suite(root_suite.clone(), &request.submission.did_document)
            .map(|hash| format_hash(&request.submission.hash_algorithm, &hash))
            .map_err(ApiError::internal)?;
    metadata.metadata_hash.clear();
    metadata.package_hash.clear();
    let metadata_hash = hash_resource_metadata_with_suite(root_suite.clone(), &metadata)
        .map(|hash| format_hash(&request.submission.hash_algorithm, &hash))
        .map_err(ApiError::internal)?;
    if did_document_hash != request.submission.did_document_hash {
        return Err(ApiError::bad_request("did_document_hash_mismatch"));
    }
    if metadata_hash != request.submission.metadata_hash {
        return Err(ApiError::bad_request("metadata_hash_mismatch"));
    }
    metadata.metadata_hash = metadata_hash.clone();
    metadata.package_hash = request.submission.package_hash.clone();
    let package_hash = hash_json_with_suite(
        root_suite.clone(),
        &json!({
            "packageVersion": request.submission.package_version,
            "resourceDid": request.submission.resource_did,
            "resourceType": request.submission.resource_type,
            "didDocumentHash": request.submission.did_document_hash,
            "metadataHash": request.submission.metadata_hash,
            "hashAlgorithm": request.submission.hash_algorithm,
        }),
    )
    .map(|hash| format_hash(&request.submission.hash_algorithm, &hash))
    .map_err(ApiError::internal)?;
    if package_hash != request.submission.package_hash {
        return Err(ApiError::bad_request("package_hash_mismatch"));
    }

    let package_claims = ResourcePackageClaims {
        resource_did: request.submission.resource_did.clone(),
        resource_type: request.submission.resource_type.clone(),
        version: request.submission.package_version.clone(),
        did_document_hash: request.submission.did_document_hash.clone(),
        metadata_hash: request.submission.metadata_hash.clone(),
        package_hash: request.submission.package_hash.clone(),
        hash_algorithm: request.submission.hash_algorithm.clone(),
        lifecycle_state: metadata.lifecycle_state.clone(),
        authorized_domains: metadata.authorized_domains.clone(),
        bulletin_ref: metadata
            .protocol_bindings
            .iter()
            .find_map(|value| value.get("bulletinRef").and_then(Value::as_str))
            .map(ToOwned::to_owned),
    };
    let claims_value = serde_json::to_value(&package_claims).map_err(ApiError::internal)?;
    let package = ResourcePackage {
        package_version: request.submission.package_version.clone(),
        resource_did: request.submission.resource_did.clone(),
        resource_type: request.submission.resource_type.clone(),
        did_document: request.submission.did_document.clone(),
        did_document_hash: request.submission.did_document_hash.clone(),
        metadata_hash: request.submission.metadata_hash.clone(),
        package_hash: request.submission.package_hash.clone(),
        hash_algorithm: request.submission.hash_algorithm.clone(),
        metadata,
        root_proof: RootProof {
            root_did: state.root_did.clone(),
            bulletin_event_hash: None,
            signature: None,
            package_claims: Some(claims_value.clone()),
            proof: Some(
                build_data_integrity_proof(
                    &claims_value,
                    format!("{}#key-1", state.root_did),
                    format!("{}#key-1", state.root_did),
                    &state.signing_key,
                )
                .map_err(ApiError::internal)?,
            ),
            crypto_suite: Some(state.signing_key.crypto_suite()),
            hash_algorithm: Some(state.signing_key.crypto_suite().hash_algorithm().to_owned()),
        },
        created_at: Utc::now(),
    };
    package
        .verify_resource_type_consistency()
        .and_then(|_| package.verify_metadata_consistency())
        .and_then(|_| package.verify_root_claim_binding())
        .map_err(|err| ApiError::bad_request(err.to_string()))?;

    archive_resource_verified(&state, &package).map_err(ApiError::internal)?;
    persist_resource_acceptance(&state, &package)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(json!({
        "status": "resource-verified-and-queued",
        "resourceDid": package.resource_did,
        "resourceType": package.resource_type,
        "packageVersion": package.package_version,
        "didDocumentHash": package.did_document_hash,
        "metadataHash": package.metadata_hash,
        "packageHash": package.package_hash,
        "lifecycleState": package.metadata.lifecycle_state,
        "cdnDispatchStatus": "queued"
    })))
}

async fn authorize_registrar(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<RootAuthorizeRequest>,
) -> ApiResult<Value> {
    let _principal = require_admin(&headers, &state)?;
    let suite = request
        .did_document
        .verification_method
        .iter()
        .find(|method| {
            request
                .did_document
                .assertion_method
                .iter()
                .any(|id| id == &method.id)
        })
        .and_then(|method| method.crypto_suite())
        .unwrap_or(CryptoSuite::Ed25519Sha256Legacy);
    let did_document_hash =
        hash_json_with_suite(suite, &request.did_document).map_err(ApiError::internal)?;
    append_event(
        &state,
        BulletinEventType::RegistrarAuthorized,
        &request.target_did,
        json!({
            "targetRole": request.target_role,
            "didDocumentHash": did_document_hash,
        }),
    )
    .map_err(ApiError::internal)?;
    let authorized_domains = request
        .did_document
        .oan_metadata
        .as_ref()
        .map(|metadata| metadata.authorized_domains.clone())
        .unwrap_or_default();
    update_authorization_state(
        &state,
        &request.target_did,
        NodeAuthorizationState {
            status: "active".to_owned(),
            updated_at: Utc::now(),
            did_document_hash,
            did_document_snapshot: Some(request.did_document),
            authorized_domains,
        },
        &request.target_role,
        None,
    )
    .map_err(ApiError::internal)?;
    Ok(Json(json!({"status": "ok"})))
}

async fn authorize_discovery(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<RootAuthorizeRequest>,
) -> ApiResult<Value> {
    let _principal = require_admin(&headers, &state)?;
    let suite = request
        .did_document
        .verification_method
        .iter()
        .find(|method| {
            request
                .did_document
                .assertion_method
                .iter()
                .any(|id| id == &method.id)
        })
        .and_then(|method| method.crypto_suite())
        .unwrap_or(CryptoSuite::Ed25519Sha256Legacy);
    let did_document_hash =
        hash_json_with_suite(suite, &request.did_document).map_err(ApiError::internal)?;
    append_event(
        &state,
        BulletinEventType::DiscoveryNodeAuthorized,
        &request.target_did,
        json!({
            "targetRole": request.target_role,
            "didDocumentHash": did_document_hash,
        }),
    )
    .map_err(ApiError::internal)?;
    update_discovery_authorization_state(
        &state,
        &request.target_did,
        DiscoveryAuthorizationState {
            status: "active".to_owned(),
            updated_at: Utc::now(),
            did_document_hash,
            did_document_snapshot: Some(request.did_document),
            authorized_domains: vec!["*".to_owned()],
            tag_tree_version: state.tag_tree.version,
        },
    )
    .map_err(ApiError::internal)?;
    Ok(Json(json!({"status": "ok"})))
}

async fn issue_infrastructure_authorization_vc(
    State(state): State<AppState>,
    Json(request): Json<InfrastructureAuthorizationVcIssueRequest>,
) -> ApiResult<Value> {
    let subject_type =
        governance_subject_type_for_role(&request.payload.role).map_err(ApiError::bad_request)?;
    let did_document_stable_hash = normalize_hash_claim(&request.payload.did_document_stable_hash)
        .map_err(ApiError::bad_request)?;
    validate_authorization_vc_issue_request(
        &state,
        &request,
        subject_type,
        &did_document_stable_hash,
    )
    .await
    .map_err(ApiError::bad_request)?;
    let did_document_hash = did_document_hash_for_root(&state, &request.payload.did_document)
        .map_err(ApiError::internal)?;
    let governance = ensure_governance_active(&state, subject_type, &request.payload.subject_did)
        .await
        .map_err(ApiError::forbidden)?;
    let governance_subject =
        fetch_governance_subject_record(&state, subject_type, &request.payload.subject_did)
            .await
            .map_err(ApiError::forbidden)?;
    validate_governance_subject_binding(
        subject_type,
        &request.payload,
        &did_document_stable_hash,
        &governance_subject,
    )
    .map_err(ApiError::forbidden)?;
    let indexer_status = fetch_trust_indexer_status(&state).await.unwrap_or_default();
    let credential = build_infrastructure_authorization_credential(
        &state,
        subject_type,
        &request.payload,
        &did_document_stable_hash,
        &governance,
        &governance_subject,
        &indexer_status,
    )
    .map_err(ApiError::internal)?;

    match subject_type {
        GovernanceSubjectType::Registrar | GovernanceSubjectType::VcIssuer => {
            update_authorization_state(
                &state,
                &request.payload.subject_did,
                NodeAuthorizationState {
                    status: "active".to_owned(),
                    updated_at: Utc::now(),
                    did_document_hash: did_document_hash.clone(),
                    did_document_snapshot: Some(request.payload.did_document.clone()),
                    authorized_domains: if subject_type == GovernanceSubjectType::Registrar {
                        request.payload.authorized_domains.clone()
                    } else {
                        Vec::new()
                    },
                },
                subject_type.label(),
                None,
            )
            .map_err(ApiError::internal)?;
        }
        GovernanceSubjectType::Discovery => {
            update_discovery_authorization_state(
                &state,
                &request.payload.subject_did,
                DiscoveryAuthorizationState {
                    status: "active".to_owned(),
                    updated_at: Utc::now(),
                    did_document_hash: did_document_hash.clone(),
                    did_document_snapshot: Some(request.payload.did_document.clone()),
                    authorized_domains: request.payload.authorized_domains.clone(),
                    tag_tree_version: state.tag_tree.version,
                },
            )
            .map_err(ApiError::internal)?;
        }
    }

    Ok(Json(json!({
        "status": "issued",
        "subjectDid": request.payload.subject_did,
        "role": subject_type.label(),
        "didDocumentHash": did_document_hash,
        "didDocumentStableHash": did_document_stable_hash,
        "credential": credential
    })))
}

async fn update_discovery_domains(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Path(did): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let _principal = require_admin(&headers, &state)?;
    let domains = payload["authorizedDomains"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    append_event(
        &state,
        BulletinEventType::DiscoveryNodeDomainsUpdated,
        &did,
        payload,
    )
    .map_err(ApiError::internal)?;
    let mut authorization_state = current_authorization_state(&state);
    if let Some(entry) = authorization_state.discovery_nodes.get_mut(&did) {
        entry.authorized_domains = domains;
        entry.tag_tree_version = state.tag_tree.version;
        entry.updated_at = Utc::now();
        persist_authorization_state(&state, authorization_state).map_err(ApiError::internal)?;
    }
    Ok(Json(json!({"status": "ok"})))
}

async fn revoke_node(
    headers: HeaderMap,
    State(state): State<AppState>,
    axum::extract::Path(did): axum::extract::Path<String>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let _principal = require_admin(&headers, &state)?;
    append_event(&state, BulletinEventType::NodeRevoked, &did, payload)
        .map_err(ApiError::internal)?;
    revoke_authorization_state(&state, &did).map_err(ApiError::internal)?;
    Ok(Json(json!({"status": "ok"})))
}

async fn api_status(State(state): State<AppState>) -> ApiResult<Value> {
    let authorization_state = current_authorization_state(&state);
    if let Some(counts) = cached_root_status_counts_from_database(&state)
        .await
        .map_err(ApiError::internal)?
    {
        return Ok(Json(json!({
            "rootDid": state.root_did,
            "bulletinEventCount": counts.bulletin_event_count,
            "latestVersionCount": counts.latest_version_count,
            "cdnQueueCount": counts.cdn_ready_queue_count,
            "cdnReadyQueueCount": counts.cdn_ready_queue_count,
            "cdnActiveQueueCount": counts.cdn_active_queue_count,
            "cdnOutboxCount": counts.cdn_outbox_active_count,
            "cdnOutboxReadyCount": counts.cdn_outbox_ready_count,
            "cdnOutboxActiveCount": counts.cdn_outbox_active_count,
            "discoveryQueueCount": counts.discovery_ready_queue_count,
            "discoveryReadyQueueCount": counts.discovery_ready_queue_count,
            "discoveryPendingQueueCount": counts.discovery_pending_queue_count,
            "discoveryItemPendingCount": counts.discovery_item_pending_count,
            "statusBackend": counts.backend,
            "capabilityTreeVersion": state.tag_tree.version,
            "registrarAuthorizationCount": authorization_state.registrars.len(),
            "discoveryAuthorizationCount": authorization_state.discovery_nodes.len(),
            "vcIssuerAuthorizationCount": authorization_state.vc_issuers.len(),
            "workerProfile": worker_profile_json(&state.config.security.workers),
            "workerRuntime": worker_runtime_json(&state),
            "eventRuntime": event_runtime_json(&state),
            "admissionRuntime": admission_runtime_json(&state),
            "trustIndexer": {
                "enabled": state.config.security.trust_indexer.enabled,
                "endpoint": state.config.security.trust_indexer.endpoint,
                "failMode": state.config.security.trust_indexer.fail_mode,
                "pollIntervalMs": state.config.security.trust_indexer.poll_interval_ms,
                "timeoutMs": state.config.security.trust_indexer.timeout_ms
            }
        })));
    }
    let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
    let latest_versions = read_latest_versions(&state).map_err(ApiError::internal)?;
    let cdn_queue = read_ready_cdn_queue(&state)
        .await
        .map_err(ApiError::internal)?;
    let cdn_active_queue = read_cdn_queue(&state).await.map_err(ApiError::internal)?;
    let discovery_pending_queue = read_discovery_queue(&state)
        .await
        .map_err(ApiError::internal)?;
    let discovery_ready_queue = read_ready_discovery_queue(&state)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "rootDid": state.root_did,
        "bulletinEventCount": bulletin.events.len(),
        "latestVersionCount": latest_versions.len(),
        "cdnQueueCount": cdn_queue.len(),
        "cdnReadyQueueCount": cdn_queue.len(),
        "cdnActiveQueueCount": cdn_active_queue.len(),
        "cdnOutboxCount": 0,
        "cdnOutboxReadyCount": 0,
        "cdnOutboxActiveCount": 0,
        "discoveryQueueCount": discovery_ready_queue.len(),
        "discoveryReadyQueueCount": discovery_ready_queue.len(),
        "discoveryPendingQueueCount": discovery_pending_queue.len(),
        "discoveryItemPendingCount": 0,
        "capabilityTreeVersion": state.tag_tree.version,
        "registrarAuthorizationCount": authorization_state.registrars.len(),
        "discoveryAuthorizationCount": authorization_state.discovery_nodes.len(),
        "vcIssuerAuthorizationCount": authorization_state.vc_issuers.len(),
        "workerProfile": worker_profile_json(&state.config.security.workers),
        "workerRuntime": worker_runtime_json(&state),
        "eventRuntime": event_runtime_json(&state),
        "admissionRuntime": admission_runtime_json(&state),
        "trustIndexer": {
            "enabled": state.config.security.trust_indexer.enabled,
            "endpoint": state.config.security.trust_indexer.endpoint,
            "failMode": state.config.security.trust_indexer.fail_mode,
            "pollIntervalMs": state.config.security.trust_indexer.poll_interval_ms,
            "timeoutMs": state.config.security.trust_indexer.timeout_ms
        }
    })))
}

fn worker_profile_json(workers: &WorkerSecurityConfig) -> Value {
    json!({
        "enabled": workers.enabled,
        "cdnIntervalMs": workers.cdn_interval_ms,
        "discoveryIntervalMs": workers.discovery_interval_ms,
        "cdnBatchSize": workers.cdn_batch_size,
        "discoveryBatchSize": workers.discovery_batch_size,
        "cdnConcurrency": workers.cdn_concurrency,
        "discoveryConcurrency": workers.discovery_concurrency,
        "admissionConcurrency": workers.admission_concurrency,
        "leaseSeconds": workers.lease_seconds,
        "retryBackoffSeconds": workers.retry_backoff_seconds,
        "httpTimeoutSeconds": workers.http_timeout_seconds
    })
}

fn worker_runtime_json(state: &AppState) -> Value {
    state
        .worker_runtime
        .lock()
        .map(|runtime| serde_json::to_value(&*runtime).unwrap_or_else(|_| json!({})))
        .unwrap_or_else(|_| json!({"status": "unavailable"}))
}

fn event_runtime_json(state: &AppState) -> Value {
    state
        .event_runtime
        .lock()
        .map(|runtime| serde_json::to_value(&*runtime).unwrap_or_else(|_| json!({})))
        .unwrap_or_else(|_| json!({"status": "unavailable"}))
}

fn admission_runtime_json(state: &AppState) -> Value {
    state
        .admission_runtime
        .lock()
        .map(|runtime| serde_json::to_value(&*runtime).unwrap_or_else(|_| json!({})))
        .unwrap_or_else(|_| json!({"status": "unavailable"}))
}

fn invalidate_status_counts_cache(state: &AppState) {
    if let Ok(mut cache) = state.status_counts_cache.lock() {
        *cache = None;
    }
}

fn effective_worker_batch_size(
    configured: usize,
    ready_depth: usize,
    max_multiplier: usize,
) -> usize {
    let base = configured.max(1);
    if ready_depth > base * 4 {
        base.saturating_mul(max_multiplier.max(1)).min(5_000)
    } else if ready_depth > base * 2 {
        base.saturating_mul(2).min(5_000)
    } else {
        base
    }
}

fn effective_discovery_target_item_batch_size(
    configured: usize,
    claimed_target_count: usize,
    concurrency: usize,
    claimed_cursor_lag: i64,
) -> usize {
    let base = configured.max(1);
    let lag = claimed_cursor_lag.max(0) as usize;
    let active_targets = claimed_target_count.max(1);
    if active_targets <= concurrency.max(1) / 2 && lag > base.saturating_mul(active_targets * 2) {
        return base.saturating_mul(4).min(1_000);
    }
    if active_targets <= concurrency.max(1) && lag > base.saturating_mul(active_targets) {
        return base.saturating_mul(2).min(500);
    }
    base
}

fn record_discovery_worker_runtime(state: &AppState, sample: DiscoveryWorkerRuntimeSample) {
    if let Ok(mut runtime) = state.worker_runtime.lock() {
        let trigger_type = runtime.discovery_last_trigger_type.clone().or_else(|| {
            if runtime.discovery_event_trigger_count > runtime.discovery_timer_trigger_count {
                Some("event".to_owned())
            } else if runtime.discovery_timer_trigger_count > 0 {
                Some("timer".to_owned())
            } else {
                None
            }
        });
        runtime.discovery_last_elapsed_ms = sample.elapsed_ms;
        runtime.discovery_last_success_count = sample.success_count;
        runtime.discovery_last_failed_count = sample.failed_count;
        if sample.success_count > 0 || sample.failed_count > 0 {
            runtime.discovery_last_progress_elapsed_ms = sample.elapsed_ms;
            runtime.discovery_last_progress_success_count = sample.success_count;
            runtime.discovery_last_progress_failed_count = sample.failed_count;
            runtime.discovery_last_progress_trigger_type = trigger_type;
        }
        runtime.discovery_last_claim_elapsed_ms = sample.stage_metrics.claim_elapsed_ms;
        runtime.discovery_last_prepare_elapsed_ms = sample.stage_metrics.prepare_elapsed_ms;
        runtime.discovery_last_notify_elapsed_ms = sample.stage_metrics.notify_elapsed_ms;
        runtime.discovery_effective_batch_size = sample.batch_size;
        runtime.discovery_effective_item_batch_size = sample.outcome_metrics.item_batch_size;
        runtime.discovery_effective_concurrency = sample.concurrency;
        runtime.discovery_last_claimed_target_count = sample.outcome_metrics.claimed_target_count;
        runtime.discovery_last_carry_forward_count = sample.outcome_metrics.carry_forward_count;
        runtime.discovery_last_ready_queue_depth_after =
            sample.outcome_metrics.ready_queue_depth_after;
        runtime.discovery_last_pending_queue_depth_after =
            sample.outcome_metrics.pending_queue_depth_after;
        runtime.discovery_last_claimed_cursor_lag = sample.outcome_metrics.claimed_cursor_lag;
        runtime.updated_at = Some(Utc::now());
    }
}

fn record_admission_accepted(state: &AppState, wait_ms: u128) {
    if let Ok(mut runtime) = state.admission_runtime.lock() {
        runtime.last_wait_ms = wait_ms;
        runtime.max_wait_ms = runtime.max_wait_ms.max(wait_ms);
        runtime.accepted_count = runtime.accepted_count.saturating_add(1);
        runtime.last_error = None;
        runtime.updated_at = Some(Utc::now());
    }
}

fn record_admission_busy(state: &AppState, wait_ms: u128) {
    if let Ok(mut runtime) = state.admission_runtime.lock() {
        runtime.last_wait_ms = wait_ms;
        runtime.max_wait_ms = runtime.max_wait_ms.max(wait_ms);
        runtime.busy_rejected_count = runtime.busy_rejected_count.saturating_add(1);
        runtime.last_error = Some("root_admission_busy".to_owned());
        runtime.updated_at = Some(Utc::now());
    }
}

fn record_cdn_worker_runtime(
    state: &AppState,
    elapsed_ms: u128,
    success_count: usize,
    failed_count: usize,
    batch_size: usize,
    concurrency: usize,
    stage_metrics: CdnWorkerStageMetrics,
) {
    if let Ok(mut runtime) = state.worker_runtime.lock() {
        let trigger_type = runtime.cdn_last_trigger_type.clone().or_else(|| {
            if runtime.cdn_event_trigger_count > runtime.cdn_timer_trigger_count {
                Some("event".to_owned())
            } else if runtime.cdn_timer_trigger_count > 0 {
                Some("timer".to_owned())
            } else {
                None
            }
        });
        runtime.cdn_last_elapsed_ms = elapsed_ms;
        runtime.cdn_last_success_count = success_count;
        runtime.cdn_last_failed_count = failed_count;
        if success_count > 0 || failed_count > 0 {
            runtime.cdn_last_progress_elapsed_ms = elapsed_ms;
            runtime.cdn_last_progress_success_count = success_count;
            runtime.cdn_last_progress_failed_count = failed_count;
            runtime.cdn_last_progress_trigger_type = trigger_type;
        }
        runtime.cdn_last_claim_elapsed_ms = stage_metrics.claim_elapsed_ms;
        runtime.cdn_last_publish_elapsed_ms = stage_metrics.publish_elapsed_ms;
        runtime.cdn_last_mark_published_elapsed_ms = stage_metrics.mark_published_elapsed_ms;
        runtime.cdn_last_mark_retry_elapsed_ms = stage_metrics.mark_retry_elapsed_ms;
        runtime.cdn_effective_batch_size = batch_size;
        runtime.cdn_effective_concurrency = concurrency;
        runtime.updated_at = Some(Utc::now());
    }
}

fn record_worker_trigger(state: &AppState, cdn_worker: bool, trigger: WorkerTriggerType) {
    if let Ok(mut runtime) = state.worker_runtime.lock() {
        match (cdn_worker, trigger) {
            (true, WorkerTriggerType::Event) => {
                runtime.cdn_event_trigger_count = runtime.cdn_event_trigger_count.saturating_add(1);
                runtime.cdn_last_trigger_type = Some("event".to_owned());
            }
            (true, WorkerTriggerType::Timer) => {
                runtime.cdn_timer_trigger_count = runtime.cdn_timer_trigger_count.saturating_add(1);
                runtime.cdn_last_trigger_type = Some("timer".to_owned());
            }
            (false, WorkerTriggerType::Event) => {
                runtime.discovery_event_trigger_count =
                    runtime.discovery_event_trigger_count.saturating_add(1);
                runtime.discovery_last_trigger_type = Some("event".to_owned());
            }
            (false, WorkerTriggerType::Timer) => {
                runtime.discovery_timer_trigger_count =
                    runtime.discovery_timer_trigger_count.saturating_add(1);
                runtime.discovery_last_trigger_type = Some("timer".to_owned());
            }
        }
        runtime.updated_at = Some(Utc::now());
    }
}

fn signal_worker_event(state: &AppState, cdn_worker: bool) {
    if let Ok(mut wake_state) = state.worker_wake_state.lock() {
        if cdn_worker {
            wake_state.cdn_last_event_signal_at = Some(Instant::now());
            wake_state.cdn_pending_event_signal_count =
                wake_state.cdn_pending_event_signal_count.saturating_add(1);
        } else {
            wake_state.discovery_last_event_signal_at = Some(Instant::now());
            wake_state.discovery_pending_event_signal_count = wake_state
                .discovery_pending_event_signal_count
                .saturating_add(1);
        }
    }
    if cdn_worker {
        state.cdn_worker_notify.notify_one();
    } else {
        state.discovery_worker_notify.notify_one();
    }
}

fn consume_pending_worker_signal_trigger(state: &AppState, cdn_worker: bool) -> bool {
    let had_pending_signal = if let Ok(mut wake_state) = state.worker_wake_state.lock() {
        if cdn_worker {
            if wake_state.cdn_pending_event_signal_count > 0 {
                wake_state.cdn_pending_event_signal_count -= 1;
                true
            } else {
                false
            }
        } else if wake_state.discovery_pending_event_signal_count > 0 {
            wake_state.discovery_pending_event_signal_count -= 1;
            true
        } else {
            false
        }
    } else {
        false
    };
    if had_pending_signal {
        record_worker_trigger(state, cdn_worker, WorkerTriggerType::Event);
        if let Some(delay_ms) = take_worker_event_delay_ms(state, cdn_worker) {
            record_worker_event_delay(state, cdn_worker, delay_ms);
        }
    }
    had_pending_signal
}

fn take_worker_event_delay_ms(state: &AppState, cdn_worker: bool) -> Option<u128> {
    let signaled_at = state
        .worker_wake_state
        .lock()
        .ok()
        .and_then(|mut wake_state| {
            if cdn_worker {
                wake_state.cdn_pending_event_signal_count =
                    wake_state.cdn_pending_event_signal_count.saturating_sub(1);
                if wake_state.cdn_pending_event_signal_count == 0 {
                    wake_state.cdn_last_event_signal_at.take()
                } else {
                    wake_state.cdn_last_event_signal_at
                }
            } else {
                wake_state.discovery_pending_event_signal_count = wake_state
                    .discovery_pending_event_signal_count
                    .saturating_sub(1);
                if wake_state.discovery_pending_event_signal_count == 0 {
                    wake_state.discovery_last_event_signal_at.take()
                } else {
                    wake_state.discovery_last_event_signal_at
                }
            }
        })?;
    Some(signaled_at.elapsed().as_millis())
}

fn record_worker_event_delay(state: &AppState, cdn_worker: bool, delay_ms: u128) {
    if let Ok(mut runtime) = state.worker_runtime.lock() {
        if cdn_worker {
            runtime.cdn_last_event_to_cycle_start_ms = delay_ms;
        } else {
            runtime.discovery_last_event_to_cycle_start_ms = delay_ms;
        }
        runtime.updated_at = Some(Utc::now());
    }
}

fn record_worker_oldest_pending_age(state: &AppState, cdn_worker: bool, age_ms: u128) {
    if let Ok(mut runtime) = state.worker_runtime.lock() {
        if cdn_worker {
            runtime.cdn_oldest_pending_age_ms = age_ms;
        } else {
            runtime.discovery_oldest_pending_age_ms = age_ms;
        }
        runtime.updated_at = Some(Utc::now());
    }
}

fn resource_package_oldest_age_ms(items: &[ResourcePackage]) -> u128 {
    let now = Utc::now();
    items
        .iter()
        .filter_map(|item| (now - item.created_at).to_std().ok())
        .map(|duration| duration.as_millis())
        .max()
        .unwrap_or(0)
}

fn discovery_queue_oldest_age_ms(items: &[Value]) -> u128 {
    let now = Utc::now();
    items
        .iter()
        .filter_map(|item| item.get("updatedAt").and_then(Value::as_str))
        .filter_map(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        .map(|value| now.signed_duration_since(value.with_timezone(&Utc)))
        .filter_map(|duration| duration.to_std().ok())
        .map(|duration| duration.as_millis())
        .max()
        .unwrap_or(0)
}

fn record_worker_noop_cycle(state: &AppState, cdn_worker: bool) {
    if let Ok(mut runtime) = state.worker_runtime.lock() {
        if cdn_worker {
            runtime.cdn_noop_cycle_count = runtime.cdn_noop_cycle_count.saturating_add(1);
        } else {
            runtime.discovery_noop_cycle_count =
                runtime.discovery_noop_cycle_count.saturating_add(1);
        }
        runtime.updated_at = Some(Utc::now());
    }
}

fn record_mark_published_runtime(state: &AppState, sample: MarkPublishedRuntimeSample) {
    if let Ok(mut runtime) = state.worker_runtime.lock() {
        runtime.mark_published_last_job_count = sample.job_count;
        runtime.mark_published_last_fetch_elapsed_ms = sample.fetch_elapsed_ms;
        runtime.mark_published_last_fetch_sql_elapsed_ms = sample.fetch_sql_elapsed_ms;
        runtime.mark_published_last_watermark_match_elapsed_ms = sample.watermark_match_elapsed_ms;
        runtime.mark_published_last_update_elapsed_ms = sample.update_elapsed_ms;
        runtime.mark_published_last_watermark_elapsed_ms = sample.watermark_elapsed_ms;
        runtime.mark_published_last_store_items_elapsed_ms = sample.store_items_elapsed_ms;
        runtime.mark_published_last_upsert_targets_elapsed_ms = sample.upsert_targets_elapsed_ms;
        runtime.mark_published_last_delete_jobs_elapsed_ms = sample.delete_jobs_elapsed_ms;
        runtime.mark_published_last_total_elapsed_ms = sample.total_elapsed_ms;
        runtime.mark_published_total_call_count =
            runtime.mark_published_total_call_count.saturating_add(1);
        runtime.mark_published_max_update_elapsed_ms = runtime
            .mark_published_max_update_elapsed_ms
            .max(sample.update_elapsed_ms);
        runtime.mark_published_max_total_elapsed_ms = runtime
            .mark_published_max_total_elapsed_ms
            .max(sample.total_elapsed_ms);
        runtime.updated_at = Some(Utc::now());
    }
}

fn record_event_publish_success(state: &AppState) {
    if let Ok(mut runtime) = state.event_runtime.lock() {
        runtime.publish_success_count = runtime.publish_success_count.saturating_add(1);
        runtime.last_error = None;
        runtime.updated_at = Some(Utc::now());
    }
}

fn record_event_publish_failure(state: &AppState, error: &str) {
    if let Ok(mut runtime) = state.event_runtime.lock() {
        runtime.publish_failure_count = runtime.publish_failure_count.saturating_add(1);
        runtime.last_error = Some(error.to_owned());
        runtime.updated_at = Some(Utc::now());
    }
}

#[derive(Clone, Debug)]
struct RootStatusCounts {
    backend: &'static str,
    bulletin_event_count: i64,
    latest_version_count: i64,
    cdn_ready_queue_count: i64,
    cdn_active_queue_count: i64,
    cdn_outbox_ready_count: i64,
    cdn_outbox_active_count: i64,
    discovery_ready_queue_count: i64,
    discovery_pending_queue_count: i64,
    discovery_item_pending_count: i64,
}

async fn cached_root_status_counts_from_database(
    state: &AppState,
) -> Result<Option<RootStatusCounts>> {
    if let Ok(cache) = state.status_counts_cache.lock() {
        if let Some(cached) = cache.as_ref() {
            if cached.captured_at.elapsed() <= StdDuration::from_millis(ROOT_STATUS_CACHE_TTL_MS) {
                return Ok(Some(cached.counts.clone()));
            }
        }
    }
    let counts = root_status_counts_from_database(state).await?;
    if let Some(counts) = counts.as_ref() {
        if let Ok(mut cache) = state.status_counts_cache.lock() {
            *cache = Some(CachedRootStatusCounts {
                captured_at: Instant::now(),
                counts: counts.clone(),
            });
        }
    }
    Ok(counts)
}

async fn root_status_counts_from_database(state: &AppState) -> Result<Option<RootStatusCounts>> {
    let now = Utc::now().to_rfc3339();
    if let Some(sqlite) = &state.sqlite {
        let bulletin_event_count =
            sqlx::query(&format!("SELECT COUNT(*) FROM {ROOT_BULLETIN_EVENT_TABLE}"))
                .fetch_one(sqlite.pool())
                .await?
                .get::<i64, _>(0);
        let latest_version_count =
            sqlx::query(&format!("SELECT COUNT(*) FROM {ROOT_SUBJECT_LATEST_TABLE}"))
                .fetch_one(sqlite.pool())
                .await?
                .get::<i64, _>(0);
        let cdn_ready_queue_count = sqlx::query(&format!(
            r#"
            SELECT COUNT(*) FROM {ROOT_CDN_JOB_TABLE}
            WHERE status = 'ready'
               OR (status = 'retry-wait' AND next_attempt_at <= ?)
               OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)
            "#
        ))
        .bind(&now)
        .bind(&now)
        .fetch_one(sqlite.pool())
        .await?
        .get::<i64, _>(0);
        let cdn_active_queue_count = sqlx::query(&format!(
            "SELECT COUNT(*) FROM {ROOT_CDN_JOB_TABLE} WHERE status IN ('ready', 'leased', 'retry-wait')"
        ))
        .fetch_one(sqlite.pool())
        .await?
        .get::<i64, _>(0);
        let cdn_outbox_ready_count = sqlx::query(&format!(
            r#"
            SELECT COUNT(*) FROM {ROOT_CDN_OUTBOX_TABLE}
            WHERE status = 'ready'
               OR (status = 'retry-wait' AND next_attempt_at <= ?)
               OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)
            "#
        ))
        .bind(&now)
        .bind(&now)
        .fetch_one(sqlite.pool())
        .await?
        .get::<i64, _>(0);
        let cdn_outbox_active_count = sqlx::query(&format!(
            "SELECT COUNT(*) FROM {ROOT_CDN_OUTBOX_TABLE} WHERE status IN ('ready', 'leased', 'retry-wait')"
        ))
        .fetch_one(sqlite.pool())
        .await?
        .get::<i64, _>(0);
        let discovery_ready_queue_count = sqlx::query(&format!(
            r#"
            SELECT COUNT(*) FROM {ROOT_DISCOVERY_TARGET_TABLE}
            WHERE status = 'active'
              AND pending_cursor > delivered_cursor
              AND next_attempt_at <= ?
              AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
            "#
        ))
        .bind(&now)
        .bind(&now)
        .fetch_one(sqlite.pool())
        .await?
        .get::<i64, _>(0);
        let discovery_pending_queue_count = sqlx::query(&format!(
            "SELECT COUNT(*) FROM {ROOT_DISCOVERY_TARGET_TABLE} WHERE status = 'active' AND pending_cursor > delivered_cursor"
        ))
        .fetch_one(sqlite.pool())
        .await?
        .get::<i64, _>(0);
        let discovery_item_pending_count =
            sqlx::query(&format!("SELECT COUNT(*) FROM {ROOT_DISCOVERY_ITEM_TABLE}"))
                .fetch_one(sqlite.pool())
                .await?
                .get::<i64, _>(0);
        return Ok(Some(RootStatusCounts {
            backend: "sqlite",
            bulletin_event_count,
            latest_version_count,
            cdn_ready_queue_count,
            cdn_active_queue_count,
            cdn_outbox_ready_count,
            cdn_outbox_active_count,
            discovery_ready_queue_count,
            discovery_pending_queue_count,
            discovery_item_pending_count,
        }));
    }
    if let Some(postgres) = &state.postgres {
        let row = sqlx::query(&format!(
            r#"
            SELECT
                (SELECT COUNT(*) FROM {ROOT_BULLETIN_EVENT_TABLE}) AS bulletin_event_count,
                (SELECT COUNT(*) FROM {ROOT_SUBJECT_LATEST_TABLE}) AS latest_version_count,
                (
                    SELECT COUNT(*) FROM {ROOT_CDN_JOB_TABLE}
                    WHERE status = 'ready'
                       OR (status = 'retry-wait' AND next_attempt_at <= $1::timestamptz)
                       OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= $1::timestamptz)
                ) AS cdn_ready_queue_count,
                (
                    SELECT COUNT(*) FROM {ROOT_CDN_JOB_TABLE}
                    WHERE status IN ('ready', 'leased', 'retry-wait')
                ) AS cdn_active_queue_count,
                (
                    SELECT COUNT(*) FROM {ROOT_CDN_OUTBOX_TABLE}
                    WHERE status = 'ready'
                       OR (status = 'retry-wait' AND next_attempt_at <= $1::timestamptz)
                       OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= $1::timestamptz)
                ) AS cdn_outbox_ready_count,
                (
                    SELECT COUNT(*) FROM {ROOT_CDN_OUTBOX_TABLE}
                    WHERE status IN ('ready', 'leased', 'retry-wait')
                ) AS cdn_outbox_active_count,
                (
                    SELECT COUNT(*) FROM {ROOT_DISCOVERY_TARGET_TABLE}
                    WHERE status = 'active'
                      AND pending_cursor > delivered_cursor
                      AND next_attempt_at <= $1::timestamptz
                      AND (lease_expires_at IS NULL OR lease_expires_at <= $1::timestamptz)
                ) AS discovery_ready_queue_count,
                (
                    SELECT COUNT(*) FROM {ROOT_DISCOVERY_TARGET_TABLE}
                    WHERE status = 'active' AND pending_cursor > delivered_cursor
                ) AS discovery_pending_queue_count,
                (
                    SELECT COUNT(*) FROM {ROOT_DISCOVERY_ITEM_TABLE}
                ) AS discovery_item_pending_count
            "#
        ))
        .bind(&now)
        .fetch_one(postgres.pool())
        .await?;
        return Ok(Some(RootStatusCounts {
            backend: "postgres",
            bulletin_event_count: row.get::<i64, _>("bulletin_event_count"),
            latest_version_count: row.get::<i64, _>("latest_version_count"),
            cdn_ready_queue_count: row.get::<i64, _>("cdn_ready_queue_count"),
            cdn_active_queue_count: row.get::<i64, _>("cdn_active_queue_count"),
            cdn_outbox_ready_count: row.get::<i64, _>("cdn_outbox_ready_count"),
            cdn_outbox_active_count: row.get::<i64, _>("cdn_outbox_active_count"),
            discovery_ready_queue_count: row.get::<i64, _>("discovery_ready_queue_count"),
            discovery_pending_queue_count: row.get::<i64, _>("discovery_pending_queue_count"),
            discovery_item_pending_count: row.get::<i64, _>("discovery_item_pending_count"),
        }));
    }
    Ok(None)
}

async fn api_registrars(State(state): State<AppState>) -> ApiResult<Value> {
    let authorization_state = current_authorization_state(&state);
    let items: Vec<Value> = authorization_state
        .registrars
        .into_iter()
        .map(|(did, entry)| {
            json!({
                "did": did,
                "status": entry.status,
                "didDocumentHash": entry.did_document_hash,
                "authorizedDomains": entry.authorized_domains,
                "updatedAt": entry.updated_at
            })
        })
        .collect();
    let items = if items.is_empty() {
        let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
        bulletin
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event.core.event_type,
                    BulletinEventType::RegistrarAuthorized | BulletinEventType::RegistrarRevoked
                )
            })
            .map(|event| {
                json!({
                    "did": event.core.subject_did,
                    "eventType": event.core.event_type,
                    "sequence": event.core.sequence,
                    "payload": event.core.payload
                })
            })
            .collect::<Vec<_>>()
    } else {
        items
    };
    Ok(Json(json!({ "items": items })))
}

async fn api_registrar_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
    let events: Vec<Value> = bulletin
        .events
        .iter()
        .filter(|event| event.core.subject_did == did)
        .map(|event| {
            json!({
                "sequence": event.core.sequence,
                "eventType": event.core.event_type,
                "payload": event.core.payload
            })
        })
        .collect();
    Ok(Json(json!({ "did": did, "events": events })))
}

async fn api_discovery_nodes(State(state): State<AppState>) -> ApiResult<Value> {
    let authorization_state = current_authorization_state(&state);
    let items: Vec<Value> = authorization_state
        .discovery_nodes
        .into_iter()
        .map(|(did, entry)| {
            json!({
                "did": did,
                "status": entry.status,
                "didDocumentHash": entry.did_document_hash,
                "authorizedDomains": entry.authorized_domains,
                "tagTreeVersion": entry.tag_tree_version,
                "updatedAt": entry.updated_at
            })
        })
        .collect();
    let items = if items.is_empty() {
        let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
        bulletin
            .events
            .iter()
            .filter(|event| {
                matches!(
                    event.core.event_type,
                    BulletinEventType::DiscoveryNodeAuthorized
                        | BulletinEventType::DiscoveryNodeDomainsUpdated
                        | BulletinEventType::DiscoveryNodeRevoked
                )
            })
            .map(|event| {
                json!({
                    "did": event.core.subject_did,
                    "eventType": event.core.event_type,
                    "sequence": event.core.sequence,
                    "payload": event.core.payload
                })
            })
            .collect::<Vec<_>>()
    } else {
        items
    };
    Ok(Json(json!({ "items": items })))
}

async fn api_discovery_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
    let latest_domains = bulletin
        .events
        .iter()
        .rev()
        .find(|event| {
            event.core.subject_did == did
                && matches!(
                    event.core.event_type,
                    BulletinEventType::DiscoveryNodeDomainsUpdated
                )
        })
        .map(|event| event.core.payload.clone())
        .unwrap_or_else(|| json!({"authorizedDomains": []}));
    Ok(Json(json!({
        "did": did,
        "status": latest_node_status(&bulletin, &did),
        "latestDomains": latest_domains,
        "events": bulletin.events.iter().filter(|event| event.core.subject_did == did).map(|event| json!({
            "sequence": event.core.sequence,
            "eventType": event.core.event_type,
            "payload": event.core.payload
        })).collect::<Vec<_>>()
    })))
}

async fn api_resource_versions(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    if state.sqlite.is_some() || state.postgres.is_some() {
        let items = repository::resource_versions_impl(&state, &did)
            .await
            .map_err(ApiError::internal)?;
        return Ok(Json(json!({ "did": did, "items": items })));
    }
    let prefix = format!(
        "archive/{}",
        did_to_file_name(&did).trim_end_matches(".json")
    );
    let index = state
        .data
        .read::<Value>(format!("{prefix}/index.json"))
        .ok()
        .and_then(|value| value.as_array().cloned())
        .unwrap_or_default();
    Ok(Json(json!({ "did": did, "items": index })))
}

async fn api_resource_version_detail(
    State(state): State<AppState>,
    AxumPath((did, version)): AxumPath<(String, String)>,
) -> ApiResult<Value> {
    if state.sqlite.is_some() || state.postgres.is_some() {
        let row = repository::resource_version_detail_impl(&state, &did, &version)
            .await
            .map_err(ApiError::internal)?;
        let Some((package, accepted_at)) = row else {
            return Ok(Json(json!({
                "did": did,
                "version": version,
                "didDocument": Value::Null,
                "metadata": Value::Null,
                "package": Value::Null
            })));
        };
        return Ok(Json(json!({
            "did": did,
            "version": version,
            "acceptedAt": accepted_at,
            "didDocument": package.did_document,
            "metadata": package.metadata,
            "package": package
        })));
    }
    let prefix = format!(
        "resources/{}/{}",
        did_to_file_name(&did).trim_end_matches(".json"),
        version
    );
    let did_document: Option<DidDocument> =
        state.data.read(format!("{prefix}/did-document.json")).ok();
    let metadata: Option<ResourceMetadata> =
        state.data.read(format!("{prefix}/metadata.json")).ok();
    let package: Option<ResourcePackage> = state
        .data
        .read(format!("{prefix}/resource-package.json"))
        .ok();
    Ok(Json(json!({
        "did": did,
        "version": version,
        "didDocument": did_document,
        "metadata": metadata,
        "package": package
    })))
}

async fn api_mark_cdn_publication_jobs_published(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<MarkCdnPublicationJobsPublishedRequest>,
) -> ApiResult<Value> {
    let started = Instant::now();
    let _principal = require_admin(&headers, &state)?;
    if request.jobs.is_empty() {
        return Err(ApiError::bad_request("empty_jobs"));
    }
    let job_keys = request
        .jobs
        .iter()
        .map(|job| job.job_key.trim().to_owned())
        .collect::<Vec<_>>();
    if job_keys.iter().any(|job_key| job_key.is_empty()) {
        return Err(ApiError::bad_request("empty_job_key"));
    }
    let authorization_state = current_authorization_state(&state);
    let completion = repository::complete_cdn_publication_jobs_impl(
        &state,
        &request.jobs,
        &authorization_state.discovery_nodes,
        &state.tag_tree,
    )
    .await
    .map_err(|err| {
        let message = err.to_string();
        if message.contains("unknown_cdn_publication_job") {
            ApiError::bad_request(message)
        } else {
            ApiError::internal(err)
        }
    })?;
    invalidate_status_counts_cache(&state);
    let total_elapsed_ms = started.elapsed().as_millis();
    record_mark_published_runtime(
        &state,
        MarkPublishedRuntimeSample {
            job_count: completion.marked_count,
            fetch_elapsed_ms: completion.fetch_elapsed_ms,
            fetch_sql_elapsed_ms: completion.fetch_sql_elapsed_ms,
            watermark_match_elapsed_ms: completion.watermark_match_elapsed_ms,
            update_elapsed_ms: completion.update_elapsed_ms,
            watermark_elapsed_ms: completion.watermark_elapsed_ms,
            store_items_elapsed_ms: completion.store_items_elapsed_ms,
            upsert_targets_elapsed_ms: completion.upsert_targets_elapsed_ms,
            delete_jobs_elapsed_ms: completion.delete_jobs_elapsed_ms,
            total_elapsed_ms,
        },
    );
    if completion.advanced_discovery_count > 0 {
        signal_worker_event(&state, false);
    }
    Ok(Json(json!({
        "status": "ok",
        "markedCount": completion.marked_count,
        "storedNotificationCount": completion.stored_notification_count,
        "advancedDiscoveryCount": completion.advanced_discovery_count,
        "timing": {
            "fetchElapsedMs": completion.fetch_elapsed_ms,
            "fetchSqlElapsedMs": completion.fetch_sql_elapsed_ms,
            "watermarkMatchElapsedMs": completion.watermark_match_elapsed_ms,
            "updateElapsedMs": completion.update_elapsed_ms,
            "watermarkElapsedMs": completion.watermark_elapsed_ms,
            "storeItemsElapsedMs": completion.store_items_elapsed_ms,
            "upsertTargetsElapsedMs": completion.upsert_targets_elapsed_ms,
            "deleteJobsElapsedMs": completion.delete_jobs_elapsed_ms,
            "totalElapsedMs": total_elapsed_ms
        }
    })))
}

async fn api_cdn_publication_jobs_packages(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(request): Json<CdnPublicationJobsPackageRequest>,
) -> ApiResult<Value> {
    let _principal = require_admin(&headers, &state)?;
    if request.jobs.is_empty() {
        return Err(ApiError::bad_request("empty_jobs"));
    }
    let job_keys = request
        .jobs
        .iter()
        .map(|job| job.job_key.trim().to_owned())
        .collect::<Vec<_>>();
    if job_keys.iter().any(|job_key| job_key.is_empty()) {
        return Err(ApiError::bad_request("empty_job_key"));
    }
    let packages = resource_packages_for_jobs(&state, &job_keys)
        .await
        .map_err(ApiError::internal)?;
    let items = job_keys
        .iter()
        .filter_map(|job_key| {
            packages.get(job_key).map(|(package, publication_cursor)| {
                json!({
                    "jobKey": job_key,
                    "publicationCursor": publication_cursor,
                    "resourceDid": package.resource_did,
                    "packageVersion": package.package_version,
                    "packageHash": package.package_hash,
                    "didDocumentHash": package.did_document_hash,
                    "metadataHash": package.metadata_hash,
                    "package": package
                })
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "status": "ok",
        "requestedCount": request.jobs.len(),
        "foundCount": items.len(),
        "items": items
    })))
}

async fn api_cdn_publish_queue(State(state): State<AppState>) -> ApiResult<Value> {
    let queue = read_cdn_queue(&state).await.map_err(ApiError::internal)?;
    Ok(Json(json!({ "items": queue, "count": queue.len() })))
}

async fn api_discovery_notify_queue(State(state): State<AppState>) -> ApiResult<Value> {
    let queue = read_discovery_queue(&state)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({ "items": queue, "count": queue.len() })))
}

async fn api_capability_tree(State(state): State<AppState>) -> ApiResult<CapabilityTagTree> {
    Ok(Json(state.tag_tree.clone()))
}

async fn api_validate_tags(
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> ApiResult<Value> {
    let tags = payload["capabilityTags"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    let custom_tags = tags
        .iter()
        .filter(|tag| state.tag_tree.normalize_tag(tag).is_none())
        .cloned()
        .collect::<Vec<_>>();
    let canonical_tags = tags
        .iter()
        .filter_map(|tag| state.tag_tree.normalize_tag(tag).map(ToOwned::to_owned))
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "valid": true,
        "canonicalTags": canonical_tags,
        "customTags": custom_tags,
        "note": "Capability tree tags are recommended for network-wide coarse discovery. Custom tags are allowed and can be used for later fine-grained filtering."
    })))
}

async fn api_bulletin_events(State(state): State<AppState>) -> ApiResult<Value> {
    let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
    Ok(Json(json!({ "items": bulletin.events })))
}

async fn api_bulletin_event_detail(
    State(state): State<AppState>,
    AxumPath(sequence): AxumPath<u64>,
) -> ApiResult<Value> {
    let bulletin = read_bulletin(&state).map_err(ApiError::internal)?;
    let event = bulletin
        .events
        .into_iter()
        .find(|event| event.core.sequence == sequence);
    Ok(Json(json!({ "event": event })))
}

fn latest_node_status(bulletin: &Bulletin, did: &str) -> String {
    if bulletin.events.iter().any(|event| {
        event.core.subject_did == did
            && matches!(event.core.event_type, BulletinEventType::NodeRevoked)
    }) {
        "revoked".to_owned()
    } else {
        "active".to_owned()
    }
}

fn load_authorized_registrar_entry(
    state: &AppState,
    did: &str,
) -> std::result::Result<NodeAuthorizationState, String> {
    let authorization_state = current_authorization_state(state);
    let entry = authorization_state
        .registrars
        .get(did)
        .cloned()
        .ok_or_else(|| "registrar_not_authorized".to_owned())?;
    if entry.status != "active" {
        return Err("registrar_not_authorized".to_owned());
    }
    Ok(entry)
}

fn load_authorized_registrar_document(state: &AppState, did: &str) -> Result<DidDocument> {
    let entry = load_authorized_registrar_entry(state, did).map_err(|err| anyhow!(err))?;
    entry
        .did_document_snapshot
        .ok_or_else(|| anyhow!("authorized_registrar_document_missing"))
}

fn validate_authorized_domain_list(domains: &[String]) -> std::result::Result<(), String> {
    if domains.iter().any(|domain| domain == "*") {
        return if domains.len() == 1 {
            Ok(())
        } else {
            Err("invalid_authorized_domains".to_owned())
        };
    }
    for domain in domains {
        if domain.trim().is_empty()
            || domain != domain.trim()
            || domain.contains("..")
            || domain.starts_with('.')
            || domain.ends_with('.')
        {
            return Err("invalid_authorized_domains".to_owned());
        }
    }
    if domains.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err("invalid_authorized_domains".to_owned());
    }
    Ok(())
}

fn authorized_domain_covers(granted: &str, requested: &str) -> bool {
    granted == requested
        || requested
            .strip_prefix(granted)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

fn authorized_domains_cover(granted: &[String], requested: &[String]) -> bool {
    if requested.is_empty() {
        return true;
    }
    if granted.iter().any(|domain| domain == "*") {
        return true;
    }
    if granted.is_empty() {
        return false;
    }
    requested.iter().all(|requested_domain| {
        granted
            .iter()
            .any(|granted_domain| authorized_domain_covers(granted_domain, requested_domain))
    })
}

fn validate_resource_authorized_domains(
    resource_domains: &[String],
    registrar_domains: &[String],
) -> std::result::Result<(), String> {
    if resource_domains.is_empty() {
        return Err("resource_domains_required".to_owned());
    }
    validate_authorized_domain_list(resource_domains)?;
    validate_authorized_domain_list(registrar_domains)?;
    if !authorized_domains_cover(registrar_domains, resource_domains) {
        return Err("unauthorized_domains".to_owned());
    }
    Ok(())
}

fn governance_subject_type_for_role(
    role: &str,
) -> std::result::Result<GovernanceSubjectType, String> {
    match role {
        "registrar" | "Registrar" | "Registrar Node" | "registrar-node" => {
            Ok(GovernanceSubjectType::Registrar)
        }
        "discovery" | "Discovery" | "Discovery Node" | "discovery-node" => {
            Ok(GovernanceSubjectType::Discovery)
        }
        "vc_issuer" | "vc-issuer" | "VC Issuer" | "third-party-vc-issuer" => {
            Ok(GovernanceSubjectType::VcIssuer)
        }
        _ => Err("unsupported_infrastructure_role".to_owned()),
    }
}

async fn validate_authorization_vc_issue_request(
    state: &AppState,
    request: &InfrastructureAuthorizationVcIssueRequest,
    subject_type: GovernanceSubjectType,
    did_document_stable_hash: &str,
) -> std::result::Result<(), String> {
    if request.payload.subject_did.trim().is_empty() {
        return Err("missing_subject_did".to_owned());
    }
    if !request.payload.subject_did.starts_with("did:oan:") {
        return Err("unsupported_subject_did_method".to_owned());
    }
    validate_infrastructure_did_prefix(subject_type, &request.payload.subject_did)?;
    if request.payload.did_document.id != request.payload.subject_did {
        return Err("did_document_subject_mismatch".to_owned());
    }
    if did_document_stable_hash.trim().is_empty() {
        return Err("missing_did_document_stable_hash".to_owned());
    }
    validate_infrastructure_did_document_profile(&request.payload, subject_type)?;
    let policy = TrustedUpstreamPolicy {
        expected_purpose: PURPOSE_INFRASTRUCTURE_AUTHORIZATION_VC_ISSUE.to_owned(),
        expected_method: "POST".to_owned(),
        expected_path: PATH_ROOT_INFRASTRUCTURE_AUTHORIZATION_VCS_ISSUE.to_owned(),
        expected_audience: state.root_did.clone(),
        max_clock_skew_seconds: state
            .config
            .security
            .trusted_upstream
            .max_clock_skew_seconds,
        nonce_ttl_seconds: state.config.security.trusted_upstream.nonce_ttl_seconds,
        nonce_store_path: state.config.paths.request_nonce_file.clone(),
    };
    verify_signed_request_envelope(
        &request.upstream_auth,
        &request.payload,
        &request.payload.subject_did,
        &request.payload.did_document,
        &policy,
        Utc::now(),
    )
    .map_err(|err| err.to_string())?;
    if matches!(
        subject_type,
        GovernanceSubjectType::Registrar | GovernanceSubjectType::Discovery
    ) && request.payload.authorized_domains.is_empty()
    {
        return Err("infrastructure_authorized_domains_required".to_owned());
    }
    if subject_type == GovernanceSubjectType::VcIssuer
        && !request.payload.authorized_domains.is_empty()
    {
        return Err("vc_issuer_authorized_domains_forbidden".to_owned());
    }
    if let Some(claimed_hash) =
        did_document_chain_governance_stable_hash(&request.payload.did_document)
    {
        if claimed_hash != did_document_stable_hash {
            return Err("did_document_stable_hash_claim_mismatch".to_owned());
        }
    }
    Ok(())
}

fn normalize_hash_claim(value: &str) -> std::result::Result<String, String> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err("missing_did_document_stable_hash".to_owned());
    }
    let normalized = if trimmed.starts_with("sha256:") {
        trimmed.to_owned()
    } else {
        format!("sha256:{trimmed}")
    };
    let hex = normalized.trim_start_matches("sha256:");
    if hex.len() != 64 || !hex.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err("invalid_did_document_stable_hash".to_owned());
    }
    Ok(normalized.to_ascii_lowercase())
}

fn normalize_chain_metadata_hash(value: &str) -> String {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.starts_with("sha256:") {
        trimmed.to_ascii_lowercase()
    } else {
        format!("sha256:{}", trimmed.to_ascii_lowercase())
    }
}

fn validate_infrastructure_did_prefix(
    subject_type: GovernanceSubjectType,
    did: &str,
) -> std::result::Result<(), String> {
    let expected_prefix = match subject_type {
        GovernanceSubjectType::Registrar => "did:oan:INRG:",
        GovernanceSubjectType::Discovery => "did:oan:INDS:",
        GovernanceSubjectType::VcIssuer => "did:oan:INVC:",
    };
    if did.starts_with(expected_prefix) {
        Ok(())
    } else {
        Err("infrastructure_did_prefix_mismatch".to_owned())
    }
}

fn validate_infrastructure_did_document_profile(
    payload: &InfrastructureAuthorizationVcIssuePayload,
    subject_type: GovernanceSubjectType,
) -> std::result::Result<(), String> {
    let did_document = &payload.did_document;
    if did_document.verification_method.is_empty() {
        return Err("did_document_verification_method_required".to_owned());
    }
    let key_id = format!("{}#key-1", payload.subject_did);
    if !did_document
        .verification_method
        .iter()
        .any(|method| method.id == key_id && method.controller == payload.subject_did)
    {
        return Err("did_document_primary_key_required".to_owned());
    }
    if !did_document.authentication.iter().any(|id| id == &key_id) {
        return Err("did_document_authentication_key_required".to_owned());
    }
    if !did_document.assertion_method.iter().any(|id| id == &key_id) {
        return Err("did_document_assertion_key_required".to_owned());
    }
    let metadata = did_document
        .oan_metadata
        .as_ref()
        .ok_or_else(|| "did_document_oan_metadata_required".to_owned())?;
    if metadata.subject_type != ResourceType::InfrastructureNode
        || metadata.resource_type != ResourceType::InfrastructureNode
    {
        return Err("did_document_infrastructure_metadata_required".to_owned());
    }
    let expected_node_role = match subject_type {
        GovernanceSubjectType::Registrar => "registrar",
        GovernanceSubjectType::Discovery => "discovery",
        GovernanceSubjectType::VcIssuer => "vc_issuer",
    };
    if metadata.node_role.as_deref() != Some(expected_node_role) {
        return Err("did_document_node_role_mismatch".to_owned());
    }
    let expected_identity_type = match subject_type {
        GovernanceSubjectType::Registrar => "registrar-node",
        GovernanceSubjectType::Discovery => "discovery-node",
        GovernanceSubjectType::VcIssuer => "vc-issuer-node",
    };
    if let Some(identity_type) = metadata.identity_type.as_deref() {
        if identity_type != expected_identity_type {
            return Err("did_document_identity_type_mismatch".to_owned());
        }
    }
    let expected_service_type = match subject_type {
        GovernanceSubjectType::Registrar => "OANRegistrarService",
        GovernanceSubjectType::Discovery => "OANDiscoveryService",
        GovernanceSubjectType::VcIssuer => "OANVcIssuerService",
    };
    let service = did_document
        .service
        .iter()
        .find(|service| service.service_type == expected_service_type)
        .ok_or_else(|| "did_document_service_type_mismatch".to_owned())?;
    if let Some(endpoint) = payload.endpoint.as_deref() {
        if service.service_endpoint != endpoint {
            return Err("did_document_endpoint_mismatch".to_owned());
        }
    }
    if matches!(
        subject_type,
        GovernanceSubjectType::Registrar | GovernanceSubjectType::Discovery
    ) {
        let metadata_domains = metadata.authorized_domains.clone();
        let mut request_domains = payload.authorized_domains.clone();
        let mut metadata_domains_sorted = metadata_domains;
        request_domains.sort();
        metadata_domains_sorted.sort();
        if request_domains != metadata_domains_sorted {
            return Err("did_document_authorized_domains_mismatch".to_owned());
        }
    }
    Ok(())
}

fn did_document_hash_for_root(state: &AppState, did_document: &DidDocument) -> Result<String> {
    hash_json_with_suite(state.signing_key.crypto_suite(), did_document)
        .map(|hash| format_hash("sha256", &hash))
        .map_err(Into::into)
}

#[cfg(test)]
fn stable_did_document_hash_for_root(
    state: &AppState,
    did_document: &DidDocument,
) -> Result<String> {
    let mut value = serde_json::to_value(did_document)?;
    if let Some(metadata) = value
        .get_mut("oanMetadata")
        .and_then(serde_json::Value::as_object_mut)
    {
        metadata.remove("chainGovernance");
    }
    hash_json_with_suite(state.signing_key.crypto_suite(), &value)
        .map(|hash| format_hash("sha256", &hash))
        .map_err(Into::into)
}

fn did_document_chain_governance_stable_hash(did_document: &DidDocument) -> Option<String> {
    did_document
        .oan_metadata
        .as_ref()
        .and_then(|metadata| metadata.extra.get("chainGovernance"))
        .and_then(|value| value.get("didDocumentStableHash"))
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
}

fn build_infrastructure_authorization_proof(
    unsigned: &Value,
    verification_method: String,
    signing_key: &SigningKey,
) -> Result<InfrastructureAuthorizationProof> {
    let suite = signing_key.crypto_suite();
    let proof_type = match suite {
        CryptoSuite::Ed25519Sha256 | CryptoSuite::Ed25519Sha256Legacy => "OANEd25519Signature2026",
        CryptoSuite::Sm2Sm3 => "OANSM2Signature2026",
    };
    let cryptosuite = match suite {
        CryptoSuite::Ed25519Sha256 | CryptoSuite::Ed25519Sha256Legacy => "ed25519-jcs-2026",
        CryptoSuite::Sm2Sm3 => "sm2-sm3-jcs-2026",
    };
    let input = signature_input(suite, unsigned)?;
    Ok(InfrastructureAuthorizationProof {
        proof_type: proof_type.to_owned(),
        cryptosuite: cryptosuite.to_owned(),
        proof_purpose: "assertionMethod".to_owned(),
        verification_method,
        created: Utc::now(),
        canonicalization_algorithm: "JCS-RFC8785-compatible-key-sorted-json".to_owned(),
        proof_value: sign_bytes(signing_key, &input)?,
    })
}

fn latest_governance_action_label(status: Option<&str>) -> String {
    match status {
        Some("active") => "active".to_owned(),
        Some(value) if !value.is_empty() => value.to_owned(),
        _ => "active".to_owned(),
    }
}

fn build_infrastructure_authorization_credential(
    state: &AppState,
    subject_type: GovernanceSubjectType,
    payload: &InfrastructureAuthorizationVcIssuePayload,
    did_document_stable_hash: &str,
    governance: &GovernanceDecision,
    governance_subject: &GovernanceSubjectRecord,
    indexer_status: &TrustIndexerStatus,
) -> Result<InfrastructureAuthorizationCredential> {
    let issuance_date = Utc::now();
    let mut credential_status = json!({
        "type": "OANChainGovernanceBackedAuthorizationStatus2026",
        "status": "active",
        "chainGovernanceNoticeFile": "chain-governance-notice.json",
        "expectedGovernanceState": "active",
        "latestAction": latest_governance_action_label(governance.status.as_deref()),
        "didDocumentStableHash": did_document_stable_hash
    });
    if let Some(package_id) = &indexer_status.package_id {
        credential_status["packageId"] = json!(package_id);
    }
    if let Some(bulletin_object_id) = &indexer_status.bulletin_object_id {
        credential_status["bulletinObjectId"] = json!(bulletin_object_id);
    }
    if governance_subject.last_sequence > 0 {
        credential_status["eventSequence"] = json!(governance_subject.last_sequence);
    }
    if !governance_subject.last_event_digest.is_empty() {
        credential_status["eventDigest"] = json!(governance_subject.last_event_digest);
    }
    if !governance_subject.policy_hash.is_empty() {
        credential_status["policyHash"] = json!(governance_subject.policy_hash);
    }
    if governance_subject.effective_from_ms > 0 {
        credential_status["effectiveFromMs"] = json!(governance_subject.effective_from_ms);
    }
    if governance_subject.expires_at_ms > 0 {
        credential_status["expiresAtMs"] = json!(governance_subject.expires_at_ms);
    }

    let mut unsigned = json!({
        "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://openagenet.org/credentials/v1"
        ],
        "id": format!(
            "urn:oan:root-authorization:{}:{}",
            subject_type.label(),
            did_to_file_name(&payload.subject_did).trim_end_matches(".json")
        ),
        "type": [
            "VerifiableCredential",
            "OANInfrastructureAuthorizationCredential"
        ],
        "issuer": state.root_did,
        "issuanceDate": issuance_date,
        "credentialSubject": {
            "id": payload.subject_did,
            "role": subject_type.label(),
            "subjectType": subject_type.code(),
            "endpoint": payload.endpoint,
            "authorizedDomains": payload.authorized_domains,
            "didDocumentFile": "did-document.json"
        },
        "credentialStatus": credential_status
    });
    let proof = build_infrastructure_authorization_proof(
        &unsigned,
        format!("{}#key-1", state.root_did),
        &state.signing_key,
    )?;
    unsigned["proof"] = serde_json::to_value(proof)?;
    serde_json::from_value(unsigned).map_err(Into::into)
}

async fn api_resource_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    if state.sqlite.is_some() || state.postgres.is_some() {
        let package = repository::latest_resource_detail_impl(&state, &did)
            .await
            .map_err(ApiError::internal)?;
        return Ok(Json(json!({ "resourceDid": did, "package": package })));
    }
    let package: Option<ResourcePackage> = state
        .data
        .read(format!("resource-packages/{}", did_to_file_name(&did)))
        .ok();
    Ok(Json(json!({ "resourceDid": did, "package": package })))
}

fn verify_resource_request(
    state: &AppState,
    request: &ResourceVerifyAndPublishRequest,
) -> std::result::Result<(), String> {
    let registrar_document = load_authorized_registrar_document(state, &request.registrar_did)
        .map_err(|_| "registrar_not_authorized".to_owned())?;
    let policy = trusted_upstream_policy(state, PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH);
    verify_signed_request_envelope(
        &request.upstream_auth,
        &request.submission,
        &request.registrar_did,
        &registrar_document,
        &policy,
        Utc::now(),
    )
    .map_err(|err| err.to_string())?;
    request.submission.validate_shape()?;
    Ok(())
}

fn build_resource_metadata(
    submission: &oan_protocol::ResourceRegistrationSubmission,
) -> Result<ResourceMetadata> {
    let oan_metadata = submission
        .did_document
        .oan_metadata
        .as_ref()
        .ok_or_else(|| anyhow!("missing_oan_metadata"))?;
    let description = oan_metadata.resource_description.as_ref();
    let metadata_value = &submission.metadata;
    let name = metadata_value["name"]
        .as_str()
        .map(ToOwned::to_owned)
        .or_else(|| description.and_then(|value| value.name.clone()))
        .unwrap_or_else(|| submission.resource_did.clone());
    let description_text = metadata_value["description"]
        .as_str()
        .map(ToOwned::to_owned)
        .or_else(|| description.and_then(|value| value.description.clone()))
        .unwrap_or_default();
    let capability_tags = if let Some(tags) = metadata_value["capabilityTags"].as_array() {
        tags.iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect::<Vec<_>>()
    } else if !oan_metadata.capability_tags.is_empty() {
        oan_metadata.capability_tags.clone()
    } else {
        description
            .map(|value| value.capability_tags.clone())
            .unwrap_or_default()
    };
    let authorized_domains = if let Some(domains) = metadata_value["authorizedDomains"].as_array() {
        let domains = domains
            .iter()
            .filter_map(|value| value.as_str().map(ToOwned::to_owned))
            .collect::<Vec<_>>();
        if domains != oan_metadata.authorized_domains {
            return Err(anyhow!("authorized_domains_mismatch"));
        }
        domains
    } else {
        oan_metadata.authorized_domains.clone()
    };
    let lifecycle_state = metadata_value["lifecycleState"]
        .as_str()
        .unwrap_or_else(|| oan_metadata.lifecycle_state.as_deref().unwrap_or("active"))
        .to_owned();
    let updated_at = submission
        .subject_control_proof
        .verified_at
        .unwrap_or(submission.subject_control_proof.challenge.issued_at);
    Ok(ResourceMetadata {
        resource_did: submission.resource_did.clone(),
        resource_type: submission.resource_type.clone(),
        subject_type: oan_metadata.subject_type.clone(),
        publisher_did: oan_metadata.publisher_did.clone(),
        subject_did: Some(submission.resource_did.clone()),
        name,
        description: description_text,
        capability_tags,
        authorized_domains,
        protocol_bindings: oan_metadata
            .protocol_bindings
            .iter()
            .map(serde_json::to_value)
            .collect::<std::result::Result<Vec<_>, _>>()?,
        services: submission.did_document.service.clone(),
        lifecycle_state,
        package_version: submission.package_version.clone(),
        package_hash: submission.package_hash.clone(),
        metadata_hash: submission.metadata_hash.clone(),
        hash_algorithm: submission.hash_algorithm.clone(),
        updated_at,
    })
}

fn format_hash(algorithm: &str, hash: &str) -> String {
    if hash.starts_with(&format!("{algorithm}:")) {
        hash.to_owned()
    } else {
        format!("{algorithm}:{hash}")
    }
}

fn archive_resource_verified(state: &AppState, package: &ResourcePackage) -> Result<()> {
    if state.sqlite.is_some() || state.postgres.is_some() {
        return Ok(());
    }
    let name = did_to_file_name(&package.resource_did);
    let archive_root = format!("archive/{}", name.trim_end_matches(".json"));
    let prefix = format!(
        "resources/{}/{}",
        name.trim_end_matches(".json"),
        package.package_version
    );
    state
        .data
        .write(format!("{prefix}/did-document.json"), &package.did_document)?;
    state
        .data
        .write(format!("{prefix}/metadata.json"), &package.metadata)?;
    state
        .data
        .write(format!("{prefix}/resource-package.json"), package)?;
    state
        .data
        .write(format!("resource-packages/{name}"), package)?;
    let mut index = state
        .data
        .read::<BTreeMap<String, ResourcePackage>>("resource-packages/index.json")
        .unwrap_or_default();
    index.insert(package.resource_did.clone(), package.clone());
    state.data.write("resource-packages/index.json", &index)?;

    let mut version_index = state
        .data
        .read::<Vec<Value>>(format!("{archive_root}/index.json"))
        .unwrap_or_default();
    version_index.retain(|item| {
        item.get("packageVersion").and_then(Value::as_str) != Some(package.package_version.as_str())
    });
    version_index.push(json!({
        "packageVersion": package.package_version,
        "didDocumentHash": package.did_document_hash,
        "metadataHash": package.metadata_hash,
        "packageHash": package.package_hash,
        "acceptedAt": package.created_at,
    }));
    state
        .data
        .write(format!("{archive_root}/index.json"), &version_index)?;
    Ok(())
}

async fn persist_resource_acceptance(state: &AppState, package: &ResourcePackage) -> Result<()> {
    repository::persist_resource_acceptance_impl(state, package).await?;
    invalidate_status_counts_cache(state);
    signal_worker_event(state, true);
    Ok(())
}

async fn enqueue_resource_cdn(state: &AppState, package: &ResourcePackage) -> Result<()> {
    let mut queue: Vec<ResourcePackage> = state
        .data
        .read("queues/cdn-publish.json")
        .unwrap_or_default();
    queue.retain(|item| item.resource_did != package.resource_did);
    queue.push(package.clone());
    state.data.write("queues/cdn-publish.json", &queue)?;
    Ok(())
}

#[cfg(test)]
fn cdn_publication_job_key(package: &ResourcePackage) -> String {
    format!("{}:{}", package.resource_did, package.package_version)
}

#[cfg(test)]
async fn build_cdn_publish_requested_event(
    state: &AppState,
    package: &ResourcePackage,
) -> Result<CdnPublishRequestedEvent> {
    let job_key = cdn_publication_job_key(package);
    let cursors = publication_cursors_for_jobs(state, std::slice::from_ref(&job_key)).await?;
    let publication_cursor = cursors
        .get(&job_key)
        .copied()
        .ok_or_else(|| anyhow!("publication_cursor_missing_for_job: {job_key}"))?;
    Ok(CdnPublishRequestedEvent::new(
        CdnPublishRequestedEventInput {
            job_key,
            resource_did: package.resource_did.clone(),
            package_version: package.package_version.clone(),
            publication_cursor,
            root_did: state.root_did.clone(),
            package_hash: package.package_hash.clone(),
            did_document_hash: package.did_document_hash.clone(),
            metadata_hash: package.metadata_hash.clone(),
            created_at: Utc::now(),
        },
    ))
}

#[cfg(test)]
async fn publish_cdn_requested_event_for_package(
    state: &AppState,
    package: &ResourcePackage,
) -> Result<()> {
    let event = build_cdn_publish_requested_event(state, package).await?;
    match state.event_publisher.publish_cdn_requested(&event).await {
        Ok(true) => record_event_publish_success(state),
        Ok(false) => {}
        Err(err) => {
            record_event_publish_failure(state, &err.to_string());
            match state.config.events.failure_mode.as_str() {
                "closed" => return Err(err),
                "fallback" => {
                    eprintln!("cdn publish event failed; fallback queue retained: {err}");
                }
                other => return Err(anyhow!("unsupported_event_failure_mode: {other}")),
            }
        }
    }
    Ok(())
}

async fn publish_cdn_requested_outbox_event(
    state: &AppState,
    event: &CdnPublishRequestedEvent,
) -> Result<()> {
    match state.event_publisher.publish_cdn_requested(event).await {
        Ok(true) => record_event_publish_success(state),
        Ok(false) => {}
        Err(err) => {
            record_event_publish_failure(state, &err.to_string());
            return Err(err);
        }
    }
    Ok(())
}

fn read_bulletin(state: &AppState) -> Result<Bulletin> {
    if state.sqlite.is_some() || state.postgres.is_some() {
        return read_bulletin_from_store(state);
    }
    let store = JsonStore::new(".");
    if state.config.paths.bulletin_file.exists() {
        store
            .read(&state.config.paths.bulletin_file)
            .map_err(Into::into)
    } else {
        Ok(Bulletin {
            version: "0.1.0".to_owned(),
            root_did: state.root_did.clone(),
            created_at: Utc::now(),
            events: vec![],
        })
    }
}

fn read_bulletin_from_store(state: &AppState) -> Result<Bulletin> {
    repository::read_bulletin_from_store_impl(state)
}

fn latest_bulletin_event(state: &AppState) -> Result<Option<BulletinEvent>> {
    repository::latest_bulletin_event_impl(state)
}

fn persist_bulletin_event(state: &AppState, event: &BulletinEvent) -> Result<()> {
    repository::persist_bulletin_event_impl(state, event)
}

fn load_authorization_state(path: &Path) -> Result<AuthorizationState> {
    let store = JsonStore::new(".");
    if path.exists() {
        store.read(path).map_err(Into::into)
    } else {
        Ok(AuthorizationState::default())
    }
}

fn current_authorization_state(state: &AppState) -> AuthorizationState {
    state
        .authorization_state
        .lock()
        .map(|value| value.clone())
        .unwrap_or_default()
}

fn persist_authorization_state(
    state: &AppState,
    authorization_state: AuthorizationState,
) -> Result<()> {
    JsonStore::new(".").write(
        &state.config.paths.authorization_state_file,
        &authorization_state,
    )?;
    if let Ok(mut current) = state.authorization_state.lock() {
        *current = authorization_state;
    }
    Ok(())
}

fn update_authorization_state(
    state: &AppState,
    did: &str,
    entry: NodeAuthorizationState,
    role: &str,
    discovery: Option<DiscoveryAuthorizationState>,
) -> Result<()> {
    let mut authorization_state = current_authorization_state(state);
    match role {
        "registrar" | "Registrar" | "Registrar Node" => {
            authorization_state.registrars.insert(did.to_owned(), entry);
        }
        "discovery" | "Discovery" | "Discovery Node" => {
            if let Some(entry) = discovery {
                authorization_state
                    .discovery_nodes
                    .insert(did.to_owned(), entry);
            }
        }
        "vc-issuer" | "VC Issuer" => {
            authorization_state.vc_issuers.insert(did.to_owned(), entry);
        }
        _ => {
            authorization_state.registrars.insert(did.to_owned(), entry);
        }
    }
    persist_authorization_state(state, authorization_state)?;
    Ok(())
}

fn update_discovery_authorization_state(
    state: &AppState,
    did: &str,
    entry: DiscoveryAuthorizationState,
) -> Result<()> {
    let entry_status = entry.status.clone();
    let mut authorization_state = current_authorization_state(state);
    authorization_state
        .discovery_nodes
        .insert(did.to_owned(), entry);
    persist_authorization_state(state, authorization_state)?;
    if state.sqlite.is_some() || state.postgres.is_some() {
        sync_discovery_target_state(state, did, &entry_status)?;
    }
    Ok(())
}

fn revoke_authorization_state(state: &AppState, did: &str) -> Result<()> {
    let mut authorization_state = current_authorization_state(state);
    if let Some(entry) = authorization_state.registrars.get_mut(did) {
        entry.status = "revoked".to_owned();
        entry.updated_at = Utc::now();
    }
    if let Some(entry) = authorization_state.discovery_nodes.get_mut(did) {
        entry.status = "revoked".to_owned();
        entry.updated_at = Utc::now();
    }
    if let Some(entry) = authorization_state.vc_issuers.get_mut(did) {
        entry.status = "revoked".to_owned();
        entry.updated_at = Utc::now();
    }
    persist_authorization_state(state, authorization_state)?;
    if state.sqlite.is_some() || state.postgres.is_some() {
        sync_discovery_target_state(state, did, "revoked")?;
    }
    Ok(())
}

fn sync_discovery_target_state(state: &AppState, did: &str, auth_status: &str) -> Result<()> {
    repository::sync_discovery_target_state_impl(state, did, auth_status)
}

fn write_bulletin(state: &AppState, bulletin: &Bulletin) -> Result<()> {
    JsonStore::new(".").write(&state.config.paths.bulletin_file, bulletin)?;
    Ok(())
}

fn append_event(
    state: &AppState,
    event_type: BulletinEventType,
    subject_did: &str,
    payload: Value,
) -> Result<BulletinEvent> {
    let latest = latest_bulletin_event(state)?;
    let previous_hash = latest.as_ref().map(|event| event.event_hash.clone());
    let next_sequence = latest
        .as_ref()
        .map(|event| event.core.sequence + 1)
        .unwrap_or(1);
    let event = BulletinEventCore {
        sequence: next_sequence,
        previous_hash,
        event_type,
        subject_did: subject_did.to_owned(),
        actor_did: state.root_did.clone(),
        payload,
        created_at: Utc::now(),
    }
    .sign(&state.signing_key)?;
    if state.sqlite.is_some() || state.postgres.is_some() {
        persist_bulletin_event(state, &event)?;
    } else {
        let mut bulletin = read_bulletin(state)?;
        bulletin.events.push(event.clone());
        write_bulletin(state, &bulletin)?;
    }
    Ok(event)
}

fn read_latest_versions(state: &AppState) -> Result<BTreeMap<String, Value>> {
    repository::read_latest_versions_impl(state)
}

async fn read_cdn_queue(state: &AppState) -> Result<Vec<ResourcePackage>> {
    repository::read_cdn_queue_impl(state).await
}

async fn read_ready_cdn_queue(state: &AppState) -> Result<Vec<ResourcePackage>> {
    repository::read_ready_cdn_queue_impl(state).await
}

async fn read_discovery_queue(state: &AppState) -> Result<Vec<Value>> {
    if state.sqlite.is_some() || state.postgres.is_some() {
        let targets = read_discovery_target_states(state).await?;
        return Ok(targets
            .into_iter()
            .filter(|item| item.pending_cursor > item.delivered_cursor)
            .map(|item| {
                json!({
                    "discoveryDid": item.discovery_did,
                    "pendingCursor": item.pending_cursor,
                    "deliveredCursor": item.delivered_cursor,
                    "status": item.status,
                    "attemptCount": item.attempt_count,
                    "nextAttemptAt": item.next_attempt_at,
                    "lastError": item.last_error,
                    "updatedAt": item.updated_at
                })
            })
            .collect());
    }
    Ok(state
        .data
        .read("queues/discovery-notify.json")
        .unwrap_or_default())
}

fn is_ready_discovery_target(item: &DiscoveryNotifyTargetState) -> bool {
    if item.status != "active" || item.pending_cursor <= item.delivered_cursor {
        return false;
    }
    let next_attempt_ready = chrono::DateTime::parse_from_rfc3339(&item.next_attempt_at)
        .map(|next_attempt_at| next_attempt_at.with_timezone(&Utc) <= Utc::now())
        .unwrap_or(true);
    if !next_attempt_ready {
        return false;
    }
    match &item.lease_expires_at {
        Some(lease_expires_at) => chrono::DateTime::parse_from_rfc3339(lease_expires_at)
            .map(|lease_expires_at| lease_expires_at.with_timezone(&Utc) <= Utc::now())
            .unwrap_or(true),
        None => true,
    }
}

async fn read_ready_discovery_queue(state: &AppState) -> Result<Vec<Value>> {
    if state.sqlite.is_some() || state.postgres.is_some() {
        let targets = read_discovery_target_states(state).await?;
        return Ok(targets
            .into_iter()
            .filter(is_ready_discovery_target)
            .map(|item| {
                json!({
                    "discoveryDid": item.discovery_did,
                    "pendingCursor": item.pending_cursor,
                    "deliveredCursor": item.delivered_cursor,
                    "status": item.status,
                    "attemptCount": item.attempt_count,
                    "nextAttemptAt": item.next_attempt_at,
                    "lastError": item.last_error,
                    "updatedAt": item.updated_at
                })
            })
            .collect());
    }
    read_discovery_queue(state).await
}

async fn export_root_debug_snapshot(state: &AppState) -> Result<()> {
    if state.sqlite.is_none() && state.postgres.is_none() {
        return Ok(());
    }
    let bulletin = read_bulletin_from_store(state)?;
    write_bulletin(state, &bulletin)?;
    let latest = read_latest_versions(state)?;
    state
        .data
        .write("indexes/latest-did-document-versions.json", &latest)?;
    let cdn_queue = read_cdn_queue(state).await?;
    state.data.write("queues/cdn-publish.json", &cdn_queue)?;
    let discovery_queue = read_discovery_queue(state).await?;
    state
        .data
        .write("queues/discovery-notify.json", &discovery_queue)?;
    Ok(())
}

async fn read_discovery_target_states(state: &AppState) -> Result<Vec<DiscoveryNotifyTargetState>> {
    repository::read_discovery_target_states_impl(state).await
}

async fn claim_discovery_targets(
    state: &AppState,
    worker_id: &str,
    limit: usize,
    lease_seconds: i64,
) -> Result<Vec<DiscoveryNotifyTargetLease>> {
    repository::claim_discovery_targets_impl(state, worker_id, limit, lease_seconds).await
}

async fn oldest_ready_discovery_target_age_ms(state: &AppState) -> Result<Option<u128>> {
    if state.sqlite.is_some() || state.postgres.is_some() {
        return repository::oldest_ready_discovery_target_age_ms_impl(state).await;
    }
    let queue = read_ready_discovery_queue(state).await?;
    Ok(Some(discovery_queue_oldest_age_ms(&queue)))
}

async fn mark_discovery_target_notified(
    state: &AppState,
    discovery_did: &str,
    delivered_cursor: i64,
) -> Result<()> {
    repository::mark_discovery_target_notified_impl(state, discovery_did, delivered_cursor).await?;
    invalidate_status_counts_cache(state);
    Ok(())
}

async fn mark_discovery_target_retry(
    state: &AppState,
    discovery_did: &str,
    error: &str,
) -> Result<()> {
    repository::mark_discovery_target_retry_impl(state, discovery_did, error).await?;
    invalidate_status_counts_cache(state);
    Ok(())
}

#[cfg(test)]
async fn advance_discovery_target_watermarks_batch(
    state: &AppState,
    packages: &[(ResourcePackage, i64)],
) -> Result<usize> {
    let updated =
        repository::advance_discovery_target_watermarks_batch_impl(state, packages).await?;
    if updated > 0 {
        invalidate_status_counts_cache(state);
    }
    Ok(updated)
}

async fn resource_packages_for_jobs(
    state: &AppState,
    job_keys: &[String],
) -> Result<BTreeMap<String, (ResourcePackage, i64)>> {
    repository::resource_packages_for_jobs_impl(state, job_keys).await
}

async fn claim_cdn_outbox_events(
    state: &AppState,
    worker_id: &str,
    limit: i64,
    lease_seconds: i64,
) -> Result<Vec<(String, CdnPublishRequestedEvent)>> {
    repository::claim_cdn_outbox_events_impl(state, worker_id, limit, lease_seconds).await
}

async fn oldest_ready_cdn_outbox_age_ms(state: &AppState) -> Result<Option<u128>> {
    if state.sqlite.is_some() || state.postgres.is_some() {
        return repository::oldest_ready_cdn_outbox_age_ms_impl(state).await;
    }
    let queue = read_ready_cdn_queue(state).await?;
    Ok(Some(resource_package_oldest_age_ms(&queue)))
}

async fn mark_cdn_outbox_events_published_batch(
    state: &AppState,
    job_keys: &[String],
) -> Result<u64> {
    let updated = repository::mark_cdn_outbox_events_published_batch_impl(state, job_keys).await?;
    if updated > 0 {
        invalidate_status_counts_cache(state);
    }
    Ok(updated)
}

async fn mark_cdn_outbox_events_retry_batch(
    state: &AppState,
    jobs: &[(String, String)],
) -> Result<u64> {
    let updated = repository::mark_cdn_outbox_events_retry_batch_impl(state, jobs).await?;
    if updated > 0 {
        invalidate_status_counts_cache(state);
    }
    Ok(updated)
}

#[cfg(test)]
async fn publication_cursors_for_jobs(
    state: &AppState,
    job_keys: &[String],
) -> Result<BTreeMap<String, i64>> {
    repository::publication_cursors_for_jobs_impl(state, job_keys).await
}

async fn authorized_discovery_summary_items(
    state: &AppState,
    discovery_did: &str,
    delivered_cursor: i64,
    target_cursor: i64,
) -> Result<Vec<DiscoveryNotificationItem>> {
    repository::authorized_discovery_summary_items_impl(
        state,
        discovery_did,
        delivered_cursor,
        target_cursor,
    )
    .await
}

async fn run_cdn_outbox_relay_cycle(state: &AppState) -> Result<Value> {
    let started = std::time::Instant::now();
    if let Some(age_ms) = oldest_ready_cdn_outbox_age_ms(state).await? {
        record_worker_oldest_pending_age(state, true, age_ms);
    }
    let (ready_depth_before, active_depth_before) = cdn_queue_depths(state).await?;
    let batch_size = state
        .config
        .security
        .workers
        .cdn_batch_size
        .max(1)
        .saturating_mul(4)
        .min(5_000);
    let worker_id = request_id("root-cdn-outbox-relay");
    let claim_started = std::time::Instant::now();
    let claimed = claim_cdn_outbox_events(
        state,
        &worker_id,
        batch_size as i64,
        state.config.security.workers.lease_seconds,
    )
    .await?;
    let claimed = order_cdn_outbox_claims_by_publication_cursor(claimed);
    let claim_elapsed_ms = claim_started.elapsed().as_millis();
    let attempted_count = claimed.len();
    let concurrency = state.config.security.workers.cdn_concurrency.max(1);
    let mut published = Vec::new();
    let mut failed = Vec::new();
    let mut in_flight = JoinSet::new();
    let mut claimed_iter = claimed.into_iter();
    let publish_started = std::time::Instant::now();
    loop {
        while in_flight.len() < concurrency {
            let Some((job_key, event)) = claimed_iter.next() else {
                break;
            };
            let state = state.clone();
            in_flight.spawn(async move {
                let result = publish_cdn_requested_outbox_event(&state, &event).await;
                (job_key, result)
            });
        }
        if in_flight.is_empty() {
            break;
        }
        let Some(joined) = in_flight.join_next().await else {
            break;
        };
        let (job_key, result) =
            joined.map_err(|err| anyhow!("cdn_outbox_publish_task_failed:{err}"))?;
        match result {
            Ok(()) => published.push(job_key),
            Err(err) => failed.push(json!({
                "jobKey": job_key,
                "error": err.to_string(),
                "mode": state.config.events.failure_mode
            })),
        }
    }
    let failed_jobs = failed
        .iter()
        .filter_map(|item| {
            Some((
                item.get("jobKey")?.as_str()?.to_owned(),
                item.get("error")?.as_str()?.to_owned(),
            ))
        })
        .collect::<Vec<_>>();
    let publish_elapsed_ms = publish_started.elapsed().as_millis();
    let mark_published_started = std::time::Instant::now();
    let marked_published_count = mark_cdn_outbox_events_published_batch(state, &published).await?;
    let mark_published_elapsed_ms = mark_published_started.elapsed().as_millis();
    let mark_retry_started = std::time::Instant::now();
    let marked_retry_count = mark_cdn_outbox_events_retry_batch(state, &failed_jobs).await?;
    let mark_retry_elapsed_ms = mark_retry_started.elapsed().as_millis();
    let elapsed_ms = started.elapsed().as_millis();
    let (ready_depth_after, active_depth_after) = cdn_queue_depths(state).await?;
    record_cdn_worker_runtime(
        state,
        elapsed_ms,
        published.len(),
        failed.len(),
        batch_size,
        concurrency,
        CdnWorkerStageMetrics {
            claim_elapsed_ms,
            publish_elapsed_ms,
            mark_published_elapsed_ms,
            mark_retry_elapsed_ms,
        },
    );
    Ok(json!({
        "enabled": true,
        "attemptedCount": attempted_count,
        "publishedCount": published.len(),
        "failedCount": failed.len(),
        "concurrency": concurrency,
        "effectiveBatchSize": batch_size,
        "claimElapsedMs": claim_elapsed_ms,
        "publishElapsedMs": publish_elapsed_ms,
        "markPublishedElapsedMs": mark_published_elapsed_ms,
        "markRetryElapsedMs": mark_retry_elapsed_ms,
        "elapsedMs": elapsed_ms,
        "drainRatePerSec": drain_rate_per_sec(published.len(), elapsed_ms),
        "markedPublishedCount": marked_published_count,
        "markedRetryCount": marked_retry_count,
        "readyQueueDepthBefore": ready_depth_before,
        "activeQueueDepthBefore": active_depth_before,
        "readyQueueDepthAfter": ready_depth_after,
        "activeQueueDepthAfter": active_depth_after,
        "published": published,
        "failed": failed
    }))
}

fn order_cdn_outbox_claims_by_publication_cursor(
    mut claimed: Vec<(String, CdnPublishRequestedEvent)>,
) -> Vec<(String, CdnPublishRequestedEvent)> {
    claimed.sort_by(|a, b| {
        a.1.publication_cursor
            .cmp(&b.1.publication_cursor)
            .then_with(|| a.0.cmp(&b.0))
    });
    claimed
}

fn discovery_sync_url(auth: &DiscoveryAuthorizationState) -> Result<String> {
    let did_document = auth
        .did_document_snapshot
        .as_ref()
        .ok_or_else(|| anyhow!("discovery_did_document_missing"))?;
    let endpoint = did_document
        .service
        .iter()
        .find(|service| {
            service
                .service_type
                .eq_ignore_ascii_case("AgentDiscoveryService")
                || service
                    .service_type
                    .eq_ignore_ascii_case("OANDiscoveryService")
        })
        .map(|service| service.service_endpoint.trim_end_matches('/').to_owned())
        .ok_or_else(|| anyhow!("discovery_service_endpoint_missing"))?;
    Ok(format!("{endpoint}/discovery/resources/sync-authorized"))
}

async fn run_discovery_notify_cycle(state: &AppState) -> Result<Value> {
    let started = std::time::Instant::now();
    if let Some(age_ms) = oldest_ready_discovery_target_age_ms(state).await? {
        record_worker_oldest_pending_age(state, false, age_ms);
    }
    let (ready_depth_before, pending_depth_before) = discovery_queue_depths(state).await?;
    let claim_started = std::time::Instant::now();
    let targets = claim_discovery_targets(
        state,
        "root-discovery-worker",
        effective_worker_batch_size(
            state.config.security.workers.discovery_batch_size,
            ready_depth_before,
            2,
        ),
        state.config.security.workers.lease_seconds,
    )
    .await?;
    let claim_elapsed_ms = claim_started.elapsed().as_millis();
    let claimed_count = targets.len();
    let claimed_cursor_lag: i64 = targets
        .iter()
        .map(|target| (target.target_cursor - target.delivered_cursor).max(0))
        .sum();
    let authorization_state = current_authorization_state(state);
    let mut notified = Vec::new();
    let mut failed = Vec::<Value>::new();
    let mut carry_forward_count = 0usize;
    let concurrency = state.config.security.workers.discovery_concurrency.max(1);
    let discovery_item_batch_size = effective_discovery_target_item_batch_size(
        state.config.security.workers.discovery_batch_size,
        claimed_count,
        concurrency,
        claimed_cursor_lag,
    );
    let mut in_flight = JoinSet::new();
    let mut target_iter = targets.into_iter();
    let notify_started = std::time::Instant::now();

    loop {
        while in_flight.len() < concurrency {
            let Some(lease) = target_iter.next() else {
                break;
            };
            let state = state.clone();
            let auth = authorization_state
                .discovery_nodes
                .get(&lease.discovery_did)
                .cloned();
            in_flight.spawn(async move {
                let Some(auth) = auth else {
                    mark_discovery_target_retry(
                        &state,
                        &lease.discovery_did,
                        "discovery_not_authorized",
                    )
                    .await?;
                    return Ok::<Value, anyhow::Error>(json!({
                        "kind": "failed",
                        "discoveryDid": lease.discovery_did,
                        "error": "discovery_not_authorized"
                    }));
                };
                if auth.status != "active" {
                    mark_discovery_target_retry(
                        &state,
                        &lease.discovery_did,
                        "discovery_not_active",
                    )
                    .await?;
                    return Ok(json!({
                        "kind": "failed",
                        "discoveryDid": lease.discovery_did,
                        "error": "discovery_not_active"
                    }));
                }
                if let Err(reason) = ensure_governance_active(
                    &state,
                    GovernanceSubjectType::Discovery,
                    &lease.discovery_did,
                )
                .await
                {
                    mark_discovery_target_retry(&state, &lease.discovery_did, &reason).await?;
                    mark_local_governance_inactive(
                        &state,
                        GovernanceSubjectType::Discovery,
                        &lease.discovery_did,
                        &reason,
                    )?;
                    return Ok(json!({
                        "kind": "failed",
                        "discoveryDid": lease.discovery_did,
                        "error": reason
                    }));
                }
                let sync_url = match discovery_sync_url(&auth) {
                    Ok(url) => url,
                    Err(err) => {
                        mark_discovery_target_retry(&state, &lease.discovery_did, &err.to_string())
                            .await?;
                        return Ok(json!({
                            "kind": "failed",
                            "discoveryDid": lease.discovery_did,
                            "error": err.to_string()
                        }));
                    }
                };
                let mut summary_items = authorized_discovery_summary_items(
                    &state,
                    &lease.discovery_did,
                    lease.delivered_cursor,
                    lease.target_cursor,
                )
                .await?;
                let max_items = discovery_item_batch_size.max(1);
                if summary_items.len() > max_items {
                    summary_items.truncate(max_items);
                }
                let batch_target_cursor = summary_items
                    .last()
                    .map(|item| item.publication_cursor)
                    .unwrap_or(lease.target_cursor)
                    .min(lease.target_cursor)
                    .max(lease.delivered_cursor);
                let response = state
                    .client
                    .post(&sync_url)
                    .json(&json!({
                        "maxPublications": max_items,
                        "cursorHint": batch_target_cursor,
                        "items": summary_items
                    }))
                    .send()
                    .await;
                match response {
                    Ok(response) if response.status().is_success() => {
                        let response_body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
                        let delivered_cursor = response_body
                            .get("toCursor")
                            .and_then(Value::as_i64);
                        let delivered_cursor = delivered_cursor
                            .unwrap_or(batch_target_cursor)
                            .min(batch_target_cursor)
                            .max(lease.delivered_cursor);
                        let rejected_count = response_body
                            .get("rejectedCount")
                            .and_then(Value::as_i64)
                            .unwrap_or(0);
                        let cursor_lag = response_body
                            .get("cursorLag")
                            .and_then(Value::as_i64)
                            .unwrap_or_else(|| batch_target_cursor.saturating_sub(delivered_cursor));
                        if delivered_cursor > lease.delivered_cursor {
                            mark_discovery_target_notified(
                                &state,
                                &lease.discovery_did,
                                delivered_cursor,
                            )
                            .await?;
                            if delivered_cursor < lease.target_cursor {
                                signal_worker_event(&state, false);
                            }
                        }
                        if rejected_count > 0 {
                            let error = format!(
                                "discovery_partial_sync:delivered={delivered_cursor}:target={}:rejected={rejected_count}:cursorLag={cursor_lag}",
                                batch_target_cursor
                            );
                            mark_discovery_target_retry(&state, &lease.discovery_did, &error)
                                .await?;
                            return Ok(json!({
                                "kind": "partial",
                                "rootDid": state.root_did,
                                "targetDiscoveryDid": lease.discovery_did,
                                "authorizedDomains": auth.authorized_domains,
                                "itemCount": summary_items.len(),
                                "deliveredCursor": delivered_cursor,
                                "targetCursor": batch_target_cursor,
                                "pendingTargetCursor": lease.target_cursor,
                                "previousDeliveredCursor": lease.delivered_cursor,
                                "syncUrl": sync_url,
                                "syncResult": response_body,
                                "error": error,
                                "createdAt": Utc::now()
                            }));
                        }
                        if cursor_lag > 0 || delivered_cursor < batch_target_cursor {
                            return Ok(json!({
                                "kind": "notified",
                                "rootDid": state.root_did,
                                "targetDiscoveryDid": lease.discovery_did,
                                "authorizedDomains": auth.authorized_domains,
                                "itemCount": summary_items.len(),
                                "deliveredCursor": delivered_cursor,
                                "targetCursor": batch_target_cursor,
                                "pendingTargetCursor": lease.target_cursor,
                                "remainingCursorLag": lease.target_cursor.saturating_sub(delivered_cursor),
                                "previousDeliveredCursor": lease.delivered_cursor,
                                "syncUrl": sync_url,
                                "syncResult": response_body,
                                "partialProgress": true,
                                "createdAt": Utc::now()
                            }));
                        }
                        Ok(json!({
                            "kind": "notified",
                            "rootDid": state.root_did,
                            "targetDiscoveryDid": lease.discovery_did,
                            "authorizedDomains": auth.authorized_domains,
                            "itemCount": summary_items.len(),
                            "deliveredCursor": delivered_cursor,
                            "targetCursor": batch_target_cursor,
                            "pendingTargetCursor": lease.target_cursor,
                            "remainingCursorLag": lease.target_cursor.saturating_sub(delivered_cursor),
                            "previousDeliveredCursor": lease.delivered_cursor,
                            "syncUrl": sync_url,
                            "syncResult": response_body,
                            "createdAt": Utc::now()
                        }))
                    }
                    Ok(response) => {
                        let status = response.status().as_u16();
                        let body = response.text().await.unwrap_or_default();
                        let error = if body.is_empty() {
                            format!("status:{status}")
                        } else {
                            format!("status:{status}:{body}")
                        };
                        mark_discovery_target_retry(&state, &lease.discovery_did, &error).await?;
                        Ok(json!({
                            "kind": "failed",
                            "discoveryDid": lease.discovery_did,
                            "syncUrl": sync_url,
                            "status": status,
                            "error": error
                        }))
                    }
                    Err(err) => {
                        let error = err.to_string();
                        mark_discovery_target_retry(&state, &lease.discovery_did, &error).await?;
                        Ok(json!({
                            "kind": "failed",
                            "discoveryDid": lease.discovery_did,
                            "syncUrl": sync_url,
                            "error": error
                        }))
                    }
                }
            });
        }

        let Some(joined) = in_flight.join_next().await else {
            break;
        };
        match joined {
            Ok(Ok(result)) if result["kind"] == "notified" => {
                if result["remainingCursorLag"].as_i64().unwrap_or(0) > 0 {
                    carry_forward_count = carry_forward_count.saturating_add(1);
                }
                notified.push(result)
            }
            Ok(Ok(result)) => failed.push(result),
            Ok(Err(err)) => failed.push(json!({ "error": err.to_string() })),
            Err(err) => failed.push(json!({ "error": err.to_string() })),
        }
    }
    let elapsed_ms = started.elapsed().as_millis();
    let notify_elapsed_ms = notify_started.elapsed().as_millis();
    let prepare_elapsed_ms = elapsed_ms.saturating_sub(claim_elapsed_ms + notify_elapsed_ms);
    let (ready_depth_after, pending_depth_after) = discovery_queue_depths(state).await?;
    record_discovery_worker_runtime(
        state,
        DiscoveryWorkerRuntimeSample {
            elapsed_ms,
            success_count: notified.len(),
            failed_count: failed.len(),
            batch_size: effective_worker_batch_size(
                state.config.security.workers.discovery_batch_size,
                ready_depth_before,
                2,
            ),
            concurrency,
            stage_metrics: DiscoveryWorkerStageMetrics {
                claim_elapsed_ms,
                prepare_elapsed_ms,
                notify_elapsed_ms,
            },
            outcome_metrics: DiscoveryWorkerOutcomeMetrics {
                claimed_target_count: claimed_count,
                carry_forward_count,
                ready_queue_depth_after: ready_depth_after,
                pending_queue_depth_after: pending_depth_after,
                claimed_cursor_lag,
                item_batch_size: discovery_item_batch_size,
            },
        },
    );
    let result = json!({
        "status": if failed.is_empty() { "ok" } else { "partial" },
        "notificationMode": "worker-watermark-trigger",
        "claimedTargetCount": claimed_count,
        "targetCount": notified.len() + failed.len(),
        "successCount": notified.len(),
        "notifiedCount": notified.len(),
        "failedCount": failed.len(),
        "carryForwardCount": carry_forward_count,
        "claimElapsedMs": claim_elapsed_ms,
        "prepareElapsedMs": prepare_elapsed_ms,
        "notifyElapsedMs": notify_elapsed_ms,
        "elapsedMs": elapsed_ms,
        "drainRatePerSec": drain_rate_per_sec(notified.len(), elapsed_ms),
        "claimedCursorLag": claimed_cursor_lag,
        "itemBatchSize": discovery_item_batch_size,
        "concurrency": concurrency,
        "readyQueueDepthBefore": ready_depth_before,
        "pendingQueueDepthBefore": pending_depth_before,
        "readyQueueDepthAfter": ready_depth_after,
        "pendingQueueDepthAfter": pending_depth_after,
        "targets": notified,
        "failed": failed
    });
    write_queue_cycle_history(
        state,
        "discovery-notify-cycle-history",
        json!({
            "cycleType": "discovery-notify",
            "processedAt": Utc::now(),
            "trigger": "worker-cycle",
            "targetCount": result["targetCount"],
            "notifiedCount": result["notifiedCount"],
            "failed": result["failed"]
        }),
    )
    .await?;
    Ok(result)
}

fn drain_rate_per_sec(success_count: usize, elapsed_ms: u128) -> f64 {
    if success_count == 0 {
        return 0.0;
    }
    let elapsed_seconds = (elapsed_ms as f64 / 1000.0).max(0.001);
    success_count as f64 / elapsed_seconds
}

fn value_u64(result: &Value, field: &str) -> u64 {
    result.get(field).and_then(Value::as_u64).unwrap_or(0)
}

fn cdn_cycle_made_progress(result: &Value) -> bool {
    value_u64(result, "publishedCount") > 0 || value_u64(result, "failedCount") > 0
}

fn cdn_cycle_should_continue_immediately(result: &Value) -> bool {
    let ready_after = value_u64(result, "readyQueueDepthAfter");
    let attempted = value_u64(result, "attemptedCount");
    let effective_batch_size = value_u64(result, "effectiveBatchSize");
    ready_after > 0 || (effective_batch_size > 0 && attempted >= effective_batch_size)
}

fn discovery_cycle_made_progress(result: &Value) -> bool {
    value_u64(result, "notifiedCount") > 0 || value_u64(result, "failedCount") > 0
}

fn discovery_cycle_should_continue_immediately(result: &Value) -> bool {
    let ready_after = value_u64(result, "readyQueueDepthAfter");
    let claimed_targets = value_u64(result, "claimedTargetCount");
    let effective_batch_size = value_u64(result, "effectiveBatchSize");
    let carry_forward_count = value_u64(result, "carryForwardCount");
    ready_after > 0
        || carry_forward_count > 0
        || (effective_batch_size > 0 && claimed_targets >= effective_batch_size)
}

async fn cdn_queue_depths(state: &AppState) -> Result<(usize, usize)> {
    if let Some(counts) = root_status_counts_from_database(state).await? {
        return Ok((
            counts.cdn_outbox_ready_count.max(0) as usize,
            counts.cdn_outbox_active_count.max(0) as usize,
        ));
    }
    let ready = read_ready_cdn_queue(state).await?.len();
    let active = read_cdn_queue(state).await?.len();
    Ok((ready, active))
}

async fn discovery_queue_depths(state: &AppState) -> Result<(usize, usize)> {
    if let Some(counts) = root_status_counts_from_database(state).await? {
        return Ok((
            counts.discovery_ready_queue_count.max(0) as usize,
            counts.discovery_pending_queue_count.max(0) as usize,
        ));
    }
    Ok((
        read_ready_discovery_queue(state).await?.len(),
        read_discovery_queue(state).await?.len(),
    ))
}

async fn write_queue_cycle_history(state: &AppState, namespace: &str, item: Value) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        sqlite
            .upsert_json(
                namespace,
                &format!("{}", Utc::now().timestamp_nanos_opt().unwrap_or_default()),
                &item,
            )
            .await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        postgres
            .upsert_json(
                namespace,
                &format!("{}", Utc::now().timestamp_nanos_opt().unwrap_or_default()),
                &item,
            )
            .await?;
        return Ok(());
    }
    let mut history: Vec<Value> = state
        .data
        .read(format!("indexes/{namespace}.json"))
        .unwrap_or_default();
    history.push(item);
    state
        .data
        .write(format!("indexes/{namespace}.json"), &history)?;
    Ok(())
}

fn default_tag_tree() -> CapabilityTagTree {
    CapabilityTagTree {
        version: 1,
        tags: vec![
            tag("text-processing", "Text Processing", None, &[]),
            tag(
                "translation",
                "Translation",
                Some("text-processing"),
                &["translate"],
            ),
            tag(
                "summarization",
                "Summarization",
                Some("text-processing"),
                &["summary"],
            ),
            tag("echo", "Echo", Some("text-processing"), &[]),
            tag("mcp", "MCP", None, &[]),
            tag("a2a", "A2A", None, &[]),
        ],
        tree: vec![],
    }
}

fn tag(id: &str, label: &str, parent: Option<&str>, aliases: &[&str]) -> CapabilityTag {
    CapabilityTag {
        id: id.to_owned(),
        label: label.to_owned(),
        parent: parent.map(ToOwned::to_owned),
        aliases: aliases.iter().map(|value| (*value).to_owned()).collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{routing::post, Router};
    use chrono::Duration;
    use oan_core::{
        CryptoSuite, ImplementationLink, OanMetadata, ProtocolBinding, ResourceDescription,
        ResourceType, ServiceEndpoint, VerificationMethod,
    };
    use oan_crypto::{
        generate_ed25519_keypair, hash_json_with_suite, public_key_jwk, public_key_multibase,
        SigningKey as OanSigningKey, VerifyingKey as OanVerifyingKey,
    };
    use oan_protocol::{
        DidControlChallenge, SubjectControlProofBundle, PURPOSE_RESOURCE_REGISTRATION,
    };
    use oan_service_security::hash_proof;
    use tempfile::tempdir;

    fn root_did() -> &'static str {
        "did:oan:AGRT:5HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu"
    }

    fn registrar_did() -> &'static str {
        "did:oan:INRG:6HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu"
    }

    fn discovery_did() -> &'static str {
        "did:oan:INDS:8HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu"
    }

    fn resource_did() -> &'static str {
        "did:oan:SKLG:7HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu"
    }

    fn openagenet_test_tag_tree() -> CapabilityTagTree {
        CapabilityTagTree {
            version: 1,
            tags: vec![
                tag("openagenet.local", "OpenAgenet Local", None, &[]),
                tag(
                    "openagenet.local.agent",
                    "OpenAgenet Local Agent",
                    Some("openagenet.local"),
                    &[],
                ),
                tag(
                    "unassigned.openagenet.local.agent",
                    "Unassigned OpenAgenet Agent",
                    None,
                    &[],
                ),
            ],
            tree: vec![],
        }
    }

    fn did_document_with_key(did: &str, key: &ed25519_dalek::SigningKey) -> DidDocument {
        let key_id = format!("{did}#key-1");
        let verifying_key = OanVerifyingKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256,
            key: key.verifying_key(),
        };
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: key_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                public_key_format: Some("multibase".to_owned()),
                public_key_multibase: Some(public_key_multibase(&verifying_key)),
                public_key_jwk: Some(public_key_jwk(&verifying_key)),
            }],
            authentication: vec![key_id.clone()],
            assertion_method: vec![key_id],
            service: vec![],
            oan_metadata: None,
        }
    }

    fn infrastructure_document_with_key(
        did: &str,
        key: &ed25519_dalek::SigningKey,
        role: GovernanceSubjectType,
        endpoint: &str,
        authorized_domains: Vec<String>,
    ) -> DidDocument {
        let mut document = did_document_with_key(did, key);
        let service_type = match role {
            GovernanceSubjectType::Registrar => "OANRegistrarService",
            GovernanceSubjectType::Discovery => "OANDiscoveryService",
            GovernanceSubjectType::VcIssuer => "OANVcIssuerService",
        };
        let node_role = match role {
            GovernanceSubjectType::Registrar => "registrar",
            GovernanceSubjectType::Discovery => "discovery",
            GovernanceSubjectType::VcIssuer => "vc_issuer",
        };
        let identity_type = match role {
            GovernanceSubjectType::Registrar => "registrar-node",
            GovernanceSubjectType::Discovery => "discovery-node",
            GovernanceSubjectType::VcIssuer => "vc-issuer-node",
        };
        document.context = vec![
            "https://www.w3.org/ns/did/v1".to_owned(),
            "https://w3id.org/oan/v1".to_owned(),
        ];
        document.service = vec![ServiceEndpoint {
            id: format!("{did}#service"),
            service_type: service_type.to_owned(),
            service_endpoint: endpoint.to_owned(),
            version: Some("1.0.0".to_owned()),
            protocol: Some("https".to_owned()),
            server_type: None,
            port: None,
        }];
        document.oan_metadata = Some(OanMetadata {
            subject_type: ResourceType::InfrastructureNode,
            resource_type: ResourceType::InfrastructureNode,
            node_role: Some(node_role.to_owned()),
            identity_type: Some(identity_type.to_owned()),
            controller_did: None,
            publisher_did: None,
            issuer_did: None,
            ttl: None,
            resource_description: None,
            agent_description: None,
            capability_tags: Vec::new(),
            authorized_domains,
            protocol_bindings: Vec::new(),
            implementation_links: Vec::new(),
            credential_requirements: Vec::new(),
            package_info: None,
            service_policy: None,
            network_scope: None,
            lifecycle_state: Some("active".to_owned()),
            extra: BTreeMap::new(),
        });
        document
    }

    fn resource_document_with_key(did: &str, key: &ed25519_dalek::SigningKey) -> DidDocument {
        let key_id = format!("{did}#key-1");
        let verifying_key = OanVerifyingKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256,
            key: key.verifying_key(),
        };
        DidDocument {
            context: vec!["https://www.w3.org/ns/did/v1".to_owned()],
            id: did.to_owned(),
            verification_method: vec![VerificationMethod {
                id: key_id.clone(),
                method_type: "Ed25519VerificationKey2020".to_owned(),
                controller: did.to_owned(),
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                public_key_format: Some("multibase".to_owned()),
                public_key_multibase: Some(public_key_multibase(&verifying_key)),
                public_key_jwk: Some(public_key_jwk(&verifying_key)),
            }],
            authentication: vec![key_id.clone()],
            assertion_method: vec![key_id],
            service: vec![ServiceEndpoint {
                id: format!("{did}#download"),
                service_type: "SkillPackageDownload".to_owned(),
                service_endpoint: "https://example.org/skills/contract-review.json".to_owned(),
                version: Some("1.0.0".to_owned()),
                protocol: Some("https".to_owned()),
                server_type: None,
                port: None,
            }],
            oan_metadata: Some(OanMetadata {
                subject_type: ResourceType::Skill,
                resource_type: ResourceType::Skill,
                node_role: None,
                identity_type: None,
                controller_did: None,
                publisher_did: Some("did:oan:AGUS:8HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned()),
                issuer_did: None,
                ttl: None,
                resource_description: Some(ResourceDescription {
                    name: Some("Contract Review Skill".to_owned()),
                    description: Some("Review contracts and flag risky clauses".to_owned()),
                    capability_tags: vec!["legal.contract.review".to_owned()],
                    use_case_examples: vec!["Review termination clause".to_owned()],
                    ..Default::default()
                }),
                agent_description: None,
                capability_tags: vec!["legal.contract.review".to_owned()],
                authorized_domains: vec!["legal".to_owned()],
                protocol_bindings: vec![ProtocolBinding {
                    id: format!("{did}#binding-https"),
                    protocol: "https".to_owned(),
                    version: None,
                    transport: Some("http".to_owned()),
                    service_ref: Some(format!("{did}#download")),
                    schema_ref: None,
                    extra: Default::default(),
                }],
                implementation_links: vec![ImplementationLink {
                    relation: "download".to_owned(),
                    target_did: did.to_owned(),
                    target_type: Some(ResourceType::Skill),
                    target_service: Some(format!("{did}#download")),
                    version_constraint: Some("1".to_owned()),
                }],
                credential_requirements: vec![],
                package_info: None,
                service_policy: None,
                network_scope: None,
                lifecycle_state: Some("active".to_owned()),
                extra: Default::default(),
            }),
        }
    }

    fn app_state(dir: &std::path::Path) -> AppState {
        let root_key = generate_ed25519_keypair();
        JsonStore::new(dir)
            .write(
                "did-document.json",
                &did_document_with_key(root_did(), &root_key),
            )
            .unwrap();
        let mut security = SecurityConfig::default();
        security.trust_indexer.enabled = false;
        AppState {
            data: JsonStore::new(dir),
            config: Config {
                server: ServerConfig {
                    host: "127.0.0.1".to_owned(),
                    port: 8001,
                },
                cors: CorsConfig::default(),
                debug: DebugConfig::default(),
                events: EventStreamConfig::default(),
                security,
                paths: PathConfig {
                    data_dir: dir.to_path_buf(),
                    keys_dir: dir.join("keys"),
                    database_url: None,
                    bulletin_file: dir.join("bulletin.json"),
                    capability_tree_file: dir.join("capability-tree.json"),
                    authorization_state_file: dir.join("authorization-state.json"),
                    request_nonce_file: dir.join("request-nonces.json"),
                },
            },
            root_did: root_did().to_owned(),
            signing_key: OanSigningKey::Ed25519 {
                suite: CryptoSuite::Ed25519Sha256,
                key: root_key,
            },
            tag_tree: default_tag_tree(),
            sqlite: None,
            postgres: None,
            authorization_state: Arc::new(Mutex::new(AuthorizationState::default())),
            client: reqwest::Client::new(),
            trust_indexer_client: reqwest::Client::new(),
            event_publisher: EventPublisher::Succeed,
            worker_runtime: Arc::new(Mutex::new(WorkerRuntimeState::default())),
            event_runtime: Arc::new(Mutex::new(EventRuntimeState::default())),
            admission_runtime: Arc::new(Mutex::new(AdmissionRuntimeState::default())),
            status_counts_cache: Arc::new(Mutex::new(None)),
            worker_wake_state: Arc::new(Mutex::new(WorkerWakeState::default())),
            admission_semaphore: Arc::new(Semaphore::new(
                SecurityConfig::default()
                    .workers
                    .admission_concurrency
                    .max(1),
            )),
            cdn_worker_notify: Arc::new(Notify::new()),
            discovery_worker_notify: Arc::new(Notify::new()),
        }
    }

    fn package_from_request(
        state: &AppState,
        request: &ResourceVerifyAndPublishRequest,
    ) -> ResourcePackage {
        let metadata = build_resource_metadata(&request.submission).unwrap();
        ResourcePackage {
            package_version: request.submission.package_version.clone(),
            resource_did: request.submission.resource_did.clone(),
            resource_type: request.submission.resource_type.clone(),
            did_document: request.submission.did_document.clone(),
            did_document_hash: request.submission.did_document_hash.clone(),
            metadata_hash: request.submission.metadata_hash.clone(),
            package_hash: request.submission.package_hash.clone(),
            hash_algorithm: request.submission.hash_algorithm.clone(),
            metadata,
            root_proof: RootProof {
                root_did: state.root_did.clone(),
                bulletin_event_hash: None,
                signature: None,
                package_claims: Some(json!({
                    "resourceDid": request.submission.resource_did,
                    "resourceType": request.submission.resource_type,
                    "version": request.submission.package_version,
                    "didDocumentHash": request.submission.did_document_hash,
                    "metadataHash": request.submission.metadata_hash,
                    "packageHash": request.submission.package_hash,
                    "hashAlgorithm": request.submission.hash_algorithm,
                    "lifecycleState": "active"
                })),
                proof: None,
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                hash_algorithm: Some("sha256".to_owned()),
            },
            created_at: Utc::now(),
        }
    }

    #[derive(Clone)]
    struct MockTrustIndexerState {
        active: bool,
        subject_did: String,
        subject_type: GovernanceSubjectType,
        metadata_hash: String,
        authorized_domains: Vec<String>,
    }

    async fn mock_trust_indexer(
        active: bool,
        subject_type: GovernanceSubjectType,
        subject_did: String,
        metadata_hash: String,
        authorized_domains: Vec<String>,
    ) -> String {
        async fn governance_handler(State(state): State<MockTrustIndexerState>) -> Json<Value> {
            Json(json!({
                "governance_active": state.active,
                "authorized": state.active,
                "reason": if state.active { "active" } else { "revoked" },
                "subject_type": state.subject_type.label(),
                "subject_type_code": state.subject_type.code(),
                "subject_did": state.subject_did,
                "status": if state.active { "active" } else { "revoked" },
                "scope": "chain_governance_state_only"
            }))
        }
        async fn subject_handler(
            State(state): State<MockTrustIndexerState>,
        ) -> (StatusCode, Json<Value>) {
            if !state.active {
                return (
                    StatusCode::OK,
                    Json(json!({
                        "subject_type": state.subject_type.code(),
                        "subject_type_label": state.subject_type.label(),
                        "subject_did": state.subject_did,
                        "status": 3,
                        "status_label": "revoked",
                        "authorized_domains": state.authorized_domains,
                        "policy_hash": "policy",
                        "metadata_hash": state.metadata_hash,
                        "effective_from_ms": 0,
                        "expires_at_ms": 0,
                        "version": 1,
                        "updated_at_ms": 1,
                        "last_sequence": 7,
                        "last_event_digest": "digest"
                    })),
                );
            }
            (
                StatusCode::OK,
                Json(json!({
                    "subject_type": state.subject_type.code(),
                    "subject_type_label": state.subject_type.label(),
                    "subject_did": state.subject_did,
                    "status": 1,
                    "status_label": "active",
                    "authorized_domains": state.authorized_domains,
                    "policy_hash": "policy",
                    "metadata_hash": state.metadata_hash,
                    "effective_from_ms": 0,
                    "expires_at_ms": 0,
                    "version": 1,
                    "updated_at_ms": 1,
                    "last_sequence": 7,
                    "last_event_digest": "digest"
                })),
            )
        }
        async fn status_handler() -> Json<Value> {
            Json(json!({
                "package_id": "0xpackage",
                "bulletin_object_id": "0xbulletin"
            }))
        }
        let mock_state = MockTrustIndexerState {
            active,
            subject_did,
            subject_type,
            metadata_hash,
            authorized_domains,
        };
        let app = Router::new()
            .route(
                "/v1/subjects/{subject_type}/{subject_did}/governance-active",
                axum::routing::get(governance_handler),
            )
            .route(
                "/v1/subjects/{subject_type}/{subject_did}",
                axum::routing::get(subject_handler),
            )
            .route("/v1/status", axum::routing::get(status_handler))
            .with_state(mock_state);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    fn enable_trust_indexer(state: &mut AppState, endpoint: String) {
        state.config.security.trust_indexer.enabled = true;
        state.config.security.trust_indexer.endpoint = Some(endpoint);
        state.config.security.trust_indexer.fail_mode = "closed".to_owned();
    }

    async fn enable_mock_registrar_indexer(
        state: &mut AppState,
        active: bool,
        metadata_hash: String,
    ) {
        let authorized_domains = vec!["*".to_owned()];
        let endpoint = mock_trust_indexer(
            active,
            GovernanceSubjectType::Registrar,
            registrar_did().to_owned(),
            metadata_hash,
            authorized_domains,
        )
        .await;
        enable_trust_indexer(state, endpoint);
    }

    fn infrastructure_vc_issue_request(
        state: &AppState,
        subject_key: &ed25519_dalek::SigningKey,
        role: &str,
    ) -> InfrastructureAuthorizationVcIssueRequest {
        let subject_type = governance_subject_type_for_role(role).unwrap();
        let endpoint = "http://127.0.0.1:8101";
        let authorized_domains = match subject_type {
            GovernanceSubjectType::Registrar | GovernanceSubjectType::Discovery => {
                vec!["*".to_owned()]
            }
            GovernanceSubjectType::VcIssuer => Vec::new(),
        };
        let did_document = infrastructure_document_with_key(
            registrar_did(),
            subject_key,
            subject_type,
            endpoint,
            authorized_domains.clone(),
        );
        let did_document_stable_hash =
            stable_did_document_hash_for_root(state, &did_document).unwrap();
        let payload = InfrastructureAuthorizationVcIssuePayload {
            subject_did: registrar_did().to_owned(),
            role: role.to_owned(),
            did_document,
            did_document_stable_hash,
            authorized_domains,
            endpoint: Some(endpoint.to_owned()),
        };
        let subject_signing_key = OanSigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256,
            key: subject_key.clone(),
        };
        let upstream_auth = create_signed_request_envelope(SignedRequestEnvelopeInput {
            request_id: request_id("infrastructure-authorization-vc-issue"),
            protocol_version: OAN_RESOURCE_PROTOCOL_VERSION.to_owned(),
            purpose: PURPOSE_INFRASTRUCTURE_AUTHORIZATION_VC_ISSUE.to_owned(),
            method: "POST".to_owned(),
            path: PATH_ROOT_INFRASTRUCTURE_AUTHORIZATION_VCS_ISSUE.to_owned(),
            aud: state.root_did.clone(),
            payload: &payload,
            creator: registrar_did().to_owned(),
            verification_method: format!("{}#key-1", registrar_did()),
            signing_key: &subject_signing_key,
            nonce: request_nonce("infrastructure-authorization-vc-issue"),
        })
        .unwrap();
        InfrastructureAuthorizationVcIssueRequest {
            payload,
            upstream_auth,
        }
    }

    async fn app_state_with_sqlite(dir: &std::path::Path) -> AppState {
        let mut state = app_state(dir);
        let sqlite_url = format!("sqlite:{}", dir.join("root-test.db").display());
        let sqlite = SqliteJsonStore::connect(&sqlite_url).await.unwrap();
        initialize_root_sqlite(&sqlite).await.unwrap();
        state.config.paths.database_url = Some(sqlite_url);
        state.sqlite = Some(sqlite);
        state
    }

    fn authorize_registrar(state: &AppState, key: &ed25519_dalek::SigningKey) {
        authorize_registrar_with_domains(state, key, vec!["*".to_owned()]);
    }

    fn authorize_registrar_with_domains(
        state: &AppState,
        key: &ed25519_dalek::SigningKey,
        authorized_domains: Vec<String>,
    ) {
        let mut did_document = did_document_with_key(registrar_did(), key);
        did_document.oan_metadata = Some(OanMetadata {
            subject_type: ResourceType::InfrastructureNode,
            resource_type: ResourceType::InfrastructureNode,
            node_role: Some("registrar".to_owned()),
            identity_type: Some("registrar-node".to_owned()),
            controller_did: None,
            publisher_did: None,
            issuer_did: None,
            ttl: None,
            resource_description: None,
            agent_description: None,
            capability_tags: Vec::new(),
            authorized_domains: authorized_domains.clone(),
            protocol_bindings: Vec::new(),
            implementation_links: Vec::new(),
            credential_requirements: Vec::new(),
            package_info: None,
            service_policy: None,
            network_scope: None,
            lifecycle_state: Some("active".to_owned()),
            extra: Default::default(),
        });
        let did_document_hash =
            hash_json_with_suite(CryptoSuite::Ed25519Sha256, &did_document).unwrap();
        let entry = NodeAuthorizationState {
            status: "active".to_owned(),
            did_document_hash,
            did_document_snapshot: Some(did_document),
            updated_at: Utc::now(),
            authorized_domains,
        };
        update_authorization_state(state, registrar_did(), entry, "registrar", None).unwrap();
    }

    fn authorize_discovery_with_endpoint(
        state: &AppState,
        key: &ed25519_dalek::SigningKey,
        endpoint: &str,
    ) {
        authorize_discovery_with_endpoint_and_domains(state, key, endpoint, vec!["*".to_owned()]);
    }

    fn authorize_discovery_with_endpoint_and_domains(
        state: &AppState,
        key: &ed25519_dalek::SigningKey,
        endpoint: &str,
        authorized_domains: Vec<String>,
    ) {
        let mut did_document = did_document_with_key(discovery_did(), key);
        did_document.service = vec![ServiceEndpoint {
            id: format!("{}#discovery", discovery_did()),
            service_type: "OANDiscoveryService".to_owned(),
            service_endpoint: endpoint.to_owned(),
            version: Some("1.0.0".to_owned()),
            protocol: Some("http".to_owned()),
            server_type: Some("test-discovery".to_owned()),
            port: None,
        }];
        let did_document_hash =
            hash_json_with_suite(CryptoSuite::Ed25519Sha256, &did_document).unwrap();
        update_discovery_authorization_state(
            state,
            discovery_did(),
            DiscoveryAuthorizationState {
                status: "active".to_owned(),
                updated_at: Utc::now(),
                did_document_hash,
                did_document_snapshot: Some(did_document),
                authorized_domains,
                tag_tree_version: 1,
            },
        )
        .unwrap();
    }

    fn overwrite_authorization_state_for_test(
        state: &AppState,
        mutate: impl FnOnce(&mut AuthorizationState),
    ) {
        let mut authorization_state = current_authorization_state(state);
        mutate(&mut authorization_state);
        persist_authorization_state(state, authorization_state).unwrap();
    }

    fn resource_verify_request(
        state: &AppState,
        registrar_key: &ed25519_dalek::SigningKey,
        resource_key: &ed25519_dalek::SigningKey,
        upstream_path: &str,
    ) -> ResourceVerifyAndPublishRequest {
        resource_verify_request_with_version(state, registrar_key, resource_key, upstream_path, "1")
    }

    fn resource_verify_request_with_version(
        state: &AppState,
        registrar_key: &ed25519_dalek::SigningKey,
        resource_key: &ed25519_dalek::SigningKey,
        upstream_path: &str,
        package_version: &str,
    ) -> ResourceVerifyAndPublishRequest {
        let did_document = resource_document_with_key(resource_did(), resource_key);
        let did_document_hash = hash_json_with_suite(CryptoSuite::Ed25519Sha256, &did_document)
            .map(|hash| format!("sha256:{hash}"))
            .unwrap();
        let challenge = DidControlChallenge {
            challenge_id: "challenge-1".to_owned(),
            draft_id: "resource-draft-1".to_owned(),
            subject_did: resource_did().to_owned(),
            did_document_hash: did_document_hash.clone(),
            registrar_did: registrar_did().to_owned(),
            purpose: PURPOSE_RESOURCE_REGISTRATION.to_owned(),
            verification_method: format!("{}#key-1", resource_did()),
            nonce: "nonce-1".to_owned(),
            issued_at: Utc::now(),
            expires_at: Utc::now() + Duration::seconds(300),
        };
        let resource_signing_key = OanSigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256,
            key: resource_key.clone(),
        };
        let proof = build_data_integrity_proof(
            &challenge,
            resource_did().to_owned(),
            format!("{}#key-1", resource_did()),
            &resource_signing_key,
        )
        .unwrap();
        let proof_hash = hash_proof(&proof).unwrap();
        let proof_bundle = SubjectControlProofBundle {
            challenge,
            proof,
            verified_at: Some(Utc::now()),
            verified_verification_method: Some(format!("{}#key-1", resource_did())),
            proof_hash: Some(proof_hash),
        };
        let metadata_value = json!({
            "name": "Metadata Override Skill",
            "description": "Metadata supplied description",
            "capabilityTags": ["legal.override"],
            "lifecycleState": "active"
        });
        let mut metadata = build_resource_metadata(&oan_protocol::ResourceRegistrationSubmission {
            resource_did: resource_did().to_owned(),
            resource_type: ResourceType::Skill,
            did_document: did_document.clone(),
            did_document_hash: did_document_hash.clone(),
            metadata: metadata_value.clone(),
            package_version: package_version.to_owned(),
            package_hash: String::new(),
            metadata_hash: String::new(),
            hash_algorithm: "sha256".to_owned(),
            registration_credential: json!({"status":"active"}),
            subject_control_proof: proof_bundle.clone(),
        })
        .unwrap();
        metadata.metadata_hash.clear();
        metadata.package_hash.clear();
        let metadata_hash =
            hash_resource_metadata_with_suite(CryptoSuite::Ed25519Sha256, &metadata)
                .map(|hash| format!("sha256:{hash}"))
                .unwrap();
        let package_hash = hash_json_with_suite(
            CryptoSuite::Ed25519Sha256,
            &json!({
                "packageVersion": package_version,
                "resourceDid": resource_did(),
                "resourceType": ResourceType::Skill,
                "didDocumentHash": did_document_hash,
                "metadataHash": metadata_hash,
                "hashAlgorithm": "sha256",
            }),
        )
        .map(|hash| format!("sha256:{hash}"))
        .unwrap();
        let submission = oan_protocol::ResourceRegistrationSubmission {
            resource_did: resource_did().to_owned(),
            resource_type: ResourceType::Skill,
            did_document,
            did_document_hash,
            metadata: metadata_value,
            package_version: package_version.to_owned(),
            package_hash,
            metadata_hash,
            hash_algorithm: "sha256".to_owned(),
            registration_credential: json!({"status":"active"}),
            subject_control_proof: proof_bundle,
        };
        let registrar_signing_key = OanSigningKey::Ed25519 {
            suite: CryptoSuite::Ed25519Sha256,
            key: registrar_key.clone(),
        };
        let upstream_auth = create_signed_request_envelope(SignedRequestEnvelopeInput {
            request_id: request_id("resource-verify-and-publish"),
            protocol_version: OAN_RESOURCE_PROTOCOL_VERSION.to_owned(),
            purpose: PURPOSE_VERIFY_AND_PUBLISH.to_owned(),
            method: "POST".to_owned(),
            path: upstream_path.to_owned(),
            aud: state.root_did.clone(),
            payload: &submission,
            creator: registrar_did().to_owned(),
            verification_method: format!("{}#key-1", registrar_did()),
            signing_key: &registrar_signing_key,
            nonce: request_nonce("resource-verify-and-publish"),
        })
        .unwrap();
        ResourceVerifyAndPublishRequest {
            registrar_did: registrar_did().to_owned(),
            submission,
            upstream_auth,
        }
    }

    #[test]
    fn verify_resource_request_accepts_resource_path_and_rejects_legacy_path() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);

        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        assert!(verify_resource_request(&state, &request).is_ok());

        let legacy = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            "/root/agents/verify-and-publish",
        );
        assert!(verify_resource_request(&state, &legacy)
            .unwrap_err()
            .contains("path"));
    }

    #[test]
    fn build_resource_metadata_prefers_submission_metadata() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );

        let metadata = build_resource_metadata(&request.submission).unwrap();
        assert_eq!(metadata.resource_did, resource_did());
        assert_eq!(metadata.resource_type, ResourceType::Skill);
        assert_eq!(metadata.name, "Metadata Override Skill");
        assert_eq!(metadata.capability_tags, vec!["legal.override".to_owned()]);
    }

    #[test]
    fn root_debug_config_defaults_to_no_snapshot_exports() {
        let debug = DebugConfig::default();
        assert!(!debug.export_snapshots);
        assert!(debug.export_interval_ms >= 100);
    }

    #[test]
    fn worker_config_separates_batch_size_from_concurrency() {
        let workers = WorkerSecurityConfig::default();
        assert!(workers.cdn_batch_size >= workers.cdn_concurrency);
        assert!(workers.discovery_batch_size >= workers.discovery_concurrency);
        assert!(workers.cdn_concurrency > 0);
        assert!(workers.discovery_concurrency > 0);
        assert!(workers.admission_concurrency > 0);
    }

    #[test]
    fn event_failure_mode_accepts_only_known_modes() {
        assert!(validate_event_failure_mode("fallback").is_ok());
        assert!(validate_event_failure_mode("closed").is_ok());
        let err = validate_event_failure_mode("best-effort")
            .unwrap_err()
            .to_string();
        assert!(err.contains("unsupported_event_failure_mode"));
    }

    #[test]
    fn effective_worker_batch_size_scales_with_ready_depth_but_stays_bounded() {
        assert_eq!(effective_worker_batch_size(50, 10, 4), 50);
        assert_eq!(effective_worker_batch_size(50, 120, 4), 100);
        assert_eq!(effective_worker_batch_size(50, 300, 4), 200);
        assert_eq!(effective_worker_batch_size(2_000, 20_000, 4), 5_000);
    }

    #[tokio::test]
    async fn verify_resource_and_publish_archives_and_queues_resource_package() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );

        let response = verify_resource_and_publish(State(state.clone()), Json(request))
            .await
            .unwrap();
        assert_eq!(response.0["status"], "resource-verified-and-queued");
        assert_eq!(response.0["resourceDid"], resource_did());
        let admission_runtime = state.admission_runtime.lock().unwrap().clone();
        assert_eq!(admission_runtime.accepted_count, 1);
        assert_eq!(admission_runtime.busy_rejected_count, 0);

        let package: ResourcePackage = state
            .data
            .read(format!(
                "resource-packages/{}",
                did_to_file_name(resource_did())
            ))
            .unwrap();
        assert_eq!(package.resource_did, resource_did());
        let queue = read_cdn_queue(&state).await.unwrap();
        assert_eq!(queue.len(), 1);
        assert_eq!(queue[0].resource_did, resource_did());
    }

    #[tokio::test]
    async fn verify_resource_and_publish_rejects_resource_domains_outside_registrar_scope() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar_with_domains(&state, &registrar_key, vec!["finance".to_owned()]);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );

        let err = verify_resource_and_publish(State(state), Json(request))
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert_eq!(err.message, "unauthorized_domains");
    }

    #[test]
    fn validate_resource_authorized_domains_enforces_shape_and_coverage() {
        assert!(validate_resource_authorized_domains(
            &["legal.contract".to_owned()],
            &["legal".to_owned()]
        )
        .is_ok());
        assert!(
            validate_resource_authorized_domains(&["legal".to_owned()], &["*".to_owned()]).is_ok()
        );
        assert_eq!(
            validate_resource_authorized_domains(&[], &["*".to_owned()]).unwrap_err(),
            "resource_domains_required"
        );
        assert_eq!(
            validate_resource_authorized_domains(
                &["legal".to_owned()],
                &["*".to_owned(), "finance".to_owned()]
            )
            .unwrap_err(),
            "invalid_authorized_domains"
        );
        assert_eq!(
            validate_resource_authorized_domains(
                &["legal".to_owned(), "finance".to_owned()],
                &["*".to_owned()]
            )
            .unwrap_err(),
            "invalid_authorized_domains"
        );
        assert_eq!(
            validate_resource_authorized_domains(&["legal".to_owned()], &["finance".to_owned()])
                .unwrap_err(),
            "unauthorized_domains"
        );
    }

    #[test]
    fn authorization_state_reads_legacy_snake_case_domain_fields() {
        let json = json!({
            "registrars": {
                "did:oan:REG:legacy": {
                    "status": "active",
                    "updated_at": "2026-01-01T00:00:00Z",
                    "did_document_hash": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "authorized_domains": ["legal"]
                }
            },
            "discovery_nodes": {
                "did:oan:DIS:legacy": {
                    "status": "active",
                    "updated_at": "2026-01-01T00:00:00Z",
                    "did_document_hash": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "authorizedDomains": ["legal"],
                    "tag_tree_version": 1
                }
            },
            "vc_issuers": {}
        });

        let state: AuthorizationState = serde_json::from_value(json).unwrap();

        assert_eq!(
            state
                .registrars
                .get("did:oan:REG:legacy")
                .unwrap()
                .authorized_domains,
            vec!["legal".to_owned()]
        );
        assert_eq!(
            state
                .discovery_nodes
                .get("did:oan:DIS:legacy")
                .unwrap()
                .authorized_domains,
            vec!["legal".to_owned()]
        );
    }

    #[tokio::test]
    async fn verify_resource_and_publish_returns_busy_when_admission_queue_is_saturated() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        state.config.security.workers.http_timeout_seconds = 1;
        state.admission_semaphore = Arc::new(Semaphore::new(1));
        let _held_permit = state
            .admission_semaphore
            .clone()
            .acquire_owned()
            .await
            .unwrap();
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );

        let err = verify_resource_and_publish(State(state.clone()), Json(request))
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(err.message, "root_admission_busy");
        let admission_runtime = state.admission_runtime.lock().unwrap().clone();
        assert_eq!(admission_runtime.accepted_count, 0);
        assert_eq!(admission_runtime.busy_rejected_count, 1);
    }

    #[tokio::test]
    async fn verify_resource_and_publish_rejects_registrar_when_governance_inactive() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        enable_mock_registrar_indexer(
            &mut state,
            false,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        )
        .await;
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );

        let err = verify_resource_and_publish(State(state), Json(request))
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert!(err.message.contains("governance_inactive"));
    }

    #[tokio::test]
    async fn governance_reconciliation_marks_local_authorization_inactive() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        enable_mock_registrar_indexer(
            &mut state,
            false,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        )
        .await;
        let registrar_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);

        reconcile_governance_state(&state).await.unwrap();

        let authorization_state =
            load_authorization_state(&state.config.paths.authorization_state_file).unwrap();
        let registrar = authorization_state.registrars.get(registrar_did()).unwrap();
        assert_eq!(registrar.status, "governance_inactive");
    }

    #[tokio::test]
    async fn governance_reconciliation_restores_only_governance_inactive_entries() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        enable_mock_registrar_indexer(
            &mut state,
            true,
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
        )
        .await;
        let registrar_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        overwrite_authorization_state_for_test(&state, |authorization_state| {
            authorization_state
                .registrars
                .get_mut(registrar_did())
                .unwrap()
                .status = "governance_inactive".to_owned();
        });

        reconcile_governance_state(&state).await.unwrap();

        let authorization_state =
            load_authorization_state(&state.config.paths.authorization_state_file).unwrap();
        assert_eq!(
            authorization_state
                .registrars
                .get(registrar_did())
                .unwrap()
                .status,
            "active"
        );

        overwrite_authorization_state_for_test(&state, |authorization_state| {
            authorization_state
                .registrars
                .get_mut(registrar_did())
                .unwrap()
                .status = "revoked".to_owned();
        });
        reconcile_governance_state(&state).await.unwrap();
        let authorization_state =
            load_authorization_state(&state.config.paths.authorization_state_file).unwrap();
        assert_eq!(
            authorization_state
                .registrars
                .get(registrar_did())
                .unwrap()
                .status,
            "revoked"
        );
    }

    #[tokio::test]
    async fn issue_infrastructure_authorization_vc_requires_chain_governance_active() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        let registrar_key = generate_ed25519_keypair();
        let request = infrastructure_vc_issue_request(&state, &registrar_key, "registrar");
        enable_mock_registrar_indexer(
            &mut state,
            false,
            request.payload.did_document_stable_hash.clone(),
        )
        .await;

        let err = issue_infrastructure_authorization_vc(State(state), Json(request))
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert!(err.message.contains("governance_inactive"));
    }

    #[tokio::test]
    async fn issue_infrastructure_authorization_vc_returns_signed_credential_and_updates_state() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        let registrar_key = generate_ed25519_keypair();
        let request = infrastructure_vc_issue_request(&state, &registrar_key, "registrar");
        enable_mock_registrar_indexer(
            &mut state,
            true,
            request.payload.did_document_stable_hash.clone(),
        )
        .await;

        let response = issue_infrastructure_authorization_vc(State(state.clone()), Json(request))
            .await
            .unwrap();

        assert_eq!(response.0["status"], "issued");
        assert_eq!(
            response.0["credential"]["type"][1],
            "OANInfrastructureAuthorizationCredential"
        );
        assert_eq!(
            response.0["credential"]["credentialSubject"]["id"],
            registrar_did()
        );
        assert_eq!(
            response.0["credential"]["credentialSubject"]["role"],
            "registrar"
        );
        assert_eq!(
            response.0["credential"]["credentialSubject"]["didDocumentFile"],
            "did-document.json"
        );
        assert_eq!(
            response.0["credential"]["credentialStatus"]["type"],
            "OANChainGovernanceBackedAuthorizationStatus2026"
        );
        assert_eq!(
            response.0["credential"]["credentialStatus"]["chainGovernanceNoticeFile"],
            "chain-governance-notice.json"
        );
        assert_eq!(
            response.0["credential"]["credentialStatus"]["didDocumentStableHash"],
            response.0["didDocumentStableHash"]
        );
        assert_eq!(
            response.0["credential"]["proof"]["type"],
            "OANEd25519Signature2026"
        );
        assert_eq!(
            response.0["credential"]["proof"]["cryptosuite"],
            "ed25519-jcs-2026"
        );
        assert_eq!(
            response.0["credential"]["proof"]["canonicalizationAlgorithm"],
            "JCS-RFC8785-compatible-key-sorted-json"
        );
        assert!(
            response.0["credential"]["proof"]["proofValue"]
                .as_str()
                .unwrap()
                .len()
                > 20
        );
        let authorization_state =
            load_authorization_state(&state.config.paths.authorization_state_file).unwrap();
        let registrar = authorization_state.registrars.get(registrar_did()).unwrap();
        assert_eq!(registrar.status, "active");
        assert!(registrar.did_document_snapshot.is_some());
    }

    #[tokio::test]
    async fn issue_infrastructure_authorization_vc_rejects_metadata_hash_mismatch() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        let registrar_key = generate_ed25519_keypair();
        let request = infrastructure_vc_issue_request(&state, &registrar_key, "registrar");
        enable_mock_registrar_indexer(
            &mut state,
            true,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".to_owned(),
        )
        .await;

        let err = issue_infrastructure_authorization_vc(State(state), Json(request))
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::FORBIDDEN);
        assert!(err
            .message
            .contains("governance_subject_metadata_hash_mismatch"));
    }

    #[tokio::test]
    async fn issue_infrastructure_authorization_vc_rejects_non_infrastructure_profile() {
        let dir = tempdir().unwrap();
        let mut state = app_state(dir.path());
        let registrar_key = generate_ed25519_keypair();
        let mut request = infrastructure_vc_issue_request(&state, &registrar_key, "registrar");
        request.payload.subject_did = "did:oan:AGRG:6HkPq7Vm3RdT9Ya2WcX8Ns4Bf6GjLeZu".to_owned();
        request.payload.did_document.id = request.payload.subject_did.clone();
        enable_mock_registrar_indexer(
            &mut state,
            true,
            request.payload.did_document_stable_hash.clone(),
        )
        .await;

        let err = issue_infrastructure_authorization_vc(State(state), Json(request))
            .await
            .unwrap_err();
        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("infrastructure_did_prefix_mismatch"));
    }

    #[tokio::test]
    async fn verify_resource_and_publish_preserves_string_package_version() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request_with_version(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
            "1.0.0",
        );

        let response = verify_resource_and_publish(State(state.clone()), Json(request))
            .await
            .unwrap();
        assert_eq!(response.0["packageVersion"], "1.0.0");

        let versions = api_resource_versions(
            State(state.clone()),
            axum::extract::Path(resource_did().to_owned()),
        )
        .await
        .unwrap();
        assert_eq!(versions.0["items"][0]["packageVersion"], "1.0.0");

        let detail = api_resource_version_detail(
            State(state),
            axum::extract::Path((resource_did().to_owned(), "1.0.0".to_owned())),
        )
        .await
        .unwrap();
        assert_eq!(detail.0["package"]["packageVersion"], "1.0.0");
    }

    #[tokio::test]
    async fn builds_cdn_publish_requested_event_from_package() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let package = package_from_request(&state, &request);
        persist_resource_acceptance(&state, &package).await.unwrap();

        let event = build_cdn_publish_requested_event(&state, &package)
            .await
            .unwrap();
        assert_eq!(event.event_type, "cdn_publish_requested");
        assert_eq!(event.job_key, cdn_publication_job_key(&package));
        assert_eq!(event.resource_did, resource_did());
        assert_eq!(event.package_version, package.package_version);
        assert!(event.publication_cursor > 0);
        event.validate().unwrap();
    }

    #[tokio::test]
    async fn sqlite_persist_resource_acceptance_writes_cdn_job_and_outbox_atomically() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.events.enabled = true;
        state.event_publisher = EventPublisher::Succeed;
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let package = package_from_request(&state, &request);

        persist_resource_acceptance(&state, &package).await.unwrap();

        let counts = root_status_counts_from_database(&state)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(counts.latest_version_count, 1);
        assert_eq!(counts.cdn_ready_queue_count, 1);
        assert_eq!(counts.cdn_active_queue_count, 1);
        assert_eq!(counts.cdn_outbox_ready_count, 1);
        assert_eq!(counts.cdn_outbox_active_count, 1);
        let status = api_status(State(state.clone())).await.unwrap();
        assert_eq!(status.0["cdnOutboxCount"], 1);
        assert_eq!(status.0["cdnOutboxReadyCount"], 1);
        assert_eq!(status.0["cdnOutboxActiveCount"], 1);

        let outbox = claim_cdn_outbox_events(&state, "test-worker", 10, 30)
            .await
            .unwrap();
        assert_eq!(outbox.len(), 1);
        assert_eq!(outbox[0].0, cdn_publication_job_key(&package));
        assert_eq!(outbox[0].1.resource_did, package.resource_did);
        assert_eq!(outbox[0].1.package_version, package.package_version);
        assert!(outbox[0].1.publication_cursor > 0);
        outbox[0].1.validate().unwrap();
    }

    #[tokio::test]
    async fn cdn_outbox_relay_publishes_and_marks_outbox_succeeded() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.events.enabled = true;
        state.event_publisher = EventPublisher::Succeed;
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let package = package_from_request(&state, &request);
        persist_resource_acceptance(&state, &package).await.unwrap();

        let result = run_cdn_outbox_relay_cycle(&state).await.unwrap();
        assert_eq!(result["attemptedCount"], 1);
        assert_eq!(result["publishedCount"], 1);
        assert_eq!(result["failedCount"], 0);
        assert_eq!(result["markedPublishedCount"], 1);
        assert_eq!(result["markedRetryCount"], 0);

        let counts = root_status_counts_from_database(&state)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(counts.cdn_outbox_ready_count, 0);
        assert_eq!(counts.cdn_outbox_active_count, 0);
        assert_eq!(counts.cdn_active_queue_count, 1);
        let runtime = state.event_runtime.lock().unwrap().clone();
        assert_eq!(runtime.publish_success_count, 1);
        assert_eq!(runtime.publish_failure_count, 0);
    }

    #[tokio::test]
    async fn cdn_outbox_relay_respects_effective_batch_limit_and_keeps_remaining_ready() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.events.enabled = true;
        state.config.security.workers.cdn_batch_size = 2;
        state.event_publisher = EventPublisher::Succeed;
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);

        for version in 1..=10 {
            let request = resource_verify_request_with_version(
                &state,
                &registrar_key,
                &resource_key,
                PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
                &version.to_string(),
            );
            persist_resource_acceptance(&state, &package_from_request(&state, &request))
                .await
                .unwrap();
        }

        let first = run_cdn_outbox_relay_cycle(&state).await.unwrap();
        assert_eq!(first["attemptedCount"], 8);
        assert_eq!(first["publishedCount"], 8);
        assert_eq!(first["concurrency"], 16);
        assert_eq!(first["effectiveBatchSize"], 8);
        assert_eq!(first["markedPublishedCount"], 8);
        assert_eq!(first["failedCount"], 0);
        assert_eq!(first["readyQueueDepthBefore"], 10);
        assert_eq!(first["activeQueueDepthBefore"], 10);
        assert_eq!(first["readyQueueDepthAfter"], 2);
        assert_eq!(first["activeQueueDepthAfter"], 2);
        assert!(cdn_cycle_should_continue_immediately(&first));

        let counts = root_status_counts_from_database(&state)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(counts.cdn_outbox_ready_count, 2);
        assert_eq!(counts.cdn_outbox_active_count, 2);
        assert_eq!(counts.cdn_active_queue_count, 10);
        let runtime = state.event_runtime.lock().unwrap().clone();
        assert_eq!(runtime.publish_success_count, 8);
        assert_eq!(runtime.publish_failure_count, 0);

        let second = run_cdn_outbox_relay_cycle(&state).await.unwrap();
        assert_eq!(second["attemptedCount"], 2);
        assert_eq!(second["publishedCount"], 2);
        assert_eq!(second["readyQueueDepthAfter"], 0);
        assert_eq!(second["activeQueueDepthAfter"], 0);
        assert!(!cdn_cycle_should_continue_immediately(&second));
        let counts = root_status_counts_from_database(&state)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(counts.cdn_outbox_ready_count, 0);
        assert_eq!(counts.cdn_outbox_active_count, 0);
        let runtime = state.event_runtime.lock().unwrap().clone();
        assert_eq!(runtime.publish_success_count, 10);
        let worker_runtime = state.worker_runtime.lock().unwrap().clone();
        assert_eq!(worker_runtime.cdn_last_success_count, 2);
        assert_eq!(worker_runtime.cdn_last_progress_success_count, 2);
        assert_eq!(worker_runtime.cdn_effective_batch_size, 8);
    }

    #[tokio::test]
    async fn cdn_outbox_relay_reports_configured_publish_concurrency() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.events.enabled = true;
        state.config.security.workers.cdn_batch_size = 4;
        state.config.security.workers.cdn_concurrency = 2;
        state.event_publisher = EventPublisher::Succeed;
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);

        for version in ["1", "2", "3", "4"] {
            let request = resource_verify_request_with_version(
                &state,
                &registrar_key,
                &resource_key,
                PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
                version,
            );
            persist_resource_acceptance(&state, &package_from_request(&state, &request))
                .await
                .unwrap();
        }

        let result = run_cdn_outbox_relay_cycle(&state).await.unwrap();
        assert_eq!(result["attemptedCount"], 4);
        assert_eq!(result["publishedCount"], 4);
        assert_eq!(result["failedCount"], 0);
        assert_eq!(result["concurrency"], 2);
        assert_eq!(result["markedPublishedCount"], 4);
        let runtime = state.event_runtime.lock().unwrap().clone();
        assert_eq!(runtime.publish_success_count, 4);
    }

    #[test]
    fn cdn_outbox_claims_are_ordered_by_publication_cursor() {
        let base = CdnPublishRequestedEvent {
            event_type: "cdn_publish_requested".to_owned(),
            schema_version: "1".to_owned(),
            root_did: "did:oan:AGRT:test".to_owned(),
            job_key: "job".to_owned(),
            resource_did: "did:oan:AGUS:test".to_owned(),
            package_version: "1".to_owned(),
            publication_cursor: 1,
            package_hash: "sha256:pkg".to_owned(),
            did_document_hash: "sha256:did".to_owned(),
            metadata_hash: "sha256:meta".to_owned(),
            created_at: Utc::now(),
        };
        let first = CdnPublishRequestedEvent {
            job_key: "job-20".to_owned(),
            publication_cursor: 20,
            ..base.clone()
        };
        let second = CdnPublishRequestedEvent {
            job_key: "job-3".to_owned(),
            publication_cursor: 3,
            ..base.clone()
        };
        let third = CdnPublishRequestedEvent {
            job_key: "job-11".to_owned(),
            publication_cursor: 11,
            ..base
        };

        let ordered = order_cdn_outbox_claims_by_publication_cursor(vec![
            ("job-20".to_owned(), first),
            ("job-11".to_owned(), third),
            ("job-3".to_owned(), second),
        ]);

        assert_eq!(ordered[0].0, "job-3");
        assert_eq!(ordered[1].0, "job-11");
        assert_eq!(ordered[2].0, "job-20");
    }

    #[tokio::test]
    async fn cdn_outbox_relay_retries_failed_event_without_dropping_fallback_job() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.events.enabled = true;
        state.config.events.failure_mode = "fallback".to_owned();
        state.config.security.workers.retry_backoff_seconds = 60;
        state.event_publisher = EventPublisher::Failing("nats unavailable".to_owned());
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let package = package_from_request(&state, &request);
        persist_resource_acceptance(&state, &package).await.unwrap();

        let result = run_cdn_outbox_relay_cycle(&state).await.unwrap();
        assert_eq!(result["attemptedCount"], 1);
        assert_eq!(result["publishedCount"], 0);
        assert_eq!(result["failedCount"], 1);
        assert!(result["failed"][0]["error"]
            .as_str()
            .unwrap()
            .contains("nats unavailable"));

        let counts = root_status_counts_from_database(&state)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(counts.cdn_outbox_ready_count, 0);
        assert_eq!(counts.cdn_outbox_active_count, 1);
        assert_eq!(counts.cdn_active_queue_count, 1);
        let runtime = state.event_runtime.lock().unwrap().clone();
        assert_eq!(runtime.publish_success_count, 0);
        assert_eq!(runtime.publish_failure_count, 1);
        assert!(runtime.last_error.unwrap().contains("nats unavailable"));
    }

    #[tokio::test]
    async fn cdn_outbox_relay_can_publish_after_retry_becomes_ready() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.events.enabled = true;
        state.config.events.failure_mode = "fallback".to_owned();
        state.config.security.workers.retry_backoff_seconds = 0;
        state.event_publisher = EventPublisher::Failing("temporary outage".to_owned());
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        persist_resource_acceptance(&state, &package_from_request(&state, &request))
            .await
            .unwrap();

        let failed = run_cdn_outbox_relay_cycle(&state).await.unwrap();
        assert_eq!(failed["attemptedCount"], 1);
        assert_eq!(failed["failedCount"], 1);

        state.event_publisher = EventPublisher::Succeed;
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let recovered = run_cdn_outbox_relay_cycle(&state).await.unwrap();
        assert_eq!(recovered["attemptedCount"], 1);
        assert_eq!(recovered["publishedCount"], 1);
        assert_eq!(recovered["failedCount"], 0);

        let counts = root_status_counts_from_database(&state)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(counts.cdn_outbox_ready_count, 0);
        assert_eq!(counts.cdn_outbox_active_count, 0);
        assert_eq!(counts.cdn_active_queue_count, 1);
        let runtime = state.event_runtime.lock().unwrap().clone();
        assert_eq!(runtime.publish_success_count, 1);
        assert_eq!(runtime.publish_failure_count, 1);
        assert_eq!(runtime.last_error, None);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cdn_worker_event_wakes_progress_without_waiting_for_timer() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.events.enabled = true;
        state.config.security.workers.cdn_interval_ms = 60_000;
        state.event_publisher = EventPublisher::Succeed;
        spawn_cdn_outbox_relay(state.clone());

        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let package = package_from_request(&state, &request);
        persist_resource_acceptance(&state, &package).await.unwrap();

        let success = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let counts = root_status_counts_from_database(&state)
                    .await
                    .unwrap()
                    .unwrap();
                let runtime = state.worker_runtime.lock().unwrap().clone();
                let event_runtime = state.event_runtime.lock().unwrap().clone();
                if counts.cdn_outbox_ready_count == 0
                    && counts.cdn_outbox_active_count == 0
                    && event_runtime.publish_success_count == 1
                    && runtime.cdn_event_trigger_count > 0
                    && runtime.cdn_last_progress_success_count > 0
                {
                    return runtime;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("cdn worker should progress from event wakeup before timer");

        assert_eq!(success.cdn_timer_trigger_count, 0);
        assert!(success.cdn_event_trigger_count > 0);
    }

    #[test]
    fn event_stream_is_enabled_by_default() {
        let events = EventStreamConfig::default();
        assert!(events.enabled);
        assert_eq!(events.backend, "nats-jetstream");
    }

    #[test]
    fn trust_indexer_is_enabled_by_default() {
        let trust_indexer = TrustIndexerConfig::default();
        assert!(trust_indexer.enabled);
        assert_eq!(
            trust_indexer.endpoint.as_deref(),
            Some("http://127.0.0.1:8088")
        );
        assert_eq!(trust_indexer.fail_mode, "closed");
    }

    #[test]
    fn load_config_rejects_disabled_root_cdn_events() {
        let dir = tempdir().unwrap();
        let config_path = dir.path().join("root.toml");
        std::fs::write(
            &config_path,
            r#"
[server]
host = "127.0.0.1"
port = 8000
endpoint = "http://localhost:8000"

[cors]
allowed_origins = []

[node]
name = "Root Node"
role = "root"
did_semantic_code = "AGRT"

[security.admin]
mode = "static-token"
static_tokens = ["local-dev-admin-token"]

[events]
enabled = false
backend = "nats-jetstream"
endpoint = "nats://127.0.0.1:4222"
stream = "OAN_RESOURCE_PUBLICATION"
cdn_publish_subject = "oan.resource.cdn.publish.requested"

[paths]
data_dir = "../root"
keys_dir = "../root/keys"
bulletin_file = "../root/bulletin.json"
authorization_state_file = "../root/authorization-state.json"
request_nonce_file = "../root/request-nonces.json"
capability_tree_file = "../capability-tree.json"
"#,
        )
        .unwrap();
        let err = load_config(config_path.to_string_lossy().into_owned())
            .unwrap_err()
            .to_string();
        assert!(err.contains("root_cdn_event_stream_required"));
    }

    #[tokio::test]
    async fn cdn_publish_event_requires_authoritative_publication_cursor() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let package = package_from_request(&state, &request);

        let err = build_cdn_publish_requested_event(&state, &package)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("publication_cursor_missing_for_job"));
    }

    #[tokio::test]
    async fn cdn_publish_event_failure_fallback_records_error_without_failing() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.events.enabled = true;
        state.config.events.failure_mode = "fallback".to_owned();
        state.event_publisher = EventPublisher::Failing("nats_down".to_owned());
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let package = package_from_request(&state, &request);
        persist_resource_acceptance(&state, &package).await.unwrap();

        publish_cdn_requested_event_for_package(&state, &package)
            .await
            .unwrap();
        let runtime = state.event_runtime.lock().unwrap().clone();
        assert_eq!(runtime.publish_failure_count, 1);
        assert_eq!(runtime.last_error.as_deref(), Some("nats_down"));
    }

    #[tokio::test]
    async fn cdn_publish_event_failure_closed_returns_error() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.config.events.enabled = true;
        state.config.events.failure_mode = "closed".to_owned();
        state.event_publisher = EventPublisher::Failing("nats_down".to_owned());
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let package = package_from_request(&state, &request);
        persist_resource_acceptance(&state, &package).await.unwrap();

        let err = publish_cdn_requested_event_for_package(&state, &package)
            .await
            .unwrap_err();
        assert_eq!(err.to_string(), "nats_down");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn api_status_counts_cdn_jobs_without_root_db_publisher_progress() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let _ = verify_resource_and_publish(State(state.clone()), Json(request))
            .await
            .unwrap();
        append_event(
            &state,
            BulletinEventType::CdnServiceInfoUpdated,
            &state.root_did.clone(),
            json!({"baseUrl": "http://127.0.0.1:1"}),
        )
        .unwrap();

        let status = api_status(State(state.clone())).await.unwrap();
        assert_eq!(status.0["statusBackend"], "sqlite");
        assert_eq!(status.0["cdnQueueCount"], 1);
        assert_eq!(status.0["cdnReadyQueueCount"], 1);
        assert_eq!(status.0["cdnActiveQueueCount"], 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn api_status_reuses_short_lived_database_count_cache() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);

        let first_request = resource_verify_request_with_version(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
            "1",
        );
        persist_resource_acceptance(&state, &package_from_request(&state, &first_request))
            .await
            .unwrap();

        let first = api_status(State(state.clone())).await.unwrap();
        assert_eq!(first.0["latestVersionCount"], 1);
        assert_eq!(first.0["cdnReadyQueueCount"], 1);

        let second_request = resource_verify_request_with_version(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
            "2",
        );
        persist_resource_acceptance(&state, &package_from_request(&state, &second_request))
            .await
            .unwrap();

        let refreshed = api_status(State(state.clone())).await.unwrap();
        assert_eq!(refreshed.0["latestVersionCount"], 1);
        assert_eq!(refreshed.0["cdnReadyQueueCount"], 2);

        let cached = api_status(State(state)).await.unwrap();
        assert_eq!(cached.0["cdnReadyQueueCount"], 2);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sqlite_marks_multiple_cdn_jobs_published_in_one_batch() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        for version in ["1", "2"] {
            let request = resource_verify_request_with_version(
                &state,
                &registrar_key,
                &resource_key,
                PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
                version,
            );
            let _ = verify_resource_and_publish(State(state.clone()), Json(request))
                .await
                .unwrap();
        }

        let before = api_status(State(state.clone())).await.unwrap();
        assert_eq!(before.0["cdnQueueCount"], 2);
        let auth = current_authorization_state(&state);
        repository::complete_cdn_publication_jobs_impl(
            &state,
            &[
                CdnPublicationJobCompletionRef {
                    job_key: format!("{}:{}", resource_did(), "1"),
                    publication_cursor: None,
                    resource_did: None,
                    package_version: None,
                    package_hash: None,
                },
                CdnPublicationJobCompletionRef {
                    job_key: format!("{}:{}", resource_did(), "2"),
                    publication_cursor: None,
                    resource_did: None,
                    package_version: None,
                    package_hash: None,
                },
            ],
            &auth.discovery_nodes,
            &state.tag_tree,
        )
        .await
        .unwrap();
        invalidate_status_counts_cache(&state);

        let after = api_status(State(state)).await.unwrap();
        assert_eq!(after.0["cdnQueueCount"], 0);
        assert_eq!(after.0["cdnReadyQueueCount"], 0);
        assert_eq!(after.0["cdnActiveQueueCount"], 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn api_cdn_publication_jobs_packages_returns_batch_packages() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state
            .config
            .security
            .admin
            .static_tokens
            .push("test-admin-token".to_owned());
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let package = package_from_request(&state, &request);
        persist_resource_acceptance(&state, &package).await.unwrap();

        let response = api_cdn_publication_jobs_packages(
            HeaderMap::from_iter([(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_str("Bearer test-admin-token").unwrap(),
            )]),
            State(state),
            Json(CdnPublicationJobsPackageRequest {
                jobs: vec![CdnPublicationJobRef {
                    job_key: format!("{}:{}", package.resource_did, package.package_version),
                }],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["status"], "ok");
        assert_eq!(response.0["requestedCount"], 1);
        assert_eq!(response.0["foundCount"], 1);
        assert_eq!(
            response.0["items"][0]["jobKey"],
            format!("{}:{}", package.resource_did, package.package_version)
        );
        assert_eq!(response.0["items"][0]["resourceDid"], package.resource_did);
        assert_eq!(
            response.0["items"][0]["packageVersion"],
            package.package_version
        );
        assert_eq!(response.0["items"][0]["packageHash"], package.package_hash);
        assert_eq!(
            response.0["items"][0]["didDocumentHash"],
            package.did_document_hash
        );
        assert_eq!(
            response.0["items"][0]["metadataHash"],
            package.metadata_hash
        );
        assert_eq!(
            response.0["items"][0]["package"]["resourceDid"],
            package.resource_did
        );
        assert!(
            response.0["items"][0]["publicationCursor"]
                .as_i64()
                .unwrap()
                > 0
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn api_mark_published_advances_authorized_discovery_targets() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.tag_tree = openagenet_test_tag_tree();
        state
            .config
            .security
            .admin
            .static_tokens
            .push("test-admin-token".to_owned());
        let registrar_key = generate_ed25519_keypair();
        let discovery_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint_and_domains(
            &state,
            &discovery_key,
            "http://127.0.0.1:1",
            vec!["technology.software_engineering".to_owned()],
        );
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let mut package = package_from_request(&state, &request);
        package.metadata.capability_tags = vec!["openagenet.local.agent".to_owned()];
        package.metadata.authorized_domains = vec!["technology.software_engineering".to_owned()];
        persist_resource_acceptance(&state, &package).await.unwrap();

        let response = api_mark_cdn_publication_jobs_published(
            HeaderMap::from_iter([(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!(
                    "Bearer {}",
                    state.config.security.admin.static_tokens[0]
                ))
                .unwrap(),
            )]),
            State(state.clone()),
            Json(MarkCdnPublicationJobsPublishedRequest {
                jobs: vec![CdnPublicationJobCompletionRef {
                    job_key: format!("{}:{}", package.resource_did, package.package_version),
                    publication_cursor: None,
                    resource_did: None,
                    package_version: None,
                    package_hash: None,
                }],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["status"], "ok");
        assert_eq!(response.0["markedCount"], 1);
        assert_eq!(response.0["advancedDiscoveryCount"], 1);
        let targets = read_discovery_target_states(&state).await.unwrap();
        assert_eq!(targets.len(), 1);
        assert!(targets[0].pending_cursor > targets[0].delivered_cursor);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn api_mark_published_accepts_minimal_job_key_only_payload() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.tag_tree = openagenet_test_tag_tree();
        state
            .config
            .security
            .admin
            .static_tokens
            .push("test-admin-token".to_owned());
        let registrar_key = generate_ed25519_keypair();
        let discovery_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint_and_domains(
            &state,
            &discovery_key,
            "http://127.0.0.1:1",
            vec!["technology.software_engineering".to_owned()],
        );
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let mut package = package_from_request(&state, &request);
        package.metadata.capability_tags = vec!["openagenet.local.agent".to_owned()];
        package.metadata.authorized_domains = vec!["technology.software_engineering".to_owned()];
        persist_resource_acceptance(&state, &package).await.unwrap();

        let response = api_mark_cdn_publication_jobs_published(
            HeaderMap::from_iter([(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!(
                    "Bearer {}",
                    state.config.security.admin.static_tokens[0]
                ))
                .unwrap(),
            )]),
            State(state.clone()),
            Json(MarkCdnPublicationJobsPublishedRequest {
                jobs: vec![CdnPublicationJobCompletionRef {
                    job_key: format!("{}:{}", package.resource_did, package.package_version),
                    publication_cursor: None,
                    resource_did: None,
                    package_version: None,
                    package_hash: None,
                }],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["status"], "ok");
        assert_eq!(response.0["markedCount"], 1);
        assert_eq!(response.0["advancedDiscoveryCount"], 1);
        assert!(response.0["timing"]["fetchElapsedMs"].as_u64().is_some());
        assert!(response.0["timing"]["fetchSqlElapsedMs"].as_u64().is_some());
        assert!(response.0["timing"]["watermarkMatchElapsedMs"]
            .as_u64()
            .is_some());
        assert!(response.0["timing"]["storeItemsElapsedMs"]
            .as_u64()
            .is_some());
        assert!(response.0["timing"]["upsertTargetsElapsedMs"]
            .as_u64()
            .is_some());
        assert!(response.0["timing"]["deleteJobsElapsedMs"]
            .as_u64()
            .is_some());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn api_mark_published_is_idempotent_for_repeated_completion() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.tag_tree = openagenet_test_tag_tree();
        state
            .config
            .security
            .admin
            .static_tokens
            .push("test-admin-token".to_owned());
        let registrar_key = generate_ed25519_keypair();
        let discovery_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint_and_domains(
            &state,
            &discovery_key,
            "http://127.0.0.1:1",
            vec!["technology.software_engineering".to_owned()],
        );
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let mut package = package_from_request(&state, &request);
        package.metadata.capability_tags = vec!["openagenet.local.agent".to_owned()];
        package.metadata.authorized_domains = vec!["technology.software_engineering".to_owned()];
        persist_resource_acceptance(&state, &package).await.unwrap();
        let payload = Json(MarkCdnPublicationJobsPublishedRequest {
            jobs: vec![CdnPublicationJobCompletionRef {
                job_key: format!("{}:{}", package.resource_did, package.package_version),
                publication_cursor: None,
                resource_did: None,
                package_version: None,
                package_hash: None,
            }],
        });
        let headers = HeaderMap::from_iter([(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!(
                "Bearer {}",
                state.config.security.admin.static_tokens[0]
            ))
            .unwrap(),
        )]);

        let first = api_mark_cdn_publication_jobs_published(
            headers.clone(),
            State(state.clone()),
            payload.clone(),
        )
        .await
        .unwrap();
        let second =
            api_mark_cdn_publication_jobs_published(headers, State(state.clone()), payload)
                .await
                .unwrap();

        assert_eq!(first.0["status"], "ok");
        assert_eq!(first.0["markedCount"], 1);
        assert_eq!(first.0["advancedDiscoveryCount"], 1);
        assert_eq!(second.0["status"], "ok");
        assert_eq!(second.0["markedCount"], 1);
        assert_eq!(second.0["advancedDiscoveryCount"], 0);
        let targets = read_discovery_target_states(&state).await.unwrap();
        assert_eq!(targets.len(), 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn api_mark_published_accepts_and_validates_enriched_completion_payload() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.tag_tree = openagenet_test_tag_tree();
        state
            .config
            .security
            .admin
            .static_tokens
            .push("test-admin-token".to_owned());
        let registrar_key = generate_ed25519_keypair();
        let discovery_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint_and_domains(
            &state,
            &discovery_key,
            "http://127.0.0.1:1",
            vec!["technology.software_engineering".to_owned()],
        );
        let mut package = package_from_request(
            &state,
            &resource_verify_request(
                &state,
                &registrar_key,
                &resource_key,
                PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
            ),
        );
        package.metadata.capability_tags = vec!["openagenet.local.agent".to_owned()];
        package.metadata.authorized_domains = vec!["technology.software_engineering".to_owned()];
        persist_resource_acceptance(&state, &package).await.unwrap();
        let job_key = format!("{}:{}", package.resource_did, package.package_version);
        let cursors = publication_cursors_for_jobs(&state, std::slice::from_ref(&job_key))
            .await
            .unwrap();
        let publication_cursor = *cursors.get(&job_key).unwrap();

        let response = api_mark_cdn_publication_jobs_published(
            HeaderMap::from_iter([(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!(
                    "Bearer {}",
                    state.config.security.admin.static_tokens[0]
                ))
                .unwrap(),
            )]),
            State(state.clone()),
            Json(MarkCdnPublicationJobsPublishedRequest {
                jobs: vec![CdnPublicationJobCompletionRef {
                    job_key,
                    publication_cursor: Some(publication_cursor),
                    resource_did: Some(package.resource_did.clone()),
                    package_version: Some(package.package_version.clone()),
                    package_hash: Some(package.package_hash.clone()),
                }],
            }),
        )
        .await
        .unwrap();

        assert_eq!(response.0["status"], "ok");
        assert_eq!(response.0["markedCount"], 1);
        assert_eq!(response.0["advancedDiscoveryCount"], 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn api_mark_published_rejects_unknown_job() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.tag_tree = openagenet_test_tag_tree();
        state
            .config
            .security
            .admin
            .static_tokens
            .push("test-admin-token".to_owned());
        let registrar_key = generate_ed25519_keypair();
        let discovery_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint_and_domains(
            &state,
            &discovery_key,
            "http://127.0.0.1:1",
            vec!["technology.software_engineering".to_owned()],
        );
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let mut package = package_from_request(&state, &request);
        package.metadata.capability_tags = vec!["openagenet.local.agent".to_owned()];
        package.metadata.authorized_domains = vec!["technology.software_engineering".to_owned()];
        persist_resource_acceptance(&state, &package).await.unwrap();

        let err = api_mark_cdn_publication_jobs_published(
            HeaderMap::from_iter([(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!(
                    "Bearer {}",
                    state.config.security.admin.static_tokens[0]
                ))
                .unwrap(),
            )]),
            State(state),
            Json(MarkCdnPublicationJobsPublishedRequest {
                jobs: vec![CdnPublicationJobCompletionRef {
                    job_key: "did:oan:AGUS:missing:9.9.9".to_owned(),
                    publication_cursor: None,
                    resource_did: None,
                    package_version: None,
                    package_hash: None,
                }],
            }),
        )
        .await
        .unwrap_err();

        assert_eq!(err.status, StatusCode::BAD_REQUEST);
        assert!(err.message.contains("unknown_cdn_publication_job"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authorized_summary_items_include_matching_domain_only() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.tag_tree = openagenet_test_tag_tree();
        let registrar_key = generate_ed25519_keypair();
        let discovery_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint_and_domains(
            &state,
            &discovery_key,
            "http://127.0.0.1:1",
            vec!["technology.software_engineering".to_owned()],
        );

        let matching_request = resource_verify_request_with_version(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
            "1",
        );
        let mut matching = package_from_request(&state, &matching_request);
        matching.metadata.capability_tags = vec!["openagenet.local.agent".to_owned()];
        matching.metadata.authorized_domains = vec!["technology.software_engineering".to_owned()];
        persist_resource_acceptance(&state, &matching)
            .await
            .unwrap();

        let unassigned_request = resource_verify_request_with_version(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
            "2",
        );
        let mut unassigned = package_from_request(&state, &unassigned_request);
        unassigned.metadata.capability_tags = vec!["unassigned.openagenet.local.agent".to_owned()];
        unassigned.metadata.authorized_domains =
            vec!["sports_and_fitness.sports_technology".to_owned()];
        persist_resource_acceptance(&state, &unassigned)
            .await
            .unwrap();

        let package_rows = resource_packages_for_jobs(
            &state,
            &[
                format!("{}:{}", matching.resource_did, matching.package_version),
                format!("{}:{}", unassigned.resource_did, unassigned.package_version),
            ],
        )
        .await
        .unwrap()
        .into_values()
        .collect::<Vec<_>>();
        let auth = current_authorization_state(&state);
        let notification_items = repository::discovery_notification_targets_for_authorized_rows(
            &package_rows,
            &auth.discovery_nodes,
            &state.tag_tree,
        );
        let target_cursors = repository::discovery_target_cursors_from_items(&notification_items);
        let completion = repository::complete_cdn_publication_jobs_impl(
            &state,
            &[
                CdnPublicationJobCompletionRef {
                    job_key: format!("{}:{}", matching.resource_did, matching.package_version),
                    publication_cursor: None,
                    resource_did: None,
                    package_version: None,
                    package_hash: None,
                },
                CdnPublicationJobCompletionRef {
                    job_key: format!("{}:{}", unassigned.resource_did, unassigned.package_version),
                    publication_cursor: None,
                    resource_did: None,
                    package_version: None,
                    package_hash: None,
                },
            ],
            &auth.discovery_nodes,
            &state.tag_tree,
        )
        .await
        .unwrap();
        assert_eq!(completion.advanced_discovery_count, target_cursors.len());
        let items = authorized_discovery_summary_items(&state, discovery_did(), 0, i64::MAX)
            .await
            .unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0].package_version, "1");
        assert_eq!(items[0].capability_tags, vec!["openagenet.local.agent"]);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn discovery_notification_targets_for_package_rows_matches_authorized_domains() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.tag_tree = openagenet_test_tag_tree();
        let registrar_key = generate_ed25519_keypair();
        let discovery_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint_and_domains(
            &state,
            &discovery_key,
            "http://127.0.0.1:1",
            vec!["technology.software_engineering".to_owned()],
        );

        let request = resource_verify_request_with_version(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
            "1",
        );
        let mut package = package_from_request(&state, &request);
        package.metadata.capability_tags = vec!["openagenet.local.agent".to_owned()];
        package.metadata.authorized_domains = vec!["technology.software_engineering".to_owned()];
        persist_resource_acceptance(&state, &package).await.unwrap();
        let job_key = format!("{}:{}", package.resource_did, package.package_version);
        let package_rows = resource_packages_for_jobs(&state, &[job_key])
            .await
            .unwrap()
            .into_values()
            .collect::<Vec<_>>();

        let auth = current_authorization_state(&state);
        let items = repository::discovery_notification_targets_for_authorized_rows(
            &package_rows,
            &auth.discovery_nodes,
            &state.tag_tree,
        );

        assert_eq!(items.len(), 1);
        assert_eq!(items[0].discovery_did, discovery_did());
        assert_eq!(items[0].item.package_version, "1");
        assert_eq!(
            items[0].item.capability_tags,
            vec!["openagenet.local.agent"]
        );
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn discovery_notification_targets_ignore_matching_tags_without_domain_coverage() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.tag_tree = openagenet_test_tag_tree();
        let registrar_key = generate_ed25519_keypair();
        let discovery_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint_and_domains(
            &state,
            &discovery_key,
            "http://127.0.0.1:1",
            vec!["technology.software_engineering".to_owned()],
        );

        let request = resource_verify_request_with_version(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
            "1",
        );
        let mut package = package_from_request(&state, &request);
        package.metadata.capability_tags = vec!["openagenet.local.agent".to_owned()];
        package.metadata.authorized_domains =
            vec!["sports_and_fitness.sports_technology".to_owned()];

        let auth = current_authorization_state(&state);
        let items = repository::discovery_notification_targets_for_authorized_rows(
            &[(package, 1)],
            &auth.discovery_nodes,
            &state.tag_tree,
        );

        assert!(items.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn authorized_discovery_summary_reads_versions_when_notification_store_is_empty() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.tag_tree = openagenet_test_tag_tree();
        let registrar_key = generate_ed25519_keypair();
        let discovery_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint_and_domains(
            &state,
            &discovery_key,
            "http://127.0.0.1:1",
            vec!["technology.software_engineering".to_owned()],
        );

        let resource_key_a = generate_ed25519_keypair();
        let request_a = resource_verify_request_with_version(
            &state,
            &registrar_key,
            &resource_key_a,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
            "1",
        );
        let mut package_a = package_from_request(&state, &request_a);
        package_a.metadata.capability_tags = vec!["openagenet.local.agent".to_owned()];
        package_a.metadata.authorized_domains = vec!["technology.software_engineering".to_owned()];
        persist_resource_acceptance(&state, &package_a)
            .await
            .unwrap();

        let resource_key_b = generate_ed25519_keypair();
        let request_b = resource_verify_request_with_version(
            &state,
            &registrar_key,
            &resource_key_b,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
            "1",
        );
        let mut package_b = package_from_request(&state, &request_b);
        package_b.metadata.capability_tags = vec!["openagenet.local.agent".to_owned()];
        package_b.metadata.authorized_domains = vec!["technology.software_engineering".to_owned()];
        package_b.resource_did = "did:oan:AGSG:derivedsummarysecondresource".to_owned();
        package_b.did_document.id = package_b.resource_did.clone();
        if let Some(method) = package_b.did_document.verification_method.get_mut(0) {
            method.id = format!("{}#key-1", package_b.resource_did);
            method.controller = package_b.resource_did.clone();
        }
        package_b.did_document.authentication = vec![format!("{}#key-1", package_b.resource_did)];
        package_b.did_document.assertion_method = vec![format!("{}#key-1", package_b.resource_did)];
        package_b.metadata.resource_did = package_b.resource_did.clone();
        package_b.metadata.subject_did = Some(package_b.resource_did.clone());
        persist_resource_acceptance(&state, &package_b)
            .await
            .unwrap();

        let items = authorized_discovery_summary_items(&state, discovery_did(), 0, i64::MAX)
            .await
            .unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!(items[0].publication_cursor, 1);
        assert_eq!(items[1].publication_cursor, 2);
        assert_eq!(items[0].resource_did, package_a.resource_did);
        assert_eq!(items[1].resource_did, package_b.resource_did);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sqlite_acceptance_uses_database_without_hot_path_archive_files() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let response = verify_resource_and_publish(State(state.clone()), Json(request))
            .await
            .unwrap();

        assert_eq!(response.0["status"], "resource-verified-and-queued");
        assert!(!dir.path().join("resource-packages").exists());
        assert!(!dir.path().join("resources").exists());
        assert!(!dir.path().join("archive").exists());

        let detail = api_resource_version_detail(
            State(state.clone()),
            axum::extract::Path((resource_did().to_owned(), "1".to_owned())),
        )
        .await
        .unwrap();
        assert_eq!(detail.0["package"]["resourceDid"], resource_did());

        let latest = api_resource_detail(
            State(state.clone()),
            axum::extract::Path(resource_did().to_owned()),
        )
        .await
        .unwrap();
        assert_eq!(latest.0["package"]["resourceDid"], resource_did());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sqlite_publication_cursor_batch_query_reads_multiple_jobs() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        for version in ["1", "2"] {
            let request = resource_verify_request_with_version(
                &state,
                &registrar_key,
                &resource_key,
                PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
                version,
            );
            let _ = verify_resource_and_publish(State(state.clone()), Json(request))
                .await
                .unwrap();
        }

        let keys = vec![
            format!("{}:{}", resource_did(), "1"),
            format!("{}:{}", resource_did(), "2"),
            format!("{}:{}", resource_did(), "missing"),
            "malformed-job-key".to_owned(),
        ];
        let cursors = publication_cursors_for_jobs(&state, &keys).await.unwrap();
        assert_eq!(cursors.len(), 2);
        assert!(cursors[&keys[0]] < cursors[&keys[1]]);
        assert!(!cursors.contains_key(&keys[2]));
        assert!(!cursors.contains_key(&keys[3]));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn sqlite_watermark_batch_coalesces_discovery_updates() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let discovery_key = generate_ed25519_keypair();
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint(&state, &discovery_key, "http://127.0.0.1:1");

        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let metadata = build_resource_metadata(&request.submission).unwrap();
        let package = ResourcePackage {
            package_version: request.submission.package_version.clone(),
            resource_did: request.submission.resource_did.clone(),
            resource_type: request.submission.resource_type.clone(),
            did_document: request.submission.did_document.clone(),
            did_document_hash: request.submission.did_document_hash.clone(),
            metadata_hash: request.submission.metadata_hash.clone(),
            package_hash: request.submission.package_hash.clone(),
            hash_algorithm: request.submission.hash_algorithm.clone(),
            metadata,
            root_proof: RootProof {
                root_did: state.root_did.clone(),
                bulletin_event_hash: None,
                signature: None,
                package_claims: None,
                proof: None,
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                hash_algorithm: Some("sha256".to_owned()),
            },
            created_at: Utc::now(),
        };

        let advanced = advance_discovery_target_watermarks_batch(
            &state,
            &[(package.clone(), 7), (package, 11)],
        )
        .await
        .unwrap();
        assert_eq!(advanced, 1);
        let targets = read_discovery_target_states(&state).await.unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].pending_cursor, 11);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn api_status_counts_only_ready_discovery_targets() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let discovery_key = generate_ed25519_keypair();
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint(&state, &discovery_key, "http://127.0.0.1:1");
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let mut metadata = build_resource_metadata(&request.submission).unwrap();
        metadata.capability_tags = vec!["legal.contract.review".to_owned()];
        let package = ResourcePackage {
            package_version: request.submission.package_version.clone(),
            resource_did: request.submission.resource_did.clone(),
            resource_type: request.submission.resource_type.clone(),
            did_document: request.submission.did_document.clone(),
            did_document_hash: request.submission.did_document_hash.clone(),
            metadata_hash: request.submission.metadata_hash.clone(),
            package_hash: request.submission.package_hash.clone(),
            hash_algorithm: request.submission.hash_algorithm.clone(),
            metadata,
            root_proof: RootProof {
                root_did: state.root_did.clone(),
                bulletin_event_hash: None,
                signature: None,
                package_claims: None,
                proof: None,
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                hash_algorithm: Some("sha256".to_owned()),
            },
            created_at: Utc::now(),
        };
        let advanced = advance_discovery_target_watermarks_batch(&state, &[(package, 42)])
            .await
            .unwrap();
        assert_eq!(advanced, 1);

        let initial_status = api_status(State(state.clone())).await.unwrap();
        assert_eq!(initial_status.0["discoveryQueueCount"], 1);
        assert_eq!(initial_status.0["discoveryReadyQueueCount"], 1);
        assert_eq!(initial_status.0["discoveryPendingQueueCount"], 1);

        let failed = run_discovery_notify_cycle(&state).await.unwrap();
        assert_eq!(failed["claimedTargetCount"], 1);
        assert_eq!(failed["targetCount"], 1);
        assert_eq!(failed["successCount"], 0);
        assert_eq!(failed["notifiedCount"], 0);
        assert_eq!(failed["failedCount"], 1);
        assert!(failed["elapsedMs"].as_u64().is_some());
        assert_eq!(failed["claimedCursorLag"], 42);
        assert_eq!(failed["readyQueueDepthBefore"], 1);
        assert_eq!(failed["readyQueueDepthAfter"], 0);
        assert!(failed["concurrency"].as_u64().unwrap_or_default() >= 1);

        let status = api_status(State(state.clone())).await.unwrap();
        assert_eq!(status.0["statusBackend"], "sqlite");
        assert_eq!(status.0["discoveryQueueCount"], 0);
        assert_eq!(status.0["discoveryReadyQueueCount"], 0);
        assert_eq!(status.0["discoveryPendingQueueCount"], 1);

        let no_progress = run_discovery_notify_cycle(&state).await.unwrap();
        assert_eq!(no_progress["claimedTargetCount"], 0);
        assert_eq!(no_progress["targetCount"], 0);
        assert_eq!(no_progress["drainRatePerSec"], 0.0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_discovery_notify_cycle_notifies_active_discovery_and_reports_metrics() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let discovery_key = generate_ed25519_keypair();
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();

        async fn sync_handler(Json(_payload): Json<Value>) -> Json<Value> {
            Json(json!({"status": "synced", "syncedResourceCount": 1}))
        }
        let app = Router::new().route("/discovery/resources/sync-authorized", post(sync_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint(&state, &discovery_key, &format!("http://{addr}"));
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let metadata = build_resource_metadata(&request.submission).unwrap();
        let package = ResourcePackage {
            package_version: request.submission.package_version.clone(),
            resource_did: request.submission.resource_did.clone(),
            resource_type: request.submission.resource_type.clone(),
            did_document: request.submission.did_document.clone(),
            did_document_hash: request.submission.did_document_hash.clone(),
            metadata_hash: request.submission.metadata_hash.clone(),
            package_hash: request.submission.package_hash.clone(),
            hash_algorithm: request.submission.hash_algorithm.clone(),
            metadata,
            root_proof: RootProof {
                root_did: state.root_did.clone(),
                bulletin_event_hash: None,
                signature: None,
                package_claims: None,
                proof: None,
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                hash_algorithm: Some("sha256".to_owned()),
            },
            created_at: Utc::now(),
        };
        advance_discovery_target_watermarks_batch(&state, &[(package, 7)])
            .await
            .unwrap();

        let result = run_discovery_notify_cycle(&state).await.unwrap();
        assert_eq!(result["claimedTargetCount"], 1);
        assert_eq!(result["targetCount"], 1);
        assert_eq!(result["successCount"], 1);
        assert_eq!(result["notifiedCount"], 1);
        assert_eq!(result["failedCount"], 0);
        assert!(result["elapsedMs"].as_u64().is_some());
        assert!(result["drainRatePerSec"].as_f64().unwrap_or_default() > 0.0);
        assert_eq!(result["claimedCursorLag"], 7);
        assert_eq!(result["readyQueueDepthBefore"], 1);
        assert_eq!(result["readyQueueDepthAfter"], 0);
        assert_eq!(result["targets"][0]["deliveredCursor"], 7);

        let status = api_status(State(state)).await.unwrap();
        assert_eq!(status.0["discoveryPendingQueueCount"], 0);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_discovery_notify_cycle_keeps_partial_progress_on_event_path() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let discovery_key = generate_ed25519_keypair();
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();

        async fn sync_handler(Json(payload): Json<Value>) -> Json<Value> {
            let to_cursor = payload
                .get("cursorHint")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            Json(json!({
                "status": "synced",
                "syncedResourceCount": 1,
                "toCursor": to_cursor.saturating_sub(1),
                "cursorLag": 1,
                "rejectedCount": 0
            }))
        }
        let app = Router::new().route("/discovery/resources/sync-authorized", post(sync_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint(&state, &discovery_key, &format!("http://{addr}"));
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let metadata = build_resource_metadata(&request.submission).unwrap();
        let package = ResourcePackage {
            package_version: request.submission.package_version.clone(),
            resource_did: request.submission.resource_did.clone(),
            resource_type: request.submission.resource_type.clone(),
            did_document: request.submission.did_document.clone(),
            did_document_hash: request.submission.did_document_hash.clone(),
            metadata_hash: request.submission.metadata_hash.clone(),
            package_hash: request.submission.package_hash.clone(),
            hash_algorithm: request.submission.hash_algorithm.clone(),
            metadata,
            root_proof: RootProof {
                root_did: state.root_did.clone(),
                bulletin_event_hash: None,
                signature: None,
                package_claims: None,
                proof: None,
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                hash_algorithm: Some("sha256".to_owned()),
            },
            created_at: Utc::now(),
        };
        advance_discovery_target_watermarks_batch(&state, &[(package, 7)])
            .await
            .unwrap();

        let result = run_discovery_notify_cycle(&state).await.unwrap();
        assert_eq!(result["successCount"], 1);
        assert_eq!(result["failedCount"], 0);
        assert_eq!(result["carryForwardCount"], 1);
        assert_eq!(result["targets"][0]["partialProgress"], true);

        let status = api_status(State(state)).await.unwrap();
        assert_eq!(status.0["discoveryReadyQueueCount"], 1);
        assert_eq!(status.0["discoveryPendingQueueCount"], 1);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn run_discovery_notify_cycle_sends_effective_max_publications() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.tag_tree = openagenet_test_tag_tree();
        state.config.security.workers.discovery_batch_size = 100;
        state.config.security.workers.discovery_concurrency = 4;
        let payloads = Arc::new(Mutex::new(Vec::<Value>::new()));
        let captured_payloads = payloads.clone();
        let app = Router::new().route(
            "/discovery/resources/sync-authorized",
            post(move |Json(payload): Json<Value>| {
                let captured_payloads = captured_payloads.clone();
                async move {
                    captured_payloads.lock().unwrap().push(payload.clone());
                    let to_cursor = payload
                        .get("cursorHint")
                        .and_then(Value::as_i64)
                        .unwrap_or_default();
                    Json(json!({"status": "synced", "toCursor": to_cursor}))
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let discovery_key = generate_ed25519_keypair();
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint(&state, &discovery_key, &format!("http://{addr}"));
        for version in 1..=450 {
            let request = resource_verify_request_with_version(
                &state,
                &registrar_key,
                &resource_key,
                PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
                &version.to_string(),
            );
            let mut package = package_from_request(&state, &request);
            package.metadata.capability_tags = vec!["openagenet.local.agent".to_owned()];
            package.metadata.authorized_domains = vec!["*".to_owned()];
            persist_resource_acceptance(&state, &package).await.unwrap();
        }
        sync_discovery_target_state(&state, discovery_did(), "active").unwrap();

        let result = run_discovery_notify_cycle(&state).await.unwrap();

        assert_eq!(result["successCount"], 1);
        let payloads = payloads.lock().unwrap();
        let payload = payloads.first().expect("sync payload should be captured");
        assert_eq!(payload["maxPublications"], 400);
        assert_eq!(payload["items"].as_array().unwrap().len(), 400);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn discovery_worker_event_wakes_progress_without_waiting_for_timer() {
        let dir = tempdir().unwrap();
        let mut state = app_state_with_sqlite(dir.path()).await;
        state.tag_tree = openagenet_test_tag_tree();
        state.config.security.workers.discovery_interval_ms = 60_000;
        state
            .config
            .security
            .admin
            .static_tokens
            .push("test-admin-token".to_owned());

        async fn sync_handler(Json(_payload): Json<Value>) -> Json<Value> {
            Json(json!({"status": "synced", "syncedResourceCount": 1, "toCursor": 1}))
        }
        let app = Router::new().route("/discovery/resources/sync-authorized", post(sync_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        spawn_root_background_workers(state.clone());

        let registrar_key = generate_ed25519_keypair();
        let discovery_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();
        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint_and_domains(
            &state,
            &discovery_key,
            &format!("http://{addr}"),
            vec!["technology.software_engineering".to_owned()],
        );
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let mut package = package_from_request(&state, &request);
        package.metadata.capability_tags = vec!["openagenet.local.agent".to_owned()];
        package.metadata.authorized_domains = vec!["technology.software_engineering".to_owned()];
        persist_resource_acceptance(&state, &package).await.unwrap();

        let _response = api_mark_cdn_publication_jobs_published(
            HeaderMap::from_iter([(
                axum::http::header::AUTHORIZATION,
                HeaderValue::from_str(&format!(
                    "Bearer {}",
                    state.config.security.admin.static_tokens[0]
                ))
                .unwrap(),
            )]),
            State(state.clone()),
            Json(MarkCdnPublicationJobsPublishedRequest {
                jobs: vec![CdnPublicationJobCompletionRef {
                    job_key: format!("{}:{}", package.resource_did, package.package_version),
                    publication_cursor: None,
                    resource_did: None,
                    package_version: None,
                    package_hash: None,
                }],
            }),
        )
        .await
        .unwrap();

        let success = tokio::time::timeout(std::time::Duration::from_secs(3), async {
            loop {
                let status = api_status(State(state.clone())).await.unwrap();
                let runtime = state.worker_runtime.lock().unwrap().clone();
                if status.0["discoveryPendingQueueCount"] == 0
                    && runtime.discovery_event_trigger_count > 0
                    && runtime.discovery_last_progress_success_count > 0
                {
                    return runtime;
                }
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
            }
        })
        .await
        .expect("discovery worker should progress from event wakeup before timer");

        assert_eq!(success.discovery_timer_trigger_count, 0);
        assert!(success.discovery_event_trigger_count > 0);
    }

    #[test]
    fn worker_event_signal_count_is_not_lost_when_signaled_multiple_times() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());

        signal_worker_event(&state, true);
        signal_worker_event(&state, true);

        let first_delay = take_worker_event_delay_ms(&state, true);
        let second_delay = take_worker_event_delay_ms(&state, true);
        let third_delay = take_worker_event_delay_ms(&state, true);

        assert!(first_delay.is_some());
        assert!(second_delay.is_some());
        assert!(third_delay.is_none());
    }

    #[test]
    fn adaptive_worker_drain_only_continues_when_ready_work_remains() {
        let cdn_continue = json!({
            "attemptedCount": 8,
            "publishedCount": 6,
            "failedCount": 0,
            "markedPublishedCount": 6,
            "markedRetryCount": 0,
            "effectiveBatchSize": 8,
            "activeQueueDepthAfter": 1,
            "readyQueueDepthAfter": 2
        });
        let cdn_retry_continue = json!({
            "attemptedCount": 8,
            "publishedCount": 0,
            "failedCount": 2,
            "markedPublishedCount": 0,
            "markedRetryCount": 2,
            "effectiveBatchSize": 8,
            "activeQueueDepthAfter": 0,
            "readyQueueDepthAfter": 3
        });
        let cdn_stop = json!({
            "attemptedCount": 3,
            "publishedCount": 0,
            "failedCount": 0,
            "markedPublishedCount": 0,
            "markedRetryCount": 0,
            "effectiveBatchSize": 8,
            "activeQueueDepthAfter": 0,
            "readyQueueDepthAfter": 0
        });
        let cdn_batch_limit_continue = json!({
            "attemptedCount": 8,
            "publishedCount": 8,
            "failedCount": 0,
            "markedPublishedCount": 8,
            "markedRetryCount": 0,
            "effectiveBatchSize": 8,
            "activeQueueDepthAfter": 0,
            "readyQueueDepthAfter": 0
        });
        let discovery_continue = json!({
            "claimedTargetCount": 1,
            "successCount": 1,
            "notifiedCount": 1,
            "failedCount": 0,
            "effectiveBatchSize": 4,
            "pendingQueueDepthAfter": 1,
            "readyQueueDepthAfter": 1
        });
        let discovery_retry_continue = json!({
            "claimedTargetCount": 2,
            "successCount": 0,
            "notifiedCount": 0,
            "failedCount": 1,
            "carryForwardCount": 0,
            "effectiveBatchSize": 4,
            "pendingQueueDepthAfter": 2,
            "readyQueueDepthAfter": 1
        });
        let discovery_carry_forward_continue = json!({
            "claimedTargetCount": 1,
            "successCount": 1,
            "notifiedCount": 1,
            "failedCount": 0,
            "carryForwardCount": 1,
            "effectiveBatchSize": 4,
            "pendingQueueDepthAfter": 0,
            "readyQueueDepthAfter": 0
        });
        let discovery_stop = json!({
            "claimedTargetCount": 1,
            "successCount": 1,
            "notifiedCount": 1,
            "failedCount": 0,
            "carryForwardCount": 0,
            "effectiveBatchSize": 4,
            "pendingQueueDepthAfter": 0,
            "readyQueueDepthAfter": 0
        });
        let discovery_batch_limit_continue = json!({
            "claimedTargetCount": 4,
            "successCount": 4,
            "notifiedCount": 4,
            "failedCount": 0,
            "effectiveBatchSize": 4,
            "pendingQueueDepthAfter": 0,
            "readyQueueDepthAfter": 0
        });

        assert!(cdn_cycle_made_progress(&cdn_continue));
        assert!(cdn_cycle_should_continue_immediately(&cdn_continue));
        assert!(cdn_cycle_should_continue_immediately(&cdn_retry_continue));
        assert!(cdn_cycle_should_continue_immediately(
            &cdn_batch_limit_continue
        ));
        assert!(!cdn_cycle_should_continue_immediately(&cdn_stop));
        assert!(discovery_cycle_made_progress(&discovery_continue));
        assert!(discovery_cycle_should_continue_immediately(
            &discovery_continue
        ));
        assert!(discovery_cycle_should_continue_immediately(
            &discovery_retry_continue
        ));
        assert!(discovery_cycle_should_continue_immediately(
            &discovery_carry_forward_continue
        ));
        assert!(discovery_cycle_should_continue_immediately(
            &discovery_batch_limit_continue
        ));
        assert!(!discovery_cycle_should_continue_immediately(
            &discovery_stop
        ));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn discovery_worker_signal_preserves_permit_when_sent_before_wait() {
        let dir = tempdir().unwrap();
        let state = app_state(dir.path());

        signal_worker_event(&state, false);

        tokio::time::timeout(
            std::time::Duration::from_millis(100),
            state.discovery_worker_notify.notified(),
        )
        .await
        .expect("discovery worker signal should retain a permit");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn discovery_worker_runtime_records_event_trigger_for_progress() {
        let dir = tempdir().unwrap();
        let state = app_state_with_sqlite(dir.path()).await;
        let discovery_key = generate_ed25519_keypair();
        let registrar_key = generate_ed25519_keypair();
        let resource_key = generate_ed25519_keypair();

        async fn sync_handler(Json(_payload): Json<Value>) -> Json<Value> {
            Json(json!({"status": "synced", "syncedResourceCount": 1}))
        }
        let app = Router::new().route("/discovery/resources/sync-authorized", post(sync_handler));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        authorize_registrar(&state, &registrar_key);
        authorize_discovery_with_endpoint(&state, &discovery_key, &format!("http://{addr}"));
        let request = resource_verify_request(
            &state,
            &registrar_key,
            &resource_key,
            PATH_ROOT_RESOURCES_VERIFY_AND_PUBLISH,
        );
        let metadata = build_resource_metadata(&request.submission).unwrap();
        let package = ResourcePackage {
            package_version: request.submission.package_version.clone(),
            resource_did: request.submission.resource_did.clone(),
            resource_type: request.submission.resource_type.clone(),
            did_document: request.submission.did_document.clone(),
            did_document_hash: request.submission.did_document_hash.clone(),
            metadata_hash: request.submission.metadata_hash.clone(),
            package_hash: request.submission.package_hash.clone(),
            hash_algorithm: request.submission.hash_algorithm.clone(),
            metadata,
            root_proof: RootProof {
                root_did: state.root_did.clone(),
                bulletin_event_hash: None,
                signature: None,
                package_claims: None,
                proof: None,
                crypto_suite: Some(CryptoSuite::Ed25519Sha256),
                hash_algorithm: Some("sha256".to_owned()),
            },
            created_at: Utc::now(),
        };
        advance_discovery_target_watermarks_batch(&state, &[(package, 7)])
            .await
            .unwrap();

        record_worker_trigger(&state, false, WorkerTriggerType::Event);
        let _ = run_discovery_notify_cycle(&state).await.unwrap();

        let status = api_status(State(state)).await.unwrap();
        assert_eq!(
            status.0["workerRuntime"]["discovery_last_progress_trigger_type"],
            "event"
        );
    }
}
