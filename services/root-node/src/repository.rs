// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use super::*;
use sqlx::Postgres;

const MAX_CDN_PUBLICATION_PACKAGE_BYTES: usize = 8 * 1024 * 1024;
const MAX_CDN_PUBLICATION_RESPONSE_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Default)]
pub(super) struct CdnPublicationBatchCompletion {
    pub marked_count: usize,
    pub stored_notification_count: usize,
    pub advanced_discovery_count: usize,
    pub fetch_elapsed_ms: u128,
    pub fetch_sql_elapsed_ms: u128,
    pub watermark_match_elapsed_ms: u128,
    pub update_elapsed_ms: u128,
    pub watermark_elapsed_ms: u128,
    pub store_items_elapsed_ms: u128,
    pub upsert_targets_elapsed_ms: u128,
    pub delete_jobs_elapsed_ms: u128,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PublicationProjectionRow {
    status: String,
    resource_did: String,
    package_version: String,
    publication_cursor: i64,
    package_hash: String,
    metadata_hash: String,
    did_document_hash: String,
    resource_type: String,
    capability_tags: Vec<String>,
    authorized_domains: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct PostgresDiscoveryNotificationItemRow<'a> {
    discovery_did: &'a str,
    publication_cursor: i64,
    resource_did: &'a str,
    package_version: &'a str,
    package_hash: &'a str,
    metadata_hash: &'a str,
    did_document_hash: &'a str,
    resource_type: &'a str,
    capability_tags_json: Vec<String>,
    authorized_domains_json: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
struct PostgresDiscoveryTargetCursorRow<'a> {
    discovery_did: &'a str,
    pending_cursor: i64,
}

pub(super) fn read_bulletin_from_store_impl(state: &AppState) -> Result<Bulletin> {
    if let Some(sqlite) = &state.sqlite {
        return block_on_sqlite(async {
            let rows = sqlx::query(&format!(
                "SELECT event_json FROM {ROOT_BULLETIN_EVENT_TABLE} ORDER BY sequence"
            ))
            .fetch_all(sqlite.pool())
            .await?;
            let mut events = Vec::with_capacity(rows.len());
            for row in rows {
                events.push(serde_json::from_str::<BulletinEvent>(
                    &row.get::<String, _>(0),
                )?);
            }
            Ok(Bulletin {
                version: "0.1.0".to_owned(),
                root_did: state.root_did.clone(),
                created_at: Utc::now(),
                events,
            })
        });
    }
    if let Some(postgres) = &state.postgres {
        return block_on_sqlite(async {
            let rows = sqlx::query(&format!(
                "SELECT event_json::text FROM {ROOT_BULLETIN_EVENT_TABLE} ORDER BY sequence"
            ))
            .fetch_all(postgres.pool())
            .await?;
            let mut events = Vec::with_capacity(rows.len());
            for row in rows {
                events.push(serde_json::from_str::<BulletinEvent>(
                    &row.get::<String, _>(0),
                )?);
            }
            Ok(Bulletin {
                version: "0.1.0".to_owned(),
                root_did: state.root_did.clone(),
                created_at: Utc::now(),
                events,
            })
        });
    }
    Ok(Bulletin {
        version: "0.1.0".to_owned(),
        root_did: state.root_did.clone(),
        created_at: Utc::now(),
        events: vec![],
    })
}

pub(super) fn latest_bulletin_event_impl(state: &AppState) -> Result<Option<BulletinEvent>> {
    if let Some(sqlite) = &state.sqlite {
        return block_on_sqlite(async {
            let row = sqlx::query(&format!(
                "SELECT event_json FROM {ROOT_BULLETIN_EVENT_TABLE} ORDER BY sequence DESC LIMIT 1"
            ))
            .fetch_optional(sqlite.pool())
            .await?;
            row.map(|row| {
                serde_json::from_str::<BulletinEvent>(&row.get::<String, _>(0))
                    .map_err(anyhow::Error::from)
            })
            .transpose()
        });
    }
    if let Some(postgres) = &state.postgres {
        return block_on_sqlite(async {
            let row = sqlx::query(&format!(
                "SELECT event_json::text FROM {ROOT_BULLETIN_EVENT_TABLE} ORDER BY sequence DESC LIMIT 1"
            ))
            .fetch_optional(postgres.pool())
            .await?;
            row.map(|row| {
                serde_json::from_str::<BulletinEvent>(&row.get::<String, _>(0))
                    .map_err(anyhow::Error::from)
            })
            .transpose()
        });
    }
    Ok(super::read_bulletin(state)?.events.into_iter().last())
}

pub(super) fn persist_bulletin_event_impl(state: &AppState, event: &BulletinEvent) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        let event_json = serde_json::to_string(event)?;
        let payload_json = serde_json::to_string(&event.core.payload)?;
        return block_on_sqlite(async {
            sqlx::query(&format!(
                r#"
                INSERT INTO {ROOT_BULLETIN_EVENT_TABLE}(sequence, event_type, subject_did, actor_did, payload_json, previous_hash, event_hash, event_json, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(sequence)
                DO UPDATE SET
                    event_type = excluded.event_type,
                    subject_did = excluded.subject_did,
                    actor_did = excluded.actor_did,
                    payload_json = excluded.payload_json,
                    previous_hash = excluded.previous_hash,
                    event_hash = excluded.event_hash,
                    event_json = excluded.event_json,
                    created_at = excluded.created_at
                "#
            ))
            .bind(event.core.sequence as i64)
            .bind(serde_json::to_value(&event.core.event_type)?.as_str().unwrap_or_default())
            .bind(&event.core.subject_did)
            .bind(&event.core.actor_did)
            .bind(payload_json)
            .bind(event.core.previous_hash.clone())
            .bind(&event.event_hash)
            .bind(event_json)
            .bind(event.core.created_at.to_rfc3339())
            .execute(sqlite.pool())
            .await?;
            Ok(())
        });
    }
    if let Some(postgres) = &state.postgres {
        let event_json = serde_json::to_string(event)?;
        let payload_json = serde_json::to_string(&event.core.payload)?;
        return block_on_sqlite(async {
            sqlx::query(&format!(
                r#"
                INSERT INTO {ROOT_BULLETIN_EVENT_TABLE}(sequence, event_type, subject_did, actor_did, payload_json, previous_hash, event_hash, event_json, created_at)
                VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8::jsonb, $9::timestamptz)
                ON CONFLICT(sequence)
                DO UPDATE SET
                    event_type = excluded.event_type,
                    subject_did = excluded.subject_did,
                    actor_did = excluded.actor_did,
                    payload_json = excluded.payload_json,
                    previous_hash = excluded.previous_hash,
                    event_hash = excluded.event_hash,
                    event_json = excluded.event_json,
                    created_at = excluded.created_at
                "#
            ))
            .bind(event.core.sequence as i64)
            .bind(serde_json::to_value(&event.core.event_type)?.as_str().unwrap_or_default())
            .bind(&event.core.subject_did)
            .bind(&event.core.actor_did)
            .bind(payload_json)
            .bind(event.core.previous_hash.clone())
            .bind(&event.event_hash)
            .bind(event_json)
            .bind(event.core.created_at.to_rfc3339())
            .execute(postgres.pool())
            .await?;
            Ok(())
        });
    }
    Ok(())
}

pub(super) async fn bootstrap_root_bulletin_from_json_impl(state: &AppState) -> Result<()> {
    let store = JsonStore::new(".");
    if !state.config.paths.bulletin_file.exists() {
        return Ok(());
    }
    let bulletin: Bulletin = store.read(&state.config.paths.bulletin_file)?;
    for event in &bulletin.events {
        persist_bulletin_event_impl(state, event)?;
    }
    Ok(())
}

#[derive(Debug)]
pub(super) struct ResourceVersionsPage {
    pub items: Vec<Value>,
    pub next_version: Option<String>,
    pub has_more: bool,
}

pub(super) async fn resource_versions_impl(
    state: &AppState,
    did: &str,
    after_version: Option<&str>,
    limit: u32,
) -> Result<ResourceVersionsPage> {
    let fetch_limit = i64::from(limit).saturating_add(1);
    if let Some(sqlite) = &state.sqlite {
        let rows = sqlx::query(&format!(
            r#"
            SELECT version, did_document_hash, metadata_hash, accepted_at
            FROM {ROOT_SUBJECT_VERSION_TABLE}
            WHERE subject_did = ? AND (? IS NULL OR version > ?)
            ORDER BY version
            LIMIT ?
            "#
        ))
        .bind(did)
        .bind(after_version)
        .bind(after_version)
        .bind(fetch_limit)
        .fetch_all(sqlite.pool())
        .await?;
        let mut items = rows
            .into_iter()
            .map(|row| {
                Ok::<_, anyhow::Error>(json!({
                    "packageVersion": row.get::<String, _>(0),
                    "didDocumentHash": row.get::<String, _>(1),
                    "metadataHash": row.get::<String, _>(2),
                    "acceptedAt": row.get::<String, _>(3),
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        let has_more = items.len() > limit as usize;
        if has_more {
            items.truncate(limit as usize);
        }
        return Ok(ResourceVersionsPage {
            next_version: if has_more {
                items
                    .last()
                    .and_then(|item| item["packageVersion"].as_str())
                    .map(ToOwned::to_owned)
            } else {
                None
            },
            has_more,
            items,
        });
    }
    if let Some(postgres) = &state.postgres {
        let rows = sqlx::query(&format!(
            r#"
            SELECT version, did_document_hash, metadata_hash,
                   to_char(accepted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
            FROM {ROOT_SUBJECT_VERSION_TABLE}
            WHERE subject_did = $1 AND ($2::text IS NULL OR version > $2)
            ORDER BY version
            LIMIT $3
            "#
        ))
        .bind(did)
        .bind(after_version)
        .bind(fetch_limit)
        .fetch_all(postgres.pool())
        .await?;
        let mut items = rows
            .into_iter()
            .map(|row| {
                Ok::<_, anyhow::Error>(json!({
                    "packageVersion": row.get::<String, _>(0),
                    "didDocumentHash": row.get::<String, _>(1),
                    "metadataHash": row.get::<String, _>(2),
                    "acceptedAt": row.get::<String, _>(3),
                }))
            })
            .collect::<Result<Vec<_>>>()?;
        let has_more = items.len() > limit as usize;
        if has_more {
            items.truncate(limit as usize);
        }
        return Ok(ResourceVersionsPage {
            next_version: if has_more {
                items
                    .last()
                    .and_then(|item| item["packageVersion"].as_str())
                    .map(ToOwned::to_owned)
            } else {
                None
            },
            has_more,
            items,
        });
    }
    Ok(ResourceVersionsPage {
        items: Vec::new(),
        next_version: None,
        has_more: false,
    })
}

#[derive(Debug)]
pub(super) struct BulletinEventsPage {
    pub items: Vec<Value>,
    pub next: Option<u64>,
    pub has_more: bool,
}

pub(super) fn bulletin_events_page_impl(
    state: &AppState,
    after: Option<u64>,
    limit: u32,
) -> Result<BulletinEventsPage> {
    let fetch_limit = i64::from(limit).saturating_add(1);
    block_on_sqlite(async {
        if let Some(sqlite) = &state.sqlite {
            let rows = sqlx::query(&format!(
                "SELECT event_json FROM {ROOT_BULLETIN_EVENT_TABLE}
                 WHERE (? IS NULL OR sequence > ?) ORDER BY sequence LIMIT ?"
            ))
            .bind(after.map(|value| value as i64))
            .bind(after.map(|value| value as i64))
            .bind(fetch_limit)
            .fetch_all(sqlite.pool())
            .await?;
            let mut items = rows
                .into_iter()
                .map(|row| {
                    serde_json::from_str::<Value>(&row.get::<String, _>(0))
                        .map_err(anyhow::Error::from)
                })
                .collect::<Result<Vec<_>>>()?;
            let has_more = items.len() > limit as usize;
            if has_more {
                items.truncate(limit as usize);
            }
            let next = items
                .last()
                .and_then(|item| item.get("core"))
                .and_then(|core| core.get("sequence"))
                .and_then(Value::as_u64);
            return Ok(BulletinEventsPage {
                items,
                next: if has_more { next } else { None },
                has_more,
            });
        }
        if let Some(postgres) = &state.postgres {
            let rows = sqlx::query(&format!(
                "SELECT event_json::text FROM {ROOT_BULLETIN_EVENT_TABLE}
                 WHERE ($1::bigint IS NULL OR sequence > $1) ORDER BY sequence LIMIT $2"
            ))
            .bind(after.map(|value| value as i64))
            .bind(fetch_limit)
            .fetch_all(postgres.pool())
            .await?;
            let mut items = rows
                .into_iter()
                .map(|row| {
                    serde_json::from_str::<Value>(&row.get::<String, _>(0))
                        .map_err(anyhow::Error::from)
                })
                .collect::<Result<Vec<_>>>()?;
            let has_more = items.len() > limit as usize;
            if has_more {
                items.truncate(limit as usize);
            }
            let next = items
                .last()
                .and_then(|item| item.get("core"))
                .and_then(|core| core.get("sequence"))
                .and_then(Value::as_u64);
            return Ok(BulletinEventsPage {
                items,
                next: if has_more { next } else { None },
                has_more,
            });
        }
        Ok(BulletinEventsPage {
            items: Vec::new(),
            next: None,
            has_more: false,
        })
    })
}

pub(super) async fn resource_version_detail_impl(
    state: &AppState,
    did: &str,
    version: &str,
) -> Result<Option<(ResourcePackage, String)>> {
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!(
            r#"
            SELECT package_json, accepted_at
            FROM {ROOT_SUBJECT_VERSION_TABLE}
            WHERE subject_did = ? AND version = ?
            "#
        ))
        .bind(did)
        .bind(version)
        .fetch_optional(sqlite.pool())
        .await?;
        return row
            .map(|row| {
                Ok((
                    serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0))?,
                    row.get::<String, _>(1),
                ))
            })
            .transpose();
    }
    if let Some(postgres) = &state.postgres {
        let row = sqlx::query(&format!(
            r#"
            SELECT package_json::text,
                   to_char(accepted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
            FROM {ROOT_SUBJECT_VERSION_TABLE}
            WHERE subject_did = $1 AND version = $2
            "#
        ))
        .bind(did)
        .bind(version)
        .fetch_optional(postgres.pool())
        .await?;
        return row
            .map(|row| {
                Ok((
                    serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0))?,
                    row.get::<String, _>(1),
                ))
            })
            .transpose();
    }
    Ok(None)
}

pub(super) async fn latest_resource_detail_impl(
    state: &AppState,
    did: &str,
) -> Result<Option<ResourcePackage>> {
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!(
            r#"
            SELECT versions.package_json
            FROM {ROOT_SUBJECT_LATEST_TABLE} AS latest
            JOIN {ROOT_SUBJECT_VERSION_TABLE} AS versions
              ON versions.subject_did = latest.subject_did
             AND versions.version = latest.current_version
            WHERE latest.subject_did = ?
            "#
        ))
        .bind(did)
        .fetch_optional(sqlite.pool())
        .await?;
        return row
            .map(|row| {
                serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0))
                    .map_err(Into::into)
            })
            .transpose();
    }
    if let Some(postgres) = &state.postgres {
        let row = sqlx::query(&format!(
            r#"
            SELECT versions.package_json::text
            FROM {ROOT_SUBJECT_LATEST_TABLE} AS latest
            JOIN {ROOT_SUBJECT_VERSION_TABLE} AS versions
              ON versions.subject_did = latest.subject_did
             AND versions.version = latest.current_version
            WHERE latest.subject_did = $1
            "#
        ))
        .bind(did)
        .fetch_optional(postgres.pool())
        .await?;
        return row
            .map(|row| {
                serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0))
                    .map_err(Into::into)
            })
            .transpose();
    }
    Ok(None)
}

pub(super) fn sync_discovery_target_state_impl(
    state: &AppState,
    did: &str,
    auth_status: &str,
) -> Result<()> {
    let did = did.to_owned();
    let auth_status = auth_status.to_owned();
    let now = Utc::now().to_rfc3339();
    if let Some(sqlite) = &state.sqlite {
        return block_on_sqlite(async {
            sqlx::query(&format!(
                r#"
                INSERT INTO {ROOT_DISCOVERY_TARGET_TABLE}(
                    discovery_did,
                    pending_cursor,
                    delivered_cursor,
                    status,
                    attempt_count,
                    lease_owner,
                    lease_expires_at,
                    next_attempt_at,
                    last_error,
                    updated_at
                )
                VALUES (
                    ?,
                    CASE
                        WHEN ? = 'active' THEN COALESCE((SELECT MAX(publication_cursor) FROM {ROOT_SUBJECT_VERSION_TABLE}), 0)
                        ELSE 0
                    END,
                    0,
                    ?,
                    0,
                    NULL,
                    NULL,
                    ?,
                    NULL,
                    ?
                )
                ON CONFLICT(discovery_did)
                DO UPDATE SET
                    status = excluded.status,
                    pending_cursor = CASE
                        WHEN excluded.status = 'active' THEN MAX({ROOT_DISCOVERY_TARGET_TABLE}.pending_cursor, excluded.pending_cursor)
                        ELSE {ROOT_DISCOVERY_TARGET_TABLE}.pending_cursor
                    END,
                    next_attempt_at = CASE
                        WHEN excluded.status = 'revoked' THEN {ROOT_DISCOVERY_TARGET_TABLE}.next_attempt_at
                        ELSE ?
                    END,
                    lease_owner = CASE
                        WHEN excluded.status = 'revoked' THEN {ROOT_DISCOVERY_TARGET_TABLE}.lease_owner
                        ELSE NULL
                    END,
                    lease_expires_at = CASE
                        WHEN excluded.status = 'revoked' THEN {ROOT_DISCOVERY_TARGET_TABLE}.lease_expires_at
                        ELSE NULL
                    END,
                    last_error = CASE
                        WHEN excluded.status = 'revoked' THEN {ROOT_DISCOVERY_TARGET_TABLE}.last_error
                        ELSE NULL
                    END,
                    updated_at = excluded.updated_at
                "#
            ))
            .bind(&did)
            .bind(&auth_status)
            .bind(&auth_status)
            .bind(&now)
            .bind(&now)
            .bind(&now)
            .execute(sqlite.pool())
            .await?;
            Ok(())
        });
    }
    if let Some(postgres) = &state.postgres {
        return block_on_sqlite(async {
            sqlx::query(&format!(
                r#"
                INSERT INTO {ROOT_DISCOVERY_TARGET_TABLE}(
                    discovery_did,
                    pending_cursor,
                    delivered_cursor,
                    status,
                    attempt_count,
                    lease_owner,
                    lease_expires_at,
                    next_attempt_at,
                    last_error,
                    updated_at
                )
                VALUES (
                    $1,
                    CASE
                        WHEN $2 = 'active' THEN COALESCE((SELECT MAX(publication_cursor) FROM {ROOT_SUBJECT_VERSION_TABLE}), 0)
                        ELSE 0
                    END,
                    0,
                    $2,
                    0,
                    NULL,
                    NULL,
                    $3::timestamptz,
                    NULL,
                    $4::timestamptz
                )
                ON CONFLICT(discovery_did)
                DO UPDATE SET
                    status = excluded.status,
                    pending_cursor = CASE
                        WHEN excluded.status = 'active' THEN GREATEST({ROOT_DISCOVERY_TARGET_TABLE}.pending_cursor, excluded.pending_cursor)
                        ELSE {ROOT_DISCOVERY_TARGET_TABLE}.pending_cursor
                    END,
                    next_attempt_at = CASE
                        WHEN excluded.status = 'revoked' THEN {ROOT_DISCOVERY_TARGET_TABLE}.next_attempt_at
                        ELSE $5::timestamptz
                    END,
                    lease_owner = CASE
                        WHEN excluded.status = 'revoked' THEN {ROOT_DISCOVERY_TARGET_TABLE}.lease_owner
                        ELSE NULL
                    END,
                    lease_expires_at = CASE
                        WHEN excluded.status = 'revoked' THEN {ROOT_DISCOVERY_TARGET_TABLE}.lease_expires_at
                        ELSE NULL
                    END,
                    last_error = CASE
                        WHEN excluded.status = 'revoked' THEN {ROOT_DISCOVERY_TARGET_TABLE}.last_error
                        ELSE NULL
                    END,
                    updated_at = excluded.updated_at
                "#
            ))
            .bind(&did)
            .bind(&auth_status)
            .bind(&now)
            .bind(&now)
            .bind(&now)
            .execute(postgres.pool())
            .await?;
            Ok(())
        });
    }
    Ok(())
}

pub(super) async fn persist_resource_acceptance_impl(
    state: &AppState,
    package: &ResourcePackage,
) -> Result<()> {
    let accepted_at = Utc::now();
    let resource_did = &package.resource_did;
    let version = package.package_version.trim();
    let operation = "upsert";
    if let Some(sqlite) = &state.sqlite {
        let package_json = serde_json::to_string(package)?;
        let archive_path = format!(
            "resources/{}/{}",
            did_to_file_name(resource_did).trim_end_matches(".json"),
            package.package_version
        );
        let package_job_key = format!("{resource_did}:{}", package.package_version);
        let now = accepted_at.to_rfc3339();
        let next_attempt_at = now.clone();
        let mut tx = sqlite.pool().begin().await?;

        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_SUBJECT_VERSION_TABLE}(subject_did, version, did_document_hash, metadata_hash, package_json, archive_path, accepted_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(subject_did, version)
            DO UPDATE SET
                did_document_hash = excluded.did_document_hash,
                metadata_hash = excluded.metadata_hash,
                package_json = excluded.package_json,
                archive_path = excluded.archive_path,
                accepted_at = excluded.accepted_at
            "#
        ))
        .bind(resource_did)
        .bind(version)
        .bind(&package.did_document_hash)
        .bind(&package.metadata_hash)
        .bind(&package_json)
        .bind(&archive_path)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_SUBJECT_LATEST_TABLE}(subject_did, current_version, did_document_hash, metadata_hash, operation, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(subject_did)
            DO UPDATE SET
                current_version = excluded.current_version,
                did_document_hash = excluded.did_document_hash,
                metadata_hash = excluded.metadata_hash,
                operation = excluded.operation,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(resource_did)
        .bind(version)
        .bind(&package.did_document_hash)
        .bind(&package.metadata_hash)
        .bind(operation)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        let publication_cursor = sqlx::query(&format!(
            "SELECT rowid FROM {ROOT_SUBJECT_VERSION_TABLE} WHERE subject_did = ? AND version = ?"
        ))
        .bind(resource_did)
        .bind(version)
        .fetch_one(&mut *tx)
        .await?
        .get::<i64, _>(0);

        sqlx::query(&format!(
            "UPDATE {ROOT_SUBJECT_VERSION_TABLE} SET publication_cursor = ? WHERE subject_did = ? AND version = ?"
        ))
        .bind(publication_cursor)
        .bind(resource_did)
        .bind(version)
        .execute(&mut *tx)
        .await?;

        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_CDN_JOB_TABLE}(job_key, payload_json, status, attempt_count, lease_owner, lease_expires_at, next_attempt_at, last_error)
            VALUES (?, ?, 'ready', 0, NULL, NULL, ?, NULL)
            ON CONFLICT(job_key)
            DO UPDATE SET
                payload_json = excluded.payload_json,
                status = 'ready',
                attempt_count = 0,
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = excluded.next_attempt_at,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            "#
        ))
        .bind(&package_job_key)
        .bind(&package_json)
        .bind(&next_attempt_at)
        .execute(&mut *tx)
        .await?;

        let event = CdnPublishRequestedEvent::new(CdnPublishRequestedEventInput {
            job_key: package_job_key.clone(),
            resource_did: package.resource_did.clone(),
            package_version: package.package_version.clone(),
            publication_cursor,
            root_did: state.root_did.clone(),
            package_hash: package.package_hash.clone(),
            did_document_hash: package.did_document_hash.clone(),
            metadata_hash: package.metadata_hash.clone(),
            created_at: accepted_at,
        });
        let event_json = serde_json::to_string(&event)?;
        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_CDN_OUTBOX_TABLE}(job_key, payload_json, status, attempt_count, lease_owner, lease_expires_at, next_attempt_at, last_error)
            VALUES (?, ?, 'ready', 0, NULL, NULL, ?, NULL)
            ON CONFLICT(job_key)
            DO UPDATE SET
                payload_json = excluded.payload_json,
                status = 'ready',
                attempt_count = 0,
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = excluded.next_attempt_at,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            "#
        ))
        .bind(&package_job_key)
        .bind(event_json)
        .bind(&next_attempt_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        let package_json = serde_json::to_string(package)?;
        let resource_type = serde_json::to_value(&package.resource_type)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "unknown".to_owned());
        let archive_path = format!(
            "resources/{}/{}",
            did_to_file_name(resource_did).trim_end_matches(".json"),
            package.package_version
        );
        let package_job_key = format!("{resource_did}:{}", package.package_version);
        let now = accepted_at.to_rfc3339();
        let next_attempt_at = now.clone();

        let mut tx = postgres.pool().begin().await?;

        let publication_cursor = sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_SUBJECT_VERSION_TABLE}(
                subject_did, version, did_document_hash, metadata_hash, package_hash, resource_type,
                capability_tags_json, authorized_domains_json, package_json, archive_path, accepted_at
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9::jsonb, $10, $11::timestamptz)
            ON CONFLICT(subject_did, version)
            DO UPDATE SET
                did_document_hash = excluded.did_document_hash,
                metadata_hash = excluded.metadata_hash,
                package_hash = excluded.package_hash,
                resource_type = excluded.resource_type,
                capability_tags_json = excluded.capability_tags_json,
                authorized_domains_json = excluded.authorized_domains_json,
                package_json = excluded.package_json,
                archive_path = excluded.archive_path,
                accepted_at = excluded.accepted_at
            RETURNING publication_cursor
            "#
        ))
        .bind(resource_did)
        .bind(version)
        .bind(&package.did_document_hash)
        .bind(&package.metadata_hash)
        .bind(&package.package_hash)
        .bind(&resource_type)
        .bind(sqlx::types::Json(package.metadata.capability_tags.clone()))
        .bind(sqlx::types::Json(package.metadata.authorized_domains.clone()))
        .bind(&package_json)
        .bind(&archive_path)
        .bind(&now)
        .fetch_one(&mut *tx)
        .await?
        .get::<i64, _>(0);

        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_SUBJECT_LATEST_TABLE}(subject_did, current_version, did_document_hash, metadata_hash, operation, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6::timestamptz)
            ON CONFLICT(subject_did)
            DO UPDATE SET
                current_version = excluded.current_version,
                did_document_hash = excluded.did_document_hash,
                metadata_hash = excluded.metadata_hash,
                operation = excluded.operation,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(resource_did)
        .bind(version)
        .bind(&package.did_document_hash)
        .bind(&package.metadata_hash)
        .bind(operation)
        .bind(&now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_CDN_JOB_TABLE}(
                job_key, payload_json, status, attempt_count, lease_owner, lease_expires_at,
                next_attempt_at, last_error, publication_cursor, resource_did, package_version,
                package_hash, metadata_hash, did_document_hash, resource_type, capability_tags_json,
                authorized_domains_json
            )
            VALUES ($1, $2, 'ready', 0, NULL, NULL, $3::timestamptz, NULL, $4, $5, $6, $7, $8, $9, $10, $11::jsonb, $12::jsonb)
            ON CONFLICT(job_key)
            DO UPDATE SET
                payload_json = excluded.payload_json,
                status = 'ready',
                attempt_count = 0,
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = excluded.next_attempt_at,
                publication_cursor = excluded.publication_cursor,
                resource_did = excluded.resource_did,
                package_version = excluded.package_version,
                package_hash = excluded.package_hash,
                metadata_hash = excluded.metadata_hash,
                did_document_hash = excluded.did_document_hash,
                resource_type = excluded.resource_type,
                capability_tags_json = excluded.capability_tags_json,
                authorized_domains_json = excluded.authorized_domains_json,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            "#
        ))
        .bind(&package_job_key)
        .bind(&package_json)
        .bind(&next_attempt_at)
        .bind(publication_cursor)
        .bind(resource_did)
        .bind(version)
        .bind(&package.package_hash)
        .bind(&package.metadata_hash)
        .bind(&package.did_document_hash)
        .bind(&resource_type)
        .bind(sqlx::types::Json(package.metadata.capability_tags.clone()))
        .bind(sqlx::types::Json(package.metadata.authorized_domains.clone()))
        .execute(&mut *tx)
        .await?;

        let event = CdnPublishRequestedEvent::new(CdnPublishRequestedEventInput {
            job_key: package_job_key.clone(),
            resource_did: package.resource_did.clone(),
            package_version: package.package_version.clone(),
            publication_cursor,
            root_did: state.root_did.clone(),
            package_hash: package.package_hash.clone(),
            did_document_hash: package.did_document_hash.clone(),
            metadata_hash: package.metadata_hash.clone(),
            created_at: accepted_at,
        });
        let event_json = serde_json::to_string(&event)?;
        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_CDN_OUTBOX_TABLE}(job_key, payload_json, status, attempt_count, lease_owner, lease_expires_at, next_attempt_at, last_error)
            VALUES ($1, $2, 'ready', 0, NULL, NULL, $3::timestamptz, NULL)
            ON CONFLICT(job_key)
            DO UPDATE SET
                payload_json = excluded.payload_json,
                status = 'ready',
                attempt_count = 0,
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = excluded.next_attempt_at,
                last_error = NULL,
                updated_at = CURRENT_TIMESTAMP
            "#
        ))
        .bind(&package_job_key)
        .bind(event_json)
        .bind(&next_attempt_at)
        .execute(&mut *tx)
        .await?;

        tx.commit().await?;
        return Ok(());
    }

    let mut latest = super::read_latest_versions(state)?;
    latest.insert(
        resource_did.to_owned(),
        json!({
            "packageVersion": version,
            "didDocumentHash": package.did_document_hash,
            "metadataHash": package.metadata_hash,
            "updatedAt": accepted_at
        }),
    );
    state
        .data
        .write("indexes/latest-did-document-versions.json", &latest)?;
    super::enqueue_resource_cdn(state, package).await?;
    Ok(())
}

pub(super) fn read_latest_versions_impl(state: &AppState) -> Result<BTreeMap<String, Value>> {
    if let Some(sqlite) = &state.sqlite {
        return block_on_sqlite(async {
            let rows = sqlx::query(&format!(
                "SELECT subject_did, current_version, did_document_hash, metadata_hash, updated_at FROM {ROOT_SUBJECT_LATEST_TABLE} ORDER BY subject_did"
            ))
            .fetch_all(sqlite.pool())
            .await?;
            let mut latest = BTreeMap::new();
            for row in rows {
                latest.insert(
                    row.get::<String, _>(0),
                    json!({
                        "packageVersion": row.get::<String, _>(1),
                        "didDocumentHash": row.get::<String, _>(2),
                        "metadataHash": row.get::<String, _>(3),
                        "updatedAt": row.get::<String, _>(4),
                    }),
                );
            }
            Ok(latest)
        });
    }
    if let Some(postgres) = &state.postgres {
        return block_on_sqlite(async {
            let rows = sqlx::query(&format!(
                r#"
                SELECT subject_did, current_version, did_document_hash, metadata_hash,
                       to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
                FROM {ROOT_SUBJECT_LATEST_TABLE}
                ORDER BY subject_did
                "#
            ))
            .fetch_all(postgres.pool())
            .await?;
            let mut latest = BTreeMap::new();
            for row in rows {
                latest.insert(
                    row.get::<String, _>(0),
                    json!({
                        "packageVersion": row.get::<String, _>(1),
                        "didDocumentHash": row.get::<String, _>(2),
                        "metadataHash": row.get::<String, _>(3),
                        "updatedAt": row.get::<String, _>(4),
                    }),
                );
            }
            Ok(latest)
        });
    }
    Ok(state
        .data
        .read("indexes/latest-did-document-versions.json")
        .unwrap_or_default())
}

pub(super) async fn read_cdn_queue_impl(state: &AppState) -> Result<Vec<ResourcePackage>> {
    if let Some(sqlite) = &state.sqlite {
        return sqlite
            .read_active_leased_jobs(ROOT_CDN_JOB_TABLE)
            .await
            .map_err(Into::into);
    }
    if let Some(postgres) = &state.postgres {
        return postgres
            .read_active_leased_jobs(ROOT_CDN_JOB_TABLE)
            .await
            .map_err(Into::into);
    }
    Ok(state
        .data
        .read("queues/cdn-publish.json")
        .unwrap_or_default())
}

pub(super) async fn read_ready_cdn_queue_impl(state: &AppState) -> Result<Vec<ResourcePackage>> {
    let now = Utc::now().to_rfc3339();
    if let Some(sqlite) = &state.sqlite {
        return sqlite
            .read_ready_leased_jobs(ROOT_CDN_JOB_TABLE, &now)
            .await
            .map_err(Into::into);
    }
    if let Some(postgres) = &state.postgres {
        return postgres
            .read_ready_leased_jobs(ROOT_CDN_JOB_TABLE, &now)
            .await
            .map_err(Into::into);
    }
    Ok(state
        .data
        .read("queues/cdn-publish.json")
        .unwrap_or_default())
}

pub(super) async fn read_discovery_target_states_impl(
    state: &AppState,
) -> Result<Vec<DiscoveryNotifyTargetState>> {
    if let Some(sqlite) = &state.sqlite {
        let rows = sqlx::query(&format!(
            r#"
            SELECT discovery_did, pending_cursor, delivered_cursor, status, attempt_count,
                   lease_owner, lease_expires_at, next_attempt_at, last_error, updated_at
            FROM {ROOT_DISCOVERY_TARGET_TABLE}
            ORDER BY discovery_did
            "#
        ))
        .fetch_all(sqlite.pool())
        .await?;
        return Ok(rows
            .into_iter()
            .map(|row| DiscoveryNotifyTargetState {
                discovery_did: row.get::<String, _>(0),
                pending_cursor: row.get::<i64, _>(1),
                delivered_cursor: row.get::<i64, _>(2),
                status: row.get::<String, _>(3),
                attempt_count: row.get::<i64, _>(4),
                lease_owner: row.get::<Option<String>, _>(5),
                lease_expires_at: row.get::<Option<String>, _>(6),
                next_attempt_at: row.get::<String, _>(7),
                last_error: row.get::<Option<String>, _>(8),
                updated_at: row.get::<String, _>(9),
            })
            .collect());
    }
    if let Some(postgres) = &state.postgres {
        let rows = sqlx::query(&format!(
            r#"
            SELECT discovery_did, pending_cursor, delivered_cursor, status, attempt_count,
                   lease_owner,
                   to_char(lease_expires_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                   to_char(next_attempt_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'),
                   last_error,
                   to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
            FROM {ROOT_DISCOVERY_TARGET_TABLE}
            ORDER BY discovery_did
            "#
        ))
        .fetch_all(postgres.pool())
        .await?;
        return Ok(rows
            .into_iter()
            .map(|row| DiscoveryNotifyTargetState {
                discovery_did: row.get::<String, _>(0),
                pending_cursor: row.get::<i64, _>(1),
                delivered_cursor: row.get::<i64, _>(2),
                status: row.get::<String, _>(3),
                attempt_count: row.get::<i64, _>(4),
                lease_owner: row.get::<Option<String>, _>(5),
                lease_expires_at: row.get::<Option<String>, _>(6),
                next_attempt_at: row.get::<String, _>(7),
                last_error: row.get::<Option<String>, _>(8),
                updated_at: row.get::<String, _>(9),
            })
            .collect());
    }
    Ok(Vec::new())
}

pub(super) async fn claim_discovery_targets_impl(
    state: &AppState,
    worker_id: &str,
    limit: usize,
    lease_seconds: i64,
) -> Result<Vec<DiscoveryNotifyTargetLease>> {
    let now = Utc::now();
    let now_rfc3339 = now.to_rfc3339();
    let lease_expires_at = (now + chrono::Duration::seconds(lease_seconds)).to_rfc3339();
    if let Some(sqlite) = &state.sqlite {
        let mut conn = sqlite.pool().acquire().await?;
        sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
        let result = async {
            let rows = sqlx::query(&format!(
                r#"
                SELECT discovery_did, pending_cursor, delivered_cursor
                FROM {ROOT_DISCOVERY_TARGET_TABLE}
                WHERE status = 'active'
                  AND pending_cursor > delivered_cursor
                  AND next_attempt_at <= ?
                  AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
                ORDER BY pending_cursor DESC, discovery_did
                LIMIT ?
                "#
            ))
            .bind(&now_rfc3339)
            .bind(&now_rfc3339)
            .bind(limit as i64)
            .fetch_all(&mut *conn)
            .await?;
            let mut claimed = Vec::with_capacity(rows.len());
            for row in rows {
                let discovery_did = row.get::<String, _>(0);
                let pending_cursor = row.get::<i64, _>(1);
                let delivered_cursor = row.get::<i64, _>(2);
                sqlx::query(&format!(
                    r#"
                    UPDATE {ROOT_DISCOVERY_TARGET_TABLE}
                    SET lease_owner = ?, lease_expires_at = ?, attempt_count = attempt_count + 1,
                        last_error = NULL, updated_at = ?
                    WHERE discovery_did = ?
                    "#
                ))
                .bind(worker_id)
                .bind(&lease_expires_at)
                .bind(&now_rfc3339)
                .bind(&discovery_did)
                .execute(&mut *conn)
                .await?;
                claimed.push(DiscoveryNotifyTargetLease {
                    discovery_did,
                    target_cursor: pending_cursor,
                    delivered_cursor,
                });
            }
            sqlx::query("COMMIT").execute(&mut *conn).await?;
            Ok(claimed)
        }
        .await;
        if result.is_err() {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        }
        return result;
    }
    if let Some(postgres) = &state.postgres {
        let rows = sqlx::query(&format!(
            r#"
            WITH claimed AS (
                SELECT discovery_did, pending_cursor, delivered_cursor
                FROM {ROOT_DISCOVERY_TARGET_TABLE}
                WHERE status = 'active'
                  AND pending_cursor > delivered_cursor
                  AND next_attempt_at <= $1::timestamptz
                  AND (lease_expires_at IS NULL OR lease_expires_at <= $1::timestamptz)
                ORDER BY pending_cursor DESC, discovery_did
                LIMIT $2
                FOR UPDATE SKIP LOCKED
            )
            UPDATE {ROOT_DISCOVERY_TARGET_TABLE} AS targets
            SET lease_owner = $3,
                lease_expires_at = $4::timestamptz,
                attempt_count = targets.attempt_count + 1,
                last_error = NULL,
                updated_at = $1::timestamptz
            FROM claimed
            WHERE targets.discovery_did = claimed.discovery_did
            RETURNING claimed.discovery_did, claimed.pending_cursor, claimed.delivered_cursor
            "#
        ))
        .bind(&now_rfc3339)
        .bind(limit as i64)
        .bind(worker_id)
        .bind(&lease_expires_at)
        .fetch_all(postgres.pool())
        .await?;
        return Ok(rows
            .into_iter()
            .map(|row| DiscoveryNotifyTargetLease {
                discovery_did: row.get::<String, _>(0),
                target_cursor: row.get::<i64, _>(1),
                delivered_cursor: row.get::<i64, _>(2),
            })
            .collect());
    }
    Ok(Vec::new())
}

pub(super) async fn mark_discovery_target_notified_impl(
    state: &AppState,
    discovery_did: &str,
    delivered_cursor: i64,
) -> Result<()> {
    let now = Utc::now();
    let now_text = now.to_rfc3339();
    if let Some(sqlite) = &state.sqlite {
        sqlx::query(&format!(
            r#"
            UPDATE {ROOT_DISCOVERY_TARGET_TABLE}
            SET delivered_cursor = MAX(delivered_cursor, ?),
                status = 'active',
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = ?,
                last_error = NULL,
                updated_at = ?
            WHERE discovery_did = ?
            "#
        ))
        .bind(delivered_cursor)
        .bind(&now_text)
        .bind(&now_text)
        .bind(discovery_did)
        .execute(sqlite.pool())
        .await?;
        sqlx::query(&format!(
            r#"
            DELETE FROM {ROOT_DISCOVERY_ITEM_TABLE}
            WHERE discovery_did = ? AND publication_cursor <= ?
            "#
        ))
        .bind(discovery_did)
        .bind(delivered_cursor)
        .execute(sqlite.pool())
        .await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        sqlx::query(&format!(
            r#"
            UPDATE {ROOT_DISCOVERY_TARGET_TABLE}
            SET delivered_cursor = GREATEST(delivered_cursor, $1),
                status = 'active',
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = $2::timestamptz,
                last_error = NULL,
                updated_at = $3::timestamptz
            WHERE discovery_did = $4
            "#
        ))
        .bind(delivered_cursor)
        .bind(now)
        .bind(now)
        .bind(discovery_did)
        .execute(postgres.pool())
        .await?;
        sqlx::query(&format!(
            r#"
            DELETE FROM {ROOT_DISCOVERY_ITEM_TABLE}
            WHERE discovery_did = $1 AND publication_cursor <= $2
            "#
        ))
        .bind(discovery_did)
        .bind(delivered_cursor)
        .execute(postgres.pool())
        .await?;
    }
    Ok(())
}

pub(super) async fn mark_discovery_target_retry_impl(
    state: &AppState,
    discovery_did: &str,
    error: &str,
) -> Result<()> {
    let retry_after = (Utc::now()
        + chrono::Duration::seconds(state.config.security.workers.retry_backoff_seconds))
    .to_rfc3339();
    let now = Utc::now().to_rfc3339();
    if let Some(sqlite) = &state.sqlite {
        sqlx::query(&format!(
            r#"
            UPDATE {ROOT_DISCOVERY_TARGET_TABLE}
            SET lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = ?,
                last_error = ?,
                updated_at = ?
            WHERE discovery_did = ?
            "#
        ))
        .bind(&retry_after)
        .bind(error)
        .bind(&now)
        .bind(discovery_did)
        .execute(sqlite.pool())
        .await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        sqlx::query(&format!(
            r#"
            UPDATE {ROOT_DISCOVERY_TARGET_TABLE}
            SET lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = $1::timestamptz,
                last_error = $2,
                updated_at = $3::timestamptz
            WHERE discovery_did = $4
            "#
        ))
        .bind(&retry_after)
        .bind(error)
        .bind(&now)
        .bind(discovery_did)
        .execute(postgres.pool())
        .await?;
    }
    Ok(())
}

#[cfg(test)]
pub(super) async fn advance_discovery_target_watermarks_batch_impl(
    state: &AppState,
    packages: &[(ResourcePackage, i64)],
) -> Result<usize> {
    if packages.is_empty() {
        return Ok(0);
    }
    let authorization_state = super::current_authorization_state(state);
    let items = discovery_notification_targets_for_authorized_rows(
        packages,
        &authorization_state.discovery_nodes,
        &state.tag_tree,
    );
    let target_cursors = discovery_target_cursors_from_items(&items);
    let advanced = target_cursors.len();
    if advanced == 0 {
        return Ok(0);
    }
    let now = Utc::now();
    let now_text = now.to_rfc3339();
    if let Some(sqlite) = &state.sqlite {
        let mut tx = sqlite.pool().begin().await?;
        let rows = target_cursors.into_iter().collect::<Vec<_>>();
        for chunk in rows.chunks(250) {
            let mut builder = QueryBuilder::<Sqlite>::new(format!(
                r#"
                INSERT INTO {ROOT_DISCOVERY_TARGET_TABLE}(
                    discovery_did, pending_cursor, delivered_cursor, status, attempt_count,
                    lease_owner, lease_expires_at, next_attempt_at, last_error, updated_at
                )
                "#
            ));
            builder.push_values(chunk, |mut row, (discovery_did, publication_cursor)| {
                row.push_bind(discovery_did)
                    .push_bind(publication_cursor)
                    .push("0")
                    .push("'active'")
                    .push("0")
                    .push("NULL")
                    .push("NULL")
                    .push_bind(&now_text)
                    .push("NULL")
                    .push_bind(&now_text);
            });
            builder.push(format!(
                r#"
                ON CONFLICT(discovery_did)
                DO UPDATE SET
                    pending_cursor = MAX({ROOT_DISCOVERY_TARGET_TABLE}.pending_cursor, excluded.pending_cursor),
                    status = 'active',
                    next_attempt_at = CASE
                        WHEN {ROOT_DISCOVERY_TARGET_TABLE}.pending_cursor < excluded.pending_cursor
                        THEN excluded.next_attempt_at
                        ELSE {ROOT_DISCOVERY_TARGET_TABLE}.next_attempt_at
                    END,
                    updated_at = excluded.updated_at
                "#
            ));
            builder.build().execute(&mut *tx).await?;
        }
        tx.commit().await?;
        return Ok(advanced);
    }
    if let Some(postgres) = &state.postgres {
        let mut tx = postgres.pool().begin().await?;
        let rows = target_cursors.into_iter().collect::<Vec<_>>();
        for chunk in rows.chunks(250) {
            let mut builder = QueryBuilder::<Postgres>::new(format!(
                r#"
                INSERT INTO {ROOT_DISCOVERY_TARGET_TABLE}(
                    discovery_did, pending_cursor, delivered_cursor, status, attempt_count,
                    lease_owner, lease_expires_at, next_attempt_at, last_error, updated_at
                )
                "#
            ));
            builder.push_values(chunk, |mut row, (discovery_did, publication_cursor)| {
                row.push_bind(discovery_did)
                    .push_bind(publication_cursor)
                    .push("0")
                    .push("'active'")
                    .push("0")
                    .push("NULL")
                    .push("NULL")
                    .push_bind(now)
                    .push("NULL")
                    .push_bind(now);
            });
            builder.push(format!(
                r#"
                ON CONFLICT(discovery_did)
                DO UPDATE SET
                    pending_cursor = GREATEST({ROOT_DISCOVERY_TARGET_TABLE}.pending_cursor, excluded.pending_cursor),
                    status = 'active',
                    next_attempt_at = CASE
                        WHEN {ROOT_DISCOVERY_TARGET_TABLE}.pending_cursor < excluded.pending_cursor
                        THEN excluded.next_attempt_at
                        ELSE {ROOT_DISCOVERY_TARGET_TABLE}.next_attempt_at
                    END,
                    updated_at = excluded.updated_at
                "#
            ));
            builder.build().execute(&mut *tx).await?;
        }
        tx.commit().await?;
        return Ok(advanced);
    }
    Ok(0)
}

pub(super) async fn complete_cdn_publication_jobs_impl(
    state: &AppState,
    jobs: &[CdnPublicationJobCompletionRef],
    discovery_nodes: &BTreeMap<String, DiscoveryAuthorizationState>,
    tag_tree: &CapabilityTagTree,
) -> Result<CdnPublicationBatchCompletion> {
    if jobs.is_empty() {
        return Ok(CdnPublicationBatchCompletion::default());
    }
    let job_keys = jobs
        .iter()
        .map(|job| job.job_key.clone())
        .collect::<Vec<_>>();
    let fetch_started = Instant::now();
    let (notification_items, target_cursors, fetch_sql_elapsed_ms) = if state.postgres.is_some() {
        let sql_started = Instant::now();
        let projections = postgres_publication_projections_for_jobs(state, &job_keys).await?;
        let fetch_sql_elapsed_ms = sql_started.elapsed().as_millis();
        let ordered = job_keys
            .iter()
            .map(|job_key| {
                projections
                    .get(job_key)
                    .cloned()
                    .ok_or_else(|| anyhow!("unknown_cdn_publication_job"))
            })
            .collect::<Result<Vec<_>>>()?;
        validate_completion_refs(jobs, &ordered)?;
        let already_published = ordered
            .iter()
            .all(|row| row.status.eq_ignore_ascii_case("published"));
        if already_published {
            (Vec::new(), BTreeMap::new(), fetch_sql_elapsed_ms)
        } else {
            let (items, cursors) = discovery_notification_targets_for_projection_rows(
                &ordered,
                discovery_nodes,
                tag_tree,
            );
            (items, cursors, fetch_sql_elapsed_ms)
        }
    } else {
        if let Some(sqlite) = &state.sqlite {
            let already_published = sqlite_cdn_jobs_all_published(state, &job_keys).await?;
            if already_published {
                let packages = resource_packages_for_jobs_impl(state, &job_keys).await?;
                if packages.len() != job_keys.len() {
                    return Err(anyhow!("unknown_cdn_publication_job"));
                }
                let rows = job_keys
                    .iter()
                    .map(|job_key| {
                        packages
                            .get(job_key)
                            .cloned()
                            .ok_or_else(|| anyhow!("unknown_cdn_publication_job"))
                    })
                    .collect::<Result<Vec<_>>>()?;
                validate_completion_refs_against_rows(jobs, &rows)?;
                let _ = sqlite;
                return Ok(CdnPublicationBatchCompletion {
                    marked_count: job_keys.len(),
                    stored_notification_count: 0,
                    advanced_discovery_count: 0,
                    fetch_elapsed_ms: fetch_started.elapsed().as_millis(),
                    fetch_sql_elapsed_ms: 0,
                    watermark_match_elapsed_ms: 0,
                    update_elapsed_ms: 0,
                    watermark_elapsed_ms: 0,
                    store_items_elapsed_ms: 0,
                    upsert_targets_elapsed_ms: 0,
                    delete_jobs_elapsed_ms: 0,
                });
            }
        }
        let packages = resource_packages_for_jobs_impl(state, &job_keys).await?;
        if packages.len() != job_keys.len() {
            return Err(anyhow!("unknown_cdn_publication_job"));
        }
        let rows = job_keys
            .iter()
            .map(|job_key| {
                packages
                    .get(job_key)
                    .cloned()
                    .ok_or_else(|| anyhow!("unknown_cdn_publication_job"))
            })
            .collect::<Result<Vec<_>>>()?;
        validate_completion_refs_against_rows(jobs, &rows)?;
        let items =
            discovery_notification_targets_for_authorized_rows(&rows, discovery_nodes, tag_tree);
        let cursors = discovery_target_cursors_from_items(&items);
        (items, cursors, 0)
    };
    let fetch_elapsed_ms = fetch_started.elapsed().as_millis();

    let watermark_started = Instant::now();
    let watermark_match_elapsed_ms = watermark_started.elapsed().as_millis();
    let watermark_elapsed_ms = watermark_started.elapsed().as_millis();

    let update_started = Instant::now();
    let stored_notification_count;
    let advanced_discovery_count = target_cursors.len();
    let mut store_items_elapsed_ms = 0;
    let mut upsert_targets_elapsed_ms = 0;
    let mut delete_jobs_elapsed_ms = 0;
    if let Some(sqlite) = &state.sqlite {
        let now_text = Utc::now().to_rfc3339();
        let mut tx = sqlite.pool().begin().await?;
        if !notification_items.is_empty() {
            let stage_started = Instant::now();
            for chunk in notification_items.chunks(250) {
                let mut builder = QueryBuilder::<Sqlite>::new(format!(
                    r#"
                    INSERT INTO {ROOT_DISCOVERY_ITEM_TABLE}(
                        discovery_did, publication_cursor, resource_did, package_version,
                        package_hash, metadata_hash, did_document_hash, resource_type,
                        capability_tags_json, authorized_domains_json
                    )
                    "#
                ));
                builder.push_values(chunk, |mut row, item| {
                    row.push_bind(&item.discovery_did)
                        .push_bind(item.item.publication_cursor)
                        .push_bind(&item.item.resource_did)
                        .push_bind(&item.item.package_version)
                        .push_bind(&item.item.package_hash)
                        .push_bind(&item.item.metadata_hash)
                        .push_bind(&item.item.did_document_hash)
                        .push_bind(&item.item.resource_type)
                        .push_bind(
                            serde_json::to_string(&item.item.capability_tags)
                                .unwrap_or_else(|_| "[]".to_owned()),
                        )
                        .push_bind(
                            serde_json::to_string(&item.item.authorized_domains)
                                .unwrap_or_else(|_| "[]".to_owned()),
                        );
                });
                builder.push(" ON CONFLICT(discovery_did, publication_cursor) DO NOTHING");
                builder.build().execute(&mut *tx).await?;
            }
            store_items_elapsed_ms = stage_started.elapsed().as_millis();
        }
        stored_notification_count = notification_items.len();
        if !target_cursors.is_empty() {
            let stage_started = Instant::now();
            let rows = target_cursors.iter().collect::<Vec<_>>();
            for chunk in rows.chunks(250) {
                let mut builder = QueryBuilder::<Sqlite>::new(format!(
                    r#"
                    INSERT INTO {ROOT_DISCOVERY_TARGET_TABLE}(
                        discovery_did, pending_cursor, delivered_cursor, status, attempt_count,
                        lease_owner, lease_expires_at, next_attempt_at, last_error, updated_at
                    )
                    "#
                ));
                builder.push_values(chunk, |mut row, (discovery_did, publication_cursor)| {
                    row.push_bind(*discovery_did)
                        .push_bind(*publication_cursor)
                        .push("0")
                        .push("'active'")
                        .push("0")
                        .push("NULL")
                        .push("NULL")
                        .push_bind(&now_text)
                        .push("NULL")
                        .push_bind(&now_text);
                });
                builder.push(format!(
                    r#"
                    ON CONFLICT(discovery_did)
                    DO UPDATE SET
                        pending_cursor = MAX({ROOT_DISCOVERY_TARGET_TABLE}.pending_cursor, excluded.pending_cursor),
                        status = 'active',
                        next_attempt_at = CASE
                            WHEN {ROOT_DISCOVERY_TARGET_TABLE}.pending_cursor < excluded.pending_cursor
                            THEN excluded.next_attempt_at
                            ELSE {ROOT_DISCOVERY_TARGET_TABLE}.next_attempt_at
                        END,
                        updated_at = excluded.updated_at
                    "#
                ));
                builder.build().execute(&mut *tx).await?;
            }
            upsert_targets_elapsed_ms = stage_started.elapsed().as_millis();
        }
        let stage_started = Instant::now();
        for chunk in job_keys.chunks(500) {
            let mut builder = QueryBuilder::<Sqlite>::new(format!(
                r#"
                UPDATE {ROOT_CDN_JOB_TABLE}
                SET status = 'published',
                    lease_owner = NULL,
                    lease_expires_at = NULL,
                    next_attempt_at = CURRENT_TIMESTAMP,
                    last_error = NULL
                WHERE job_key IN (
                "#
            ));
            let mut separated = builder.separated(", ");
            for job_key in chunk {
                separated.push_bind(job_key);
            }
            separated.push_unseparated(")");
            builder.build().execute(&mut *tx).await?;
        }
        delete_jobs_elapsed_ms = stage_started.elapsed().as_millis();
        tx.commit().await?;
    } else if let Some(postgres) = &state.postgres {
        let now = Utc::now();
        let mut tx = postgres.pool().begin().await?;
        if !notification_items.is_empty() {
            let stage_started = Instant::now();
            let rows = notification_items
                .iter()
                .map(|item| PostgresDiscoveryNotificationItemRow {
                    discovery_did: &item.discovery_did,
                    publication_cursor: item.item.publication_cursor,
                    resource_did: &item.item.resource_did,
                    package_version: &item.item.package_version,
                    package_hash: &item.item.package_hash,
                    metadata_hash: &item.item.metadata_hash,
                    did_document_hash: &item.item.did_document_hash,
                    resource_type: &item.item.resource_type,
                    capability_tags_json: item.item.capability_tags.clone(),
                    authorized_domains_json: item.item.authorized_domains.clone(),
                })
                .collect::<Vec<_>>();
            let payload = serde_json::to_value(&rows)?;
            sqlx::query(&format!(
                r#"
                INSERT INTO {ROOT_DISCOVERY_ITEM_TABLE}(
                    discovery_did,
                    publication_cursor,
                    resource_did,
                    package_version,
                    package_hash,
                    metadata_hash,
                    did_document_hash,
                    resource_type,
                    capability_tags_json,
                    authorized_domains_json
                )
                SELECT
                    entry.discovery_did,
                    entry.publication_cursor,
                    entry.resource_did,
                    entry.package_version,
                    entry.package_hash,
                    entry.metadata_hash,
                    entry.did_document_hash,
                    entry.resource_type,
                    entry.capability_tags_json,
                    entry.authorized_domains_json
                FROM jsonb_to_recordset($1::jsonb) AS entry(
                    discovery_did text,
                    publication_cursor bigint,
                    resource_did text,
                    package_version text,
                    package_hash text,
                    metadata_hash text,
                    did_document_hash text,
                    resource_type text,
                    capability_tags_json jsonb,
                    authorized_domains_json jsonb
                )
                ON CONFLICT(discovery_did, publication_cursor) DO NOTHING
                "#
            ))
            .bind(payload)
            .execute(&mut *tx)
            .await?;
            store_items_elapsed_ms = stage_started.elapsed().as_millis();
        }
        stored_notification_count = notification_items.len();
        if !target_cursors.is_empty() {
            let stage_started = Instant::now();
            let rows = target_cursors
                .iter()
                .map(
                    |(discovery_did, publication_cursor)| PostgresDiscoveryTargetCursorRow {
                        discovery_did,
                        pending_cursor: *publication_cursor,
                    },
                )
                .collect::<Vec<_>>();
            let payload = serde_json::to_value(&rows)?;
            sqlx::query(&format!(
                r#"
                INSERT INTO {ROOT_DISCOVERY_TARGET_TABLE}(
                    discovery_did,
                    pending_cursor,
                    delivered_cursor,
                    status,
                    attempt_count,
                    lease_owner,
                    lease_expires_at,
                    next_attempt_at,
                    last_error,
                    updated_at
                )
                SELECT
                    entry.discovery_did,
                    entry.pending_cursor,
                    0,
                    'active',
                    0,
                    NULL,
                    NULL,
                    $2::timestamptz,
                    NULL,
                    $2::timestamptz
                FROM jsonb_to_recordset($1::jsonb) AS entry(
                    discovery_did text,
                    pending_cursor bigint
                )
                ON CONFLICT(discovery_did)
                DO UPDATE SET
                    pending_cursor = GREATEST({ROOT_DISCOVERY_TARGET_TABLE}.pending_cursor, excluded.pending_cursor),
                    status = 'active',
                    next_attempt_at = CASE
                        WHEN {ROOT_DISCOVERY_TARGET_TABLE}.pending_cursor < excluded.pending_cursor
                        THEN excluded.next_attempt_at
                        ELSE {ROOT_DISCOVERY_TARGET_TABLE}.next_attempt_at
                    END,
                    updated_at = excluded.updated_at
                "#
            ))
            .bind(payload)
            .bind(now)
            .execute(&mut *tx)
            .await?;
            upsert_targets_elapsed_ms = stage_started.elapsed().as_millis();
        }
        let stage_started = Instant::now();
        sqlx::query(&format!(
            r#"
            UPDATE {ROOT_CDN_JOB_TABLE}
            SET status = 'published',
                lease_owner = NULL,
                lease_expires_at = NULL,
                next_attempt_at = $2::timestamptz,
                last_error = NULL
            WHERE job_key = ANY($1)
            "#
        ))
        .bind(&job_keys)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        delete_jobs_elapsed_ms = stage_started.elapsed().as_millis();
        tx.commit().await?;
    } else {
        stored_notification_count = 0;
    }
    let update_elapsed_ms = update_started.elapsed().as_millis();

    Ok(CdnPublicationBatchCompletion {
        marked_count: job_keys.len(),
        stored_notification_count,
        advanced_discovery_count,
        fetch_elapsed_ms,
        fetch_sql_elapsed_ms,
        watermark_match_elapsed_ms,
        update_elapsed_ms,
        watermark_elapsed_ms,
        store_items_elapsed_ms,
        upsert_targets_elapsed_ms,
        delete_jobs_elapsed_ms,
    })
}

fn validate_completion_refs(
    jobs: &[CdnPublicationJobCompletionRef],
    rows: &[PublicationProjectionRow],
) -> Result<()> {
    for (job, row) in jobs.iter().zip(rows.iter()) {
        validate_completion_ref(
            job,
            &row.resource_did,
            &row.package_version,
            row.publication_cursor,
            &row.package_hash,
        )?;
    }
    Ok(())
}

fn validate_completion_refs_against_rows(
    jobs: &[CdnPublicationJobCompletionRef],
    rows: &[(ResourcePackage, i64)],
) -> Result<()> {
    for (job, (package, publication_cursor)) in jobs.iter().zip(rows.iter()) {
        validate_completion_ref(
            job,
            &package.resource_did,
            &package.package_version,
            *publication_cursor,
            &package.package_hash,
        )?;
    }
    Ok(())
}

fn validate_completion_ref(
    job: &CdnPublicationJobCompletionRef,
    resource_did: &str,
    package_version: &str,
    publication_cursor: i64,
    package_hash: &str,
) -> Result<()> {
    if let Some(cursor) = job.publication_cursor {
        if cursor != publication_cursor {
            return Err(anyhow!("cdn_publication_cursor_mismatch"));
        }
    }
    if let Some(value) = job.resource_did.as_deref() {
        if value != resource_did {
            return Err(anyhow!("cdn_publication_resource_did_mismatch"));
        }
    }
    if let Some(value) = job.package_version.as_deref() {
        if value != package_version {
            return Err(anyhow!("cdn_publication_package_version_mismatch"));
        }
    }
    if let Some(value) = job.package_hash.as_deref() {
        if value != package_hash {
            return Err(anyhow!("cdn_publication_package_hash_mismatch"));
        }
    }
    Ok(())
}

pub(super) async fn claim_cdn_outbox_events_impl(
    state: &AppState,
    worker_id: &str,
    limit: i64,
    lease_seconds: i64,
) -> Result<Vec<(String, CdnPublishRequestedEvent)>> {
    if let Some(sqlite) = &state.sqlite {
        let leased = sqlite
            .lease_ready_jobs::<CdnPublishRequestedEvent>(
                ROOT_CDN_OUTBOX_TABLE,
                worker_id,
                limit,
                &Utc::now().to_rfc3339(),
                &(Utc::now() + chrono::Duration::seconds(lease_seconds)).to_rfc3339(),
            )
            .await?;
        return Ok(leased
            .into_iter()
            .map(|job| (job.job_key, job.payload))
            .collect());
    }
    if let Some(postgres) = &state.postgres {
        let leased = postgres
            .lease_ready_jobs::<CdnPublishRequestedEvent>(
                ROOT_CDN_OUTBOX_TABLE,
                worker_id,
                limit,
                &Utc::now().to_rfc3339(),
                &(Utc::now() + chrono::Duration::seconds(lease_seconds)).to_rfc3339(),
            )
            .await?;
        return Ok(leased
            .into_iter()
            .map(|job| (job.job_key, job.payload))
            .collect());
    }
    Ok(Vec::new())
}

pub(super) async fn oldest_ready_cdn_outbox_age_ms_impl(state: &AppState) -> Result<Option<u128>> {
    let now = Utc::now();
    let now_rfc3339 = now.to_rfc3339();
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!(
            r#"
            SELECT MIN(next_attempt_at)
            FROM {ROOT_CDN_OUTBOX_TABLE}
            WHERE
                status = 'ready'
                OR (status = 'retry-wait' AND next_attempt_at <= ?)
                OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= ?)
            "#
        ))
        .bind(&now_rfc3339)
        .bind(&now_rfc3339)
        .fetch_one(sqlite.pool())
        .await?;
        let oldest = row.get::<Option<String>, _>(0);
        return Ok(oldest
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(&value).ok())
            .and_then(|value| {
                now.signed_duration_since(value.with_timezone(&Utc))
                    .to_std()
                    .ok()
            })
            .map(|duration| duration.as_millis()));
    }
    if let Some(postgres) = &state.postgres {
        let row = sqlx::query(&format!(
            r#"
            SELECT to_char(
                MIN(next_attempt_at) AT TIME ZONE 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
            )
            FROM {ROOT_CDN_OUTBOX_TABLE}
            WHERE
                status = 'ready'
                OR (status = 'retry-wait' AND next_attempt_at <= $1::timestamptz)
                OR (status = 'leased' AND lease_expires_at IS NOT NULL AND lease_expires_at <= $2::timestamptz)
            "#
        ))
        .bind(now)
        .bind(now)
        .fetch_one(postgres.pool())
        .await?;
        let oldest = row.get::<Option<String>, _>(0);
        return Ok(oldest
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(&value).ok())
            .and_then(|value| {
                now.signed_duration_since(value.with_timezone(&Utc))
                    .to_std()
                    .ok()
            })
            .map(|duration| duration.as_millis()));
    }
    Ok(None)
}

pub(super) async fn oldest_ready_discovery_target_age_ms_impl(
    state: &AppState,
) -> Result<Option<u128>> {
    let now = Utc::now();
    let now_rfc3339 = now.to_rfc3339();
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!(
            r#"
            SELECT MIN(updated_at)
            FROM {ROOT_DISCOVERY_TARGET_TABLE}
            WHERE status = 'active'
              AND pending_cursor > delivered_cursor
              AND next_attempt_at <= ?
              AND (lease_expires_at IS NULL OR lease_expires_at <= ?)
            "#
        ))
        .bind(&now_rfc3339)
        .bind(&now_rfc3339)
        .fetch_one(sqlite.pool())
        .await?;
        let oldest = row.get::<Option<String>, _>(0);
        return Ok(oldest
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(&value).ok())
            .and_then(|value| {
                now.signed_duration_since(value.with_timezone(&Utc))
                    .to_std()
                    .ok()
            })
            .map(|duration| duration.as_millis()));
    }
    if let Some(postgres) = &state.postgres {
        let row = sqlx::query(&format!(
            r#"
            SELECT to_char(
                MIN(updated_at) AT TIME ZONE 'UTC',
                'YYYY-MM-DD"T"HH24:MI:SS.US"Z"'
            )
            FROM {ROOT_DISCOVERY_TARGET_TABLE}
            WHERE status = 'active'
              AND pending_cursor > delivered_cursor
              AND next_attempt_at <= $1::timestamptz
              AND (lease_expires_at IS NULL OR lease_expires_at <= $2::timestamptz)
            "#
        ))
        .bind(now)
        .bind(now)
        .fetch_one(postgres.pool())
        .await?;
        let oldest = row.get::<Option<String>, _>(0);
        return Ok(oldest
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(&value).ok())
            .and_then(|value| {
                now.signed_duration_since(value.with_timezone(&Utc))
                    .to_std()
                    .ok()
            })
            .map(|duration| duration.as_millis()));
    }
    Ok(None)
}

pub(super) async fn mark_cdn_outbox_events_published_batch_impl(
    state: &AppState,
    job_keys: &[String],
) -> Result<u64> {
    if job_keys.is_empty() {
        return Ok(0);
    }
    if let Some(sqlite) = &state.sqlite {
        return sqlite
            .mark_leased_jobs_succeeded(ROOT_CDN_OUTBOX_TABLE, job_keys)
            .await
            .map_err(Into::into);
    }
    if let Some(postgres) = &state.postgres {
        return postgres
            .mark_leased_jobs_succeeded(ROOT_CDN_OUTBOX_TABLE, job_keys)
            .await
            .map_err(Into::into);
    }
    Ok(0)
}

pub(super) async fn mark_cdn_outbox_events_retry_batch_impl(
    state: &AppState,
    jobs: &[(String, String)],
) -> Result<u64> {
    if jobs.is_empty() {
        return Ok(0);
    }
    let retry_after =
        Utc::now() + chrono::Duration::seconds(state.config.security.workers.retry_backoff_seconds);
    if let Some(sqlite) = &state.sqlite {
        return sqlite
            .mark_leased_jobs_retry(ROOT_CDN_OUTBOX_TABLE, jobs, &retry_after.to_rfc3339())
            .await
            .map_err(Into::into);
    }
    if let Some(postgres) = &state.postgres {
        return postgres
            .mark_leased_jobs_retry(ROOT_CDN_OUTBOX_TABLE, jobs, &retry_after.to_rfc3339())
            .await
            .map_err(Into::into);
    }
    Ok(0)
}

#[cfg(test)]
pub(super) async fn publication_cursors_for_jobs_impl(
    state: &AppState,
    job_keys: &[String],
) -> Result<BTreeMap<String, i64>> {
    let pairs = job_keys
        .iter()
        .filter_map(|job_key| {
            job_key.rsplit_once(':').map(|(subject_did, version)| {
                (job_key.clone(), subject_did.to_owned(), version.to_owned())
            })
        })
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        return Ok(BTreeMap::new());
    }
    if let Some(sqlite) = &state.sqlite {
        let mut builder = QueryBuilder::<Sqlite>::new(format!(
            "SELECT subject_did, version, publication_cursor FROM {ROOT_SUBJECT_VERSION_TABLE} WHERE "
        ));
        for (index, (_, subject_did, version)) in pairs.iter().enumerate() {
            if index > 0 {
                builder.push(" OR ");
            }
            builder
                .push("(subject_did = ")
                .push_bind(subject_did)
                .push(" AND version = ")
                .push_bind(version)
                .push(")");
        }
        let rows = builder.build().fetch_all(sqlite.pool()).await?;
        let mut cursors = BTreeMap::new();
        for row in rows {
            let subject_did = row.get::<String, _>(0);
            let version = row.get::<String, _>(1);
            cursors.insert(format!("{subject_did}:{version}"), row.get::<i64, _>(2));
        }
        return Ok(cursors);
    }
    if let Some(postgres) = &state.postgres {
        let mut builder = QueryBuilder::<Postgres>::new(format!(
            "SELECT subject_did, version, publication_cursor FROM {ROOT_SUBJECT_VERSION_TABLE} WHERE "
        ));
        for (index, (_, subject_did, version)) in pairs.iter().enumerate() {
            if index > 0 {
                builder.push(" OR ");
            }
            builder
                .push("(subject_did = ")
                .push_bind(subject_did)
                .push(" AND version = ")
                .push_bind(version)
                .push(")");
        }
        let rows = builder.build().fetch_all(postgres.pool()).await?;
        let mut cursors = BTreeMap::new();
        for row in rows {
            let subject_did = row.get::<String, _>(0);
            let version = row.get::<String, _>(1);
            cursors.insert(format!("{subject_did}:{version}"), row.get::<i64, _>(2));
        }
        return Ok(cursors);
    }
    Ok(BTreeMap::new())
}

pub(super) async fn resource_packages_for_jobs_impl(
    state: &AppState,
    job_keys: &[String],
) -> Result<BTreeMap<String, (ResourcePackage, i64)>> {
    let pairs = job_keys
        .iter()
        .filter_map(|job_key| {
            job_key.rsplit_once(':').map(|(subject_did, version)| {
                (job_key.clone(), subject_did.to_owned(), version.to_owned())
            })
        })
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        return Ok(BTreeMap::new());
    }
    if let Some(sqlite) = &state.sqlite {
        let mut builder = QueryBuilder::<Sqlite>::new(format!(
            "SELECT subject_did, version, package_json, publication_cursor FROM {ROOT_SUBJECT_VERSION_TABLE} WHERE "
        ));
        for (index, (_, subject_did, version)) in pairs.iter().enumerate() {
            if index > 0 {
                builder.push(" OR ");
            }
            builder
                .push("(subject_did = ")
                .push_bind(subject_did)
                .push(" AND version = ")
                .push_bind(version)
                .push(")");
        }
        let rows = builder.build().fetch_all(sqlite.pool()).await?;
        let mut packages = BTreeMap::new();
        let mut response_bytes = 0_usize;
        for row in rows {
            let subject_did = row.get::<String, _>(0);
            let version = row.get::<String, _>(1);
            let package_json = row.get::<String, _>(2);
            if package_json.len() > MAX_CDN_PUBLICATION_PACKAGE_BYTES {
                return Err(anyhow!("resource_package_too_large"));
            }
            response_bytes = response_bytes.saturating_add(package_json.len());
            if response_bytes > MAX_CDN_PUBLICATION_RESPONSE_BYTES {
                return Err(anyhow!("batch_response_too_large"));
            }
            let package = serde_json::from_str::<ResourcePackage>(&package_json)?;
            let publication_cursor = row.get::<i64, _>(3);
            packages.insert(
                format!("{subject_did}:{version}"),
                (package, publication_cursor),
            );
        }
        return Ok(packages);
    }
    if let Some(postgres) = &state.postgres {
        let mut builder =
            QueryBuilder::<Postgres>::new("WITH requested(job_key, subject_did, version) AS (");
        builder.push_values(pairs.iter(), |mut row, (job_key, subject_did, version)| {
            row.push_bind(job_key)
                .push_bind(subject_did)
                .push_bind(version);
        });
        builder.push(format!(
            r#")
            SELECT requested.job_key, versions.package_json::text, versions.publication_cursor
            FROM requested
            JOIN {ROOT_SUBJECT_VERSION_TABLE} AS versions
              ON versions.subject_did = requested.subject_did
             AND versions.version = requested.version
            "#
        ));
        let rows = builder.build().fetch_all(postgres.pool()).await?;
        let mut packages = BTreeMap::new();
        let mut response_bytes = 0_usize;
        for row in rows {
            let job_key = row.get::<String, _>(0);
            let package_json = row.get::<String, _>(1);
            if package_json.len() > MAX_CDN_PUBLICATION_PACKAGE_BYTES {
                return Err(anyhow!("resource_package_too_large"));
            }
            response_bytes = response_bytes.saturating_add(package_json.len());
            if response_bytes > MAX_CDN_PUBLICATION_RESPONSE_BYTES {
                return Err(anyhow!("batch_response_too_large"));
            }
            let package = serde_json::from_str::<ResourcePackage>(&package_json)?;
            let publication_cursor = row.get::<i64, _>(2);
            packages.insert(job_key, (package, publication_cursor));
        }
        return Ok(packages);
    }
    Ok(BTreeMap::new())
}

async fn postgres_publication_projections_for_jobs(
    state: &AppState,
    job_keys: &[String],
) -> Result<BTreeMap<String, PublicationProjectionRow>> {
    let Some(postgres) = &state.postgres else {
        return Ok(BTreeMap::new());
    };
    if job_keys.is_empty() {
        return Ok(BTreeMap::new());
    }
    let pairs = job_keys
        .iter()
        .filter_map(|job_key| {
            job_key.rsplit_once(':').map(|(subject_did, version)| {
                (job_key.clone(), subject_did.to_owned(), version.to_owned())
            })
        })
        .collect::<Vec<_>>();
    if pairs.len() != job_keys.len() {
        return Ok(BTreeMap::new());
    }
    let mut builder =
        QueryBuilder::<Postgres>::new("WITH requested(job_key, subject_did, version) AS (");
    builder.push_values(pairs.iter(), |mut row, (job_key, subject_did, version)| {
        row.push_bind(job_key)
            .push_bind(subject_did)
            .push_bind(version);
    });
    builder.push(format!(
        r#")
        SELECT requested.job_key,
               COALESCE(jobs.status, 'published') AS status,
               COALESCE(jobs.publication_cursor, versions.publication_cursor) AS publication_cursor,
               COALESCE(jobs.resource_did, versions.subject_did) AS resource_did,
               COALESCE(jobs.package_version, versions.version) AS package_version,
               COALESCE(jobs.package_hash, versions.package_hash) AS package_hash,
               COALESCE(jobs.metadata_hash, versions.metadata_hash) AS metadata_hash,
               COALESCE(jobs.did_document_hash, versions.did_document_hash) AS did_document_hash,
               COALESCE(jobs.resource_type, versions.resource_type) AS resource_type,
               COALESCE(jobs.capability_tags_json::text, versions.capability_tags_json::text, '[]'),
               COALESCE(jobs.authorized_domains_json::text, versions.authorized_domains_json::text, '[]')
        FROM requested
        LEFT JOIN {ROOT_CDN_JOB_TABLE} AS jobs
          ON jobs.job_key = requested.job_key
        LEFT JOIN {ROOT_SUBJECT_VERSION_TABLE} AS versions
          ON versions.subject_did = requested.subject_did
         AND versions.version = requested.version
        "#
    ));
    let rows = builder.build().fetch_all(postgres.pool()).await?;
    let mut items = BTreeMap::new();
    for row in rows {
        let job_key = row.get::<String, _>(0);
        let publication_cursor = row
            .try_get::<Option<i64>, _>(2)?
            .ok_or_else(|| anyhow!("missing_publication_projection:{job_key}"))?;
        let resource_did = row
            .try_get::<Option<String>, _>(3)?
            .ok_or_else(|| anyhow!("missing_publication_projection:{job_key}"))?;
        let package_version = row
            .try_get::<Option<String>, _>(4)?
            .ok_or_else(|| anyhow!("missing_publication_projection:{job_key}"))?;
        let package_hash = row
            .try_get::<Option<String>, _>(5)?
            .ok_or_else(|| anyhow!("missing_publication_projection:{job_key}"))?;
        let metadata_hash = row
            .try_get::<Option<String>, _>(6)?
            .ok_or_else(|| anyhow!("missing_publication_projection:{job_key}"))?;
        let did_document_hash = row
            .try_get::<Option<String>, _>(7)?
            .ok_or_else(|| anyhow!("missing_publication_projection:{job_key}"))?;
        let resource_type = row
            .try_get::<Option<String>, _>(8)?
            .unwrap_or_else(|| "unknown".to_owned());
        let capability_tags = row
            .try_get::<Option<String>, _>(9)?
            .map(|value| serde_json::from_str::<Vec<String>>(&value))
            .transpose()?
            .unwrap_or_default();
        let authorized_domains = row
            .try_get::<Option<String>, _>(10)?
            .map(|value| serde_json::from_str::<Vec<String>>(&value))
            .transpose()?
            .unwrap_or_default();
        items.insert(
            job_key,
            PublicationProjectionRow {
                status: row
                    .try_get::<Option<String>, _>(1)?
                    .unwrap_or_else(|| "unknown".to_owned()),
                resource_did,
                package_version,
                publication_cursor,
                package_hash,
                metadata_hash,
                did_document_hash,
                resource_type,
                capability_tags,
                authorized_domains,
            },
        );
    }
    Ok(items)
}

async fn postgres_publication_projection_rows_by_cursor_range(
    state: &AppState,
    delivered_cursor: i64,
    target_cursor: i64,
    max_items: usize,
) -> Result<Vec<PublicationProjectionRow>> {
    let Some(postgres) = &state.postgres else {
        return Ok(Vec::new());
    };
    let rows = sqlx::query(&format!(
        r#"
        SELECT publication_cursor, subject_did, version, package_hash, metadata_hash,
               did_document_hash, resource_type, capability_tags_json::text,
               authorized_domains_json::text
        FROM {ROOT_SUBJECT_VERSION_TABLE}
        WHERE publication_cursor > $1 AND publication_cursor <= $2
        ORDER BY publication_cursor
        LIMIT $3
        "#
    ))
    .bind(delivered_cursor)
    .bind(target_cursor)
    .bind(max_items as i64)
    .fetch_all(postgres.pool())
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(PublicationProjectionRow {
                status: "published".to_owned(),
                publication_cursor: row.get::<i64, _>(0),
                resource_did: row.get::<String, _>(1),
                package_version: row.get::<String, _>(2),
                package_hash: row.get::<String, _>(3),
                metadata_hash: row.get::<String, _>(4),
                did_document_hash: row.get::<String, _>(5),
                resource_type: row.get::<String, _>(6),
                capability_tags: serde_json::from_str::<Vec<String>>(&row.get::<String, _>(7))?,
                authorized_domains: serde_json::from_str::<Vec<String>>(&row.get::<String, _>(8))?,
            })
        })
        .collect()
}

async fn sqlite_cdn_jobs_all_published(state: &AppState, job_keys: &[String]) -> Result<bool> {
    let Some(sqlite) = &state.sqlite else {
        return Ok(false);
    };
    if job_keys.is_empty() {
        return Ok(false);
    }
    let mut builder = QueryBuilder::<Sqlite>::new(format!(
        r#"
        SELECT job_key, status
        FROM {ROOT_CDN_JOB_TABLE}
        WHERE job_key IN (
        "#
    ));
    let mut separated = builder.separated(", ");
    for job_key in job_keys {
        separated.push_bind(job_key);
    }
    separated.push_unseparated(")");
    let rows = builder.build().fetch_all(sqlite.pool()).await?;
    Ok(rows.len() == job_keys.len()
        && rows
            .into_iter()
            .all(|row| row.get::<String, _>(1).eq_ignore_ascii_case("published")))
}

fn discovery_notification_item_from_projection(
    row: PublicationProjectionRow,
) -> DiscoveryNotificationItem {
    DiscoveryNotificationItem {
        publication_cursor: row.publication_cursor,
        resource_did: row.resource_did,
        package_version: row.package_version,
        package_hash: row.package_hash,
        metadata_hash: row.metadata_hash,
        did_document_hash: row.did_document_hash,
        resource_type: row.resource_type,
        capability_tags: row.capability_tags,
        authorized_domains: row.authorized_domains,
    }
}

fn authorized_domains_match(resource_domains: &[String], discovery_domains: &[String]) -> bool {
    if discovery_domains.iter().any(|domain| domain == "*") {
        return true;
    }
    if resource_domains.is_empty() || discovery_domains.is_empty() {
        return false;
    }
    resource_domains.iter().all(|resource_domain| {
        discovery_domains
            .iter()
            .any(|discovery_domain| domain_covers(discovery_domain, resource_domain))
    })
}

fn domain_covers(granted_domain: &str, resource_domain: &str) -> bool {
    granted_domain == resource_domain
        || resource_domain
            .strip_prefix(granted_domain)
            .is_some_and(|suffix| suffix.starts_with('.'))
}

pub(super) fn discovery_notification_targets_for_authorized_rows(
    packages: &[(ResourcePackage, i64)],
    discovery_nodes: &BTreeMap<String, DiscoveryAuthorizationState>,
    _tag_tree: &CapabilityTagTree,
) -> Vec<DiscoveryNotificationTargetItem> {
    if packages.is_empty() {
        return Vec::new();
    }
    let active_discoveries = discovery_nodes
        .iter()
        .filter(|(_, auth)| auth.status == "active")
        .collect::<Vec<_>>();
    if active_discoveries.is_empty() {
        return Vec::new();
    }
    let mut items = Vec::new();
    for (package, publication_cursor) in packages {
        let item = DiscoveryNotificationItem {
            resource_did: package.resource_did.clone(),
            package_version: package.package_version.clone(),
            publication_cursor: *publication_cursor,
            package_hash: package.package_hash.clone(),
            metadata_hash: package.metadata_hash.clone(),
            did_document_hash: package.did_document_hash.clone(),
            resource_type: serde_json::to_value(&package.resource_type)
                .ok()
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .unwrap_or_else(|| "unknown".to_owned()),
            capability_tags: package.metadata.capability_tags.clone(),
            authorized_domains: package.metadata.authorized_domains.clone(),
        };
        for (discovery_did, auth) in &active_discoveries {
            if authorized_domains_match(&item.authorized_domains, &auth.authorized_domains) {
                items.push(DiscoveryNotificationTargetItem {
                    discovery_did: (*discovery_did).clone(),
                    item: item.clone(),
                });
            }
        }
    }
    items
}

pub(super) fn discovery_target_cursors_from_items(
    items: &[DiscoveryNotificationTargetItem],
) -> BTreeMap<String, i64> {
    let mut target_cursors = BTreeMap::<String, i64>::new();
    for item in items {
        target_cursors
            .entry(item.discovery_did.clone())
            .and_modify(|cursor| *cursor = (*cursor).max(item.item.publication_cursor))
            .or_insert(item.item.publication_cursor);
    }
    target_cursors
}

fn discovery_notification_targets_for_projection_rows(
    rows: &[PublicationProjectionRow],
    discovery_nodes: &BTreeMap<String, DiscoveryAuthorizationState>,
    _tag_tree: &CapabilityTagTree,
) -> (Vec<DiscoveryNotificationTargetItem>, BTreeMap<String, i64>) {
    if rows.is_empty() {
        return (Vec::new(), BTreeMap::new());
    }
    let active_discoveries = discovery_nodes
        .iter()
        .filter(|(_, auth)| auth.status == "active")
        .collect::<Vec<_>>();
    if active_discoveries.is_empty() {
        return (Vec::new(), BTreeMap::new());
    }
    let mut items = Vec::new();
    let mut target_cursors = BTreeMap::<String, i64>::new();
    for row in rows {
        let item = discovery_notification_item_from_projection(row.clone());
        for (discovery_did, auth) in &active_discoveries {
            if authorized_domains_match(&item.authorized_domains, &auth.authorized_domains) {
                items.push(DiscoveryNotificationTargetItem {
                    discovery_did: (*discovery_did).clone(),
                    item: item.clone(),
                });
                target_cursors
                    .entry((*discovery_did).clone())
                    .and_modify(|cursor| *cursor = (*cursor).max(item.publication_cursor))
                    .or_insert(item.publication_cursor);
            }
        }
    }
    (items, target_cursors)
}

pub(super) async fn authorized_discovery_summary_items_impl(
    state: &AppState,
    discovery_did: &str,
    delivered_cursor: i64,
    target_cursor: i64,
    max_items: usize,
) -> Result<Vec<DiscoveryNotificationItem>> {
    if target_cursor <= delivered_cursor {
        return Ok(Vec::new());
    }
    let Some(discovery_auth) = super::current_authorization_state(state)
        .discovery_nodes
        .get(discovery_did)
        .cloned()
    else {
        return Ok(Vec::new());
    };
    if discovery_auth.status != "active" {
        return Ok(Vec::new());
    }

    let stored_items = load_authorized_discovery_summary_items_from_store(
        state,
        discovery_did,
        delivered_cursor,
        target_cursor,
        max_items,
    )
    .await?;
    let mut items_by_cursor = std::collections::BTreeMap::<i64, DiscoveryNotificationItem>::new();
    for item in stored_items {
        items_by_cursor.insert(item.publication_cursor, item);
    }

    if let Some(sqlite) = &state.sqlite {
        let window = max_items.max(1).saturating_mul(4).max(100);
        let mut scan_cursor = delivered_cursor;
        while scan_cursor < target_cursor && items_by_cursor.len() < max_items {
            let rows = sqlx::query(&format!(
                r#"
                SELECT publication_cursor, package_json
                FROM {ROOT_SUBJECT_VERSION_TABLE}
                WHERE publication_cursor > ? AND publication_cursor <= ?
                ORDER BY publication_cursor
                LIMIT ?
                "#
            ))
            .bind(scan_cursor)
            .bind(target_cursor)
            .bind(window as i64)
            .fetch_all(sqlite.pool())
            .await?;
            if rows.is_empty() {
                break;
            }
            let row_count = rows.len();
            for row in rows {
                let publication_cursor = row.get::<i64, _>(0);
                scan_cursor = publication_cursor;
                if items_by_cursor.contains_key(&publication_cursor) {
                    continue;
                }
                let package = serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(1))?;
                let item = discovery_notification_item_from_package(publication_cursor, package)?;
                if authorized_domains_match(
                    &item.authorized_domains,
                    &discovery_auth.authorized_domains,
                ) {
                    items_by_cursor.insert(publication_cursor, item);
                }
            }
            if row_count < window {
                break;
            }
        }
        return Ok(items_by_cursor.into_values().take(max_items).collect());
    } else if state.postgres.is_some() {
        let window = max_items.max(1).saturating_mul(4).max(100);
        let mut scan_cursor = delivered_cursor;
        while scan_cursor < target_cursor && items_by_cursor.len() < max_items {
            let rows = postgres_publication_projection_rows_by_cursor_range(
                state,
                scan_cursor,
                target_cursor,
                window,
            )
            .await?;
            if rows.is_empty() {
                break;
            }
            let row_count = rows.len();
            for row in rows {
                let publication_cursor = row.publication_cursor;
                scan_cursor = publication_cursor;
                if items_by_cursor.contains_key(&publication_cursor) {
                    continue;
                }
                let item = discovery_notification_item_from_projection(row);
                if authorized_domains_match(
                    &item.authorized_domains,
                    &discovery_auth.authorized_domains,
                ) {
                    items_by_cursor.insert(publication_cursor, item);
                }
            }
            if row_count < window {
                break;
            }
        }
        return Ok(items_by_cursor.into_values().take(max_items).collect());
    }
    Ok(items_by_cursor.into_values().collect())
}

async fn load_authorized_discovery_summary_items_from_store(
    state: &AppState,
    discovery_did: &str,
    delivered_cursor: i64,
    target_cursor: i64,
    max_items: usize,
) -> Result<Vec<DiscoveryNotificationItem>> {
    if let Some(sqlite) = &state.sqlite {
        let db_rows = sqlx::query(&format!(
            r#"
            SELECT publication_cursor, resource_did, package_version, package_hash,
                   metadata_hash, did_document_hash, resource_type, capability_tags_json,
                   authorized_domains_json
            FROM {ROOT_DISCOVERY_ITEM_TABLE}
            WHERE discovery_did = ? AND publication_cursor > ? AND publication_cursor <= ?
            ORDER BY publication_cursor
            LIMIT ?
            "#
        ))
        .bind(discovery_did)
        .bind(delivered_cursor)
        .bind(target_cursor)
        .bind(max_items as i64)
        .fetch_all(sqlite.pool())
        .await?;
        return db_rows
            .into_iter()
            .map(|row| {
                Ok(DiscoveryNotificationItem {
                    publication_cursor: row.get::<i64, _>(0),
                    resource_did: row.get::<String, _>(1),
                    package_version: row.get::<String, _>(2),
                    package_hash: row.get::<String, _>(3),
                    metadata_hash: row.get::<String, _>(4),
                    did_document_hash: row.get::<String, _>(5),
                    resource_type: row.get::<String, _>(6),
                    capability_tags: serde_json::from_str::<Vec<String>>(&row.get::<String, _>(7))?,
                    authorized_domains: serde_json::from_str::<Vec<String>>(
                        &row.get::<String, _>(8),
                    )?,
                })
            })
            .collect();
    } else if let Some(postgres) = &state.postgres {
        let db_rows = sqlx::query(&format!(
            r#"
            SELECT publication_cursor, resource_did, package_version, package_hash,
                   metadata_hash, did_document_hash, resource_type,
                   capability_tags_json::text,
                   authorized_domains_json::text
            FROM {ROOT_DISCOVERY_ITEM_TABLE}
            WHERE discovery_did = $1 AND publication_cursor > $2 AND publication_cursor <= $3
            ORDER BY publication_cursor
            LIMIT $4
            "#
        ))
        .bind(discovery_did)
        .bind(delivered_cursor)
        .bind(target_cursor)
        .bind(max_items as i64)
        .fetch_all(postgres.pool())
        .await?;
        return db_rows
            .into_iter()
            .map(|row| {
                Ok(DiscoveryNotificationItem {
                    publication_cursor: row.get::<i64, _>(0),
                    resource_did: row.get::<String, _>(1),
                    package_version: row.get::<String, _>(2),
                    package_hash: row.get::<String, _>(3),
                    metadata_hash: row.get::<String, _>(4),
                    did_document_hash: row.get::<String, _>(5),
                    resource_type: row.get::<String, _>(6),
                    capability_tags: serde_json::from_str::<Vec<String>>(&row.get::<String, _>(7))?,
                    authorized_domains: serde_json::from_str::<Vec<String>>(
                        &row.get::<String, _>(8),
                    )?,
                })
            })
            .collect();
    }
    Ok(Vec::new())
}

fn discovery_notification_item_from_package(
    publication_cursor: i64,
    package: ResourcePackage,
) -> Result<DiscoveryNotificationItem> {
    Ok(DiscoveryNotificationItem {
        publication_cursor,
        resource_did: package.resource_did,
        package_version: package.package_version,
        package_hash: package.package_hash,
        metadata_hash: package.metadata_hash,
        did_document_hash: package.did_document_hash,
        resource_type: serde_json::to_value(&package.resource_type)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .unwrap_or_else(|| "unknown".to_owned()),
        capability_tags: package.metadata.capability_tags,
        authorized_domains: package.metadata.authorized_domains,
    })
}
