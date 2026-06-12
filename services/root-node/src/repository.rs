// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use super::*;
use sqlx::Postgres;

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

pub(super) async fn resource_versions_impl(state: &AppState, did: &str) -> Result<Vec<Value>> {
    if let Some(sqlite) = &state.sqlite {
        let rows = sqlx::query(&format!(
            r#"
            SELECT version, did_document_hash, metadata_hash, accepted_at
            FROM {ROOT_SUBJECT_VERSION_TABLE}
            WHERE subject_did = ?
            ORDER BY version
            "#
        ))
        .bind(did)
        .fetch_all(sqlite.pool())
        .await?;
        return Ok(rows
            .into_iter()
            .map(|row| {
                json!({
                    "packageVersion": row.get::<String, _>(0),
                    "didDocumentHash": row.get::<String, _>(1),
                    "metadataHash": row.get::<String, _>(2),
                    "acceptedAt": row.get::<String, _>(3),
                })
            })
            .collect());
    }
    if let Some(postgres) = &state.postgres {
        let rows = sqlx::query(&format!(
            r#"
            SELECT version, did_document_hash, metadata_hash,
                   to_char(accepted_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"')
            FROM {ROOT_SUBJECT_VERSION_TABLE}
            WHERE subject_did = $1
            ORDER BY version
            "#
        ))
        .bind(did)
        .fetch_all(postgres.pool())
        .await?;
        return Ok(rows
            .into_iter()
            .map(|row| {
                json!({
                    "packageVersion": row.get::<String, _>(0),
                    "didDocumentHash": row.get::<String, _>(1),
                    "metadataHash": row.get::<String, _>(2),
                    "acceptedAt": row.get::<String, _>(3),
                })
            })
            .collect());
    }
    Ok(Vec::new())
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
                VALUES (?, 0, 0, ?, 0, NULL, NULL, ?, NULL, ?)
                ON CONFLICT(discovery_did)
                DO UPDATE SET
                    status = excluded.status,
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
                VALUES ($1, 0, 0, $2, 0, NULL, NULL, $3::timestamptz, NULL, $4::timestamptz)
                ON CONFLICT(discovery_did)
                DO UPDATE SET
                    status = excluded.status,
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

        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_PACKAGE_JOB_TABLE}(job_key, subject_did, version, package_json, status, operation, created_at, updated_at)
            VALUES (?, ?, ?, ?, 'accepted', ?, ?, ?)
            ON CONFLICT(job_key)
            DO UPDATE SET
                package_json = excluded.package_json,
                status = 'accepted',
                operation = excluded.operation,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(&package_job_key)
        .bind(resource_did)
        .bind(version)
        .bind(&package_json)
        .bind(operation)
        .bind(now.clone())
        .bind(now)
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
                subject_did, version, did_document_hash, metadata_hash, package_json, archive_path, accepted_at
            )
            VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7::timestamptz)
            ON CONFLICT(subject_did, version)
            DO UPDATE SET
                did_document_hash = excluded.did_document_hash,
                metadata_hash = excluded.metadata_hash,
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
            INSERT INTO {ROOT_PACKAGE_JOB_TABLE}(job_key, subject_did, version, package_json, status, operation, created_at, updated_at)
            VALUES ($1, $2, $3, $4::jsonb, 'accepted', $5, $6::timestamptz, $7::timestamptz)
            ON CONFLICT(job_key)
            DO UPDATE SET
                package_json = excluded.package_json,
                status = 'accepted',
                operation = excluded.operation,
                updated_at = excluded.updated_at
            "#
        ))
        .bind(&package_job_key)
        .bind(resource_did)
        .bind(version)
        .bind(&package_json)
        .bind(operation)
        .bind(now.clone())
        .bind(now)
        .execute(&mut *tx)
        .await?;

        sqlx::query(&format!(
            r#"
            INSERT INTO {ROOT_CDN_JOB_TABLE}(job_key, payload_json, status, attempt_count, lease_owner, lease_expires_at, next_attempt_at, last_error)
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
        let mut tx = postgres.pool().begin().await?;
        let rows = sqlx::query(&format!(
            r#"
            SELECT discovery_did, pending_cursor, delivered_cursor
            FROM {ROOT_DISCOVERY_TARGET_TABLE}
            WHERE status = 'active'
              AND pending_cursor > delivered_cursor
              AND next_attempt_at <= $1::timestamptz
              AND (lease_expires_at IS NULL OR lease_expires_at <= $1::timestamptz)
            ORDER BY pending_cursor DESC, discovery_did
            LIMIT $2
            FOR UPDATE SKIP LOCKED
            "#
        ))
        .bind(&now_rfc3339)
        .bind(limit as i64)
        .fetch_all(&mut *tx)
        .await?;
        let mut claimed = Vec::with_capacity(rows.len());
        for row in rows {
            let discovery_did = row.get::<String, _>(0);
            let pending_cursor = row.get::<i64, _>(1);
            let delivered_cursor = row.get::<i64, _>(2);
            sqlx::query(&format!(
                r#"
                UPDATE {ROOT_DISCOVERY_TARGET_TABLE}
                SET lease_owner = $1, lease_expires_at = $2::timestamptz,
                    attempt_count = attempt_count + 1, last_error = NULL, updated_at = $3::timestamptz
                WHERE discovery_did = $4
                "#
            ))
            .bind(worker_id)
            .bind(&lease_expires_at)
            .bind(&now_rfc3339)
            .bind(&discovery_did)
            .execute(&mut *tx)
            .await?;
            claimed.push(DiscoveryNotifyTargetLease {
                discovery_did,
                target_cursor: pending_cursor,
                delivered_cursor,
            });
        }
        tx.commit().await?;
        return Ok(claimed);
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
    let mut target_cursors = BTreeMap::<String, i64>::new();
    for (discovery_did, auth) in authorization_state.discovery_nodes {
        if auth.status != "active" {
            continue;
        }
        let Some(publication_cursor) = packages
            .iter()
            .filter(|(package, _)| {
                state.tag_tree.matches_authorized_domains(
                    &package.metadata.capability_tags,
                    &auth.authorized_domains,
                )
            })
            .map(|(_, publication_cursor)| *publication_cursor)
            .max()
        else {
            continue;
        };
        target_cursors.insert(discovery_did, publication_cursor);
    }
    advance_discovery_target_cursors_impl(state, target_cursors).await
}

pub(super) async fn advance_discovery_target_cursors_impl(
    state: &AppState,
    target_cursors: BTreeMap<String, i64>,
) -> Result<usize> {
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

pub(super) async fn mark_cdn_jobs_published_batch_impl(
    state: &AppState,
    jobs: &[(String, String)],
) -> Result<()> {
    if jobs.is_empty() {
        return Ok(());
    }
    if let Some(sqlite) = &state.sqlite {
        let mut tx = sqlite.pool().begin().await?;
        for chunk in jobs.chunks(500) {
            let mut builder = QueryBuilder::<Sqlite>::new(format!(
                "DELETE FROM {ROOT_CDN_JOB_TABLE} WHERE job_key IN ("
            ));
            let mut separated = builder.separated(", ");
            for (job_key, _) in chunk {
                separated.push_bind(job_key);
            }
            separated.push_unseparated(")");
            builder.build().execute(&mut *tx).await?;
        }
        tx.commit().await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        let job_keys = jobs
            .iter()
            .map(|(job_key, _)| job_key.clone())
            .collect::<Vec<_>>();
        sqlx::query(&format!(
            "DELETE FROM {ROOT_CDN_JOB_TABLE} WHERE job_key = ANY($1)"
        ))
        .bind(job_keys)
        .execute(postgres.pool())
        .await?;
        return Ok(());
    }
    for (_, did) in jobs {
        super::mark_file_cdn_queue_published(state, did).await?;
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
            "SELECT subject_did, version, rowid FROM {ROOT_SUBJECT_VERSION_TABLE} WHERE "
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
            "SELECT subject_did, version, package_json, rowid FROM {ROOT_SUBJECT_VERSION_TABLE} WHERE "
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
        for row in rows {
            let subject_did = row.get::<String, _>(0);
            let version = row.get::<String, _>(1);
            let package = serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(2))?;
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
        for row in rows {
            let job_key = row.get::<String, _>(0);
            let package = serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(1))?;
            let publication_cursor = row.get::<i64, _>(2);
            packages.insert(job_key, (package, publication_cursor));
        }
        return Ok(packages);
    }
    Ok(BTreeMap::new())
}

pub(super) async fn discovery_notification_targets_for_jobs_impl(
    state: &AppState,
    job_keys: &[String],
) -> Result<Vec<DiscoveryNotificationTargetItem>> {
    let pairs = job_keys
        .iter()
        .filter_map(|job_key| {
            job_key
                .rsplit_once(':')
                .map(|(subject_did, version)| (subject_did.to_owned(), version.to_owned()))
        })
        .collect::<Vec<_>>();
    if pairs.is_empty() {
        return Ok(Vec::new());
    }
    let authorization_state = super::current_authorization_state(state);
    let active_discoveries = authorization_state
        .discovery_nodes
        .into_iter()
        .filter(|(_, auth)| auth.status == "active")
        .collect::<Vec<_>>();
    if active_discoveries.is_empty() {
        return Ok(Vec::new());
    }
    let mut packages = Vec::<(ResourcePackage, i64)>::new();
    if let Some(sqlite) = &state.sqlite {
        let mut builder = QueryBuilder::<Sqlite>::new(format!(
            "SELECT package_json, rowid FROM {ROOT_SUBJECT_VERSION_TABLE} WHERE "
        ));
        for (index, (subject_did, version)) in pairs.iter().enumerate() {
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
        for row in rows {
            packages.push((
                serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0))?,
                row.get::<i64, _>(1),
            ));
        }
    } else if let Some(postgres) = &state.postgres {
        let mut builder =
            QueryBuilder::<Postgres>::new("WITH requested(subject_did, version) AS (");
        builder.push_values(pairs.iter(), |mut row, (subject_did, version)| {
            row.push_bind(subject_did).push_bind(version);
        });
        builder.push(format!(
            r#")
            SELECT versions.package_json::text, versions.publication_cursor
            FROM requested
            JOIN {ROOT_SUBJECT_VERSION_TABLE} AS versions
              ON versions.subject_did = requested.subject_did
             AND versions.version = requested.version
            "#
        ));
        let rows = builder.build().fetch_all(postgres.pool()).await?;
        for row in rows {
            packages.push((
                serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0))?,
                row.get::<i64, _>(1),
            ));
        }
    }
    let mut items = Vec::new();
    for (package, publication_cursor) in packages {
        let item = DiscoveryNotificationItem {
            resource_did: package.resource_did,
            package_version: package.package_version,
            publication_cursor,
            package_hash: package.package_hash,
            metadata_hash: package.metadata_hash,
            did_document_hash: package.did_document_hash,
            resource_type: serde_json::to_value(&package.resource_type)
                .ok()
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
                .unwrap_or_else(|| "unknown".to_owned()),
            capability_tags: package.metadata.capability_tags,
        };
        for (discovery_did, auth) in &active_discoveries {
            if state
                .tag_tree
                .matches_authorized_domains(&item.capability_tags, &auth.authorized_domains)
            {
                items.push(DiscoveryNotificationTargetItem {
                    discovery_did: discovery_did.clone(),
                    item: item.clone(),
                });
            }
        }
    }
    Ok(items)
}

pub(super) async fn authorized_discovery_summary_items_impl(
    state: &AppState,
    discovery_did: &str,
    delivered_cursor: i64,
    target_cursor: i64,
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
    )
    .await?;
    let mut items_by_cursor = std::collections::BTreeMap::<i64, DiscoveryNotificationItem>::new();
    for item in stored_items {
        items_by_cursor.insert(item.publication_cursor, item);
    }

    if let Some(sqlite) = &state.sqlite {
        let rows = sqlx::query(&format!(
            r#"
            SELECT rowid, package_json
            FROM {ROOT_SUBJECT_VERSION_TABLE}
            WHERE rowid > ? AND rowid <= ?
            ORDER BY rowid
            "#
        ))
        .bind(delivered_cursor)
        .bind(target_cursor)
        .fetch_all(sqlite.pool())
        .await?;
        for row in rows {
            let publication_cursor = row.get::<i64, _>(0);
            if items_by_cursor.contains_key(&publication_cursor) {
                continue;
            }
            let package = serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(1))?;
            let item = discovery_notification_item_from_package(publication_cursor, package)?;
            if state.tag_tree.matches_authorized_domains(
                &item.capability_tags,
                &discovery_auth.authorized_domains,
            ) {
                items_by_cursor.insert(publication_cursor, item);
            }
        }
        return Ok(items_by_cursor.into_values().collect());
    } else if let Some(postgres) = &state.postgres {
        let rows = sqlx::query(&format!(
            r#"
            SELECT publication_cursor, package_json::text
            FROM {ROOT_SUBJECT_VERSION_TABLE}
            WHERE publication_cursor > $1 AND publication_cursor <= $2
            ORDER BY publication_cursor
            "#
        ))
        .bind(delivered_cursor)
        .bind(target_cursor)
        .fetch_all(postgres.pool())
        .await?;
        for row in rows {
            let publication_cursor = row.get::<i64, _>(0);
            if items_by_cursor.contains_key(&publication_cursor) {
                continue;
            }
            let package = serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(1))?;
            let item = discovery_notification_item_from_package(publication_cursor, package)?;
            if state.tag_tree.matches_authorized_domains(
                &item.capability_tags,
                &discovery_auth.authorized_domains,
            ) {
                items_by_cursor.insert(publication_cursor, item);
            }
        }
        return Ok(items_by_cursor.into_values().collect());
    }
    Ok(items_by_cursor.into_values().collect())
}

async fn load_authorized_discovery_summary_items_from_store(
    state: &AppState,
    discovery_did: &str,
    delivered_cursor: i64,
    target_cursor: i64,
) -> Result<Vec<DiscoveryNotificationItem>> {
    if let Some(sqlite) = &state.sqlite {
        let db_rows = sqlx::query(&format!(
            r#"
            SELECT publication_cursor, resource_did, package_version, package_hash,
                   metadata_hash, did_document_hash, resource_type, capability_tags_json
            FROM {ROOT_DISCOVERY_ITEM_TABLE}
            WHERE discovery_did = ? AND publication_cursor > ? AND publication_cursor <= ?
            ORDER BY publication_cursor
            "#
        ))
        .bind(discovery_did)
        .bind(delivered_cursor)
        .bind(target_cursor)
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
                })
            })
            .collect();
    } else if let Some(postgres) = &state.postgres {
        let db_rows = sqlx::query(&format!(
            r#"
            SELECT publication_cursor, resource_did, package_version, package_hash,
                   metadata_hash, did_document_hash, resource_type,
                   capability_tags_json::text
            FROM {ROOT_DISCOVERY_ITEM_TABLE}
            WHERE discovery_did = $1 AND publication_cursor > $2 AND publication_cursor <= $3
            ORDER BY publication_cursor
            "#
        ))
        .bind(discovery_did)
        .bind(delivered_cursor)
        .bind(target_cursor)
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
    })
}

pub(super) async fn store_discovery_notification_items_impl(
    state: &AppState,
    items: &[DiscoveryNotificationTargetItem],
) -> Result<usize> {
    if items.is_empty() {
        return Ok(0);
    }
    if let Some(sqlite) = &state.sqlite {
        let mut tx = sqlite.pool().begin().await?;
        for chunk in items.chunks(250) {
            let mut builder = QueryBuilder::<Sqlite>::new(format!(
                r#"
                INSERT INTO {ROOT_DISCOVERY_ITEM_TABLE}(
                    discovery_did, publication_cursor, resource_did, package_version,
                    package_hash, metadata_hash, did_document_hash, resource_type, capability_tags_json
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
                    );
            });
            builder.push(" ON CONFLICT(discovery_did, publication_cursor) DO NOTHING");
            builder.build().execute(&mut *tx).await?;
        }
        tx.commit().await?;
        return Ok(items.len());
    }
    if let Some(postgres) = &state.postgres {
        let mut tx = postgres.pool().begin().await?;
        for chunk in items.chunks(250) {
            let mut builder = QueryBuilder::<Postgres>::new(format!(
                r#"
                INSERT INTO {ROOT_DISCOVERY_ITEM_TABLE}(
                    discovery_did, publication_cursor, resource_did, package_version,
                    package_hash, metadata_hash, did_document_hash, resource_type, capability_tags_json
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
                    .push_bind(sqlx::types::Json(item.item.capability_tags.clone()));
            });
            builder.push(" ON CONFLICT(discovery_did, publication_cursor) DO NOTHING");
            builder.build().execute(&mut *tx).await?;
        }
        tx.commit().await?;
        return Ok(items.len());
    }
    Ok(0)
}
