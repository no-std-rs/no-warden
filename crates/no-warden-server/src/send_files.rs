//! Persistent opaque file bytes and file-Send transport providers.
//! This adapter never interprets the encrypted filename, key, or binary content.
use crate::{Failure, sends, store::Store};
use axum::{
    body::{Body, Bytes},
    extract::{DefaultBodyLimit, FromRequest, Multipart, Request},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use no_warden::{
    VaultService,
    identity::Secret,
    sends::{
        AuthorizedSendFileDownload, FileSendStorage, SendFileMetadata, SendFileQuota, SendStorage,
        ValidatedFileSend, ValidatedSendAccess, ValidatedSendFileUpload,
    },
};
use rand::RngCore;
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize};
use serde_json::json;

// The pinned server's multipart/file transport cap is decimal, unlike its
// larger 525-MiB declared-reservation ceiling in the reusable core.
pub(crate) const MAX_MULTIPART_BYTES: usize = 525_000_000;

#[derive(Deserialize)]
pub(crate) struct Metadata {
    id: String,
    size: u64,
    #[serde(rename = "fileName")]
    file_name: String,
}

pub(crate) struct Upload {
    pub file_name: Option<String>,
    pub data: Vec<u8>,
}

pub(crate) async fn parse_upload(headers: &HeaderMap, body: Bytes) -> Result<Upload, Failure> {
    let invalid_form = || Failure(StatusCode::UNPROCESSABLE_ENTITY, "Invalid multipart form");
    let mut request = Request::new(Body::from(body));
    *request.headers_mut() = headers.clone();
    DefaultBodyLimit::max(MAX_MULTIPART_BYTES).apply(&mut request);
    let mut multipart = Multipart::from_request(request, &())
        .await
        .map_err(|_| invalid_form())?;
    let mut upload = None;
    while let Some(field) = multipart.next_field().await.map_err(|_| invalid_form())? {
        if field
            .name()
            .is_some_and(|name| crate::auth_requests::query_root(name) == "data")
            && upload.is_none()
        {
            let file_name = field.file_name().map(str::to_owned);
            let data = field.bytes().await.map_err(|_| invalid_form())?.to_vec();
            upload = Some(Upload { file_name, data });
        } else {
            // The source form is lenient about unrecognized multipart fields.
            field.bytes().await.map_err(|_| invalid_form())?;
        }
    }
    upload.ok_or_else(invalid_form)
}

pub(crate) fn file_id(raw: &str) -> Result<String, Failure> {
    crate::devices::path_identifier(raw)
        .map_err(|_| Failure(StatusCode::UNPROCESSABLE_ENTITY, "Invalid Send file ID"))
}

impl FileSendStorage for Store {
    type Url = String;

    fn file_send_quota(&mut self, _owner: &str) -> rusqlite::Result<SendFileQuota> {
        Ok(SendFileQuota::default())
    }

    fn create_file_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        plan: &ValidatedFileSend<'_, '_, P>,
    ) -> rusqlite::Result<String> {
        let id = uuid::Uuid::new_v4().to_string();
        let mut entropy = [0_u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut entropy);
        let file_id: String = entropy.iter().map(|byte| format!("{byte:02x}")).collect();
        let length = plan.file_length().ok_or(rusqlite::Error::InvalidQuery)?;
        let length = i64::try_from(length).map_err(|_| rusqlite::Error::InvalidQuery)?;
        let mut data =
            serde_json::to_value(plan.request().file.ok_or(rusqlite::Error::InvalidQuery)?)
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
        if let Some(object) = data.as_object_mut() {
            object.remove("response");
            object.insert("id".into(), json!(file_id));
            object.insert("size".into(), json!(length));
            object.insert(
                "sizeName".into(),
                json!(crate::attachments::display_size(length)),
            );
        }
        let data = serde_json::to_string(&data).map_err(|_| rusqlite::Error::InvalidQuery)?;
        sends::save_file(self, owner, &id, plan, Some((data, file_id)))?;
        Ok(id)
    }

    fn update_file_send<P: Serialize + ?Sized>(
        &mut self,
        owner: &str,
        id: &str,
        plan: &ValidatedFileSend<'_, '_, P>,
    ) -> rusqlite::Result<()> {
        sends::save_file(self, owner, id, plan, None)
    }

    fn send_file_metadata(&mut self, id: &str) -> rusqlite::Result<Option<SendFileMetadata<'_>>> {
        let data = self
            .db
            .query_row("SELECT data FROM personal_sends WHERE id=?1", [id], |row| {
                row.get::<_, String>(0)
            })
            .optional()?;
        self.send_file_metadata_cache = data
            .as_deref()
            .and_then(|data| serde_json::from_str(data).ok());
        Ok(self
            .send_file_metadata_cache
            .as_ref()
            .map(|metadata| SendFileMetadata {
                file_id: &metadata.id,
                file_name: &metadata.file_name,
                file_size: metadata.size,
            }))
    }

    fn commit_send_file_upload(
        &mut self,
        owner: &str,
        plan: &ValidatedSendFileUpload<'_>,
    ) -> rusqlite::Result<bool> {
        let bytes = std::mem::take(&mut self.pending_send_file_data);
        if u64::try_from(bytes.len()).ok() != Some(plan.file_size()) {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let tx = self.db.savepoint()?;
        let exists: bool = tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM send_files WHERE send_id=?1)",
            [plan.id()],
            |row| row.get(0),
        )?;
        if exists {
            return Ok(false);
        }
        if tx.execute(
            "INSERT INTO send_files(send_id,file_id,data)
             SELECT id,?2,?3 FROM personal_sends WHERE id=?1 AND owner=?4 AND kind=1",
            params![plan.id(), plan.file_id(), bytes, owner],
        )? != 1
        {
            return Err(rusqlite::Error::QueryReturnedNoRows);
        }
        let revision = crate::store::next_revision(&tx, owner)?;
        crate::store::bump(&tx, owner, &revision)?;
        tx.commit()?;
        Ok(true)
    }

    fn touch_file_send_access(&mut self, plan: &ValidatedSendAccess<'_>) -> rusqlite::Result<()> {
        let tx = self.db.savepoint()?;
        let owner: String = tx.query_row(
            "SELECT owner FROM personal_sends WHERE id=?1",
            [plan.id()],
            |row| row.get(0),
        )?;
        let revision = crate::store::next_revision(&tx, &owner)?;
        crate::store::bump(&tx, &owner, &revision)?;
        tx.commit()
    }

    fn send_file_upload_url(&mut self, id: &str) -> rusqlite::Result<String> {
        // Arbitrary JSON still reserves a generated upload URL even when no
        // object exists in which to inject canonical file metadata.
        let file_id: String = self.db.query_row(
            "SELECT file_id FROM send_file_reservations WHERE send_id=?1",
            [id],
            |row| row.get(0),
        )?;
        Ok(format!("/sends/{id}/file/{file_id}"))
    }

    fn send_file_download_url(
        &mut self,
        grant: &AuthorizedSendFileDownload<'_>,
    ) -> rusqlite::Result<String> {
        let now = chrono::Utc::now().timestamp();
        let proof = sends::token(
            &sends::signing_key(&self.db)?,
            &sends::Claims {
                nbf: now,
                exp: now + i64::from(grant.expires_in()),
                iss: sends::issuer(&self.download_base)?,
                sub: format!("{}/{}", grant.id(), grant.file_id()),
            },
        )?;
        Ok(format!(
            "{}/api/sends/{}/{}?t={proof}",
            self.download_base.trim_end_matches('/'),
            grant.id(),
            grant.file_id()
        ))
    }

    fn verify_send_file_download(
        &mut self,
        id: &str,
        file_id: &str,
        proof: &Secret<'_>,
    ) -> rusqlite::Result<bool> {
        Ok(sends::verify_token(
            &sends::signing_key(&self.db)?,
            &sends::issuer(&self.download_base)?,
            proof,
            chrono::Utc::now().timestamp(),
        )
        .is_some_and(|subject| subject == format!("{id}/{file_id}")))
    }
}

pub(crate) fn access_file(
    store: &mut Store,
    headers: &HeaderMap,
    raw: &str,
) -> Result<Response, Failure> {
    let proof = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.rsplit("Bearer ").next())
        .ok_or_else(crate::unauthorized)?;
    // Authenticate the Send capability before the file-ID path guard.
    if store
        .verify_send_access_token(&Secret::new(proof))?
        .is_none()
    {
        return Err(crate::unauthorized());
    }
    let id = file_id(raw)?;
    let mut service = VaultService::new(store);
    Ok(
        axum::Json(service.access_send_file(&Secret::new(proof), &id, &sends::context())?)
            .into_response(),
    )
}

pub(crate) fn download(
    store: &mut Store,
    raw_id: &str,
    raw_file_id: &str,
    query: Option<&str>,
) -> Result<Response, Failure> {
    let id = sends::path_id(raw_id)?;
    let file_id = file_id(raw_file_id)?;
    let proof = url::form_urlencoded::parse(query.unwrap_or("").as_bytes())
        .find_map(|(name, value)| {
            (crate::auth_requests::query_root(&name) == "t").then(|| value.into_owned())
        })
        .ok_or(Failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Missing Send download token",
        ))?;
    VaultService::new(&mut *store).authorize_send_file_download(
        &id,
        &file_id,
        &Secret::new(&proof),
    )?;
    let bytes = store
        .db
        .query_row(
            "SELECT data FROM send_files WHERE send_id=?1 AND file_id=?2",
            params![id, file_id],
            |row| row.get::<_, Vec<u8>>(0),
        )
        .optional()?
        .ok_or_else(crate::missing)?;
    let length = bytes.len();
    let mut response = Response::new(Body::from(bytes));
    response
        .headers_mut()
        .insert(axum::http::header::CONTENT_LENGTH, length.into());
    Ok(response)
}
