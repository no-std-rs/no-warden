//! Local conformance host. Production deployment requires the work in ROADMAP.md.
#![forbid(unsafe_code)]

mod attachments;
mod protocol;
mod store;

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{DefaultBodyLimit, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use no_warden::{
    ApiError, ErrorKind, VaultService,
    bulk::CipherBulkOperation,
    identity::{AuthorizedApiKeyGrant, Secret},
    import::ImportView,
    route::{self, Route},
    validation::FolderNamePolicy,
    wire::{
        CipherRequest, ClientCredentialsRequest, FolderRelationship, FolderRequest,
        FolderWriteRequest, ImportFolderRequest, PasswordOrOtpRequest, RegisterRequest,
    },
};
use rand::{RngCore, rngs::OsRng};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
};
use store::Store;

// Core field limits apply to decoded bytes. JSON can expand one byte to six
// bytes, and a request can contain several encrypted fields and metadata.
const MAX_REQUEST_BYTES: usize = 16 * no_warden::validation::MAX_ENCRYPTED_FIELD_BYTES;

#[derive(Clone)]
struct App {
    store: Arc<Mutex<Store>>,
    base: String,
    signing_key: [u8; 32],
}

struct Failure(StatusCode, &'static str);

impl IntoResponse for Failure {
    fn into_response(self) -> Response {
        let error = if self.1 == "Invalid grant" {
            "invalid_grant"
        } else {
            "invalid_request"
        };
        (self.0, Json(json!({"object":"error","message":self.1,"error":error,"error_description":self.1,"ErrorModel":{"Message":self.1}}))).into_response()
    }
}

impl From<ApiError> for Failure {
    fn from(error: ApiError) -> Self {
        Self(
            StatusCode::from_u16(error.status_code()).unwrap(),
            error.message,
        )
    }
}
impl From<rusqlite::Error> for Failure {
    fn from(_: rusqlite::Error) -> Self {
        Self(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Storage operation failed",
        )
    }
}
fn invalid() -> Failure {
    Failure(StatusCode::BAD_REQUEST, "Invalid request")
}
fn unauthorized() -> Failure {
    Failure(StatusCode::UNAUTHORIZED, "Invalid or expired credentials")
}
fn invalid_grant() -> Failure {
    Failure(StatusCode::BAD_REQUEST, "Invalid grant")
}
fn missing() -> Failure {
    Failure(StatusCode::NOT_FOUND, "Resource not found")
}
fn invalid_folder() -> Failure {
    Failure(StatusCode::BAD_REQUEST, "Invalid folder")
}
fn folder_api_error(error: ApiError) -> Failure {
    if error.kind == ErrorKind::NotFound {
        invalid_folder()
    } else {
        error.into()
    }
}

// Decode owned strings before borrowing the core DTO, so JSON escapes are
// accepted. Parsing the raw request first also preserves duplicate-field errors
// which would be lost by decoding a Value alone.
#[derive(Deserialize)]
struct FolderInput {
    name: String,
    #[serde(default)]
    id: Option<String>,
}

fn folder_json_error(error: serde_json::Error) -> Failure {
    match error.classify() {
        serde_json::error::Category::Data => {
            Failure(StatusCode::UNPROCESSABLE_ENTITY, "Invalid request")
        }
        _ => invalid(),
    }
}

fn parse_folder_input(body: &[u8]) -> Result<(FolderInput, Value), Failure> {
    let input: FolderInput = serde_json::from_slice(body).map_err(folder_json_error)?;
    let mut document: Value = serde_json::from_slice(body).map_err(folder_json_error)?;
    // Serde's derived struct decoder also accepts positional arrays. Keep the
    // internal storage representation an object for every accepted input shape.
    if !document.is_object() {
        document = json!({"name": input.name, "id": input.id});
    }
    Ok((input, document))
}

fn json_response(value: Value) -> Response {
    Json(value).into_response()
}
fn digest(value: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(value.as_bytes()))
}
fn random_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let bind = std::env::var("NO_WARDEN_BIND").unwrap_or_else(|_| "127.0.0.1:8000".into());
    let database = std::env::var("NO_WARDEN_DB").unwrap_or_else(|_| "no-warden.db".into());
    let base = std::env::var("NO_WARDEN_URL").unwrap_or_else(|_| format!("http://{bind}"));
    let mut signing_key = [0u8; 32];
    OsRng.fill_bytes(&mut signing_key);
    let mut store = Store::open(&database)?;
    store.download_base = base.clone();
    let app = App {
        store: Arc::new(Mutex::new(store)),
        base,
        signing_key,
    };
    let router = Router::new()
        .fallback(dispatch)
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BYTES))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("no-warden conformance server listening on {bind}; database {database}");
    axum::serve(listener, router)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}

async fn dispatch(
    State(app): State<App>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Failure> {
    if method == Method::OPTIONS {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    if method == Method::GET && uri.path() == "/health" {
        return Ok(json_response(json!({"status":"ok"})));
    }
    let method = route::Method::parse(method.as_str()).ok_or_else(missing)?;
    let route = route::classify(method, uri.path()).ok_or_else(missing)?;
    if let Route::FolderGet(id) | Route::FolderUpdate(id) | Route::FolderDelete(id) = route {
        // Upstream's FromParam validates UUID syntax but keeps its original
        // spelling. In particular, an upper-case UUID must not alias another ID.
        uuid::Uuid::parse_str(id)
            .map_err(|_| Failure(StatusCode::UNPROCESSABLE_ENTITY, "Invalid folder ID"))?;
    }
    if route == Route::Config {
        return Ok(json_response(protocol::config(&app.base)));
    }
    let upload = if matches!(
        route,
        Route::AttachmentUpload(..)
            | Route::AttachmentLegacy(_)
            | Route::AttachmentLegacyReplace(..)
    ) {
        Some(attachments::parse_upload(&headers, body.clone()).await?)
    } else {
        None
    };
    let mut store = app
        .store
        .lock()
        .map_err(|_| Failure(StatusCode::INTERNAL_SERVER_ERROR, "Storage unavailable"))?;
    if let Route::AttachmentDownload(cipher_id, attachment_id) = route {
        return attachments::download(&mut store, cipher_id, attachment_id, uri.query());
    }
    if route == Route::Prelogin {
        let input: Value = serde_json::from_slice(&body).map_err(|_| invalid())?;
        let email = input["email"]
            .as_str()
            .ok_or_else(invalid)?
            .trim()
            .to_lowercase();
        let account = store
            .account("email", &email)?
            .unwrap_or(json!({"kdf":0,"kdfIterations":600000}));
        return Ok(json_response(protocol::prelogin(
            &account,
            uri.path().ends_with("/password"),
        )));
    }
    if route == Route::Register {
        let document: Value = serde_json::from_slice(&body).map_err(|_| invalid())?;
        let request = RegisterRequest::deserialize(&document).map_err(|_| invalid())?;
        no_warden::validation::validate_registration(
            &request,
            no_warden::validation::KdfPolicy::default(),
        )?;
        let salt = SaltString::generate(&mut OsRng);
        let password = Argon2::default()
            .hash_password(request.master_password_hash.as_bytes(), &salt)
            .map_err(|_| invalid())?
            .to_string();
        store.pending = document.clone();
        store.pending["_password"] = json!(password);
        let id = uuid::Uuid::new_v4().to_string();
        VaultService::new(&mut *store).register(&id, &request)?;
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    if route == Route::Token {
        let form = parse_connect_form(&body)?;
        let grant = connect_field(&form, &["grant_type", "granttype"])?.ok_or_else(invalid)?;
        let account = match grant {
            "client_credentials" => {
                let request = ClientCredentialsRequest {
                    grant_type: Some(grant),
                    client_id: connect_field(&form, &["client_id", "clientid"])?,
                    client_secret: connect_field(&form, &["client_secret", "clientsecret"])?
                        .map(Secret::new),
                    scope: connect_field(&form, &["scope"])?,
                    device_identifier: connect_field(
                        &form,
                        &["device_identifier", "deviceidentifier"],
                    )?,
                    device_name: connect_field(&form, &["device_name", "devicename"])?,
                    device_type: connect_field(&form, &["device_type", "devicetype"])?,
                };
                let grant = VaultService::new(&mut *store).authenticate_api_key(&request)?;
                let account = store.account("id", grant.user_id())?.ok_or_else(invalid)?;
                return Ok(json_response(issue_token_grant(
                    &app,
                    &store.db,
                    &account,
                    Some(&grant),
                )?));
            }
            "password" => {
                let email = form
                    .get("username")
                    .ok_or_else(unauthorized)?
                    .trim()
                    .to_lowercase();
                let account = store.account("email", &email)?.ok_or_else(invalid_grant)?;
                let encoded: String = store.db.query_row(
                    "SELECT password FROM accounts WHERE id=?1",
                    [account["id"].as_str()],
                    |r| r.get(0),
                )?;
                let password = form.get("password").ok_or_else(invalid_grant)?;
                let parsed = PasswordHash::new(&encoded).map_err(|_| invalid_grant())?;
                Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .map_err(|_| invalid_grant())?;
                account
            }
            "refresh_token" => {
                let refresh = form.get("refresh_token").ok_or_else(invalid_grant)?;
                let owner: Option<String> = store
                    .db
                    .query_row(
                        "SELECT owner FROM sessions WHERE refresh=?1 AND refresh_expires>?2",
                        params![digest(refresh), chrono::Utc::now().timestamp()],
                        |r| r.get(0),
                    )
                    .optional()?;
                let account = store
                    .account("id", &owner.ok_or_else(invalid_grant)?)?
                    .ok_or_else(invalid_grant)?;
                let tx = store.db.transaction()?;
                // Consume only refresh authority. Clients may still have requests
                // in flight with the old bearer; it remains valid until its
                // original access_expires deadline, as in Vaultwarden.
                let consumed = tx.execute(
                    "UPDATE sessions SET refresh_expires=0 WHERE refresh=?1 AND refresh_expires>?2",
                    params![digest(refresh), chrono::Utc::now().timestamp()],
                )?;
                if consumed != 1 {
                    return Err(invalid_grant());
                }
                let tokens = issue_tokens(&app, &tx, &account)?;
                tx.commit()?;
                return Ok(json_response(tokens));
            }
            _ => return Err(Failure(StatusCode::BAD_REQUEST, "Unsupported grant type")),
        };
        return Ok(json_response(issue_tokens(&app, &store.db, &account)?));
    }
    let bearer = headers
        .get("authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .ok_or_else(unauthorized)?;
    let owner: Option<String> = store
        .db
        .query_row(
            "SELECT owner FROM sessions WHERE access=?1 AND access_expires>?2",
            params![digest(bearer), chrono::Utc::now().timestamp()],
            |r| r.get(0),
        )
        .optional()?;
    let owner = owner.ok_or_else(unauthorized)?;
    let account = store.account("id", &owner)?.ok_or_else(unauthorized)?;
    match route {
        Route::AttachmentReserve(cipher_id) => {
            let document: Value = serde_json::from_slice(&body).map_err(|_| invalid())?;
            let request = no_warden::wire::AttachmentRequest::deserialize(&document)
                .map_err(|_| invalid())?;
            let id = attachments::new_id();
            VaultService::new(&mut *store).reserve_attachment(&owner, cipher_id, &id, &request)?;
            let cipher = store
                .item(&owner, cipher_id, "cipher")?
                .ok_or_else(missing)?;
            let url = format!("/ciphers/{cipher_id}/attachment/{id}");
            let response = no_warden::wire::AttachmentUploadResponse::direct(
                &id,
                Secret::new(&url),
                cipher,
                request.admin_request.unwrap_or(false),
            );
            Ok(Json(response).into_response())
        }
        Route::AttachmentGet(cipher_id, attachment_id) => {
            VaultService::new(&mut *store).authorize_attachment_read(
                &owner,
                cipher_id,
                attachment_id,
            )?;
            let record = attachments::load(&store.db, attachment_id)?.ok_or_else(missing)?;
            Ok(json_response(attachments::wire(
                &store.db, &app.base, &record,
            )?))
        }
        Route::AttachmentUpload(cipher_id, attachment_id) => {
            let upload = upload.ok_or_else(invalid)?;
            let size = upload.data.len() as u64;
            store.pending_attachment_data = upload.data;
            VaultService::new(&mut *store).upload_attachment(
                &owner,
                cipher_id,
                attachment_id,
                size,
            )?;
            Ok(StatusCode::OK.into_response())
        }
        Route::AttachmentLegacy(cipher_id) | Route::AttachmentLegacyReplace(cipher_id, _) => {
            let upload = upload.ok_or_else(invalid)?;
            let request = no_warden::wire::LegacyAttachmentRequest {
                file_name: upload.file_name.as_deref(),
                key: upload.key.as_deref(),
                file_size: upload.data.len() as u64,
            };
            let id = attachments::new_id();
            store.pending_attachment_data = upload.data;
            let mut service = VaultService::new(&mut *store);
            if let Route::AttachmentLegacyReplace(_, old_id) = route {
                service.replace_legacy_attachment(&owner, cipher_id, old_id, &id, &request)?;
            } else {
                service.create_legacy_attachment(&owner, cipher_id, &id, &request)?;
            }
            Ok(json_response(
                store
                    .item(&owner, cipher_id, "cipher")?
                    .ok_or_else(missing)?,
            ))
        }
        Route::AttachmentDelete(cipher_id, attachment_id) => {
            VaultService::new(&mut *store).delete_attachment(&owner, cipher_id, attachment_id)?;
            Ok(json_response(
                json!({"cipher":store.item(&owner, cipher_id, "cipher")?.ok_or_else(missing)?}),
            ))
        }
        Route::AccountApiKey => {
            let document: Value = serde_json::from_slice(&body).map_err(|_| invalid())?;
            let request = PasswordOrOtpRequest::deserialize(&document).map_err(|_| invalid())?;
            let mut service = VaultService::new(&mut *store);
            let response = service.get_api_key(&owner, &request)?;
            Ok(Json(response).into_response())
        }
        Route::AccountRotateApiKey => {
            let document: Value = serde_json::from_slice(&body).map_err(|_| invalid())?;
            let request = PasswordOrOtpRequest::deserialize(&document).map_err(|_| invalid())?;
            let mut service = VaultService::new(&mut *store);
            let response = service.rotate_api_key(&owner, &request)?;
            Ok(Json(response).into_response())
        }
        Route::CipherBulkTrash => cipher_bulk(route, &owner, &body, &mut store),
        Route::CipherBulkRestore => cipher_bulk(route, &owner, &body, &mut store),
        Route::CipherBulkDelete => cipher_bulk(route, &owner, &body, &mut store),
        Route::CipherBulkArchive => cipher_bulk(route, &owner, &body, &mut store),
        Route::CipherBulkUnarchive => cipher_bulk(route, &owner, &body, &mut store),
        Route::CipherArchive(_) => cipher_bulk(route, &owner, &body, &mut store),
        Route::CipherUnarchive(_) => cipher_bulk(route, &owner, &body, &mut store),
        Route::CipherImport => {
            let document: Value = serde_json::from_slice(&body).map_err(|_| invalid())?;
            let folders: Vec<ImportFolderRequest<'_>> = document
                .get("folders")
                .and_then(Value::as_array)
                .ok_or_else(invalid)?
                .iter()
                .map(ImportFolderRequest::deserialize)
                .collect::<Result<_, _>>()
                .map_err(|_| invalid())?;
            let ciphers: Vec<CipherRequest<'_>> = document
                .get("ciphers")
                .and_then(Value::as_array)
                .ok_or_else(invalid)?
                .iter()
                .map(CipherRequest::deserialize)
                .collect::<Result<_, _>>()
                .map_err(|_| invalid())?;
            let folder_relationships: Vec<FolderRelationship> = document
                .get("folderRelationships")
                .and_then(Value::as_array)
                .ok_or_else(invalid)?
                .iter()
                .map(FolderRelationship::deserialize)
                .collect::<Result<_, _>>()
                .map_err(|_| invalid())?;
            let input = ImportView {
                folders: &folders,
                ciphers: &ciphers,
                folder_relationships: &folder_relationships,
            };
            store.pending = document.clone();
            VaultService::new(&mut *store).import_personal(&owner, &input)?;
            Ok(StatusCode::OK.into_response())
        }
        Route::UserKeyId => {
            let request: no_warden::wire::UserKeyIdRequest<'_> =
                serde_json::from_slice(&body).map_err(|_| invalid())?;
            if request.user_key_id.is_empty() || request.user_key_id.len() > 512 {
                return Err(invalid());
            }
            if account
                .get("userKeyId")
                .is_some_and(|value| !value.is_null())
            {
                return Err(Failure(
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "User key identifier is already set",
                ));
            }
            let tx = store.db.transaction()?;
            let revision = store::next_revision(&tx, &owner)?;
            let mut document = account;
            document["userKeyId"] = json!(request.user_key_id);
            tx.execute(
                "UPDATE accounts SET document=?1 WHERE id=?2",
                params![document.to_string(), owner],
            )?;
            store::bump(&tx, &owner, &revision)?;
            tx.commit()?;
            Ok(StatusCode::NO_CONTENT.into_response())
        }
        Route::Profile => Ok(json_response(protocol::profile(&account))),
        Route::RevisionDate => {
            let revision: String =
                store
                    .db
                    .query_row("SELECT revision FROM accounts WHERE id=?1", [&owner], |r| {
                        r.get(0)
                    })?;
            let millis = chrono::DateTime::parse_from_rfc3339(&revision)
                .map_err(|_| invalid())?
                .timestamp_millis();
            Ok(json_response(json!(millis)))
        }
        Route::Sync => Ok(json_response(json!({
            "object":"sync","profile":protocol::profile(&account),"folders":store.items(&owner,"folder")?.iter().map(protocol::folder).collect::<Vec<_>>(),
            "ciphers":store.items(&owner,"cipher")?,"collections":[],"policies":[],"sends":[],
            "domains":{"object":"domains","equivalentDomains":[],"globalEquivalentDomains":[]},
            "userDecryption":protocol::user_decryption(&account)
        }))),
        Route::Folders => Ok(json_response(
            json!({"object":"list","data":store.items(&owner,"folder")?.iter().map(protocol::folder).collect::<Vec<_>>(),"continuationToken":null}),
        )),
        Route::Ciphers => Ok(json_response(
            json!({"object":"list","data":store.items(&owner,"cipher")?,"continuationToken":null}),
        )),
        Route::FolderGet(id) => {
            let document = store
                .item(&owner, id, "folder")?
                .ok_or_else(invalid_folder)?;
            Ok(json_response(protocol::folder(&document)))
        }
        Route::CipherGet(id) => Ok(json_response(
            store.item(&owner, id, "cipher")?.ok_or_else(missing)?,
        )),
        Route::FolderCreate | Route::FolderUpdate(_) => {
            let (input, document) = parse_folder_input(&body)?;
            let write = FolderWriteRequest {
                name: &input.name,
                id: input.id.as_deref(),
            };
            let request = FolderRequest { name: write.name };
            store.pending = document;
            let id = match route {
                Route::FolderUpdate(id) => id.to_owned(),
                _ => uuid::Uuid::new_v4().to_string(),
            };
            let mut service = VaultService::new(&mut *store);
            if matches!(route, Route::FolderUpdate(_)) {
                service
                    .update_folder_with_policy(&owner, &id, &request, FolderNamePolicy::Opaque)
                    .map_err(folder_api_error)?;
            } else {
                service
                    .create_folder_with_policy(&owner, &id, &request, FolderNamePolicy::Opaque)
                    .map_err(folder_api_error)?;
            }
            let document = store
                .item(&owner, &id, "folder")?
                .ok_or_else(invalid_folder)?;
            Ok(json_response(protocol::folder(&document)))
        }
        Route::FolderDelete(id) => {
            VaultService::new(&mut *store)
                .delete_folder(&owner, id)
                .map_err(folder_api_error)?;
            Ok(StatusCode::OK.into_response())
        }
        Route::CipherCreate | Route::CipherCreateWrapped | Route::CipherUpdate(_) => {
            let document: Value = serde_json::from_slice(&body).map_err(|_| invalid())?;
            let payload = if route == Route::CipherCreateWrapped {
                document
                    .get("cipher")
                    .or_else(|| document.get("Cipher"))
                    .ok_or_else(invalid)?
            } else {
                &document
            };
            let request = CipherRequest::deserialize(payload).map_err(|_| invalid())?;
            attachments::validate_rewrap(payload)?;
            let id = match route {
                Route::CipherUpdate(id) => id.to_owned(),
                _ => uuid::Uuid::new_v4().to_string(),
            };
            if matches!(route, Route::CipherUpdate(_)) {
                let existing = store.item(&owner, &id, "cipher")?.ok_or_else(missing)?;
                if request
                    .last_known_revision_date
                    .is_some_and(|revision| existing["revisionDate"] != revision)
                {
                    return Err(Failure(
                        StatusCode::CONFLICT,
                        "The cipher changed; sync and retry",
                    ));
                }
            }
            store.pending = payload.clone();
            let mut service = VaultService::new(&mut *store);
            if matches!(route, Route::CipherUpdate(_)) {
                service.update_cipher(&owner, &id, &request)?;
            } else if route == Route::CipherCreateWrapped {
                let wrapper = no_warden::wire::CipherCreateRequest::deserialize(&document)
                    .map_err(|_| invalid())?;
                service.create_cipher_wrapped(&owner, &id, &wrapper)?;
            } else {
                service.create_cipher(&owner, &id, &request)?;
            }
            Ok(json_response(
                store.item(&owner, &id, "cipher")?.ok_or_else(missing)?,
            ))
        }
        Route::CipherSoftDelete(id) | Route::CipherRestore(id) | Route::CipherDelete(id) => {
            let mut service = VaultService::new(&mut *store);
            match route {
                Route::CipherSoftDelete(_) => service.soft_delete_cipher(&owner, id)?,
                Route::CipherRestore(_) => service.restore_cipher(&owner, id)?,
                _ => service.delete_cipher(&owner, id)?,
            }
            if matches!(route, Route::CipherRestore(_)) {
                Ok(json_response(
                    store.item(&owner, id, "cipher")?.ok_or_else(missing)?,
                ))
            } else {
                Ok(StatusCode::NO_CONTENT.into_response())
            }
        }
        _ => Err(missing()),
    }
}

fn cipher_bulk(
    route: Route<'_>,
    owner: &str,
    body: &[u8],
    store: &mut Store,
) -> Result<Response, Failure> {
    let operation = match route {
        Route::CipherBulkTrash => CipherBulkOperation::Trash,
        Route::CipherBulkRestore => CipherBulkOperation::Restore,
        Route::CipherBulkDelete => CipherBulkOperation::Delete,
        Route::CipherArchive(_) | Route::CipherBulkArchive => CipherBulkOperation::Archive,
        Route::CipherUnarchive(_) | Route::CipherBulkUnarchive => CipherBulkOperation::Unarchive,
        _ => return Err(missing()),
    };
    let single = match route {
        Route::CipherArchive(id) | Route::CipherUnarchive(id) => Some(id),
        _ => None,
    };
    let document: Value = if single.is_some() {
        Value::Null
    } else {
        serde_json::from_slice(body).map_err(|_| invalid())?
    };
    let ids: Vec<&str> = if let Some(id) = single {
        vec![id]
    } else {
        document
            .get("ids")
            .and_then(Value::as_array)
            .ok_or_else(invalid)?
            .iter()
            .map(|id| id.as_str().ok_or_else(invalid))
            .collect::<Result<_, _>>()?
    };
    let mut scratch = vec![""; ids.len()];
    let count = VaultService::new(&mut *store).bulk_ciphers(owner, operation, ids, &mut scratch)?;
    if matches!(
        operation,
        CipherBulkOperation::Trash | CipherBulkOperation::Delete
    ) {
        return Ok(StatusCode::OK.into_response());
    }
    let data = scratch[..count]
        .iter()
        .map(|id| store.item(owner, id, "cipher")?.ok_or_else(missing))
        .collect::<Result<Vec<_>, Failure>>()?;
    if single.is_some() {
        Ok(json_response(data.into_iter().next().ok_or_else(missing)?))
    } else {
        Ok(json_response(
            json!({"object":"list","data":data,"continuationToken":null}),
        ))
    }
}

// Rocket's pinned ConnectData accepts explicit underscore/compact aliases without
// regard to ASCII case. Ambiguous alias submissions fail rather than choosing a value.
fn parse_connect_form(body: &[u8]) -> Result<BTreeMap<String, String>, Failure> {
    let fields: Vec<(String, String)> =
        serde_urlencoded::from_bytes(body).map_err(|_| invalid())?;
    let mut form = BTreeMap::new();
    for (key, value) in fields {
        if form.insert(key, value).is_some() {
            return Err(invalid());
        }
    }
    Ok(form)
}

fn connect_field<'a>(
    form: &'a BTreeMap<String, String>,
    aliases: &[&str],
) -> Result<Option<&'a str>, Failure> {
    let mut matches = form
        .iter()
        .filter(|(key, _)| aliases.iter().any(|alias| key.eq_ignore_ascii_case(alias)));
    let value = matches.next().map(|(_, value)| value.as_str());
    if matches.next().is_some() {
        return Err(invalid());
    }
    Ok(value)
}

fn issue_tokens(app: &App, db: &rusqlite::Connection, account: &Value) -> Result<Value, Failure> {
    issue_token_grant(app, db, account, None)
}

fn issue_token_grant(
    app: &App,
    db: &rusqlite::Connection,
    account: &Value,
    api: Option<&AuthorizedApiKeyGrant<'_>>,
) -> Result<Value, Failure> {
    let timestamp = chrono::Utc::now().timestamp();
    db.execute(
        "DELETE FROM sessions WHERE access_expires<=?1 AND refresh_expires<=?1",
        [timestamp],
    )?;
    let expires_in = api.map_or(3600_i64, |grant| i64::from(grant.expires_in()));
    let client_id = api.map_or("cli", |grant| grant.client_id());
    let scopes = if api.is_some() {
        vec!["api"]
    } else {
        vec!["api", "offline_access"]
    };
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = json!({"sub":account["id"],"email":account["email"],"email_verified":true,
        "name":account["name"],"premium":true,"iss":app.base,"iat":timestamp,"nbf":timestamp,"exp":timestamp+expires_in,
        "client_id":client_id,"scope":scopes,"amr":["Application"],"sstamp":account["id"],"jti":random_token()});
    let unsigned = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
    let mut mac = Hmac::<Sha256>::new_from_slice(&app.signing_key).expect("HMAC key size");
    mac.update(unsigned.as_bytes());
    let access = format!(
        "{unsigned}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    );
    let refresh = api.is_none().then(random_token);
    let refresh_digest = refresh
        .as_deref()
        .map(digest)
        .unwrap_or_else(|| format!("access-only:{}", digest(&access)));
    let refresh_expires = if refresh.is_some() {
        timestamp + 30 * 24 * 3600
    } else {
        0
    };
    db.execute("INSERT INTO sessions(access,refresh,owner,access_expires,refresh_expires) VALUES(?1,?2,?3,?4,?5)",params![digest(&access),refresh_digest,account["id"].as_str(),timestamp+expires_in,refresh_expires])?;
    let mut response = if api.is_some() {
        protocol::api_key_token_fields(account)
    } else {
        protocol::token_fields(account)
    };
    response["access_token"] = json!(access);
    if let Some(refresh) = refresh {
        response["refresh_token"] = json!(refresh);
    }
    response["token_type"] = json!("Bearer");
    response["expires_in"] = json!(expires_in);
    response["scope"] = json!(if api.is_some() {
        "api"
    } else {
        "api offline_access"
    });
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn folder_input_preserves_json_error_categories_and_duplicate_fields() {
        for (body, expected) in [
            (b"".as_slice(), StatusCode::BAD_REQUEST),
            (b"{".as_slice(), StatusCode::BAD_REQUEST),
            (
                br#"{"name":"unterminated}"#.as_slice(),
                StatusCode::BAD_REQUEST,
            ),
            (br#"{"name":"\uD800"}"#.as_slice(), StatusCode::BAD_REQUEST),
            (
                br#"{"name":"ok"} trailing"#.as_slice(),
                StatusCode::BAD_REQUEST,
            ),
            (b"{}".as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
            (b"[]".as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
            (b"null".as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
            (
                br#"{"name":null}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                br#"{"name":7}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                br#"{"name":false}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                br#"{"name":[]}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                br#"{"name":"ok","id":7}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                br#"{"name":"ok","id":false}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                br#"{"name":"ok","id":[]}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                br#"{"name":"ok","id":{}}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                br#"{"name":"first","name":"second"}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                br#"{"name":"first","na\u006de":"second"}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                br#"{"name":"ok","id":null,"id":null}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let failure = parse_folder_input(body)
                .err()
                .expect("Invalid folder input was accepted.");
            assert_eq!(failure.0, expected);
            assert_eq!(failure.1, "Invalid request");
        }
    }

    #[test]
    fn folder_input_decodes_escapes_and_accepts_opaque_names_and_ignored_string_ids() {
        let (input, document) = parse_folder_input(br#"{"name":"quoted \" \\ caf\u00e9 \ud83d\udd10","id":"not a UUID","privateExtension":{"nested":[1,null,true]}}"#)
            .unwrap_or_else(|_| panic!("Escaped folder input was rejected."));
        assert!(input.name == "quoted \" \\ café 🔐");
        assert!(input.id.as_deref() == Some("not a UUID"));
        assert!(document["name"] == input.name);
        assert!(document["privateExtension"] == json!({"nested":[1,null,true]}));
        for body in [
            br#"{"name":""}"#.as_slice(),
            br#"{"name":"future-encryption-format","id":null}"#.as_slice(),
            br#"{"name":"opaque name","id":""}"#.as_slice(),
            br#"["positional name",null]"#.as_slice(),
        ] {
            let (input, document) = parse_folder_input(body)
                .unwrap_or_else(|_| panic!("Valid folder input was rejected."));
            assert!(document.is_object());
            assert!(document["name"] == input.name);
        }
    }

    #[tokio::test]
    async fn folder_http_errors_preserve_persisted_state_and_owner_isolation() {
        const FOLDER_ID: &str = "f0c3f062-6368-4d80-8ec9-c9b8cc209749";
        let app = App {
            store: Arc::new(Mutex::new(Store::open(":memory:").unwrap())),
            base: "http://127.0.0.1".into(),
            signing_key: [1; 32],
        };
        {
            let mut store = app.store.lock().unwrap();
            for owner in ["alice", "bob"] {
                store.db.execute(
                    "INSERT INTO accounts(id,email,document,password,revision) VALUES(?1,?2,?3,'test',?4)",
                    params![owner, format!("{owner}@example.test"), json!({"id":owner}).to_string(), store::now()],
                ).unwrap();
                store.db.execute(
                    "INSERT INTO sessions(access,refresh,owner,access_expires,refresh_expires) VALUES(?1,?2,?3,?4,0)",
                    params![digest(&format!("fixture-folder-{owner}")), format!("unused-fixture-refresh-{owner}"), owner, chrono::Utc::now().timestamp() + 3_600],
                ).unwrap();
            }
            store.pending =
                json!({"name":"initial opaque name","privateExtension":{"preserved":true}});
            VaultService::new(&mut *store)
                .create_folder_with_policy(
                    "alice",
                    FOLDER_ID,
                    &FolderRequest {
                        name: "initial opaque name",
                    },
                    FolderNamePolicy::Opaque,
                )
                .unwrap();
            store
                .db
                .execute_batch(
                    "CREATE TRIGGER reject_folder_revision BEFORE UPDATE OF revision ON accounts
                 BEGIN SELECT RAISE(ABORT,'injected folder revision failure'); END;",
                )
                .unwrap();
        }
        let persisted = || {
            let store = app.store.lock().unwrap();
            store.db.prepare("SELECT 'account:'||id||':'||document||':'||revision FROM accounts UNION ALL SELECT 'item:'||id||':'||owner||':'||document||':'||deleted||':'||revision||':'||created FROM items ORDER BY 1")
                .unwrap().query_map([], |row| row.get::<_, String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
        };
        let before = persisted();
        let update_path = format!("/api/folders/{FOLDER_ID}");
        for (owner, method, path, body, status, message) in [
            (
                "alice",
                Method::POST,
                "/api/folders",
                b"{".as_slice(),
                StatusCode::BAD_REQUEST,
                "Invalid request",
            ),
            (
                "alice",
                Method::PUT,
                update_path.as_str(),
                br#"{"name":7}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid request",
            ),
            (
                "alice",
                Method::PUT,
                update_path.as_str(),
                br#"{"name":"one","name":"two"}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid request",
            ),
            (
                "alice",
                Method::POST,
                "/api/folders",
                br#"{"name":""}"#.as_slice(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage operation failed.",
            ),
            (
                "alice",
                Method::PUT,
                update_path.as_str(),
                br#"{"name":"changed opaque name"}"#.as_slice(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "Storage operation failed.",
            ),
            (
                "bob",
                Method::PUT,
                update_path.as_str(),
                br#"{"name":"foreign update"}"#.as_slice(),
                StatusCode::BAD_REQUEST,
                "Invalid folder",
            ),
            (
                "bob",
                Method::DELETE,
                update_path.as_str(),
                b"".as_slice(),
                StatusCode::BAD_REQUEST,
                "Invalid folder",
            ),
            (
                "bob",
                Method::GET,
                update_path.as_str(),
                b"".as_slice(),
                StatusCode::BAD_REQUEST,
                "Invalid folder",
            ),
            (
                "alice",
                Method::GET,
                "/api/folders/not-a-uuid",
                b"".as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
                "Invalid folder ID",
            ),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "authorization",
                format!("Bearer fixture-folder-{owner}").parse().unwrap(),
            );
            let result = dispatch(
                State(app.clone()),
                method,
                path.parse().unwrap(),
                headers,
                Bytes::copy_from_slice(body),
            )
            .await;
            let failure = match result {
                Ok(_) => panic!("A rejected folder request succeeded."),
                Err(failure) => failure,
            };
            assert_eq!(failure.0, status);
            assert_eq!(failure.1, message);
            assert!(
                persisted() == before,
                "A rejected folder request changed persisted state."
            );
        }
    }

    #[test]
    fn api_key_issuance_has_only_access_authority_and_rotation_keeps_sessions() {
        let app = App {
            store: Arc::new(Mutex::new(Store::open(":memory:").unwrap())),
            base: "http://127.0.0.1".into(),
            signing_key: [1; 32],
        };
        let mut store = app.store.lock().unwrap();
        let account = json!({"id":"alice","email":"alice@example.test","name":"Alice"});
        store.db.execute("INSERT INTO accounts(id,email,document,password,revision) VALUES('alice','alice@example.test',?1,'test',?2)",
            params![account.to_string(),store::now()]).unwrap();
        let password_tokens = issue_tokens(&app, &store.db, &account)
            .unwrap_or_else(|_| panic!("Password token issuance failed"));
        let key = no_warden::identity::IdentityStorage::get_or_create_api_key(&mut *store, "alice")
            .unwrap()
            .api_key
            .expose_secret()
            .to_owned();
        let request = ClientCredentialsRequest {
            grant_type: Some("client_credentials"),
            client_id: Some("user.alice"),
            client_secret: Some(Secret::new(&key)),
            scope: Some("api"),
            device_identifier: Some("device"),
            device_name: Some("CLI"),
            device_type: Some("8"),
        };
        let grant = VaultService::new(&mut *store)
            .authenticate_api_key(&request)
            .unwrap();
        let tokens = issue_token_grant(&app, &store.db, &account, Some(&grant))
            .unwrap_or_else(|_| panic!("API token issuance failed"));
        assert_eq!(tokens["scope"], "api");
        assert_eq!(tokens["expires_in"], 7200);
        assert!(tokens.get("refresh_token").is_none());
        assert!(tokens.get("MasterPasswordPolicy").is_none());
        let access = tokens["access_token"].as_str().unwrap();
        let claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(access.split('.').nth(1).unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(claims["client_id"], "user.alice");
        assert_eq!(claims["scope"], json!(["api"]));
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            7200
        );
        let refresh_expiry: i64 = store
            .db
            .query_row(
                "SELECT refresh_expires FROM sessions WHERE access=?1",
                [digest(access)],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(refresh_expiry, 0);
        no_warden::identity::IdentityStorage::rotate_api_key(&mut *store, "alice").unwrap();
        for bearer in [access, password_tokens["access_token"].as_str().unwrap()] {
            let live: bool = store
                .db
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sessions WHERE access=?1 AND access_expires>?2)",
                    params![digest(bearer), chrono::Utc::now().timestamp()],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(live, "Rotation must preserve existing bearer authority");
        }
        let live_refresh: bool = store
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sessions WHERE refresh=?1 AND refresh_expires>?2)",
                params![
                    digest(password_tokens["refresh_token"].as_str().unwrap()),
                    chrono::Utc::now().timestamp()
                ],
                |row| row.get(0),
            )
            .unwrap();
        assert!(
            live_refresh,
            "Rotation must preserve password refresh authority"
        );
    }

    #[test]
    fn connect_form_aliases_preserve_values_and_reject_ambiguity() {
        assert!(parse_connect_form(b"client_id=user.alice&client_id=user.bob").is_err());
        assert!(parse_connect_form(b"client_id=user.alice&client%5Fid=user.bob").is_err());
        let form = BTreeMap::from([
            ("CLIENTID".into(), "user.MixedCase".into()),
            ("Device_Type".into(), "unknown-kind".into()),
        ]);
        assert_eq!(
            connect_field(&form, &["client_id", "clientid"])
                .unwrap_or_else(|_| panic!("Client alias resolution failed")),
            Some("user.MixedCase")
        );
        assert_eq!(
            connect_field(&form, &["device_type", "devicetype"])
                .unwrap_or_else(|_| panic!("Device alias resolution failed")),
            Some("unknown-kind")
        );
        assert_eq!(
            connect_field(&form, &["scope"]).unwrap_or_else(|_| panic!("Scope resolution failed")),
            None
        );
        let mut ambiguous = form;
        ambiguous.insert("client_id".into(), "different".into());
        assert!(connect_field(&ambiguous, &["client_id", "clientid"]).is_err());
    }

    #[test]
    fn token_issuance_purges_only_sessions_with_no_live_authority() {
        let app = App {
            store: Arc::new(Mutex::new(Store::open(":memory:").unwrap())),
            base: "http://127.0.0.1".into(),
            signing_key: [1; 32],
        };
        let store = app.store.lock().unwrap();
        let account = json!({"id":"alice","email":"alice@example.test","name":"Alice"});
        store.db.execute(
            "INSERT INTO accounts(id,email,document,password,revision) VALUES('alice','alice@example.test',?1,'test',?2)",
            params![account.to_string(), store::now()],
        ).unwrap();
        let now = chrono::Utc::now().timestamp();
        for (access, refresh, access_expires, refresh_expires) in [
            ("consumed-expired", "r1", now - 60, 0),
            ("both-expired", "r2", now - 60, now - 60),
            ("expiry-boundary", "r3", now, now),
            ("live-access", "r4", now + 600, 0),
            ("live-refresh", "r5", now - 60, now + 600),
        ] {
            store.db.execute(
                "INSERT INTO sessions(access,refresh,owner,access_expires,refresh_expires) VALUES(?1,?2,'alice',?3,?4)",
                params![access,refresh,access_expires,refresh_expires],
            ).unwrap();
        }
        assert!(issue_tokens(&app, &store.db, &account).is_ok());
        let mut query = store
            .db
            .prepare("SELECT access FROM sessions ORDER BY access")
            .unwrap();
        let remaining = query
            .query_map([], |row| row.get::<_, String>(0))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(remaining.len(), 3); // Two live authorities and the new pair.
        assert!(remaining.iter().any(|access| access == "live-access"));
        assert!(remaining.iter().any(|access| access == "live-refresh"));
    }

    #[test]
    fn coverage_records_match_the_compiled_route_classifier() {
        let coverage: Value = serde_json::from_str(include_str!(
            "../../../compatibility/no-warden-coverage.json"
        ))
        .unwrap();
        for record in coverage["routes"].as_array().unwrap() {
            let method = route::Method::parse(record["method"].as_str().unwrap()).unwrap();
            let path = record["path"]
                .as_str()
                .unwrap()
                .replace("{id}", "inventory-id")
                .replace("{attachment_id}", "inventory-attachment");
            let actual = route::classify(method, &path);
            assert_eq!(
                actual.is_some(),
                record["routed"].as_bool().unwrap(),
                "{path}"
            );
            if let Some(actual) = actual {
                let expected = record["classifier_enum"]
                    .as_str()
                    .unwrap()
                    .split('(')
                    .next()
                    .unwrap();
                assert_eq!(
                    format!("{actual:?}").split('(').next().unwrap(),
                    expected,
                    "{path}"
                );
            }
        }
    }
}
