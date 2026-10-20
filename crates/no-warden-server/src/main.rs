//! Local conformance host. Production deployment requires the work in ROADMAP.md.
#![forbid(unsafe_code)]

mod account_deletion;
mod account_kdf;
mod account_key_id;
mod account_password;
mod account_security;
mod attachments;
mod auth_requests;
mod cipher_reads;
mod devices;
mod domains;
mod organization_bulk_confirmations;
mod organization_bulk_member_removal;
mod organization_bulk_member_status;
mod organization_collections;
mod organization_confirmations;
mod organization_invitations;
mod organization_member_removal;
mod organization_member_status;
mod organization_members;
mod organizations;
mod password_login;
mod prelogin;
mod protocol;
mod purge;
mod refresh;
mod registration;
mod send_files;
#[cfg(test)]
mod send_files_tests;
mod sends;
mod store;

use argon2::{Argon2, PasswordHasher, password_hash::SaltString};
use axum::{
    Json, Router,
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit, State},
    http::{HeaderMap, Method, StatusCode, Uri},
    response::{IntoResponse, Response},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use no_warden::{
    ApiError, ErrorKind, VaultService,
    auth_login::AuthRequestLoginContext,
    auth_requests::AuthRequestContext,
    bulk::CipherBulkOperation,
    devices::DeviceRegistration,
    domains::DomainProjection,
    identity::{AuthorizedApiKeyGrant, Secret},
    import::ImportView,
    route::{self, Route},
    validation::FolderNamePolicy,
    wire::{
        AccountKeys, AuthRequestCreateRequest, AuthRequestLoginRequest, AuthRequestUpdateRequest,
        AvatarUpdateRequest, CipherRequest, ClientCredentialsRequest, DevicePushTokenRequest,
        FolderRelationship, FolderRequest, FolderWriteRequest, ImportFolderRequest,
        PasswordOrOtpRequest, ProfileUpdateRequest, RegisterRequest,
    },
};
use rand::{RngCore, rngs::OsRng};
use rusqlite::{OptionalExtension, params};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};
use store::Store;

impl From<no_warden::registration::RegistrationError> for Failure {
    fn from(error: no_warden::registration::RegistrationError) -> Self {
        Self(
            StatusCode::from_u16(error.status_code()).expect("Core HTTP status"),
            error.message(),
        )
    }
}

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
        if password_login::is_password_error(self.1)
            || self.1 == "refresh_token cannot be blank"
            || sends::is_send_error(self.1)
            || self.1 == "Unexpected data"
            || self.1 == "Can't delete last owner"
            || self.1 == "Can't find organization details"
            || self.1 == "Organization not found"
            || self.1 == "User not allowed to create organizations"
            || organization_collections::is_collection_error(self.1)
            || organization_confirmations::is_confirmation_error(self.1)
            || organization_member_removal::is_removal_error(self.1)
            || organization_member_status::is_status_error(self.1)
            || self.1 == "The specified user isn't a member of the organization"
            || self.1 == "Member id is required"
        {
            return password_login::error_response(self.0, self.1);
        }
        if self.1 == "Invalid refresh token" {
            return (self.0, Json(json!({"error":"invalid_grant"}))).into_response();
        }
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

fn json_guard_error(error: serde_json::Error) -> Failure {
    match error.classify() {
        serde_json::error::Category::Data => {
            Failure(StatusCode::UNPROCESSABLE_ENTITY, "Invalid request")
        }
        _ => invalid(),
    }
}

fn parse_folder_input(body: &[u8]) -> Result<(FolderInput, Value), Failure> {
    let input: FolderInput = serde_json::from_slice(body).map_err(json_guard_error)?;
    let mut document: Value = serde_json::from_slice(body).map_err(json_guard_error)?;
    // Serde's derived struct decoder also accepts positional arrays. Keep the
    // internal storage representation an object for every accepted input shape.
    if !document.is_object() {
        document = json!({"name": input.name, "id": input.id});
    }
    Ok((input, document))
}

// Field declaration order matches upstream KeysData for positional JSON
// sequences. Named fields also accept escapes and reject known duplicates.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AccountKeysInput {
    encrypted_private_key: String,
    public_key: String,
}

fn parse_account_keys_input(body: &[u8]) -> Result<AccountKeysInput, Failure> {
    serde_json::from_slice(body).map_err(json_guard_error)
}

#[derive(Deserialize)]
struct ProfileInput {
    name: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct AvatarInput {
    avatar_color: Option<String>,
}

fn parse_profile_input(body: &[u8]) -> Result<ProfileInput, Failure> {
    serde_json::from_slice(body).map_err(json_guard_error)
}

fn parse_avatar_input(body: &[u8]) -> Result<AvatarInput, Failure> {
    serde_json::from_slice(body).map_err(json_guard_error)
}

fn json_response(value: Value) -> Response {
    Json(value).into_response()
}
fn profile_document(store: &mut Store, account: &Value) -> Result<Value, Failure> {
    let owner = account["id"].as_str().ok_or_else(invalid)?;
    let stamp = account_security::stamp(&store.db, owner)?;
    let mut document = protocol::profile(account, &stamp);
    let mut service = VaultService::new(&mut *store);
    let organizations = service.profile_organizations(owner)?;
    document["organizations"] =
        serde_json::to_value(organizations.confirmed()).map_err(|_| invalid())?;
    document["organizationsNew"] =
        serde_json::to_value(organizations.accepted_and_confirmed()).map_err(|_| invalid())?;
    Ok(document)
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
        .fallback(dispatch_http)
        .layer(axum::middleware::from_fn_with_state(
            app.clone(),
            request_body_limit,
        ))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    eprintln!("no-warden conformance server listening on {bind}; database {database}");
    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async {
        let _ = tokio::signal::ctrl_c().await;
    })
    .await?;
    Ok(())
}

async fn request_body_limit(
    State(app): State<App>,
    mut request: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    let is_file_upload = route::Method::parse(request.method().as_str())
        .and_then(|method| route::classify(method, request.uri().path()))
        .is_some_and(|route| matches!(route, Route::SendFileUpload(..)));
    let maximum = if is_file_upload {
        if !request
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("multipart/form-data"))
        {
            return missing().into_response();
        }
        // The Bytes extractor collects the body before dispatch runs. Require
        // current account/device authority before granting its larger limit.
        if let Err(error) = authorize_send_upload(&app, request.headers()) {
            return error.into_response();
        }
        send_files::MAX_MULTIPART_BYTES
    } else {
        MAX_REQUEST_BYTES
    };
    DefaultBodyLimit::max(maximum).apply(&mut request);
    next.run(request).await
}

fn authorize_send_upload(app: &App, headers: &HeaderMap) -> Result<(), Failure> {
    let bearer = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .ok_or_else(unauthorized)?;
    let access = digest(bearer);
    let mut store = app
        .store
        .lock()
        .map_err(|_| Failure(StatusCode::INTERNAL_SERVER_ERROR, "Storage unavailable"))?;
    let now = chrono::Utc::now().timestamp();
    let owner: Option<String> = store
        .db
        .query_row(
            "SELECT owner FROM sessions WHERE access=?1 AND access_expires>?2",
            params![access, now],
            |row| row.get(0),
        )
        .optional()?;
    let Some(owner) = owner else {
        // Preserve ordinary auth's expired password-exception cleanup, while
        // previous-stamp sessions remain ineligible for this upload route.
        account_password::previous_owner(&mut store.db, &access, "", now)?;
        return Err(unauthorized());
    };
    store.account("id", &owner)?.ok_or_else(unauthorized)?;
    devices::access_binding(&store.db, &access, &owner)?.ok_or_else(unauthorized)?;
    Ok(())
}

async fn dispatch_http(
    State(app): State<App>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Failure> {
    dispatch_with_peer(app, method, uri, headers, body, peer.ip()).await
}

#[cfg(test)]
async fn dispatch(
    State(app): State<App>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Response, Failure> {
    // Existing direct-dispatch tests have no socket. New IP-sensitive tests pass
    // their peer explicitly; production always obtains it from ConnectInfo.
    dispatch_with_peer(app, method, uri, headers, body, IpAddr::from([0, 0, 0, 0])).await
}

async fn dispatch_with_peer(
    app: App,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
    peer_ip: IpAddr,
) -> Result<Response, Failure> {
    if method == Method::OPTIONS {
        return Ok(StatusCode::NO_CONTENT.into_response());
    }
    if method == Method::GET && uri.path() == "/health" {
        return Ok(json_response(json!({"status":"ok"})));
    }
    let method = route::Method::parse(method.as_str()).ok_or_else(missing)?;
    // Upstream's PUT/DELETE ID handlers authenticate before rejecting the literal
    // `purge` as a UUID. GET now uses the ordinary read route and its UUID guard.
    let invalid_purge_id = uri.path().strip_suffix('/').unwrap_or(uri.path())
        == "/api/ciphers/purge"
        && matches!(method, route::Method::Put | route::Method::Delete);
    let route = route::classify(method, uri.path())
        .or_else(|| invalid_purge_id.then_some(Route::CipherGet("purge")))
        .ok_or_else(missing)?;
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
    let send_upload = if matches!(route, Route::SendFileUpload(..)) {
        if !headers
            .get("content-type")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("multipart/form-data"))
        {
            return Err(missing());
        }
        // Parse before locking, but defer data-guard failures until ordinary
        // account/device and path guards have run.
        Some(send_files::parse_upload(&headers, body.clone()).await)
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
    if let Route::SendFileDownload(send_id, file_id) = route {
        return send_files::download(&mut store, send_id, file_id, uri.query());
    }
    if let Route::SendFileAccess(file_id) = route {
        return send_files::access_file(&mut store, &headers, file_id);
    }
    if let Route::DevicePushClear(segment) = route {
        let identifier = devices::path_identifier(segment)?;
        VaultService::new(&mut *store).clear_device_push_token(&identifier)?;
        return Ok(StatusCode::OK.into_response());
    }
    if route == Route::KnownDevice {
        let headers = devices::known_headers(&headers)?;
        let response = VaultService::new(&mut *store).known_device(&headers.request())?;
        return Ok(Json(response).into_response());
    }
    if route == Route::SendAccess {
        return sends::access(&mut store, &headers);
    }
    if route == Route::AuthRequestCreate {
        let input = auth_requests::parse_input(&body)?;
        let origin = auth_requests::origin(&app.base)?;
        let request_ip = peer_ip.to_string();
        let context = AuthRequestContext {
            device_type: auth_requests::device_type(&headers),
            request_ip: &request_ip,
            origin: &origin,
        };
        let request = AuthRequestCreateRequest {
            access_code: &input.access_code,
            device_identifier: &input.device_identifier,
            email: &input.email,
            public_key: &input.public_key,
        };
        let mut service = VaultService::new(&mut *store);
        let response = service.create_auth_request(&request, &context)?;
        return Ok(Json(response).into_response());
    }
    if let Route::AuthRequestResponse(raw) = route {
        let id = auth_requests::path_id(raw)?;
        let code = auth_requests::query_code(uri.query())?;
        let origin = auth_requests::origin(&app.base)?;
        let request_ip = peer_ip.to_string();
        let context = AuthRequestContext {
            device_type: auth_requests::device_type(&headers),
            request_ip: &request_ip,
            origin: &origin,
        };
        let mut service = VaultService::new(&mut *store);
        let response = service.get_auth_request_response(&id, &Secret::new(&code), &context)?;
        return Ok(Json(response).into_response());
    }
    if route == Route::Prelogin {
        let input = prelogin::Input::parse(&body)?;
        let response = VaultService::new(&mut *store).prelogin(&input.request())?;
        return Ok(Json(response).into_response());
    }
    if route == Route::RegistrationVerification {
        let input = registration::parse_verification(&body)?;
        store.registration_issuer = registration::issuer(&app.base)?;
        let token =
            VaultService::new(&mut *store).request_registration_verification(&input.request())?;
        return Ok(if registration::accepts_json(&headers) {
            Json(token).into_response()
        } else {
            token.expose_token().to_owned().into_response()
        });
    }
    if route == Route::RegistrationFinish {
        let input = registration::parse_finish(&body)?;
        store.registration_issuer = registration::issuer(&app.base)?;
        let storage_email = input.email.to_lowercase();
        let salt_email = input.email.trim().to_lowercase();
        let email = no_warden::registration::RegistrationEmail {
            storage_email: &storage_email,
            salt_email: &salt_email,
        };
        let response =
            VaultService::new(&mut *store).finish_registration(&input.request(), &email)?;
        return Ok(Json(response).into_response());
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
        if let Some(input) = password_login::Input::ordinary(&body)? {
            return password_login::login(&app, &mut store, &input);
        }
        if let Some(input) = refresh::Input::selected(&body)? {
            return refresh::login(&app, &mut store, &input);
        }
        if let Some(input) = sends::TokenInput::selected(&body)? {
            return sends::grant(&mut store, &input);
        }
        let form = parse_connect_form(&body)?;
        let grant = connect_field(&form, &["grant_type", "granttype"])?.ok_or(Failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Missing grant type",
        ))?;
        match grant {
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
                let registration = devices::login_registration(&form)?;
                return Ok(json_response(authenticated_login(
                    &app,
                    &mut store,
                    &account,
                    &registration,
                    Some(&grant),
                    None,
                )?));
            }
            "password" => {
                // Rocket matches the compact, case-insensitive first name segment,
                // including nested scalar names. A present empty value cannot fall back.
                if auth_requests::auth_request_field(&form)?.is_some() {
                    let request = auth_request_login_form(&form, grant)?;
                    let request_ip = peer_ip.to_string();
                    let context = AuthRequestLoginContext {
                        request_ip: &request_ip,
                        now_unix_nanos: auth_requests::unix_nanos(chrono::Utc::now()),
                    };
                    return Ok(json_response(auth_request_login(
                        &app, &mut store, &request, &context,
                    )?));
                }
                // Ordinary password forms are handled before legacy grant parsing.
                return Err(invalid());
            }
            "refresh_token" => {
                // Refresh forms are handled before inherited strict parsing.
                return Err(invalid());
            }
            _ => return Err(Failure(StatusCode::BAD_REQUEST, "Unsupported grant type")),
        }
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
    let owner = match owner {
        Some(owner) => {
            if route == Route::WebAuthnCredentials {
                devices::access_binding(&store.db, &digest(bearer), &owner)?
                    .ok_or_else(unauthorized)?;
            }
            owner
        }
        None => account_password::previous_owner(
            &mut store.db,
            &digest(bearer),
            match route {
                Route::UserPublicKey(_) => "get_public_keys",
                Route::WebAuthnCredentials => "get_api_webauthn",
                _ => "",
            },
            chrono::Utc::now().timestamp(),
        )?
        .ok_or_else(unauthorized)?,
    };
    let account = store.account("id", &owner)?.ok_or_else(unauthorized)?;
    if matches!(
        route,
        Route::SendList
            | Route::SendGet(_)
            | Route::SendCreate
            | Route::SendUpdate(_)
            | Route::SendDelete(_)
            | Route::SendRemovePassword(_)
            | Route::SendFileCreate
            | Route::SendFileUpload(..)
            | Route::OrganizationCreate
            | Route::OrganizationGet(_)
            | Route::Collections
            | Route::OrganizationCollections(_)
            | Route::OrganizationCollectionCreate(_)
            | Route::OrganizationCollectionDetails(..)
            | Route::OrganizationCollectionUpdate(..)
            | Route::OrganizationCollectionDelete(..)
    ) {
        // Send and organization Headers require current device authority before UUID or JSON guards.
        devices::access_binding(&store.db, &digest(bearer), &owner)?.ok_or_else(unauthorized)?;
    }
    if invalid_purge_id {
        devices::access_binding(&store.db, &digest(bearer), &owner)?.ok_or_else(unauthorized)?;
        return Err(Failure(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Invalid cipher ID",
        ));
    }
    match route {
        Route::OrganizationCollectionUpdate(raw_org, raw_col) => {
            let (org, col) = organization_collections::paths(
                &mut store,
                &owner,
                raw_org,
                Some(raw_col),
                uri.query(),
            )?;
            let input = organization_collections::Input::parse(&body)?;
            Ok(Json(VaultService::new(&mut *store).update_org_collection(
                &owner,
                &org,
                col.as_deref().expect("Collection path"),
                &input,
            )?)
            .into_response())
        }
        Route::OrganizationCollectionDelete(raw_org, raw_col) => {
            let (org, col) = organization_collections::paths(
                &mut store,
                &owner,
                raw_org,
                Some(raw_col),
                uri.query(),
            )?;
            VaultService::new(&mut *store).delete_org_collection(
                &owner,
                &org,
                col.as_deref().expect("Collection path"),
            )?;
            Ok(StatusCode::OK.into_response())
        }
        Route::OrganizationCollections(raw) => {
            let (org, _) =
                organization_collections::paths(&mut store, &owner, raw, None, uri.query())?;
            Ok(
                Json(VaultService::new(&mut *store).list_org_collections(&owner, &org)?)
                    .into_response(),
            )
        }
        Route::OrganizationCollectionCreate(raw) => {
            let (org, _) =
                organization_collections::paths(&mut store, &owner, raw, None, uri.query())?;
            let input = organization_collections::Input::parse(&body)?;
            Ok(
                Json(VaultService::new(&mut *store).create_org_collection(&owner, &org, &input)?)
                    .into_response(),
            )
        }
        Route::OrganizationCollectionDetails(raw_org, raw_col) => {
            let (org, col) = organization_collections::paths(
                &mut store,
                &owner,
                raw_org,
                Some(raw_col),
                uri.query(),
            )?;
            Ok(
                Json(VaultService::new(&mut *store).get_org_collection_details(
                    &owner,
                    &org,
                    col.as_deref().expect("Collection path"),
                )?)
                .into_response(),
            )
        }
        Route::OrganizationInvite(raw_org) => {
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let org = organization_invitations::path(&mut store, &owner, raw_org, uri.query())?;
            let input = organization_invitations::Input::parse(&body)?;
            match VaultService::new(&mut *store).invite_org_members(&owner, &org, &input) {
                Ok(_) => Ok(StatusCode::OK.into_response()),
                Err(error) => Ok(organization_invitations::error_response(error)),
            }
        }
        Route::OrganizationBulkConfirm(raw_org) => {
            use no_warden::organization_confirmations::OrganizationBulkConfirmData;
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let org = organization_invitations::path(&mut store, &owner, raw_org, uri.query())?;
            let input = organization_bulk_confirmations::Input::parse(&body)?;
            let mut scratch = vec![None; input.len()];
            match VaultService::new(&mut *store).bulk_confirm_org_members(
                &owner,
                &org,
                &input,
                &mut scratch,
            ) {
                Ok(response) => Ok(Json(response).into_response()),
                Err(error) => Err(error.cause().into()),
            }
        }
        Route::OrganizationMemberConfirm(raw_org, raw_member) => {
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let (org, member) = organization_members::detail_paths(
                &mut store,
                &owner,
                raw_org,
                raw_member,
                uri.query(),
            )?;
            let input = organization_confirmations::Input::parse(&body)?;
            VaultService::new(&mut *store).confirm_org_member(
                &owner,
                &org,
                &member,
                &input.request(),
            )?;
            Ok(StatusCode::OK.into_response())
        }
        Route::OrganizationBulkMemberDelete(raw_org) => {
            use no_warden::organization_member_removal::OrganizationBulkMemberRemovalData;
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let org = organization_invitations::path(&mut store, &owner, raw_org, uri.query())?;
            let input = organization_bulk_member_removal::Input::parse(&body)?;
            let mut scratch = vec![None; input.len()];
            let response = VaultService::new(&mut *store).bulk_remove_org_members(
                &owner,
                &org,
                &input,
                &mut scratch,
            )?;
            Ok(Json(response).into_response())
        }
        Route::OrganizationBulkMemberRevoke(raw_org)
        | Route::OrganizationBulkMemberRestore(raw_org) => {
            use no_warden::organization_bulk_member_status::OrganizationBulkMemberStatusData;
            let revoke = matches!(route, Route::OrganizationBulkMemberRevoke(_));
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let org = organization_invitations::path(&mut store, &owner, raw_org, uri.query())?;
            let input = organization_bulk_member_status::Input::parse(&body, revoke)?;
            let mut scratch = vec![None; input.len()];
            let mut service = VaultService::new(&mut *store);
            let response = if revoke {
                service.bulk_revoke_org_members(&owner, &org, &input, &mut scratch)?
            } else {
                service.bulk_restore_org_members(&owner, &org, &input, &mut scratch)?
            };
            Ok(Json(response).into_response())
        }
        Route::OrganizationMemberRevoke(raw_org, raw_member) => {
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let (org, member) = organization_members::detail_paths(
                &mut store,
                &owner,
                raw_org,
                raw_member,
                uri.query(),
            )?;
            VaultService::new(&mut *store).revoke_org_member(&owner, &org, &member)?;
            Ok(StatusCode::OK.into_response())
        }
        Route::OrganizationMemberRestore(raw_org, raw_member)
        | Route::OrganizationMemberRestoreVNext(raw_org, raw_member) => {
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let (org, member) = organization_members::detail_paths(
                &mut store,
                &owner,
                raw_org,
                raw_member,
                uri.query(),
            )?;
            VaultService::new(&mut *store).restore_org_member(&owner, &org, &member)?;
            Ok(StatusCode::OK.into_response())
        }
        Route::OrganizationMemberDelete(raw_org, raw_member) => {
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let (org, member) = organization_members::detail_paths(
                &mut store,
                &owner,
                raw_org,
                raw_member,
                uri.query(),
            )?;
            VaultService::new(&mut *store).remove_org_member(&owner, &org, &member)?;
            Ok(StatusCode::OK.into_response())
        }
        Route::OrganizationMember(raw_org, raw_member) => {
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let (org, member) = organization_members::detail_paths(
                &mut store,
                &owner,
                raw_org,
                raw_member,
                uri.query(),
            )?;
            let query = organization_members::detail_query(uri.query());
            Ok(
                Json(VaultService::new(&mut *store).get_org_member(&owner, &org, &member, &query)?)
                    .into_response(),
            )
        }
        Route::OrganizationMembers(raw) => {
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let org = organization_members::path(&mut store, &owner, raw, uri.query())?;
            let query = organization_members::query(uri.query());
            Ok(
                Json(VaultService::new(&mut *store).list_org_members(&owner, &org, &query)?)
                    .into_response(),
            )
        }
        Route::OrganizationCreate => {
            let input = organizations::Input::parse(&body)?;
            let mut service = VaultService::new(&mut *store);
            match service.create_organization(&owner, &input.request()) {
                Ok(response) => Ok(Json(response).into_response()),
                Err(error) if error.message == "BillingEmail is not a valid email address" => Ok(
                    password_login::error_response(StatusCode::BAD_REQUEST, &input.billing_error()),
                ),
                Err(error) => Err(error.into()),
            }
        }
        Route::OrganizationGet(raw) => {
            let id = organizations::owner_path(&store.db, &owner, raw, uri.query())?;
            let mut service = VaultService::new(&mut *store);
            Ok(Json(service.get_organization(&owner, &id)?).into_response())
        }
        Route::Collections => {
            let mut service = VaultService::new(&mut *store);
            Ok(Json(service.list_user_collections(&owner)?).into_response())
        }
        Route::AccountDelete => {
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let input = account_security::parse_stamp(&body)?;
            VaultService::new(&mut *store).delete_account(&owner, &input.request())?;
            Ok(StatusCode::OK.into_response())
        }
        Route::CipherPurge => {
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            if purge::organization_requested(uri.query()) {
                // Organization vault purge is not implemented. A selected
                // organization must never fall through to personal-vault cleanup.
                return Err(Failure(
                    StatusCode::UNAUTHORIZED,
                    "The current user isn't member of the organization",
                ));
            }
            let input = account_security::parse_stamp(&body)?;
            VaultService::new(&mut *store).purge_personal_vault(&owner, &input.request())?;
            Ok(StatusCode::OK.into_response())
        }
        Route::WebAuthnCredentials => {
            let response = VaultService::new(&mut *store).get_webauthn_credentials(&owner)?;
            Ok(Json(response).into_response())
        }
        Route::AccountPasswordChange => {
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let input = account_password::parse(&body)?;
            VaultService::new(&mut *store).change_password(&owner, &input.request())?;
            Ok(StatusCode::OK.into_response())
        }
        Route::AccountKdfChange => {
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let input = account_kdf::parse(&body)?;
            VaultService::new(&mut *store).change_kdf(&owner, &input.request())?;
            Ok(StatusCode::OK.into_response())
        }
        Route::AccountVerifyPassword => {
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let input = account_security::parse_verification(&body)?;
            let response =
                VaultService::new(&mut *store).verify_password(&owner, &input.request())?;
            Ok(Json(response).into_response())
        }
        Route::AccountSecurityStamp => {
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let input = account_security::parse_stamp(&body)?;
            VaultService::new(&mut *store).reset_security_stamp(&owner, &input.request())?;
            Ok(StatusCode::OK.into_response())
        }
        Route::AuthRequestUpdate(raw) => {
            let identifier = devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let id = auth_requests::path_id(raw)?;
            let input = auth_requests::parse_update(&body)?;
            let request = AuthRequestUpdateRequest {
                device_identifier: &input.device_identifier,
                key: &input.key,
                master_password_hash: input.master_password_hash.as_deref(),
                request_approved: input.request_approved,
            };
            let origin = auth_requests::origin(&app.base)?;
            let mut service = VaultService::new(&mut *store);
            let response =
                service.respond_auth_request(&owner, &id, &identifier, &request, &origin)?;
            Ok(Json(response).into_response())
        }
        Route::AuthRequests => {
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let origin = auth_requests::origin(&app.base)?;
            let mut service = VaultService::new(&mut *store);
            let response = service.list_auth_requests(&owner, &origin)?;
            Ok(Json(response).into_response())
        }
        Route::AuthRequestGet(raw) => {
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let id = auth_requests::path_id(raw)?;
            let origin = auth_requests::origin(&app.base)?;
            let mut service = VaultService::new(&mut *store);
            let response = service.get_auth_request(&owner, &id, &origin)?;
            Ok(Json(response).into_response())
        }
        Route::DevicePushToken(segment) => {
            // Rocket's Headers guard resolves the authenticated device before
            // path and body guards. Never use a request header or path as target.
            let identifier = devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            devices::path_identifier(segment)?;
            let input = devices::parse_push_input(&body)?;
            let request = DevicePushTokenRequest {
                push_token: &input.push_token,
            };
            VaultService::new(&mut *store).set_device_push_token(&owner, &identifier, &request)?;
            Ok(StatusCode::OK.into_response())
        }
        Route::Devices => {
            let mut service = VaultService::new(&mut *store);
            let response = service.list_devices(&owner)?;
            Ok(Json(response).into_response())
        }
        Route::DeviceGet(segment) => {
            let identifier = devices::path_identifier(segment)?;
            let mut service = VaultService::new(&mut *store);
            let response = service.get_device(&owner, &identifier)?;
            Ok(Json(response).into_response())
        }
        Route::DomainsGet => {
            let mut service = VaultService::new(&mut *store);
            let response =
                service.domain_settings(&owner, domains::catalog(), DomainProjection::All)?;
            Ok(Json(response).into_response())
        }
        Route::DomainsUpdate => {
            let input = domains::parse_input(&body)?;
            let response = VaultService::new(&mut *store).update_domain_settings(&owner, &input)?;
            Ok(Json(response).into_response())
        }
        Route::ProfileUpdate => {
            let input = parse_profile_input(&body)?;
            let request = ProfileUpdateRequest { name: &input.name };
            VaultService::new(&mut *store).update_profile(&owner, &request)?;
            let account = store.account("id", &owner)?.ok_or_else(unauthorized)?;
            Ok(json_response(profile_document(&mut store, &account)?))
        }
        Route::AvatarUpdate => {
            let input = parse_avatar_input(&body)?;
            let request = AvatarUpdateRequest {
                avatar_color: input.avatar_color.as_deref(),
            };
            VaultService::new(&mut *store).update_avatar(&owner, &request)?;
            let account = store.account("id", &owner)?.ok_or_else(unauthorized)?;
            Ok(json_response(profile_document(&mut store, &account)?))
        }
        Route::AccountKeysGet => {
            let mut service = VaultService::new(&mut *store);
            let response = service.get_account_keys(&owner)?;
            Ok(Json(response).into_response())
        }
        Route::AccountKeysInitialize => {
            let input = parse_account_keys_input(&body)?;
            let request = AccountKeys {
                encrypted_private_key: &input.encrypted_private_key,
                public_key: &input.public_key,
            };
            let mut service = VaultService::new(&mut *store);
            let response = service.initialize_account_keys(&owner, &request)?;
            Ok(Json(response).into_response())
        }
        Route::UserPublicKey(id) => {
            uuid::Uuid::parse_str(id)
                .map_err(|_| Failure(StatusCode::UNPROCESSABLE_ENTITY, "Invalid user ID"))?;
            let mut service = VaultService::new(&mut *store);
            let response = service.get_user_public_key(&owner, id)?;
            Ok(Json(response).into_response())
        }
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
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let input = account_key_id::Input::parse(&body)?;
            VaultService::new(&mut *store).set_user_key_id(&owner, &input.request())?;
            Ok(StatusCode::OK.into_response())
        }
        Route::Profile => Ok(json_response(profile_document(&mut store, &account)?)),
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
        Route::Sync => {
            let send_documents = sends::sync(&mut store, &owner)?;
            let collection_documents = {
                let mut service = VaultService::new(&mut *store);
                let collections = service.list_user_collections(&owner)?;
                serde_json::to_value(collections.details()).map_err(|_| invalid())?
            };
            let exclude_domains = domains::sync_excludes(uri.query())?;
            let settings = if exclude_domains {
                Value::Null
            } else {
                let mut service = VaultService::new(&mut *store);
                let response =
                    service.domain_settings(&owner, domains::catalog(), DomainProjection::Sync)?;
                serde_json::to_value(response).map_err(|_| {
                    Failure(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "Domain response construction failed",
                    )
                })?
            };
            Ok(json_response(json!({
                "object":"sync","profile":profile_document(&mut store,&account)?,"folders":store.items(&owner,"folder")?.iter().map(protocol::folder).collect::<Vec<_>>(),
                "ciphers":store.items(&owner,"cipher")?,"collections":collection_documents,"policies":[],"sends":send_documents,
                "domains":settings,
                "userDecryption":protocol::user_decryption(&account)
            })))
        }
        Route::Folders => Ok(json_response(
            json!({"object":"list","data":store.items(&owner,"folder")?.iter().map(protocol::folder).collect::<Vec<_>>(),"continuationToken":null}),
        )),
        Route::SendList => {
            let mut service = VaultService::new(&mut *store);
            Ok(Json(service.list_sends(&owner)?).into_response())
        }
        Route::SendGet(raw) => {
            let id = sends::path_id(raw)?;
            let mut service = VaultService::new(&mut *store);
            Ok(Json(service.get_send(&owner, &id)?).into_response())
        }
        Route::SendCreate => {
            let input = sends::Input::parse(&body)?;
            input.stage_dates(&mut store);
            let request = input.request();
            let mut service = VaultService::new(&mut *store);
            Ok(
                Json(service.create_text_send(&owner, &request, &sends::context())?)
                    .into_response(),
            )
        }
        Route::SendFileCreate => {
            let input = sends::Input::parse(&body)?;
            input.stage_dates(&mut store);
            let request = input.file_request();
            let mut service = VaultService::new(&mut *store);
            Ok(
                Json(service.reserve_file_send(&owner, &request, &sends::context())?)
                    .into_response(),
            )
        }
        Route::SendFileUpload(raw_id, raw_file_id) => {
            let id = sends::path_id(raw_id)?;
            let file_id = send_files::file_id(raw_file_id)?;
            let upload = send_upload.ok_or_else(invalid)??;
            let legacy_cli:bool=store.db.query_row(
                "SELECT EXISTS(SELECT 1 FROM session_devices s JOIN device_registry d ON d.owner=s.owner AND d.identifier=s.identifier WHERE s.access=?1 AND s.owner=?2 AND d.device_type IN(23,24,25))",
                params![digest(bearer),owner],|row|row.get(0),
            )?;
            let facts = no_warden::sends::SendFileUpload {
                file_name: upload.file_name.as_deref(),
                file_size: upload.data.len() as u64,
                allow_legacy_filename_suffix: legacy_cli,
            };
            store.pending_send_file_data = upload.data;
            let result =
                VaultService::new(&mut *store).upload_send_file(&owner, &id, &file_id, &facts);
            store.pending_send_file_data = Vec::new();
            result?;
            Ok(StatusCode::OK.into_response())
        }
        Route::SendUpdate(raw) => {
            let id = sends::path_id(raw)?;
            let input = sends::Input::parse(&body)?;
            input.stage_dates(&mut store);
            if input.request().kind == 1 {
                let request = input.file_request();
                let mut service = VaultService::new(&mut *store);
                return Ok(Json(service.update_file_send(
                    &owner,
                    &id,
                    &request,
                    &sends::context(),
                )?)
                .into_response());
            }
            let request = input.request();
            let mut service = VaultService::new(&mut *store);
            Ok(
                Json(service.update_text_send(&owner, &id, &request, &sends::context())?)
                    .into_response(),
            )
        }
        Route::SendDelete(raw) => {
            let id = sends::path_id(raw)?;
            VaultService::new(&mut *store).delete_send(&owner, &id)?;
            Ok(StatusCode::OK.into_response())
        }
        Route::SendRemovePassword(raw) => {
            let id = sends::path_id(raw)?;
            let mut service = VaultService::new(&mut *store);
            Ok(Json(service.remove_send_password(&owner, &id)?).into_response())
        }
        Route::Ciphers => Ok(json_response(
            json!({"object":"list","data":store.items(&owner,"cipher")?,"continuationToken":null}),
        )),
        Route::FolderGet(id) => {
            let document = store
                .item(&owner, id, "folder")?
                .ok_or_else(invalid_folder)?;
            Ok(json_response(protocol::folder(&document)))
        }
        Route::CipherGet(raw) | Route::CipherDetails(raw) | Route::CipherAdmin(raw) => {
            // Rocket runs Headers before UuidFromParam. A malformed ID cannot
            // skip the current device/stamp check, including on the admin alias.
            devices::access_binding(&store.db, &digest(bearer), &owner)?
                .ok_or_else(unauthorized)?;
            let id = cipher_reads::path_id(raw)?;
            let grant = VaultService::new(&mut *store).authorize_cipher_read(&owner, &id)?;
            // Keep the verified context locked through projection. Preserve
            // encrypted JSON and extensions; no narrow request DTO round-trip.
            let document = store
                .item(grant.owner(), grant.id(), "cipher")?
                .ok_or(Failure(StatusCode::BAD_REQUEST, "Cipher doesn't exist"))?;
            Ok(json_response(document))
        }
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
            } else if matches!(route, Route::CipherSoftDelete(_)) {
                Ok(StatusCode::OK.into_response())
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

#[cfg(test)]
fn issue_tokens(app: &App, db: &rusqlite::Connection, account: &Value) -> Result<Value, Failure> {
    issue_token_grant(app, db, account, None)
}

#[cfg(test)]
fn issue_token_grant(
    app: &App,
    db: &rusqlite::Connection,
    account: &Value,
    api: Option<&AuthorizedApiKeyGrant<'_>>,
) -> Result<Value, Failure> {
    issue_token_grant_bound(app, db, account, api, None, None)
}

fn auth_request_login_form<'a>(
    form: &'a BTreeMap<String, String>,
    grant_type: &'a str,
) -> Result<AuthRequestLoginRequest<'a>, Failure> {
    Ok(AuthRequestLoginRequest {
        grant_type: Some(grant_type),
        password: connect_field(form, &["password"])?.map(Secret::new),
        auth_request: auth_requests::auth_request_field(form)?,
        client_id: connect_field(form, &["client_id", "clientid"])?,
        scope: connect_field(form, &["scope"])?,
        username: connect_field(form, &["username"])?,
        device_identifier: connect_field(form, &["device_identifier", "deviceidentifier"])?,
        device_name: connect_field(form, &["device_name", "devicename"])?,
        device_type: connect_field(form, &["device_type", "devicetype"])?,
    })
}

// The same mutex/savepoint covers one-time consumption and every subsequent
// activity, session and binding mutation, including a deferred commit failure.
fn auth_request_login(
    app: &App,
    store: &mut Store,
    request: &AuthRequestLoginRequest<'_>,
    context: &AuthRequestLoginContext<'_>,
) -> Result<Value, Failure> {
    store.db.execute_batch("SAVEPOINT auth_request_login")?;
    let result = (|| {
        let grant = VaultService::new(&mut *store).authenticate_auth_request(request, context)?;
        let account = store
            .account("id", grant.user_id())?
            .ok_or_else(invalid_grant)?;
        let device = grant.device();
        let registration = DeviceRegistration {
            identifier: device.identifier,
            name: device.name,
            device_type: device.device_type.parse().unwrap_or(14),
        };
        let tokens = authenticated_login(
            app,
            store,
            &account,
            &registration,
            None,
            Some(grant.client_id()),
        )?;
        store.db.execute_batch("RELEASE auth_request_login")?;
        Ok(tokens)
    })();
    if result.is_err() {
        store
            .db
            .execute_batch("ROLLBACK TO auth_request_login; RELEASE auth_request_login")?;
    }
    result
}

// The storage mutex is held across this savepoint. Registration, activity and
// session/binding issuance must all roll back together if any step fails.
fn authenticated_login(
    app: &App,
    store: &mut Store,
    account: &Value,
    registration: &DeviceRegistration<'_>,
    api: Option<&AuthorizedApiKeyGrant<'_>>,
    password_client_id: Option<&str>,
) -> Result<Value, Failure> {
    store.db.execute_batch("SAVEPOINT device_login")?;
    let result = (|| {
        let owner = account["id"].as_str().ok_or_else(invalid)?;
        VaultService::new(&mut *store).register_device(owner, registration)?;
        let tokens = issue_token_grant_bound(
            app,
            &store.db,
            account,
            api,
            Some(registration.identifier),
            password_client_id,
        )?;
        store.db.execute_batch("RELEASE device_login")?;
        Ok(tokens)
    })();
    if result.is_err() {
        store
            .db
            .execute_batch("ROLLBACK TO device_login; RELEASE device_login")?;
    }
    result
}

fn issue_token_grant_bound(
    app: &App,
    db: &rusqlite::Connection,
    account: &Value,
    api: Option<&AuthorizedApiKeyGrant<'_>>,
    device: Option<&str>,
    password_client_id: Option<&str>,
) -> Result<Value, Failure> {
    let timestamp = chrono::Utc::now().timestamp();
    db.execute(
        "DELETE FROM sessions WHERE access_expires<=?1 AND refresh_expires<?2",
        params![timestamp, timestamp.saturating_sub(30)],
    )?;
    let expires_in = api.map_or(7200_i64, |grant| i64::from(grant.expires_in()));
    let client_id = api.map_or(password_client_id.unwrap_or("undefined"), |grant| {
        grant.client_id()
    });
    let scopes = if api.is_some() {
        vec!["api"]
    } else {
        vec!["api", "offline_access"]
    };
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let security_stamp = account_security::stamp(db, account["id"].as_str().ok_or_else(invalid)?)?;
    let mut claims = json!({"sub":account["id"],"email":account["email"],"email_verified":true,
        "name":account["name"],"premium":true,"iss":app.base,"iat":timestamp,"nbf":timestamp,"exp":timestamp+expires_in,
        "client_id":client_id,"scope":scopes,"amr":["Application"],"sstamp":security_stamp,"jti":random_token()});
    let mut refresh_days = 30;
    if let Some(identifier) = device {
        claims["device"] = json!(identifier);
        let registered =
            devices::load(db, account["id"].as_str().ok_or_else(invalid)?, identifier)?
                .ok_or_else(invalid)?;
        if matches!(registered.device_type, 0 | 1) {
            refresh_days = 90;
        }
        claims["devicetype"] = json!(no_warden::auth_requests::device_type_name(
            registered.device_type
        ));
    }
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
        timestamp + refresh_days * 24 * 3600
    } else {
        0
    };
    db.execute("INSERT INTO sessions(access,refresh,owner,access_expires,refresh_expires) VALUES(?1,?2,?3,?4,?5)",params![digest(&access),refresh_digest,account["id"].as_str(),timestamp+expires_in,refresh_expires])?;
    if let Some(identifier) = device {
        devices::bind(
            db,
            account["id"].as_str().ok_or_else(invalid)?,
            identifier,
            &access,
        )?;
        account_password::remember_access(
            db,
            account["id"].as_str().ok_or_else(invalid)?,
            identifier,
            &access,
            &security_stamp,
            timestamp + expires_in,
        )?;
    }
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

    async fn modern_verification_token(app: &App, email: &str, name: Option<&str>) -> String {
        let mut headers = HeaderMap::new();
        headers.insert("accept", "application/json".parse().unwrap());
        let body = json!({"email":email,"name":name}).to_string();
        device_document(
            device_request(
                app,
                Method::POST,
                "/identity/accounts/register/send-verification-email",
                headers,
                body.as_bytes(),
            )
            .await,
        )
        .await
        .as_str()
        .unwrap()
        .to_owned()
    }
    fn modern_finish_body(email: &str, token: &str) -> Value {
        json!({"email":email,"emailVerificationToken":token,"masterPasswordAuthentication":{"kdf":{"kdfType":0,"iterations":100000},"salt":email.trim().to_lowercase(),"masterPasswordAuthenticationHash":"opaque-proof\0雪"},"masterPasswordUnlock":{"kdf":{"kdfType":0,"iterations":100000},"salt":email.trim().to_lowercase(),"masterKeyWrappedUserKey":"opaque-user-key"},"userAsymmetricKeys":{"publicKey":"opaque-public","encryptedPrivateKey":"opaque-private"},"name":"forged-name","verified":true,"emailVerified":true,"_password":"forged","avatarColor":"forged","userKeyId":"forged","id":"alice","unknown":true})
    }
    async fn modern_http_finish(app: &App, body: &Value) -> Result<Response, Failure> {
        device_request(
            app,
            Method::POST,
            "/identity/accounts/register/finish",
            HeaderMap::new(),
            body.to_string().as_bytes(),
        )
        .await
    }
    #[tokio::test]
    async fn modern_registration_http_accept_and_deferred_name_validation_do_not_create_accounts() {
        let app = device_fixture_app();
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        for (accept, json_response) in [
            (None, false),
            (Some("*/*"), false),
            (Some("application/json"), true),
            (Some("APPLICATION/JSON;charset=utf8"), true),
            (Some("application/problem+json"), false),
            (Some("text/plain,application/json"), false),
            (Some("application/json;q=0"), true),
            (Some("*/*;q=1,application/json;q=0"), true),
            (Some("application/json;q=1,text/plain"), false),
        ] {
            let mut headers = device_authorization(Some("ignored-invalid-bearer"));
            if let Some(accept) = accept {
                headers.insert("accept", accept.parse().unwrap());
            }
            let response = device_request(
                &app,
                Method::POST,
                "/identity/accounts/register/send-verification-email",
                headers,
                json!({"email":"not an email","name":"a".repeat(51),"verified":true})
                    .to_string()
                    .as_bytes(),
            )
            .await
            .unwrap_or_else(|_| panic!("Verification step applied finish validation."));
            assert_eq!(response.status(), StatusCode::OK);
            let content_type = response
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap();
            assert!(content_type.starts_with(if json_response {
                "application/json"
            } else {
                "text/plain"
            }));
            let bytes = axum::body::to_bytes(response.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap();
            let token = if json_response {
                serde_json::from_slice::<String>(&bytes).unwrap()
            } else {
                String::from_utf8(bytes.to_vec()).unwrap()
            };
            let body = json!({"email":"not an email","emailVerificationToken":token,"kdf":0,"kdfIterations":100000,"key":"","masterPasswordHash":""});
            let Err(error) = modern_http_finish(&app, &body).await else {
                panic!("Overlong signed name registered.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }
        assert!(device_push_persisted_state(&app.store.lock().unwrap()) == before);
    }
    #[tokio::test]
    async fn modern_registration_http_email_save_validation_is_deferred_and_nonmutating() {
        let app = device_fixture_app();
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        for email in [
            "not-an-email",
            "",
            " user@example.test",
            "user@example.test ",
            "user@127.0.0.1",
            "user@[127.0.0.1]",
            "user@example.test/path",
            "user@example.test?query",
        ] {
            let token = modern_verification_token(&app, email, None).await;
            let body = modern_finish_body(email, &token);
            let Err(error) = modern_http_finish(&app, &body).await else {
                panic!("Invalid email registered through HTTP.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
            assert!(error.1 == "Email address is invalid.");
            assert!(device_push_persisted_state(&app.store.lock().unwrap()) == before);
        }
        let token = modern_verification_token(&app, "not-an-email", None).await;
        let mut body = modern_finish_body("not-an-email", &token);
        body["masterPasswordAuthentication"]["kdf"]["iterations"] = json!(99999);
        body["masterPasswordUnlock"]["kdf"]["iterations"] = json!(99999);
        let Err(error) = modern_http_finish(&app, &body).await else {
            panic!("Invalid KDF accepted.")
        };
        assert!(error.1 == "PBKDF2 KDF iterations must be at least 100000.");
        body["emailVerificationToken"] = json!("invalid");
        let Err(error) = modern_http_finish(&app, &body).await else {
            panic!("Invalid token accepted.")
        };
        assert!(error.1 == "Invalid registration verification token");
        body["masterPasswordUnlock"]["salt"] = json!("mismatched");
        let Err(error) = modern_http_finish(&app, &body).await else {
            panic!("Invalid nested format accepted.")
        };
        assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        assert!(device_push_persisted_state(&app.store.lock().unwrap()) == before);
    }
    #[tokio::test]
    async fn modern_registration_http_nested_aliases_claim_name_and_password_login_are_authoritative()
     {
        let app = device_fixture_app();
        let email = "New@EXAMPLE.TEST";
        let token = modern_verification_token(&app, email, Some("")).await;
        let mut body = modern_finish_body(email, &token);
        let nested = body
            .as_object_mut()
            .unwrap()
            .remove("masterPasswordAuthentication")
            .unwrap();
        body["MasterPasswordAuthentication"] = nested;
        let authentication = body["MasterPasswordAuthentication"]
            .as_object_mut()
            .unwrap();
        let salt = authentication.remove("salt").unwrap();
        authentication.insert("Salt".into(), salt);
        let kdf = authentication.remove("kdf").unwrap();
        authentication.insert("Kdf".into(), kdf);
        let hash = authentication
            .remove("masterPasswordAuthenticationHash")
            .unwrap();
        authentication.insert("MasterPasswordAuthenticationHash".into(), hash);
        let response = device_document(modern_http_finish(&app, &body).await).await;
        assert!(response == json!({"object":"registerFinish"}));
        let account = app
            .store
            .lock()
            .unwrap()
            .account("email", "new@example.test")
            .unwrap()
            .unwrap();
        assert!(
            account["name"] == ""
                && account["id"] != "alice"
                && account["avatarColor"].is_null()
                && account["userKeyId"].is_null()
        );
        for field in [
            "masterPasswordAuthentication",
            "masterPasswordUnlock",
            "masterPasswordHash",
            "emailVerificationToken",
            "_password",
            "verified",
            "emailVerified",
            "unknown",
        ] {
            assert!(
                account.get(field).is_none(),
                "Raw registration input leaked into account storage."
            );
        }
        let form = serde_urlencoded::to_string([
            ("grant_type", "password"),
            ("client_id", "registration-test"),
            ("scope", "api offline_access"),
            ("username", "new@example.test"),
            ("password", "opaque-proof\0雪"),
            ("deviceIdentifier", "New-Device"),
            ("deviceName", "New"),
            ("deviceType", "8"),
        ])
        .unwrap();
        let tokens = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                form.as_bytes(),
            )
            .await,
        )
        .await;
        assert!(
            tokens["Key"] == "opaque-user-key"
                && tokens["PrivateKey"] == "opaque-private"
                && device_claims(&tokens)["name"] == ""
                && device_claims(&tokens)["email_verified"] == true
        );
        let profile = device_document(
            device_request(
                &app,
                Method::GET,
                "/api/accounts/profile",
                device_authorization(tokens["access_token"].as_str()),
                b"",
            )
            .await,
        )
        .await;
        assert!(
            profile["name"] == ""
                && profile["emailVerified"] == true
                && profile["id"] == account["id"]
        );
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        let Err(error) = modern_http_finish(&app, &body).await else {
            panic!("Duplicate registration replaced initialized account.")
        };
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(device_push_persisted_state(&app.store.lock().unwrap()) == before);
    }
    #[tokio::test]
    async fn modern_registration_http_schema_nested_format_proof_order_and_opaque_legacy_are_preserved()
     {
        let app = device_fixture_app();
        let token = modern_verification_token(&app, "format@example.test", Some("Claim")).await;
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        for body in [b"{}".as_slice(),b"[]",br#"{"email":"a","email":"b","key":"k","masterPasswordHash":"h","kdf":0,"kdfIterations":100000}"#,br#"{"email":"a","key":"k","masterPasswordHash":"h","kdf":0,"kdfIterations":"100000"}"#] {
            let Err(error)=device_request(&app,Method::POST,"/identity/accounts/register/finish",HeaderMap::new(),body).await else{panic!("Malformed registration schema accepted.")};assert_eq!(error.0,StatusCode::UNPROCESSABLE_ENTITY);
        }
        let Err(error) = device_request(
            &app,
            Method::POST,
            "/identity/accounts/register/finish",
            HeaderMap::new(),
            b"{",
        )
        .await
        else {
            panic!("Malformed registration syntax accepted.")
        };
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        for case in 0..8 {
            let mut body = modern_finish_body("format@example.test", &token);
            let expected = match case {
                0 => {
                    body["masterPasswordUnlock"]["salt"] = json!("wrong");
                    body["emailVerificationToken"] = json!("invalid");
                    StatusCode::UNPROCESSABLE_ENTITY
                }
                1 => {
                    body["masterPasswordUnlock"]["kdf"]["iterations"] = json!(100001);
                    StatusCode::UNPROCESSABLE_ENTITY
                }
                2 => {
                    body["masterPasswordUnlock"]["salt"] = json!("wrong");
                    body["organizationUserId"] = json!("unsupported");
                    StatusCode::UNPROCESSABLE_ENTITY
                }
                3 => {
                    body["emailVerificationToken"] = json!("invalid");
                    StatusCode::BAD_REQUEST
                }
                4 => {
                    body["email"] = json!("FORMAT@example.test");
                    StatusCode::BAD_REQUEST
                }
                5 => {
                    body["organizationUserId"] = json!("unsupported");
                    StatusCode::BAD_REQUEST
                }
                6 => {
                    body["acceptEmergencyAccessId"] = json!("unsupported");
                    body["acceptEmergencyAccessInviteToken"] = json!("unsupported");
                    StatusCode::BAD_REQUEST
                }
                _ => {
                    body["token"] = json!("unsupported");
                    StatusCode::BAD_REQUEST
                }
            };
            let Err(error) = modern_http_finish(&app, &body).await else {
                panic!("Invalid registration proof or format accepted.")
            };
            assert_eq!(error.0, expected);
            assert!(device_push_persisted_state(&app.store.lock().unwrap()) == before);
        }
        let token = modern_verification_token(&app, "opaque@example.test", None).await;
        let body = json!({"email":"opaque@example.test","emailVerificationToken":token,"kdf":-1,"kdfIterations":-2,"kdfMemory":-3,"kdfParallelism":-4,"userSymmetricKey":"","master_password_hash":"","masterPasswordHint":"\n\t"});
        assert!(modern_http_finish(&app, &body).await.is_ok());
        let account = app
            .store
            .lock()
            .unwrap()
            .account("email", "opaque@example.test")
            .unwrap()
            .unwrap();
        assert!(
            account["name"] == "opaque@example.test"
                && account["key"] == ""
                && account["kdf"] == -1
                && account["kdfIterations"] == -2
                && account["kdfMemory"].is_null()
                && account["masterPasswordHint"].is_null()
        );
    }

    const PASSWORD_PUBLIC_PATH: &str = "/api/users/00000000-0000-4000-8000-000000000001/public-key";
    const READ_CIPHER: &str = "123e4567-e89b-42d3-a456-426614174000";
    const READ_TRASH: &str = "123e4567-e89b-42d3-a456-426614174001";
    const READ_ARCHIVE: &str = "123e4567-e89b-42d3-a456-426614174002";
    const READ_FOREIGN: &str = "123e4567-e89b-42d3-a456-426614174003";
    const READ_MISSING: &str = "123e4567-e89b-42d3-a456-426614174004";

    fn cipher_read_fixture_app() -> App {
        let app = auth_request_fixture_app();
        let store = app.store.lock().unwrap();
        for (id, owner, deleted) in [
            (READ_CIPHER, "alice", false),
            (READ_TRASH, "alice", true),
            (READ_ARCHIVE, "alice", false),
            (READ_FOREIGN, "bob", false),
        ] {
            let document = json!({"id":id,"name":"opaque-ciphertext","deletedDate":deleted.then_some("2026-01-01T00:00:00.000Z"),"archivedDate":null,"futureProtocolExtension":{"preserved":[0,null,"opaque"]}});
            store.db.execute("INSERT INTO items(id,owner,kind,document,deleted,revision,created) VALUES(?1,?2,'cipher',?3,?4,?5,?5)",params![id,owner,document.to_string(),deleted,store::now()]).unwrap();
        }
        store.db.execute("INSERT INTO cipher_archives(cipher_id,owner,archived_at) VALUES(?1,'alice','2026-01-01T00:00:00.000Z')",[READ_ARCHIVE]).unwrap();
        drop(store);
        app
    }

    #[tokio::test]
    async fn cipher_read_http_aliases_preserve_all_owned_states_and_opaque_json_without_vault_writes()
     {
        let app = cipher_read_fixture_app();
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        let changes = app.store.lock().unwrap().db.total_changes();
        for id in [READ_CIPHER, READ_TRASH, READ_ARCHIVE] {
            let mut baseline = None;
            for suffix in ["", "/details", "/admin"] {
                let path = format!(
                    "/api/ciphers/{id}{suffix}/?owner=bob&organizationId=forged&unknown=ignored"
                );
                let document = device_document(
                    device_request(
                        &app,
                        Method::GET,
                        &path,
                        device_authorization(Some("device-fixture-alice")),
                        b"{",
                    )
                    .await,
                )
                .await;
                assert!(document["id"] == id && document["name"] == "opaque-ciphertext");
                assert!(
                    document["futureProtocolExtension"] == json!({"preserved":[0,null,"opaque"]})
                );
                assert_eq!(document["deletedDate"].is_string(), id == READ_TRASH);
                assert_eq!(document["archivedDate"].is_string(), id == READ_ARCHIVE);
                if let Some(expected) = &baseline {
                    assert!(&document == expected);
                } else {
                    baseline = Some(document);
                }
            }
        }
        assert!(device_push_persisted_state(&app.store.lock().unwrap()) == before);
        // This fixture has no attachments, so projection mints no download grants.
        assert_eq!(app.store.lock().unwrap().db.total_changes(), changes);
    }

    #[tokio::test]
    async fn cipher_read_http_guards_authenticate_before_uuid_and_distinguish_missing_from_foreign()
    {
        let app = cipher_read_fixture_app();
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        for suffix in ["", "/details", "/admin"] {
            for id in [READ_CIPHER, "not-a-uuid", "%ff"] {
                for bearer in [None, Some("invalid"), Some("legacy-auth-access")] {
                    let path = format!("/api/ciphers/{id}{suffix}");
                    let Err(error) =
                        device_request(&app, Method::GET, &path, device_authorization(bearer), b"")
                            .await
                    else {
                        panic!("Unbound cipher read accepted.")
                    };
                    assert_eq!(error.0, StatusCode::UNAUTHORIZED);
                }
            }
            for raw in [
                "not-a-uuid",
                "%ff",
                "%2531%2532%2533e4567-e89b-42d3-a456-426614174000",
            ] {
                let path = format!("/api/ciphers/{raw}{suffix}");
                let Err(error) = device_request(
                    &app,
                    Method::GET,
                    &path,
                    device_authorization(Some("device-fixture-alice")),
                    b"",
                )
                .await
                else {
                    panic!("Invalid cipher read UUID accepted.")
                };
                assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
            }
            for (id, message) in [
                (READ_MISSING, "Cipher doesn't exist"),
                (READ_FOREIGN, "Cipher is not owned by user"),
                (
                    "123E4567-E89B-42D3-A456-426614174000",
                    "Cipher doesn't exist",
                ),
                ("123e4567e89b42d3a456426614174000", "Cipher doesn't exist"),
            ] {
                let path = format!("/api/ciphers/{id}{suffix}");
                let Err(error) = device_request(
                    &app,
                    Method::GET,
                    &path,
                    device_authorization(Some("device-fixture-alice")),
                    b"",
                )
                .await
                else {
                    panic!("Missing or foreign cipher read accepted.")
                };
                assert_eq!(error.0, StatusCode::BAD_REQUEST);
                assert!(error.1 == message);
            }
            let path = format!("/api/ciphers/%31%32%33e4567-e89b-42d3-a456-426614174000{suffix}");
            let document = device_document(
                device_request(
                    &app,
                    Method::GET,
                    &path,
                    device_authorization(Some("device-fixture-alice")),
                    b"",
                )
                .await,
            )
            .await;
            assert!(document["id"] == READ_CIPHER);
        }
        for literal in [
            "create",
            "import",
            "purge",
            "admin",
            "delete",
            "delete-admin",
            "restore",
            "restore-admin",
            "archive",
            "unarchive",
        ] {
            let path = format!("/api/ciphers/{literal}");
            let Err(error) = device_request(
                &app,
                Method::GET,
                &path,
                device_authorization(Some("device-fixture-alice")),
                b"",
            )
            .await
            else {
                panic!("Reserved literal bypassed read UUID guard.")
            };
            assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        }
        assert!(device_push_persisted_state(&app.store.lock().unwrap()) == before);
    }

    #[tokio::test]
    async fn cipher_read_http_denies_previous_stamp_and_reuses_only_fresh_bound_authority() {
        let app = cipher_read_fixture_app();
        let body = account_password_body("fixture-master-hash", "next-proof", "next-key");
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/accounts/password",
                device_authorization(Some("device-fixture-alice")),
                body.to_string().as_bytes(),
            )
            .await,
        )
        .await;
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        for suffix in ["", "/details", "/admin"] {
            for raw in [READ_CIPHER, "invalid"] {
                let path = format!("/api/ciphers/{raw}{suffix}");
                let Err(error) = device_request(
                    &app,
                    Method::GET,
                    &path,
                    device_authorization(Some("device-fixture-alice")),
                    b"",
                )
                .await
                else {
                    panic!("Previous-stamp bearer authorized a cipher read.")
                };
                assert_eq!(error.0, StatusCode::UNAUTHORIZED);
            }
        }
        assert!(device_push_persisted_state(&app.store.lock().unwrap()) == before);
        let tokens = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                account_password_login("next-proof", "Fresh-Read-Device").as_bytes(),
            )
            .await,
        )
        .await;
        for suffix in ["", "/details", "/admin"] {
            let path = format!("/api/ciphers/{READ_CIPHER}{suffix}");
            let document = device_document(
                device_request(
                    &app,
                    Method::GET,
                    &path,
                    device_authorization(tokens["access_token"].as_str()),
                    b"",
                )
                .await,
            )
            .await;
            assert!(document["id"] == READ_CIPHER);
        }
    }

    fn account_password_target(app: &App) {
        let account = json!({"id":"00000000-0000-4000-8000-000000000001","email":"target@example.test","keys":{"publicKey":"target-public","encryptedPrivateKey":"target-private"}});
        app.store.lock().unwrap().db.execute("INSERT INTO accounts(id,email,document,password,revision) VALUES('00000000-0000-4000-8000-000000000001','target@example.test',?1,'unused-verifier',?2)",params![account.to_string(),store::now()]).unwrap();
    }
    fn account_password_body(old: &str, new: &str, key: &str) -> Value {
        json!({"masterPasswordHash":old,"newMasterPasswordHash":new,"key":key,"owner":"bob","securityStamp":"forged","stampException":{"routes":["profile"],"expire":4_000_000_000_i64},"passwordHintsAllowed":true,"_password":"forged"})
    }
    fn account_password_login(proof: &str, id: &str) -> String {
        serde_urlencoded::to_string([
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("username", "alice@example.test"),
            ("password", proof),
            ("deviceIdentifier", id),
            ("deviceName", "Replacement"),
            ("deviceType", "14"),
        ])
        .unwrap()
    }

    #[tokio::test]
    async fn account_deletion_http_aliases_require_bound_proof_and_revoke_only_the_owner() {
        for (method, path) in [
            (Method::DELETE, "/api/accounts"),
            (Method::POST, "/api/accounts/delete"),
        ] {
            let app = auth_request_fixture_app();
            let before = device_push_persisted_state(&app.store.lock().unwrap());
            for bearer in [None, Some("invalid"), Some("legacy-auth-access")] {
                let Err(error) = device_request(
                    &app,
                    method.clone(),
                    path,
                    device_authorization(bearer),
                    b"{",
                )
                .await
                else {
                    panic!("Unbound account deletion accepted.")
                };
                assert_eq!(error.0, StatusCode::UNAUTHORIZED);
            }
            for (body, expected) in [
                (b"{".as_slice(), StatusCode::BAD_REQUEST),
                (b"[]", StatusCode::UNPROCESSABLE_ENTITY),
                (b"{}", StatusCode::BAD_REQUEST),
                (br#"{"masterPasswordHash":"wrong"}"#, StatusCode::BAD_REQUEST),
                (br#"{"otp":"unsupported"}"#, StatusCode::BAD_REQUEST),
                (br#"{"masterPasswordHash":"fixture-master-hash","otp":"unsupported"}"#, StatusCode::BAD_REQUEST),
                (br#"{"masterPasswordHash":"fixture-master-hash","MasterPasswordHash":"fixture-master-hash"}"#, StatusCode::UNPROCESSABLE_ENTITY),
            ] {
                let Err(error) = device_request(&app, method.clone(), path, device_authorization(Some("device-fixture-alice")), body).await else { panic!("Invalid account deletion proof accepted.") };
                assert_eq!(error.0, expected);
            }
            assert!(device_push_persisted_state(&app.store.lock().unwrap()) == before);
            let foreign = {
                let store = app.store.lock().unwrap();
                store.account("id", "bob").unwrap().unwrap()
            };
            // Neither query nor document extensions may choose a different owner.
            let query = format!("{path}/?organizationId=invalid&owner=bob&unknown=ignored");
            device_push_empty(
                device_request(
                    &app,
                    method.clone(),
                    &query,
                    device_authorization(Some("device-fixture-alice")),
                    br#"{"MasterPasswordHash":"fixture-master-hash","owner":"bob","userId":"bob"}"#,
                )
                .await,
            )
            .await;
            assert!(
                app.store
                    .lock()
                    .unwrap()
                    .account("id", "alice")
                    .unwrap()
                    .is_none()
            );
            assert!(
                app.store
                    .lock()
                    .unwrap()
                    .account("id", "bob")
                    .unwrap()
                    .unwrap()
                    == foreign
            );
            for (rejected_method, rejected_path, body) in [
                (Method::GET, "/api/accounts/profile", b"".as_slice()),
                (
                    method.clone(),
                    path,
                    br#"{"masterPasswordHash":"fixture-master-hash"}"#,
                ),
            ] {
                let Err(error) = device_request(
                    &app,
                    rejected_method,
                    rejected_path,
                    device_authorization(Some("device-fixture-alice")),
                    body,
                )
                .await
                else {
                    panic!("Deleted bearer retained account authority.")
                };
                assert_eq!(error.0, StatusCode::UNAUTHORIZED);
            }
            assert!(
                device_request(
                    &app,
                    Method::GET,
                    "/api/accounts/profile",
                    device_authorization(Some("device-fixture-bob")),
                    b""
                )
                .await
                .is_ok()
            );
        }
    }

    #[tokio::test]
    async fn account_deletion_http_denies_previous_stamp_before_schema_and_accepts_fresh_login() {
        let app = auth_request_fixture_app();
        let body = account_password_body("fixture-master-hash", "next-proof", "next-key");
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/accounts/password",
                device_authorization(Some("device-fixture-alice")),
                body.to_string().as_bytes(),
            )
            .await,
        )
        .await;
        let changes = app.store.lock().unwrap().db.total_changes();
        for (method, path) in [
            (Method::DELETE, "/api/accounts"),
            (Method::POST, "/api/accounts/delete"),
        ] {
            let Err(error) = device_request(
                &app,
                method,
                path,
                device_authorization(Some("device-fixture-alice")),
                b"{",
            )
            .await
            else {
                panic!("Previous-stamp bearer authorized account deletion.")
            };
            assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        }
        assert_eq!(app.store.lock().unwrap().db.total_changes(), changes);
        let tokens = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                account_password_login("next-proof", "Fresh-Deletion-Device").as_bytes(),
            )
            .await,
        )
        .await;
        device_push_empty(
            device_request(
                &app,
                Method::DELETE,
                "/api/accounts",
                device_authorization(tokens["access_token"].as_str()),
                br#"["next-proof",null]"#,
            )
            .await,
        )
        .await;
        assert!(
            app.store
                .lock()
                .unwrap()
                .account("id", "alice")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn account_deletion_http_storage_failure_preserves_credentials_and_allows_retry() {
        let app = auth_request_fixture_app();
        app.store.lock().unwrap().db.execute_batch("CREATE TRIGGER reject_deletion AFTER DELETE ON accounts BEGIN SELECT RAISE(FAIL,'fixture'); END;").unwrap();
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        let Err(error) = device_request(
            &app,
            Method::DELETE,
            "/api/accounts",
            device_authorization(Some("device-fixture-alice")),
            br#"{"masterPasswordHash":"fixture-master-hash"}"#,
        )
        .await
        else {
            panic!("Storage failure accepted account deletion.")
        };
        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(device_push_persisted_state(&app.store.lock().unwrap()) == before);
        assert!(
            device_request(
                &app,
                Method::GET,
                "/api/accounts/profile",
                device_authorization(Some("device-fixture-alice")),
                b""
            )
            .await
            .is_ok()
        );
        app.store
            .lock()
            .unwrap()
            .db
            .execute_batch("DROP TRIGGER reject_deletion")
            .unwrap();
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/accounts/delete",
                device_authorization(Some("device-fixture-alice")),
                br#"{"masterPasswordHash":"fixture-master-hash"}"#,
            )
            .await,
        )
        .await;
    }

    #[tokio::test]
    async fn personal_purge_http_requires_bound_authority_and_keeps_org_queries_out_of_personal_scope()
     {
        let app = auth_request_fixture_app();
        {
            let store = app.store.lock().unwrap();
            for owner in ["alice", "bob"] {
                store.db.execute("INSERT INTO items(id,owner,kind,document,revision,created) VALUES(?1,?2,'cipher',json_object('id',?1),?3,?3)",params![format!("purge-{owner}"),owner,store::now()]).unwrap();
            }
        }
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        for bearer in [None, Some("invalid"), Some("legacy-auth-access")] {
            let Err(error) = device_request(
                &app,
                Method::POST,
                "/api/ciphers/purge",
                device_authorization(bearer),
                b"{",
            )
            .await
            else {
                panic!("Unbound purge accepted.")
            };
            assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        }
        for method in [Method::GET, Method::PUT, Method::DELETE] {
            for (bearer, expected) in [
                (None, StatusCode::UNAUTHORIZED),
                (
                    Some("device-fixture-alice"),
                    StatusCode::UNPROCESSABLE_ENTITY,
                ),
            ] {
                let Err(error) = device_request(
                    &app,
                    method.clone(),
                    "/api/ciphers/purge",
                    device_authorization(bearer),
                    b"",
                )
                .await
                else {
                    panic!("Non-POST cipher action accepted the purge literal.")
                };
                assert_eq!(error.0, expected);
            }
        }
        for query in [
            "organizationId",
            "organizationId=",
            "organizationId=invalid",
            "organizationId=00000000-0000-0000-0000-000000000000",
            "organizationId.x=ignored",
            "%5BorganizationId%5D=ignored",
            ".organizationId=ignored",
            "organizationId=invalid&organizationId=",
        ] {
            let path = format!("/api/ciphers/purge?{query}");
            let Err(error) = device_request(
                &app,
                Method::POST,
                &path,
                device_authorization(Some("device-fixture-alice")),
                br#"{"masterPasswordHash":"fixture-master-hash"}"#,
            )
            .await
            else {
                panic!("Organization query purged the personal vault.")
            };
            assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        }
        for (body,expected) in [
            (b"{".as_slice(),StatusCode::BAD_REQUEST),
            (b"[]",StatusCode::UNPROCESSABLE_ENTITY),
            (b"{}",StatusCode::BAD_REQUEST),
            (br#"{"masterPasswordHash":"wrong"}"#,StatusCode::BAD_REQUEST),
            (br#"{"otp":"unsupported"}"#,StatusCode::BAD_REQUEST),
            (br#"{"masterPasswordHash":"fixture-master-hash","otp":"unsupported"}"#,StatusCode::BAD_REQUEST),
            (br#"{"masterPasswordHash":"fixture-master-hash","MasterPasswordHash":"fixture-master-hash"}"#,StatusCode::UNPROCESSABLE_ENTITY),
        ] {
            let Err(error)=device_request(&app,Method::POST,"/api/ciphers/purge",device_authorization(Some("device-fixture-alice")),body).await else {panic!("Invalid purge proof accepted.")};
            assert_eq!(error.0,expected);
        }
        assert!(device_push_persisted_state(&app.store.lock().unwrap()) == before);
        device_push_empty(device_request(&app,Method::POST,"/api/ciphers/purge/?unknown=ignored",device_authorization(Some("device-fixture-alice")),br#"{"MasterPasswordHash":"fixture-master-hash","owner":"bob","organizationId":"forged"}"#).await).await;
        let store = app.store.lock().unwrap();
        assert!(store.items("alice", "cipher").unwrap().is_empty());
        assert_eq!(store.items("bob", "cipher").unwrap().len(), 1);
        assert!(
            devices::access_binding(&store.db, &digest("device-fixture-alice"), "alice")
                .unwrap()
                .is_some()
        );
    }

    #[tokio::test]
    async fn personal_purge_http_rejects_previous_stamp_and_allows_only_fresh_bound_credentials() {
        let app = auth_request_fixture_app();
        let body = account_password_body("fixture-master-hash", "next-proof", "next-key");
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/accounts/password",
                device_authorization(Some("device-fixture-alice")),
                body.to_string().as_bytes(),
            )
            .await,
        )
        .await;
        let changes = app.store.lock().unwrap().db.total_changes();
        let Err(error) = device_request(
            &app,
            Method::POST,
            "/api/ciphers/purge",
            device_authorization(Some("device-fixture-alice")),
            br#"{"masterPasswordHash":"next-proof"}"#,
        )
        .await
        else {
            panic!("Previous-stamp bearer authorized personal purge.")
        };
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        assert_eq!(app.store.lock().unwrap().db.total_changes(), changes);
        let form = account_password_login("next-proof", "Fresh-Purge-Device");
        let tokens = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                form.as_bytes(),
            )
            .await,
        )
        .await;
        let bearer = tokens["access_token"].as_str().unwrap();
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/ciphers/purge",
                device_authorization(Some(bearer)),
                br#"["next-proof",null]"#,
            )
            .await,
        )
        .await;
    }

    async fn webauthn_document(app: &App, bearer: &str, path: &str, body: &[u8]) {
        let document = device_document(
            device_request(
                app,
                Method::GET,
                path,
                device_authorization(Some(bearer)),
                body,
            )
            .await,
        )
        .await;
        assert_eq!(
            document,
            json!({"object":"list","data":[],"continuationToken":null})
        );
    }

    #[tokio::test]
    async fn webauthn_credentials_http_requires_owned_bound_current_access_and_never_writes() {
        let app = auth_request_fixture_app();
        let changes = app.store.lock().unwrap().db.total_changes();
        for bearer in [None, Some("invalid"), Some("legacy-auth-access")] {
            let Err(error) = device_request(
                &app,
                Method::GET,
                "/api/webauthn",
                device_authorization(bearer),
                b"{",
            )
            .await
            else {
                panic!("Unauthenticated credential discovery succeeded.")
            };
            assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        }
        for bearer in ["device-fixture-alice", "device-fixture-bob"] {
            for path in [
                "/api/webauthn",
                "/api/webauthn/",
                "/api/webauthn?unknown=ignored&userId=foreign",
            ] {
                webauthn_document(&app, bearer, path, b"malformed ignored body").await;
            }
        }
        assert_eq!(app.store.lock().unwrap().db.total_changes(), changes);
        app.store
            .lock()
            .unwrap()
            .db
            .execute(
                "UPDATE sessions SET access_expires=0 WHERE access=?1",
                [digest("device-fixture-alice")],
            )
            .unwrap();
        let Err(error) = device_request(
            &app,
            Method::GET,
            "/api/webauthn",
            device_authorization(Some("device-fixture-alice")),
            b"",
        )
        .await
        else {
            panic!("Expired current access authorized credential discovery.")
        };
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn webauthn_credentials_http_cannot_borrow_another_owners_device() {
        let app = auth_request_fixture_app();
        app.store
            .lock()
            .unwrap()
            .db
            .execute(
                "DELETE FROM device_registry WHERE owner='alice' AND identifier='Request-Device'",
                [],
            )
            .unwrap();
        let mut headers = device_authorization(Some("device-fixture-alice"));
        headers.insert("device-identifier", "Request-Device".parse().unwrap());
        let Err(error) = device_request(&app, Method::GET, "/api/webauthn", headers, b"").await
        else {
            panic!("Foreign owned device authorized credential discovery.")
        };
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        webauthn_document(&app, "device-fixture-bob", "/api/webauthn", b"").await;
    }

    #[tokio::test]
    async fn webauthn_credentials_http_preserves_previous_access_deadline_and_expiry_cleanup_order()
    {
        let app = auth_request_fixture_app();
        let body = account_password_body("fixture-master-hash", "next-proof", "next-key");
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/accounts/password",
                device_authorization(Some("device-fixture-alice")),
                body.to_string().as_bytes(),
            )
            .await,
        )
        .await;
        let changes = app.store.lock().unwrap().db.total_changes();
        webauthn_document(&app, "device-fixture-alice", "/api/webauthn", b"{").await;
        assert_eq!(app.store.lock().unwrap().db.total_changes(), changes);
        let Err(error) = device_request(
            &app,
            Method::GET,
            "/api/accounts/profile",
            device_authorization(Some("device-fixture-alice")),
            b"",
        )
        .await
        else {
            panic!("Credential-discovery exception authorized profile access.")
        };
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        {
            let store = app.store.lock().unwrap();
            store
                .db
                .execute(
                    "UPDATE account_password_access SET access_expires=0 WHERE access=?1",
                    [digest("device-fixture-alice")],
                )
                .unwrap();
            store
                .db
                .execute(
                    "UPDATE account_password_exceptions SET expires=0 WHERE owner='alice'",
                    [],
                )
                .unwrap();
        }
        let changes = app.store.lock().unwrap().db.total_changes();
        let Err(error) = device_request(
            &app,
            Method::GET,
            "/api/webauthn",
            device_authorization(Some("device-fixture-alice")),
            b"",
        )
        .await
        else {
            panic!("Credential discovery extended the original access deadline.")
        };
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        assert_eq!(app.store.lock().unwrap().db.total_changes(), changes);
        {
            let store = app.store.lock().unwrap();
            let count: i64 = store
                .db
                .query_row(
                    "SELECT COUNT(*) FROM account_password_exceptions WHERE owner='alice'",
                    [],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(count, 1);
            store
                .db
                .execute(
                    "UPDATE account_password_access SET access_expires=4000000000 WHERE access=?1",
                    [digest("device-fixture-alice")],
                )
                .unwrap();
        }
        let revision = app
            .store
            .lock()
            .unwrap()
            .account("id", "alice")
            .unwrap()
            .unwrap()["revisionDate"]
            .clone();
        let Err(error) = device_request(
            &app,
            Method::GET,
            "/api/webauthn",
            device_authorization(Some("device-fixture-alice")),
            b"",
        )
        .await
        else {
            panic!("Expired password-change exception authorized discovery.")
        };
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        let changes = app.store.lock().unwrap().db.total_changes();
        assert!(
            app.store
                .lock()
                .unwrap()
                .account("id", "alice")
                .unwrap()
                .unwrap()["revisionDate"]
                != revision
        );
        let Err(error) = device_request(
            &app,
            Method::GET,
            "/api/webauthn",
            device_authorization(Some("device-fixture-alice")),
            b"",
        )
        .await
        else {
            panic!("Expired exception authorized repeated discovery.")
        };
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        assert_eq!(app.store.lock().unwrap().db.total_changes(), changes);
    }

    #[tokio::test]
    async fn account_password_http_guards_schema_hint_policy_and_partial_nested_legacy_fallback() {
        let app = auth_request_fixture_app();
        account_password_target(&app);
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        for bearer in [None, Some("invalid"), Some("legacy-auth-access")] {
            let Err(error) = device_request(
                &app,
                Method::POST,
                "/api/accounts/password",
                device_authorization(bearer),
                b"{",
            )
            .await
            else {
                panic!("Unbound password change accepted.")
            };
            assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        }
        for bearer in [None, Some("invalid")] {
            let Err(error) = device_request(
                &app,
                Method::GET,
                "/api/users/not-a-uuid/public-key",
                device_authorization(bearer),
                b"",
            )
            .await
            else {
                panic!("Unauthenticated public-key request accepted.")
            };
            assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        }
        let Err(error) = device_request(
            &app,
            Method::GET,
            "/api/users/not-a-uuid/public-key",
            device_authorization(Some("device-fixture-alice")),
            b"",
        )
        .await
        else {
            panic!("Malformed public-key ID accepted.")
        };
        assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        for (body,status) in [
            (b"{".as_slice(),StatusCode::BAD_REQUEST),
            (b"{}",StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"MasterPasswordHash":"fixture-master-hash","newMasterPasswordHash":"new","key":"key"}"#,StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"masterPasswordHash":"fixture-master-hash","newMasterPasswordHash":"new","key":"key","authenticationData":{}}"#,StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"masterPasswordHash":"wrong","newMasterPasswordHash":"new","key":"key"}"#,StatusCode::BAD_REQUEST),
            (br#"{"masterPasswordHash":"fixture-master-hash","key":"key"}"#,StatusCode::BAD_REQUEST),
        ] {
            let Err(error)=device_request(&app,Method::POST,"/api/accounts/password",device_authorization(Some("device-fixture-alice")),body).await else {panic!("Invalid password-change request accepted.")};
            assert_eq!(error.0,status);
        }
        app.store
            .lock()
            .unwrap()
            .registration_policy
            .password_hints_allowed = false;
        let mut body = account_password_body("fixture-master-hash", "new-proof", "new-key");
        body["masterPasswordHint"] = json!(" prohibited ");
        let Err(error) = device_request(
            &app,
            Method::POST,
            "/api/accounts/password",
            device_authorization(Some("device-fixture-alice")),
            body.to_string().as_bytes(),
        )
        .await
        else {
            panic!("Untrusted hint policy override accepted.")
        };
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(device_push_persisted_state(&app.store.lock().unwrap()) == before);
        body["masterPasswordHint"] = json!(" \n \t");
        body["authenticationData"] = json!({"salt":"ignored-partial","kdf":{"kdf":0,"kdfIterations":-1},"masterPasswordAuthenticationHash":"ignored-partial"});
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/accounts/password",
                device_authorization(Some("device-fixture-alice")),
                body.to_string().as_bytes(),
            )
            .await,
        )
        .await;
        let account = app
            .store
            .lock()
            .unwrap()
            .account("id", "alice")
            .unwrap()
            .unwrap();
        assert!(
            account["key"] == "new-key"
                && account["masterPasswordHint"].is_null()
                && account.get("_password").is_none()
                && account.get("stampException").is_none()
        );
        assert!(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                account_password_login("new-proof", "Request-Device").as_bytes()
            )
            .await
            .is_ok()
        );
    }
    #[tokio::test]
    async fn account_password_http_old_password_and_api_bearers_are_route_limited_and_overwritten()
    {
        let app = auth_request_fixture_app();
        account_password_target(&app);
        let secret = {
            let mut store = app.store.lock().unwrap();
            no_warden::identity::IdentityStorage::get_or_create_api_key(&mut *store, "alice")
                .unwrap()
                .api_key
                .expose_secret()
                .to_owned()
        };
        let api_body = serde_urlencoded::to_string([
            ("grant_type", "client_credentials"),
            ("client_id", "user.alice"),
            ("client_secret", secret.as_str()),
            ("scope", "api"),
            ("deviceIdentifier", "Request-Device"),
            ("deviceName", "Ignored replacement"),
            ("deviceType", "8"),
        ])
        .unwrap();
        let password = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                account_password_login("fixture-master-hash", "Request-Device").as_bytes(),
            )
            .await,
        )
        .await;
        let api = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                api_body.as_bytes(),
            )
            .await,
        )
        .await;
        assert!(api.get("refresh_token").is_none());
        let mut body = account_password_body("fixture-master-hash", "one\0雪", "key-one\0雪");
        body["masterPasswordHint"] = json!(" \n hint 雪 \t");
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/accounts/password",
                device_authorization(Some("device-fixture-alice")),
                body.to_string().as_bytes(),
            )
            .await,
        )
        .await;
        for bearer in [
            "device-fixture-alice",
            password["access_token"].as_str().unwrap(),
            api["access_token"].as_str().unwrap(),
        ] {
            let public = device_document(
                device_request(
                    &app,
                    Method::GET,
                    PASSWORD_PUBLIC_PATH,
                    device_authorization(Some(bearer)),
                    b"",
                )
                .await,
            )
            .await;
            assert!(public["publicKey"] == "target-public" && public.get("privateKey").is_none());
            for (method, path, data) in [
                (Method::GET, "/api/accounts/profile", b"".as_slice()),
                (Method::POST, "/api/accounts/password", b"{"),
            ] {
                let Err(error) =
                    device_request(&app, method, path, device_authorization(Some(bearer)), data)
                        .await
                else {
                    panic!("Previous stamp authorized an unrelated route.")
                };
                assert_eq!(error.0, StatusCode::UNAUTHORIZED);
            }
        }
        let refresh = serde_urlencoded::to_string([
            ("grant_type", "refresh_token"),
            ("refresh_token", password["refresh_token"].as_str().unwrap()),
        ])
        .unwrap();
        assert!(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                refresh.as_bytes()
            )
            .await
            .is_err()
        );
        let current = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                account_password_login("one\0雪", "Request-Device").as_bytes(),
            )
            .await,
        )
        .await;
        let body = account_password_body("one\0雪", "two", "key-two");
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/accounts/password",
                device_authorization(current["access_token"].as_str()),
                body.to_string().as_bytes(),
            )
            .await,
        )
        .await;
        for bearer in [
            "device-fixture-alice",
            password["access_token"].as_str().unwrap(),
            api["access_token"].as_str().unwrap(),
        ] {
            let Err(error) = device_request(
                &app,
                Method::GET,
                PASSWORD_PUBLIC_PATH,
                device_authorization(Some(bearer)),
                b"",
            )
            .await
            else {
                panic!("Previous exception generation survived replacement.")
            };
            assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        }
        assert!(
            device_request(
                &app,
                Method::GET,
                PASSWORD_PUBLIC_PATH,
                device_authorization(current["access_token"].as_str()),
                b""
            )
            .await
            .is_ok()
        );
        let fresh = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                account_password_login("two", "Request-Device").as_bytes(),
            )
            .await,
        )
        .await;
        assert!(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                api_body.as_bytes()
            )
            .await
            .is_ok()
        );
        let revision = {
            let store = app.store.lock().unwrap();
            store
                .db
                .execute(
                    "UPDATE account_password_exceptions SET expires=?1 WHERE owner='alice'",
                    [chrono::Utc::now().timestamp() - 1],
                )
                .unwrap();
            store.account("id", "alice").unwrap().unwrap()["revisionDate"].clone()
        };
        assert!(
            device_request(
                &app,
                Method::GET,
                "/api/accounts/profile",
                device_authorization(fresh["access_token"].as_str()),
                b""
            )
            .await
            .is_ok()
        );
        let exception_count: i64 = app
            .store
            .lock()
            .unwrap()
            .db
            .query_row(
                "SELECT COUNT(*) FROM account_password_exceptions WHERE owner='alice'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exception_count, 1);
        let Err(error) = device_request(
            &app,
            Method::GET,
            "/api/users/not-a-uuid/public-key",
            device_authorization(password["access_token"].as_str()),
            b"",
        )
        .await
        else {
            panic!("Expired previous stamp passed auth before UUID guard.")
        };
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        let profile = device_document(
            device_request(
                &app,
                Method::GET,
                "/api/accounts/profile",
                device_authorization(fresh["access_token"].as_str()),
                b"",
            )
            .await,
        )
        .await;
        assert!(profile["securityStamp"] == device_claims(&fresh)["sstamp"]);
        let store = app.store.lock().unwrap();
        assert!(store.account("id", "alice").unwrap().unwrap()["revisionDate"] != revision);
        let exception_count: i64 = store
            .db
            .query_row(
                "SELECT COUNT(*) FROM account_password_exceptions WHERE owner='alice'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(exception_count, 0);
    }
    #[tokio::test]
    async fn account_password_http_exception_survives_kdf_reset_and_exact_device_recreation() {
        let (app, id) = auth_login_fixture();
        account_password_target(&app);
        let requests = auth_request_persisted_rows(&app.store.lock().unwrap());
        let body = account_password_body("fixture-master-hash", "one", "key-one");
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/accounts/password",
                device_authorization(Some("device-fixture-alice")),
                body.to_string().as_bytes(),
            )
            .await,
        )
        .await;
        let current = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                account_password_login("one", "Request-Device").as_bytes(),
            )
            .await,
        )
        .await;
        let kdf = no_warden::wire::RegistrationKdf {
            kdf: 0,
            kdf_iterations: 700_000,
            kdf_memory: None,
            kdf_parallelism: None,
        };
        let body = account_kdf_document("one", "two", "key-two", kdf);
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/accounts/kdf",
                device_authorization(current["access_token"].as_str()),
                body.to_string().as_bytes(),
            )
            .await,
        )
        .await;
        assert!(
            device_request(
                &app,
                Method::GET,
                PASSWORD_PUBLIC_PATH,
                device_authorization(Some("device-fixture-alice")),
                b""
            )
            .await
            .is_ok()
        );
        let Err(error) = device_request(
            &app,
            Method::GET,
            PASSWORD_PUBLIC_PATH,
            device_authorization(current["access_token"].as_str()),
            b"",
        )
        .await
        else {
            panic!("KDF change added its old current stamp to the password exception.")
        };
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        let current = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                account_password_login("two", "Request-Device").as_bytes(),
            )
            .await,
        )
        .await;
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/accounts/security-stamp",
                device_authorization(current["access_token"].as_str()),
                br#"{"masterPasswordHash":"two"}"#,
            )
            .await,
        )
        .await;
        let Err(error) = device_request(
            &app,
            Method::GET,
            PASSWORD_PUBLIC_PATH,
            device_authorization(Some("device-fixture-alice")),
            b"",
        )
        .await
        else {
            panic!("Deleted device passed previous-stamp guard.")
        };
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        assert!(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                account_password_login("two", "Other-Device").as_bytes()
            )
            .await
            .is_ok()
        );
        assert!(
            device_request(
                &app,
                Method::GET,
                PASSWORD_PUBLIC_PATH,
                device_authorization(Some("device-fixture-alice")),
                b""
            )
            .await
            .is_err()
        );
        assert!(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                account_password_login("two", "Request-Device").as_bytes()
            )
            .await
            .is_ok()
        );
        assert!(
            device_request(
                &app,
                Method::GET,
                PASSWORD_PUBLIC_PATH,
                device_authorization(Some("device-fixture-alice")),
                b""
            )
            .await
            .is_ok()
        );
        assert!(auth_request_persisted_rows(&app.store.lock().unwrap()) == requests);
        assert!(auth_login_http(&app, &auth_login_form(&id)).await.is_ok());
    }

    fn account_kdf_document(
        old: &str,
        new: &str,
        key: &str,
        kdf: no_warden::wire::RegistrationKdf,
    ) -> Value {
        let kdf = json!({"kdf":kdf.kdf,"kdfIterations":kdf.kdf_iterations,"kdfMemory":kdf.kdf_memory,"kdfParallelism":kdf.kdf_parallelism});
        json!({"authenticationData":{"salt":"alice@example.test","kdf":kdf,"masterPasswordAuthenticationHash":new},"unlockData":{"salt":"alice@example.test","kdf":kdf,"masterKeyWrappedUserKey":key},"masterPasswordHash":old,"id":"bob","owner":"bob","securityStamp":"forged","keys":{"publicKey":"forged"},"_password":"forged","apiKey":"forged","future":"ignored"})
    }
    #[tokio::test]
    async fn account_kdf_http_authentication_schema_proof_and_salt_failures_are_nonmutating() {
        let app = auth_request_fixture_app();
        let kdf = no_warden::wire::RegistrationKdf {
            kdf: 0,
            kdf_iterations: 700_000,
            kdf_memory: None,
            kdf_parallelism: None,
        };
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        for bearer in [None, Some("invalid"), Some("legacy-auth-access")] {
            let Err(error) = device_request(
                &app,
                Method::POST,
                "/api/accounts/kdf",
                device_authorization(bearer),
                b"{",
            )
            .await
            else {
                panic!("Unauthenticated or unbound KDF request succeeded.")
            };
            assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        }
        for (body,status) in [
            (b"{".as_slice(),StatusCode::BAD_REQUEST),
            (b"{}",StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"kdf":0,"kdfIterations":700000,"masterPasswordHash":"fixture-master-hash","newMasterPasswordHash":"new","key":"key"}"#,StatusCode::UNPROCESSABLE_ENTITY),
        ] {
            let Err(error)=device_request(&app,Method::POST,"/api/accounts/kdf",device_authorization(Some("device-fixture-alice")),body).await else {panic!("Invalid KDF schema accepted.")};
            assert_eq!(error.0,status);
        }
        for phase in 0..5 {
            let mut document =
                account_kdf_document("fixture-master-hash", "new-proof", "new-key", kdf);
            match phase {
                0 => document["masterPasswordHash"] = json!("wrong"),
                1 => document["authenticationData"]["salt"] = json!("ALICE@EXAMPLE.TEST"),
                2 => document["unlockData"]["salt"] = json!(" alice@example.test "),
                3 => document["unlockData"]["kdf"]["kdfIterations"] = json!(700_001),
                _ => {
                    document["authenticationData"]["kdf"]["kdfIterations"] = json!(99_999);
                    document["unlockData"]["kdf"]["kdfIterations"] = json!(99_999);
                }
            }
            let Err(error) = device_request(
                &app,
                Method::POST,
                "/api/accounts/kdf",
                device_authorization(Some("device-fixture-alice")),
                document.to_string().as_bytes(),
            )
            .await
            else {
                panic!("Invalid KDF proof or settings accepted.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }
        assert!(
            device_push_persisted_state(&app.store.lock().unwrap()) == before,
            "Rejected KDF request changed persisted authority."
        );
        assert!(
            device_request(
                &app,
                Method::GET,
                "/api/accounts/profile",
                device_authorization(Some("device-fixture-alice")),
                b""
            )
            .await
            .is_ok()
        );
    }
    #[tokio::test]
    async fn account_kdf_http_transitions_revoke_sessions_preserve_devices_and_accept_opaque_new_proofs()
     {
        let (app, id) = auth_login_fixture();
        let api_secret = {
            let mut store = app.store.lock().unwrap();
            store.db.execute("INSERT INTO device_push_tokens(owner,identifier,token) VALUES('alice','Request-Device','opaque-push')",[]).unwrap();
            no_warden::identity::IdentityStorage::get_or_create_api_key(&mut *store, "alice")
                .unwrap()
                .api_key
                .expose_secret()
                .to_owned()
        };
        let requests = auth_request_persisted_rows(&app.store.lock().unwrap());
        let retained = |store: &Store| {
            device_push_persisted_state(store)
                .into_iter()
                .filter(|row| row.starts_with("device:") || row.starts_with("push:"))
                .collect::<Vec<_>>()
        };
        let devices = retained(&app.store.lock().unwrap());
        let login = |proof: &str| {
            serde_urlencoded::to_string([
                ("grant_type", "password"),
                ("client_id", "cli"),
                ("scope", "api offline_access"),
                ("username", "alice@example.test"),
                ("password", proof),
                ("deviceIdentifier", "Request-Device"),
                ("deviceName", "Ignored replacement"),
                ("deviceType", "14"),
            ])
            .unwrap()
        };
        let api_login = || {
            serde_urlencoded::to_string([
                ("grant_type", "client_credentials"),
                ("client_id", "user.alice"),
                ("client_secret", api_secret.as_str()),
                ("scope", "api"),
                ("deviceIdentifier", "Request-Device"),
                ("deviceName", "Ignored replacement"),
                ("deviceType", "14"),
            ])
            .unwrap()
        };
        let argon = no_warden::wire::RegistrationKdf {
            kdf: 1,
            kdf_iterations: 1,
            kdf_memory: Some(15),
            kdf_parallelism: Some(16),
        };
        let first =
            account_kdf_document("fixture-master-hash", "new-proof\0雪", "new-key\0雪", argon);
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/accounts/kdf",
                device_authorization(Some("device-fixture-alice")),
                first.to_string().as_bytes(),
            )
            .await,
        )
        .await;
        {
            let store = app.store.lock().unwrap();
            assert!(retained(&store) == devices && auth_request_persisted_rows(&store) == requests);
            assert!(
                store.account("id", "alice").unwrap().unwrap()["keys"]["publicKey"]
                    == "preserved-public"
            );
        }
        let Err(error) = device_request(
            &app,
            Method::GET,
            "/api/accounts/profile",
            device_authorization(Some("device-fixture-alice")),
            b"",
        )
        .await
        else {
            panic!("KDF change retained old bearer authority.")
        };
        assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        let refresh = serde_urlencoded::to_string([
            ("grant_type", "refresh_token"),
            ("refresh_token", "device-fixture-refresh-alice"),
        ])
        .unwrap();
        let Err(error) = device_request(
            &app,
            Method::POST,
            "/identity/connect/token",
            HeaderMap::new(),
            refresh.as_bytes(),
        )
        .await
        else {
            panic!("KDF change retained old refresh authority.")
        };
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                login("fixture-master-hash").as_bytes()
            )
            .await
            .is_err()
        );
        assert!(
            device_request(
                &app,
                Method::GET,
                "/api/accounts/profile",
                device_authorization(Some("device-fixture-bob")),
                b""
            )
            .await
            .is_ok()
        );
        for path in [
            "/identity/accounts/prelogin",
            "/identity/accounts/prelogin/password",
        ] {
            let data = device_document(
                device_request(
                    &app,
                    Method::POST,
                    path,
                    HeaderMap::new(),
                    br#"{"email":"alice@example.test"}"#,
                )
                .await,
            )
            .await;
            assert!(
                data["kdf"] == 1
                    && data["kdfIterations"] == 1
                    && data["kdfMemory"] == 15
                    && data["kdfParallelism"] == 16
            );
        }
        let tokens = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                login("new-proof\0雪").as_bytes(),
            )
            .await,
        )
        .await;
        assert!(tokens["Key"] == "new-key\0雪" && tokens["Kdf"] == 1);
        let first_stamp = device_claims(&tokens)["sstamp"].clone();
        let unknown = no_warden::wire::RegistrationKdf {
            kdf: -7,
            kdf_iterations: -8,
            kdf_memory: Some(-9),
            kdf_parallelism: Some(-10),
        };
        let second = account_kdf_document("new-proof\0雪", "", "", unknown);
        let before_second = retained(&app.store.lock().unwrap());
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/accounts/kdf",
                device_authorization(tokens["access_token"].as_str()),
                second.to_string().as_bytes(),
            )
            .await,
        )
        .await;
        {
            let store = app.store.lock().unwrap();
            assert!(
                retained(&store) == before_second
                    && auth_request_persisted_rows(&store) == requests
            );
            let account = store.account("id", "alice").unwrap().unwrap();
            assert!(
                account["key"] == ""
                    && account["kdf"] == -7
                    && account["kdfIterations"] == -8
                    && account["kdfMemory"].is_null()
                    && account["kdfParallelism"].is_null()
            );
            assert!(
                account.get("apiKey").is_none()
                    && account.get("masterPasswordHash").is_none()
                    && account.get("_password").is_none()
            );
        }
        let empty = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                login("").as_bytes(),
            )
            .await,
        )
        .await;
        assert!(empty.get("Key").is_none() && empty["Kdf"] == -7 && empty["KdfIterations"] == -8);
        assert!(
            empty["UserDecryptionOptions"]["MasterPasswordUnlock"]["MasterKeyWrappedUserKey"] == ""
        );
        assert!(device_claims(&empty)["sstamp"] != first_stamp);
        let api = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                api_login().as_bytes(),
            )
            .await,
        )
        .await;
        assert!(api.get("Key").is_some_and(|key| key == "") && api.get("refresh_token").is_none());
        let sync = device_document(
            device_request(
                &app,
                Method::GET,
                "/api/sync",
                device_authorization(empty["access_token"].as_str()),
                b"",
            )
            .await,
        )
        .await;
        assert!(
            sync["profile"]["key"] == ""
                && sync["profile"]["securityStamp"] == device_claims(&empty)["sstamp"]
                && sync["userDecryption"]["masterPasswordUnlock"]["kdf"]["kdfType"] == -7
        );
        let keys = device_document(
            device_request(
                &app,
                Method::GET,
                "/api/accounts/keys",
                device_authorization(empty["access_token"].as_str()),
                b"",
            )
            .await,
        )
        .await;
        assert!(keys["key"].is_null());
        // An approved, unused code is independent of the changed master proof.
        let auth_tokens = device_document(auth_login_http(&app, &auth_login_form(&id)).await).await;
        assert!(
            auth_tokens.get("Key").is_none()
                && device_claims(&auth_tokens)["sstamp"] == device_claims(&empty)["sstamp"]
        );
    }

    #[tokio::test]
    async fn account_security_http_authenticates_bound_device_before_schema_and_preserves_state() {
        let app = auth_request_fixture_app();
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        for path in [
            "/api/accounts/verify-password",
            "/api/accounts/security-stamp",
        ] {
            for bearer in [None, Some("invalid"), Some("legacy-auth-access")] {
                let Err(error) =
                    device_request(&app, Method::POST, path, device_authorization(bearer), b"{")
                        .await
                else {
                    panic!("Unbound account-security request succeeded.")
                };
                assert_eq!(error.0, StatusCode::UNAUTHORIZED);
            }
        }
        for (path, body, expected) in [
            ("/api/accounts/verify-password", b"{".as_slice(), StatusCode::BAD_REQUEST),
            ("/api/accounts/verify-password", b"{}", StatusCode::UNPROCESSABLE_ENTITY),
            ("/api/accounts/verify-password", br#"{"MasterPasswordHash":"fixture-master-hash"}"#, StatusCode::UNPROCESSABLE_ENTITY),
            ("/api/accounts/verify-password", br#"{"masterPasswordHash":"wrong"}"#, StatusCode::BAD_REQUEST),
            ("/api/accounts/verify-password", br#"{"masterPasswordHash":""}"#, StatusCode::BAD_REQUEST),
            ("/api/accounts/security-stamp", b"[]", StatusCode::UNPROCESSABLE_ENTITY),
            ("/api/accounts/security-stamp", b"{}", StatusCode::BAD_REQUEST),
            ("/api/accounts/security-stamp", br#"{"otp":"unsupported"}"#, StatusCode::BAD_REQUEST),
            ("/api/accounts/security-stamp", br#"{"masterPasswordHash":"fixture-master-hash","otp":"unsupported"}"#, StatusCode::BAD_REQUEST),
            ("/api/accounts/security-stamp", br#"{"masterPasswordHash":"wrong"}"#, StatusCode::BAD_REQUEST),
            ("/api/accounts/security-stamp", br#"{"masterPasswordHash":"fixture-master-hash","MasterPasswordHash":"fixture-master-hash"}"#, StatusCode::UNPROCESSABLE_ENTITY),
        ] {
            let Err(error) = device_request(&app, Method::POST, path, device_authorization(Some("device-fixture-alice")), body).await else {
                panic!("Invalid account-security request succeeded.")
            };
            assert_eq!(error.0, expected);
        }
        for body in [br#"{"masterPasswordHash":"fixture-master-hash","owner":"bob","securityStamp":"forged"}"#.as_slice(), br#"["fixture-master-hash"]"#] {
            let response = device_document(device_request(&app, Method::POST, "/api/accounts/verify-password", device_authorization(Some("device-fixture-alice")), body).await).await;
            assert!(response == json!({"Object":"masterPasswordPolicy"}));
        }
        {
            let store = app.store.lock().unwrap();
            assert!(
                device_push_persisted_state(&store) == before,
                "Account verification or rejected renewal mutated state."
            );
            let private_rows: i64 = store
                .db
                .query_row("SELECT COUNT(*) FROM account_security", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(private_rows, 0);
        }
        // The deliberate binding requirement applies only to these new routes.
        assert!(
            device_request(
                &app,
                Method::GET,
                "/api/accounts/profile",
                device_authorization(Some("legacy-auth-access")),
                b""
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn account_security_http_renewal_revokes_owner_and_projects_private_stamp_after_relogin()
    {
        let app = auth_request_fixture_app();
        let api_secret = {
            let mut store = app.store.lock().unwrap();
            let mut account = store.account("id", "alice").unwrap().unwrap();
            account["securityStamp"] = json!("forged-document-stamp");
            store
                .db
                .execute(
                    "UPDATE accounts SET document=?1 WHERE id='alice'",
                    [account.to_string()],
                )
                .unwrap();
            store.db.execute("INSERT INTO device_push_tokens(owner,identifier,token) VALUES('alice','Request-Device','private-token')",[]).unwrap();
            no_warden::identity::IdentityStorage::get_or_create_api_key(&mut *store, "alice")
                .unwrap()
                .api_key
                .expose_secret()
                .to_owned()
        };
        let login_body = device_login_body("alice", "Extra-Device", "Retained", "8");
        let prior = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                &login_body,
            )
            .await,
        )
        .await;
        assert!(device_claims(&prior)["sstamp"] == "alice");
        let profile = device_document(
            device_request(
                &app,
                Method::GET,
                "/api/accounts/profile",
                device_authorization(Some("device-fixture-alice")),
                b"",
            )
            .await,
        )
        .await;
        assert!(profile["securityStamp"] == "alice");
        device_push_empty(device_request(&app,Method::POST,"/api/accounts/security-stamp",device_authorization(Some("device-fixture-alice")),br#"{"MasterPasswordHash":"fixture-master-hash","owner":"bob","securityStamp":"forged"}"#).await).await;
        let stamp = {
            let store = app.store.lock().unwrap();
            let stamp = account_security::stamp(&store.db, "alice").unwrap();
            assert!(
                uuid::Uuid::parse_str(&stamp).is_ok()
                    && stamp != "alice"
                    && stamp != "forged-document-stamp"
            );
            for table in [
                "sessions",
                "session_devices",
                "device_registry",
                "device_push_tokens",
            ] {
                let count: i64 = store
                    .db
                    .query_row(
                        &format!("SELECT COUNT(*) FROM {table} WHERE owner='alice'"),
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
                assert_eq!(count, 0);
            }
            stamp
        };
        for access in [
            "device-fixture-alice",
            "legacy-auth-access",
            prior["access_token"].as_str().unwrap(),
        ] {
            let Err(error) = device_request(
                &app,
                Method::GET,
                "/api/accounts/profile",
                device_authorization(Some(access)),
                b"",
            )
            .await
            else {
                panic!("Renewal left owner access usable.")
            };
            assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        }
        for refresh in [
            "device-fixture-refresh-alice",
            prior["refresh_token"].as_str().unwrap(),
        ] {
            let body = serde_urlencoded::to_string([
                ("grant_type", "refresh_token"),
                ("refresh_token", refresh),
            ])
            .unwrap();
            let Err(error) = device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                body.as_bytes(),
            )
            .await
            else {
                panic!("Renewal left owner refresh usable.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }
        assert!(
            device_request(
                &app,
                Method::GET,
                "/api/accounts/profile",
                device_authorization(Some("device-fixture-bob")),
                b""
            )
            .await
            .is_ok()
        );
        let password = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                &login_body,
            )
            .await,
        )
        .await;
        assert!(device_claims(&password)["sstamp"] == stamp);
        let api_body = serde_urlencoded::to_string([
            ("grant_type", "client_credentials"),
            ("client_id", "user.alice"),
            ("client_secret", &api_secret),
            ("scope", "api"),
            ("deviceIdentifier", "API-After-Reset"),
            ("deviceName", "API"),
            ("deviceType", "8"),
        ])
        .unwrap();
        let api = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                api_body.as_bytes(),
            )
            .await,
        )
        .await;
        assert!(device_claims(&api)["sstamp"] == stamp && api.get("refresh_token").is_none());
        for path in ["/api/accounts/profile", "/api/sync"] {
            let document = device_document(
                device_request(
                    &app,
                    Method::GET,
                    path,
                    device_authorization(password["access_token"].as_str()),
                    b"",
                )
                .await,
            )
            .await;
            let profile = if path.ends_with("sync") {
                &document["profile"]
            } else {
                &document
            };
            assert!(profile["securityStamp"] == stamp);
        }
        let updated = device_document(
            device_request(
                &app,
                Method::PUT,
                "/api/accounts/profile",
                device_authorization(password["access_token"].as_str()),
                br#"{"name":"renamed","securityStamp":"forged-update"}"#,
            )
            .await,
        )
        .await;
        assert!(updated["securityStamp"] == stamp);
        let avatar = device_document(
            device_request(
                &app,
                Method::PUT,
                "/api/accounts/avatar",
                device_authorization(password["access_token"].as_str()),
                br##"{"avatarColor":"#123456","securityStamp":"forged-update"}"##,
            )
            .await,
        )
        .await;
        assert!(avatar["securityStamp"] == stamp);
        let refresh_body = serde_urlencoded::to_string([
            ("grant_type", "refresh_token"),
            ("refresh_token", password["refresh_token"].as_str().unwrap()),
        ])
        .unwrap();
        let refreshed = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                refresh_body.as_bytes(),
            )
            .await,
        )
        .await;
        assert!(device_claims(&refreshed)["sstamp"] == stamp);
    }

    #[tokio::test]
    async fn account_security_http_renewal_preserves_approved_request_proof_and_public_polling() {
        let (app, id) = auth_login_fixture();
        let before = auth_request_persisted_rows(&app.store.lock().unwrap());
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/accounts/security-stamp",
                device_authorization(Some("device-fixture-alice")),
                br#"["fixture-master-hash",null]"#,
            )
            .await,
        )
        .await;
        let stamp = {
            let store = app.store.lock().unwrap();
            assert!(auth_request_persisted_rows(&store) == before);
            account_security::stamp(&store.db, "alice").unwrap()
        };
        let polled = device_document(
            auth_request_http(
                &app,
                Method::GET,
                &auth_response_poll_path(&id),
                HeaderMap::new(),
                b"",
                Some("8"),
            )
            .await,
        )
        .await;
        assert!(polled["requestApproved"] == true && polled["id"] == id);
        let tokens = device_document(auth_login_http(&app, &auth_login_form(&id)).await).await;
        assert!(device_claims(&tokens)["sstamp"] == stamp);
        let used: i64 = app
            .store
            .lock()
            .unwrap()
            .db
            .query_row(
                "SELECT authentication_date IS NOT NULL FROM auth_requests WHERE id=?1",
                [&id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(used, 1);
        assert!(
            auth_request_http(
                &app,
                Method::GET,
                &auth_response_poll_path(&id),
                HeaderMap::new(),
                b"",
                Some("8")
            )
            .await
            .is_ok()
        );
    }

    #[tokio::test]
    async fn account_security_http_storage_failure_keeps_authenticated_session_and_allows_retry() {
        let app = auth_request_fixture_app();
        app.store.lock().unwrap().db.execute_batch("CREATE TRIGGER fail_http_security AFTER DELETE ON device_registry BEGIN SELECT RAISE(FAIL,'fixture'); END;").unwrap();
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        let Err(error) = device_request(
            &app,
            Method::POST,
            "/api/accounts/security-stamp",
            device_authorization(Some("device-fixture-alice")),
            br#"{"masterPasswordHash":"fixture-master-hash"}"#,
        )
        .await
        else {
            panic!("Injected reset failure succeeded.")
        };
        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(device_push_persisted_state(&app.store.lock().unwrap()) == before);
        assert!(
            device_request(
                &app,
                Method::GET,
                "/api/accounts/profile",
                device_authorization(Some("device-fixture-alice")),
                b""
            )
            .await
            .is_ok()
        );
        app.store
            .lock()
            .unwrap()
            .db
            .execute_batch("DROP TRIGGER fail_http_security")
            .unwrap();
        device_push_empty(
            device_request(
                &app,
                Method::POST,
                "/api/accounts/security-stamp",
                device_authorization(Some("device-fixture-alice")),
                br#"{"masterPasswordHash":"fixture-master-hash"}"#,
            )
            .await,
        )
        .await;
    }

    fn auth_login_fixture() -> (App, String) {
        let app = auth_request_fixture_app();
        let id = {
            let mut store = app.store.lock().unwrap();
            let context = AuthRequestContext {
                device_type: 8,
                request_ip: "203.0.113.73",
                origin: "https://origin.example.test",
            };
            let request = AuthRequestCreateRequest {
                access_code: "NUL\0private-auth-access-sentinel",
                device_identifier: "Request-Device",
                email: "alice@example.test",
                public_key: "opaque-public",
            };
            let id = serde_json::to_value(
                VaultService::new(&mut *store)
                    .create_auth_request(&request, &context)
                    .unwrap(),
            )
            .unwrap()["id"]
                .as_str()
                .unwrap()
                .to_owned();
            let response = AuthRequestUpdateRequest {
                device_identifier: "Request-Device",
                key: "opaque-response-key",
                master_password_hash: Some("not-the-access-code"),
                request_approved: true,
            };
            VaultService::new(&mut *store)
                .respond_auth_request(
                    "alice",
                    &id,
                    "Request-Device",
                    &response,
                    "https://origin.example.test",
                )
                .unwrap();
            id
        };
        (app, id)
    }
    fn auth_login_form(id: &str) -> BTreeMap<String, String> {
        [
            ("GRANTTYPE", "password"),
            ("PASSWORD", "NUL\0private-auth-access-sentinel"),
            ("AuThReQuEsT", id),
            ("CLIENTID", "opaque-client 雪"),
            ("SCOPE", "api offline_access"),
            ("USERNAME", " ALICE@EXAMPLE.TEST "),
            ("DeviceIdentifier", "Different-Login"),
            ("device_name", "New login"),
            ("DEVICETYPE", "-7"),
        ]
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value.to_owned()))
        .collect()
    }
    async fn auth_login_http(
        app: &App,
        form: &BTreeMap<String, String>,
    ) -> Result<Response, Failure> {
        let body = serde_urlencoded::to_string(form).unwrap();
        auth_request_http(
            app,
            Method::POST,
            "/identity/connect/token",
            HeaderMap::new(),
            body.as_bytes(),
            Some("2147483647"),
        )
        .await
    }
    #[tokio::test]
    async fn auth_login_issues_password_authority_for_new_device_and_poll_remains_readable() {
        let (app, id) = auth_login_fixture();
        let account = app
            .store
            .lock()
            .unwrap()
            .account("id", "alice")
            .unwrap()
            .unwrap();
        let before_poll = device_document(
            auth_request_http(
                &app,
                Method::GET,
                &auth_response_poll_path(&id),
                HeaderMap::new(),
                b"",
                Some("8"),
            )
            .await,
        )
        .await;
        let tokens = device_document(auth_login_http(&app, &auth_login_form(&id)).await).await;
        let claims = device_claims(&tokens);
        assert!(
            tokens["expires_in"] == 7200
                && tokens["scope"] == "api offline_access"
                && tokens["refresh_token"].is_string()
        );
        assert!(
            claims["sub"] == "alice"
                && claims["device"] == "Different-Login"
                && claims["client_id"] == "opaque-client 雪"
                && claims["devicetype"] == "Unknown Browser"
                && claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap() == 7200
        );
        let after_poll = device_document(
            auth_request_http(
                &app,
                Method::GET,
                &auth_response_poll_path(&id),
                HeaderMap::new(),
                b"",
                Some("8"),
            )
            .await,
        )
        .await;
        assert!(before_poll == after_poll && after_poll["requestApproved"] == true);
        {
            let store = app.store.lock().unwrap();
            assert!(store.account("id", "alice").unwrap().unwrap() == account);
            let registered = devices::load(&store.db, "alice", "Different-Login")
                .unwrap()
                .unwrap();
            assert!(registered.device_type == -7 && registered.name == "New login");
            assert!(
                devices::access_binding(
                    &store.db,
                    &digest(tokens["access_token"].as_str().unwrap()),
                    "alice"
                )
                .unwrap()
                .as_deref()
                    == Some("Different-Login")
            );
        }
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        let rows = auth_request_persisted_rows(&app.store.lock().unwrap());
        let Err(error) = auth_login_http(&app, &auth_login_form(&id)).await else {
            panic!("Consumed request replayed.")
        };
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(
            device_push_persisted_state(&app.store.lock().unwrap()) == before
                && auth_request_persisted_rows(&app.store.lock().unwrap()) == rows
        );
        let refresh = serde_urlencoded::to_string([
            ("grant_type", "refresh_token"),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("CLIENTID", "replacement-client"),
        ])
        .unwrap();
        let refreshed = device_document(
            auth_request_http(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                refresh.as_bytes(),
                None,
            )
            .await,
        )
        .await;
        assert!(
            refreshed["expires_in"] == 7200
                && device_claims(&refreshed)["client_id"] == "replacement-client"
                && device_claims(&refreshed)["device"] == "Different-Login"
        );
        let refresh = serde_urlencoded::to_string([
            ("grant_type", "refresh_token"),
            (
                "refresh_token",
                refreshed["refresh_token"].as_str().unwrap(),
            ),
        ])
        .unwrap();
        let refreshed = device_document(
            auth_request_http(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                refresh.as_bytes(),
                None,
            )
            .await,
        )
        .await;
        assert!(
            device_claims(&refreshed)["client_id"] == "undefined"
                && refreshed["expires_in"] == 7200
        );
    }

    #[tokio::test]
    async fn auth_login_required_fields_proof_selection_and_private_disabled_policy_are_atomic() {
        let (app, id) = auth_login_fixture();
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        let rows = auth_request_persisted_rows(&app.store.lock().unwrap());
        let mut missing_grant = auth_login_form(&id);
        missing_grant.remove("GRANTTYPE");
        let Err(error) = auth_login_http(&app, &missing_grant).await else {
            panic!("Missing required form field accepted.")
        };
        assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        for missing in [
            "PASSWORD",
            "CLIENTID",
            "SCOPE",
            "USERNAME",
            "DeviceIdentifier",
            "device_name",
            "DEVICETYPE",
        ] {
            let mut form = auth_login_form(&id);
            form.remove(missing);
            let Err(error) = auth_login_http(&app, &form).await else {
                panic!("Missing grant field accepted.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }
        for (key, value) in [
            ("AuThReQuEsT", ""),
            ("AuThReQuEsT", "not-a-UUID"),
            ("PASSWORD", "not-the-access-code"),
            ("USERNAME", "bob@example.test"),
            ("SCOPE", "offline_access api"),
        ] {
            let mut form = auth_login_form(&id);
            form.insert(key.into(), value.into());
            let Err(error) = auth_login_http(&app, &form).await else {
                panic!("Invalid auth grant accepted.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }
        let mut form = auth_login_form("");
        form.insert("PASSWORD".into(), "fixture-master-hash".into());
        assert!(
            auth_login_http(&app, &form).await.is_err(),
            "Empty authRequest fell back to password verification."
        );
        let body = serde_urlencoded::to_string(auth_login_form(&id)).unwrap();
        let Err(error) = dispatch_with_peer(
            app.clone(),
            Method::POST,
            "/identity/connect/token".parse().unwrap(),
            HeaderMap::new(),
            Bytes::from(body),
            "203.0.113.74".parse().unwrap(),
        )
        .await
        else {
            panic!("Wrong peer accepted.")
        };
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(
            device_push_persisted_state(&app.store.lock().unwrap()) == before
                && auth_request_persisted_rows(&app.store.lock().unwrap()) == rows
        );
        app.store
            .lock()
            .unwrap()
            .db
            .execute(
                "INSERT INTO account_auth_policy(owner,enabled) VALUES('alice',0)",
                [],
            )
            .unwrap();
        assert!(auth_login_http(&app, &auth_login_form(&id)).await.is_err());
        assert!(
            device_push_persisted_state(&app.store.lock().unwrap()) == before
                && auth_request_persisted_rows(&app.store.lock().unwrap()) == rows
        );
    }

    #[tokio::test]
    async fn auth_login_late_failures_roll_back_consumption_activity_sessions_and_bindings() {
        for phase in 0..6 {
            let (app, id) = auth_login_fixture();
            {
                let store = app.store.lock().unwrap();
                let sql = match phase {
                    0 => {
                        "CREATE TRIGGER reject_auth_login BEFORE UPDATE OF authentication_date ON auth_requests BEGIN SELECT RAISE(ABORT,'fixture'); END;"
                    }
                    1 => {
                        "CREATE TRIGGER reject_auth_login BEFORE INSERT ON device_registry BEGIN SELECT RAISE(ABORT,'fixture'); END;"
                    }
                    2 => {
                        "CREATE TRIGGER reject_auth_login BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT,'fixture'); END;"
                    }
                    3 => {
                        "CREATE TRIGGER reject_auth_login BEFORE INSERT ON session_devices BEGIN SELECT RAISE(ABORT,'fixture'); END;"
                    }
                    4 => {
                        "CREATE TABLE failed_auth_login_commit(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_auth_login AFTER INSERT ON sessions BEGIN INSERT INTO failed_auth_login_commit(owner) VALUES('missing'); END;"
                    }
                    _ => {
                        "CREATE TRIGGER reject_auth_login BEFORE UPDATE OF updated ON device_registry BEGIN SELECT RAISE(ABORT,'fixture'); END;"
                    }
                };
                store.db.execute_batch(sql).unwrap();
            }
            let before = device_push_persisted_state(&app.store.lock().unwrap());
            let rows = auth_request_persisted_rows(&app.store.lock().unwrap());
            let mut form = auth_login_form(&id);
            if phase == 5 {
                form.insert("DeviceIdentifier".into(), "Request-Device".into());
            }
            assert!(auth_login_http(&app, &form).await.is_err());
            assert!(
                device_push_persisted_state(&app.store.lock().unwrap()) == before
                    && auth_request_persisted_rows(&app.store.lock().unwrap()) == rows,
                "Failed issuance escaped the rollback boundary."
            );
            app.store
                .lock()
                .unwrap()
                .db
                .execute_batch("DROP TRIGGER reject_auth_login")
                .unwrap();
            assert!(
                auth_login_http(&app, &form).await.is_ok(),
                "Failed issuance consumed the proof."
            );
        }
    }

    #[tokio::test]
    async fn auth_login_opaque_form_id_and_blank_proof_metadata_work_without_uuid_or_type_guard() {
        let (app, id) = auth_login_fixture();
        let opaque = "opaque\0request 雪";
        app.store
            .lock()
            .unwrap()
            .db
            .execute(
                "UPDATE auth_requests SET id=?1,access_code='' WHERE id=?2",
                params![opaque, id],
            )
            .unwrap();
        let mut form = auth_login_form(opaque);
        for key in [
            "PASSWORD",
            "CLIENTID",
            "DeviceIdentifier",
            "device_name",
            "DEVICETYPE",
        ] {
            form.insert(key.into(), String::new());
        }
        let tokens = device_document(auth_login_http(&app, &form).await).await;
        assert!(
            device_claims(&tokens)["device"] == "" && device_claims(&tokens)["client_id"] == ""
        );
        let store = app.store.lock().unwrap();
        let device = devices::load(&store.db, "alice", "").unwrap().unwrap();
        assert!(device.device_type == 14 && device.name.is_empty());
    }

    #[tokio::test]
    async fn auth_login_existing_device_claim_uses_retained_type_and_name() {
        let (app, id) = auth_login_fixture();
        let mut form = auth_login_form(&id);
        form.insert("DeviceIdentifier".into(), "Request-Device".into());
        form.insert("device_name".into(), "Replacement".into());
        let tokens = device_document(auth_login_http(&app, &form).await).await;
        assert!(device_claims(&tokens)["devicetype"] == "Linux");
        {
            let store = app.store.lock().unwrap();
            let device = devices::load(&store.db, "alice", "Request-Device")
                .unwrap()
                .unwrap();
            assert!(device.device_type == 8 && device.name == "Original");
        }
        let refresh = serde_urlencoded::to_string([
            ("grant_type", "refresh_token"),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("deviceType", "14"),
        ])
        .unwrap();
        let tokens = device_document(
            auth_request_http(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                refresh.as_bytes(),
                None,
            )
            .await,
        )
        .await;
        assert!(device_claims(&tokens)["devicetype"] == "Linux");
    }

    #[tokio::test]
    async fn auth_login_replay_race_issues_exactly_one_bound_session() {
        let (app, id) = auth_login_fixture();
        let count: i64 = app
            .store
            .lock()
            .unwrap()
            .db
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
            .unwrap();
        let form = auth_login_form(&id);
        let (one, two) = tokio::join!(auth_login_http(&app, &form), auth_login_http(&app, &form));
        assert!(one.is_ok() != two.is_ok());
        let store = app.store.lock().unwrap();
        let after: i64 = store
            .db
            .query_row("SELECT COUNT(*) FROM sessions", [], |row| row.get(0))
            .unwrap();
        assert_eq!(after, count + 1);
    }

    #[tokio::test]
    async fn auth_login_nested_selector_never_falls_back_to_a_valid_ordinary_password() {
        let app = device_fixture_app();
        let mut form =
            parse_connect_form(&device_login_body("alice", "Nested-Login", "Original", "8"))
                .unwrap_or_else(|_| panic!("Fixture form failed."));
        form.insert("client_id".into(), "ordinary-client".into());
        form.insert("scope".into(), "api offline_access".into());
        // These credentials are valid on the ordinary password branch.
        assert!(auth_login_http(&app, &form).await.is_ok());
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        for field in [
            "authRequest.x",
            "[authRequest]",
            ".authRequest",
            "authRequest[root]",
            "[AUTHREQUEST]suffix",
            "[authRequest",
        ] {
            let mut nested = form.clone();
            nested.insert(field.into(), "missing-auth-request".into());
            let Err(error) = auth_login_http(&app, &nested).await else {
                panic!("Nested authRequest fell back to ordinary password verification.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
            assert!(device_push_persisted_state(&app.store.lock().unwrap()) == before);
        }
        for field in [
            "auth_request.x",
            "code[root]",
            "..authRequest",
            "[authRequest.x]",
        ] {
            let mut unrelated = form.clone();
            unrelated.insert(field.into(), "ignored".into());
            assert!(
                auth_login_http(&app, &unrelated).await.is_ok(),
                "Unrelated form root selected authRequest proof."
            );
        }
        let (app, id) = auth_login_fixture();
        let mut form = auth_login_form(&id);
        form.insert("[AUTHREQUEST]suffix".into(), id.clone());
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        let rows = auth_request_persisted_rows(&app.store.lock().unwrap());
        assert!(
            auth_login_http(&app, &form).await.is_err(),
            "Ambiguous selector roots accepted."
        );
        assert!(
            device_push_persisted_state(&app.store.lock().unwrap()) == before
                && auth_request_persisted_rows(&app.store.lock().unwrap()) == rows
        );
        form.remove("AuThReQuEsT");
        assert!(
            auth_login_http(&app, &form).await.is_ok(),
            "Nested selector was not used for proof lookup."
        );
    }

    #[tokio::test]
    async fn auth_login_underscore_field_is_ignored_and_ordinary_password_authority_matches_source()
    {
        let app = device_fixture_app();
        let mut form = parse_connect_form(&device_login_body(
            "alice",
            "Ordinary-Login",
            "Original",
            "8",
        ))
        .unwrap_or_else(|_| panic!("Fixture form failed."));
        form.insert("client_id".into(), "ordinary-client".into());
        form.insert("auth_request".into(), "not-an-auth-request-field".into());
        let body = serde_urlencoded::to_string(form).unwrap();
        let tokens = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                body.as_bytes(),
            )
            .await,
        )
        .await;
        assert!(
            tokens["expires_in"] == 7200
                && device_claims(&tokens)["client_id"] == "ordinary-client"
        );
    }

    fn auth_response_poll_path(id: &str) -> String {
        format!(
            "/api/auth-requests/{id}/response?{}",
            serde_urlencoded::to_string([("code", "NUL\0private-auth-access-sentinel")]).unwrap()
        )
    }
    #[tokio::test]
    async fn auth_response_http_pending_approval_repeated_poll_and_rejection_snapshots() {
        let app = auth_request_fixture_app();
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        let created = device_document(
            auth_request_http(
                &app,
                Method::POST,
                "/api/auth-requests",
                HeaderMap::new(),
                &auth_request_body("alice@example.test", "Request-Device"),
                Some("8"),
            )
            .await,
        )
        .await;
        let id = created["id"].as_str().unwrap();
        let poll = auth_response_poll_path(id);
        let update = format!("/api/auth-requests/{id}");
        let pending = device_document(
            auth_request_http(
                &app,
                Method::GET,
                &poll,
                device_authorization(Some("invalid")),
                b"",
                Some("8"),
            )
            .await,
        )
        .await;
        assert!(pending["requestApproved"].is_null() && pending["key"].is_null());
        let approved=device_document(auth_request_http(&app,Method::PUT,&update,device_authorization(Some("device-fixture-alice")),br#"{"deviceIdentifier":"Request-Device","key":"NUL\u0000opaque-key","masterPasswordHash":"","requestApproved":true,"owner":"bob","responseDate":"1900-01-01T00:00:00Z"}"#,None).await).await;
        assert_eq!(approved.as_object().unwrap().len(), 11);
        assert!(
            approved["requestApproved"] == true
                && approved["key"] == "NUL\0opaque-key"
                && approved["masterPasswordHash"] == ""
                && approved["responseDate"] != "1900-01-01T00:00:00Z"
        );
        let rows = auth_request_persisted_rows(&app.store.lock().unwrap());
        let changes = app.store.lock().unwrap().db.total_changes();
        for _ in 0..2 {
            let read = device_document(
                auth_request_http(&app, Method::GET, &poll, HeaderMap::new(), b"", Some("8")).await,
            )
            .await;
            assert!(read == approved);
        }
        assert_eq!(app.store.lock().unwrap().db.total_changes(), changes);
        let Err(error) = auth_request_http(
            &app,
            Method::PUT,
            &update,
            device_authorization(Some("device-fixture-alice")),
            br#"["Request-Device","replacement",null,false]"#,
            None,
        )
        .await
        else {
            panic!("Already-approved auth request changed.")
        };
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(auth_request_persisted_rows(&app.store.lock().unwrap()) == rows);
        let pending = device_document(
            auth_request_http(
                &app,
                Method::GET,
                "/api/auth-requests/pending",
                device_authorization(Some("device-fixture-alice")),
                b"",
                None,
            )
            .await,
        )
        .await;
        assert!(pending["data"].as_array().unwrap().is_empty());
        let another = device_document(
            auth_request_http(
                &app,
                Method::POST,
                "/api/auth-requests",
                HeaderMap::new(),
                &auth_request_body("alice@example.test", "Request-Device"),
                Some("8"),
            )
            .await,
        )
        .await;
        let rejected_id = another["id"].as_str().unwrap();
        let rejected = device_document(
            auth_request_http(
                &app,
                Method::PUT,
                &format!("/api/auth-requests/{rejected_id}"),
                device_authorization(Some("device-fixture-alice")),
                br#"["Request-Device","ignored","ignored-hash",false]"#,
                None,
            )
            .await,
        )
        .await;
        assert!(
            rejected["requestApproved"].is_null()
                && rejected["key"].is_null()
                && rejected["masterPasswordHash"].is_null()
                && rejected["responseDate"].is_string()
        );
        let Err(error) = auth_request_http(
            &app,
            Method::GET,
            &auth_response_poll_path(rejected_id),
            HeaderMap::new(),
            b"",
            Some("8"),
        )
        .await
        else {
            panic!("Rejected auth request remained readable.")
        };
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(device_push_persisted_state(&app.store.lock().unwrap()) == before);
    }
    #[tokio::test]
    async fn auth_response_http_guard_precedence_wrong_proofs_and_failures_are_nonmutating() {
        let app = auth_request_fixture_app();
        let created = device_document(
            auth_request_http(
                &app,
                Method::POST,
                "/api/auth-requests",
                HeaderMap::new(),
                &auth_request_body("alice@example.test", "Request-Device"),
                Some("8"),
            )
            .await,
        )
        .await;
        let id = created["id"].as_str().unwrap();
        let update = format!("/api/auth-requests/{id}");
        let poll = auth_response_poll_path(id);
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        let rows = auth_request_persisted_rows(&app.store.lock().unwrap());
        for bearer in [None, Some("invalid"), Some("legacy-auth-access")] {
            let Err(error) = auth_request_http(
                &app,
                Method::PUT,
                "/api/auth-requests/not-a-uuid",
                device_authorization(bearer),
                b"{",
                None,
            )
            .await
            else {
                panic!("Unauthenticated decision succeeded.")
            };
            assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        }
        for (path, body, status) in [
            (
                "/api/auth-requests/not-a-uuid",
                b"{".as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (update.as_str(), b"{", StatusCode::BAD_REQUEST),
            (update.as_str(), b"{}", StatusCode::UNPROCESSABLE_ENTITY),
            (
                update.as_str(),
                br#"["Request-Device","k",null,true,null]"#,
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let Err(error) = auth_request_http(
                &app,
                Method::PUT,
                path,
                device_authorization(Some("device-fixture-alice")),
                body,
                None,
            )
            .await
            else {
                panic!("Invalid decision guard accepted.")
            };
            assert_eq!(error.0, status);
        }
        for bearer in ["device-fixture-alice", "device-fixture-bob"] {
            let Err(error) = auth_request_http(
                &app,
                Method::PUT,
                &update,
                device_authorization(Some(bearer)),
                br#"{"deviceIdentifier":"Different-Device","key":"k","requestApproved":true}"#,
                None,
            )
            .await
            else {
                panic!("Wrong response device or owner accepted.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }
        for path in [
            format!("/api/auth-requests/{id}/response"),
            format!("/api/auth-requests/{id}/response?Code=ignored"),
        ] {
            let Err(error) =
                auth_request_http(&app, Method::GET, &path, HeaderMap::new(), b"", Some("8")).await
            else {
                panic!("Missing code guard accepted.")
            };
            assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
        }
        for (path, kind) in [
            (
                format!("/api/auth-requests/{id}/response?code=wrong"),
                Some("8"),
            ),
            (poll.clone(), Some("14")),
            (
                "/api/auth-requests/10000000-0000-4000-8000-0000000000ab/response?code=wrong"
                    .to_owned(),
                Some("8"),
            ),
        ] {
            let Err(error) =
                auth_request_http(&app, Method::GET, &path, HeaderMap::new(), b"", kind).await
            else {
                panic!("Wrong polling proof accepted.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
            assert_eq!(error.1, "AuthRequest doesn't exist");
        }
        let mut headers = HeaderMap::new();
        headers.insert("device-type", "8".parse().unwrap());
        let Err(error) = dispatch_with_peer(
            app.clone(),
            Method::GET,
            poll.parse().unwrap(),
            headers,
            Bytes::new(),
            "203.0.113.74".parse().unwrap(),
        )
        .await
        else {
            panic!("Wrong IP polling succeeded.")
        };
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert_eq!(error.1, "AuthRequest doesn't exist");
        {
            let store = app.store.lock().unwrap();
            assert!(
                device_push_persisted_state(&store) == before
                    && auth_request_persisted_rows(&store) == rows
            );
            store.db.execute_batch("CREATE TRIGGER reject_http_auth_response AFTER UPDATE ON auth_requests BEGIN SELECT RAISE(ABORT,'injected auth response failure'); END;").unwrap();
        }
        let Err(error) = auth_request_http(
            &app,
            Method::PUT,
            &update,
            device_authorization(Some("device-fixture-alice")),
            br#"["Request-Device","k",null,true]"#,
            None,
        )
        .await
        else {
            panic!("Injected decision failure succeeded.")
        };
        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        {
            let store = app.store.lock().unwrap();
            assert!(
                device_push_persisted_state(&store) == before
                    && auth_request_persisted_rows(&store) == rows
            );
        }
    }
    #[tokio::test]
    async fn auth_response_http_code_query_preserves_empty_plus_and_first_match_semantics() {
        let app = auth_request_fixture_app();
        for code in ["", "a+b NUL\0雪"] {
            let body=json!({"accessCode":code,"deviceIdentifier":"Request-Device","email":"alice@example.test","publicKey":""}).to_string();
            let created = device_document(
                auth_request_http(
                    &app,
                    Method::POST,
                    "/api/auth-requests",
                    HeaderMap::new(),
                    body.as_bytes(),
                    Some("8"),
                )
                .await,
            )
            .await;
            let id = created["id"].as_str().unwrap();
            let query = serde_urlencoded::to_string([("code", code)]).unwrap();
            for query in [
                query.clone(),
                format!("{query}&code=wrong"),
                query.replacen("code=", "[code]=", 1),
                query.replacen("code=", "code.nested=", 1),
            ] {
                let value = device_document(
                    auth_request_http(
                        &app,
                        Method::GET,
                        &format!("/api/auth-requests/{id}/response?{query}"),
                        device_authorization(Some("invalid")),
                        b"",
                        Some("8"),
                    )
                    .await,
                )
                .await;
                assert!(value["id"] == id && value["requestApproved"].is_null());
            }
            let Err(error) = auth_request_http(
                &app,
                Method::GET,
                &format!("/api/auth-requests/{id}/response?code=wrong&{query}"),
                HeaderMap::new(),
                b"",
                Some("8"),
            )
            .await
            else {
                panic!("Later code value replaced the first.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
            if code.contains('+') {
                let raw = query.replace("%2B", "+");
                let Err(error) = auth_request_http(
                    &app,
                    Method::GET,
                    &format!("/api/auth-requests/{id}/response?{raw}"),
                    HeaderMap::new(),
                    b"",
                    Some("8"),
                )
                .await
                else {
                    panic!("Literal plus was not decoded as space.")
                };
                assert_eq!(error.0, StatusCode::BAD_REQUEST);
            }
        }
    }

    fn auth_request_fixture_app() -> App {
        let mut app = device_fixture_app();
        app.base = "https://ORIGIN.example.test:443/configured/path".into();
        {
            let mut store = app.store.lock().unwrap();
            for (owner, id, kind) in [
                ("alice", "Request-Device", 8),
                ("bob", "Request-Device", 8),
                ("alice", "Fallback-Device", 14),
            ] {
                VaultService::new(&mut *store)
                    .register_device(
                        owner,
                        &DeviceRegistration {
                            identifier: id,
                            name: "Original",
                            device_type: kind,
                        },
                    )
                    .unwrap();
            }
            for owner in ["alice", "bob"] {
                devices::bind(
                    &store.db,
                    owner,
                    "Request-Device",
                    &format!("device-fixture-{owner}"),
                )
                .unwrap();
            }
            store.db.execute("INSERT INTO sessions(access,refresh,owner,access_expires,refresh_expires) VALUES(?1,'legacy-auth-refresh','alice',4000000000,4000000000)",[digest("legacy-auth-access")]).unwrap();
        }
        app
    }
    fn auth_request_body(email: &str, id: &str) -> Vec<u8> {
        json!({"accessCode":"NUL\0private-auth-access-sentinel","deviceIdentifier":id,"email":email,"publicKey":"opaque-public\0café 雪","owner":"bob","userId":"bob","requestApproved":true,"key":"untrusted","creationDate":"1900-01-01T00:00:00Z","requestIpAddress":"198.51.100.2"}).to_string().into_bytes()
    }
    async fn auth_request_http(
        app: &App,
        method: Method,
        path: &str,
        mut headers: HeaderMap,
        body: &[u8],
        kind: Option<&str>,
    ) -> Result<Response, Failure> {
        if let Some(kind) = kind {
            headers.insert("device-type", kind.parse().unwrap());
        }
        dispatch_with_peer(
            app.clone(),
            method,
            path.parse().unwrap(),
            headers,
            Bytes::copy_from_slice(body),
            "203.0.113.73".parse().unwrap(),
        )
        .await
    }
    fn auth_request_persisted_rows(store: &Store) -> Vec<String> {
        store.db.prepare("SELECT id||':'||owner||':'||request_device_identifier||':'||device_type||':'||request_ip||':'||access_code||':'||public_key||':'||COALESCE(encrypted_key,'null')||':'||COALESCE(master_password_hash,'null')||':'||COALESCE(approved,'null')||':'||creation_date||':'||COALESCE(response_date,'null') FROM auth_requests ORDER BY id").unwrap().query_map([],|row|row.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }
    #[tokio::test]
    async fn auth_request_http_create_read_list_and_pending_device_projection_preserve_boundaries()
    {
        let app = auth_request_fixture_app();
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        let created = device_document(
            auth_request_http(
                &app,
                Method::POST,
                "/api/auth-requests",
                device_authorization(Some("invalid")),
                &auth_request_body("ALICE@EXAMPLE.TEST", "Request-Device"),
                Some("8"),
            )
            .await,
        )
        .await;
        assert_eq!(created.as_object().unwrap().len(), 11);
        assert!(
            created["requestApproved"] == false
                && created["requestIpAddress"] == "203.0.113.73"
                && created["origin"] == "https://origin.example.test"
                && created["requestDeviceType"] == "Linux"
        );
        assert!(
            created["publicKey"] == "opaque-public\0café 雪"
                && created["key"].is_null()
                && created["masterPasswordHash"].is_null()
                && !created.to_string().contains("private-auth-access-sentinel")
        );
        let id = created["id"].as_str().unwrap();
        let mut expected = created.clone();
        expected["requestApproved"] = Value::Null;
        let read = device_document(
            auth_request_http(
                &app,
                Method::GET,
                &format!("/api/auth-requests/{id}"),
                device_authorization(Some("device-fixture-alice")),
                b"",
                None,
            )
            .await,
        )
        .await;
        assert!(read == expected);
        let encoded = format!("/api/auth-requests/%{:02X}{}", id.as_bytes()[0], &id[1..]);
        let encoded_read = device_document(
            auth_request_http(
                &app,
                Method::GET,
                &encoded,
                device_authorization(Some("device-fixture-alice")),
                b"",
                None,
            )
            .await,
        )
        .await;
        assert!(encoded_read == expected);
        device_document(
            auth_request_http(
                &app,
                Method::POST,
                "/api/auth-requests",
                HeaderMap::new(),
                &auth_request_body("bob@example.test", "Request-Device"),
                Some("8"),
            )
            .await,
        )
        .await;
        for path in ["/api/auth-requests", "/api/auth-requests/pending"] {
            let list = device_document(
                auth_request_http(
                    &app,
                    Method::GET,
                    path,
                    device_authorization(Some("device-fixture-alice")),
                    b"",
                    None,
                )
                .await,
            )
            .await;
            assert!(list == json!({"object":"list","data":[expected],"continuationToken":null}));
        }
        let devices = device_document(
            device_request(
                &app,
                Method::GET,
                "/api/devices",
                device_authorization(Some("device-fixture-alice")),
                b"",
            )
            .await,
        )
        .await;
        let pending = devices["data"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == "Request-Device")
            .unwrap();
        assert_eq!(pending.as_object().unwrap().len(), 10);
        assert!(
            pending["devicePendingAuthRequest"]
                == json!({"id":id,"creationDate":created["creationDate"]})
        );
        let single = device_document(
            device_request(
                &app,
                Method::GET,
                "/api/devices/identifier/Request-Device",
                device_authorization(Some("device-fixture-alice")),
                b"",
            )
            .await,
        )
        .await;
        assert_eq!(single.as_object().unwrap().len(), 7);
        assert!(
            device_push_persisted_state(&app.store.lock().unwrap()) == before,
            "Auth-request discovery changed unrelated persisted state."
        );
    }
    #[tokio::test]
    async fn auth_request_http_rejections_guard_order_and_legacy_policy_preserve_state() {
        let app = auth_request_fixture_app();
        let created = device_document(
            auth_request_http(
                &app,
                Method::POST,
                "/api/auth-requests",
                HeaderMap::new(),
                &auth_request_body("alice@example.test", "Request-Device"),
                Some("8"),
            )
            .await,
        )
        .await;
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        let requests = auth_request_persisted_rows(&app.store.lock().unwrap());
        for bearer in [None, Some("invalid"), Some("legacy-auth-access")] {
            for path in [
                "/api/auth-requests",
                "/api/auth-requests/pending",
                "/api/auth-requests/not-a-uuid",
            ] {
                let Err(error) = auth_request_http(
                    &app,
                    Method::GET,
                    path,
                    device_authorization(bearer),
                    b"",
                    None,
                )
                .await
                else {
                    panic!("Unauthenticated auth-request read succeeded.")
                };
                assert_eq!(error.0, StatusCode::UNAUTHORIZED);
            }
        }
        for (bearer, path, status) in [
            (
                "device-fixture-bob",
                format!("/api/auth-requests/{}", created["id"].as_str().unwrap()),
                StatusCode::BAD_REQUEST,
            ),
            (
                "device-fixture-alice",
                "/api/auth-requests/not-a-uuid".into(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "device-fixture-alice",
                "/api/auth-requests/%FF".into(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "device-fixture-alice",
                "/api/auth-requests/%7B10000000-0000-4000-8000-0000000000ab%7D".into(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "device-fixture-alice",
                "/api/auth-requests/urn%3Auuid%3A10000000-0000-4000-8000-0000000000ab".into(),
                StatusCode::BAD_REQUEST,
            ),
        ] {
            let Err(error) = auth_request_http(
                &app,
                Method::GET,
                &path,
                device_authorization(Some(bearer)),
                b"",
                None,
            )
            .await
            else {
                panic!("Invalid or foreign auth-request read succeeded.")
            };
            assert_eq!(error.0, status);
        }
        for (body,kind,status) in [(b"{".as_slice(),None,StatusCode::BAD_REQUEST),(b"{}",None,StatusCode::UNPROCESSABLE_ENTITY),(br#"["a","b","c","d",null]"#,None,StatusCode::BAD_REQUEST),(br#"{"accessCode":"a","deviceIdentifier":"d","email":"e","publicKey":"p","accessCode":"duplicate"}"#,None,StatusCode::UNPROCESSABLE_ENTITY)] {
            let Err(error)=auth_request_http(&app,Method::POST,"/api/auth-requests",HeaderMap::new(),body,kind).await else{panic!("Invalid auth-request JSON accepted.")};assert_eq!(error.0,status);
        }
        for (email, id, kind) in [
            (" alice@example.test", "Request-Device", Some("8")),
            ("alice@example.test ", "Request-Device", Some("8")),
            ("alice@example.test", "request-device", Some("8")),
            ("alice@example.test", "Request-Device", None),
            ("alice@example.test", "Request-Device", Some("iOS")),
            ("bob@example.test", "Fallback-Device", Some("14")),
        ] {
            let Err(error) = auth_request_http(
                &app,
                Method::POST,
                "/api/auth-requests",
                HeaderMap::new(),
                &auth_request_body(email, id),
                kind,
            )
            .await
            else {
                panic!("Invalid auth-request device verification succeeded.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
        }
        let legacy = device_document(
            device_request(
                &app,
                Method::GET,
                "/api/devices",
                device_authorization(Some("legacy-auth-access")),
                b"",
            )
            .await,
        )
        .await;
        assert_eq!(legacy["data"].as_array().unwrap().len(), 2);
        {
            let store = app.store.lock().unwrap();
            assert!(
                device_push_persisted_state(&store) == before
                    && auth_request_persisted_rows(&store) == requests,
                "Rejected auth request changed persisted state."
            );
        }
        let fallback = device_document(
            auth_request_http(
                &app,
                Method::POST,
                "/api/auth-requests",
                HeaderMap::new(),
                &auth_request_body("alice@example.test", "Fallback-Device"),
                Some("iOS"),
            )
            .await,
        )
        .await;
        assert!(fallback["requestDeviceType"] == "Unknown Browser");
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        let requests = auth_request_persisted_rows(&app.store.lock().unwrap());
        app.store.lock().unwrap().db.execute_batch("CREATE TRIGGER reject_http_auth_request AFTER INSERT ON auth_requests BEGIN SELECT RAISE(ABORT,'injected auth request failure'); END;").unwrap();
        let Err(error) = auth_request_http(
            &app,
            Method::POST,
            "/api/auth-requests",
            HeaderMap::new(),
            &auth_request_body("alice@example.test", "Request-Device"),
            Some("8"),
        )
        .await
        else {
            panic!("Injected auth-request write failure succeeded.")
        };
        assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
        {
            let store = app.store.lock().unwrap();
            assert!(
                device_push_persisted_state(&store) == before
                    && auth_request_persisted_rows(&store) == requests
            );
        }
    }
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn auth_request_http_records_actual_socket_peer_without_trusting_forwarded_headers() {
        use std::io::{Read, Write};
        let app = auth_request_fixture_app();
        let router = Router::new().fallback(dispatch_http).with_state(app);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(
                listener,
                router.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .unwrap();
        });
        let socket = tokio::net::TcpSocket::new_v4().unwrap();
        socket.bind("127.0.0.2:0".parse().unwrap()).unwrap();
        let stream = socket.connect(address).await.unwrap().into_std().unwrap();
        let response = tokio::task::spawn_blocking(move || {
            let mut stream = stream;
            stream.set_nonblocking(false).unwrap();
            stream.set_read_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            stream.set_write_timeout(Some(std::time::Duration::from_secs(5))).unwrap();
            let body = auth_request_body("alice@example.test", "Request-Device");
            let headers = format!(
                "POST /api/auth-requests HTTP/1.1\r\nHost: local.test\r\ndevice-type: 8\r\nContent-Type: application/json\r\nX-Real-IP: 198.51.100.99\r\nX-Forwarded-For: 198.51.100.99\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
                body.len()
            );
            stream.write_all(headers.as_bytes()).unwrap();
            stream.write_all(&body).unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).unwrap();
            response
        }).await.unwrap();
        server.abort();
        let boundary = response
            .windows(4)
            .position(|part| part == b"\r\n\r\n")
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
        let document: Value = serde_json::from_slice(&response[boundary + 4..]).unwrap();
        assert!(
            document["requestIpAddress"] == "127.0.0.2"
                && document["origin"] == "https://origin.example.test"
        );
    }

    fn device_push_fixture_app() -> App {
        let app = device_fixture_app();
        {
            let mut store = app.store.lock().unwrap();
            for (owner, identifier) in [
                ("alice", "Current-Device"),
                ("alice", "Other-Device"),
                ("bob", "Current-Device"),
                ("bob", "Foreign-Device"),
            ] {
                VaultService::new(&mut *store)
                    .register_device(
                        owner,
                        &DeviceRegistration {
                            identifier,
                            name: "Original",
                            device_type: 1,
                        },
                    )
                    .unwrap();
            }
            devices::bind(&store.db, "alice", "Current-Device", "device-fixture-alice").unwrap();
            devices::bind(&store.db, "bob", "Current-Device", "device-fixture-bob").unwrap();
        }
        app
    }
    fn device_push_persisted_state(store: &Store) -> Vec<String> {
        let mut rows = device_persisted_state(store);
        rows.extend(store.db.prepare("SELECT 'push:'||owner||':'||identifier||':'||token FROM device_push_tokens ORDER BY owner,identifier").unwrap().query_map([],|row|row.get::<_,String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap());
        rows
    }
    async fn device_push_empty(result: Result<Response, Failure>) {
        let response = result.unwrap_or_else(|_| panic!("Valid device push request failed."));
        assert_eq!(response.status(), StatusCode::OK);
        assert!(response.headers().get("content-type").is_none());
        assert!(
            axum::body::to_bytes(response.into_body(), 1024)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn device_push_http_uses_session_binding_and_ignores_path_headers_and_extra_fields() {
        let app = device_push_fixture_app();
        let account_before = {
            let store = app.store.lock().unwrap();
            store.account("id", "alice").unwrap().unwrap()
        };
        let original = {
            let store = app.store.lock().unwrap();
            devices::load(&store.db, "alice", "Current-Device")
                .unwrap()
                .unwrap()
        };
        for (method, path, token) in [
            (
                Method::POST,
                "/api/devices/identifier/Other-Device/token",
                "",
            ),
            (
                Method::PUT,
                "/api/devices/identifier/Foreign-Device/token",
                "NUL\0café 雪\r\n",
            ),
            (
                Method::POST,
                "/api/devices/identifier/Missing-Device/token",
                "private-device-push-sentinel",
            ),
        ] {
            let mut headers = device_authorization(Some("device-fixture-alice"));
            headers.insert("x-device-identifier", "Other-Device".parse().unwrap());
            headers.insert(
                "x-request-email",
                URL_SAFE_NO_PAD.encode("bob@example.test").parse().unwrap(),
            );
            let body=json!({"pushToken":token,"identifier":"Foreign-Device","userId":"bob","owner":"bob","device":"Other-Device","creationDate":"1900-01-01T00:00:00Z"}).to_string();
            device_push_empty(device_request(&app, method, path, headers, body.as_bytes()).await)
                .await;
            let store = app.store.lock().unwrap();
            assert!(
                devices::push_token(&store.db, "alice", "Current-Device")
                    .unwrap()
                    .as_deref()
                    == Some(token)
            );
            for (owner, id) in [
                ("alice", "Other-Device"),
                ("bob", "Current-Device"),
                ("bob", "Foreign-Device"),
            ] {
                assert!(devices::push_token(&store.db, owner, id).unwrap().is_none());
            }
            assert!(store.account("id", "alice").unwrap().unwrap() == account_before);
            let current = devices::load(&store.db, "alice", "Current-Device")
                .unwrap()
                .unwrap();
            assert!(
                current.name == original.name
                    && current.device_type == original.device_type
                    && current.created == original.created
            );
        }
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        for method in [Method::POST, Method::PUT] {
            device_push_empty(
                device_request(
                    &app,
                    method,
                    "/api/devices/identifier/%4Dissing-Device/token",
                    device_authorization(Some("device-fixture-alice")),
                    br#"["private-device-push-sentinel"]"#,
                )
                .await,
            )
            .await;
            assert!(
                device_push_persisted_state(&app.store.lock().unwrap()) == before,
                "Repeated push update changed activity or authority."
            );
        }
        for path in ["/api/devices", "/api/devices/identifier/Current-Device"] {
            let value = device_document(
                device_request(
                    &app,
                    Method::GET,
                    path,
                    device_authorization(Some("device-fixture-alice")),
                    b"",
                )
                .await,
            )
            .await;
            assert!(
                !value.to_string().contains("private-device-push-sentinel"),
                "Push token leaked through device projection."
            );
        }
    }

    #[tokio::test]
    async fn device_push_http_guard_order_and_disabled_public_clear_preserve_all_state() {
        let app = device_push_fixture_app();
        {
            let mut store = app.store.lock().unwrap();
            for owner in ["alice", "bob"] {
                VaultService::new(&mut *store)
                    .set_device_push_token(
                        owner,
                        "Current-Device",
                        &DevicePushTokenRequest {
                            push_token: "preserved",
                        },
                    )
                    .unwrap();
            }
            store.db.execute("INSERT INTO sessions(access,refresh,owner,access_expires,refresh_expires) VALUES(?1,'legacy-push-refresh','alice',4000000000,4000000000)",[digest("legacy-push-access")]).unwrap();
        }
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        for method in [Method::POST, Method::PUT] {
            for bearer in [None, Some("invalid"), Some("legacy-push-access")] {
                for path in [
                    "/api/devices/identifier/Missing/token",
                    "/api/devices/identifier/%5Fbad/token",
                ] {
                    let Err(error) = device_request(
                        &app,
                        method.clone(),
                        path,
                        device_authorization(bearer),
                        b"{",
                    )
                    .await
                    else {
                        panic!("Unverified session device accepted for push update.")
                    };
                    assert_eq!(error.0, StatusCode::UNAUTHORIZED);
                }
            }
            for (path, body, status) in [
                (
                    "/api/devices/identifier/%5Fbad/token",
                    b"{".as_slice(),
                    StatusCode::UNPROCESSABLE_ENTITY,
                ),
                (
                    "/api/devices/identifier/Missing/token",
                    b"{",
                    StatusCode::BAD_REQUEST,
                ),
                (
                    "/api/devices/identifier/Missing/token",
                    b"{}",
                    StatusCode::UNPROCESSABLE_ENTITY,
                ),
                (
                    "/api/devices/identifier/Missing/token",
                    br#"{"pushToken":null}"#,
                    StatusCode::UNPROCESSABLE_ENTITY,
                ),
                (
                    "/api/devices/identifier/Missing/token",
                    br#"{"pushToken":"one","pushToken":"two"}"#,
                    StatusCode::UNPROCESSABLE_ENTITY,
                ),
                (
                    "/api/devices/identifier/Missing/token",
                    br#"["one","extra"]"#,
                    StatusCode::BAD_REQUEST,
                ),
            ] {
                let Err(error) = device_request(
                    &app,
                    method.clone(),
                    path,
                    device_authorization(Some("device-fixture-alice")),
                    body,
                )
                .await
                else {
                    panic!("Invalid push path/body accepted.")
                };
                assert_eq!(error.0, status);
            }
            for bearer in [
                None,
                Some("invalid"),
                Some("legacy-push-access"),
                Some("device-fixture-alice"),
                Some("device-fixture-bob"),
            ] {
                for id in ["Current-Device", "Missing", "%43urrent-Device"] {
                    let path = format!("/api/devices/identifier/{id}/clear-token");
                    device_push_empty(
                        device_request(
                            &app,
                            method.clone(),
                            &path,
                            device_authorization(bearer),
                            b"malformed ignored body {",
                        )
                        .await,
                    )
                    .await;
                }
                let Err(error) = device_request(
                    &app,
                    method.clone(),
                    "/api/devices/identifier/%5Fbad/clear-token",
                    device_authorization(bearer),
                    b"{",
                )
                .await
                else {
                    panic!("Invalid public clear path accepted.")
                };
                assert_eq!(error.0, StatusCode::UNPROCESSABLE_ENTITY);
            }
        }
        let devices = device_document(
            device_request(
                &app,
                Method::GET,
                "/api/devices",
                device_authorization(Some("legacy-push-access")),
                b"",
            )
            .await,
        )
        .await;
        assert_eq!(devices["data"].as_array().unwrap().len(), 2);
        assert!(
            device_push_persisted_state(&app.store.lock().unwrap()) == before,
            "Rejected push updates or disabled clear changed persisted state."
        );
    }

    #[tokio::test]
    async fn device_push_http_refresh_uses_original_binding_and_storage_failure_is_atomic() {
        let app = device_push_fixture_app();
        {
            let mut store = app.store.lock().unwrap();
            VaultService::new(&mut *store)
                .set_device_push_token(
                    "alice",
                    "Current-Device",
                    &DevicePushTokenRequest {
                        push_token: "original",
                    },
                )
                .unwrap();
        }
        let body = serde_urlencoded::to_string([
            ("grant_type", "refresh_token"),
            ("refresh_token", "device-fixture-refresh-alice"),
            ("deviceIdentifier", "Other-Device"),
        ])
        .unwrap();
        let refreshed = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                body.as_bytes(),
            )
            .await,
        )
        .await;
        assert!(device_claims(&refreshed)["device"] == "Current-Device");
        device_push_empty(
            device_request(
                &app,
                Method::PUT,
                "/api/devices/identifier/Other-Device/token",
                device_authorization(refreshed["access_token"].as_str()),
                br#"{"pushToken":"updated-after-refresh"}"#,
            )
            .await,
        )
        .await;
        {
            let store = app.store.lock().unwrap();
            assert!(
                devices::push_token(&store.db, "alice", "Current-Device")
                    .unwrap()
                    .as_deref()
                    == Some("updated-after-refresh")
            );
            assert!(
                devices::push_token(&store.db, "alice", "Other-Device")
                    .unwrap()
                    .is_none()
            );
            store.db.execute_batch("CREATE TRIGGER reject_http_push_activity BEFORE UPDATE OF updated ON device_registry BEGIN SELECT RAISE(ABORT,'injected push activity failure'); END;").unwrap();
        }
        let before = device_push_persisted_state(&app.store.lock().unwrap());
        for method in [Method::POST, Method::PUT] {
            let Err(error) = device_request(
                &app,
                method,
                "/api/devices/identifier/Missing/token",
                device_authorization(refreshed["access_token"].as_str()),
                br#"{"pushToken":"rejected"}"#,
            )
            .await
            else {
                panic!("Injected push storage failure succeeded.")
            };
            assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
            assert!(
                device_push_persisted_state(&app.store.lock().unwrap()) == before,
                "Failed push request committed token/activity or changed session authority."
            );
        }
    }

    fn device_fixture_app() -> App {
        let store = Store::open(":memory:").unwrap();
        let encoded = Argon2::default()
            .hash_password(b"fixture-master-hash", &SaltString::generate(&mut OsRng))
            .unwrap()
            .to_string();
        for owner in ["alice", "bob"] {
            let account = json!({"id":owner,"email":format!("{owner}@example.test"),"name":"Preserved","key":"preserved-wrapped-key","keys":{"publicKey":"preserved-public","encryptedPrivateKey":"preserved-private"},"future":{"preserved":true},"devices":[{"identifier":"forged-registration-device"}]});
            store.db.execute("INSERT INTO accounts(id,email,document,password,revision) VALUES(?1,?2,?3,?4,?5)", params![owner,format!("{owner}@example.test"),account.to_string(),encoded,store::now()]).unwrap();
            store.db.execute("INSERT INTO sessions(access,refresh,owner,access_expires,refresh_expires) VALUES(?1,?2,?3,4000000000,4000000000)",params![digest(&format!("device-fixture-{owner}")),digest(&format!("device-fixture-refresh-{owner}")),owner]).unwrap();
        }
        App {
            store: Arc::new(Mutex::new(store)),
            base: "http://127.0.0.1".into(),
            signing_key: [1; 32],
        }
    }
    fn device_authorization(bearer: Option<&str>) -> HeaderMap {
        let mut headers = HeaderMap::new();
        if let Some(bearer) = bearer {
            headers.insert("authorization", format!("Bearer {bearer}").parse().unwrap());
        }
        headers
    }
    async fn device_request(
        app: &App,
        method: Method,
        path: &str,
        headers: HeaderMap,
        body: &[u8],
    ) -> Result<Response, Failure> {
        dispatch(
            State(app.clone()),
            method,
            path.parse().unwrap(),
            headers,
            Bytes::copy_from_slice(body),
        )
        .await
    }
    async fn device_document(result: Result<Response, Failure>) -> Value {
        let response = result.unwrap_or_else(|_| panic!("Valid device request failed."));
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), MAX_REQUEST_BYTES)
            .await
            .unwrap();
        serde_json::from_slice(&body).unwrap()
    }
    fn device_claims(tokens: &Value) -> Value {
        let payload = tokens["access_token"]
            .as_str()
            .unwrap()
            .split('.')
            .nth(1)
            .unwrap();
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).unwrap()).unwrap()
    }
    fn device_login_body(owner: &str, identifier: &str, name: &str, kind: &str) -> Vec<u8> {
        serde_urlencoded::to_string([
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("username", &format!("{owner}@example.test")),
            ("password", "fixture-master-hash"),
            ("DeviceIdentifier", identifier),
            ("device_name", name),
            ("DEVICETYPE", kind),
        ])
        .unwrap()
        .into_bytes()
    }
    #[tokio::test]
    async fn password_login_guards_fail_before_verification_or_device_mutation() {
        let app = device_fixture_app();
        let before = device_persisted_state(&app.store.lock().unwrap());
        for (body, message) in [
            ("grant_type=password", "client_id cannot be blank"),
            (
                "grant_type=password&client_id=cli",
                "password cannot be blank",
            ),
            (
                "grant_type=password&client_id=cli&password=x",
                "scope cannot be blank",
            ),
            (
                "grant_type=password&client_id=cli&password=x&scope=bad",
                "username cannot be blank",
            ),
            (
                "grant_type=password&client_id=cli&password=x&scope=bad&username=missing",
                "device_identifier cannot be blank",
            ),
            (
                "grant_type=password&client_id=cli&password=x&scope=bad&username=missing&deviceIdentifier=x",
                "device_name cannot be blank",
            ),
            (
                "grant_type=password&client_id=cli&password=x&scope=bad&username=missing&deviceIdentifier=x&deviceName=",
                "device_type cannot be blank",
            ),
        ] {
            let Err(error) = device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                body.as_bytes(),
            )
            .await
            else {
                panic!("Incomplete password form authorized")
            };
            assert!(error.0 == StatusCode::BAD_REQUEST && error.1 == message);
            let response = error.into_response();
            let document: Value = serde_json::from_slice(
                &axum::body::to_bytes(response.into_body(), usize::MAX)
                    .await
                    .unwrap(),
            )
            .unwrap();
            assert!(
                document["error"] == ""
                    && document["error_description"] == ""
                    && document["errorModel"]["message"] == message
                    && document["validationErrors"][""][0] == message
            );
        }
        let response = device_request(&app, Method::POST, "/identity/connect/token", HeaderMap::new(), b"grant_type=password&client_id=&password=&scope=api%0Aoffline_access&username=&deviceIdentifier=&deviceName=&deviceType=").await.unwrap_or_else(|_| panic!("Scope response unavailable"));
        assert!(response.status() == StatusCode::BAD_REQUEST);
        let document: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), usize::MAX)
                .await
                .unwrap(),
        )
        .unwrap();
        assert!(
            document["message"] == "Scope (api\\noffline_access) not supported"
                && document["error"] == ""
        );
        assert!(device_persisted_state(&app.store.lock().unwrap()) == before);
    }

    #[tokio::test]
    async fn password_login_checks_authoritative_enabled_policy_after_proof() {
        let app = device_fixture_app();
        {
            let store = app.store.lock().unwrap();
            store
                .db
                .execute(
                    "INSERT INTO account_auth_policy(owner,enabled) VALUES('alice',0)",
                    [],
                )
                .unwrap();
            store.db.execute("UPDATE accounts SET document=json_set(document,'$.enabled',1,'$.disabled',0) WHERE id='alice'", []).unwrap();
        }
        let before = device_persisted_state(&app.store.lock().unwrap());
        for (proof, message) in [
            ("wrong", "Username or password is incorrect. Try again"),
            ("fixture-master-hash", "This user has been disabled"),
        ] {
            let body = account_password_login(proof, "Disabled-Device");
            let Err(error) = device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                body.as_bytes(),
            )
            .await
            else {
                panic!("Disabled account authorized")
            };
            assert!(error.0 == StatusCode::BAD_REQUEST && error.1 == message);
            assert!(device_persisted_state(&app.store.lock().unwrap()) == before);
        }
    }

    #[tokio::test]
    async fn password_login_nested_aliases_and_first_grant_drive_owner_and_device_binding() {
        let app = device_fixture_app();
        let form = serde_urlencoded::to_string([
            ("[GrAnTtYpE].ignored", "password"),
            ("grant_type", "other"),
            (".CLIENTID[nested]", "first-client"),
            ("[USERNAME]", "\u{2003}ALICE@EXAMPLE.TEST \n"),
            ("PASSWORD.x", "fixture-master-hash"),
            ("scope.x", "api offline_access"),
            ("[deviceIdentifier]", "Opaque_+/雪"),
            ("deviceName.x", ""),
            ("deviceType.x", "invalid"),
        ])
        .unwrap();
        let tokens = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                form.as_bytes(),
            )
            .await,
        )
        .await;
        let claims = device_claims(&tokens);
        assert!(claims["sub"] == "alice" && claims["client_id"] == "first-client");
        let store = app.store.lock().unwrap();
        let record: (String,i32) = store.db.query_row("SELECT name,device_type FROM device_registry WHERE owner='alice' AND identifier=?1", ["Opaque_+/雪"], |row| Ok((row.get(0)?,row.get(1)?))).unwrap();
        assert!(record.0.is_empty() && record.1 == 14 && tokens["refresh_token"].is_string());
    }

    fn device_persisted_state(store: &Store) -> Vec<String> {
        store.db.prepare("SELECT 'account:'||id||':'||document||':'||password||':'||revision FROM accounts UNION ALL SELECT 'session:'||access||':'||refresh||':'||owner||':'||access_expires||':'||refresh_expires FROM sessions UNION ALL SELECT 'device:'||owner||':'||identifier||':'||name||':'||device_type||':'||created||':'||updated FROM device_registry UNION ALL SELECT 'binding:'||access||':'||owner||':'||identifier FROM session_devices ORDER BY 1").unwrap().query_map([],|row|row.get(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap()
    }

    #[tokio::test]
    async fn device_http_discovery_projects_exact_fields_and_authenticates_before_path_guard() {
        let app = device_fixture_app();
        {
            let mut store = app.store.lock().unwrap();
            for (owner, identifier, name) in [
                ("alice", "not-a-UUID", "Alice device"),
                ("bob", "foreign-device", "Bob device"),
            ] {
                VaultService::new(&mut *store)
                    .register_device(
                        owner,
                        &DeviceRegistration {
                            identifier,
                            name,
                            device_type: 8,
                        },
                    )
                    .unwrap();
            }
        }
        for bearer in [None, Some("invalid")] {
            for path in [
                "/api/devices",
                "/api/devices/identifier/not-a-UUID",
                "/api/devices/identifier/%5Finvalid",
            ] {
                let Err(error) =
                    device_request(&app, Method::GET, path, device_authorization(bearer), b"")
                        .await
                else {
                    panic!("Anonymous device read succeeded.")
                };
                assert_eq!(error.0, StatusCode::UNAUTHORIZED);
            }
        }
        let list = device_document(
            device_request(
                &app,
                Method::GET,
                "/api/devices",
                device_authorization(Some("device-fixture-alice")),
                b"",
            )
            .await,
        )
        .await;
        assert_eq!(list.as_object().unwrap().len(), 3);
        assert!(list["object"] == "list" && list["continuationToken"].is_null());
        assert_eq!(list["data"].as_array().unwrap().len(), 1);
        assert_eq!(list["data"][0].as_object().unwrap().len(), 10);
        assert!(
            list["data"][0]["name"] == "Alice device"
                && list["data"][0]["encryptedPublicKey"].is_null()
                && list["data"][0]["encryptedUserKey"].is_null()
                && list["data"][0]["devicePendingAuthRequest"].is_null()
        );
        let single = device_document(
            device_request(
                &app,
                Method::GET,
                "/api/devices/identifier/%6Eot-a-UUID",
                device_authorization(Some("device-fixture-alice")),
                b"",
            )
            .await,
        )
        .await;
        assert_eq!(single.as_object().unwrap().len(), 7);
        assert!(
            single["id"] == "not-a-UUID"
                && single["identifier"] == "not-a-UUID"
                && single["object"] == "device"
                && single["isTrusted"] == false
        );
        for (path, status) in [
            (
                "/api/devices/identifier/foreign-device",
                StatusCode::BAD_REQUEST,
            ),
            (
                "/api/devices/identifier/NOT-a-UUID",
                StatusCode::BAD_REQUEST,
            ),
            (
                "/api/devices/identifier/%5Fbad",
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "/api/devices/identifier/a+b",
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "/api/devices/identifier/a%2Bb",
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "/api/devices/identifier/a%2Fb",
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let Err(error) = device_request(
                &app,
                Method::GET,
                path,
                device_authorization(Some("device-fixture-alice")),
                b"",
            )
            .await
            else {
                panic!("Invalid or foreign device read succeeded.")
            };
            assert_eq!(error.0, status);
        }
        let before = device_persisted_state(&app.store.lock().unwrap());
        for (email, identifier, expected) in [
            ("ALICE@EXAMPLE.TEST", "not-a-UUID", true),
            (" alice@example.test", "not-a-UUID", false),
            ("alice@example.test ", "not-a-UUID", false),
            ("bob@example.test", "not-a-UUID", false),
            ("alice@example.test", "forged-registration-device", false),
            ("alice@example.test", "opaque-雪", false),
            ("alice@example.test", "opaque:_/+", false),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "x-request-email",
                format!("{}=====", URL_SAFE_NO_PAD.encode(email))
                    .parse()
                    .unwrap(),
            );
            headers.insert(
                "x-device-identifier",
                axum::http::HeaderValue::from_bytes(identifier.as_bytes()).unwrap(),
            );
            let value = device_document(
                device_request(&app, Method::GET, "/api/devices/knowndevice", headers, b"").await,
            )
            .await;
            assert!(value == json!(expected));
        }
        let Err(error) = device_request(
            &app,
            Method::GET,
            "/api/devices/knowndevice",
            HeaderMap::new(),
            b"",
        )
        .await
        else {
            panic!("Missing discovery headers accepted.")
        };
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(
            device_persisted_state(&app.store.lock().unwrap()) == before,
            "Device discovery mutated persisted state."
        );
    }

    #[tokio::test]
    async fn device_password_and_api_logins_register_only_verified_owners_and_preserve_metadata() {
        let app = device_fixture_app();
        let authority_before = device_persisted_state(&app.store.lock().unwrap());
        let mut wrong =
            parse_connect_form(&device_login_body("alice", "failed-device", "Failed", "8"))
                .unwrap_or_else(|_| panic!("Fixture form failed."));
        wrong.insert("password".into(), "wrong".into());
        let wrong = serde_urlencoded::to_string(&wrong).unwrap();
        let Err(error) = device_request(
            &app,
            Method::POST,
            "/identity/connect/token",
            HeaderMap::new(),
            wrong.as_bytes(),
        )
        .await
        else {
            panic!("Wrong credential registered a device.")
        };
        assert_eq!(error.0, StatusCode::BAD_REQUEST);
        assert!(device_persisted_state(&app.store.lock().unwrap()) == authority_before);
        for omitted in ["DeviceIdentifier", "device_name", "DEVICETYPE"] {
            let mut form =
                parse_connect_form(&device_login_body("alice", "failed-device", "Failed", "8"))
                    .unwrap_or_else(|_| panic!("Fixture form failed."));
            form.remove(omitted);
            let body = serde_urlencoded::to_string(form).unwrap();
            let Err(error) = device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                body.as_bytes(),
            )
            .await
            else {
                panic!("Missing device field accepted.")
            };
            assert_eq!(error.0, StatusCode::BAD_REQUEST);
            assert!(device_persisted_state(&app.store.lock().unwrap()) == authority_before);
        }
        let first = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                &device_login_body("alice", "Shared-Login", "Original 雪", "iOS"),
            )
            .await,
        )
        .await;
        assert!(device_claims(&first)["device"] == "Shared-Login");
        let original = {
            let store = app.store.lock().unwrap();
            devices::load(&store.db, "alice", "Shared-Login")
                .unwrap()
                .unwrap()
        };
        let revision_before = {
            let store = app.store.lock().unwrap();
            store.account("id", "alice").unwrap().unwrap()
        };
        let repeat = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                &device_login_body("alice", "Shared-Login", "Replacement", "-1"),
            )
            .await,
        )
        .await;
        assert!(device_claims(&repeat)["device"] == "Shared-Login");
        let bob = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                &device_login_body("bob", "Shared-Login", "Bob", "-1"),
            )
            .await,
        )
        .await;
        assert!(device_claims(&bob)["sub"] == "bob");
        {
            let store = app.store.lock().unwrap();
            let retained = devices::load(&store.db, "alice", "Shared-Login")
                .unwrap()
                .unwrap();
            assert!(
                retained.name == original.name
                    && retained.created == original.created
                    && retained.device_type == 14
            );
            assert!(
                store.account("id", "alice").unwrap().unwrap() == revision_before,
                "Login changed the account document or revision."
            );
            assert_eq!(
                devices::load(&store.db, "bob", "Shared-Login")
                    .unwrap()
                    .unwrap()
                    .device_type,
                -1
            );
        }
        let secret = {
            let mut store = app.store.lock().unwrap();
            no_warden::identity::IdentityStorage::get_or_create_api_key(&mut *store, "alice")
                .unwrap()
                .api_key
                .expose_secret()
                .to_owned()
        };
        let api_body = |supplied: &str| {
            serde_urlencoded::to_string([
                ("grant_type", "client_credentials"),
                ("client_id", "user.alice"),
                ("client_secret", supplied),
                ("scope", "api"),
                ("deviceIdentifier", "API-Device"),
                ("deviceName", "API original"),
                ("deviceType", "2147483647"),
            ])
            .unwrap()
        };
        let before = device_persisted_state(&app.store.lock().unwrap());
        assert!(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                api_body("wrong").as_bytes()
            )
            .await
            .is_err()
        );
        assert!(device_persisted_state(&app.store.lock().unwrap()) == before);
        let api = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                api_body(&secret).as_bytes(),
            )
            .await,
        )
        .await;
        assert!(
            device_claims(&api)["device"] == "API-Device" && api.get("refresh_token").is_none()
        );
        let store = app.store.lock().unwrap();
        assert_eq!(
            devices::load(&store.db, "alice", "API-Device")
                .unwrap()
                .unwrap()
                .device_type,
            i32::MAX
        );
        assert!(
            devices::load(&store.db, "bob", "API-Device")
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn device_refresh_reuses_bound_proofs_and_rejects_unbound_legacy_authority() {
        let app = device_fixture_app();
        let first = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                &device_login_body("alice", "Refresh-Device", "Original", "8"),
            )
            .await,
        )
        .await;
        let before = {
            let store = app.store.lock().unwrap();
            store.db.execute("UPDATE device_registry SET updated='2000-01-01T00:00:00.000000Z' WHERE owner='alice'",[]).unwrap();
            store.account("id", "alice").unwrap().unwrap()
        };
        let body = serde_urlencoded::to_string([
            ("grant_type", "refresh_token"),
            ("refresh_token", first["refresh_token"].as_str().unwrap()),
            ("deviceIdentifier", "forged-refresh-device"),
        ])
        .unwrap();
        let refreshed = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                body.as_bytes(),
            )
            .await,
        )
        .await;
        assert!(device_claims(&refreshed)["device"] == "Refresh-Device");
        {
            let store = app.store.lock().unwrap();
            assert!(store.account("id", "alice").unwrap().unwrap() == before);
            assert!(
                devices::refresh_binding(
                    &store.db,
                    &digest(refreshed["refresh_token"].as_str().unwrap()),
                    "alice"
                )
                .unwrap()
                .as_deref()
                    == Some("Refresh-Device")
            );
            let updated: String = store
                .db
                .query_row(
                    "SELECT updated FROM device_registry WHERE owner='alice'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(updated != "2000-01-01T00:00:00.000000Z");
            assert_eq!(devices::list(&store.db, "alice").unwrap().0.len(), 1);
        }
        let list = device_document(
            device_request(
                &app,
                Method::GET,
                "/api/devices",
                device_authorization(first["access_token"].as_str()),
                b"",
            )
            .await,
        )
        .await;
        assert_eq!(list["data"].as_array().unwrap().len(), 1);
        let original_deadline: i64 = app
            .store
            .lock()
            .unwrap()
            .db
            .query_row(
                "SELECT refresh_expires FROM sessions WHERE refresh=?1",
                [digest(first["refresh_token"].as_str().unwrap())],
                |row| row.get(0),
            )
            .unwrap();
        let replayed = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                body.as_bytes(),
            )
            .await,
        )
        .await;
        assert!(device_claims(&replayed)["device"] == "Refresh-Device");
        {
            let store = app.store.lock().unwrap();
            let deadline: i64 = store
                .db
                .query_row(
                    "SELECT refresh_expires FROM sessions WHERE refresh=?1",
                    [digest(first["refresh_token"].as_str().unwrap())],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(
                deadline == original_deadline
                    && store.account("id", "alice").unwrap().unwrap() == before
            );
        }
        let snapshot = device_persisted_state(&app.store.lock().unwrap());
        let legacy_body = b"grant_type=refresh_token&refresh_token=device-fixture-refresh-bob";
        let Err(error) = device_request(
            &app,
            Method::POST,
            "/identity/connect/token",
            HeaderMap::new(),
            legacy_body,
        )
        .await
        else {
            panic!("Unbound legacy refresh authorized")
        };
        assert!(error.0 == StatusCode::BAD_REQUEST);
        let store = app.store.lock().unwrap();
        assert!(device_persisted_state(&store) == snapshot);
        assert!(devices::list(&store.db, "bob").unwrap().0.is_empty());
    }

    #[tokio::test]
    async fn refresh_http_keeps_original_deadlines_and_uses_stored_mobile_type() {
        for (kind, days) in [("0", 90), ("1", 90), ("15", 30), ("8", 30)] {
            let app = device_fixture_app();
            let first = device_document(
                device_request(
                    &app,
                    Method::POST,
                    "/identity/connect/token",
                    HeaderMap::new(),
                    &device_login_body("alice", "TTL-Device", "Original", kind),
                )
                .await,
            )
            .await;
            let original = first["refresh_token"].as_str().unwrap();
            let before: (i64, i64) = app
                .store
                .lock()
                .unwrap()
                .db
                .query_row(
                    "SELECT access_expires,refresh_expires FROM sessions WHERE refresh=?1",
                    [digest(original)],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .unwrap();
            assert!(before.1 - (before.0 - 7200) == days * 86400);
            let spaced = format!("\u{2003}{}\n {}\u{a0}", &original[..5], &original[5..]);
            let form = serde_urlencoded::to_string([
                ("GRANTTYPE.x", "refresh_token"),
                ("[REFRESHTOKEN]", spaced.as_str()),
                (".CLIENTID", "changed"),
                ("deviceType", "15"),
                ("deviceIdentifier", "forged"),
            ])
            .unwrap();
            for _ in 0..2 {
                let tokens = device_document(
                    device_request(
                        &app,
                        Method::POST,
                        "/identity/connect/token",
                        HeaderMap::new(),
                        form.as_bytes(),
                    )
                    .await,
                )
                .await;
                assert!(
                    tokens.as_object().unwrap().len() == 5
                        && device_claims(&tokens)["client_id"] == "changed"
                        && device_claims(&tokens)["device"] == "TTL-Device"
                );
                let store = app.store.lock().unwrap();
                let after: (i64, i64) = store
                    .db
                    .query_row(
                        "SELECT access_expires,refresh_expires FROM sessions WHERE refresh=?1",
                        [digest(original)],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                let new: (i64, i64) = store
                    .db
                    .query_row(
                        "SELECT access_expires,refresh_expires FROM sessions WHERE refresh=?1",
                        [digest(tokens["refresh_token"].as_str().unwrap())],
                        |row| Ok((row.get(0)?, row.get(1)?)),
                    )
                    .unwrap();
                assert!(after == before && new.1 - (new.0 - 7200) == days * 86400);
            }
        }
    }

    #[tokio::test]
    async fn refresh_http_rolls_back_every_issuance_stage_and_retries_original_proof() {
        fn snapshot(store: &Store) -> Vec<String> {
            let mut rows = device_persisted_state(store);
            rows.extend(store.db.prepare("SELECT json_array(access,owner,identifier,stamp,access_expires) FROM account_password_access ORDER BY access").unwrap().query_map([], |row| row.get::<_,String>(0)).unwrap().collect::<rusqlite::Result<Vec<_>>>().unwrap());
            rows
        }
        for stage in ["activity", "session", "binding", "history", "commit"] {
            let app = device_fixture_app();
            let first = device_document(
                device_request(
                    &app,
                    Method::POST,
                    "/identity/connect/token",
                    HeaderMap::new(),
                    &device_login_body("alice", "Refresh-Atomic", "Original", "8"),
                )
                .await,
            )
            .await;
            {
                let store = app.store.lock().unwrap();
                store.db.execute("UPDATE device_registry SET updated='2000-01-01T00:00:00.000000Z' WHERE owner='alice'",[]).unwrap();
                store
                    .db
                    .execute(
                        "INSERT INTO sessions VALUES('expired-access','expired-proof','alice',0,0)",
                        [],
                    )
                    .unwrap();
                let trigger = match stage {
                    "activity" => {
                        "CREATE TRIGGER fail_refresh BEFORE UPDATE ON device_registry BEGIN SELECT RAISE(ABORT,'injected activity failure'); END;"
                    }
                    "session" => {
                        "CREATE TRIGGER fail_refresh BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT,'injected session failure'); END;"
                    }
                    "binding" => {
                        "CREATE TRIGGER fail_refresh BEFORE INSERT ON session_devices BEGIN SELECT RAISE(ABORT,'injected binding failure'); END;"
                    }
                    "history" => {
                        "CREATE TRIGGER fail_refresh BEFORE INSERT ON account_password_access BEGIN SELECT RAISE(ABORT,'injected history failure'); END;"
                    }
                    "commit" => {
                        "CREATE TABLE failed_refresh(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER fail_refresh AFTER INSERT ON account_password_access BEGIN INSERT INTO failed_refresh VALUES('missing'); END;"
                    }
                    _ => unreachable!(),
                };
                store.db.execute_batch(trigger).unwrap();
            }
            let before = snapshot(&app.store.lock().unwrap());
            let form = serde_urlencoded::to_string([
                ("grant_type", "refresh_token"),
                ("refresh_token", first["refresh_token"].as_str().unwrap()),
            ])
            .unwrap();
            let Err(error) = device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                form.as_bytes(),
            )
            .await
            else {
                panic!("Injected refresh failure succeeded")
            };
            assert!(error.0 == StatusCode::INTERNAL_SERVER_ERROR);
            {
                let store = app.store.lock().unwrap();
                assert!(snapshot(&store) == before && store.db.is_autocommit());
                store.db.execute_batch("DROP TRIGGER fail_refresh").unwrap();
            }
            let tokens = device_document(
                device_request(
                    &app,
                    Method::POST,
                    "/identity/connect/token",
                    HeaderMap::new(),
                    form.as_bytes(),
                )
                .await,
            )
            .await;
            assert!(
                tokens.as_object().unwrap().len() == 5
                    && device_claims(&tokens)["device"] == "Refresh-Atomic"
            );
        }
    }

    #[tokio::test]
    async fn device_login_and_refresh_failures_roll_back_registry_sessions_and_binding() {
        for failure in ["session", "binding", "commit"] {
            let app = device_fixture_app();
            {
                let mut store = app.store.lock().unwrap();
                VaultService::new(&mut *store)
                    .register_device(
                        "alice",
                        &DeviceRegistration {
                            identifier: "Existing-Device",
                            name: "Original",
                            device_type: 8,
                        },
                    )
                    .unwrap();
                store
                    .db
                    .execute(
                        "UPDATE device_registry SET updated='2000-01-01T00:00:00.000000Z'",
                        [],
                    )
                    .unwrap();
                store.db.execute("INSERT INTO sessions(access,refresh,owner,access_expires,refresh_expires) VALUES('expired-access','expired-refresh','alice',0,0)",[]).unwrap();
                let trigger = match failure {
                    "session" => {
                        "CREATE TRIGGER reject_device_session BEFORE INSERT ON sessions BEGIN SELECT RAISE(ABORT,'injected session failure'); END;"
                    }
                    "binding" => {
                        "CREATE TRIGGER reject_device_binding BEFORE INSERT ON session_devices BEGIN SELECT RAISE(ABORT,'injected binding failure'); END;"
                    }
                    "commit" => {
                        "CREATE TABLE failed_device_login(owner TEXT REFERENCES accounts(id) DEFERRABLE INITIALLY DEFERRED); CREATE TRIGGER reject_device_login AFTER INSERT ON session_devices BEGIN INSERT INTO failed_device_login(owner) VALUES('missing'); END;"
                    }
                    _ => unreachable!(),
                };
                store.db.execute_batch(trigger).unwrap();
            }
            let before = device_persisted_state(&app.store.lock().unwrap());
            for identifier in ["New-Device", "Existing-Device"] {
                let Err(error) = device_request(
                    &app,
                    Method::POST,
                    "/identity/connect/token",
                    HeaderMap::new(),
                    &device_login_body("alice", identifier, "Replacement", "-1"),
                )
                .await
                else {
                    panic!("Injected device login failure succeeded.")
                };
                assert_eq!(error.0, StatusCode::INTERNAL_SERVER_ERROR);
                let store = app.store.lock().unwrap();
                assert!(
                    device_persisted_state(&store) == before,
                    "Failed login committed device or session state."
                );
                assert!(store.db.is_autocommit());
            }
        }
        let app = device_fixture_app();
        let first = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                &device_login_body("alice", "Refresh-Failure", "Original", "8"),
            )
            .await,
        )
        .await;
        {
            let store = app.store.lock().unwrap();
            store
                .db
                .execute(
                    "UPDATE device_registry SET updated='2000-01-01T00:00:00.000000Z'",
                    [],
                )
                .unwrap();
            store.db.execute_batch("CREATE TRIGGER reject_refresh_binding BEFORE INSERT ON session_devices BEGIN SELECT RAISE(ABORT,'injected refresh binding failure'); END;").unwrap();
        }
        let before = device_persisted_state(&app.store.lock().unwrap());
        let body = serde_urlencoded::to_string([
            ("grant_type", "refresh_token"),
            ("refresh_token", first["refresh_token"].as_str().unwrap()),
        ])
        .unwrap();
        assert!(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                body.as_bytes()
            )
            .await
            .is_err()
        );
        assert!(
            device_persisted_state(&app.store.lock().unwrap()) == before,
            "Failed refresh consumed authority or changed device activity."
        );
        app.store
            .lock()
            .unwrap()
            .db
            .execute_batch("DROP TRIGGER reject_refresh_binding")
            .unwrap();
        let retry = device_document(
            device_request(
                &app,
                Method::POST,
                "/identity/connect/token",
                HeaderMap::new(),
                body.as_bytes(),
            )
            .await,
        )
        .await;
        assert!(device_claims(&retry)["device"] == "Refresh-Failure");
    }

    #[tokio::test]
    async fn domain_http_dispatch_preserves_owner_isolation_and_sync_projection() {
        async fn request(
            app: &App,
            owner: Option<&str>,
            method: Method,
            path: &str,
            body: &[u8],
        ) -> Result<Response, Failure> {
            let mut headers = HeaderMap::new();
            if let Some(owner) = owner {
                headers.insert(
                    "authorization",
                    format!("Bearer fixture-domains-{owner}").parse().unwrap(),
                );
            }
            dispatch(
                State(app.clone()),
                method,
                path.parse().unwrap(),
                headers,
                Bytes::copy_from_slice(body),
            )
            .await
        }
        async fn document(response: Result<Response, Failure>) -> Value {
            let response = response.unwrap_or_else(|_| panic!("Valid domain HTTP request failed."));
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap();
            serde_json::from_slice(&bytes).unwrap()
        }
        let app = App {
            store: Arc::new(Mutex::new(Store::open(":memory:").unwrap())),
            base: "http://127.0.0.1".into(),
            signing_key: [1; 32],
        };
        {
            let store = app.store.lock().unwrap();
            for owner in ["alice", "bob"] {
                let account = json!({"id":owner,"email":format!("{owner}@example.test"),"name":"preserved-name","key":"preserved-user-key","keys":{"publicKey":"preserved-public","encryptedPrivateKey":"preserved-private"},"futureField":{"preserved":true},"equivalentDomains":[["untrusted-root-value"]]});
                store.db.execute("INSERT INTO accounts(id,email,document,password,revision) VALUES(?1,?2,?3,'preserved-verifier',?4)",params![owner,format!("{owner}@example.test"),account.to_string(),store::now()]).unwrap();
                store.db.execute("INSERT INTO sessions(access,refresh,owner,access_expires,refresh_expires) VALUES(?1,?2,?3,4000000000,4000000000)",params![digest(&format!("fixture-domains-{owner}")),format!("fixture-domain-refresh-{owner}"),owner]).unwrap();
            }
        }
        for method in [Method::GET, Method::POST, Method::PUT] {
            let result = request(&app, None, method, "/api/settings/domains", b"{}").await;
            let Err(error) = result else {
                panic!("Anonymous domain request succeeded.")
            };
            assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        }
        let mut query_statuses = Vec::new();
        for owner in [None, Some("invalid"), Some("alice")] {
            let result = request(
                &app,
                owner,
                Method::GET,
                "/api/sync?excludeDomains=invalid",
                b"",
            )
            .await;
            let Err(error) = result else {
                panic!("Invalid sync query succeeded.")
            };
            query_statuses.push(error.0);
        }
        assert_eq!(
            query_statuses,
            [
                StatusCode::UNAUTHORIZED,
                StatusCode::UNAUTHORIZED,
                StatusCode::UNPROCESSABLE_ENTITY
            ]
        );
        let original = app
            .store
            .lock()
            .unwrap()
            .account("id", "alice")
            .unwrap()
            .unwrap();
        let foreign = app
            .store
            .lock()
            .unwrap()
            .account("id", "bob")
            .unwrap()
            .unwrap();
        let body=br#"{"excludedGlobalEquivalentDomains":[2,2,-1],"equivalentDomains":[[],["","NUL\u0000caf\u00e9","duplicate","duplicate"]],"id":"bob","owner":"bob","name":"forged","key":"forged","keys":{"publicKey":"forged"}}"#;
        let response = document(
            request(
                &app,
                Some("alice"),
                Method::POST,
                "/api/settings/domains",
                body,
            )
            .await,
        )
        .await;
        assert!(response == json!({}));
        let all = document(
            request(
                &app,
                Some("alice"),
                Method::GET,
                "/api/settings/domains",
                b"",
            )
            .await,
        )
        .await;
        assert_eq!(all["object"], "domains");
        assert!(
            all["equivalentDomains"] == json!([[], ["", "NUL\0café", "duplicate", "duplicate"]])
        );
        assert_eq!(all["globalEquivalentDomains"].as_array().unwrap().len(), 91);
        assert_eq!(all["globalEquivalentDomains"][0]["excluded"], true);
        let sync = document(
            request(
                &app,
                Some("alice"),
                Method::GET,
                "/api/sync?excludeDomains=false",
                b"",
            )
            .await,
        )
        .await;
        assert!(sync["domains"]["equivalentDomains"] == all["equivalentDomains"]);
        assert_eq!(
            sync["domains"]["globalEquivalentDomains"]
                .as_array()
                .unwrap()
                .len(),
            90
        );
        assert!(
            sync["domains"]["globalEquivalentDomains"]
                .as_array()
                .unwrap()
                .iter()
                .all(|group| group["type"] != 2 && group["excluded"] == false)
        );
        let excluded = document(
            request(
                &app,
                Some("alice"),
                Method::GET,
                "/api/sync?excludeDomains=true",
                b"",
            )
            .await,
        )
        .await;
        assert!(excluded["domains"].is_null());
        let other =
            document(request(&app, Some("bob"), Method::GET, "/api/settings/domains", b"").await)
                .await;
        assert!(other["equivalentDomains"] == json!([]));
        assert!(
            other["globalEquivalentDomains"]
                .as_array()
                .unwrap()
                .iter()
                .all(|group| group["excluded"] == false)
        );
        {
            let store = app.store.lock().unwrap();
            let saved = store.account("id", "alice").unwrap().unwrap();
            for field in [
                "id",
                "email",
                "name",
                "key",
                "keys",
                "futureField",
                "equivalentDomains",
            ] {
                assert!(
                    saved[field] == original[field],
                    "Domain update trusted an unrelated body field."
                );
            }
            assert!(
                store.account("id", "bob").unwrap().unwrap() == foreign,
                "Domain update changed another account."
            );
        }
        let reset = document(
            request(
                &app,
                Some("alice"),
                Method::PUT,
                "/api/settings/domains",
                b"{}",
            )
            .await,
        )
        .await;
        assert!(reset == json!({}));
        let cleared = document(
            request(
                &app,
                Some("alice"),
                Method::GET,
                "/api/settings/domains",
                b"",
            )
            .await,
        )
        .await;
        assert!(cleared["equivalentDomains"] == json!([]));
        assert!(
            cleared["globalEquivalentDomains"]
                .as_array()
                .unwrap()
                .iter()
                .all(|group| group["excluded"] == false)
        );
        let persisted = || {
            let store = app.store.lock().unwrap();
            store.db.query_row("SELECT a.document||':'||a.revision||':'||COALESCE(d.excluded_globals,'[]')||':'||COALESCE(d.equivalent_domains,'[]') FROM accounts a LEFT JOIN account_domains d ON d.owner=a.id WHERE a.id='alice'",[],|row|row.get::<_,String>(0)).unwrap()
        };
        let before = persisted();
        for (method, path, body, status) in [
            (
                Method::POST,
                "/api/settings/domains",
                b"[]".as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                Method::PUT,
                "/api/settings/domains",
                b"{".as_slice(),
                StatusCode::BAD_REQUEST,
            ),
            (
                Method::PUT,
                "/api/settings/domains",
                br#"{"excludedGlobalEquivalentDomains":[2147483648]}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                Method::GET,
                "/api/sync?excludeDomains=invalid",
                b"".as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let result = request(&app, Some("alice"), method, path, body).await;
            let Err(error) = result else {
                panic!("Invalid domain request succeeded.")
            };
            assert_eq!(error.0, status);
            assert!(
                persisted() == before,
                "Rejected domain request changed settings or account state."
            );
        }
    }

    #[test]
    fn profile_and_avatar_inputs_match_upstream_schema_escapes_and_sequence_shapes() {
        for (body, expected) in [
            (br#"{"name":""}"#.as_slice(), ""),
            (br#"["name"]"#.as_slice(), "name"),
            (
                br#"{"name":"quoted \" \u00e9\u0000\n","id":"ignored","culture":"ignored"}"#
                    .as_slice(),
                "quoted \" é\0\n",
            ),
        ] {
            let input = parse_profile_input(body)
                .unwrap_or_else(|_| panic!("Valid profile input was rejected."));
            assert!(input.name == expected);
        }
        for body in [
            br#"{}"#.as_slice(),
            br#"{"avatarColor":null}"#.as_slice(),
            br#"[null]"#.as_slice(),
        ] {
            let input = parse_avatar_input(body)
                .unwrap_or_else(|_| panic!("Valid avatar clear input was rejected."));
            assert!(input.avatar_color.is_none());
        }
        for body in [
            br#"{"avatarColor":"\u00e9abcde","id":"ignored","name":"ignored"}"#.as_slice(),
            br#"["\u00e9abcde"]"#.as_slice(),
        ] {
            let input = parse_avatar_input(body)
                .unwrap_or_else(|_| panic!("Valid avatar string input was rejected."));
            assert!(input.avatar_color.as_deref() == Some("éabcde"));
        }
        for (profile, body, status) in [
            (true, b"{".as_slice(), StatusCode::BAD_REQUEST),
            (
                true,
                br#"["name","extra"]"#.as_slice(),
                StatusCode::BAD_REQUEST,
            ),
            (true, br#"{}"#.as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
            (true, br#"[]"#.as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
            (
                true,
                br#"{"name":null}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                true,
                br#"{"name":7}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                true,
                br#"{"name":"first","na\u006de":"second"}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (false, b"{".as_slice(), StatusCode::BAD_REQUEST),
            (false, br#"[null,null]"#.as_slice(), StatusCode::BAD_REQUEST),
            (false, br#"[]"#.as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
            (
                false,
                br#"null"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                false,
                br#"{"avatarColor":7}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                false,
                br#"{"avatarColor":false}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                false,
                br#"{"avatarColor":[]}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                false,
                br#"{"avatarColor":null,"avatarColor":null}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let error = if profile {
                parse_profile_input(body).err()
            } else {
                parse_avatar_input(body).err()
            }
            .expect("Invalid profile metadata input was accepted.");
            assert_eq!(error.0, status);
            assert_eq!(error.1, "Invalid request");
        }
    }

    #[tokio::test]
    async fn profile_http_mutations_use_authenticated_identity_and_persist_into_get_and_sync() {
        let app = App {
            store: Arc::new(Mutex::new(Store::open(":memory:").unwrap())),
            base: "http://127.0.0.1".into(),
            signing_key: [1; 32],
        };
        {
            let store = app.store.lock().unwrap();
            for owner in ["alice", "bob"] {
                let account = json!({"id":owner,"email":format!("{owner}@example.test"),"name":"initial","avatarColor":"#123456","key":"preserved-user-key","keys":{"publicKey":"preserved-public","encryptedPrivateKey":"preserved-private"},"userKeyId":"preserved-key-id","securityStamp":"preserved-stamp","futureField":{"preserved":true}});
                store.db.execute("INSERT INTO accounts(id,email,document,password,revision) VALUES(?1,?2,?3,'preserved-password-verifier',?4)",params![owner,format!("{owner}@example.test"),account.to_string(),store::now()]).unwrap();
                store.db.execute("INSERT INTO sessions(access,refresh,owner,access_expires,refresh_expires) VALUES(?1,?2,?3,4000000000,4000000000)",params![digest(&format!("fixture-profile-{owner}")),format!("fixture-refresh-{owner}"),owner]).unwrap();
            }
        }
        let original = app
            .store
            .lock()
            .unwrap()
            .account("id", "alice")
            .unwrap()
            .unwrap();
        let foreign = app
            .store
            .lock()
            .unwrap()
            .account("id", "bob")
            .unwrap()
            .unwrap();
        for (method, path, body) in [
            (
                Method::PUT,
                "/api/accounts/profile",
                br#"{"name":"x"}"#.as_slice(),
            ),
            (
                Method::POST,
                "/api/accounts/profile",
                br#"{"name":"x"}"#.as_slice(),
            ),
            (
                Method::PUT,
                "/api/accounts/avatar",
                br#"{"avatarColor":null}"#.as_slice(),
            ),
        ] {
            let result = dispatch(
                State(app.clone()),
                method,
                path.parse().unwrap(),
                HeaderMap::new(),
                Bytes::copy_from_slice(body),
            )
            .await;
            let Err(error) = result else {
                panic!("Anonymous profile mutation succeeded.")
            };
            assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        }
        for (method,path,body,name,avatar) in [
            (Method::POST,"/api/accounts/profile",br#"{"name":"","id":"bob","owner":"bob","email":"forged@example.test","culture":"forged","key":"forged","keys":{"publicKey":"forged"},"avatarColor":"forged"}"#.as_slice(),"","#123456"),
            (Method::PUT,"/api/accounts/profile",br#"{"name":"quoted \" \u00e9"}"#.as_slice(),"quoted \" é","#123456"),
            (Method::PUT,"/api/accounts/avatar",br#"{"avatarColor":"\u00e9abcde","id":"bob","name":"forged","key":"forged"}"#.as_slice(),"quoted \" é","éabcde"),
        ] {
            let mut headers=HeaderMap::new();
            headers.insert("authorization","Bearer fixture-profile-alice".parse().unwrap());
            let response=dispatch(State(app.clone()),method,path.parse().unwrap(),headers,Bytes::copy_from_slice(body)).await
                .unwrap_or_else(|_|panic!("Valid profile mutation failed."));
            assert_eq!(response.status(),StatusCode::OK);
            let bytes=axum::body::to_bytes(response.into_body(),MAX_REQUEST_BYTES).await.unwrap();
            let response:Value=serde_json::from_slice(&bytes).unwrap();
            assert!(response["name"]==name);
            assert!(response["avatarColor"]==avatar);
            assert!(response["id"]=="alice");
            assert!(response["email"]=="alice@example.test");
            assert_eq!(response["culture"],"en-US");
            let store=app.store.lock().unwrap();
            let account=store.account("id","alice").unwrap().unwrap();
            for field in ["id","email","key","keys","userKeyId","securityStamp","futureField"] {
                assert!(account[field]==original[field],"Profile mutation trusted an unrelated request field.");
            }
            assert!(store.account("id","bob").unwrap().unwrap()==foreign,"Profile mutation modified a foreign account.");
        }
        for path in ["/api/accounts/profile", "/api/sync"] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "authorization",
                "Bearer fixture-profile-alice".parse().unwrap(),
            );
            let response = dispatch(
                State(app.clone()),
                Method::GET,
                path.parse().unwrap(),
                headers,
                Bytes::new(),
            )
            .await
            .unwrap_or_else(|_| panic!("Profile metadata read failed."));
            let bytes = axum::body::to_bytes(response.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap();
            let response: Value = serde_json::from_slice(&bytes).unwrap();
            let profile = if path == "/api/sync" {
                &response["profile"]
            } else {
                &response
            };
            assert!(profile["name"] == "quoted \" é");
            assert!(profile["avatarColor"] == "éabcde");
        }
        let before = app
            .store
            .lock()
            .unwrap()
            .account("id", "alice")
            .unwrap()
            .unwrap();
        for (path, body, status) in [
            (
                "/api/accounts/avatar",
                br#"[]"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "/api/accounts/profile",
                br#"{"name":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}"#.as_slice(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "/api/accounts/avatar",
                br#"{"avatarColor":""}"#.as_slice(),
                StatusCode::BAD_REQUEST,
            ),
            (
                "/api/accounts/profile",
                br#"{"name":null}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "/api/accounts/avatar",
                br#"{"avatarColor":null,"avatarColor":null}"#.as_slice(),
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "authorization",
                "Bearer fixture-profile-alice".parse().unwrap(),
            );
            let result = dispatch(
                State(app.clone()),
                Method::PUT,
                path.parse().unwrap(),
                headers,
                Bytes::copy_from_slice(body),
            )
            .await;
            let Err(error) = result else {
                panic!("Invalid profile metadata mutation succeeded.")
            };
            assert_eq!(error.0, status);
            assert!(
                app.store
                    .lock()
                    .unwrap()
                    .account("id", "alice")
                    .unwrap()
                    .unwrap()
                    == before,
                "Rejected profile mutation changed account state."
            );
        }
    }

    #[test]
    fn account_key_input_matches_upstream_string_schema_and_sequence_order() {
        for (body, private, public) in [
            (br#"{"encryptedPrivateKey":"","publicKey":""}"#.as_slice(), "", ""),
            (br#"["wrapped-private","public"]"#.as_slice(), "wrapped-private", "public"),
            (br#"{"publicKey":"future public","encryptedPrivateKey":"quoted \" \u00e9","ignored":{"nested":true}}"#.as_slice(), "quoted \" é", "future public"),
        ] {
            let parsed = parse_account_keys_input(body).unwrap_or_else(|_| panic!("Valid account key input was rejected."));
            assert!(parsed.encrypted_private_key == private);
            assert!(parsed.public_key == public);
        }
        for (body, status) in [
            (b"{".as_slice(), StatusCode::BAD_REQUEST),
            (br#"{"publicKey":"x","encryptedPrivateKey":"\uD800"}"#.as_slice(), StatusCode::BAD_REQUEST),
            (br#"["private","public","extra"]"#.as_slice(), StatusCode::BAD_REQUEST),
            (b"{}".as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
            (b"null".as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"publicKey":"x"}"#.as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"encryptedPrivateKey":"x"}"#.as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"publicKey":null,"encryptedPrivateKey":"x"}"#.as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"publicKey":"x","encryptedPrivateKey":7}"#.as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"publicKey":"first","publicKey":"second","encryptedPrivateKey":"x"}"#.as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
            (br#"{"publicKey":"x","encryptedPrivateKey":"first","encryptedPrivate\u004bey":"second"}"#.as_slice(), StatusCode::UNPROCESSABLE_ENTITY),
        ] {
            let error = parse_account_keys_input(body).err().expect("Invalid account key input was accepted.");
            assert_eq!(error.0, status);
            assert_eq!(error.1, "Invalid request");
        }
    }

    #[tokio::test]
    async fn account_key_http_boundaries_authenticate_and_never_disclose_another_private_key() {
        const ALICE: &str = "f0c3f062-6368-4d80-8ec9-c9b8cc209749";
        const BOB: &str = "e3878851-41cc-40f7-a74f-b2c4042a54b9";
        let app = App {
            store: Arc::new(Mutex::new(Store::open(":memory:").unwrap())),
            base: "http://127.0.0.1".into(),
            signing_key: [1; 32],
        };
        {
            let store = app.store.lock().unwrap();
            for (id, public, private) in [
                (ALICE, "alice-public", "alice-wrapped-private"),
                (BOB, "bob-public", "bob-wrapped-private"),
            ] {
                store.db.execute("INSERT INTO accounts(id,email,document,password,revision) VALUES(?1,?2,?3,'test',?4)",
                    params![id, format!("{id}@example.test"), json!({"id":id,"email":format!("{id}@example.test"),"key":"wrapped-user-key","keys":{"publicKey":public,"encryptedPrivateKey":private}}).to_string(), store::now()]).unwrap();
            }
            store.db.execute("INSERT INTO sessions(access,refresh,owner,access_expires,refresh_expires) VALUES(?1,'unused-fixture-refresh',?2,?3,0)",
                params![digest("fixture-key-bearer"), ALICE, chrono::Utc::now().timestamp()+3_600]).unwrap();
        }
        let public_path = format!("/api/users/{BOB}/public-key");
        for (method, path, body) in [
            (Method::GET, "/api/accounts/keys", b"".as_slice()),
            (
                Method::POST,
                "/api/accounts/keys",
                br#"{"encryptedPrivateKey":"x","publicKey":"y"}"#.as_slice(),
            ),
            (Method::GET, public_path.as_str(), b"".as_slice()),
        ] {
            let result = dispatch(
                State(app.clone()),
                method,
                path.parse().unwrap(),
                HeaderMap::new(),
                Bytes::copy_from_slice(body),
            )
            .await;
            let Err(error) = result else {
                panic!("Anonymous account key request succeeded.")
            };
            assert_eq!(error.0, StatusCode::UNAUTHORIZED);
        }
        for (path, expected_fields, public) in [
            ("/api/accounts/keys", 5, "alice-public"),
            (public_path.as_str(), 3, "bob-public"),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "authorization",
                "Bearer fixture-key-bearer".parse().unwrap(),
            );
            let response = dispatch(
                State(app.clone()),
                Method::GET,
                path.parse().unwrap(),
                headers,
                Bytes::new(),
            )
            .await
            .unwrap_or_else(|_| panic!("Authenticated account key request failed."));
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = axum::body::to_bytes(response.into_body(), MAX_REQUEST_BYTES)
                .await
                .unwrap();
            let value: Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value.as_object().unwrap().len(), expected_fields);
            assert!(value["publicKey"] == public);
            assert!(
                !bytes
                    .windows(b"bob-wrapped-private".len())
                    .any(|part| part == b"bob-wrapped-private")
            );
            if path == public_path {
                assert!(value["userId"] == BOB);
                assert!(value.get("privateKey").is_none());
                assert!(value.get("key").is_none());
                assert!(value.get("accountKeys").is_none());
            }
        }
        let uppercase = format!("/api/users/{}/public-key", BOB.to_uppercase());
        for (path, status) in [
            (
                "/api/users/not-a-uuid/public-key",
                StatusCode::UNPROCESSABLE_ENTITY,
            ),
            (
                "/api/users/00000000-0000-0000-0000-000000000000/public-key",
                StatusCode::NOT_FOUND,
            ),
            (uppercase.as_str(), StatusCode::NOT_FOUND),
        ] {
            let mut headers = HeaderMap::new();
            headers.insert(
                "authorization",
                "Bearer fixture-key-bearer".parse().unwrap(),
            );
            let result = dispatch(
                State(app.clone()),
                Method::GET,
                path.parse().unwrap(),
                headers,
                Bytes::new(),
            )
            .await;
            let Err(error) = result else {
                panic!("Invalid public key lookup succeeded.")
            };
            assert_eq!(error.0, status);
        }
    }

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
        assert_eq!(remaining.len(), 4); // Two live authorities, refresh leeway and the new pair.
        assert!(remaining.iter().any(|access| access == "expiry-boundary"));
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
