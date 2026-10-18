//! Local conformance host. Production deployment requires the work in ROADMAP.md.
#![forbid(unsafe_code)]

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
    ApiError, VaultService,
    route::{self, Route},
    wire::{CipherRequest, FolderRequest, RegisterRequest},
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
    let app = App {
        store: Arc::new(Mutex::new(Store::open(&database)?)),
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
    if route == Route::Config {
        return Ok(json_response(protocol::config(&app.base)));
    }
    let mut store = app
        .store
        .lock()
        .map_err(|_| Failure(StatusCode::INTERNAL_SERVER_ERROR, "Storage unavailable"))?;
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
        let form: BTreeMap<String, String> =
            serde_urlencoded::from_bytes(&body).map_err(|_| invalid())?;
        let grant = form
            .get("grant_type")
            .map(String::as_str)
            .ok_or_else(invalid)?;
        let account = match grant {
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
            "object":"sync","profile":protocol::profile(&account),"folders":store.items(&owner,"folder")?,
            "ciphers":store.items(&owner,"cipher")?,"collections":[],"policies":[],"sends":[],
            "domains":{"object":"domains","equivalentDomains":[],"globalEquivalentDomains":[]},
            "userDecryption":protocol::user_decryption(&account)
        }))),
        Route::Folders | Route::Ciphers => {
            let kind = if route == Route::Folders {
                "folder"
            } else {
                "cipher"
            };
            Ok(json_response(
                json!({"object":"list","data":store.items(&owner,kind)?,"continuationToken":null}),
            ))
        }
        Route::FolderGet(id) | Route::CipherGet(id) => {
            let kind = if matches!(route, Route::FolderGet(_)) {
                "folder"
            } else {
                "cipher"
            };
            Ok(json_response(
                store.item(&owner, id, kind)?.ok_or_else(missing)?,
            ))
        }
        Route::FolderCreate | Route::FolderUpdate(_) => {
            let document: Value = serde_json::from_slice(&body).map_err(|_| invalid())?;
            let request = FolderRequest::deserialize(&document).map_err(|_| invalid())?;
            store.pending = document.clone();
            let id = match route {
                Route::FolderUpdate(id) => id.to_owned(),
                _ => uuid::Uuid::new_v4().to_string(),
            };
            let mut service = VaultService::new(&mut *store);
            if matches!(route, Route::FolderUpdate(_)) {
                service.update_folder(&owner, &id, &request)?;
            } else {
                service.create_folder(&owner, &id, &request)?;
            }
            Ok(json_response(
                store.item(&owner, &id, "folder")?.ok_or_else(missing)?,
            ))
        }
        Route::FolderDelete(id) => {
            VaultService::new(&mut *store).delete_folder(&owner, id)?;
            Ok(StatusCode::NO_CONTENT.into_response())
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

fn issue_tokens(app: &App, db: &rusqlite::Connection, account: &Value) -> Result<Value, Failure> {
    let timestamp = chrono::Utc::now().timestamp();
    db.execute(
        "DELETE FROM sessions WHERE access_expires<=?1 AND refresh_expires<=?1",
        [timestamp],
    )?;
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","typ":"JWT"}"#);
    let claims = json!({"sub":account["id"],"email":account["email"],"email_verified":true,
        "name":account["name"],"premium":true,"iss":app.base,"iat":timestamp,"nbf":timestamp,"exp":timestamp+3600,
        "client_id":"cli","scope":["api","offline_access"],"amr":["Application"],"sstamp":account["id"],"jti":random_token()});
    let unsigned = format!("{header}.{}", URL_SAFE_NO_PAD.encode(claims.to_string()));
    let mut mac = Hmac::<Sha256>::new_from_slice(&app.signing_key).expect("HMAC key size");
    mac.update(unsigned.as_bytes());
    let access = format!(
        "{unsigned}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    );
    let refresh = random_token();
    db.execute("INSERT INTO sessions(access,refresh,owner,access_expires,refresh_expires) VALUES(?1,?2,?3,?4,?5)",params![digest(&access),digest(&refresh),account["id"].as_str(),timestamp+3600,timestamp+30*24*3600])?;
    let mut response = protocol::token_fields(account);
    response["access_token"] = json!(access);
    response["refresh_token"] = json!(refresh);
    response["token_type"] = json!("Bearer");
    response["expires_in"] = json!(3600);
    response["scope"] = json!("api offline_access");
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;

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
                .replace("{id}", "inventory-id");
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
