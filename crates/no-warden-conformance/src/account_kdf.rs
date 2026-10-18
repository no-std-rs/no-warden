//! Exact nested account-KDF requests and fresh-client decoding after a rewrap.
//!
//! Vaultwarden58a980f850464f7d9cdc99a765df36f0a3308b91 accounts.rs690–793;
//! release1.37.4/7c188967 accounts.rs674–778. Neither accepts a legacy flat DTO.
//! Main normalizes the stored email for salt comparison; release compares it
//! directly. The ordinary lowercase fixture emails satisfy both contracts.
//! Server verifier algorithms, remembered2FA, notifications, storage rollback,
//! arbitrary existing stamp exceptions and successful Argon2 client derivation
//! remain separate. CLI checks follow an HTTP mutation; the CLI does not post it.
//! Private data never enters diagnostics or the authored/count-only receipts.

use crate::{capture, fixture, transport::TlsProxy};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Method, blocking::Client};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr},
    path::{Path, PathBuf},
    thread,
    time::Duration,
};
use tempfile::TempDir;
use uuid::Uuid;

const KDF: &str = "/api/accounts/kdf";
const MAX_REPLY: u64 = 16 * 1024 * 1024;
type Form = BTreeMap<String, String>;
type Case = fn(&mut Suite) -> Result<(), AccountKdfError>;
const CASES: [(&str, Case); 8] = [
    (
        "account_kdf_required_nested_schema_and_no_legacy_fallback",
        account_kdf_required_nested_schema_and_no_legacy_fallback,
    ),
    (
        "account_kdf_guard_precedence_and_wrong_old_proof",
        account_kdf_guard_precedence_and_wrong_old_proof,
    ),
    (
        "account_kdf_nested_equality_and_exact_salts",
        account_kdf_nested_equality_and_exact_salts,
    ),
    (
        "account_kdf_signed_limits_and_nonmutation",
        account_kdf_signed_limits_and_nonmutation,
    ),
    (
        "account_kdf_valid_pbkdf2_rewrap_and_session_revocation",
        account_kdf_valid_pbkdf2_rewrap_and_session_revocation,
    ),
    (
        "account_kdf_aliases_and_positional_update",
        account_kdf_aliases_and_positional_update,
    ),
    (
        "account_kdf_opaque_future_configuration_and_keys",
        account_kdf_opaque_future_configuration_and_keys,
    ),
    (
        "account_kdf_restore_and_preserve_account_vault_devices",
        account_kdf_restore_and_preserve_account_vault_devices,
    ),
];

/// Static diagnostics deliberately retain no underlying transport/process errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountKdfError(&'static str);
impl fmt::Display for AccountKdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for AccountKdfError {}
fn require(value: bool, message: &'static str) -> Result<(), AccountKdfError> {
    if value {
        Ok(())
    } else {
        Err(AccountKdfError(message))
    }
}
fn text(value: &Value) -> Result<&str, AccountKdfError> {
    value
        .as_str()
        .ok_or(AccountKdfError("Required KDF fixture string missing"))
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, AccountKdfError> {
        if self.status != expected {
            eprintln!(
                "KDF HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "KDF HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, AccountKdfError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| AccountKdfError("KDF response was not JSON"))
    }
    fn empty(self) -> Result<(), AccountKdfError> {
        require(self.bytes.is_empty(), "KDF success body was not empty")
    }
    fn rejected(self, status: u16) -> Result<(), AccountKdfError> {
        let response = self.status(status)?;
        // Rocket guard failures may use a non-JSON catcher. Discard that body.
        if let Ok(value) = serde_json::from_slice::<Value>(&response.bytes) {
            require(
                ["access_token", "refresh_token", "apiKey"]
                    .iter()
                    .all(|k| value.get(k).is_none()),
                "Rejected KDF response supplied credential authority",
            )?;
        }
        Ok(())
    }
}
struct Http {
    server: String,
    client: Client,
    requests: usize,
    identities: usize,
    logins: usize,
    refreshes: usize,
    creates: usize,
    polls: usize,
}
impl Http {
    fn new() -> Result<Self, AccountKdfError> {
        let server = std::env::var("BW_E2E_SERVER")
            .unwrap_or_else(|_| "http://127.0.0.1:8000".into())
            .trim_end_matches('/')
            .to_owned();
        let client = Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .local_address(IpAddr::V4(Ipv4Addr::LOCALHOST))
            .connect_timeout(Duration::from_secs(15))
            .timeout(Duration::from_secs(30))
            .build()
            .map_err(|_| AccountKdfError("KDF HTTP client initialization failed"))?;
        Ok(Self {
            server,
            client,
            requests: 0,
            identities: 0,
            logins: 0,
            refreshes: 0,
            creates: 0,
            polls: 0,
        })
    }
    fn read(response: reqwest::blocking::Response) -> Result<Reply, AccountKdfError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_REPLY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AccountKdfError("KDF HTTP response read failed"))?;
        require(
            bytes.len() as u64 <= MAX_REPLY,
            "KDF response exceeded capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn request(
        &mut self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&[u8]>,
        kind: Option<&str>,
    ) -> Result<Reply, AccountKdfError> {
        self.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.server));
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        if let Some(kind) = kind {
            request = request.header("device-type", kind);
        }
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        Self::read(
            request
                .send()
                .map_err(|_| AccountKdfError("KDF HTTP request failed"))?,
        )
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, AccountKdfError> {
        let body = body.map(Value::to_string);
        self.request(
            method,
            path,
            Some(token),
            body.as_deref().map(str::as_bytes),
            None,
        )?
        .status(200)?
        .json()
    }
    fn token(&mut self, form: &Form, expected: u16) -> Result<Value, AccountKdfError> {
        self.requests += 1;
        self.identities += 1;
        if form.get("grant_type").is_some_and(|v| v == "refresh_token") {
            self.refreshes += 1;
        }
        require(self.identities <= 9, "KDF identity request budget exceeded")?;
        let reply = Self::read(
            self.client
                .post(format!("{}/identity/connect/token", self.server))
                .form(form)
                .send()
                .map_err(|_| AccountKdfError("KDF identity request failed"))?,
        )?;
        if expected != 200 {
            reply.rejected(expected)?;
            return Ok(Value::Null);
        }
        self.logins += 1;
        reply.status(200)?.json()
    }
    fn login(&mut self, fixture: &Value, device: &str) -> Result<Session, AccountKdfError> {
        let tokens = self.token(&password_form(fixture, device)?, 200)?;
        let key = text(&fixture["key"])?;
        require(
            if key.is_empty() {
                tokens.get("Key").is_none()
            } else {
                tokens["Key"] == key
            },
            "Password token top-level wrapped-key presence differed",
        )?;
        require(
            tokens["Kdf"] == fixture["kdf"]
                && tokens["KdfIterations"] == fixture["kdfIterations"]
                && tokens["KdfMemory"] == fixture["kdfMemory"]
                && tokens["KdfParallelism"] == fixture["kdfParallelism"],
            "Password token KDF metadata differed",
        )?;
        require(
            tokens["UserDecryptionOptions"]["MasterPasswordUnlock"]["MasterKeyWrappedUserKey"]
                == key
                && tokens["UserDecryptionOptions"]["MasterPasswordUnlock"]["MasterKeyEncryptedUserKey"]
                    == key,
            "Password token nested wrapped key lost its opaque value",
        )?;
        Ok(Session {
            access: text(&tokens["access_token"])?.to_owned(),
            refresh: tokens["refresh_token"].as_str().map(str::to_owned),
            device: device.to_owned(),
        })
    }
}
#[derive(Clone)]
struct Session {
    access: String,
    refresh: Option<String>,
    device: String,
}
#[derive(Clone)]
struct Account {
    fixture: Value,
    password: String,
    id: String,
    current: Session,
}
#[derive(Clone, PartialEq)]
struct Snapshot {
    profile: Value,
    sync: Value,
    keys: Value,
    domains: Value,
    revision: i64,
}
#[derive(Clone)]
struct AuthRequest {
    code: String,
    wire: Value,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Receipt<'a> {
    schema_version: u8,
    status: &'static str,
    cases: &'a [&'static str],
    expected_cases: usize,
    passed_cases: usize,
    http_requests: usize,
    identity_requests: usize,
    successful_logins: usize,
    refresh_requests: usize,
    decoded_creation_attempts: usize,
    guard_valid_response_polls: usize,
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    sessions: Vec<Session>,
    target: Value,
    restored: Value,
    api_secret: String,
    auth: Vec<AuthRequest>,
    passed: Vec<&'static str>,
    receipt: Option<fs::File>,
    finished: bool,
}
impl Drop for Suite {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.receipt("failed");
        }
    }
}
impl Suite {
    fn receipt(&mut self, status: &'static str) -> Result<(), AccountKdfError> {
        if let Some(file) = &mut self.receipt {
            let record = Receipt {
                schema_version: 1,
                status,
                cases: &self.passed,
                expected_cases: CASES.len(),
                passed_cases: self.passed.len(),
                http_requests: self.http.requests,
                identity_requests: self.http.identities,
                successful_logins: self.http.logins,
                refresh_requests: self.http.refreshes,
                decoded_creation_attempts: self.http.creates,
                guard_valid_response_polls: self.http.polls,
            };
            write_receipt(file, &record)?;
        }
        Ok(())
    }
    fn snapshot(&mut self, owner: usize) -> Result<Snapshot, AccountKdfError> {
        snapshot(&mut self.http, &self.accounts[owner].current.access)
    }
    fn snapshots(&mut self) -> Result<Vec<Snapshot>, AccountKdfError> {
        (0..self.accounts.len()).map(|i| self.snapshot(i)).collect()
    }
    fn devices(&mut self) -> Result<Vec<Value>, AccountKdfError> {
        self.accounts
            .iter()
            .map(|a| {
                self.http
                    .json(Method::GET, "/api/devices", &a.current.access, None)
            })
            .collect()
    }
    fn unchanged(&mut self, before: &[Snapshot], devices: &[Value]) -> Result<(), AccountKdfError> {
        require(
            self.snapshots()? == before,
            "Rejected KDF change mutated accounts, keys or vaults",
        )?;
        require(
            self.devices()? == devices,
            "Rejected KDF change mutated devices",
        )
    }
    fn reject(
        &mut self,
        body: &Value,
        message: Option<&'static str>,
    ) -> Result<(), AccountKdfError> {
        let reply = self.http.request(
            Method::POST,
            KDF,
            Some(&self.accounts[0].current.access),
            Some(body.to_string().as_bytes()),
            None,
        )?;
        if let Some(message) = message {
            require(
                reply.status(400)?.json()?["message"] == message,
                "KDF validation error ordering differed",
            )
        } else {
            reply.rejected(400)
        }
    }
    fn reject_raw(&mut self, bodies: &[String], expected: u16) -> Result<(), AccountKdfError> {
        for (index, body) in bodies.iter().enumerate() {
            let reply = self.http.request(
                Method::POST,
                KDF,
                Some(&self.accounts[0].current.access),
                Some(body.as_bytes()),
                None,
            )?;
            if reply.status != expected {
                eprintln!("KDF JSON fixture {}, method POST", index + 1);
            }
            reply.rejected(expected)?;
        }
        Ok(())
    }
    fn prelogin(&mut self) -> Result<(), AccountKdfError> {
        let f = &self.accounts[0].fixture;
        let value = self
            .http
            .request(
                Method::POST,
                "/identity/accounts/prelogin",
                None,
                Some(json!({"email":f["email"]}).to_string().as_bytes()),
                None,
            )?
            .status(200)?
            .json()?;
        require(
            value
                == json!({"kdf":f["kdf"],"kdfIterations":f["kdfIterations"],"kdfMemory":f["kdfMemory"],"kdfParallelism":f["kdfParallelism"],"kdfSettings":settings(f),"salt":null}),
            "KDF prelogin projection differed",
        )
    }
    fn create_auth(&mut self, approve: bool) -> Result<(), AccountKdfError> {
        self.http.creates += 1;
        let code = format!("kdf-proof\0雪+{}", Uuid::new_v4());
        let body = json!({"accessCode":code,"deviceIdentifier":self.sessions[1].device,"email":self.accounts[0].fixture["email"],"publicKey":"opaque-kdf-request-public"});
        let mut wire = self
            .http
            .request(
                Method::POST,
                "/api/auth-requests",
                None,
                Some(body.to_string().as_bytes()),
                Some("8"),
            )?
            .status(200)?
            .json()?;
        wire["requestApproved"] = Value::Null;
        if approve {
            wire=self.http.json(Method::PUT,&format!("/api/auth-requests/{}",text(&wire["id"])?),&self.accounts[0].current.access,Some(&json!({"deviceIdentifier":self.accounts[0].current.device,"key":self.accounts[0].fixture["key"],"masterPasswordHash":"opaque-approved-kdf-proof","requestApproved":true})))?;
        }
        self.auth.push(AuthRequest { code, wire });
        Ok(())
    }
    fn retained_auth(&mut self) -> Result<(), AccountKdfError> {
        for record in self.auth.clone() {
            let path = format!("/api/auth-requests/{}", text(&record.wire["id"])?);
            require(
                self.http
                    .json(Method::GET, &path, &self.accounts[0].current.access, None)?
                    == record.wire,
                "KDF change altered an authentication request",
            )?;
            if record.wire["requestApproved"] == true {
                let mut url = reqwest::Url::parse("http://localhost/")
                    .map_err(|_| AccountKdfError("KDF poll query construction failed"))?;
                url.query_pairs_mut().append_pair("code", &record.code);
                self.http.polls += 1;
                let response = self
                    .http
                    .request(
                        Method::GET,
                        &format!(
                            "{path}/response?{}",
                            url.query()
                                .ok_or(AccountKdfError("KDF poll query missing"))?
                        ),
                        None,
                        None,
                        Some("8"),
                    )?
                    .status(200)?
                    .json()?;
                require(
                    response == record.wire,
                    "KDF change altered approved public polling",
                )?;
            }
        }
        require(
            self.http.creates + self.http.polls <= 10,
            "KDF public request budget exceeded",
        )
    }
    fn mutate(&mut self, target: Value, body: Value) -> Result<(), AccountKdfError> {
        let before = self.snapshot(0)?;
        let foreign = self.snapshot(1)?;
        let devices = self.devices()?;
        let old = self.accounts[0].clone();
        thread::sleep(Duration::from_millis(10));
        self.http
            .request(
                Method::POST,
                KDF,
                Some(&old.current.access),
                Some(body.to_string().as_bytes()),
                None,
            )?
            .status(200)?
            .empty()?;
        for session in self.sessions.clone() {
            self.http
                .request(Method::GET, "/api/sync", Some(&session.access), None, None)?
                .rejected(401)?;
        }
        self.accounts[0].fixture = target;
        // Reuse the same identifier: metadata survives, while an old signed token
        // must stay invalid even after that identifier successfully logs in again.
        let current = self
            .http
            .login(&self.accounts[0].fixture, &old.current.device)?;
        self.accounts[0].current = current.clone();
        self.sessions.push(current.clone());
        self.http
            .request(
                Method::GET,
                "/api/accounts/profile",
                Some(&old.current.access),
                None,
                None,
            )?
            .rejected(401)?;
        let after = self.snapshot(0)?;
        changed(&before, &after, &self.accounts[0].fixture)?;
        require(
            self.snapshot(1)? == foreign,
            "KDF change affected another account",
        )?;
        require(
            self.devices()? == devices,
            "KDF change deleted or changed device metadata",
        )?;
        let claims = jwt_claims(&current.access)?;
        require(
            claims["sstamp"] == after.profile["securityStamp"]
                && claims["device"] == old.current.device
                && claims["sub"] == old.id,
            "KDF recovery token stamp, device or owner differed",
        )?;
        self.prelogin()?;
        let proof = self.accounts[0].fixture["masterPasswordHash"].clone();
        let response = self.http.json(
            Method::POST,
            "/api/accounts/api-key",
            &current.access,
            Some(&json!({"masterPasswordHash":proof})),
        )?;
        require(
            response["apiKey"] == self.api_secret,
            "KDF change rotated the API-key secret",
        )?;
        let policy = self.http.json(
            Method::POST,
            "/api/accounts/verify-password",
            &current.access,
            Some(&json!({"masterPasswordHash":proof})),
        )?;
        require(
            policy == json!({"Object":"masterPasswordPolicy"}),
            "New KDF authentication proof did not verify",
        )?;
        self.http
            .request(
                Method::POST,
                "/api/accounts/verify-password",
                Some(&current.access),
                Some(
                    json!({"masterPasswordHash":old.fixture["masterPasswordHash"]})
                        .to_string()
                        .as_bytes(),
                ),
                None,
            )?
            .rejected(400)?;
        self.retained_auth()?;
        require(
            self.snapshot(0)? == after,
            "KDF credential checks changed account revision or vault data",
        )
    }
}
fn settings(f: &Value) -> Value {
    json!({"kdfType":f["kdf"],"iterations":f["kdfIterations"],"memory":f["kdfMemory"],"parallelism":f["kdfParallelism"]})
}
fn kdf_data(f: &Value) -> Value {
    json!({"kdf":f["kdf"],"kdfIterations":f["kdfIterations"],"kdfMemory":f["kdfMemory"],"kdfParallelism":f["kdfParallelism"]})
}
fn change_body(old: &Value, new: &Value) -> Value {
    json!({"authenticationData":{"salt":old["email"],"kdf":kdf_data(new),"masterPasswordAuthenticationHash":new["masterPasswordHash"]},"unlockData":{"salt":old["email"],"kdf":kdf_data(new),"masterKeyWrappedUserKey":new["key"]},"masterPasswordHash":old["masterPasswordHash"]})
}
fn password_form(f: &Value, device: &str) -> Result<Form, AccountKdfError> {
    Ok(BTreeMap::from([
        ("grant_type".into(), "password".into()),
        ("client_id".into(), "cli".into()),
        ("scope".into(), "api offline_access".into()),
        ("username".into(), text(&f["email"])?.to_owned()),
        (
            "password".into(),
            text(&f["masterPasswordHash"])?.to_owned(),
        ),
        ("deviceIdentifier".into(), device.to_owned()),
        ("deviceType".into(), "8".into()),
        ("deviceName".into(), "KDF comparison device".into()),
    ]))
}
fn jwt_claims(token: &str) -> Result<Value, AccountKdfError> {
    let part = token
        .split('.')
        .nth(1)
        .ok_or(AccountKdfError("KDF token lacked claims"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| AccountKdfError("KDF token claims were not encoded"))?;
    serde_json::from_slice(&bytes).map_err(|_| AccountKdfError("KDF token claims were not JSON"))
}
fn snapshot(http: &mut Http, token: &str) -> Result<Snapshot, AccountKdfError> {
    let profile = http.json(Method::GET, "/api/accounts/profile", token, None)?;
    let sync = http.json(Method::GET, "/api/sync", token, None)?;
    let keys = http.json(Method::GET, "/api/accounts/keys", token, None)?;
    let domains = http.json(Method::GET, "/api/settings/domains", token, None)?;
    let revision = http
        .json(Method::GET, "/api/accounts/revision-date", token, None)?
        .as_i64()
        .ok_or(AccountKdfError("KDF account revision was not an integer"))?;
    require(sync["profile"] == profile, "KDF profile and sync differed")?;
    Ok(Snapshot {
        profile,
        sync,
        keys,
        domains,
        revision,
    })
}
fn changed(before: &Snapshot, after: &Snapshot, new: &Value) -> Result<(), AccountKdfError> {
    let stamp = text(&after.profile["securityStamp"])?;
    require(
        Uuid::parse_str(stamp).is_ok()
            && after.profile["securityStamp"] != before.profile["securityStamp"]
            && after.revision > before.revision,
        "KDF change did not renew stamp and revision",
    )?;
    let mut expected = before.clone();
    expected.profile["securityStamp"] = json!(stamp);
    expected.profile["key"] = new["key"].clone();
    expected.sync["profile"] = expected.profile.clone();
    let unlock = &mut expected.sync["userDecryption"]["masterPasswordUnlock"];
    unlock["kdf"] = settings(new);
    unlock["masterKeyEncryptedUserKey"] = new["key"].clone();
    unlock["masterKeyWrappedUserKey"] = new["key"].clone();
    expected.keys["key"] = if text(&new["key"])?.is_empty() {
        Value::Null
    } else {
        new["key"].clone()
    };
    expected.revision = after.revision;
    require(
        *after == expected,
        "KDF change altered unrelated keys, vault, settings or account fields",
    )
}

fn account_kdf_required_nested_schema_and_no_legacy_fallback(
    s: &mut Suite,
) -> Result<(), AccountKdfError> {
    let before = s.snapshots()?;
    let devices = s.devices()?;
    let valid = change_body(&s.accounts[0].fixture, &s.target);
    let mut invalid: Vec<String> = [
        "null",
        "false",
        "7",
        "\"text\"",
        "{}",
        "[]",
        "[null,null,null]",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for field in ["authenticationData", "unlockData", "masterPasswordHash"] {
        let mut body = valid.clone();
        body.as_object_mut()
            .ok_or(AccountKdfError("KDF fixture shape missing"))?
            .remove(field);
        invalid.push(body.to_string());
        for value in [Value::Null, json!(7), json!(false)] {
            let mut body = valid.clone();
            body[field] = value;
            invalid.push(body.to_string());
        }
    }
    for (field, alias) in [
        ("authenticationData", "AuthenticationData"),
        ("unlockData", "UnlockData"),
        ("masterPasswordHash", "MasterPasswordHash"),
    ] {
        let mut body = valid.clone();
        let value = body
            .as_object_mut()
            .ok_or(AccountKdfError("KDF fixture shape missing"))?
            .remove(field)
            .ok_or(AccountKdfError("KDF field missing"))?;
        body[alias] = value;
        invalid.push(body.to_string());
    }
    invalid.push(json!({"masterPasswordHash":s.accounts[0].fixture["masterPasswordHash"],"newMasterPasswordHash":"ignored","key":"ignored","kdf":0,"kdfIterations":700000}).to_string());
    for (field, alias) in [
        ("salt", "Salt"),
        ("kdf", "Kdf"),
        ("masterKeyWrappedUserKey", "MasterKeyWrappedUserKey"),
    ] {
        let mut body = valid.clone();
        let value = body["unlockData"]
            .as_object_mut()
            .ok_or(AccountKdfError("KDF fixture shape missing"))?
            .remove(field)
            .ok_or(AccountKdfError("KDF field missing"))?;
        body["unlockData"][alias] = value;
        invalid.push(body.to_string());
    }
    let mut overflow = valid.clone();
    overflow["authenticationData"]["kdf"]["kdf"] = json!(2147483648_i64);
    invalid.push(overflow.to_string());
    invalid.push(format!("{{\"authenticationData\":{},\"unlockData\":{},\"masterPasswordHash\":\"a\",\"masterPasswordHa\\u0073h\":\"b\"}}",valid["authenticationData"],valid["unlockData"]));
    let mut duplicate = valid.clone();
    duplicate["authenticationData"] = json!({"salt":"a","Salt":"b","kdf":kdf_data(&s.target),"masterPasswordAuthenticationHash":"proof"});
    invalid.push(duplicate.to_string());
    s.reject_raw(&invalid, 422)?;
    s.reject_raw(
        &[
            String::new(),
            "{".into(),
            format!("{valid} trailing"),
            format!("{valid}{{}}"),
            format!(
                "[{},{},{},0]",
                valid["authenticationData"], valid["unlockData"], valid["masterPasswordHash"]
            ),
        ],
        400,
    )?;
    s.unchanged(&before, &devices)
}
fn account_kdf_guard_precedence_and_wrong_old_proof(s: &mut Suite) -> Result<(), AccountKdfError> {
    let before = s.snapshots()?;
    let devices = s.devices()?;
    let valid = change_body(&s.accounts[0].fixture, &s.target);
    for bearer in [None, Some("invalid-kdf-bearer")] {
        for body in ["{".to_owned(), valid.to_string()] {
            s.http
                .request(Method::POST, KDF, bearer, Some(body.as_bytes()), None)?
                .rejected(401)?;
        }
    }
    for proof in [
        json!(""),
        json!("wrong-old-proof\0雪"),
        s.accounts[1].fixture["masterPasswordHash"].clone(),
    ] {
        let mut body = valid.clone();
        body["masterPasswordHash"] = proof;
        body["authenticationData"]["salt"] = json!("wrong");
        body["unlockData"]["kdf"]["kdfIterations"] = json!(99999);
        s.reject(&body, Some("Invalid password"))?;
    }
    s.unchanged(&before, &devices)
}
fn account_kdf_nested_equality_and_exact_salts(s: &mut Suite) -> Result<(), AccountKdfError> {
    let before = s.snapshots()?;
    let devices = s.devices()?;
    let valid = change_body(&s.accounts[0].fixture, &s.target);
    for (field, value) in [
        ("kdf", json!(1)),
        ("kdfIterations", json!(700001)),
        ("kdfMemory", json!(1)),
        ("kdfParallelism", json!(1)),
    ] {
        let mut body = valid.clone();
        body["authenticationData"]["kdf"][field] = value;
        body["authenticationData"]["salt"] = json!("wrong");
        s.reject(
            &body,
            Some("KDF settings must be equal for authentication and unlock"),
        )?;
    }
    let email = text(&s.accounts[0].fixture["email"])?.to_owned();
    for (auth, unlock) in [
        (email.to_uppercase(), email.clone()),
        (email.clone(), email.to_uppercase()),
        (format!(" {email}"), format!(" {email}")),
        (String::new(), String::new()),
    ] {
        let mut body = valid.clone();
        body["authenticationData"]["salt"] = json!(auth);
        body["unlockData"]["salt"] = json!(unlock);
        s.reject(&body, Some("Invalid master password salt"))?;
    }
    s.unchanged(&before, &devices)
}
fn account_kdf_signed_limits_and_nonmutation(s: &mut Suite) -> Result<(), AccountKdfError> {
    let before = s.snapshots()?;
    let devices = s.devices()?;
    for kdf in [
        json!({"kdf":0,"kdfIterations":99999}),
        json!({"kdf":0,"kdfIterations":-1}),
        json!({"kdf":1,"kdfIterations":0,"kdfMemory":64,"kdfParallelism":4}),
        json!({"kdf":1,"kdfIterations":3,"kdfParallelism":4}),
        json!({"kdf":1,"kdfIterations":3,"kdfMemory":14,"kdfParallelism":4}),
        json!({"kdf":1,"kdfIterations":3,"kdfMemory":1025,"kdfParallelism":4}),
        json!({"kdf":1,"kdfIterations":3,"kdfMemory":64}),
        json!({"kdf":1,"kdfIterations":3,"kdfMemory":64,"kdfParallelism":0}),
        json!({"kdf":1,"kdfIterations":3,"kdfMemory":64,"kdfParallelism":17}),
    ] {
        let mut body = change_body(&s.accounts[0].fixture, &s.target);
        body["authenticationData"]["kdf"] = kdf.clone();
        body["unlockData"]["kdf"] = kdf;
        s.reject(&body, None)?;
    }
    s.unchanged(&before, &devices)
}
fn account_kdf_valid_pbkdf2_rewrap_and_session_revocation(
    s: &mut Suite,
) -> Result<(), AccountKdfError> {
    s.create_auth(false)?;
    s.create_auth(true)?;
    let refresh = s.sessions[0]
        .refresh
        .clone()
        .ok_or(AccountKdfError("Old KDF refresh fixture missing"))?;
    let mut body = change_body(&s.accounts[0].fixture, &s.target);
    body["id"] = json!(s.accounts[1].id);
    body["securityStamp"] = json!("forged");
    body["name"] = json!("ignored");
    body["kdf"] = json!(-100);
    body["key"] = json!("ignored-legacy-key");
    s.mutate(s.target.clone(), body)?;
    s.http.token(
        &Form::from([
            ("grant_type".into(), "refresh_token".into()),
            ("refresh_token".into(), refresh),
            ("client_id".into(), "cli".into()),
        ]),
        400,
    )?;
    Ok(())
}
fn account_kdf_aliases_and_positional_update(s: &mut Suite) -> Result<(), AccountKdfError> {
    let old = &s.accounts[0].fixture;
    let new = &s.restored;
    let aliases = json!({"kdfType":new["kdf"],"iterations":new["kdfIterations"],"memory":new["kdfMemory"],"parallelism":new["kdfParallelism"]});
    let body = json!([{"Salt":old["email"],"Kdf":aliases,"MasterPasswordAuthenticationHash":new["masterPasswordHash"]},[old["email"],[new["kdf"],new["kdfIterations"],new["kdfMemory"],new["kdfParallelism"]],new["key"]],old["masterPasswordHash"]]);
    s.mutate(s.restored.clone(), body)
}
fn account_kdf_opaque_future_configuration_and_keys(s: &mut Suite) -> Result<(), AccountKdfError> {
    let mut next = s.accounts[0].fixture.clone();
    next["kdf"] = json!(-7);
    next["kdfIterations"] = json!(-8);
    next["masterPasswordHash"] = json!("");
    next["key"] = json!("");
    next["kdfMemory"] = Value::Null;
    next["kdfParallelism"] = Value::Null;
    let mut body = change_body(&s.accounts[0].fixture, &next);
    for field in ["authenticationData", "unlockData"] {
        body[field]["kdf"]["kdfMemory"] = json!(-9);
        body[field]["kdf"]["kdfParallelism"] = json!(-10);
    }
    s.mutate(next, body)
}
fn account_kdf_restore_and_preserve_account_vault_devices(
    s: &mut Suite,
) -> Result<(), AccountKdfError> {
    let old = &s.accounts[0].fixture;
    let new = &s.restored;
    let body = json!({"authenticationData":[old["email"],[new["kdf"],new["kdfIterations"],new["kdfMemory"],new["kdfParallelism"]],new["masterPasswordHash"]],"unlockData":{"salt":old["email"],"kdf":kdf_data(new),"masterKeyWrappedUserKey":new["key"]},"masterPasswordHash":old["masterPasswordHash"]});
    s.mutate(s.restored.clone(), body)?;
    require(
        s.http.identities == 9 && s.http.logins == 8 && s.http.refreshes == 1,
        "Authored KDF identity counts changed",
    )
}

fn private_receipt(name: &str) -> Result<Option<fs::File>, AccountKdfError> {
    let Some(path) = std::env::var_os(name) else {
        return Ok(None);
    };
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| AccountKdfError("KDF private receipt creation failed"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| AccountKdfError("KDF private receipt permissions failed"))?;
    Ok(Some(file))
}
fn write_receipt(file: &mut fs::File, value: &impl Serialize) -> Result<(), AccountKdfError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| AccountKdfError("KDF receipt encoding failed"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| AccountKdfError("KDF receipt seek failed"))?;
    file.set_len(0)
        .map_err(|_| AccountKdfError("KDF receipt update failed"))?;
    file.write_all(&bytes)
        .map_err(|_| AccountKdfError("KDF receipt write failed"))?;
    file.sync_all()
        .map_err(|_| AccountKdfError("KDF receipt persistence failed"))
}
fn seed(http: &mut Http) -> Result<Account, AccountKdfError> {
    let email = format!("account-kdf-{}@example.test", Uuid::new_v4());
    let password = format!("Private-kdf-fixture-{}", Uuid::new_v4());
    let fixture = fixture::seed_account(&http.server, &email, &password)
        .map_err(|_| AccountKdfError("KDF fixture registration failed"))?;
    let current = http.login(&fixture, &Uuid::new_v4().to_string())?;
    let profile = http.json(Method::GET, "/api/accounts/profile", &current.access, None)?;
    let id = text(&profile["id"])?.to_owned();
    Ok(Account {
        fixture,
        password,
        id,
        current,
    })
}
fn cipher_fixture(http: &mut Http, a: &Account) -> Result<Value, AccountKdfError> {
    let name = fixture::encrypted_pbkdf2_value(&a.fixture, &a.password, b"Preexisting KDF note")
        .map_err(|_| AccountKdfError("KDF encrypted name fixture failed"))?;
    let notes = fixture::encrypted_pbkdf2_value(
        &a.fixture,
        &a.password,
        "Preserved Unicode note 雪\0 after rewrap".as_bytes(),
    )
    .map_err(|_| AccountKdfError("KDF encrypted notes fixture failed"))?;
    let folder = http.json(
        Method::POST,
        "/api/folders",
        &a.current.access,
        Some(&json!({"name":name})),
    )?;
    http.json(Method::POST,"/api/ciphers",&a.current.access,Some(&json!({"type":2,"name":name,"notes":notes,"folderId":folder["id"],"encryptedFor":a.id,"secureNote":{"type":0}})))
}
/// Eight selected HTTP cases, nine identity requests and no mutation/auth retries.
pub fn run() -> Result<(), AccountKdfError> {
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        sessions: Vec::new(),
        target: Value::Null,
        restored: Value::Null,
        api_secret: String::new(),
        auth: Vec::new(),
        passed: Vec::new(),
        receipt: private_receipt("BW_ACCOUNT_KDF_RECEIPT")?,
        finished: false,
    };
    s.receipt("running")?;
    for _ in 0..2 {
        let a = seed(&mut s.http)?;
        cipher_fixture(&mut s.http, &a)?;
        s.accounts.push(a);
    }
    let a = s.accounts[0].clone();
    s.sessions.push(a.current.clone());
    s.sessions
        .push(s.http.login(&a.fixture, &Uuid::new_v4().to_string())?);
    let api = s.http.json(
        Method::POST,
        "/api/accounts/api-key",
        &a.current.access,
        Some(&json!({"masterPasswordHash":a.fixture["masterPasswordHash"]})),
    )?;
    s.api_secret = text(&api["apiKey"])?.to_owned();
    let device = Uuid::new_v4().to_string();
    let result = s.http.token(
        &Form::from([
            ("grant_type".into(), "client_credentials".into()),
            ("client_id".into(), format!("user.{}", a.id)),
            ("client_secret".into(), s.api_secret.clone()),
            ("scope".into(), "api".into()),
            ("deviceIdentifier".into(), device.clone()),
            ("deviceName".into(), "KDF API device".into()),
            ("deviceType".into(), "8".into()),
        ]),
        200,
    )?;
    s.sessions.push(Session {
        access: text(&result["access_token"])?.to_owned(),
        refresh: None,
        device,
    });
    s.target = fixture::rewrap_pbkdf2(&a.fixture, &a.password, 700_000)
        .map_err(|_| AccountKdfError("KDF first rewrap fixture failed"))?;
    s.restored = fixture::rewrap_pbkdf2(&s.target, &a.password, 800_000)
        .map_err(|_| AccountKdfError("KDF second rewrap fixture failed"))?;
    for (name, case) in CASES {
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
        println!("PASS {name}");
    }
    s.receipt("passed")?;
    s.finished = true;
    println!("PASS account-KDF HTTP cases: {}", s.passed.len());
    Ok(())
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CliReceipt {
    schema_version: u8,
    status: &'static str,
    cli_version: &'static str,
    commands: usize,
    expected_commands: usize,
    direct_http_requests: usize,
    direct_identity_requests: usize,
    cli_login_commands: usize,
    registration_requests_included: bool,
    cli_internal_requests_included: bool,
    old_iterations: u32,
    new_iterations: u32,
}
struct Cli {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    commands: usize,
    receipt: Option<fs::File>,
    http_requests: usize,
    identities: usize,
    login_commands: usize,
    finished: bool,
}
impl Drop for Cli {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.receipt("failed");
        }
    }
}
impl Cli {
    fn receipt(&mut self, status: &'static str) -> Result<(), AccountKdfError> {
        if let Some(file) = &mut self.receipt {
            write_receipt(
                file,
                &CliReceipt {
                    schema_version: 1,
                    status,
                    cli_version: "2026.10.0",
                    commands: self.commands,
                    expected_commands: 9,
                    direct_http_requests: self.http_requests,
                    direct_identity_requests: self.identities,
                    cli_login_commands: self.login_commands,
                    registration_requests_included: false,
                    cli_internal_requests_included: false,
                    old_iterations: 600000,
                    new_iterations: 700000,
                },
            )?;
        }
        Ok(())
    }
    fn command(&mut self, args: &[&str]) -> Result<String, AccountKdfError> {
        self.commands += 1;
        if args.first() == Some(&"login") {
            self.login_commands += 1;
        }
        let args: Vec<OsString> = args.iter().map(OsString::from).collect();
        let result = capture::run(
            &self.binary,
            &args,
            &self.environment,
            Duration::from_secs(90),
        )
        .map_err(|_| AccountKdfError("KDF CLI capture failed"))?;
        if !result.status.success() {
            eprintln!(
                "KDF CLI command {} failed; status {:?}, stdout bytes {}, stderr bytes {}",
                self.commands,
                result.status.code(),
                result.stdout.len(),
                result.stderr_bytes
            );
        }
        require(result.status.success(), "KDF CLI command failed")?;
        self.receipt("running")?;
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| AccountKdfError("KDF CLI output was not UTF8"))
    }
    fn json(&mut self, args: &[&str]) -> Result<Value, AccountKdfError> {
        serde_json::from_str(&self.command(args)?)
            .map_err(|_| AccountKdfError("KDF CLI output was not JSON"))
    }
}
fn private_directory(prefix: &str) -> Result<TempDir, AccountKdfError> {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| AccountKdfError("KDF private directory creation failed"))?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .map_err(|_| AccountKdfError("KDF private directory permissions failed"))?;
    Ok(directory)
}
/// A separate focused official-client proof, outside the default HTTP group.
/// HTTP changes KDF first. A fresh CLI cache then authenticates, unlocks and
/// decrypts preexisting ciphertext. This does not attribute POST /accounts/kdf
/// to a CLI command, and leaves the existing full CLI runner unchanged.
pub fn run_cli() -> Result<(), AccountKdfError> {
    let appdata = private_directory("no-warden-kdf-cli-")?;
    let tls = private_directory("no-warden-kdf-tls-")?;
    let local = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/node_modules/.bin/bw");
    let binary = std::env::var_os("BW_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| if local.exists() { local } else { "bw".into() });
    let mut cli = Cli {
        binary,
        environment: std::env::vars_os().collect(),
        commands: 0,
        receipt: private_receipt("BW_ACCOUNT_KDF_CLI_RECEIPT")?,
        http_requests: 0,
        identities: 0,
        login_commands: 0,
        finished: false,
    };
    cli.receipt("running")?;
    for key in ["BW_SESSION", "BW_CLIENTID", "BW_CLIENTSECRET"] {
        cli.environment.remove(&OsString::from(key));
    }
    cli.environment.insert(
        "BITWARDENCLI_APPDATA_DIR".into(),
        appdata.path().as_os_str().to_owned(),
    );
    cli.environment
        .insert("BW_NOINTERACTION".into(), "true".into());
    let mut http = Http::new()?;
    let a = seed(&mut http)?;
    let cipher = cipher_fixture(&mut http, &a)?;
    let before = http.json(Method::GET, "/api/sync", &a.current.access, None)?;
    let new = fixture::rewrap_pbkdf2(&a.fixture, &a.password, 700000)
        .map_err(|_| AccountKdfError("CLI KDF rewrap fixture failed"))?;
    http.request(
        Method::POST,
        KDF,
        Some(&a.current.access),
        Some(change_body(&a.fixture, &new).to_string().as_bytes()),
        None,
    )?
    .status(200)?
    .empty()?;
    http.request(
        Method::GET,
        "/api/sync",
        Some(&a.current.access),
        None,
        None,
    )?
    .rejected(401)?;
    cli.http_requests = http.requests;
    cli.identities = http.identities;
    cli.environment
        .insert("BW_E2E_PASSWORD".into(), a.password.into());
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| AccountKdfError("KDF CLI TLS proxy startup failed"))?,
        )
    } else {
        None
    };
    let client_server = proxy
        .as_ref()
        .map_or(http.server.as_str(), TlsProxy::url)
        .to_owned();
    if let Some(proxy) = &proxy {
        cli.environment.insert(
            "NODE_EXTRA_CA_CERTS".into(),
            proxy.certificate().as_os_str().to_owned(),
        );
    }
    require(
        cli.command(&["--version"])? == "2026.10.0",
        "KDF CLI version differed",
    )?;
    cli.command(&["config", "server", &client_server])?;
    let unlocked = cli.command(&[
        "login",
        text(&a.fixture["email"])?,
        "--passwordenv",
        "BW_E2E_PASSWORD",
        "--raw",
    ])?;
    require(unlocked.len() > 20, "KDF CLI login did not unlock")?;
    cli.environment.insert("BW_SESSION".into(), unlocked.into());
    require(
        cli.json(&["status"])?["status"] == "unlocked",
        "KDF CLI fresh cache did not unlock",
    )?;
    cli.command(&["lock"])?;
    cli.environment.remove(&OsString::from("BW_SESSION"));
    let unlocked = cli.command(&["unlock", "--passwordenv", "BW_E2E_PASSWORD", "--raw"])?;
    require(unlocked.len() > 20, "KDF CLI second unlock failed")?;
    cli.environment.insert("BW_SESSION".into(), unlocked.into());
    cli.command(&["sync"])?;
    let fetched = cli.json(&["get", "item", text(&cipher["id"])?])?;
    require(
        fetched["name"] == "Preexisting KDF note"
            && fetched["notes"] == "Preserved Unicode note 雪\0 after rewrap"
            && fetched["secureNote"]["type"] == 0,
        "Fresh CLI could not decrypt the preserved user-key ciphertext",
    )?;
    // The HTTP group separately compares exact ciphertext after changes. Here
    // the preexisting fixture and the real client's decrypted result are proof;
    // the client's internal HTTP calls are not counted or attributed as traces.
    require(
        before["ciphers"]
            .as_array()
            .is_some_and(|items| items.iter().any(|item| item == &cipher)),
        "Preexisting KDF ciphertext was absent before mutation",
    )?;
    cli.command(&["logout"])?;
    require(
        cli.commands == 9 && cli.login_commands == 1 && http.identities == 1,
        "Focused KDF CLI command budget changed",
    )?;
    cli.receipt("passed")?;
    cli.finished = true;
    println!("PASS account-KDF fresh CLI commands: {}", cli.commands);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KdfShape {
        #[serde(alias = "kdfType")]
        kdf: i32,
        #[serde(alias = "iterations")]
        kdf_iterations: i32,
        #[serde(alias = "memory")]
        kdf_memory: Option<i32>,
        #[serde(alias = "parallelism")]
        kdf_parallelism: Option<i32>,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AuthShape {
        #[serde(alias = "Salt")]
        salt: String,
        #[serde(alias = "Kdf")]
        kdf: KdfShape,
        #[serde(alias = "MasterPasswordAuthenticationHash")]
        master_password_authentication_hash: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct UnlockShape {
        salt: String,
        kdf: KdfShape,
        master_key_wrapped_user_key: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ChangeShape {
        authentication_data: AuthShape,
        unlock_data: UnlockShape,
        master_password_hash: String,
    }
    #[test]
    fn kdf_nested_aliases_and_exact_sequence_order_match_upstream() {
        let shape:ChangeShape=serde_json::from_value(json!([{"Salt":"salt","Kdf":{"kdfType":-7,"iterations":-8},"MasterPasswordAuthenticationHash":"new"},["salt",[-7,-8,null,null],"wrapped"],"old"])).unwrap();
        assert!(
            shape.authentication_data.salt == "salt"
                && shape
                    .authentication_data
                    .master_password_authentication_hash
                    == "new"
                && shape.authentication_data.kdf.kdf == -7
                && shape.authentication_data.kdf.kdf_iterations == -8
        );
        assert!(
            shape.unlock_data.salt == "salt"
                && shape.unlock_data.kdf.kdf_memory.is_none()
                && shape.unlock_data.kdf.kdf_parallelism.is_none()
                && shape.unlock_data.master_key_wrapped_user_key == "wrapped"
                && shape.master_password_hash == "old"
        );
        let flat = json!({"masterPasswordHash":"old","newMasterPasswordHash":"new","key":"wrapped","kdf":0,"kdfIterations":700000});
        assert!(serde_json::from_value::<ChangeShape>(flat).is_err());
        assert!(
            serde_json::from_str::<KdfShape>("[0,700000]")
                .err()
                .unwrap()
                .is_data()
        );
        assert!(
            serde_json::from_str::<KdfShape>("[0,700000,null,null,0]")
                .err()
                .unwrap()
                .is_syntax()
        );
    }
    #[test]
    fn kdf_expected_projection_changes_only_wrapping_and_stamp() {
        let f = json!({"email":"a@example.test","kdf":0,"kdfIterations":700000,"kdfMemory":null,"kdfParallelism":null,"key":"new"});
        let before = Snapshot {
            profile: json!({"securityStamp":"old","key":"old","opaque":"preserved"}),
            sync: json!({"profile":{"securityStamp":"old","key":"old","opaque":"preserved"},"userDecryption":{"masterPasswordUnlock":{"kdf":{},"masterKeyEncryptedUserKey":"old","masterKeyWrappedUserKey":"old","salt":"a@example.test"}},"ciphers":[{"opaque":"untouched"}]}),
            keys: json!({"key":"old","privateKey":"preserved"}),
            domains: json!({}),
            revision: 1,
        };
        let mut after = before.clone();
        let stamp = Uuid::new_v4().to_string();
        after.profile["securityStamp"] = json!(stamp);
        after.profile["key"] = json!("new");
        after.sync["profile"] = after.profile.clone();
        after.sync["userDecryption"]["masterPasswordUnlock"]["kdf"] = settings(&f);
        after.sync["userDecryption"]["masterPasswordUnlock"]["masterKeyEncryptedUserKey"] =
            json!("new");
        after.sync["userDecryption"]["masterPasswordUnlock"]["masterKeyWrappedUserKey"] =
            json!("new");
        after.keys["key"] = json!("new");
        after.revision = 2;
        assert!(changed(&before, &after, &f).is_ok());
        after.sync["ciphers"][0]["opaque"] = json!("changed");
        assert!(changed(&before, &after, &f).is_err());
    }
    #[test]
    fn kdf_diagnostics_and_receipts_do_not_contain_private_data() {
        let marker = "private-kdf-marker";
        let error = Reply {
            status: 500,
            bytes: marker.as_bytes().to_vec(),
        }
        .status(200)
        .err()
        .unwrap();
        assert!(!format!("{error} {error:?}").contains(marker));
        let error = jwt_claims(marker).err().unwrap();
        assert!(!format!("{error} {error:?}").contains(marker));
        let receipt = CliReceipt {
            schema_version: 1,
            status: "passed",
            cli_version: "2026.10.0",
            commands: 9,
            expected_commands: 9,
            direct_http_requests: 8,
            direct_identity_requests: 1,
            cli_login_commands: 1,
            registration_requests_included: false,
            cli_internal_requests_included: false,
            old_iterations: 600000,
            new_iterations: 700000,
        };
        assert!(!serde_json::to_string(&receipt).unwrap().contains(marker));
    }
}
