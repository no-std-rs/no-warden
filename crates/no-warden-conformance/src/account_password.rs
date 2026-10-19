//! Password changes and the exact previous-stamp exception lifecycle.
//!
//! Vaultwarden58a980f850464f7d9cdc99a765df36f0a3308b91 accounts.rs620–688,
//! user.rs201–250 and auth.rs679–711; release1.37.4/7c188967 matches, apart
//! from an event enum cast. Nested KDF values are compared but not applied.
//! Only the existing public-key route is tested as an exception; rotation,
//! emergency contacts and /webauthn remain separate endpoint capabilities.
//! Hints are submitted but their hidden persistence needs provider tests.
//! Diagnostics/receipts contain only authored names, status and numeric counts.

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
    time::{Duration, Instant},
};
use tempfile::TempDir;
use uuid::Uuid;
const PASSWORD: &str = "/api/accounts/password";
const MAX_REPLY: u64 = 16 * 1024 * 1024;
type Form = BTreeMap<String, String>;
type Case = fn(&mut Suite) -> Result<(), AccountPasswordError>;
const CASES: [(&str, Case); 8] = [
    (
        "account_password_schema_and_authenticated_guards",
        account_password_schema_and_authenticated_guards,
    ),
    (
        "account_password_old_proof_and_nested_validation",
        account_password_old_proof_and_nested_validation,
    ),
    (
        "account_password_nested_precedence_and_opaque_hint",
        account_password_nested_precedence_and_opaque_hint,
    ),
    (
        "account_password_prior_stamp_route_and_refresh_authority",
        account_password_prior_stamp_route_and_refresh_authority,
    ),
    (
        "account_password_exception_survives_kdf_and_reset",
        account_password_exception_survives_kdf_and_reset,
    ),
    (
        "account_password_repeated_change_overwrites_exception",
        account_password_repeated_change_overwrites_exception,
    ),
    (
        "account_password_partial_nested_legacy_fallback_and_opaque_values",
        account_password_partial_nested_legacy_fallback_and_opaque_values,
    ),
    (
        "account_password_exception_expiry_and_owner_isolation",
        account_password_exception_expiry_and_owner_isolation,
    ),
];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountPasswordError(&'static str);
impl fmt::Display for AccountPasswordError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for AccountPasswordError {}
fn require(value: bool, message: &'static str) -> Result<(), AccountPasswordError> {
    if value {
        Ok(())
    } else {
        Err(AccountPasswordError(message))
    }
}
fn text(value: &Value) -> Result<&str, AccountPasswordError> {
    value.as_str().ok_or(AccountPasswordError(
        "Required password fixture string missing",
    ))
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, AccountPasswordError> {
        if self.status != expected {
            eprintln!(
                "Password HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Password HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, AccountPasswordError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| AccountPasswordError("Password response was not JSON"))
    }
    fn empty(self) -> Result<(), AccountPasswordError> {
        require(self.bytes.is_empty(), "Password success body was not empty")
    }
    fn rejected(self, status: u16) -> Result<(), AccountPasswordError> {
        let response = self.status(status)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&response.bytes) {
            require(
                ["access_token", "refresh_token", "apiKey"]
                    .iter()
                    .all(|k| value.get(k).is_none()),
                "Rejected password response supplied credential authority",
            )?;
        }
        Ok(())
    }
}
struct Http {
    server: String,
    clients: [Client; 2],
    peer: usize,
    requests: usize,
    identities: usize,
    logins: usize,
    refreshes: usize,
    successful_refreshes: usize,
    per_peer: [usize; 2],
    creates: usize,
    polls: usize,
}
impl Http {
    fn new() -> Result<Self, AccountPasswordError> {
        let server = std::env::var("BW_E2E_SERVER")
            .unwrap_or_else(|_| "http://127.0.0.1:8000".into())
            .trim_end_matches('/')
            .to_owned();
        let client = |last| {
            Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .local_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, last)))
                .connect_timeout(Duration::from_secs(15))
                .timeout(Duration::from_secs(30))
                .build()
                .map_err(|_| AccountPasswordError("Password HTTP client initialization failed"))
        };
        Ok(Self {
            server,
            clients: [client(1)?, client(2)?],
            peer: 0,
            requests: 0,
            identities: 0,
            logins: 0,
            refreshes: 0,
            successful_refreshes: 0,
            per_peer: [0; 2],
            creates: 0,
            polls: 0,
        })
    }
    fn read(response: reqwest::blocking::Response) -> Result<Reply, AccountPasswordError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_REPLY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AccountPasswordError("Password response read failed"))?;
        require(
            bytes.len() as u64 <= MAX_REPLY,
            "Password response exceeded capture limit",
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
    ) -> Result<Reply, AccountPasswordError> {
        self.requests += 1;
        let mut request = self.clients[self.peer].request(method, format!("{}{path}", self.server));
        if let Some(b) = bearer {
            request = request.bearer_auth(b);
        }
        if let Some(k) = kind {
            request = request.header("device-type", k);
        }
        if let Some(b) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(b.to_vec());
        }
        Self::read(
            request
                .send()
                .map_err(|_| AccountPasswordError("Password HTTP request failed"))?,
        )
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, AccountPasswordError> {
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
    fn token(&mut self, form: &Form, expected: u16) -> Result<Value, AccountPasswordError> {
        self.requests += 1;
        self.identities += 1;
        self.per_peer[self.peer] += 1;
        let refresh = form.get("grant_type").is_some_and(|v| v == "refresh_token");
        if refresh {
            self.refreshes += 1;
        }
        require(
            self.per_peer[self.peer] <= 6,
            "Password identity peer budget exceeded",
        )?;
        let reply = Self::read(
            self.clients[self.peer]
                .post(format!("{}/identity/connect/token", self.server))
                .form(form)
                .send()
                .map_err(|_| AccountPasswordError("Password identity request failed"))?,
        )?;
        if expected != 200 {
            reply.rejected(expected)?;
            return Ok(Value::Null);
        }
        if refresh {
            self.successful_refreshes += 1;
        } else {
            self.logins += 1;
        }
        reply.status(200)?.json()
    }
    fn login(&mut self, f: &Value, device: &str) -> Result<Session, AccountPasswordError> {
        let tokens = self.token(&password_form(f, device)?, 200)?;
        let key = text(&f["key"])?;
        require(
            if key.is_empty() {
                tokens.get("Key").is_none()
            } else {
                tokens["Key"] == key
            },
            "Password recovery wrapped-key presence differed",
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
    successful_refreshes: usize,
    max_identity_requests_per_peer: usize,
    decoded_creation_attempts: usize,
    guard_valid_response_polls: usize,
    expiry_wait_seconds: u64,
    latest_expiry_wait_seconds: u64,
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    target: Value,
    target_password: String,
    after_kdf: Value,
    restored: Value,
    restored_password: String,
    original: Vec<Session>,
    first_new: Option<Session>,
    second_new: Option<Session>,
    api_secret: String,
    auth: Vec<AuthRequest>,
    expiry_start: Instant,
    expiry_wait: u64,
    latest_change: Option<Instant>,
    latest_expiry_wait: u64,
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
    fn receipt(&mut self, status: &'static str) -> Result<(), AccountPasswordError> {
        if let Some(file) = &mut self.receipt {
            write_receipt(
                file,
                &Receipt {
                    schema_version: 1,
                    status,
                    cases: &self.passed,
                    expected_cases: 8,
                    passed_cases: self.passed.len(),
                    http_requests: self.http.requests,
                    identity_requests: self.http.identities,
                    successful_logins: self.http.logins,
                    refresh_requests: self.http.refreshes,
                    successful_refreshes: self.http.successful_refreshes,
                    max_identity_requests_per_peer: *self.http.per_peer.iter().max().unwrap_or(&0),
                    decoded_creation_attempts: self.http.creates,
                    guard_valid_response_polls: self.http.polls,
                    expiry_wait_seconds: self.expiry_wait,
                    latest_expiry_wait_seconds: self.latest_expiry_wait,
                },
            )?;
        }
        Ok(())
    }
    fn snapshot(&mut self, owner: usize) -> Result<Snapshot, AccountPasswordError> {
        snapshot(&mut self.http, &self.accounts[owner].current.access)
    }
    fn snapshots(&mut self) -> Result<Vec<Snapshot>, AccountPasswordError> {
        (0..2).map(|i| self.snapshot(i)).collect()
    }
    fn devices(&mut self) -> Result<Vec<Value>, AccountPasswordError> {
        (0..2)
            .map(|i| {
                self.http.json(
                    Method::GET,
                    "/api/devices",
                    &self.accounts[i].current.access,
                    None,
                )
            })
            .collect()
    }
    fn unchanged(
        &mut self,
        before: &[Snapshot],
        devices: &[Value],
    ) -> Result<(), AccountPasswordError> {
        require(
            self.snapshots()? == before,
            "Rejected password change altered account, keys or vault",
        )?;
        require(
            self.devices()? == devices,
            "Rejected password change altered devices",
        )
    }
    fn public_key(&mut self, token: &str, expected: u16) -> Result<(), AccountPasswordError> {
        let b = &self.accounts[1];
        let response = self.http.request(
            Method::GET,
            &format!("/api/users/{}/public-key", b.id),
            Some(token),
            None,
            None,
        )?;
        if expected == 200 {
            require(
                response.status(200)?.json()?
                    == json!({"userId":b.id,"publicKey":b.fixture["keys"]["publicKey"],"object":"userKey"}),
                "Previous-stamp public-key projection differed",
            )
        } else {
            response.rejected(expected)
        }
    }
    fn reject(&mut self, body: &Value, message: &'static str) -> Result<(), AccountPasswordError> {
        let response = self
            .http
            .request(
                Method::POST,
                PASSWORD,
                Some(&self.accounts[0].current.access),
                Some(body.to_string().as_bytes()),
                None,
            )?
            .status(400)?
            .json()?;
        require(
            response["message"] == message,
            "Password validation ordering differed",
        )
    }
    fn reject_raw(&mut self, bodies: &[String], expected: u16) -> Result<(), AccountPasswordError> {
        for (index, body) in bodies.iter().enumerate() {
            let r = self.http.request(
                Method::POST,
                PASSWORD,
                Some(&self.accounts[0].current.access),
                Some(body.as_bytes()),
                None,
            )?;
            if r.status != expected {
                eprintln!("Password JSON fixture {}, method POST", index + 1);
            }
            r.rejected(expected)?;
        }
        Ok(())
    }
    fn create_auth(&mut self, approve: bool) -> Result<(), AccountPasswordError> {
        let previous = self.http.peer;
        self.http.peer = 0;
        self.http.creates += 1;
        let code = format!("password-proof\0雪+{}", Uuid::new_v4());
        let body = json!({"accessCode":code,"deviceIdentifier":self.original[1].device,"email":self.accounts[0].fixture["email"],"publicKey":"opaque-password-request-key"});
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
            wire=self.http.json(Method::PUT,&format!("/api/auth-requests/{}",text(&wire["id"])?),&self.accounts[0].current.access,Some(&json!({"deviceIdentifier":self.accounts[0].current.device,"key":self.accounts[0].fixture["key"],"masterPasswordHash":"opaque-approved-password-proof","requestApproved":true})))?;
        }
        self.auth.push(AuthRequest { code, wire });
        self.http.peer = previous;
        Ok(())
    }
    fn retained(&mut self) -> Result<(), AccountPasswordError> {
        let previous = self.http.peer;
        self.http.peer = 0;
        for record in self.auth.clone() {
            let path = format!("/api/auth-requests/{}", text(&record.wire["id"])?);
            require(
                self.http
                    .json(Method::GET, &path, &self.accounts[0].current.access, None)?
                    == record.wire,
                "Password change altered an auth request",
            )?;
            if record.wire["requestApproved"] == true {
                let mut url = reqwest::Url::parse("http://localhost/")
                    .map_err(|_| AccountPasswordError("Password poll query failed"))?;
                url.query_pairs_mut().append_pair("code", &record.code);
                self.http.polls += 1;
                let result = self
                    .http
                    .request(
                        Method::GET,
                        &format!(
                            "{path}/response?{}",
                            url.query()
                                .ok_or(AccountPasswordError("Password poll query missing"))?
                        ),
                        None,
                        None,
                        Some("8"),
                    )?
                    .status(200)?
                    .json()?;
                require(
                    result == record.wire,
                    "Password change altered approved polling",
                )?;
            }
        }
        require(
            self.http.creates + self.http.polls <= 12,
            "Password public request budget exceeded",
        )?;
        self.http.peer = previous;
        Ok(())
    }
    fn mutate(&mut self, new: Value, body: Value) -> Result<Session, AccountPasswordError> {
        let before = self.snapshot(0)?;
        let foreign = self.snapshot(1)?;
        let devices = self.devices()?;
        let old = self.accounts[0].current.clone();
        let old_proof = self.accounts[0].fixture["masterPasswordHash"].clone();
        thread::sleep(Duration::from_millis(10));
        self.http
            .request(
                Method::POST,
                PASSWORD,
                Some(&old.access),
                Some(body.to_string().as_bytes()),
                None,
            )?
            .status(200)?
            .empty()?;
        self.latest_change = Some(Instant::now());
        self.public_key(&old.access, 200)?;
        self.http
            .request(Method::GET, "/api/sync", Some(&old.access), None, None)?
            .rejected(401)?;
        self.accounts[0].fixture = new;
        self.http.peer = 1;
        let current = self.http.login(&self.accounts[0].fixture, &old.device)?;
        self.accounts[0].current = current;
        let after = self.snapshot(0)?;
        changed(&before, &after, &self.accounts[0].fixture)?;
        require(
            self.snapshot(1)? == foreign,
            "Password change affected another owner",
        )?;
        require(
            self.devices()? == devices,
            "Password change changed registered devices",
        )?;
        self.retained()?;
        let proof = self.accounts[0].fixture["masterPasswordHash"].clone();
        let key = self.http.json(
            Method::POST,
            "/api/accounts/api-key",
            &self.accounts[0].current.access,
            Some(&json!({"masterPasswordHash":proof})),
        )?;
        require(
            key["apiKey"] == self.api_secret,
            "Password change rotated the API secret",
        )?;
        self.http
            .request(
                Method::POST,
                "/api/accounts/verify-password",
                Some(&self.accounts[0].current.access),
                Some(
                    json!({"masterPasswordHash":self.accounts[0].fixture["masterPasswordHash"]})
                        .to_string()
                        .as_bytes(),
                ),
                None,
            )?
            .status(200)?;
        self.http
            .request(
                Method::POST,
                "/api/accounts/verify-password",
                Some(&self.accounts[0].current.access),
                Some(
                    json!({"masterPasswordHash":old_proof})
                        .to_string()
                        .as_bytes(),
                ),
                None,
            )?
            .rejected(400)?;
        require(
            self.snapshot(0)? == after,
            "Password credential checks changed account revision",
        )?;
        Ok(old)
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
fn legacy_body(old: &Value, new: &Value) -> Value {
    json!({"masterPasswordHash":old["masterPasswordHash"],"newMasterPasswordHash":new["masterPasswordHash"],"key":new["key"]})
}
fn password_form(f: &Value, device: &str) -> Result<Form, AccountPasswordError> {
    Ok(Form::from([
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
        ("deviceName".into(), "Password comparison device".into()),
    ]))
}
fn jwt_claims(token: &str) -> Result<Value, AccountPasswordError> {
    let part = token
        .split('.')
        .nth(1)
        .ok_or(AccountPasswordError("Password token lacked claims"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .map_err(|_| AccountPasswordError("Password token claims encoding differed"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| AccountPasswordError("Password token claims were not JSON"))
}
fn snapshot(http: &mut Http, token: &str) -> Result<Snapshot, AccountPasswordError> {
    let profile = http.json(Method::GET, "/api/accounts/profile", token, None)?;
    let sync = http.json(Method::GET, "/api/sync", token, None)?;
    let keys = http.json(Method::GET, "/api/accounts/keys", token, None)?;
    let domains = http.json(Method::GET, "/api/settings/domains", token, None)?;
    let revision = http
        .json(Method::GET, "/api/accounts/revision-date", token, None)?
        .as_i64()
        .ok_or(AccountPasswordError(
            "Password account revision was not numeric",
        ))?;
    require(
        sync["profile"] == profile,
        "Password profile and sync differed",
    )?;
    Ok(Snapshot {
        profile,
        sync,
        keys,
        domains,
        revision,
    })
}
fn changed(before: &Snapshot, after: &Snapshot, new: &Value) -> Result<(), AccountPasswordError> {
    let stamp = text(&after.profile["securityStamp"])?;
    require(
        Uuid::parse_str(stamp).is_ok()
            && after.profile["securityStamp"] != before.profile["securityStamp"]
            && after.revision > before.revision,
        "Credential transition did not renew stamp and revision",
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
        "Credential transition altered unrelated keys, vault or settings",
    )
}

fn account_password_schema_and_authenticated_guards(
    s: &mut Suite,
) -> Result<(), AccountPasswordError> {
    let before = s.snapshots()?;
    let devices = s.devices()?;
    let valid = change_body(&s.accounts[0].fixture, &s.target);
    let mut bad: Vec<String> = [
        "null",
        "false",
        "7",
        "\"text\"",
        "{}",
        "[]",
        "[null]",
        "{\"MasterPasswordHash\":\"a\"}",
        "{\"masterPasswordHash\":null}",
        "{\"masterPasswordHash\":7}",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    for field in [
        "masterPasswordHint",
        "authenticationData",
        "unlockData",
        "newMasterPasswordHash",
        "key",
    ] {
        let mut b = valid.clone();
        b[field] = json!(7);
        bad.push(b.to_string());
    }
    bad.push(String::from(
        "{\"masterPasswordHash\":\"a\",\"masterPasswordHa\\u0073h\":\"b\"}",
    ));
    let mut malformed = legacy_body(&s.accounts[0].fixture, &s.target);
    malformed["authenticationData"] = json!({});
    bad.push(malformed.to_string());
    s.reject_raw(&bad, 422)?;
    s.reject_raw(
        &[
            String::new(),
            "{".into(),
            format!("{valid} trailing"),
            "[\"a\",null,null,null,null,null,0]".into(),
        ],
        400,
    )?;
    for bearer in [None, Some("invalid-password-bearer")] {
        for b in ["{".to_owned(), valid.to_string()] {
            s.http
                .request(Method::POST, PASSWORD, bearer, Some(b.as_bytes()), None)?
                .rejected(401)?;
        }
    }
    s.unchanged(&before, &devices)
}
fn account_password_old_proof_and_nested_validation(
    s: &mut Suite,
) -> Result<(), AccountPasswordError> {
    let before = s.snapshots()?;
    let devices = s.devices()?;
    let valid = change_body(&s.accounts[0].fixture, &s.target);
    for proof in [
        json!(""),
        json!("wrong-proof\0雪"),
        s.accounts[1].fixture["masterPasswordHash"].clone(),
    ] {
        let mut b = valid.clone();
        b["masterPasswordHash"] = proof;
        b["authenticationData"]["salt"] = json!("wrong");
        b["authenticationData"]["kdf"]["kdf"] = json!(-7);
        s.reject(&b, "Invalid password")?;
    }
    for field in ["kdf", "kdfIterations", "kdfMemory", "kdfParallelism"] {
        let mut b = valid.clone();
        b["authenticationData"]["kdf"][field] = json!(-9);
        b["authenticationData"]["salt"] = json!("wrong");
        b["newMasterPasswordHash"] = json!("ignored");
        b["key"] = json!("ignored");
        s.reject(
            &b,
            "KDF settings must be equal for authentication and unlock",
        )?;
    }
    for field in ["authenticationData", "unlockData"] {
        let mut b = valid.clone();
        b[field]["salt"] = json!(text(&s.accounts[0].fixture["email"])?.to_uppercase());
        s.reject(&b, "Invalid master password salt")?;
    }
    s.reject(
        &json!({"masterPasswordHash":s.accounts[0].fixture["masterPasswordHash"]}),
        "Invalid request!",
    )?;
    s.unchanged(&before, &devices)
}
fn account_password_nested_precedence_and_opaque_hint(
    s: &mut Suite,
) -> Result<(), AccountPasswordError> {
    s.create_auth(false)?;
    s.create_auth(true)?;
    let mut body = change_body(&s.accounts[0].fixture, &s.target);
    for f in ["authenticationData", "unlockData"] {
        body[f]["kdf"] = json!({"kdf":-7,"kdfIterations":-8,"kdfMemory":-9,"kdfParallelism":-10});
    }
    body["masterPasswordHint"] = json!(" \t opaque hint\0雪 \n ");
    body["newMasterPasswordHash"] = json!("ignored-legacy-proof");
    body["key"] = json!("ignored-legacy-key");
    body["securityStamp"] = json!("forged");
    body["id"] = json!(s.accounts[1].id);
    s.mutate(s.target.clone(), body)?;
    s.accounts[0].password = s.target_password.clone();
    s.first_new = Some(s.accounts[0].current.clone());
    Ok(())
}
fn account_password_prior_stamp_route_and_refresh_authority(
    s: &mut Suite,
) -> Result<(), AccountPasswordError> {
    for old in s.original.clone() {
        s.public_key(&old.access, 200)?;
        s.http
            .request(
                Method::GET,
                "/api/accounts/profile",
                Some(&old.access),
                None,
                None,
            )?
            .rejected(401)?;
    }
    let refresh = s.original[0]
        .refresh
        .clone()
        .ok_or(AccountPasswordError("Old password refresh fixture missing"))?;
    s.http.peer = 0;
    s.http.token(
        &Form::from([
            ("grant_type".into(), "refresh_token".into()),
            ("refresh_token".into(), refresh),
            ("client_id".into(), "cli".into()),
        ]),
        400,
    )?;
    s.http.peer = 1;
    let current = s.accounts[0].current.clone();
    let form = Form::from([
        ("grant_type".into(), "refresh_token".into()),
        (
            "refresh_token".into(),
            current
                .refresh
                .clone()
                .ok_or(AccountPasswordError("New refresh fixture missing"))?,
        ),
        ("client_id".into(), "cli".into()),
    ]);
    let tokens = s.http.token(&form, 200)?;
    let refreshed = Session {
        access: text(&tokens["access_token"])?.to_owned(),
        refresh: tokens["refresh_token"].as_str().map(str::to_owned),
        device: current.device,
    };
    require(
        jwt_claims(&refreshed.access)?["sstamp"] == jwt_claims(&current.access)?["sstamp"],
        "Refresh changed password exception stamp",
    )?;
    s.accounts[0].current = refreshed;
    s.public_key(&s.original[0].access.clone(), 200)
}
fn account_password_exception_survives_kdf_and_reset(
    s: &mut Suite,
) -> Result<(), AccountPasswordError> {
    let before = s.snapshot(0)?;
    let devices = s.devices()?;
    let old = s.accounts[0].current.clone();
    let body = change_body(&s.accounts[0].fixture, &s.after_kdf);
    s.http
        .request(
            Method::POST,
            "/api/accounts/kdf",
            Some(&old.access),
            Some(body.to_string().as_bytes()),
            None,
        )?
        .status(200)?
        .empty()?;
    s.public_key(&s.original[0].access.clone(), 200)?;
    s.public_key(&old.access, 401)?;
    s.public_key(
        &s.first_new
            .clone()
            .ok_or(AccountPasswordError("First password session missing"))?
            .access,
        401,
    )?;
    s.accounts[0].fixture = s.after_kdf.clone();
    s.accounts[0].current = s.http.login(&s.accounts[0].fixture, &old.device)?;
    changed(&before, &s.snapshot(0)?, &s.accounts[0].fixture)?;
    require(
        s.devices()? == devices,
        "KDF exception flow changed devices",
    )?;
    let current = s.accounts[0].current.clone();
    s.http
        .request(
            Method::POST,
            "/api/accounts/security-stamp",
            Some(&current.access),
            Some(
                json!({"masterPasswordHash":s.accounts[0].fixture["masterPasswordHash"]})
                    .to_string()
                    .as_bytes(),
            ),
            None,
        )?
        .status(200)?
        .empty()?;
    s.public_key(&s.original[0].access.clone(), 401)?;
    s.accounts[0].current = s.http.login(&s.accounts[0].fixture, &current.device)?;
    s.public_key(&s.original[0].access.clone(), 200)?;
    s.public_key(&s.original[1].access.clone(), 401)?;
    s.public_key(&current.access, 401)?;
    s.retained()
}
fn account_password_repeated_change_overwrites_exception(
    s: &mut Suite,
) -> Result<(), AccountPasswordError> {
    let old = s.accounts[0].fixture.clone();
    let new = s.restored.clone();
    let body = json!([
        old["masterPasswordHash"],
        null,
        null,
        null,
        new["masterPasswordHash"],
        new["key"]
    ]);
    let previous = s.mutate(new, body)?;
    s.accounts[0].password = s.restored_password.clone();
    s.public_key(&s.original[0].access.clone(), 401)?;
    s.public_key(&previous.access, 200)?;
    s.second_new = Some(s.accounts[0].current.clone());
    Ok(())
}
fn account_password_partial_nested_legacy_fallback_and_opaque_values(
    s: &mut Suite,
) -> Result<(), AccountPasswordError> {
    let mut new = s.accounts[0].fixture.clone();
    new["masterPasswordHash"] = json!("");
    new["key"] = json!("");
    let body = json!([s.accounts[0].fixture["masterPasswordHash"]," \t ",{"Salt":"ignored-wrong-salt","Kdf":{"kdfType":1,"iterations":0,"memory":-9,"parallelism":-10},"MasterPasswordAuthenticationHash":"ignored"},null,"",""]);
    s.mutate(new, body)?;
    let previous = s
        .second_new
        .clone()
        .ok_or(AccountPasswordError("Repeated password fixture missing"))?;
    s.public_key(&previous.access, 200)?;
    s.public_key(&s.original[0].access.clone(), 401)?;
    Ok(())
}
fn account_password_exception_expiry_and_owner_isolation(
    s: &mut Suite,
) -> Result<(), AccountPasswordError> {
    let latest = s.latest_change.ok_or(AccountPasswordError(
        "Latest password clock fixture missing",
    ))?;
    while s.expiry_start.elapsed() < Duration::from_secs(121)
        || latest.elapsed() < Duration::from_secs(121)
    {
        let remaining =
            Duration::from_secs(121).saturating_sub(s.expiry_start.elapsed().min(latest.elapsed()));
        thread::sleep(remaining.min(Duration::from_secs(1)));
    }
    s.expiry_wait = s.expiry_start.elapsed().as_secs();
    s.latest_expiry_wait = latest.elapsed().as_secs();
    let foreign = s.snapshot(1)?;
    s.public_key(&s.accounts[2].current.access.clone(), 401)?;
    // Expiry is checked before the old-stamp equality check. Even this much
    // older generation must lazily clear the latest expired exception once.
    let before = s.snapshot(0)?;
    s.public_key(&s.original[0].access.clone(), 401)?;
    let after = s.snapshot(0)?;
    require(
        after.revision > before.revision,
        "Older bearer did not trigger expired latest-exception cleanup",
    )?;
    let mut expected = before;
    expected.revision = after.revision;
    require(
        after == expected,
        "Expired exception cleanup altered account credentials or vault data",
    )?;
    s.public_key(&s.original[0].access.clone(), 401)?;
    require(
        s.snapshot(0)? == after,
        "Repeated expired bearer performed another exception cleanup",
    )?;
    s.public_key(&s.accounts[1].current.access.clone(), 200)?;
    require(
        s.snapshot(1)? == foreign,
        "Exception expiry changed another account",
    )?;
    require(
        s.http.identities == 11
            && s.http.logins == 9
            && s.http.refreshes == 2
            && s.http.successful_refreshes == 1,
        "Authored password identity counts changed",
    )
}

fn private_receipt(name: &str) -> Result<Option<fs::File>, AccountPasswordError> {
    let Some(path) = std::env::var_os(name) else {
        return Ok(None);
    };
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| AccountPasswordError("Password private receipt creation failed"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| AccountPasswordError("Password private receipt permissions failed"))?;
    Ok(Some(file))
}
fn write_receipt(file: &mut fs::File, value: &impl Serialize) -> Result<(), AccountPasswordError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| AccountPasswordError("Password receipt encoding failed"))?;
    file.seek(SeekFrom::Start(0))
        .map_err(|_| AccountPasswordError("Password receipt seek failed"))?;
    file.set_len(0)
        .map_err(|_| AccountPasswordError("Password receipt update failed"))?;
    file.write_all(&bytes)
        .map_err(|_| AccountPasswordError("Password receipt write failed"))?;
    file.sync_all()
        .map_err(|_| AccountPasswordError("Password receipt persistence failed"))
}
fn seed(http: &mut Http) -> Result<Account, AccountPasswordError> {
    let email = format!("account-password-{}@example.test", Uuid::new_v4());
    let password = format!("Private-password-fixture-{}", Uuid::new_v4());
    let fixture = fixture::seed_account(&http.server, &email, &password)
        .map_err(|_| AccountPasswordError("Password fixture registration failed"))?;
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
fn cipher_fixture(http: &mut Http, a: &Account) -> Result<Value, AccountPasswordError> {
    let name =
        fixture::encrypted_pbkdf2_value(&a.fixture, &a.password, b"Preexisting password note")
            .map_err(|_| AccountPasswordError("Password encrypted name fixture failed"))?;
    let notes = fixture::encrypted_pbkdf2_value(
        &a.fixture,
        &a.password,
        "Preserved Unicode note 雪\0 after password change".as_bytes(),
    )
    .map_err(|_| AccountPasswordError("Password encrypted notes fixture failed"))?;
    let folder = http.json(
        Method::POST,
        "/api/folders",
        &a.current.access,
        Some(&json!({"name":name})),
    )?;
    http.json(Method::POST,"/api/ciphers",&a.current.access,Some(&json!({"type":2,"name":name,"notes":notes,"folderId":folder["id"],"encryptedFor":a.id,"secureNote":{"type":0}})))
}
/// Eight selected HTTP cases. Eleven identity requests are split across two
/// direct loopback peers, with at most six per peer and unchanged rate controls.
/// A dedicated old-stamp proof expires after at least 121 real elapsed seconds.
pub fn run() -> Result<(), AccountPasswordError> {
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        target: Value::Null,
        target_password: String::new(),
        after_kdf: Value::Null,
        restored: Value::Null,
        restored_password: String::new(),
        original: Vec::new(),
        first_new: None,
        second_new: None,
        api_secret: String::new(),
        auth: Vec::new(),
        expiry_start: Instant::now(),
        expiry_wait: 0,
        latest_change: None,
        latest_expiry_wait: 0,
        passed: Vec::new(),
        receipt: private_receipt("BW_ACCOUNT_PASSWORD_RECEIPT")?,
        finished: false,
    };
    s.receipt("running")?;
    for i in 0..3 {
        let a = seed(&mut s.http)?;
        if i < 2 {
            cipher_fixture(&mut s.http, &a)?;
        }
        s.accounts.push(a);
    }
    let a = s.accounts[0].clone();
    s.original.push(a.current.clone());
    let key = s.http.json(
        Method::POST,
        "/api/accounts/api-key",
        &a.current.access,
        Some(&json!({"masterPasswordHash":a.fixture["masterPasswordHash"]})),
    )?;
    s.api_secret = text(&key["apiKey"])?.to_owned();
    let device = Uuid::new_v4().to_string();
    let tokens = s.http.token(
        &Form::from([
            ("grant_type".into(), "client_credentials".into()),
            ("client_id".into(), format!("user.{}", a.id)),
            ("client_secret".into(), s.api_secret.clone()),
            ("scope".into(), "api".into()),
            ("deviceIdentifier".into(), device.clone()),
            ("deviceName".into(), "Password API device".into()),
            ("deviceType".into(), "8".into()),
        ]),
        200,
    )?;
    s.original.push(Session {
        access: text(&tokens["access_token"])?.to_owned(),
        refresh: None,
        device,
    });
    // Prepare all expensive client crypto before starting either grace clock.
    s.target_password = format!("Changed-private-password-{}", Uuid::new_v4());
    s.restored_password = format!("Changed-again-private-password-{}", Uuid::new_v4());
    s.target = fixture::rewrap_pbkdf2_password(&a.fixture, &a.password, &s.target_password)
        .map_err(|_| AccountPasswordError("First password rewrap fixture failed"))?;
    s.after_kdf = fixture::rewrap_pbkdf2(&s.target, &s.target_password, 700000)
        .map_err(|_| AccountPasswordError("Intermediate KDF fixture failed"))?;
    s.restored =
        fixture::rewrap_pbkdf2_password(&s.after_kdf, &s.target_password, &s.restored_password)
            .map_err(|_| AccountPasswordError("Second password rewrap fixture failed"))?;
    let timed = s.accounts[2].clone();
    let next = fixture::rewrap_pbkdf2_password(
        &timed.fixture,
        &timed.password,
        &format!("Timed-private-password-{}", Uuid::new_v4()),
    )
    .map_err(|_| AccountPasswordError("Timed password fixture failed"))?;
    s.http
        .request(
            Method::POST,
            PASSWORD,
            Some(&timed.current.access),
            Some(legacy_body(&timed.fixture, &next).to_string().as_bytes()),
            None,
        )?
        .status(200)?
        .empty()?;
    s.expiry_start = Instant::now();
    s.public_key(&timed.current.access, 200)?;
    for (name, case) in CASES {
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
        println!("PASS {name}");
    }
    s.receipt("passed")?;
    s.finished = true;
    println!("PASS account-password HTTP cases: {}", s.passed.len());
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
    client_iterations: u32,
    password_changed_by_http: bool,
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
    fn receipt(&mut self, status: &'static str) -> Result<(), AccountPasswordError> {
        if let Some(file) = &mut self.receipt {
            write_receipt(
                file,
                &CliReceipt {
                    schema_version: 1,
                    status,
                    cli_version: "2026.10.0",
                    commands: self.commands,
                    expected_commands: 10,
                    direct_http_requests: self.http_requests,
                    direct_identity_requests: self.identities,
                    cli_login_commands: self.login_commands,
                    registration_requests_included: false,
                    cli_internal_requests_included: false,
                    client_iterations: 600000,
                    password_changed_by_http: true,
                },
            )?;
        }
        Ok(())
    }
    fn command(&mut self, args: &[&str]) -> Result<String, AccountPasswordError> {
        self.command_status(args, true)
    }
    fn rejected(&mut self, args: &[&str]) -> Result<(), AccountPasswordError> {
        self.command_status(args, false).map(|_| ())
    }
    fn command_status(
        &mut self,
        args: &[&str],
        success: bool,
    ) -> Result<String, AccountPasswordError> {
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
        .map_err(|_| AccountPasswordError("Password CLI capture failed"))?;
        if result.status.success() != success {
            eprintln!(
                "Password CLI command {} unexpected status {:?}; stdout bytes {}, stderr bytes {}",
                self.commands,
                result.status.code(),
                result.stdout.len(),
                result.stderr_bytes
            );
        }
        require(
            result.status.success() == success,
            "Password CLI command status differed",
        )?;
        self.receipt("running")?;
        if !success {
            return Ok(String::new());
        }
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| AccountPasswordError("Password CLI output was not UTF8"))
    }
    fn json(&mut self, args: &[&str]) -> Result<Value, AccountPasswordError> {
        serde_json::from_str(&self.command(args)?)
            .map_err(|_| AccountPasswordError("Password CLI output was not JSON"))
    }
}
fn private_directory(prefix: &str) -> Result<TempDir, AccountPasswordError> {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| AccountPasswordError("Password private directory creation failed"))?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
        .map_err(|_| AccountPasswordError("Password private directory permissions failed"))?;
    Ok(directory)
}
/// A separate focused official-client proof, outside the default HTTP group.
/// HTTP changes the password first. A fresh CLI cache then authenticates, unlocks and
/// decrypts preexisting ciphertext. This does not attribute POST /accounts/password
/// to a CLI command, and leaves the existing full CLI runner unchanged.
pub fn run_cli() -> Result<(), AccountPasswordError> {
    let appdata = private_directory("no-warden-password-cli-")?;
    let tls = private_directory("no-warden-password-tls-")?;
    let local = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/node_modules/.bin/bw");
    let binary = std::env::var_os("BW_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| if local.exists() { local } else { "bw".into() });
    let mut cli = Cli {
        binary,
        environment: std::env::vars_os().collect(),
        commands: 0,
        receipt: private_receipt("BW_ACCOUNT_PASSWORD_CLI_RECEIPT")?,
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
    let new_password = format!("Changed-CLI-private-password-{}", Uuid::new_v4());
    let new = fixture::rewrap_pbkdf2_password(&a.fixture, &a.password, &new_password)
        .map_err(|_| AccountPasswordError("CLI password rewrap fixture failed"))?;
    http.request(
        Method::POST,
        PASSWORD,
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
        .insert("BW_E2E_PASSWORD".into(), a.password.clone().into());
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| AccountPasswordError("Password CLI TLS proxy startup failed"))?,
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
        "Password CLI version differed",
    )?;
    cli.command(&["config", "server", &client_server])?;
    cli.rejected(&[
        "login",
        text(&a.fixture["email"])?,
        "--passwordenv",
        "BW_E2E_PASSWORD",
        "--raw",
    ])?;
    cli.environment
        .insert("BW_E2E_PASSWORD".into(), new_password.into());
    let unlocked = cli.command(&[
        "login",
        text(&a.fixture["email"])?,
        "--passwordenv",
        "BW_E2E_PASSWORD",
        "--raw",
    ])?;
    require(unlocked.len() > 20, "Password CLI login did not unlock")?;
    cli.environment.insert("BW_SESSION".into(), unlocked.into());
    require(
        cli.json(&["status"])?["status"] == "unlocked",
        "Password CLI fresh cache did not unlock",
    )?;
    cli.command(&["lock"])?;
    cli.environment.remove(&OsString::from("BW_SESSION"));
    let unlocked = cli.command(&["unlock", "--passwordenv", "BW_E2E_PASSWORD", "--raw"])?;
    require(unlocked.len() > 20, "Password CLI second unlock failed")?;
    cli.environment.insert("BW_SESSION".into(), unlocked.into());
    cli.command(&["sync"])?;
    let fetched = cli.json(&["get", "item", text(&cipher["id"])?])?;
    require(
        fetched["name"] == "Preexisting password note"
            && fetched["notes"] == "Preserved Unicode note 雪\0 after password change"
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
        "Preexisting password ciphertext was absent before mutation",
    )?;
    cli.command(&["logout"])?;
    require(
        cli.commands == 10 && cli.login_commands == 2 && http.identities == 1,
        "Focused Password CLI command budget changed",
    )?;
    cli.receipt("passed")?;
    cli.finished = true;
    println!("PASS account-password fresh CLI commands: {}", cli.commands);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Shape {
        master_password_hash: String,
        master_password_hint: Option<String>,
        authentication_data: Option<Value>,
        unlock_data: Option<Value>,
        new_master_password_hash: Option<String>,
        key: Option<String>,
    }
    #[test]
    fn password_optional_sequence_slots_and_legacy_fields_match_source() {
        let shape: Shape =
            serde_json::from_value(json!(["old", null, null, null, "new", "key"])).unwrap();
        assert!(
            shape.master_password_hash == "old"
                && shape.master_password_hint.is_none()
                && shape.authentication_data.is_none()
                && shape.unlock_data.is_none()
                && shape.new_master_password_hash.as_deref() == Some("new")
                && shape.key.as_deref() == Some("key")
        );
        assert!(
            serde_json::from_str::<Shape>("[\"old\"]")
                .err()
                .unwrap()
                .is_data()
        );
        assert!(
            serde_json::from_str::<Shape>("[\"old\",null,null,null,null,null,0]")
                .err()
                .unwrap()
                .is_syntax()
        );
        assert!(serde_json::from_str::<Shape>("{\"MasterPasswordHash\":\"old\"}").is_err());
    }
    #[test]
    fn password_expected_projection_preserves_kdf_and_ciphertext() {
        let f = json!({"key":"new","kdf":0,"kdfIterations":600000,"kdfMemory":null,"kdfParallelism":null});
        let before = Snapshot {
            profile: json!({"key":"old","securityStamp":"old"}),
            sync: json!({"profile":{"key":"old","securityStamp":"old"},"userDecryption":{"masterPasswordUnlock":{"kdf":settings(&f),"masterKeyEncryptedUserKey":"old","masterKeyWrappedUserKey":"old"}},"ciphers":[{"opaque":"preserved"}]}),
            keys: json!({"key":"old"}),
            domains: json!({}),
            revision: 1,
        };
        let mut after = before.clone();
        after.profile["key"] = json!("new");
        after.profile["securityStamp"] = json!(Uuid::new_v4().to_string());
        after.sync["profile"] = after.profile.clone();
        for field in ["masterKeyEncryptedUserKey", "masterKeyWrappedUserKey"] {
            after.sync["userDecryption"]["masterPasswordUnlock"][field] = json!("new");
        }
        after.keys["key"] = json!("new");
        after.revision = 2;
        assert!(changed(&before, &after, &f).is_ok());
        after.sync["ciphers"][0]["opaque"] = json!("changed");
        assert!(changed(&before, &after, &f).is_err());
    }
    #[test]
    fn password_diagnostics_and_receipts_exclude_private_data() {
        let marker = "private-password-marker";
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
            commands: 10,
            expected_commands: 10,
            direct_http_requests: 7,
            direct_identity_requests: 1,
            cli_login_commands: 2,
            registration_requests_included: false,
            cli_internal_requests_included: false,
            client_iterations: 600000,
            password_changed_by_http: true,
        };
        assert!(!serde_json::to_string(&receipt).unwrap().contains(marker));
    }
}
