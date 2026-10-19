//! Personal-vault purge contracts, with disposable encrypted accounts.
//!
//! Vaultwarden 58a980f850464f7d9cdc99a765df36f0a3308b91 ciphers.rs:1703-1776,
//! auth.rs:756-815 and api/mod.rs:49-79. OrganizationId's query FromForm wraps
//! String; its UuidFromParam validation applies only to path parameters.
//! Matched organizationId queries select organization authorization, including
//! empty/invalid values; unknown and wrong-case roots use the personal handler.
//! HTTP deletion assertions do not claim global error-envelope, SMTP, OTP-success,
//! organization-purge, notifications or actual CLI-caller coverage.
//! All errors/receipts are static or counts-only; private responses never log.

use crate::fixture;
use base64::{Engine, engine::general_purpose::STANDARD};
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use reqwest::{Method, blocking::Client};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    collections::BTreeMap,
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr},
    thread,
    time::{Duration, Instant},
};
use uuid::Uuid;

const PATH: &str = "/api/ciphers/purge";
const MAX_REPLY: u64 = 32 * 1024 * 1024;
const PLAINTEXT: &[u8] = b"Post-purge encrypted note \0 with preserved user key";
type Form = BTreeMap<String, String>;
type Case = fn(&mut Suite) -> Result<(), PurgeError>;
const CASES: [(&str, Case); 6] = [
    (
        "personal_vault_purge_authentication_and_proof_guards",
        authentication_and_proof_guards,
    ),
    (
        "personal_vault_purge_json_schema_and_methods",
        json_schema_and_methods,
    ),
    (
        "personal_vault_purge_organization_query_isolation",
        organization_query_isolation,
    ),
    (
        "personal_vault_purge_removes_all_personal_payloads",
        removes_all_personal_payloads,
    ),
    (
        "personal_vault_purge_repeated_empty_and_unknown_queries",
        repeated_empty_and_unknown_queries,
    ),
    (
        "personal_vault_purge_preserves_authority_and_recovers",
        preserves_authority_and_recovers,
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PurgeError(&'static str);
impl fmt::Display for PurgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for PurgeError {}
fn require(value: bool, message: &'static str) -> Result<(), PurgeError> {
    if value {
        Ok(())
    } else {
        Err(PurgeError(message))
    }
}
fn text(value: &Value) -> Result<&str, PurgeError> {
    value
        .as_str()
        .ok_or(PurgeError("Required purge fixture string missing"))
}
fn array(value: &Value) -> Result<&[Value], PurgeError> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(PurgeError("Required purge fixture array missing"))
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, PurgeError> {
        if self.status != expected {
            eprintln!(
                "Purge HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Purge HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, PurgeError> {
        serde_json::from_slice(&self.bytes).map_err(|_| PurgeError("Purge response was not JSON"))
    }
    fn empty(self) -> Result<(), PurgeError> {
        require(self.bytes.is_empty(), "Purge success body was not empty")
    }
    fn rejected(self, status: u16) -> Result<(), PurgeError> {
        let response = self.status(status)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&response.bytes) {
            require(
                ["access_token", "refresh_token", "apiKey"]
                    .iter()
                    .all(|field| value.get(field).is_none()),
                "Rejected purge supplied credential authority",
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
    creations: usize,
    polls: usize,
}
impl Http {
    fn new() -> Result<Self, PurgeError> {
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
            .map_err(|_| PurgeError("Purge client initialization failed"))?;
        Ok(Self {
            server,
            client,
            requests: 0,
            identities: 0,
            logins: 0,
            refreshes: 0,
            creations: 0,
            polls: 0,
        })
    }
    fn read(response: reqwest::blocking::Response) -> Result<Reply, PurgeError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_REPLY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| PurgeError("Purge response read failed"))?;
        require(
            bytes.len() as u64 <= MAX_REPLY,
            "Purge response exceeded capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn send(
        &mut self,
        method: Method,
        url: &str,
        bearer: Option<&str>,
        body: Option<(&[u8], &str)>,
    ) -> Result<Reply, PurgeError> {
        self.requests += 1;
        let mut request = self.client.request(method, url).header("device-type", "8");
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        if let Some((bytes, content_type)) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(bytes.to_vec());
        }
        Self::read(
            request
                .send()
                .map_err(|_| PurgeError("Purge HTTP request failed"))?,
        )
    }
    fn raw(
        &mut self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Reply, PurgeError> {
        self.send(
            method,
            &format!("{}{path}", self.server),
            bearer,
            body.map(|bytes| (bytes, "application/json")),
        )
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        bearer: &str,
        body: Option<&Value>,
    ) -> Result<Value, PurgeError> {
        let body = body.map(Value::to_string);
        self.raw(
            method,
            path,
            Some(bearer),
            body.as_deref().map(str::as_bytes),
        )?
        .status(200)?
        .json()
    }
    fn download(&mut self, url: &str, status: u16) -> Result<Vec<u8>, PurgeError> {
        let target = reqwest::Url::parse(url)
            .map_err(|_| PurgeError("Attachment capability URL invalid"))?;
        let base = reqwest::Url::parse(&self.server)
            .map_err(|_| PurgeError("Purge server URL invalid"))?;
        require(
            target.origin() == base.origin() && target.path().starts_with("/attachments/"),
            "Attachment capability escaped fixture origin",
        )?;
        Ok(self
            .send(Method::GET, url, None, None)?
            .status(status)?
            .bytes)
    }
    fn token(&mut self, form: &Form) -> Result<Session, PurgeError> {
        self.requests += 1;
        self.identities += 1;
        require(self.identities <= 6, "Purge identity peer budget exceeded")?;
        let is_refresh = form
            .get("grant_type")
            .is_some_and(|value| value == "refresh_token");
        if is_refresh {
            self.refreshes += 1;
        }
        let value = Self::read(
            self.client
                .post(format!("{}/identity/connect/token", self.server))
                .form(form)
                .send()
                .map_err(|_| PurgeError("Purge identity request failed"))?,
        )?
        .status(200)?
        .json()?;
        if !is_refresh {
            self.logins += 1;
        }
        Ok(Session {
            access: text(&value["access_token"])?.into(),
            refresh: value["refresh_token"].as_str().map(str::to_owned),
        })
    }
    fn login(&mut self, fixture: &Value, device: &str) -> Result<Session, PurgeError> {
        self.token(&Form::from([
            ("grant_type".into(), "password".into()),
            ("client_id".into(), "cli".into()),
            ("scope".into(), "api offline_access".into()),
            ("username".into(), text(&fixture["email"])?.into()),
            (
                "password".into(),
                text(&fixture["masterPasswordHash"])?.into(),
            ),
            ("deviceIdentifier".into(), device.into()),
            ("deviceName".into(), "Purge fixture".into()),
            ("deviceType".into(), "8".into()),
        ]))
    }
}
#[derive(Clone)]
struct Session {
    access: String,
    refresh: Option<String>,
}
struct Account {
    fixture: Value,
    password: String,
    id: String,
    device: String,
    current: Session,
}
struct Attachment {
    metadata_path: String,
    url: String,
    bytes: Vec<u8>,
}
#[derive(Default)]
struct Vault {
    folders: Vec<String>,
    ciphers: Vec<String>,
    attachments: Vec<Attachment>,
}
struct AuthRequest {
    owner: usize,
    id: String,
    code: String,
    approved: bool,
}
#[derive(Clone, PartialEq)]
struct Snapshot {
    sync: Value,
    keys: Value,
    domains: Value,
    devices: Value,
    auth: Vec<Value>,
    pending: Value,
    revision: i64,
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
    max_identity_requests_per_peer: usize,
    fixture_registrations: usize,
    decoded_creation_attempts: usize,
    response_polls: usize,
    purge_requests: usize,
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    vaults: Vec<Vault>,
    auth: Vec<AuthRequest>,
    api_secret: String,
    next: Value,
    next_password: String,
    purges: usize,
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
fn normalize_capabilities(sync: &mut Value) -> Result<(), PurgeError> {
    for cipher in sync["ciphers"]
        .as_array_mut()
        .ok_or(PurgeError("Purge sync ciphers missing"))?
    {
        if let Some(attachments) = cipher["attachments"].as_array_mut() {
            for attachment in attachments {
                let mut url = reqwest::Url::parse(text(&attachment["url"])?)
                    .map_err(|_| PurgeError("Attachment snapshot URL invalid"))?;
                url.set_query(None);
                attachment["url"] = json!(url.to_string());
            }
        }
    }
    Ok(())
}
impl Suite {
    fn receipt(&mut self, status: &'static str) -> Result<(), PurgeError> {
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
                max_identity_requests_per_peer: self.http.identities,
                fixture_registrations: self.accounts.len(),
                decoded_creation_attempts: self.http.creations,
                response_polls: self.http.polls,
                purge_requests: self.purges,
            };
            let bytes = serde_json::to_vec(&record)
                .map_err(|_| PurgeError("Purge receipt encoding failed"))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| PurgeError("Purge receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| PurgeError("Purge receipt update failed"))?;
            file.write_all(&bytes)
                .map_err(|_| PurgeError("Purge receipt write failed"))?;
            file.sync_all()
                .map_err(|_| PurgeError("Purge receipt persistence failed"))?;
        }
        Ok(())
    }
    fn snapshot(&mut self, owner: usize) -> Result<Snapshot, PurgeError> {
        let token = self.accounts[owner].current.access.clone();
        let mut sync = self.http.json(Method::GET, "/api/sync", &token, None)?;
        normalize_capabilities(&mut sync)?;
        let keys = self
            .http
            .json(Method::GET, "/api/accounts/keys", &token, None)?;
        let domains = self
            .http
            .json(Method::GET, "/api/settings/domains", &token, None)?;
        let devices = self.http.json(Method::GET, "/api/devices", &token, None)?;
        let pending = self
            .http
            .json(Method::GET, "/api/auth-requests", &token, None)?;
        let revision = self
            .http
            .json(Method::GET, "/api/accounts/revision-date", &token, None)?
            .as_i64()
            .ok_or(PurgeError("Purge revision was not numeric"))?;
        let mut auth = Vec::new();
        for record in self.auth.iter().filter(|record| record.owner == owner) {
            auth.push(self.http.json(
                Method::GET,
                &format!("/api/auth-requests/{}", record.id),
                &token,
                None,
            )?);
        }
        Ok(Snapshot {
            sync,
            keys,
            domains,
            devices,
            auth,
            pending,
            revision,
        })
    }
    fn snapshots(&mut self) -> Result<Vec<Snapshot>, PurgeError> {
        (0..2).map(|owner| self.snapshot(owner)).collect()
    }
    fn proof(&self) -> Value {
        json!({"masterPasswordHash":self.accounts[0].fixture["masterPasswordHash"]})
    }
    fn purge(&mut self, query: &str, body: &Value) -> Result<(), PurgeError> {
        // Upstream's wall-clock revision has millisecond observable precision.
        thread::sleep(Duration::from_millis(10));
        self.purges += 1;
        self.http
            .raw(
                Method::POST,
                &format!("{PATH}{query}"),
                Some(&self.accounts[0].current.access),
                Some(body.to_string().as_bytes()),
            )?
            .status(200)?
            .empty()
    }
    fn refresh_attachment_capabilities(&mut self, owner: usize) -> Result<(), PurgeError> {
        let token = self.accounts[owner].current.access.clone();
        for attachment in &mut self.vaults[owner].attachments {
            let response = self
                .http
                .json(Method::GET, &attachment.metadata_path, &token, None)?;
            let url = text(&response["url"])?.to_owned();
            require(
                self.http.download(&url, 200)? == attachment.bytes,
                "Fresh purge attachment capability did not preserve bytes",
            )?;
            attachment.url = url;
        }
        Ok(())
    }
    fn empty(&mut self) -> Result<(), PurgeError> {
        let token = self.accounts[0].current.access.clone();
        let sync = self.http.json(Method::GET, "/api/sync", &token, None)?;
        require(
            array(&sync["ciphers"])?.is_empty() && array(&sync["folders"])?.is_empty(),
            "Purged personal vault remained in fresh sync",
        )?;
        let folders = self.http.json(Method::GET, "/api/folders", &token, None)?;
        require(
            array(&folders["data"])?.is_empty(),
            "Purged folder remained in list",
        )
    }
    fn approved_poll(&mut self) -> Result<(), PurgeError> {
        let record = self
            .auth
            .iter()
            .find(|record| record.owner == 0 && record.approved)
            .ok_or(PurgeError("Approved purge request fixture missing"))?;
        let mut url = reqwest::Url::parse("http://localhost/")
            .map_err(|_| PurgeError("Purge poll query initialization failed"))?;
        url.query_pairs_mut().append_pair("code", &record.code);
        self.http.polls += 1;
        let response = self
            .http
            .raw(
                Method::GET,
                &format!(
                    "/api/auth-requests/{}/response?{}",
                    record.id,
                    url.query().ok_or(PurgeError("Purge poll query missing"))?
                ),
                None,
                None,
            )?
            .status(200)?
            .json()?;
        require(
            response["requestApproved"] == true,
            "Purge changed approved access-code polling",
        )
    }
}
fn authentication_and_proof_guards(s: &mut Suite) -> Result<(), PurgeError> {
    let before = s.snapshots()?;
    for token in [None, Some("invalid-purge-bearer")] {
        s.http
            .raw(Method::POST, PATH, token, Some(b"{"))?
            .rejected(401)?;
    }
    let token = s.accounts[0].current.access.clone();
    for body in [
        json!({}),
        json!([null, null]),
        json!({"masterPasswordHash":""}),
        json!({"masterPasswordHash":"wrong\0雪"}),
        json!({"masterPasswordHash":s.accounts[1].fixture["masterPasswordHash"]}),
        json!({"otp":"unsupported-protected-action"}),
        json!({"masterPasswordHash":s.accounts[0].fixture["masterPasswordHash"],"otp":"both-present"}),
    ] {
        s.http
            .raw(
                Method::POST,
                PATH,
                Some(&token),
                Some(body.to_string().as_bytes()),
            )?
            .rejected(400)?;
    }
    require(
        s.snapshots()? == before,
        "Rejected purge changed account authority or vault",
    )
}
fn json_schema_and_methods(s: &mut Suite) -> Result<(), PurgeError> {
    let before = s.snapshots()?;
    let token = s.accounts[0].current.access.clone();
    for body in [
        "null",
        "false",
        "[]",
        "[null]",
        "{\"masterPasswordHash\":3}",
        "{\"otp\":false}",
        "{\"masterPasswordHash\":\"a\",\"MasterPasswordHash\":\"b\"}",
    ] {
        s.http
            .raw(Method::POST, PATH, Some(&token), Some(body.as_bytes()))?
            .rejected(422)?;
    }
    for body in ["{", "[null,null,null]", "{} trailing"] {
        s.http
            .raw(Method::POST, PATH, Some(&token), Some(body.as_bytes()))?
            .rejected(400)?;
    }
    // These methods match dynamic cipher-ID routes upstream, then fail UUID guards.
    for method in [Method::GET, Method::PUT, Method::DELETE] {
        s.http
            .raw(method, PATH, Some(&token), None)?
            .rejected(422)?;
    }
    s.http
        .raw(Method::PATCH, PATH, Some(&token), None)?
        .rejected(404)?;
    require(
        s.snapshots()? == before,
        "Purge schema or method rejection changed vault data",
    )
}
fn organization_query_isolation(s: &mut Suite) -> Result<(), PurgeError> {
    let before = s.snapshots()?;
    let token = s.accounts[0].current.access.clone();
    let org = Uuid::new_v4().to_string();
    let body = s.proof().to_string();
    for query in [
        format!("?organizationId={org}"),
        "?organizationId=".into(),
        "?organizationId".into(),
        "?organizationId=not-a-uuid".into(),
        format!("?organizationId={org}&organizationId=invalid"),
        format!("?organizationId=invalid&organizationId={org}"),
        format!("?organizationId.x={org}"),
        format!("?%5BorganizationId%5D={org}"),
        format!("?.organizationId={org}"),
        format!("?%5BorganizationId={org}"),
        format!("?%6FrganizationId={org}"),
    ] {
        s.http
            .raw(
                Method::POST,
                &format!("{PATH}{query}"),
                Some(&token),
                Some(body.as_bytes()),
            )?
            .rejected(401)?;
    }
    require(
        s.snapshots()? == before,
        "Organization query incorrectly purged a personal vault",
    )
}
fn removes_all_personal_payloads(s: &mut Suite) -> Result<(), PurgeError> {
    let before = s.snapshot(0)?;
    let foreign = s.snapshot(1)?;
    require(
        array(&before.sync["ciphers"])?.len() == 3 && array(&before.sync["folders"])?.len() == 2,
        "Purge lifecycle fixture counts differed",
    )?;
    require(
        array(&before.sync["ciphers"])?
            .iter()
            .any(|cipher| !cipher["deletedDate"].is_null())
            && array(&before.sync["ciphers"])?
                .iter()
                .any(|cipher| !cipher["archivedDate"].is_null()),
        "Purge trash/archive fixtures missing",
    )?;
    let proof = s.proof();
    // Capabilities expire after 60 seconds upstream. Refresh and exercise every
    // grant just before purge, then bound all post-purge checks below half that
    // lifetime so an expired fixture token cannot explain the owned 404s.
    let grants_started = Instant::now();
    s.refresh_attachment_capabilities(0)?;
    s.refresh_attachment_capabilities(1)?;
    s.purge("", &proof)?;
    for attachment in &s.vaults[0].attachments {
        s.http.download(&attachment.url, 404)?;
    }
    for attachment in &s.vaults[1].attachments {
        require(
            s.http.download(&attachment.url, 200)? == attachment.bytes,
            "Personal purge changed foreign attachment bytes",
        )?;
    }
    require(
        grants_started.elapsed() < Duration::from_secs(30),
        "Purge capability checks exceeded the pre-expiry proof window",
    )?;
    s.empty()?;
    let after = s.snapshot(0)?;
    require(
        after.revision > before.revision,
        "Personal purge did not advance owner revision",
    )?;
    let mut expected = before;
    expected.sync["ciphers"] = json!([]);
    expected.sync["folders"] = json!([]);
    expected.revision = after.revision;
    require(
        after == expected,
        "Purge changed credentials, keys, sessions, devices, requests or domains",
    )?;
    require(
        s.snapshot(1)? == foreign,
        "Personal purge changed foreign account or vault",
    )?;
    s.approved_poll()
}
fn repeated_empty_and_unknown_queries(s: &mut Suite) -> Result<(), PurgeError> {
    let foreign = s.snapshot(1)?;
    for body in [
        json!({"MasterPasswordHash":s.accounts[0].fixture["masterPasswordHash"]}),
        json!([s.accounts[0].fixture["masterPasswordHash"], null]),
    ] {
        let before = s.snapshot(0)?;
        s.purge("", &body)?;
        let after = s.snapshot(0)?;
        require(
            after.revision > before.revision,
            "Empty personal purge did not advance revision",
        )?;
        let mut expected = before;
        expected.revision = after.revision;
        require(after == expected, "Empty purge changed account authority")?;
    }
    for query in [
        "?ignored=true",
        "?OrganizationId=not-an-org",
        "?organizationid=not-an-org",
        "?organizationIdOther=not-an-org",
        "?unknown=first&OrganizationId=ignored",
    ] {
        seed_cipher(&mut s.http, &s.accounts[0], None)?;
        let proof = s.proof();
        s.purge(query, &proof)?;
        s.empty()?;
    }
    require(
        s.snapshot(1)? == foreign,
        "Query-selected personal purge changed a foreign vault",
    )
}
fn preserves_authority_and_recovers(s: &mut Suite) -> Result<(), PurgeError> {
    let foreign = s.snapshot(1)?;
    let account = &s.accounts[0];
    let original = account.current.clone();
    let key = s.http.json(
        Method::POST,
        "/api/accounts/api-key",
        &original.access,
        Some(&json!({"masterPasswordHash":account.fixture["masterPasswordHash"]})),
    )?;
    require(
        key["apiKey"] == s.api_secret,
        "Purge rotated account API credentials",
    )?;
    let refresh = original
        .refresh
        .clone()
        .ok_or(PurgeError("Purge refresh fixture missing"))?;
    let refreshed = s.http.token(&Form::from([
        ("grant_type".into(), "refresh_token".into()),
        ("refresh_token".into(), refresh),
    ]))?;
    let logged_in = s.http.login(&account.fixture, &account.device)?;
    let api = s.http.token(&Form::from([
        ("grant_type".into(), "client_credentials".into()),
        ("client_id".into(), format!("user.{}", account.id)),
        ("client_secret".into(), s.api_secret.clone()),
        ("scope".into(), "api".into()),
        ("deviceIdentifier".into(), account.device.clone()),
        ("deviceName".into(), "Purge fixture".into()),
        ("deviceType".into(), "8".into()),
    ]))?;
    require(
        api.refresh.is_none(),
        "Purge API recovery gained refresh authority",
    )?;
    for session in [&original, &logged_in, &refreshed, &api] {
        s.http
            .json(Method::GET, "/api/sync", &session.access, None)?;
    }
    s.accounts[0].current = refreshed;
    let cipher = seed_cipher(&mut s.http, &s.accounts[0], None)?;
    let read = s.http.json(
        Method::GET,
        &format!("/api/ciphers/{cipher}"),
        &s.accounts[0].current.access,
        None,
    )?;
    let profile = s.http.json(
        Method::GET,
        "/api/accounts/profile",
        &s.accounts[0].current.access,
        None,
    )?;
    require(
        decrypt_note(&s.accounts[0], &profile, &read)? == PLAINTEXT,
        "Post-purge recovered cipher did not decrypt",
    )?;
    s.approved_poll()?;
    require(
        s.snapshot(1)? == foreign,
        "Purge recovery changed foreign owner",
    )?;
    // Purge is not one of the previous-stamp follow-up routes after password change.
    let old = s.accounts[0].current.clone();
    let body = json!({"masterPasswordHash":s.accounts[0].fixture["masterPasswordHash"],"newMasterPasswordHash":s.next["masterPasswordHash"],"key":s.next["key"]});
    s.http
        .raw(
            Method::POST,
            "/api/accounts/password",
            Some(&old.access),
            Some(body.to_string().as_bytes()),
        )?
        .status(200)?
        .empty()?;
    s.accounts[0].fixture = s.next.clone();
    s.accounts[0].password = s.next_password.clone();
    s.accounts[0].current = s
        .http
        .login(&s.accounts[0].fixture, &s.accounts[0].device)?;
    let before = s.snapshot(0)?;
    for bearer in [&old.access, &api.access] {
        s.http
            .raw(Method::POST, PATH, Some(bearer), Some(b"{"))?
            .rejected(401)?;
    }
    require(
        s.snapshot(0)? == before,
        "Previous-stamp purge bypass changed recovered vault",
    )?;
    let read = s.http.json(
        Method::GET,
        &format!("/api/ciphers/{cipher}"),
        &s.accounts[0].current.access,
        None,
    )?;
    require(
        decrypt_note(&s.accounts[0], &before.sync["profile"], &read)? == PLAINTEXT,
        "Password recovery lost post-purge cipher decryption",
    )?;
    require(
        s.http.identities == 6 && s.http.logins == 5 && s.http.refreshes == 1,
        "Purge identity counts changed",
    )
}
fn seed(http: &mut Http) -> Result<Account, PurgeError> {
    let email = format!("purge-{}@example.test", Uuid::new_v4());
    let password = format!("Private-purge-fixture-{}", Uuid::new_v4());
    let fixture = fixture::seed_account(&http.server, &email, &password)
        .map_err(|_| PurgeError("Purge account registration failed"))?;
    let device = Uuid::new_v4().to_string();
    let current = http.login(&fixture, &device)?;
    let profile = http.json(Method::GET, "/api/accounts/profile", &current.access, None)?;
    Ok(Account {
        fixture,
        password,
        id: text(&profile["id"])?.into(),
        device,
        current,
    })
}
fn seed_cipher(
    http: &mut Http,
    account: &Account,
    folder: Option<&str>,
) -> Result<String, PurgeError> {
    let name = fixture::encrypted_pbkdf2_value(
        &account.fixture,
        &account.password,
        b"Purge cipher fixture",
    )
    .map_err(|_| PurgeError("Purge encrypted name fixture failed"))?;
    let notes = fixture::encrypted_pbkdf2_value(&account.fixture, &account.password, PLAINTEXT)
        .map_err(|_| PurgeError("Purge encrypted notes fixture failed"))?;
    let cipher=http.json(Method::POST,"/api/ciphers",&account.current.access,Some(&json!({"type":2,"name":name,"notes":notes,"folderId":folder,"encryptedFor":account.id,"secureNote":{"type":0}})))?;
    Ok(text(&cipher["id"])?.into())
}
fn seed_attachment(
    http: &mut Http,
    account: &Account,
    cipher: &str,
) -> Result<Attachment, PurgeError> {
    let name = fixture::encrypted_pbkdf2_value(&account.fixture, &account.password, b"opaque.bin")
        .map_err(|_| PurgeError("Purge attachment name fixture failed"))?;
    let key = fixture::encrypted_pbkdf2_value(&account.fixture, &account.password, &[0x42; 64])
        .map_err(|_| PurgeError("Purge attachment key fixture failed"))?;
    let bytes: Vec<u8> = (0..=255).chain([0, 13, 10, 255]).collect();
    let reserve = http.json(
        Method::POST,
        &format!("/api/ciphers/{cipher}/attachment/v2"),
        &account.current.access,
        Some(&json!({"fileName":name,"key":key,"fileSize":bytes.len()})),
    )?;
    require(
        reserve["fileUploadType"] == 0,
        "Purge attachment fixture was not direct upload",
    )?;
    let id = text(&reserve["attachmentId"])?;
    let boundary = format!("purge-{}", Uuid::new_v4());
    let mut multipart=format!("--{boundary}\r\nContent-Disposition: form-data; name=\"data\"; filename=\"opaque.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
    multipart.extend_from_slice(&bytes);
    multipart.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    http.send(
        Method::POST,
        &format!("{}/api/ciphers/{cipher}/attachment/{id}", http.server),
        Some(&account.current.access),
        Some((
            &multipart,
            &format!("multipart/form-data; boundary={boundary}"),
        )),
    )?
    .status(200)?
    .empty()?;
    let metadata_path = format!("/api/ciphers/{cipher}/attachment/{id}");
    let attachment = http.json(Method::GET, &metadata_path, &account.current.access, None)?;
    let url = text(&attachment["url"])?.to_owned();
    require(
        http.download(&url, 200)? == bytes,
        "Purge attachment fixture bytes changed",
    )?;
    Ok(Attachment {
        metadata_path,
        url,
        bytes,
    })
}
fn seed_vault(http: &mut Http, account: &Account, owner: usize) -> Result<Vault, PurgeError> {
    let name = fixture::encrypted_pbkdf2_value(
        &account.fixture,
        &account.password,
        b"Purge folder fixture",
    )
    .map_err(|_| PurgeError("Purge encrypted folder fixture failed"))?;
    let mut vault = Vault::default();
    for _ in 0..2 {
        let folder = http.json(
            Method::POST,
            "/api/folders",
            &account.current.access,
            Some(&json!({"name":name})),
        )?;
        vault.folders.push(text(&folder["id"])?.into());
    }
    for index in 0..3 {
        let cipher = seed_cipher(http, account, Some(&vault.folders[0]))?;
        if owner == 0 || index == 0 {
            vault
                .attachments
                .push(seed_attachment(http, account, &cipher)?);
        }
        if index > 0 {
            let action = if index == 1 { "delete" } else { "archive" };
            let response = http.raw(
                Method::PUT,
                &format!("/api/ciphers/{cipher}/{action}"),
                Some(&account.current.access),
                None,
            )?;
            require(
                (200..300).contains(&response.status),
                "Purge lifecycle fixture preparation failed",
            )?;
        }
        vault.ciphers.push(cipher);
    }
    Ok(vault)
}
fn create_auth(s: &mut Suite, owner: usize, approve: bool) -> Result<(), PurgeError> {
    let account = &s.accounts[owner];
    let code = format!("purge-access\0雪+{}", Uuid::new_v4());
    s.http.creations += 1;
    let created=s.http.raw(Method::POST,"/api/auth-requests",None,Some(json!({"accessCode":code,"deviceIdentifier":account.device,"email":account.fixture["email"],"publicKey":"opaque-purge-public-key"}).to_string().as_bytes()))?.status(200)?.json()?;
    let id = text(&created["id"])?.to_owned();
    if approve {
        s.http.json(Method::PUT,&format!("/api/auth-requests/{id}"),&account.current.access,Some(&json!({"deviceIdentifier":account.device,"key":account.fixture["key"],"masterPasswordHash":"opaque-purge-response-proof","requestApproved":true})))?;
    }
    s.auth.push(AuthRequest {
        owner,
        id,
        code,
        approved: approve,
    });
    Ok(())
}
fn decrypt(cipher: &str, key: &[u8; 64]) -> Result<Vec<u8>, PurgeError> {
    let fail = || PurgeError("Purge encrypted value authentication failed");
    let fields: Vec<_> = cipher
        .strip_prefix("2.")
        .ok_or_else(fail)?
        .split('|')
        .collect();
    require(fields.len() == 3, "Purge encrypted value shape differed")?;
    let iv = STANDARD.decode(fields[0]).map_err(|_| fail())?;
    let encrypted = STANDARD.decode(fields[1]).map_err(|_| fail())?;
    let mac = STANDARD.decode(fields[2]).map_err(|_| fail())?;
    let mut verifier = Hmac::<Sha256>::new_from_slice(&key[32..]).map_err(|_| fail())?;
    verifier.update(&iv);
    verifier.update(&encrypted);
    verifier.verify_slice(&mac).map_err(|_| fail())?;
    let iv: [u8; 16] = iv.try_into().map_err(|_| fail())?;
    cbc::Decryptor::<aes::Aes256>::new(key[..32].into(), (&iv).into())
        .decrypt_padded_vec_mut::<Pkcs7>(&encrypted)
        .map_err(|_| fail())
}
fn decrypt_note(account: &Account, profile: &Value, cipher: &Value) -> Result<Vec<u8>, PurgeError> {
    let iterations = account.fixture["kdfIterations"]
        .as_u64()
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .ok_or(PurgeError("Purge client KDF fixture invalid"))?;
    let mut master = [0; 32];
    pbkdf2_hmac::<Sha256>(
        account.password.as_bytes(),
        text(&profile["email"])?.trim().to_lowercase().as_bytes(),
        iterations,
        &mut master,
    );
    let mut stretched = [0; 64];
    for (index, info) in [b"enc", b"mac"].into_iter().enumerate() {
        let mut mac = Hmac::<Sha256>::new_from_slice(&master)
            .map_err(|_| PurgeError("Purge key derivation failed"))?;
        mac.update(info);
        mac.update(&[1]);
        stretched[index * 32..(index + 1) * 32].copy_from_slice(&mac.finalize().into_bytes());
    }
    let user_key: [u8; 64] = decrypt(text(&profile["key"])?, &stretched)?
        .try_into()
        .map_err(|_| PurgeError("Purge user-key length differed"))?;
    decrypt(text(&cipher["notes"])?, &user_key)
}
fn private_receipt() -> Result<Option<fs::File>, PurgeError> {
    let Some(path) = std::env::var_os("BW_PURGE_RECEIPT") else {
        return Ok(None);
    };
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| PurgeError("Purge private receipt creation failed"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| PurgeError("Purge receipt permissions failed"))?;
    Ok(Some(file))
}
/// Six selected cases. Six identity requests share one direct peer, with no
/// reference rate-limit changes. Registration helper requests are counted separately.
pub fn run() -> Result<(), PurgeError> {
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        vaults: Vec::new(),
        auth: Vec::new(),
        api_secret: String::new(),
        next: Value::Null,
        next_password: format!("Changed-purge-password-{}", Uuid::new_v4()),
        purges: 0,
        passed: Vec::new(),
        receipt: private_receipt()?,
        finished: false,
    };
    s.receipt("running")?;
    for owner in 0..2 {
        let account = seed(&mut s.http)?;
        let vault = seed_vault(&mut s.http, &account, owner)?;
        s.accounts.push(account);
        s.vaults.push(vault);
    }
    for account in &s.accounts {
        s.http.json(Method::POST,"/api/settings/domains",&account.current.access,Some(&json!({"excludedGlobalEquivalentDomains":[1,1,-7],"equivalentDomains":[["purge.invalid","opaque-雪\0"],[]]})))?;
    }
    let alice = &s.accounts[0];
    let key = s.http.json(
        Method::POST,
        "/api/accounts/api-key",
        &alice.current.access,
        Some(&json!({"masterPasswordHash":alice.fixture["masterPasswordHash"]})),
    )?;
    s.api_secret = text(&key["apiKey"])?.into();
    s.next = fixture::rewrap_pbkdf2_password(&alice.fixture, &alice.password, &s.next_password)
        .map_err(|_| PurgeError("Purge credential recovery fixture failed"))?;
    create_auth(&mut s, 0, false)?;
    create_auth(&mut s, 0, true)?;
    create_auth(&mut s, 1, false)?;
    s.approved_poll()?;
    for (name, case) in CASES {
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
        println!("PASS {name}");
    }
    s.receipt("passed")?;
    s.finished = true;
    println!("PASS personal-vault-purge HTTP cases: {}", s.passed.len());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::BlockEncryptMut;
    #[test]
    fn purge_decryption_verifies_mac_and_rejects_tampering_without_echoing_plaintext() {
        let key = [0x42; 64];
        let iv = [0x24; 16];
        let encrypted = cbc::Encryptor::<aes::Aes256>::new(key[..32].into(), (&iv).into())
            .encrypt_padded_vec_mut::<Pkcs7>(PLAINTEXT);
        let mut mac = Hmac::<Sha256>::new_from_slice(&key[32..]).unwrap();
        mac.update(&iv);
        mac.update(&encrypted);
        let tag = mac.finalize().into_bytes();
        let value = format!(
            "2.{}|{}|{}",
            STANDARD.encode(iv),
            STANDARD.encode(&encrypted),
            STANDARD.encode(tag)
        );
        assert!(decrypt(&value, &key).is_ok_and(|plain| plain == PLAINTEXT));
        let mut altered = encrypted;
        altered[0] ^= 1;
        let tampered = format!(
            "2.{}|{}|{}",
            STANDARD.encode(iv),
            STANDARD.encode(altered),
            STANDARD.encode(tag)
        );
        let error = decrypt(&tampered, &key).unwrap_err();
        assert!(!format!("{error:?} {error}").contains("Post-purge encrypted note"));
        assert!(decrypt(&value, &[0x43; 64]).is_err());
    }
}
