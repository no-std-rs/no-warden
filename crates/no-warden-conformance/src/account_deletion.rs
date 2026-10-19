//! Disposable account-deletion aliases, independently of real CLI attribution.
//!
//! Vaultwarden 58a980f850464f7d9cdc99a765df36f0a3308b91 accounts.rs1321-1334,
//! api/mod.rs49-79 and user.rs365-399. Release1.37.4 has the same handlers but
//! lacks the pin's explicit auth-request cleanup. These portable fixtures omit
//! auth requests; complete adapter SQL cleanup is verified separately.
//! No organization-owner, protected-OTP success, SMTP, notification or error-
//! envelope parity is claimed. All fixture accounts are newly generated.

use crate::fixture;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use reqwest::{Method, blocking::Client};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr},
    time::{Duration, Instant},
};
use uuid::Uuid;

const DELETE: &str = "/api/accounts";
const POST: &str = "/api/accounts/delete";
const MAX_REPLY: u64 = 32 * 1024 * 1024;
type Form = BTreeMap<String, String>;
type Case = fn(&mut Suite) -> Result<(), AccountDeletionError>;
const CASES: [(&str, Case); 6] = [
    (
        "account_deletion_authentication_and_proof_guards",
        authentication_and_proof_guards,
    ),
    (
        "account_deletion_json_schema_and_method_guards",
        json_schema_and_method_guards,
    ),
    (
        "account_deletion_delete_alias_revokes_live_authority",
        delete_alias_revokes_live_authority,
    ),
    (
        "account_deletion_re_registration_creates_new_authority",
        re_registration_creates_new_authority,
    ),
    (
        "account_deletion_post_alias_and_ignored_queries",
        post_alias_and_ignored_queries,
    ),
    (
        "account_deletion_foreign_vault_and_authority_survive",
        foreign_vault_and_authority_survive,
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountDeletionError(&'static str);
impl fmt::Display for AccountDeletionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for AccountDeletionError {}
fn require(value: bool, message: &'static str) -> Result<(), AccountDeletionError> {
    if value {
        Ok(())
    } else {
        Err(AccountDeletionError(message))
    }
}
fn text(value: &Value) -> Result<&str, AccountDeletionError> {
    value.as_str().ok_or(AccountDeletionError(
        "Required deletion fixture string missing",
    ))
}
fn array(value: &Value) -> Result<&[Value], AccountDeletionError> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(AccountDeletionError(
            "Required deletion fixture array missing",
        ))
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, AccountDeletionError> {
        if self.status != expected {
            eprintln!(
                "Account deletion HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(
            self.status == expected,
            "Account deletion HTTP status differed",
        )?;
        Ok(self)
    }
    fn json(self) -> Result<Value, AccountDeletionError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| AccountDeletionError("Account deletion response was not JSON"))
    }
    fn empty(self) -> Result<(), AccountDeletionError> {
        require(
            self.bytes.is_empty(),
            "Account deletion success body was not empty",
        )
    }
    fn rejected(self, expected: u16) -> Result<(), AccountDeletionError> {
        let response = self.status(expected)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&response.bytes) {
            require(
                ["access_token", "refresh_token", "apiKey"]
                    .iter()
                    .all(|key| value.get(key).is_none()),
                "Rejected deletion response supplied credential authority",
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
    api_attempts: usize,
    deleted: usize,
}
impl Http {
    fn new() -> Result<Self, AccountDeletionError> {
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
            .map_err(|_| AccountDeletionError("Account deletion client initialization failed"))?;
        Ok(Self {
            server,
            client,
            requests: 0,
            identities: 0,
            logins: 0,
            refreshes: 0,
            api_attempts: 0,
            deleted: 0,
        })
    }
    fn read(response: reqwest::blocking::Response) -> Result<Reply, AccountDeletionError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_REPLY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AccountDeletionError("Account deletion response read failed"))?;
        require(
            bytes.len() as u64 <= MAX_REPLY,
            "Account deletion response exceeded private capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn send(
        &mut self,
        method: Method,
        url: &str,
        bearer: Option<&str>,
        body: Option<(&[u8], &str)>,
    ) -> Result<Reply, AccountDeletionError> {
        self.requests += 1;
        let mut request = self.client.request(method, url).header("device-type", "8");
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        if let Some((bytes, content_type)) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, content_type)
                .body(bytes.to_vec());
        }
        Self::read(
            request
                .send()
                .map_err(|_| AccountDeletionError("Account deletion HTTP request failed"))?,
        )
    }
    fn raw(
        &mut self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Reply, AccountDeletionError> {
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
    ) -> Result<Value, AccountDeletionError> {
        let bytes = body.map(Value::to_string);
        self.raw(
            method,
            path,
            Some(bearer),
            bytes.as_deref().map(str::as_bytes),
        )?
        .status(200)?
        .json()
    }
    fn token(&mut self, form: &Form, status: u16) -> Result<Option<Session>, AccountDeletionError> {
        self.requests += 1;
        self.identities += 1;
        require(
            self.identities <= 6,
            "Account deletion identity peer budget exceeded",
        )?;
        let grant = form.get("grant_type").map(String::as_str);
        if grant == Some("refresh_token") {
            self.refreshes += 1;
        }
        if grant == Some("client_credentials") {
            self.api_attempts += 1;
        }
        let reply = Self::read(
            self.client
                .post(format!("{}/identity/connect/token", self.server))
                .form(form)
                .send()
                .map_err(|_| AccountDeletionError("Account deletion identity request failed"))?,
        )?;
        if status != 200 {
            reply.rejected(status)?;
            return Ok(None);
        }
        let value = reply.status(200)?.json()?;
        if grant == Some("password") {
            self.logins += 1;
        }
        Ok(Some(Session {
            access: text(&value["access_token"])?.into(),
            refresh: text(&value["refresh_token"])?.into(),
        }))
    }
    fn login(&mut self, fixture: &Value, device: &str) -> Result<Session, AccountDeletionError> {
        self.token(
            &Form::from([
                ("grant_type".into(), "password".into()),
                ("client_id".into(), "cli".into()),
                ("scope".into(), "api offline_access".into()),
                ("username".into(), text(&fixture["email"])?.into()),
                (
                    "password".into(),
                    text(&fixture["masterPasswordHash"])?.into(),
                ),
                ("deviceIdentifier".into(), device.into()),
                ("deviceName".into(), "Disposable deletion fixture".into()),
                ("deviceType".into(), "8".into()),
            ]),
            200,
        )?
        .ok_or(AccountDeletionError(
            "Account deletion login did not create a session",
        ))
    }
    fn known(&mut self, account: &Account) -> Result<bool, AccountDeletionError> {
        self.requests += 1;
        let response = self
            .client
            .get(format!("{}/api/devices/knowndevice", self.server))
            .header(
                "X-Request-Email",
                URL_SAFE_NO_PAD.encode(text(&account.fixture["email"])?),
            )
            .header("X-Device-Identifier", &account.device)
            .send()
            .map_err(|_| AccountDeletionError("Account deletion known-device request failed"))?;
        Self::read(response)?
            .status(200)?
            .json()?
            .as_bool()
            .ok_or(AccountDeletionError(
                "Account deletion known-device response was not boolean",
            ))
    }
    fn download(&mut self, url: &str, status: u16) -> Result<Vec<u8>, AccountDeletionError> {
        let target = reqwest::Url::parse(url)
            .map_err(|_| AccountDeletionError("Account deletion capability URL invalid"))?;
        let server = reqwest::Url::parse(&self.server)
            .map_err(|_| AccountDeletionError("Account deletion server URL invalid"))?;
        require(
            target.origin() == server.origin() && target.path().starts_with("/attachments/"),
            "Account deletion capability escaped fixture origin",
        )?;
        Ok(self
            .send(Method::GET, url, None, None)?
            .status(status)?
            .bytes)
    }
}
#[derive(Clone)]
struct Session {
    access: String,
    refresh: String,
}
struct Account {
    fixture: Value,
    encrypted_name: String,
    encrypted_attachment_key: String,
    id: String,
    device: String,
    current: Session,
    api_secret: String,
}
struct Attachment {
    metadata_path: String,
    url: String,
    bytes: Vec<u8>,
}
#[derive(Default)]
struct Vault {
    attachments: Vec<Attachment>,
}
#[derive(Clone, PartialEq)]
struct Snapshot {
    sync: Value,
    keys: Value,
    domains: Value,
    devices: Value,
    requests: Value,
    revision: Value,
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
    api_key_attempts: usize,
    max_identity_requests_per_peer: usize,
    fixture_registrations: usize,
    deleted_accounts: usize,
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    vaults: Vec<Vault>,
    foreign: Option<Snapshot>,
    old_id: String,
    old_keys: Value,
    old_api_secret: String,
    old_access: Vec<String>,
    registrations: usize,
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
    fn receipt(&mut self, status: &'static str) -> Result<(), AccountDeletionError> {
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
                api_key_attempts: self.http.api_attempts,
                max_identity_requests_per_peer: self.http.identities,
                fixture_registrations: self.registrations,
                deleted_accounts: self.http.deleted,
            };
            let bytes = serde_json::to_vec(&record)
                .map_err(|_| AccountDeletionError("Account deletion receipt encoding failed"))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| AccountDeletionError("Account deletion receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| AccountDeletionError("Account deletion receipt update failed"))?;
            file.write_all(&bytes)
                .map_err(|_| AccountDeletionError("Account deletion receipt write failed"))?;
            file.sync_all()
                .map_err(|_| AccountDeletionError("Account deletion receipt persistence failed"))?;
        }
        Ok(())
    }
    fn snapshot(&mut self, owner: usize) -> Result<Snapshot, AccountDeletionError> {
        let token = self.accounts[owner].current.access.clone();
        let mut sync = self.http.json(Method::GET, "/api/sync", &token, None)?;
        for cipher in sync["ciphers"].as_array_mut().ok_or(AccountDeletionError(
            "Account deletion sync ciphers missing",
        ))? {
            if let Some(attachments) = cipher["attachments"].as_array_mut() {
                for attachment in attachments {
                    let mut url = reqwest::Url::parse(text(&attachment["url"])?).map_err(|_| {
                        AccountDeletionError("Account deletion snapshot URL invalid")
                    })?;
                    url.set_query(None);
                    attachment["url"] = json!(url.to_string());
                }
            }
        }
        Ok(Snapshot {
            sync,
            keys: self
                .http
                .json(Method::GET, "/api/accounts/keys", &token, None)?,
            domains: self
                .http
                .json(Method::GET, "/api/settings/domains", &token, None)?,
            devices: self.http.json(Method::GET, "/api/devices", &token, None)?,
            requests: self
                .http
                .json(Method::GET, "/api/auth-requests", &token, None)?,
            revision: self
                .http
                .json(Method::GET, "/api/accounts/revision-date", &token, None)?,
        })
    }
    fn snapshots(&mut self) -> Result<Vec<Snapshot>, AccountDeletionError> {
        (0..2).map(|owner| self.snapshot(owner)).collect()
    }
    fn refresh_capabilities(&mut self) -> Result<(), AccountDeletionError> {
        for owner in 0..2 {
            let token = self.accounts[owner].current.access.clone();
            for attachment in &mut self.vaults[owner].attachments {
                let metadata =
                    self.http
                        .json(Method::GET, &attachment.metadata_path, &token, None)?;
                let url = text(&metadata["url"])?.to_owned();
                require(
                    self.http.download(&url, 200)? == attachment.bytes,
                    "Fresh account deletion capability did not preserve bytes",
                )?;
                attachment.url = url;
            }
        }
        Ok(())
    }
    fn delete(
        &mut self,
        method: Method,
        path: &str,
        proof: &Value,
    ) -> Result<(), AccountDeletionError> {
        let started = Instant::now();
        self.refresh_capabilities()?;
        let token = self.accounts[0].current.access.clone();
        self.http
            .raw(
                method,
                path,
                Some(&token),
                Some(proof.to_string().as_bytes()),
            )?
            .status(200)?
            .empty()?;
        self.http.deleted += 1;
        for attachment in &self.vaults[0].attachments {
            self.http.download(&attachment.url, 404)?;
        }
        for attachment in &self.vaults[1].attachments {
            require(
                self.http.download(&attachment.url, 200)? == attachment.bytes,
                "Account deletion changed foreign attachment bytes",
            )?;
        }
        require(
            started.elapsed() < Duration::from_secs(30),
            "Account deletion capability checks exceeded the pre-expiry proof window",
        )?;
        require(
            !self.http.known(&self.accounts[0])?,
            "Deleted account retained known-device authority",
        )?;
        for access in self.old_access.iter().chain(std::iter::once(&token)) {
            for path in [
                "/api/accounts/profile",
                "/api/sync",
                "/api/devices",
                "/api/accounts/keys",
            ] {
                self.http
                    .raw(Method::GET, path, Some(access), None)?
                    .rejected(401)?;
            }
        }
        let foreign = &self.accounts[1].current.access;
        self.http
            .raw(
                Method::GET,
                &format!("/api/users/{}/public-key", self.accounts[0].id),
                Some(foreign),
                None,
            )?
            .rejected(404)?;
        require(
            self.snapshot(1)?
                == *self
                    .foreign
                    .as_ref()
                    .ok_or(AccountDeletionError("Foreign deletion snapshot missing"))?,
            "Account deletion changed foreign vault or authority",
        )
    }
}
fn authentication_and_proof_guards(s: &mut Suite) -> Result<(), AccountDeletionError> {
    let before = s.snapshots()?;
    for (method, path) in [(Method::DELETE, DELETE), (Method::POST, POST)] {
        for bearer in [None, Some("invalid-account-deletion-bearer")] {
            s.http
                .raw(method.clone(), path, bearer, Some(b"{"))?
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
                    method.clone(),
                    path,
                    Some(&token),
                    Some(body.to_string().as_bytes()),
                )?
                .rejected(400)?;
        }
        for query in [
            "?organizationId=invalid",
            "?organizationId=&organizationId=another",
            "?OrganizationId=true",
            "?ignored=value",
            "?%5BorganizationId%5D=invalid",
        ] {
            s.http
                .raw(
                    method.clone(),
                    &format!("{path}{query}"),
                    Some(&token),
                    Some(b"{}"),
                )?
                .rejected(400)?;
        }
    }
    require(
        s.snapshots()? == before,
        "Rejected deletion changed owner or foreign data",
    )
}
fn json_schema_and_method_guards(s: &mut Suite) -> Result<(), AccountDeletionError> {
    let before = s.snapshots()?;
    let token = s.accounts[0].current.access.clone();
    for (method, path) in [(Method::DELETE, DELETE), (Method::POST, POST)] {
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
                .raw(method.clone(), path, Some(&token), Some(body.as_bytes()))?
                .rejected(422)?;
        }
        for body in ["{", "[null,null,null]", "{} trailing"] {
            s.http
                .raw(method.clone(), path, Some(&token), Some(body.as_bytes()))?
                .rejected(400)?;
        }
    }
    for (method, path) in [
        (Method::GET, DELETE),
        (Method::POST, DELETE),
        (Method::PUT, DELETE),
        (Method::PATCH, DELETE),
        (Method::GET, POST),
        (Method::PUT, POST),
        (Method::DELETE, POST),
        (Method::PATCH, POST),
    ] {
        s.http
            .raw(method, path, Some(&token), None)?
            .rejected(404)?;
    }
    require(
        s.snapshots()? == before,
        "Deletion JSON or method guards changed vault or authority",
    )
}
fn delete_alias_revokes_live_authority(s: &mut Suite) -> Result<(), AccountDeletionError> {
    let current = s.accounts[0].current.clone();
    s.old_access.push(current.access.clone());
    let refreshed = s
        .http
        .token(
            &Form::from([
                ("grant_type".into(), "refresh_token".into()),
                ("refresh_token".into(), current.refresh),
            ]),
            200,
        )?
        .ok_or(AccountDeletionError(
            "Deletion precondition refresh did not create authority",
        ))?;
    s.accounts[0].current = refreshed.clone();
    s.http
        .json(Method::GET, "/api/sync", &refreshed.access, None)?;
    s.old_access.push(refreshed.access.clone());
    let owned = s.snapshot(0)?;
    require(
        array(&owned.sync["ciphers"])?.len() == 3
            && array(&owned.sync["folders"])?.len() == 2
            && array(&owned.sync["ciphers"])?
                .iter()
                .any(|item| !item["deletedDate"].is_null())
            && array(&owned.sync["ciphers"])?
                .iter()
                .any(|item| !item["archivedDate"].is_null()),
        "Account deletion lifecycle fixtures missing",
    )?;
    let proof = json!({"MasterPasswordHash":s.accounts[0].fixture["masterPasswordHash"],"ownerId":s.accounts[1].id,"id":s.accounts[1].id,"email":s.accounts[1].fixture["email"],"key":"ignored-owner-override"});
    s.delete(
        Method::DELETE,
        "/api/accounts?organizationId=invalid&organizationId=&OrganizationId=foreign&ignored=true",
        &proof,
    )?;
    s.http.token(
        &Form::from([
            ("grant_type".into(), "refresh_token".into()),
            ("refresh_token".into(), refreshed.refresh),
        ]),
        400,
    )?;
    Ok(())
}
fn re_registration_creates_new_authority(s: &mut Suite) -> Result<(), AccountDeletionError> {
    let email = text(&s.accounts[0].fixture["email"])?.to_owned();
    let device = s.accounts[0].device.clone();
    let account = seed_account(&mut s.http, &email, &device)?;
    s.registrations += 1;
    require(
        account.id != s.old_id,
        "Re-registration reused deleted account identity",
    )?;
    require(
        account.fixture["keys"]["publicKey"] != s.old_keys["keys"]["publicKey"]
            && account.fixture["key"] != s.old_keys["key"]
            && account.api_secret != s.old_api_secret,
        "Re-registration retained deleted account key or API authority",
    )?;
    s.accounts[0] = account;
    let empty = s.snapshot(0)?;
    require(
        array(&empty.sync["ciphers"])?.is_empty()
            && array(&empty.sync["folders"])?.is_empty()
            && array(&empty.devices["data"])?.len() == 1,
        "Re-registration inherited deleted personal storage or devices",
    )?;
    require(
        empty.keys["publicKey"] == s.accounts[0].fixture["keys"]["publicKey"]
            && empty.keys["privateKey"] == s.accounts[0].fixture["keys"]["encryptedPrivateKey"]
            && empty.keys["key"] == s.accounts[0].fixture["key"],
        "Re-registration key response differed from new authority",
    )?;
    require(
        array(&empty.domains["equivalentDomains"])?.is_empty(),
        "Re-registration inherited deleted custom domain settings",
    )?;
    require(
        s.http.known(&s.accounts[0])?,
        "Re-registration did not bind its fresh owned device",
    )?;
    for access in &s.old_access {
        s.http
            .raw(Method::GET, "/api/sync", Some(access), None)?
            .rejected(401)?;
    }
    s.http.token(
        &Form::from([
            ("grant_type".into(), "client_credentials".into()),
            ("client_id".into(), format!("user.{}", s.old_id)),
            ("client_secret".into(), s.old_api_secret.clone()),
            ("scope".into(), "api".into()),
            ("deviceIdentifier".into(), device),
            ("deviceName".into(), "Deleted authority probe".into()),
            ("deviceType".into(), "8".into()),
        ]),
        400,
    )?;
    s.vaults[0] = seed_vault(&mut s.http, &s.accounts[0], true)?;
    Ok(())
}
fn post_alias_and_ignored_queries(s: &mut Suite) -> Result<(), AccountDeletionError> {
    let proof = json!([s.accounts[0].fixture["masterPasswordHash"], null]);
    s.delete(Method::POST, "/api/accounts/delete?ignored=true&organizationId=invalid&organizationId=&OrganizationId=foreign", &proof)
}
fn foreign_vault_and_authority_survive(s: &mut Suite) -> Result<(), AccountDeletionError> {
    require(
        s.snapshot(1)?
            == *s.foreign.as_ref().ok_or(AccountDeletionError(
                "Foreign account deletion snapshot missing",
            ))?,
        "Account deletion changed foreign snapshot",
    )?;
    let account = &s.accounts[1];
    let key = s.http.json(
        Method::POST,
        "/api/accounts/api-key",
        &account.current.access,
        Some(&json!({"masterPasswordHash":account.fixture["masterPasswordHash"]})),
    )?;
    require(
        key["apiKey"] == account.api_secret && s.http.known(account)?,
        "Account deletion changed foreign API secret or device authority",
    )?;
    require(
        s.http.identities == 6
            && s.http.logins == 3
            && s.http.refreshes == 2
            && s.http.api_attempts == 1
            && s.http.deleted == 2,
        "Account deletion identity or alias counts differed",
    )
}
fn seed_account(
    http: &mut Http,
    email: &str,
    device: &str,
) -> Result<Account, AccountDeletionError> {
    let password = format!("Private-deletion-fixture-{}", Uuid::new_v4());
    let fixture = fixture::seed_account(&http.server, email, &password)
        .map_err(|_| AccountDeletionError("Account deletion fixture registration failed"))?;
    let encrypted_name = fixture::encrypted_pbkdf2_value(
        &fixture,
        &password,
        b"Disposable account deletion payload",
    )
    .map_err(|_| AccountDeletionError("Account deletion encrypted field fixture failed"))?;
    let encrypted_attachment_key =
        fixture::encrypted_pbkdf2_value(&fixture, &password, &[0x42; 64])
            .map_err(|_| AccountDeletionError("Account deletion attachment key fixture failed"))?;
    let current = http.login(&fixture, device)?;
    let profile = http.json(Method::GET, "/api/accounts/profile", &current.access, None)?;
    let api = http.json(
        Method::POST,
        "/api/accounts/api-key",
        &current.access,
        Some(&json!({"masterPasswordHash":fixture["masterPasswordHash"]})),
    )?;
    Ok(Account {
        fixture,
        encrypted_name,
        encrypted_attachment_key,
        id: text(&profile["id"])?.into(),
        device: device.into(),
        current,
        api_secret: text(&api["apiKey"])?.into(),
    })
}
fn seed_vault(
    http: &mut Http,
    account: &Account,
    owned: bool,
) -> Result<Vault, AccountDeletionError> {
    // Reuse valid client-encrypted fixture fields without repeating a KDF per item.
    let name = &account.encrypted_name;
    let mut folders = Vec::new();
    for _ in 0..2 {
        let folder = http.json(
            Method::POST,
            "/api/folders",
            &account.current.access,
            Some(&json!({"name":name})),
        )?;
        folders.push(text(&folder["id"])?.to_owned());
    }
    let mut vault = Vault::default();
    for index in 0..3 {
        let cipher = http.json(Method::POST, "/api/ciphers", &account.current.access, Some(&json!({"type":2,"name":name,"notes":name,"folderId":folders[0],"encryptedFor":account.id,"secureNote":{"type":0}})))?;
        let id = text(&cipher["id"])?;
        if owned || index == 0 {
            vault.attachments.push(seed_attachment(http, account, id)?);
        }
        if index > 0 {
            let action = if index == 1 { "delete" } else { "archive" };
            let reply = http.raw(
                Method::PUT,
                &format!("/api/ciphers/{id}/{action}"),
                Some(&account.current.access),
                None,
            )?;
            require(
                (200..300).contains(&reply.status),
                "Account deletion trash or archive preparation failed",
            )?;
        }
    }
    http.json(Method::POST, "/api/settings/domains", &account.current.access, Some(&json!({"excludedGlobalEquivalentDomains":[1,-7],"equivalentDomains":[["delete.invalid","opaque-雪\0"],[]]})))?;
    Ok(vault)
}
fn seed_attachment(
    http: &mut Http,
    account: &Account,
    cipher: &str,
) -> Result<Attachment, AccountDeletionError> {
    let bytes: Vec<u8> = (0..=255).chain([0, 13, 10, 255]).collect();
    let reserve = http.json(Method::POST, &format!("/api/ciphers/{cipher}/attachment/v2"), &account.current.access, Some(&json!({"fileName":account.encrypted_name,"key":account.encrypted_attachment_key,"fileSize":bytes.len()})))?;
    require(
        reserve["fileUploadType"] == 0,
        "Account deletion attachment fixture was not direct upload",
    )?;
    let id = text(&reserve["attachmentId"])?;
    let metadata_path = format!("/api/ciphers/{cipher}/attachment/{id}");
    let boundary = format!("deletion-{}", Uuid::new_v4());
    let mut multipart = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"data\"; filename=\"opaque.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
    multipart.extend_from_slice(&bytes);
    multipart.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    http.send(
        Method::POST,
        &format!("{}{metadata_path}", http.server),
        Some(&account.current.access),
        Some((
            &multipart,
            &format!("multipart/form-data; boundary={boundary}"),
        )),
    )?
    .status(200)?
    .empty()?;
    let metadata = http.json(Method::GET, &metadata_path, &account.current.access, None)?;
    Ok(Attachment {
        metadata_path,
        url: text(&metadata["url"])?.into(),
        bytes,
    })
}
fn private_receipt() -> Result<Option<fs::File>, AccountDeletionError> {
    let Some(path) = std::env::var_os("BW_ACCOUNT_DELETION_RECEIPT") else {
        return Ok(None);
    };
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| AccountDeletionError("Account deletion private receipt creation failed"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| AccountDeletionError("Account deletion receipt permissions failed"))?;
    Ok(Some(file))
}
/// Six opt-in cases, two synthetic email fixtures and six identity attempts.
/// Registration helper requests are recorded separately, as in the other suites.
pub fn run() -> Result<(), AccountDeletionError> {
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        vaults: Vec::new(),
        foreign: None,
        old_id: String::new(),
        old_keys: Value::Null,
        old_api_secret: String::new(),
        old_access: Vec::new(),
        registrations: 0,
        passed: Vec::new(),
        receipt: private_receipt()?,
        finished: false,
    };
    s.receipt("running")?;
    for owner in 0..2 {
        let email = format!("account-deletion-{}@example.test", Uuid::new_v4());
        let device = Uuid::new_v4().to_string();
        let account = seed_account(&mut s.http, &email, &device)?;
        s.registrations += 1;
        let vault = seed_vault(&mut s.http, &account, owner == 0)?;
        s.accounts.push(account);
        s.vaults.push(vault);
    }
    s.old_id = s.accounts[0].id.clone();
    s.old_keys = s.accounts[0].fixture.clone();
    s.old_api_secret = s.accounts[0].api_secret.clone();
    s.foreign = Some(s.snapshot(1)?);
    for (name, case) in CASES {
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
        println!("PASS {name}");
    }
    s.receipt("passed")?;
    s.finished = true;
    println!("PASS account-deletion HTTP cases: {}", s.passed.len());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProofShape {
        #[serde(alias = "MasterPasswordHash")]
        master_password_hash: Option<String>,
        otp: Option<String>,
    }
    #[test]
    fn deletion_proof_aliases_and_optional_sequence_slots_match_source() {
        let parsed: ProofShape =
            serde_json::from_str(r#"{"MasterPasswordHash":"opaque\u0000雪","ownerId":"ignored"}"#)
                .unwrap();
        assert!(
            parsed.master_password_hash.as_deref() == Some("opaque\0雪") && parsed.otp.is_none()
        );
        assert!(serde_json::from_str::<ProofShape>("[null,null]").is_ok());
        for raw in [
            "[]",
            "[null]",
            "null",
            r#"{"masterPasswordHash":3}"#,
            r#"{"masterPasswordHash":"a","MasterPasswordHash":"b"}"#,
        ] {
            assert!(
                serde_json::from_str::<ProofShape>(raw)
                    .is_err_and(|e| e.classify() == serde_json::error::Category::Data)
            );
        }
        assert!(
            serde_json::from_str::<ProofShape>("[null,null,null]")
                .is_err_and(|e| e.classify() == serde_json::error::Category::Syntax)
        );
    }
    #[test]
    fn deletion_errors_discard_response_material() {
        let private = b"opaque-private-password-token-key";
        let error = Reply {
            status: 200,
            bytes: private.to_vec(),
        }
        .json()
        .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("opaque-private"));
        assert!(
            Reply {
                status: 400,
                bytes: br#"{"access_token":"opaque-private"}"#.to_vec()
            }
            .rejected(400)
            .is_err()
        );
    }
}
