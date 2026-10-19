//! Password-method refresh proofs, reusable device authority and revocation.
//!
//! Vaultwarden pin/release1.37.4 identity.rs65-68,142-174;auth.rs130-150,
//! 1292-1397;device.rs266-276;user.rs165-230. Refresh does not call the login
//! limiter. Missing Option proofs use the outer nine-field API guard; present
//! invalid proofs use exactly {error:invalid_grant}. Refresh responses have five
//! fields and do not include account keys. Tokens remain opaque to this suite.
//! Original proof deadlines/mobile lifetimes/leeway, provider failure boundaries
//! and disabled policy are separate adapter/core tests, not long-running HTTP
//! expiry claims. Official CLI120 remains a separate regression, not a timed
//! refresh-caller trace. Every diagnostic/receipt excludes response material.

use crate::fixture;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use cbc::cipher::{BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use reqwest::{Method, blocking::Client};
use serde::Serialize;
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr},
    thread,
    time::Duration,
};
use uuid::Uuid;

const MAX_REPLY: u64 = 16 * 1024 * 1024;
const PLAINTEXT: &[u8] = b"Retained refresh vault payload \0 with authenticated encryption";
type Form = Vec<(String, String)>;
type Case = fn(&mut Suite) -> Result<(), RefreshGrantsError>;
const CASES: [(&str, Case); 8] = [
    (
        "refresh_grants_form_and_invalid_token_guards",
        form_and_invalid_token_guards,
    ),
    (
        "refresh_grants_original_reuse_across_clock",
        original_reuse_across_clock,
    ),
    (
        "refresh_grants_client_fields_and_device_binding",
        client_fields_and_device_binding,
    ),
    (
        "refresh_grants_multiple_devices_and_foreign_isolation",
        multiple_devices_and_foreign_isolation,
    ),
    (
        "refresh_grants_password_change_revokes_old_proofs",
        password_change_revokes_old_proofs,
    ),
    (
        "refresh_grants_kdf_change_revokes_old_proofs",
        kdf_change_revokes_old_proofs,
    ),
    (
        "refresh_grants_security_reset_revokes_owned_devices",
        security_reset_revokes_owned_devices,
    ),
    (
        "refresh_grants_current_keys_and_cipher_decryption",
        current_keys_and_cipher_decryption,
    ),
];
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RefreshGrantsError(&'static str);
impl fmt::Display for RefreshGrantsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for RefreshGrantsError {}
fn require(condition: bool, message: &'static str) -> Result<(), RefreshGrantsError> {
    if condition {
        Ok(())
    } else {
        Err(RefreshGrantsError(message))
    }
}
fn text(value: &Value) -> Result<&str, RefreshGrantsError> {
    value.as_str().ok_or(RefreshGrantsError(
        "Required refresh fixture string missing",
    ))
}
fn array(value: &Value) -> Result<&[Value], RefreshGrantsError> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(RefreshGrantsError("Required refresh fixture array missing"))
}
fn missing_refresh_error() -> Value {
    json!({"message":"refresh_token cannot be blank","validationErrors":{"": ["refresh_token cannot be blank"]},"errorModel":{"message":"refresh_token cannot be blank","object":"error"},"error":"","error_description":"","exceptionMessage":null,"exceptionStackTrace":null,"innerExceptionMessage":null,"object":"error"})
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, RefreshGrantsError> {
        if self.status != expected {
            eprintln!(
                "Refresh grant HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(
            self.status == expected,
            "Refresh grant HTTP status differed",
        )?;
        Ok(self)
    }
    fn json(self) -> Result<Value, RefreshGrantsError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| RefreshGrantsError("Refresh grant response was not JSON"))
    }
    fn empty(self) -> Result<(), RefreshGrantsError> {
        require(
            self.bytes.is_empty(),
            "Refresh fixture mutation success body was not empty",
        )
    }
    fn invalid_refresh(self) -> Result<(), RefreshGrantsError> {
        require(
            self.status(400)?.json()? == json!({"error":"invalid_grant"}),
            "Invalid refresh did not return the minimal invalid_grant response",
        )
    }
    fn missing_refresh(self) -> Result<(), RefreshGrantsError> {
        require(
            self.status(400)?.json()? == missing_refresh_error(),
            "Missing/duplicate refresh proof did not use the outer presence guard",
        )
    }
    fn rejected(self, status: u16) -> Result<(), RefreshGrantsError> {
        let response = self.status(status)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&response.bytes) {
            require(
                ["access_token", "refresh_token", "Key", "PrivateKey"]
                    .iter()
                    .all(|key| value.get(key).is_none()),
                "Rejected refresh response exposed token/key authority",
            )?;
        }
        Ok(())
    }
}
struct Http {
    server: String,
    client: Client,
    requests: usize,
    passwords: usize,
    refreshes: usize,
    refresh_success: usize,
    invalid_refreshes: usize,
    presence_guards: usize,
    form_guards: usize,
}
impl Http {
    fn new() -> Result<Self, RefreshGrantsError> {
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
            .map_err(|_| RefreshGrantsError("Refresh client initialization failed"))?;
        Ok(Self {
            server,
            client,
            requests: 0,
            passwords: 0,
            refreshes: 0,
            refresh_success: 0,
            invalid_refreshes: 0,
            presence_guards: 0,
            form_guards: 0,
        })
    }
    fn capture(response: reqwest::blocking::Response) -> Result<Reply, RefreshGrantsError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_REPLY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| RefreshGrantsError("Refresh response capture failed"))?;
        require(
            bytes.len() as u64 <= MAX_REPLY,
            "Refresh response exceeded private capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn token(
        &mut self,
        form: &Form,
        password: bool,
        bearer: Option<&str>,
    ) -> Result<Reply, RefreshGrantsError> {
        self.requests += 1;
        if password {
            self.passwords += 1;
        } else {
            self.refreshes += 1;
        }
        require(
            self.passwords <= 6 && self.refreshes <= 42,
            "Refresh suite request budget exceeded",
        )?;
        let mut request = self
            .client
            .post(format!("{}/identity/connect/token", self.server))
            .form(form);
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        let reply = Self::capture(
            request
                .send()
                .map_err(|_| RefreshGrantsError("Refresh token request failed"))?,
        )?;
        if !password && reply.status == 200 {
            self.refresh_success += 1;
        }
        Ok(reply)
    }
    fn raw(
        &mut self,
        method: Method,
        path: &str,
        bearer: &str,
        body: Option<&Value>,
    ) -> Result<Reply, RefreshGrantsError> {
        self.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.server))
            .bearer_auth(bearer);
        if let Some(body) = body {
            request = request.json(body);
        }
        Self::capture(
            request
                .send()
                .map_err(|_| RefreshGrantsError("Refresh authority request failed"))?,
        )
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        bearer: &str,
        body: Option<&Value>,
    ) -> Result<Value, RefreshGrantsError> {
        self.raw(method, path, bearer, body)?.status(200)?.json()
    }
    fn login(&mut self, fixture: &Value, device: &str) -> Result<Session, RefreshGrantsError> {
        let form = vec![
            ("grant_type".into(), "password".into()),
            ("client_id".into(), "cli".into()),
            ("scope".into(), "api offline_access".into()),
            ("username".into(), text(&fixture["email"])?.into()),
            (
                "password".into(),
                text(&fixture["masterPasswordHash"])?.into(),
            ),
            ("deviceIdentifier".into(), device.into()),
            ("deviceName".into(), "Refresh proof device".into()),
            ("deviceType".into(), "8".into()),
        ];
        let tokens = self.token(&form, true, None)?.status(200)?.json()?;
        require(
            tokens["Key"] == fixture["key"],
            "Refresh setup login did not use current account key",
        )?;
        session(&tokens, device)
    }
}
#[derive(Clone)]
struct Session {
    access: String,
    refresh: String,
    device: String,
}
fn session(value: &Value, device: &str) -> Result<Session, RefreshGrantsError> {
    let access = text(&value["access_token"])?;
    let refresh = text(&value["refresh_token"])?;
    require(
        !access.is_empty() && !refresh.is_empty(),
        "Refresh response supplied empty authority",
    )?;
    Ok(Session {
        access: access.into(),
        refresh: refresh.into(),
        device: device.into(),
    })
}
struct Account {
    fixture: Value,
    password: String,
    id: String,
    primary: Session,
    cipher: String,
}
#[derive(Clone, PartialEq)]
struct Snapshot {
    profile: Value,
    sync: Value,
    keys: Value,
    domains: Value,
    devices: Value,
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
    token_http_requests: usize,
    password_credential_attempts: usize,
    max_password_attempts_per_peer: usize,
    refresh_post_requests: usize,
    successful_refreshes: usize,
    invalid_grant_refreshes: usize,
    refresh_presence_guards: usize,
    refresh_form_guards: usize,
    fixture_registrations: usize,
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    initial: Vec<Session>,
    clock_new: Option<Session>,
    secondary: Option<Session>,
    password_epoch: Option<Session>,
    password_refreshed: Option<Session>,
    kdf_epoch: Option<Session>,
    kdf_refreshed: Option<Session>,
    final_refreshed: Option<Session>,
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
fn refresh_form(proof: &str, client: Option<&str>) -> Form {
    let mut form = vec![
        ("grant_type".into(), "refresh_token".into()),
        ("refresh_token".into(), proof.into()),
    ];
    if let Some(client) = client {
        form.push(("client_id".into(), client.into()));
    }
    form
}
fn jwt_claims(token: &str) -> Result<Value, RefreshGrantsError> {
    let mut parts = token.split('.');
    let _ = parts.next();
    let body = parts
        .next()
        .ok_or(RefreshGrantsError("Refresh access JWT shape invalid"))?;
    require(
        parts.next().is_some() && parts.next().is_none(),
        "Refresh access JWT shape invalid",
    )?;
    let bytes = URL_SAFE_NO_PAD
        .decode(body)
        .map_err(|_| RefreshGrantsError("Refresh access JWT encoding invalid"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| RefreshGrantsError("Refresh access JWT claims invalid"))
}
fn required(value: &Option<Session>) -> Result<Session, RefreshGrantsError> {
    value
        .clone()
        .ok_or(RefreshGrantsError("Refresh epoch fixture missing"))
}
impl Suite {
    fn receipt(&mut self, status: &'static str) -> Result<(), RefreshGrantsError> {
        if let Some(file) = &mut self.receipt {
            let record = Receipt {
                schema_version: 1,
                status,
                cases: &self.passed,
                expected_cases: CASES.len(),
                passed_cases: self.passed.len(),
                http_requests: self.http.requests,
                token_http_requests: self.http.passwords + self.http.refreshes,
                password_credential_attempts: self.http.passwords,
                max_password_attempts_per_peer: self.http.passwords,
                refresh_post_requests: self.http.refreshes,
                successful_refreshes: self.http.refresh_success,
                invalid_grant_refreshes: self.http.invalid_refreshes,
                refresh_presence_guards: self.http.presence_guards,
                refresh_form_guards: self.http.form_guards,
                fixture_registrations: self.accounts.len(),
            };
            let bytes = serde_json::to_vec(&record)
                .map_err(|_| RefreshGrantsError("Refresh receipt encoding failed"))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| RefreshGrantsError("Refresh receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| RefreshGrantsError("Refresh receipt update failed"))?;
            file.write_all(&bytes)
                .map_err(|_| RefreshGrantsError("Refresh receipt write failed"))?;
            file.sync_all()
                .map_err(|_| RefreshGrantsError("Refresh receipt persistence failed"))?;
        }
        Ok(())
    }
    fn snapshot(&mut self, owner: usize) -> Result<Snapshot, RefreshGrantsError> {
        let token = self.accounts[owner].primary.access.clone();
        Ok(Snapshot {
            profile: self
                .http
                .json(Method::GET, "/api/accounts/profile", &token, None)?,
            sync: self.http.json(Method::GET, "/api/sync", &token, None)?,
            keys: self
                .http
                .json(Method::GET, "/api/accounts/keys", &token, None)?,
            domains: self
                .http
                .json(Method::GET, "/api/settings/domains", &token, None)?,
            devices: self.http.json(Method::GET, "/api/devices", &token, None)?,
            revision: self
                .http
                .json(Method::GET, "/api/accounts/revision-date", &token, None)?,
        })
    }
    fn snapshots(&mut self) -> Result<Vec<Snapshot>, RefreshGrantsError> {
        (0..2).map(|owner| self.snapshot(owner)).collect()
    }
    fn live(&mut self, owner: usize, session: &Session) -> Result<(), RefreshGrantsError> {
        let profile =
            self.http
                .json(Method::GET, "/api/accounts/profile", &session.access, None)?;
        require(
            profile["id"] == self.accounts[owner].id
                && profile["key"] == self.accounts[owner].fixture["key"],
            "Refresh access lost current owner/key authority",
        )
    }
    fn checked_refresh(
        &mut self,
        owner: usize,
        source: &Session,
        form: &Form,
        client: &str,
        bearer: Option<&str>,
    ) -> Result<Session, RefreshGrantsError> {
        let tokens = self.http.token(form, false, bearer)?.status(200)?.json()?;
        require(
            tokens.as_object().is_some_and(|object| {
                object.len() == 5
                    && [
                        "access_token",
                        "refresh_token",
                        "expires_in",
                        "token_type",
                        "scope",
                    ]
                    .iter()
                    .all(|key| object.contains_key(*key))
            }) && tokens["token_type"] == "Bearer"
                && tokens["scope"] == "api offline_access"
                && tokens["expires_in"]
                    .as_i64()
                    .is_some_and(|seconds| (7195..=7200).contains(&seconds)),
            "Refresh response did not have the five password-method fields",
        )?;
        let issued = session(&tokens, &source.device)?;
        let claims = jwt_claims(&issued.access)?;
        let profile = self
            .http
            .json(Method::GET, "/api/accounts/profile", &issued.access, None)?;
        require(
            claims["sub"] == self.accounts[owner].id
                && profile["id"] == self.accounts[owner].id
                && profile["key"] == self.accounts[owner].fixture["key"]
                && claims["sstamp"] == profile["securityStamp"]
                && claims["device"] == source.device
                && claims["devicetype"] == "Linux"
                && claims["client_id"] == client
                && claims["scope"] == json!(["api", "offline_access"])
                && claims["exp"]
                    .as_i64()
                    .zip(claims["nbf"].as_i64())
                    .is_some_and(|(exp, nbf)| exp - nbf == 7200),
            "Refreshed access owner/device/client/stamp/lifetime differed",
        )?;
        Ok(issued)
    }
    fn refresh(
        &mut self,
        owner: usize,
        source: &Session,
        client: Option<&str>,
    ) -> Result<Session, RefreshGrantsError> {
        self.checked_refresh(
            owner,
            source,
            &refresh_form(&source.refresh, client),
            client.unwrap_or("undefined"),
            None,
        )
    }
    fn invalid(&mut self, proof: &str) -> Result<(), RefreshGrantsError> {
        self.http
            .token(&refresh_form(proof, None), false, None)?
            .invalid_refresh()?;
        self.http.invalid_refreshes += 1;
        Ok(())
    }
}
fn form_and_invalid_token_guards(s: &mut Suite) -> Result<(), RefreshGrantsError> {
    let before = s.snapshots()?;
    let proof = s.initial[0].refresh.clone();
    s.http
        .token(&vec![("refresh_token".into(), proof.clone())], false, None)?
        .rejected(422)?;
    s.http.form_guards += 1;
    s.http
        .token(
            &vec![("grant_type".into(), "refresh_token".into())],
            false,
            None,
        )?
        .missing_refresh()?;
    s.http.presence_guards += 1;
    for (first, second) in [
        ("refresh_token", "refresh_token"),
        ("REFRESHTOKEN", "refresh_token"),
        ("[refresh_token]", "refreshToken.foo"),
    ] {
        let form = vec![
            ("grant_type".into(), "refresh_token".into()),
            (first.into(), proof.clone()),
            (second.into(), proof.clone()),
        ];
        s.http.token(&form, false, None)?.missing_refresh()?;
        s.http.presence_guards += 1;
    }
    for invalid in [
        String::new(),
        " \u{2003}\t".into(),
        "malformed-refresh-proof".into(),
        s.initial[0].access.clone(),
        format!("{proof}-invalid"),
    ] {
        s.invalid(&invalid)?;
    }
    require(
        s.snapshots()? == before,
        "Refresh form/token rejection changed account or vault state",
    )
}
fn original_reuse_across_clock(s: &mut Suite) -> Result<(), RefreshGrantsError> {
    let before = s.snapshots()?;
    let original = s.initial[0].clone();
    let first = s.refresh(0, &original, None)?;
    thread::sleep(Duration::from_millis(1100));
    let second = s.refresh(0, &original, None)?;
    let third = s.refresh(0, &original, None)?;
    let fourth = s.refresh(0, &first, None)?;
    for access in [&original, &first, &second, &third, &fourth] {
        s.live(0, access)?;
    }
    s.clock_new = Some(second);
    require(
        s.snapshots()? == before,
        "Reusable refresh proofs changed existing access/vault/account state",
    )
}
fn client_fields_and_device_binding(s: &mut Suite) -> Result<(), RefreshGrantsError> {
    let before = s.snapshots()?;
    let original = s.initial[0].clone();
    let form = vec![
        ("GRANTTYPE.nested".into(), "refresh_token".into()),
        ("grant_type".into(), "password".into()),
        (".REFRESHTOKEN".into(), original.refresh.clone()),
        ("[CLIENTID]".into(), "browser".into()),
        (
            "username".into(),
            text(&s.accounts[1].fixture["email"])?.into(),
        ),
        ("scope".into(), "api admin".into()),
        ("deviceIdentifier".into(), "ignored-device".into()),
        ("deviceName".into(), "ignored-name".into()),
        ("deviceType".into(), "1".into()),
        ("authRequest".into(), "ignored-auth-request".into()),
    ];
    s.checked_refresh(
        0,
        &original,
        &form,
        "browser",
        Some("invalid-refresh-bearer"),
    )?;
    s.refresh(0, &original, None)?;
    s.refresh(0, &original, Some(""))?;
    let mut duplicate = refresh_form(&original.refresh, Some("second"));
    duplicate.insert(0, ("CLIENTID".into(), "first".into()));
    s.checked_refresh(0, &original, &duplicate, "undefined", None)?;
    let split = original
        .refresh
        .char_indices()
        .nth(original.refresh.chars().count() / 2)
        .map_or(0, |(index, _)| index);
    let normalized = format!(
        "\u{2003}{}\t{}\n",
        &original.refresh[..split],
        &original.refresh[split..]
    );
    s.checked_refresh(
        0,
        &original,
        &refresh_form(&normalized, None),
        "undefined",
        None,
    )?;
    let mut ignored = refresh_form(&original.refresh, Some("desktop"));
    ignored.extend([
        ("scope".into(), "invalid".into()),
        ("SCOPE".into(), "also-invalid".into()),
        (
            "username".into(),
            text(&s.accounts[1].fixture["email"])?.into(),
        ),
        ("password".into(), "ignored-proof".into()),
        (
            "deviceIdentifier".into(),
            s.accounts[1].primary.device.clone(),
        ),
        ("deviceName".into(), "ignored-foreign-name".into()),
        ("deviceType".into(), "bad-type".into()),
    ]);
    s.checked_refresh(0, &original, &ignored, "desktop", None)?;
    require(
        s.snapshots()? == before,
        "Refresh form/header inputs changed device ownership, metadata or vault state",
    )
}
fn multiple_devices_and_foreign_isolation(s: &mut Suite) -> Result<(), RefreshGrantsError> {
    let before = s.snapshots()?;
    let device = Uuid::new_v4().to_string();
    let secondary = s.http.login(&s.accounts[0].fixture, &device)?;
    let after_login = s.snapshots()?;
    let mut expected = before;
    expected[0].devices = after_login[0].devices.clone();
    require(
        after_login == expected && array(&after_login[0].devices["data"])?.len() == 2,
        "Second device login changed existing vault/account/foreign authority",
    )?;
    let original = s.initial[0].clone();
    let bob = s.initial[1].clone();
    s.refresh(0, &original, None)?;
    s.refresh(0, &secondary, None)?;
    let mut form = refresh_form(&bob.refresh, Some("cli"));
    form.extend([
        (
            "username".into(),
            text(&s.accounts[0].fixture["email"])?.into(),
        ),
        ("deviceIdentifier".into(), original.device.clone()),
        ("deviceName".into(), "ignored-foreign-device".into()),
        ("deviceType".into(), "1".into()),
    ]);
    s.checked_refresh(1, &bob, &form, "cli", Some(&original.access))?;
    for (owner, session) in [(0, &original), (0, &secondary), (1, &bob)] {
        s.live(owner, session)?;
    }
    s.secondary = Some(secondary);
    require(
        s.snapshots()? == after_login,
        "Refresh crossed owner/device boundaries or changed retained metadata",
    )
}
fn password_change_revokes_old_proofs(s: &mut Suite) -> Result<(), RefreshGrantsError> {
    let foreign = s.snapshot(1)?;
    let password = format!("Changed-refresh-password-{}", Uuid::new_v4());
    let next =
        fixture::rewrap_pbkdf2_password(&s.accounts[0].fixture, &s.accounts[0].password, &password)
            .map_err(|_| RefreshGrantsError("Refresh password rewrap fixture failed"))?;
    let body = json!({"masterPasswordHash":s.accounts[0].fixture["masterPasswordHash"],"newMasterPasswordHash":next["masterPasswordHash"],"key":next["key"]});
    s.http
        .raw(
            Method::POST,
            "/api/accounts/password",
            &s.accounts[0].primary.access,
            Some(&body),
        )?
        .status(200)?
        .empty()?;
    for old in [
        s.initial[0].clone(),
        required(&s.clock_new)?,
        required(&s.secondary)?,
    ] {
        s.invalid(&old.refresh)?;
    }
    let bob = s.initial[1].clone();
    s.refresh(1, &bob, None)?;
    s.http
        .raw(Method::GET, "/api/sync", &s.initial[0].access, None)?
        .rejected(401)?;
    s.accounts[0].fixture = next;
    s.accounts[0].password = password;
    let login = s.http.login(&s.accounts[0].fixture, &s.initial[0].device)?;
    s.accounts[0].primary = login.clone();
    let refreshed = s.refresh(0, &login, None)?;
    s.password_epoch = Some(login);
    s.password_refreshed = Some(refreshed);
    require(
        s.snapshot(1)? == foreign,
        "Password refresh revocation changed foreign account or vault",
    )
}
fn kdf_change_revokes_old_proofs(s: &mut Suite) -> Result<(), RefreshGrantsError> {
    let foreign = s.snapshot(1)?;
    let next = fixture::rewrap_pbkdf2(&s.accounts[0].fixture, &s.accounts[0].password, 800_000)
        .map_err(|_| RefreshGrantsError("Refresh KDF rewrap fixture failed"))?;
    let kdf = json!({"kdf":next["kdf"],"kdfIterations":next["kdfIterations"],"kdfMemory":next["kdfMemory"],"kdfParallelism":next["kdfParallelism"]});
    let body = json!({"masterPasswordHash":s.accounts[0].fixture["masterPasswordHash"],"authenticationData":{"salt":s.accounts[0].fixture["email"],"kdf":kdf,"masterPasswordAuthenticationHash":next["masterPasswordHash"]},"unlockData":{"salt":s.accounts[0].fixture["email"],"kdf":kdf,"masterKeyWrappedUserKey":next["key"]}});
    s.http
        .raw(
            Method::POST,
            "/api/accounts/kdf",
            &s.accounts[0].primary.access,
            Some(&body),
        )?
        .status(200)?
        .empty()?;
    for old in [
        required(&s.password_epoch)?,
        required(&s.password_refreshed)?,
        s.initial[0].clone(),
    ] {
        s.invalid(&old.refresh)?;
    }
    let bob = s.initial[1].clone();
    s.refresh(1, &bob, None)?;
    s.accounts[0].fixture = next;
    let login = s.http.login(&s.accounts[0].fixture, &s.initial[0].device)?;
    s.accounts[0].primary = login.clone();
    let refreshed = s.refresh(0, &login, None)?;
    s.kdf_epoch = Some(login);
    s.kdf_refreshed = Some(refreshed);
    require(
        s.snapshot(1)? == foreign,
        "KDF refresh revocation changed foreign account or vault",
    )
}
fn security_reset_revokes_owned_devices(s: &mut Suite) -> Result<(), RefreshGrantsError> {
    let foreign = s.snapshot(1)?;
    let old_access = s.accounts[0].primary.access.clone();
    s.http
        .raw(
            Method::POST,
            "/api/accounts/security-stamp",
            &old_access,
            Some(&json!({"masterPasswordHash":s.accounts[0].fixture["masterPasswordHash"]})),
        )?
        .status(200)?
        .empty()?;
    for old in [
        required(&s.kdf_epoch)?,
        required(&s.kdf_refreshed)?,
        s.initial[0].clone(),
    ] {
        s.invalid(&old.refresh)?;
    }
    let bob = s.initial[1].clone();
    s.refresh(1, &bob, None)?;
    s.http
        .raw(Method::GET, "/api/sync", &old_access, None)?
        .rejected(401)?;
    let login = s.http.login(&s.accounts[0].fixture, &s.initial[0].device)?;
    s.accounts[0].primary = login.clone();
    s.final_refreshed = Some(s.refresh(0, &login, None)?);
    let current = s.snapshot(0)?;
    require(
        array(&current.devices["data"])?.len() == 1,
        "Security reset retained deleted secondary-device registry",
    )?;
    require(
        s.snapshot(1)? == foreign,
        "Security reset refresh revocation changed foreign account or vault",
    )
}
fn current_keys_and_cipher_decryption(s: &mut Suite) -> Result<(), RefreshGrantsError> {
    let before = s.snapshots()?;
    let original = s.accounts[0].primary.clone();
    let issued = required(&s.final_refreshed)?;
    let bob = s.initial[1].clone();
    let first = s.refresh(0, &original, None)?;
    let second = s.refresh(0, &issued, None)?;
    let foreign = s.refresh(1, &bob, None)?;
    let old = s.initial[0].refresh.clone();
    s.invalid(&old)?;
    for (owner, session) in [
        (0, &original),
        (0, &first),
        (0, &second),
        (1, &bob),
        (1, &foreign),
    ] {
        s.live(owner, session)?;
    }
    let after = s.snapshots()?;
    require(
        after == before,
        "Final refresh replay changed current account/foreign vault state",
    )?;
    for (owner, snapshot) in after.iter().enumerate() {
        let cipher = array(&snapshot.sync["ciphers"])?
            .iter()
            .find(|cipher| cipher["id"] == s.accounts[owner].cipher)
            .ok_or(RefreshGrantsError("Retained refresh cipher missing"))?;
        require(
            decrypt_note(&s.accounts[owner], &snapshot.profile, cipher)? == PLAINTEXT,
            "Refreshed current account keys could not decrypt retained original cipher",
        )?;
    }
    require(
        s.http.passwords == 6
            && s.http.refreshes == 42
            && s.http.refresh_success == 22
            && s.http.invalid_refreshes == 15
            && s.http.presence_guards == 4
            && s.http.form_guards == 1,
        "Refresh/password/guard outcome counts differed",
    )
}
fn seed(http: &mut Http) -> Result<Account, RefreshGrantsError> {
    let email = format!("refresh-grant-{}@example.test", Uuid::new_v4());
    let password = format!("Private-refresh-fixture-{}", Uuid::new_v4());
    let fixture = fixture::seed_account(&http.server, &email, &password)
        .map_err(|_| RefreshGrantsError("Refresh fixture registration failed"))?;
    let encrypted = fixture::encrypted_pbkdf2_value(&fixture, &password, PLAINTEXT)
        .map_err(|_| RefreshGrantsError("Refresh encrypted vault fixture failed"))?;
    let device = Uuid::new_v4().to_string();
    let primary = http.login(&fixture, &device)?;
    let profile = http.json(Method::GET, "/api/accounts/profile", &primary.access, None)?;
    let id = text(&profile["id"])?.to_owned();
    let folder = http.json(
        Method::POST,
        "/api/folders",
        &primary.access,
        Some(&json!({"name":encrypted})),
    )?;
    let cipher=http.json(Method::POST,"/api/ciphers",&primary.access,Some(&json!({"encryptedFor":id,"folderId":folder["id"],"type":2,"name":encrypted,"notes":encrypted,"secureNote":{"type":0}})))?;
    Ok(Account {
        fixture,
        password,
        id,
        primary,
        cipher: text(&cipher["id"])?.into(),
    })
}
fn decrypt(value: &str, key: &[u8; 64]) -> Result<Vec<u8>, RefreshGrantsError> {
    let invalid = || RefreshGrantsError("Refresh encrypted value authentication failed");
    let fields: Vec<_> = value
        .strip_prefix("2.")
        .ok_or_else(invalid)?
        .split('|')
        .collect();
    require(fields.len() == 3, "Refresh encrypted value shape invalid")?;
    let iv = STANDARD.decode(fields[0]).map_err(|_| invalid())?;
    let ciphertext = STANDARD.decode(fields[1]).map_err(|_| invalid())?;
    let tag = STANDARD.decode(fields[2]).map_err(|_| invalid())?;
    let mut mac = Hmac::<Sha256>::new_from_slice(&key[32..]).map_err(|_| invalid())?;
    mac.update(&iv);
    mac.update(&ciphertext);
    mac.verify_slice(&tag).map_err(|_| invalid())?;
    let iv: [u8; 16] = iv.try_into().map_err(|_| invalid())?;
    cbc::Decryptor::<aes::Aes256>::new(key[..32].into(), (&iv).into())
        .decrypt_padded_vec_mut::<Pkcs7>(&ciphertext)
        .map_err(|_| invalid())
}
fn decrypt_note(
    account: &Account,
    profile: &Value,
    cipher: &Value,
) -> Result<Vec<u8>, RefreshGrantsError> {
    let iterations = account.fixture["kdfIterations"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| *n > 0)
        .ok_or(RefreshGrantsError("Refresh client KDF fixture invalid"))?;
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
            .map_err(|_| RefreshGrantsError("Refresh client key derivation failed"))?;
        mac.update(info);
        mac.update(&[1]);
        stretched[index * 32..(index + 1) * 32].copy_from_slice(&mac.finalize().into_bytes());
    }
    let user: [u8; 64] = decrypt(text(&profile["key"])?, &stretched)?
        .try_into()
        .map_err(|_| RefreshGrantsError("Refresh user key length invalid"))?;
    decrypt(text(&cipher["notes"])?, &user)
}
fn private_receipt() -> Result<Option<fs::File>, RefreshGrantsError> {
    let Some(path) = std::env::var_os("BW_REFRESH_GRANTS_RECEIPT") else {
        return Ok(None);
    };
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| RefreshGrantsError("Refresh private receipt creation failed"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| RefreshGrantsError("Refresh receipt permissions failed"))?;
    Ok(Some(file))
}
/// Eight opt-in cases, six password credential attempts and 42 refresh POSTs.
/// Registration helper requests are recorded separately; refresh has no source
/// login-limiter call. Original proof deadlines are never extended by this test.
pub fn run() -> Result<(), RefreshGrantsError> {
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        initial: Vec::new(),
        clock_new: None,
        secondary: None,
        password_epoch: None,
        password_refreshed: None,
        kdf_epoch: None,
        kdf_refreshed: None,
        final_refreshed: None,
        passed: Vec::new(),
        receipt: private_receipt()?,
        finished: false,
    };
    s.receipt("running")?;
    for _ in 0..2 {
        let account = seed(&mut s.http)?;
        s.initial.push(account.primary.clone());
        s.accounts.push(account);
    }
    for (name, case) in CASES {
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
        println!("PASS {name}");
    }
    s.receipt("passed")?;
    s.finished = true;
    println!("PASS refresh-grants HTTP cases: {}", s.passed.len());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use cbc::cipher::BlockEncryptMut;
    #[test]
    fn refresh_decryption_authenticates_before_returning_plaintext() {
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
        require(
            decrypt(&value, &key).is_ok_and(|plain| plain == PLAINTEXT),
            "Synthetic refresh crypto vector failed",
        )
        .unwrap();
        let mut tampered = encrypted;
        tampered[0] ^= 1;
        let value = format!(
            "2.{}|{}|{}",
            STANDARD.encode(iv),
            STANDARD.encode(tampered),
            STANDARD.encode(tag)
        );
        assert!(decrypt(&value, &key).is_err());
    }
    #[test]
    fn refresh_presence_and_invalid_grant_are_distinct_redacted_contracts() {
        assert!(
            Reply {
                status: 400,
                bytes: serde_json::to_vec(&missing_refresh_error()).unwrap()
            }
            .missing_refresh()
            .is_ok()
        );
        assert!(
            Reply {
                status: 400,
                bytes: br#"{"error":"invalid_grant"}"#.to_vec()
            }
            .invalid_refresh()
            .is_ok()
        );
        assert!(
            Reply {
                status: 400,
                bytes: serde_json::to_vec(&missing_refresh_error()).unwrap()
            }
            .invalid_refresh()
            .is_err()
        );
        let error = Reply {
            status: 200,
            bytes: b"private-refresh-token-key".to_vec(),
        }
        .json()
        .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("private-refresh"));
    }
}
