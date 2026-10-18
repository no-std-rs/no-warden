//! Portable password verification and device-session security-stamp reset.
//!
//! Vaultwarden 58a980f850464f7d9cdc99a765df36f0a3308b91 accounts.rs1084–1099,
//! 1445–1474; api/mod.rs49–125; user.rs165–230; device.rs174–181,266–276.
//! These handlers/model hooks are identical in release1.37.4/7c188967, except
//! an unrelated typed-enum change in protected-action OTP lookup. No-SMTP,
//! personal-account policy is exercised; provider verifier upgrades, OTP success,
//! failure injection and push/notification delivery require separate tests.
//! Pending/approved auth requests and API-key secrets survive the reset upstream.
//! All diagnostics and receipts exclude credentials, tokens, keys and bodies.

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
    thread,
    time::Duration,
};
use uuid::Uuid;

const VERIFY: &str = "/api/accounts/verify-password";
const STAMP: &str = "/api/accounts/security-stamp";
const AUTH_REQUESTS: &str = "/api/auth-requests";
const MAX_REPLY_BYTES: u64 = 16 * 1024 * 1024;
type Case = fn(&mut Suite) -> Result<(), AccountSecurityError>;
const CASES: [(&str, Case); 8] = [
    (
        "account_security_verify_password_policy_and_authority",
        account_security_verify_password_policy_and_authority,
    ),
    (
        "account_security_verify_password_schema_and_syntax",
        account_security_verify_password_schema_and_syntax,
    ),
    (
        "account_security_password_proof_failures_and_isolation",
        account_security_password_proof_failures_and_isolation,
    ),
    (
        "account_security_stamp_proof_and_json_guards",
        account_security_stamp_proof_and_json_guards,
    ),
    (
        "account_security_stamp_revokes_existing_access_and_refresh",
        account_security_stamp_revokes_existing_access_and_refresh,
    ),
    (
        "account_security_stamp_device_cleanup_and_owner_isolation",
        account_security_stamp_device_cleanup_and_owner_isolation,
    ),
    (
        "account_security_stamp_preserves_api_key_and_auth_requests",
        account_security_stamp_preserves_api_key_and_auth_requests,
    ),
    (
        "account_security_stamp_positional_repeat_and_recovery",
        account_security_stamp_positional_repeat_and_recovery,
    ),
];

/// Authored static messages retain no server URLs, identifiers or private data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountSecurityError(&'static str);
impl fmt::Display for AccountSecurityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for AccountSecurityError {}
fn require(condition: bool, message: &'static str) -> Result<(), AccountSecurityError> {
    if condition {
        Ok(())
    } else {
        Err(AccountSecurityError(message))
    }
}
fn text(value: &Value) -> Result<&str, AccountSecurityError> {
    value.as_str().ok_or(AccountSecurityError(
        "Required account-security string missing",
    ))
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, AccountSecurityError> {
        if self.status != expected {
            eprintln!(
                "Account-security HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Account-security status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, AccountSecurityError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| AccountSecurityError("Account-security reply was not valid JSON"))
    }
    fn empty(self) -> Result<(), AccountSecurityError> {
        require(
            self.bytes.is_empty(),
            "Security-stamp success was not empty",
        )
    }
    fn rejected(self, expected: u16) -> Result<(), AccountSecurityError> {
        let response = self.status(expected)?;
        // Rocket's data/request guard catchers need not be JSON. Check their
        // status, and ensure any JSON rejection supplies no successful authority.
        if let Ok(value) = serde_json::from_slice::<Value>(&response.bytes) {
            require(
                ["access_token", "refresh_token", "apiKey"]
                    .iter()
                    .all(|field| value.get(field).is_none()),
                "Rejected security request returned credential authority",
            )?;
        }
        Ok(())
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
struct Request {
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
    identity_login_attempts: usize,
    successful_logins: usize,
    refresh_requests: usize,
    decoded_creation_attempts: usize,
    guard_valid_response_polls: usize,
}
struct Suite {
    server: String,
    client: Client,
    accounts: Vec<Account>,
    old_alice: Vec<Session>,
    api_secret: String,
    pending: Option<Request>,
    approved: Option<Request>,
    before_reset: Option<Snapshot>,
    requests: usize,
    identity_requests: usize,
    login_attempts: usize,
    successful_logins: usize,
    refresh_requests: usize,
    creations: usize,
    polls: usize,
    passed: Vec<&'static str>,
    receipt: Option<fs::File>,
    finished: bool,
}
impl Drop for Suite {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.write_receipt("failed");
        }
    }
}
impl Suite {
    fn write_receipt(&mut self, status: &'static str) -> Result<(), AccountSecurityError> {
        if let Some(file) = &mut self.receipt {
            let record = Receipt {
                schema_version: 1,
                status,
                cases: &self.passed,
                expected_cases: CASES.len(),
                passed_cases: self.passed.len(),
                http_requests: self.requests,
                identity_requests: self.identity_requests,
                identity_login_attempts: self.login_attempts,
                successful_logins: self.successful_logins,
                refresh_requests: self.refresh_requests,
                decoded_creation_attempts: self.creations,
                guard_valid_response_polls: self.polls,
            };
            let data = serde_json::to_vec(&record)
                .map_err(|_| AccountSecurityError("Account-security receipt encoding failed"))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| AccountSecurityError("Account-security receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| AccountSecurityError("Account-security receipt update failed"))?;
            file.write_all(&data)
                .map_err(|_| AccountSecurityError("Account-security receipt write failed"))?;
            file.sync_all()
                .map_err(|_| AccountSecurityError("Account-security receipt persistence failed"))?;
        }
        Ok(())
    }
    fn read(response: reqwest::blocking::Response) -> Result<Reply, AccountSecurityError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_REPLY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AccountSecurityError("Account-security reply read failed"))?;
        require(
            bytes.len() as u64 <= MAX_REPLY_BYTES,
            "Account-security reply exceeded capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn request(
        &mut self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Reply, AccountSecurityError> {
        self.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.server));
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        Self::read(
            request
                .send()
                .map_err(|_| AccountSecurityError("Account-security request failed"))?,
        )
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        bearer: &str,
        body: Option<&Value>,
    ) -> Result<Value, AccountSecurityError> {
        let bytes = body.map(Value::to_string);
        self.request(
            method,
            path,
            Some(bearer),
            bytes.as_deref().map(str::as_bytes),
        )?
        .status(200)?
        .json()
    }
    fn token(
        &mut self,
        form: &BTreeMap<String, String>,
        expected: u16,
    ) -> Result<Value, AccountSecurityError> {
        self.requests += 1;
        self.identity_requests += 1;
        if form.get("grant_type").is_some_and(|g| g == "refresh_token") {
            self.refresh_requests += 1;
        } else {
            self.login_attempts += 1;
        }
        require(
            self.identity_requests <= 9,
            "Account-security identity budget exceeded",
        )?;
        let reply = Self::read(
            self.client
                .post(format!("{}/identity/connect/token", self.server))
                .form(form)
                .send()
                .map_err(|_| AccountSecurityError("Account-security identity request failed"))?,
        )?;
        if expected != 200 {
            reply.rejected(expected)?;
            return Ok(Value::Null);
        }
        self.successful_logins += 1;
        reply.status(200)?.json()
    }
    fn password_login(&mut self, owner: usize) -> Result<Session, AccountSecurityError> {
        let fixture = self.accounts[owner].fixture.clone();
        let device = Uuid::new_v4().to_string();
        let tokens = self.token(&password_form(&fixture, &device)?, 200)?;
        session(&tokens, &device, true)
    }
    fn api_login(&mut self) -> Result<Session, AccountSecurityError> {
        let device = Uuid::new_v4().to_string();
        let form = BTreeMap::from([
            ("grant_type".into(), "client_credentials".into()),
            ("client_id".into(), format!("user.{}", self.accounts[0].id)),
            ("client_secret".into(), self.api_secret.clone()),
            ("scope".into(), "api".into()),
            ("deviceIdentifier".into(), device.clone()),
            ("deviceName".into(), "account-security API fixture".into()),
            ("deviceType".into(), "8".into()),
        ]);
        let tokens = self.token(&form, 200)?;
        require(tokens["scope"] == "api", "API key changed access scope")?;
        session(&tokens, &device, false)
    }
    fn snapshot(&mut self, bearer: &str) -> Result<Snapshot, AccountSecurityError> {
        let profile = self.json(Method::GET, "/api/accounts/profile", bearer, None)?;
        let sync = self.json(Method::GET, "/api/sync", bearer, None)?;
        let keys = self.json(Method::GET, "/api/accounts/keys", bearer, None)?;
        let domains = self.json(Method::GET, "/api/settings/domains", bearer, None)?;
        let revision = self
            .json(Method::GET, "/api/accounts/revision-date", bearer, None)?
            .as_i64()
            .ok_or(AccountSecurityError(
                "Account-security revision was not an integer",
            ))?;
        require(
            sync["profile"] == profile,
            "Sync and profile account views differed",
        )?;
        Ok(Snapshot {
            profile,
            sync,
            keys,
            domains,
            revision,
        })
    }
    fn snapshots(&mut self) -> Result<Vec<Snapshot>, AccountSecurityError> {
        let tokens: Vec<_> = self
            .accounts
            .iter()
            .map(|a| a.current.access.clone())
            .collect();
        tokens.iter().map(|token| self.snapshot(token)).collect()
    }
    fn device_lists(&mut self) -> Result<Vec<Value>, AccountSecurityError> {
        let tokens: Vec<_> = self
            .accounts
            .iter()
            .map(|a| a.current.access.clone())
            .collect();
        tokens
            .iter()
            .map(|t| self.json(Method::GET, "/api/devices", t, None))
            .collect()
    }
    fn unchanged(
        &mut self,
        snapshots: &[Snapshot],
        devices: &[Value],
    ) -> Result<(), AccountSecurityError> {
        require(
            self.snapshots()? == snapshots,
            "Security check changed accounts, credentials or vault data",
        )?;
        require(
            self.device_lists()? == devices,
            "Security check changed registered devices",
        )
    }
    fn verify(&mut self, body: &Value) -> Result<(), AccountSecurityError> {
        let token = self.accounts[0].current.access.clone();
        let response = self.json(Method::POST, VERIFY, &token, Some(body))?;
        require(
            response == json!({"Object":"masterPasswordPolicy"}),
            "Personal password policy projection differed",
        )
    }
    fn reject_bodies(
        &mut self,
        path: &str,
        bodies: &[&str],
        expected: u16,
    ) -> Result<(), AccountSecurityError> {
        let token = self.accounts[0].current.access.clone();
        for (index, body) in bodies.iter().enumerate() {
            let response = self.request(Method::POST, path, Some(&token), Some(body.as_bytes()))?;
            if response.status != expected {
                eprintln!("Account-security JSON fixture {}, method POST", index + 1);
            }
            response.rejected(expected)?;
        }
        Ok(())
    }
    fn known(
        &mut self,
        device: &str,
        owner: usize,
        expected: bool,
    ) -> Result<(), AccountSecurityError> {
        self.requests += 1;
        let email = text(&self.accounts[owner].fixture["email"])?;
        let reply = Self::read(
            self.client
                .get(format!("{}/api/devices/knowndevice", self.server))
                .header("X-Request-Email", URL_SAFE_NO_PAD.encode(email))
                .header("X-Device-Identifier", device)
                .send()
                .map_err(|_| AccountSecurityError("Account-security discovery request failed"))?,
        )?
        .status(200)?
        .json()?;
        require(
            reply == json!(expected),
            "Reset device-discovery result differed",
        )
    }
    fn create_request(&mut self, device: &str) -> Result<Request, AccountSecurityError> {
        self.requests += 1;
        self.creations += 1;
        let code = format!("reset-proof\0雪+{}", Uuid::new_v4());
        let body = json!({"accessCode":code,"deviceIdentifier":device,
            "email":self.accounts[0].fixture["email"],"publicKey":"opaque-reset-public-key"});
        let mut wire = Self::read(
            self.client
                .post(format!("{}{AUTH_REQUESTS}", self.server))
                .header("device-type", "8")
                .json(&body)
                .send()
                .map_err(|_| AccountSecurityError("Reset auth-request creation failed"))?,
        )?
        .status(200)?
        .json()?;
        require(
            wire["requestApproved"] == false,
            "Reset auth-request did not begin pending",
        )?;
        wire["requestApproved"] = Value::Null;
        Ok(Request { code, wire })
    }
    fn poll(&mut self, record: &Request, expected: u16) -> Result<(), AccountSecurityError> {
        self.polls += 1;
        require(
            self.creations + self.polls <= 10,
            "Account-security public budget exceeded",
        )?;
        let query = serde_url_query(&record.code)?;
        let path = format!(
            "{AUTH_REQUESTS}/{}/response?{query}",
            text(&record.wire["id"])?
        );
        self.requests += 1;
        let response = Self::read(
            self.client
                .get(format!("{}{path}", self.server))
                .header("device-type", "8")
                .send()
                .map_err(|_| AccountSecurityError("Reset auth-request polling failed"))?,
        )?;
        if expected == 200 {
            require(
                response.status(200)?.json()? == record.wire,
                "Reset changed or consumed the public approved request",
            )
        } else {
            response.rejected(expected)
        }
    }
    fn assert_requests(&mut self) -> Result<(), AccountSecurityError> {
        let bearer = self.accounts[0].current.access.clone();
        let pending = self
            .pending
            .clone()
            .ok_or(AccountSecurityError("Pending reset fixture missing"))?;
        let approved = self
            .approved
            .clone()
            .ok_or(AccountSecurityError("Approved reset fixture missing"))?;
        for record in [&pending, &approved] {
            let actual = self.json(
                Method::GET,
                &format!("{AUTH_REQUESTS}/{}", text(&record.wire["id"])?),
                &bearer,
                None,
            )?;
            require(
                actual == record.wire,
                "Security-stamp reset changed a retained auth request",
            )?;
        }
        let list = self.json(Method::GET, AUTH_REQUESTS, &bearer, None)?;
        let rows = list["data"]
            .as_array()
            .ok_or(AccountSecurityError("Reset pending list shape differed"))?;
        require(
            rows.len() == 1 && rows[0] == pending.wire,
            "Reset did not retain exactly its pending auth request",
        )
    }
    fn reset(&mut self, body: &Value) -> Result<(), AccountSecurityError> {
        let bearer = self.accounts[0].current.access.clone();
        thread::sleep(Duration::from_millis(10));
        self.request(
            Method::POST,
            STAMP,
            Some(&bearer),
            Some(body.to_string().as_bytes()),
        )?
        .status(200)?
        .empty()
    }
}

fn password_form(
    fixture: &Value,
    device: &str,
) -> Result<BTreeMap<String, String>, AccountSecurityError> {
    Ok(BTreeMap::from([
        ("grant_type".into(), "password".into()),
        ("client_id".into(), "cli".into()),
        ("scope".into(), "api offline_access".into()),
        ("username".into(), text(&fixture["email"])?.to_owned()),
        (
            "password".into(),
            text(&fixture["masterPasswordHash"])?.to_owned(),
        ),
        ("deviceIdentifier".into(), device.to_owned()),
        (
            "deviceName".into(),
            "account-security password fixture".into(),
        ),
        ("deviceType".into(), "8".into()),
    ]))
}
fn session(tokens: &Value, device: &str, refresh: bool) -> Result<Session, AccountSecurityError> {
    let access = text(&tokens["access_token"])?.to_owned();
    require(
        !access.is_empty() && tokens["token_type"] == "Bearer",
        "Reset recovery grant lacked bearer authority",
    )?;
    require(
        tokens.get("refresh_token").is_some_and(Value::is_string) == refresh,
        "Reset recovery grant refresh authority differed",
    )?;
    Ok(Session {
        access,
        refresh: tokens["refresh_token"].as_str().map(str::to_owned),
        device: device.to_owned(),
    })
}
fn jwt_claims(token: &str) -> Result<Value, AccountSecurityError> {
    let encoded = token
        .split('.')
        .nth(1)
        .ok_or(AccountSecurityError("Reset token lacked claims"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| AccountSecurityError("Reset token claims encoding differed"))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| AccountSecurityError("Reset token claims were not JSON"))
}
fn serde_url_query(code: &str) -> Result<String, AccountSecurityError> {
    // Url's form encoder preserves opaque plus, Unicode and NUL without exposing
    // the code in diagnostics or hand-building query escaping.
    let mut url = reqwest::Url::parse("http://localhost/")
        .map_err(|_| AccountSecurityError("Reset query construction failed"))?;
    url.query_pairs_mut().append_pair("code", code);
    Ok(url
        .query()
        .ok_or(AccountSecurityError("Reset query missing"))?
        .to_owned())
}
fn changed_stamp(before: &Snapshot, after: &Snapshot) -> Result<(), AccountSecurityError> {
    let stamp = text(&after.profile["securityStamp"])?;
    require(
        Uuid::parse_str(stamp).is_ok()
            && after.profile["securityStamp"] != before.profile["securityStamp"],
        "Reset did not generate a fresh security stamp",
    )?;
    require(
        after.revision > before.revision,
        "Reset did not advance account revision",
    )?;
    let mut expected = before.clone();
    expected.profile["securityStamp"] = json!(stamp);
    expected.sync["profile"] = expected.profile.clone();
    expected.revision = after.revision;
    require(
        *after == expected,
        "Reset changed password, keys, settings or encrypted vault data",
    )
}

fn account_security_verify_password_policy_and_authority(
    s: &mut Suite,
) -> Result<(), AccountSecurityError> {
    let before = s.snapshots()?;
    let devices = s.device_lists()?;
    let hash = s.accounts[0].fixture["masterPasswordHash"].clone();
    for body in [
        json!({"masterPasswordHash":hash}),
        json!({"masterPasswordHash":hash,"id":s.accounts[1].id,"owner":s.accounts[1].id,
            "email":s.accounts[1].fixture["email"],"securityStamp":"forged","key":"forged",
            "passwordIterations":1,"kdf":-1,"otp":7,"unknown":{"opaque":"雪\0"}}),
        json!([hash]),
    ] {
        s.verify(&body)?;
    }
    s.unchanged(&before, &devices)
}
fn account_security_verify_password_schema_and_syntax(
    s: &mut Suite,
) -> Result<(), AccountSecurityError> {
    let before = s.snapshots()?;
    let devices = s.device_lists()?;
    s.reject_bodies(
        VERIFY,
        &[
            "null",
            "false",
            "7",
            "\"text\"",
            "{}",
            "[]",
            "[null]",
            "[7]",
            "{\"masterPasswordHash\":null}",
            "{\"masterPasswordHash\":false}",
            "{\"masterPasswordHash\":7}",
            "{\"masterPasswordHash\":[]}",
            "{\"masterPasswordHash\":{}}",
            "{\"MasterPasswordHash\":\"wrong-case\"}",
            "{\"master_password_hash\":\"wrong-name\"}",
            "{\"otp\":\"not-a-password-proof\"}",
            "{\"masterPasswordHash\":\"a\",\"masterPasswordHash\":\"b\"}",
            "{\"masterPasswordHash\":\"a\",\"masterPasswordHa\\u0073h\":\"b\"}",
        ],
        422,
    )?;
    s.reject_bodies(
        VERIFY,
        &[
            "",
            "{",
            "{\"masterPasswordHash\":",
            "[\"a\",null]",
            "{\"masterPasswordHash\":\"a\"} trailing",
            "{\"masterPasswordHash\":\"a\"}{}",
        ],
        400,
    )?;
    s.unchanged(&before, &devices)
}
fn account_security_password_proof_failures_and_isolation(
    s: &mut Suite,
) -> Result<(), AccountSecurityError> {
    let before = s.snapshots()?;
    let devices = s.device_lists()?;
    let alice = s.accounts[0].current.access.clone();
    for proof in [
        json!(""),
        json!("wrong-proof\0雪"),
        s.accounts[1].fixture["masterPasswordHash"].clone(),
    ] {
        s.request(
            Method::POST,
            VERIFY,
            Some(&alice),
            Some(json!({"masterPasswordHash":proof}).to_string().as_bytes()),
        )?
        .rejected(400)?;
    }
    for path in [VERIFY, STAMP] {
        for bearer in [None, Some("invalid-account-security-bearer")] {
            for body in ["{", "{\"masterPasswordHash\":\"wrong\"}"] {
                s.request(Method::POST, path, bearer, Some(body.as_bytes()))?
                    .rejected(401)?;
            }
        }
    }
    s.unchanged(&before, &devices)
}
fn account_security_stamp_proof_and_json_guards(s: &mut Suite) -> Result<(), AccountSecurityError> {
    let before = s.snapshots()?;
    let devices = s.device_lists()?;
    s.reject_bodies(
        STAMP,
        &[
            "null",
            "false",
            "7",
            "\"text\"",
            "[]",
            "[null]",
            "[\"a\"]",
            "[7,null]",
            "[null,7]",
            "{\"masterPasswordHash\":7}",
            "{\"masterPasswordHash\":false}",
            "{\"masterPasswordHash\":[]}",
            "{\"otp\":7}",
            "{\"otp\":false}",
            "{\"otp\":{}}",
            "{\"masterPasswordHash\":\"a\",\"MasterPasswordHash\":\"b\"}",
            "{\"masterPasswordHash\":\"a\",\"masterPasswordHa\\u0073h\":\"b\"}",
            "{\"otp\":\"a\",\"otp\":\"b\"}",
        ],
        422,
    )?;
    s.reject_bodies(
        STAMP,
        &["", "{", "{\"otp\":", "[null,null,0]", "{} trailing", "{}{}"],
        400,
    )?;
    let alice = s.accounts[0].current.access.clone();
    for body in [
        json!({}),
        json!({"masterPasswordHash":null,"otp":null}),
        json!([null, null]),
        json!({"masterPasswordHash":""}),
        json!({"MasterPasswordHash":"wrong-proof\0雪"}),
        json!({"masterPasswordHash":s.accounts[1].fixture["masterPasswordHash"]}),
        json!({"otp":"missing-protected-action-token"}),
        json!({"masterPasswordHash":s.accounts[0].fixture["masterPasswordHash"],"otp":"both-present"}),
    ] {
        s.request(
            Method::POST,
            STAMP,
            Some(&alice),
            Some(body.to_string().as_bytes()),
        )?
        .rejected(400)?;
    }
    s.unchanged(&before, &devices)?;
    // Create these immediately before reset so the separate five-minute grant
    // deadline stays unrelated to this suite's schema checks.
    let device = s.old_alice[1].device.clone();
    s.pending = Some(s.create_request(&device)?);
    let mut approved = s.create_request(&device)?;
    let body = json!({"deviceIdentifier":s.accounts[0].current.device,
        "key":s.accounts[0].fixture["key"],"masterPasswordHash":"opaque-approved-hash\0雪","requestApproved":true});
    approved.wire = s.json(
        Method::PUT,
        &format!("{AUTH_REQUESTS}/{}", text(&approved.wire["id"])?),
        &alice,
        Some(&body),
    )?;
    require(
        approved.wire["requestApproved"] == true && approved.wire["responseDate"].is_string(),
        "Reset approval fixture was not approved",
    )?;
    s.approved = Some(approved);
    s.assert_requests()
}
fn account_security_stamp_revokes_existing_access_and_refresh(
    s: &mut Suite,
) -> Result<(), AccountSecurityError> {
    s.before_reset = Some(s.snapshot(&s.accounts[0].current.access.clone())?);
    let bob = s.snapshot(&s.accounts[1].current.access.clone())?;
    let bob_devices = s.json(
        Method::GET,
        "/api/devices",
        &s.accounts[1].current.access.clone(),
        None,
    )?;
    s.reset(&json!({"MasterPasswordHash":s.accounts[0].fixture["masterPasswordHash"],"otp":null,
        "id":s.accounts[1].id,"owner":s.accounts[1].id,"securityStamp":"forged","key":"forged","unknown":{"future":true}}))?;
    for session in s.old_alice.clone() {
        for path in [
            "/api/accounts/profile",
            "/api/sync",
            "/api/devices",
            VERIFY,
            STAMP,
        ] {
            let method = if path == VERIFY || path == STAMP {
                Method::POST
            } else {
                Method::GET
            };
            s.request(method, path, Some(&session.access), Some(b"{"))?
                .rejected(401)?;
        }
    }
    let refresh = s.old_alice[0]
        .refresh
        .clone()
        .ok_or(AccountSecurityError("Old refresh fixture missing"))?;
    s.token(
        &BTreeMap::from([
            ("grant_type".into(), "refresh_token".into()),
            ("refresh_token".into(), refresh),
            ("client_id".into(), "cli".into()),
        ]),
        400,
    )?;
    require(
        s.snapshot(&s.accounts[1].current.access.clone())? == bob,
        "Reset changed the other account",
    )?;
    require(
        s.json(
            Method::GET,
            "/api/devices",
            &s.accounts[1].current.access.clone(),
            None,
        )? == bob_devices,
        "Reset removed another owner's devices",
    )
}
fn account_security_stamp_device_cleanup_and_owner_isolation(
    s: &mut Suite,
) -> Result<(), AccountSecurityError> {
    for old in s.old_alice.clone() {
        s.known(&old.device, 0, false)?;
    }
    s.known(&s.accounts[1].current.device.clone(), 1, true)?;
    let recovery = s.api_login()?;
    s.accounts[0].current = recovery.clone();
    let snapshot = s.snapshot(&recovery.access)?;
    changed_stamp(
        s.before_reset
            .as_ref()
            .ok_or(AccountSecurityError("Reset baseline missing"))?,
        &snapshot,
    )?;
    let claims = jwt_claims(&recovery.access)?;
    require(
        claims["sstamp"] == snapshot.profile["securityStamp"]
            && claims["device"] == recovery.device
            && claims["sub"] == s.accounts[0].id,
        "Recovery JWT did not carry the new stamp and owned device",
    )?;
    let devices = s.json(Method::GET, "/api/devices", &recovery.access, None)?;
    let rows = devices["data"]
        .as_array()
        .ok_or(AccountSecurityError("Recovery devices were not a list"))?;
    require(
        rows.len() == 1 && rows[0]["identifier"] == recovery.device,
        "Reset retained an old device or lost its recovery device",
    )?;
    // Recreating an old identifier must not resurrect its old signed bearer.
    let device = s.old_alice[0].device.clone();
    let fixture = s.accounts[0].fixture.clone();
    let tokens = s.token(&password_form(&fixture, &device)?, 200)?;
    let password = session(&tokens, &device, true)?;
    s.request(
        Method::GET,
        "/api/accounts/profile",
        Some(&s.old_alice[0].access.clone()),
        None,
    )?
    .rejected(401)?;
    require(
        s.snapshot(&password.access)? == snapshot,
        "Password recovery changed account or vault data",
    )?;
    s.accounts[0].current = password;
    s.assert_requests()
}
fn account_security_stamp_preserves_api_key_and_auth_requests(
    s: &mut Suite,
) -> Result<(), AccountSecurityError> {
    let alice = s.accounts[0].clone();
    let before = s.snapshot(&alice.current.access)?;
    let response = s.json(
        Method::POST,
        "/api/accounts/api-key",
        &alice.current.access,
        Some(&json!({"masterPasswordHash":alice.fixture["masterPasswordHash"]})),
    )?;
    require(
        response["apiKey"] == s.api_secret,
        "Reset rotated or removed the existing API-key secret",
    )?;
    s.assert_requests()?;
    let approved = s
        .approved
        .clone()
        .ok_or(AccountSecurityError("Approved reset fixture missing"))?;
    let pending = s
        .pending
        .clone()
        .ok_or(AccountSecurityError("Pending reset fixture missing"))?;
    s.poll(&approved, 200)?;
    s.poll(&pending, 200)?;
    let device = Uuid::new_v4().to_string();
    let mut form = password_form(&alice.fixture, &device)?;
    form.insert("authRequest".into(), text(&approved.wire["id"])?.to_owned());
    form.insert("password".into(), approved.code.clone());
    let tokens = s.token(&form, 200)?;
    let granted = session(&tokens, &device, true)?;
    require(
        s.snapshot(&granted.access)? == before,
        "Retained approved request lost account authority or changed vault data",
    )?;
    s.accounts[0].current = granted;
    s.poll(&approved, 200)?;
    s.assert_requests()?;
    require(
        s.snapshot(&s.accounts[0].current.access.clone())? == before,
        "Surviving credentials changed account revision or encrypted data",
    )
}
fn account_security_stamp_positional_repeat_and_recovery(
    s: &mut Suite,
) -> Result<(), AccountSecurityError> {
    let before = s.snapshot(&s.accounts[0].current.access.clone())?;
    let bob = s.snapshot(&s.accounts[1].current.access.clone())?;
    let old = s.accounts[0].current.clone();
    s.reset(&json!([s.accounts[0].fixture["masterPasswordHash"], null]))?;
    s.request(Method::GET, "/api/sync", Some(&old.access), None)?
        .rejected(401)?;
    s.known(&old.device, 0, false)?;
    s.accounts[0].current = s.password_login(0)?;
    let after = s.snapshot(&s.accounts[0].current.access.clone())?;
    changed_stamp(&before, &after)?;
    require(
        jwt_claims(&s.accounts[0].current.access)?["sstamp"] == after.profile["securityStamp"],
        "Repeated reset recovery JWT reused the prior stamp",
    )?;
    s.verify(&json!({"masterPasswordHash":s.accounts[0].fixture["masterPasswordHash"]}))?;
    s.assert_requests()?;
    require(
        s.snapshot(&s.accounts[1].current.access.clone())? == bob,
        "Repeated reset changed the other account",
    )?;
    require(
        s.identity_requests == 9 && s.successful_logins == 8 && s.refresh_requests == 1,
        "Authored security identity counts changed",
    )
}

fn private_receipt() -> Result<Option<fs::File>, AccountSecurityError> {
    let Some(path) = std::env::var_os("BW_ACCOUNT_SECURITY_RECEIPT") else {
        return Ok(None);
    };
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| AccountSecurityError("Account-security private receipt creation failed"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| AccountSecurityError("Account-security private receipt permissions failed"))?;
    Ok(Some(file))
}
/// Run this selected group on a fresh reference process with unchanged limits.
/// It uses nine token requests (eight successful grants and one failed refresh),
/// two public auth-request creations and three public polls, with no retries.
pub fn run() -> Result<(), AccountSecurityError> {
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
        .map_err(|_| AccountSecurityError("Account-security client construction failed"))?;
    let mut suite = Suite {
        server,
        client,
        accounts: Vec::new(),
        old_alice: Vec::new(),
        api_secret: String::new(),
        pending: None,
        approved: None,
        before_reset: None,
        requests: 0,
        identity_requests: 0,
        login_attempts: 0,
        successful_logins: 0,
        refresh_requests: 0,
        creations: 0,
        polls: 0,
        passed: Vec::new(),
        receipt: private_receipt()?,
        finished: false,
    };
    suite.write_receipt("running")?;
    for _ in 0..2 {
        let email = format!("account-security-{}@example.test", Uuid::new_v4());
        let password = format!("Private-security-fixture-{}", Uuid::new_v4());
        let fixture = fixture::seed_account(&suite.server, &email, &password)
            .map_err(|_| AccountSecurityError("Account-security fixture registration failed"))?;
        let device = Uuid::new_v4().to_string();
        let tokens = suite.token(&password_form(&fixture, &device)?, 200)?;
        let current = session(&tokens, &device, true)?;
        let profile = suite.json(Method::GET, "/api/accounts/profile", &current.access, None)?;
        let id = text(&profile["id"])?.to_owned();
        let folder = suite.json(
            Method::POST,
            "/api/folders",
            &current.access,
            Some(&json!({"name":fixture["key"]})),
        )?;
        suite.json(Method::POST, "/api/ciphers", &current.access, Some(&json!({"type":2,"name":fixture["key"],"notes":fixture["key"],"folderId":folder["id"],"encryptedFor":id,"secureNote":{"type":0,"futureOpaqueField":fixture["key"]}})))?;
        suite.accounts.push(Account {
            fixture,
            id,
            current,
        });
    }
    suite.old_alice.push(suite.accounts[0].current.clone());
    let second = suite.password_login(0)?;
    suite.old_alice.push(second);
    let alice = suite.accounts[0].clone();
    let api_key = suite.json(
        Method::POST,
        "/api/accounts/api-key",
        &alice.current.access,
        Some(&json!({"masterPasswordHash":alice.fixture["masterPasswordHash"]})),
    )?;
    suite.api_secret = text(&api_key["apiKey"])?.to_owned();
    let api = suite.api_login()?;
    suite.old_alice.push(api);
    for (name, case) in CASES {
        case(&mut suite)?;
        suite.passed.push(name);
        suite.write_receipt("running")?;
        println!("PASS {name}");
    }
    suite.write_receipt("passed")?;
    suite.finished = true;
    println!("PASS account-security HTTP cases: {}", suite.passed.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PasswordShape {
        master_password_hash: String,
    }
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct PasswordOrOtpShape {
        #[serde(alias = "MasterPasswordHash")]
        master_password_hash: Option<String>,
        otp: Option<String>,
    }
    #[test]
    fn password_schema_has_no_pascal_alias_and_sequence_has_one_slot() {
        let body: PasswordShape = serde_json::from_str("[\"opaque\"]").unwrap();
        assert!(body.master_password_hash == "opaque");
        assert!(
            serde_json::from_str::<PasswordShape>("{\"MasterPasswordHash\":\"opaque\"}")
                .err()
                .unwrap()
                .is_data()
        );
        assert!(
            serde_json::from_str::<PasswordShape>(
                "{\"masterPasswordHash\":\"a\",\"masterPasswordHa\\u0073h\":\"b\"}"
            )
            .err()
            .unwrap()
            .is_data()
        );
        assert!(
            serde_json::from_str::<PasswordShape>("[\"opaque\",null]")
                .err()
                .unwrap()
                .is_syntax()
        );
    }
    #[test]
    fn password_or_otp_optional_map_fields_require_both_sequence_slots() {
        let body: PasswordOrOtpShape = serde_json::from_str("{}").unwrap();
        assert!(body.master_password_hash.is_none() && body.otp.is_none());
        let body: PasswordOrOtpShape = serde_json::from_str("[\"opaque\",null]").unwrap();
        assert!(body.master_password_hash.as_deref() == Some("opaque") && body.otp.is_none());
        assert!(
            serde_json::from_str::<PasswordOrOtpShape>("[\"opaque\"]")
                .err()
                .unwrap()
                .is_data()
        );
        assert!(
            serde_json::from_str::<PasswordOrOtpShape>("[null,null,0]")
                .err()
                .unwrap()
                .is_syntax()
        );
    }
    #[test]
    fn diagnostics_and_typed_receipts_exclude_private_data() {
        let marker = "private-account-security-marker";
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
        let record = Receipt {
            schema_version: 1,
            status: "passed",
            cases: &[CASES[0].0],
            expected_cases: 8,
            passed_cases: 1,
            http_requests: 1,
            identity_requests: 9,
            identity_login_attempts: 8,
            successful_logins: 8,
            refresh_requests: 1,
            decoded_creation_attempts: 2,
            guard_valid_response_polls: 3,
        };
        let wire = serde_json::to_value(record).unwrap();
        assert!(
            wire["identityRequests"] == 9
                && wire["identityLoginAttempts"] == 8
                && !wire.to_string().contains(marker)
        );
    }
}
