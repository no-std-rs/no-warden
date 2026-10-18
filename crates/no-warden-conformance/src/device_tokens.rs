//! Portable device push-token contracts with the push relay disabled.
//!
//! Pinned Vaultwarden 58a980f850464f7d9cdc99a765df36f0a3308b91:
//! core/accounts.rs1577–1641, push.rs87–151, and auth.rs637–710.
//! Rocket v0.5.1 codegen attribute/route/mod.rs323–328 evaluates request
//! guards before path guards, then JSON data guards. Hidden push-token storage,
//! same-value activity shortcuts, and relay delivery need provider-level tests;
//! public discovery responses cannot prove those properties.

use crate::fixture;
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use std::{
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    time::Duration,
};
use uuid::Uuid;

type Case = fn(&mut Suite) -> Result<(), DeviceTokensError>;
const CASES: [(&str, Case); 8] = [
    (
        "device_tokens_aliases_and_empty_responses",
        device_tokens_aliases_and_empty_responses,
    ),
    (
        "device_tokens_valid_path_identifiers_are_advisory",
        device_tokens_valid_path_identifiers_are_advisory,
    ),
    (
        "device_tokens_opaque_values_and_ignored_fields",
        device_tokens_opaque_values_and_ignored_fields,
    ),
    (
        "device_tokens_positional_and_same_value",
        device_tokens_positional_and_same_value,
    ),
    (
        "device_tokens_schema_and_syntax_rejections",
        device_tokens_schema_and_syntax_rejections,
    ),
    (
        "device_tokens_authenticated_guard_precedence",
        device_tokens_authenticated_guard_precedence,
    ),
    (
        "device_tokens_public_clear_push_disabled",
        device_tokens_public_clear_push_disabled,
    ),
    (
        "device_tokens_clear_path_guard_and_ignored_body",
        device_tokens_clear_path_guard_and_ignored_body,
    ),
];
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// Diagnostics retain only authored static messages, never URLs or payloads.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeviceTokensError(&'static str);
impl fmt::Display for DeviceTokensError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for DeviceTokensError {}
fn require(condition: bool, message: &'static str) -> Result<(), DeviceTokensError> {
    if condition {
        Ok(())
    } else {
        Err(DeviceTokensError(message))
    }
}
fn text(value: &Value) -> Result<&str, DeviceTokensError> {
    value
        .as_str()
        .ok_or(DeviceTokensError("Required token fixture string missing"))
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, DeviceTokensError> {
        if self.status != expected {
            eprintln!(
                "Device-token HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Device-token HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, DeviceTokensError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| DeviceTokensError("Device-token response was not valid JSON"))
    }
    fn empty(self) -> Result<(), DeviceTokensError> {
        require(
            self.bytes.is_empty(),
            "Device-token success response was not empty",
        )
    }
}
#[derive(Clone)]
struct Session {
    token: String,
    device_id: String,
}
#[derive(Clone)]
struct Account {
    session: Session,
    id: String,
    fixture: Value,
}
#[derive(PartialEq)]
struct Snapshot {
    profile: Value,
    sync: Value,
    devices: Value,
    revision: i64,
}
struct Suite {
    server: String,
    client: Client,
    accounts: Vec<Account>,
    second_alice: Option<Session>,
    requests: usize,
    identity_requests: usize,
    successful_logins: usize,
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
    fn write_receipt(&mut self, status: &'static str) -> Result<(), DeviceTokensError> {
        if let Some(file) = &mut self.receipt {
            let record = json!({"schemaVersion":1,"status":status,"cases":self.passed,
                "passedCases":self.passed.len(),"expectedCases":CASES.len(),
                "httpRequests":self.requests,"identityRequests":self.identity_requests,
                "identityLoginAttempts":self.identity_requests,"successfulLogins":self.successful_logins,
                "refreshRequests":0});
            file.seek(SeekFrom::Start(0))
                .map_err(|_| DeviceTokensError("Device-token receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| DeviceTokensError("Device-token receipt update failed"))?;
            file.write_all(record.to_string().as_bytes())
                .map_err(|_| DeviceTokensError("Device-token receipt write failed"))?;
            file.sync_all()
                .map_err(|_| DeviceTokensError("Device-token receipt persistence failed"))?;
        }
        Ok(())
    }
    fn read(&self, response: reqwest::blocking::Response) -> Result<Reply, DeviceTokensError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| DeviceTokensError("Device-token response read failed"))?;
        require(
            bytes.len() as u64 <= MAX_RESPONSE_BYTES,
            "Device-token response exceeded capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn request(
        &mut self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Reply, DeviceTokensError> {
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
        let response = request
            .send()
            .map_err(|_| DeviceTokensError("Device-token HTTP request failed"))?;
        self.read(response)
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        bearer: &str,
        body: Option<&Value>,
    ) -> Result<Value, DeviceTokensError> {
        let body = body.map(Value::to_string);
        self.request(
            method,
            path,
            Some(bearer),
            body.as_deref().map(str::as_bytes),
        )?
        .status(200)?
        .json()
    }
    fn login(
        &mut self,
        fixture: &Value,
        id: &str,
        name: &str,
    ) -> Result<Session, DeviceTokensError> {
        let form = [
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("username", text(&fixture["email"])?),
            ("password", text(&fixture["masterPasswordHash"])?),
            ("deviceIdentifier", id),
            ("deviceName", name),
            ("deviceType", "8"),
        ];
        self.requests += 1;
        self.identity_requests += 1;
        let response = self
            .client
            .post(format!("{}/identity/connect/token", self.server))
            .form(&form)
            .send()
            .map_err(|_| DeviceTokensError("Device-token fixture login failed"))?;
        let response = self.read(response)?.status(200)?.json()?;
        let session = Session {
            token: text(&response["access_token"])?.to_owned(),
            device_id: id.to_owned(),
        };
        self.successful_logins += 1;
        Ok(session)
    }
    fn snapshot(&mut self, bearer: &str) -> Result<Snapshot, DeviceTokensError> {
        let profile = self.json(Method::GET, "/api/accounts/profile", bearer, None)?;
        let sync = self.json(Method::GET, "/api/sync", bearer, None)?;
        let devices = self.json(Method::GET, "/api/devices", bearer, None)?;
        let revision = self
            .json(Method::GET, "/api/accounts/revision-date", bearer, None)?
            .as_i64()
            .ok_or(DeviceTokensError(
                "Device-token account revision was not an integer",
            ))?;
        Ok(Snapshot {
            profile,
            sync,
            devices,
            revision,
        })
    }
    fn seed_vault(&mut self, account: &Account) -> Result<(), DeviceTokensError> {
        let encrypted = text(&account.fixture["key"])?;
        let folder = self.json(
            Method::POST,
            "/api/folders",
            &account.session.token,
            Some(&json!({"name":encrypted})),
        )?;
        let cipher = self.json(
            Method::POST,
            "/api/ciphers",
            &account.session.token,
            Some(&json!({"type":2,
            "name":encrypted,"notes":encrypted,"folderId":folder["id"],"encryptedFor":account.id,
            "secureNote":{"type":0,"futureOpaqueField":encrypted}})),
        )?;
        require(
            cipher["folderId"] == folder["id"],
            "Device-token vault fixture lost its folder association",
        )
    }
    fn other_alice(&self) -> Result<Session, DeviceTokensError> {
        self.second_alice.clone().ok_or(DeviceTokensError(
            "Second authenticated device fixture missing",
        ))
    }
    fn update(
        &mut self,
        method: Method,
        session: &Session,
        path_id: &str,
        body: &Value,
    ) -> Result<(), DeviceTokensError> {
        self.request(
            method,
            &format!("/api/devices/identifier/{path_id}/token"),
            Some(&session.token),
            Some(body.to_string().as_bytes()),
        )?
        .status(200)?
        .empty()
    }
    fn clear(
        &mut self,
        method: Method,
        path_id: &str,
        bearer: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Reply, DeviceTokensError> {
        self.request(
            method,
            &format!("/api/devices/identifier/{path_id}/clear-token"),
            bearer,
            body,
        )
    }
}

fn device_tokens_aliases_and_empty_responses(s: &mut Suite) -> Result<(), DeviceTokensError> {
    let alice = s.accounts[0].session.clone();
    let bob = s.accounts[1].session.clone();
    let second = s.other_alice()?;
    for method in [Method::PUT, Method::POST] {
        for session in [&alice, &bob, &second] {
            let value = format!("alias-{}", Uuid::new_v4());
            s.update(
                method.clone(),
                session,
                &session.device_id,
                &json!({"pushToken":value}),
            )?;
        }
    }
    Ok(())
}

fn device_tokens_valid_path_identifiers_are_advisory(
    s: &mut Suite,
) -> Result<(), DeviceTokensError> {
    let alice = s.accounts[0].session.clone();
    let bob = s.accounts[1].session.clone();
    let second = s.other_alice()?;
    let missing = format!("Missing-{}", Uuid::new_v4());
    // The second Alice device is foreign to Bob. All these valid path IDs are
    // accepted; the actual storage target is hidden and tested by host SQL tests.
    for method in [Method::PUT, Method::POST] {
        for session in [&alice, &second, &bob] {
            for id in [&alice.device_id, &second.device_id, &missing] {
                let value = format!("advisory-{}", Uuid::new_v4());
                s.update(method.clone(), session, id, &json!({"pushToken":value}))?;
            }
        }
    }
    Ok(())
}

fn device_tokens_opaque_values_and_ignored_fields(s: &mut Suite) -> Result<(), DeviceTokensError> {
    let a = s.accounts[0].clone();
    let b = s.accounts[1].clone();
    for method in [Method::PUT, Method::POST] {
        for value in [
            "".to_owned(),
            "  unchanged whitespace  ".to_owned(),
            "\0\t\r\n雪🔐".to_owned(),
            "future:opaque/token+with=padding".to_owned(),
            "x".repeat(1024 * 1024 + 1),
        ] {
            s.update(
                method.clone(),
                &a.session,
                &a.session.device_id,
                &json!({"pushToken":value}),
            )?;
        }
        let second = s.other_alice()?;
        s.update(method,&a.session,&a.session.device_id,&json!({"pushToken":"only-this-field",
            "PushToken":{"ignored":true},"userId":b.id,"id":b.session.device_id,
            "deviceIdentifier":second.device_id,"owner":b.id,"name":"ignored","type":99,
            "creationDate":"1900-01-01T00:00:00Z","isTrusted":true,"encryptedUserKey":{"ignored":true},
            "futureField":["ignored"]}))?;
    }
    Ok(())
}

fn device_tokens_positional_and_same_value(s: &mut Suite) -> Result<(), DeviceTokensError> {
    let session = s.other_alice()?;
    for method in [Method::PUT, Method::POST] {
        s.update(
            method.clone(),
            &session,
            &session.device_id,
            &json!(["positional-token"]),
        )?;
        // HTTP acceptance only: hidden activity timestamps cannot prove the
        // upstream same-value storage shortcut; host provider tests do that.
        for _ in 0..2 {
            s.update(
                method.clone(),
                &session,
                &session.device_id,
                &json!({"pushToken":"same-value-token"}),
            )?;
        }
    }
    Ok(())
}

fn device_tokens_schema_and_syntax_rejections(s: &mut Suite) -> Result<(), DeviceTokensError> {
    let a = s.accounts[0].session.clone();
    let invalid = [
        "null",
        "true",
        "7",
        "\"string\"",
        "{}",
        "[]",
        "[null]",
        "[7]",
        "{\"pushToken\":null}",
        "{\"pushToken\":7}",
        "{\"pushToken\":false}",
        "{\"pushToken\":[]}",
        "{\"pushToken\":{}}",
        "{\"PushToken\":\"wrong-case\"}",
        "{\"pushToken\":\"a\",\"pushToken\":\"b\"}",
        "{\"pushToken\":\"a\",\"pushTo\\u006ben\":\"b\"}",
    ];
    let malformed = [
        "",
        "{",
        "{\"pushToken\":",
        "{\"pushToken\":\"valid\"} trailing",
        "{\"pushToken\":\"valid\"}{}",
        "[\"valid\",0]",
    ];
    for method in [Method::PUT, Method::POST] {
        for (expected, bodies) in [(422, invalid.as_slice()), (400, malformed.as_slice())] {
            for (index, body) in bodies.iter().enumerate() {
                let response = s.request(
                    method.clone(),
                    &format!("/api/devices/identifier/{}/token", a.device_id),
                    Some(&a.token),
                    Some(body.as_bytes()),
                )?;
                if response.status != expected {
                    eprintln!(
                        "Device-token JSON fixture {}, method {}",
                        index + 1,
                        method.as_str()
                    );
                }
                response.status(expected)?;
            }
        }
    }
    Ok(())
}

fn device_tokens_authenticated_guard_precedence(s: &mut Suite) -> Result<(), DeviceTokensError> {
    let a = s.accounts[0].session.clone();
    for method in [Method::PUT, Method::POST] {
        for bearer in [None, Some("invalid-device-token-bearer")] {
            for id in [a.device_id.as_str(), "invalid%5Fid"] {
                for body in [b"{\"pushToken\":\"valid\"}".as_slice(), b"{".as_slice()] {
                    s.request(
                        method.clone(),
                        &format!("/api/devices/identifier/{id}/token"),
                        bearer,
                        Some(body),
                    )?
                    .status(401)?;
                }
            }
        }
        for (index, id) in [
            "invalid_id",
            "invalid%2Fid",
            "invalid%20id",
            "%E9%9B%AA",
            "id+plus",
        ]
        .iter()
        .enumerate()
        {
            for body in [b"{\"pushToken\":\"valid\"}".as_slice(), b"{".as_slice()] {
                let response = s.request(
                    method.clone(),
                    &format!("/api/devices/identifier/{id}/token"),
                    Some(&a.token),
                    Some(body),
                )?;
                if response.status != 422 {
                    eprintln!(
                        "Device-token path fixture {}, method {}",
                        index + 1,
                        method.as_str()
                    );
                }
                response.status(422)?;
            }
        }
        let encoded = format!("%53{}", &a.device_id[1..]);
        s.update(method, &a, &encoded, &json!({"pushToken":"encoded-path"}))?;
    }
    Ok(())
}

fn device_tokens_public_clear_push_disabled(s: &mut Suite) -> Result<(), DeviceTokensError> {
    let a = s.accounts[0].session.clone();
    let second = s.other_alice()?;
    let missing = format!("Missing-{}", Uuid::new_v4());
    for method in [Method::PUT, Method::POST] {
        for id in [&a.device_id, &second.device_id, &missing] {
            for bearer in [
                None,
                Some("invalid-device-token-bearer"),
                Some(a.token.as_str()),
            ] {
                s.clear(method.clone(), id, bearer, None)?
                    .status(200)?
                    .empty()?;
            }
        }
    }
    Ok(())
}

fn device_tokens_clear_path_guard_and_ignored_body(s: &mut Suite) -> Result<(), DeviceTokensError> {
    let a = s.accounts[0].session.clone();
    for method in [Method::PUT, Method::POST] {
        for (index, id) in [
            "invalid_id",
            "invalid%2Fid",
            "invalid%20id",
            "%E9%9B%AA",
            "id+plus",
        ]
        .iter()
        .enumerate()
        {
            for bearer in [
                None,
                Some("invalid-device-token-bearer"),
                Some(a.token.as_str()),
            ] {
                let response = s.clear(method.clone(), id, bearer, Some(b"{"))?;
                if response.status != 422 {
                    eprintln!(
                        "Device-token clear path fixture {}, method {}",
                        index + 1,
                        method.as_str()
                    );
                }
                response.status(422)?;
            }
        }
        let encoded = format!("%53{}", &a.device_id[1..]);
        s.clear(method.clone(), &encoded, None, None)?
            .status(200)?
            .empty()?;
        for body in [
            b"".as_slice(),
            b"{".as_slice(),
            b"[0]".as_slice(),
            b"{\"pushToken\":\"ignored\"}".as_slice(),
        ] {
            s.clear(method.clone(), &a.device_id, None, Some(body))?
                .status(200)?
                .empty()?;
        }
    }
    Ok(())
}

fn receipt() -> Result<Option<fs::File>, DeviceTokensError> {
    let Some(path) = std::env::var_os("BW_DEVICE_TOKENS_RECEIPT") else {
        return Ok(None);
    };
    let mut options = fs::OpenOptions::new();
    options.create_new(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|_| DeviceTokensError("Private device-token receipt creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| DeviceTokensError("Private device-token receipt permissions failed"))?;
    }
    Ok(Some(file))
}

/// Run this selected group against a fresh reference process with push disabled.
/// Three password logins create two accounts and two different Alice sessions.
/// Shared fixture registration is excluded from the HTTP count. Mutations and
/// authentication are never retried. Twenty-eight clear requests reach the
/// handler, below the unchanged upstream unauthenticated burst limit of fifty;
/// malformed paths are rejected before its rate-limit check.
pub fn run() -> Result<(), DeviceTokensError> {
    let server = std::env::var("BW_E2E_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8000".into());
    let server = server.trim_end_matches('/').to_owned();
    let url = reqwest::Url::parse(&server)
        .map_err(|_| DeviceTokensError("Invalid device-token test server configuration"))?;
    require(
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Invalid device-token test server configuration",
    )?;
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| DeviceTokensError("Device-token HTTP client initialization failed"))?;
    let mut suite = Suite {
        server,
        client,
        accounts: Vec::new(),
        second_alice: None,
        requests: 0,
        identity_requests: 0,
        successful_logins: 0,
        passed: Vec::new(),
        receipt: receipt()?,
        finished: false,
    };
    suite.write_receipt("running")?;
    let shared_id = format!("Shared-{}", Uuid::new_v4());
    for name in ["Token comparison Alice", "Token comparison Bob"] {
        let email = format!("device-tokens-{}@example.test", Uuid::new_v4());
        let password = format!("Nw!{}", Uuid::new_v4());
        let body = fixture::seed_account(&suite.server, &email, &password)
            .map_err(|_| DeviceTokensError("Device-token fixture registration failed"))?;
        let session = suite.login(&body, &shared_id, name)?;
        let profile = suite.json(Method::GET, "/api/accounts/profile", &session.token, None)?;
        let account = Account {
            session,
            id: text(&profile["id"])?.to_owned(),
            fixture: body,
        };
        suite.seed_vault(&account)?;
        suite.accounts.push(account);
    }
    let a = suite.accounts[0].clone();
    suite.second_alice = Some(suite.login(
        &a.fixture,
        &format!("Other-{}", Uuid::new_v4()),
        "Second Alice token session",
    )?);
    for (name, case) in CASES {
        let alice = suite.accounts[0].session.token.clone();
        let bob = suite.accounts[1].session.token.clone();
        let other = suite.other_alice()?.token;
        let before_alice = suite.snapshot(&alice)?;
        let before_bob = suite.snapshot(&bob)?;
        require(
            suite.snapshot(&other)? == before_alice,
            "Same-owner device sessions had different public authority",
        )?;
        case(&mut suite)?;
        require(
            suite.snapshot(&alice)? == before_alice
                && suite.snapshot(&other)? == before_alice
                && suite.snapshot(&bob)? == before_bob,
            "Device-token operation changed public account, vault, device metadata, or revision",
        )?;
        suite.passed.push(name);
        suite.write_receipt("running")?;
        println!("PASS {name}");
    }
    require(
        suite.identity_requests == 3 && suite.successful_logins == 3,
        "Device-token identity request budget differed",
    )?;
    suite.write_receipt("passed")?;
    suite.finished = true;
    println!(
        "PASS device-tokens: {} cases, {} HTTP requests, {} successful logins",
        suite.passed.len(),
        suite.requests,
        suite.identity_requests
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Request {
        push_token: String,
    }
    #[test]
    fn required_opaque_string_positional_order_and_guard_error_categories() {
        for (body, expected) in [
            ("{\"pushToken\":\"\"}", ""),
            ("[\"position-zero\"]", "position-zero"),
            ("{\"pushToken\":\"\\u0000雪\"}", "\0雪"),
        ] {
            assert_eq!(
                serde_json::from_str::<Request>(body).unwrap().push_token,
                expected
            );
        }
        for body in [
            "{}",
            "[]",
            "[null]",
            "{\"pushToken\":null}",
            "{\"pushToken\":\"a\",\"pushTo\\u006ben\":\"b\"}",
        ] {
            assert_eq!(
                serde_json::from_str::<Request>(body)
                    .err()
                    .unwrap()
                    .classify(),
                serde_json::error::Category::Data
            );
        }
        for body in ["[\"valid\",0]", "{\"pushToken\":\"valid\"} trailing"] {
            assert_eq!(
                serde_json::from_str::<Request>(body)
                    .err()
                    .unwrap()
                    .classify(),
                serde_json::error::Category::Syntax
            );
        }
        assert_eq!(
            serde_json::from_str::<Request>("{")
                .err()
                .unwrap()
                .classify(),
            serde_json::error::Category::Eof
        );
    }
    #[test]
    fn diagnostics_and_empty_response_assertions_discard_contents() {
        let error = Reply {
            status: 500,
            bytes: b"private-push-marker".to_vec(),
        }
        .status(200)
        .err()
        .unwrap();
        assert!(!format!("{error} {error:?}").contains("private-push-marker"));
        let error = Reply {
            status: 200,
            bytes: b"private-push-marker".to_vec(),
        }
        .json()
        .err()
        .unwrap();
        assert!(!format!("{error} {error:?}").contains("private-push-marker"));
        let error = Reply {
            status: 200,
            bytes: b"private-push-marker".to_vec(),
        }
        .empty()
        .err()
        .unwrap();
        assert!(!format!("{error} {error:?}").contains("private-push-marker"));
        assert!(
            Reply {
                status: 200,
                bytes: vec![]
            }
            .empty()
            .is_ok()
        );
    }
}
