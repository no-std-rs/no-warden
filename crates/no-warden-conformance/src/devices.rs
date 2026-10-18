//! Portable device discovery contracts, without device-management mutations.
//!
//! Facts are pinned to Vaultwarden 58a980f850464f7d9cdc99a765df36f0a3308b91:
//! accounts.rs1504–1580, models/device.rs23–130, identity.rs776–797, and
//! macros/src/lib.rs32–58. Private snapshots never enter diagnostics or receipts.

use crate::fixture;
use base64::{
    Engine,
    engine::general_purpose::{URL_SAFE, URL_SAFE_NO_PAD},
};
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    time::Duration,
};
use uuid::Uuid;

type Case = fn(&mut Suite) -> Result<(), DevicesError>;
const CASES: [(&str, Case); 8] = [
    ("devices_known_public_headers", devices_known_public_headers),
    (
        "devices_known_email_and_identifier_matching",
        devices_known_email_and_identifier_matching,
    ),
    (
        "devices_list_and_single_projection",
        devices_list_and_single_projection,
    ),
    (
        "devices_identifier_path_guards",
        devices_identifier_path_guards,
    ),
    (
        "devices_duplicate_login_preserves_metadata",
        devices_duplicate_login_preserves_metadata,
    ),
    (
        "devices_api_key_login_registers_device",
        devices_api_key_login_registers_device,
    ),
    (
        "devices_refresh_preserves_identity",
        devices_refresh_preserves_identity,
    ),
    (
        "devices_failed_login_and_auth_guards",
        devices_failed_login_and_auth_guards,
    ),
];
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const KNOWN: &str = "/api/devices/knowndevice";
const DEVICES: &str = "/api/devices";

/// Authored static diagnostics retain no credentials, identifiers, or bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DevicesError(&'static str);
impl fmt::Display for DevicesError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for DevicesError {}
fn require(condition: bool, message: &'static str) -> Result<(), DevicesError> {
    if condition {
        Ok(())
    } else {
        Err(DevicesError(message))
    }
}
fn text(value: &Value) -> Result<&str, DevicesError> {
    value
        .as_str()
        .ok_or(DevicesError("Required device fixture string missing"))
}

struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, DevicesError> {
        if self.status != expected {
            eprintln!(
                "Device HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Device HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, DevicesError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| DevicesError("Device response was not valid JSON"))
    }
}
#[derive(Clone)]
struct Account {
    token: String,
    refresh: String,
    id: String,
    fixture: Value,
    device_id: String,
    device_name: String,
    device_type: i32,
}
#[derive(PartialEq)]
struct Snapshot {
    profile: Value,
    sync: Value,
    revision: i64,
}
#[derive(Clone, Copy)]
enum TokenKind {
    Login,
    Refresh,
}
struct Suite {
    server: String,
    client: Client,
    accounts: Vec<Account>,
    api_key: String,
    requests: usize,
    identity_requests: usize,
    identity_login_attempts: usize,
    successful_logins: usize,
    refresh_requests: usize,
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
    fn write_receipt(&mut self, status: &'static str) -> Result<(), DevicesError> {
        if let Some(file) = &mut self.receipt {
            let record = json!({"schemaVersion":1,"status":status,"cases":self.passed,
                "passedCases":self.passed.len(),"expectedCases":CASES.len(),"httpRequests":self.requests,
                "identityRequests":self.identity_requests,"identityLoginAttempts":self.identity_login_attempts,
                "successfulLogins":self.successful_logins,"refreshRequests":self.refresh_requests});
            file.seek(SeekFrom::Start(0))
                .map_err(|_| DevicesError("Device receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| DevicesError("Device receipt update failed"))?;
            file.write_all(record.to_string().as_bytes())
                .map_err(|_| DevicesError("Device receipt write failed"))?;
            file.sync_all()
                .map_err(|_| DevicesError("Device receipt persistence failed"))?;
        }
        Ok(())
    }
    fn read(&self, response: reqwest::blocking::Response) -> Result<Reply, DevicesError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| DevicesError("Device response read failed"))?;
        require(
            bytes.len() as u64 <= MAX_RESPONSE_BYTES,
            "Device response exceeded capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn request(
        &mut self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
        headers: &[(&str, &str)],
    ) -> Result<Reply, DevicesError> {
        self.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.server));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        let response = request
            .send()
            .map_err(|_| DevicesError("Device HTTP request failed"))?;
        self.read(response)
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, DevicesError> {
        let body = body.map(Value::to_string);
        self.request(
            method,
            path,
            Some(token),
            body.as_deref().map(str::as_bytes),
            &[],
        )?
        .status(200)?
        .json()
    }
    fn token(
        &mut self,
        form: &[(&str, &str)],
        expected: u16,
        kind: TokenKind,
    ) -> Result<Value, DevicesError> {
        self.requests += 1;
        self.identity_requests += 1;
        match kind {
            TokenKind::Login => self.identity_login_attempts += 1,
            TokenKind::Refresh => self.refresh_requests += 1,
        }
        let response = self
            .client
            .post(format!("{}/identity/connect/token", self.server))
            .form(form)
            .send()
            .map_err(|_| DevicesError("Device identity request failed"))?;
        let result = self.read(response)?.status(expected)?.json()?;
        if expected == 200 && matches!(kind, TokenKind::Login) {
            self.successful_logins += 1;
        }
        Ok(result)
    }
    fn password_login(
        &mut self,
        body: &Value,
        id: &str,
        name: &str,
        device_type: &str,
    ) -> Result<Value, DevicesError> {
        self.token(
            &[
                ("grant_type", "password"),
                ("client_id", "cli"),
                ("scope", "api offline_access"),
                ("username", text(&body["email"])?),
                ("password", text(&body["masterPasswordHash"])?),
                ("deviceIdentifier", id),
                ("deviceName", name),
                ("deviceType", device_type),
            ],
            200,
            TokenKind::Login,
        )
    }
    fn known_raw(
        &mut self,
        email: Option<&str>,
        id: Option<&str>,
        bearer: Option<&str>,
    ) -> Result<Reply, DevicesError> {
        let mut headers = Vec::new();
        if let Some(email) = email {
            headers.push(("X-Request-Email", email));
        }
        if let Some(id) = id {
            headers.push(("X-Device-Identifier", id));
        }
        self.request(Method::GET, KNOWN, bearer, None, &headers)
    }
    fn known(&mut self, email: &str, id: &str, expected: bool) -> Result<(), DevicesError> {
        let encoded = URL_SAFE_NO_PAD.encode(email.as_bytes());
        require(
            self.known_raw(Some(&encoded), Some(id), None)?
                .status(200)?
                .json()?
                == json!(expected),
            "Known-device result differed",
        )
    }
    fn list(&mut self, token: &str) -> Result<BTreeMap<String, Value>, DevicesError> {
        let response = self.json(Method::GET, DEVICES, token, None)?;
        list_projection(&response)
    }
    fn single(&mut self, token: &str, id: &str) -> Result<Value, DevicesError> {
        let response = self.json(
            Method::GET,
            &format!("/api/devices/identifier/{id}"),
            token,
            None,
        )?;
        validate_single(&response)?;
        Ok(response)
    }
    fn snapshot(&mut self, token: &str) -> Result<Snapshot, DevicesError> {
        let profile = self.json(Method::GET, "/api/accounts/profile", token, None)?;
        let sync = self.json(Method::GET, "/api/sync", token, None)?;
        let revision = self
            .json(Method::GET, "/api/accounts/revision-date", token, None)?
            .as_i64()
            .ok_or(DevicesError("Device account revision was not an integer"))?;
        Ok(Snapshot {
            profile,
            sync,
            revision,
        })
    }
    fn seed_vault(&mut self, account: &Account) -> Result<(), DevicesError> {
        let encrypted = text(&account.fixture["key"])?;
        let folder = self.json(
            Method::POST,
            "/api/folders",
            &account.token,
            Some(&json!({"name":encrypted})),
        )?;
        let cipher = self.json(
            Method::POST,
            "/api/ciphers",
            &account.token,
            Some(&json!({"type":2,
            "name":encrypted,"notes":encrypted,"folderId":folder["id"],"encryptedFor":account.id,
            "secureNote":{"type":0,"futureOpaqueField":encrypted}})),
        )?;
        require(
            cipher["folderId"] == folder["id"],
            "Device vault fixture lost folder association",
        )
    }
}

fn validate_single(device: &Value) -> Result<(), DevicesError> {
    require(
        device.as_object().is_some_and(|object| object.len() == 7)
            && device["id"].is_string()
            && device["identifier"] == device["id"]
            && device["name"].is_string()
            && device["type"]
                .as_i64()
                .is_some_and(|n| i32::try_from(n).is_ok())
            && device["creationDate"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
            && device["isTrusted"] == false
            && device["object"] == "device",
        "Single device did not match the exact seven-field projection",
    )
}
fn single_from_list(device: &Value) -> Value {
    let mut device = device.clone();
    if let Some(object) = device.as_object_mut() {
        for name in [
            "devicePendingAuthRequest",
            "encryptedPublicKey",
            "encryptedUserKey",
        ] {
            object.remove(name);
        }
    }
    device
}
fn list_projection(value: &Value) -> Result<BTreeMap<String, Value>, DevicesError> {
    require(
        value.as_object().is_some_and(|object| object.len() == 3)
            && value["object"] == "list"
            && value.get("continuationToken") == Some(&Value::Null),
        "Device list wrapper differed",
    )?;
    let devices = value["data"]
        .as_array()
        .ok_or(DevicesError("Device list entries missing"))?;
    let mut result = BTreeMap::new();
    for device in devices {
        require(
            device.as_object().is_some_and(|object| object.len() == 10)
                && device.get("devicePendingAuthRequest") == Some(&Value::Null)
                && device.get("encryptedPublicKey") == Some(&Value::Null)
                && device.get("encryptedUserKey") == Some(&Value::Null),
            "Device list entry did not match the ten-field projection",
        )?;
        validate_single(&single_from_list(device))?;
        require(
            result
                .insert(text(&device["id"])?.to_owned(), device.clone())
                .is_none(),
            "Device list contained duplicate identifiers",
        )?;
    }
    Ok(result)
}
fn matching_metadata(
    value: &Value,
    id: &str,
    name: &str,
    device_type: i32,
) -> Result<(), DevicesError> {
    require(
        value["id"] == id
            && value["identifier"] == id
            && value["name"] == name
            && value["type"] == device_type,
        "Device metadata differed from original login",
    )
}

fn devices_known_public_headers(s: &mut Suite) -> Result<(), DevicesError> {
    let a = s.accounts[0].clone();
    let before = s.list(&a.token)?;
    let encoded = URL_SAFE_NO_PAD.encode(text(&a.fixture["email"])?);
    let padded = URL_SAFE.encode(text(&a.fixture["email"])?);
    for (index, (email, id)) in [
        (None, None),
        (Some(encoded.as_str()), None),
        (None, Some(a.device_id.as_str())),
    ]
    .iter()
    .enumerate()
    {
        let response = s.known_raw(*email, *id, None)?;
        if response.status != 400 {
            eprintln!("Device missing-header fixture {}", index + 1);
        }
        response.status(400)?;
    }
    for (index, email) in ["%", "A", "+w", "/w", "_w", "Zh", "Z g", "Zg==junk"]
        .iter()
        .enumerate()
    {
        let response = s.known_raw(Some(email), Some(&a.device_id), None)?;
        if response.status != 400 {
            eprintln!("Device invalid-header fixture {}", index + 1);
        }
        response.status(400)?;
    }
    for email in [encoded, padded.clone(), format!("{padded}====")] {
        for bearer in [None, Some("invalid-device-discovery-bearer")] {
            require(
                s.known_raw(Some(&email), Some(&a.device_id), bearer)?
                    .status(200)?
                    .json()?
                    == true,
                "Public known-device route required a bearer or rejected padding",
            )?;
        }
    }
    for email in ["", "===="] {
        require(
            s.known_raw(Some(email), Some(&a.device_id), None)?
                .status(200)?
                .json()?
                == false,
            "Empty decoded email did not produce a false known-device result",
        )?;
    }
    require(
        s.list(&a.token)? == before,
        "Known-device header reads mutated device state",
    )
}

fn devices_known_email_and_identifier_matching(s: &mut Suite) -> Result<(), DevicesError> {
    let a = s.accounts[0].clone();
    let email = text(&a.fixture["email"])?;
    let before = s.list(&a.token)?;
    s.known(email, &a.device_id, true)?;
    s.known(&email.to_uppercase(), &a.device_id, true)?;
    for email in [
        format!(" {email}"),
        format!("{email} "),
        "unknown-device-user@example.test".to_owned(),
    ] {
        s.known(&email, &a.device_id, false)?;
    }
    for id in [
        "".to_owned(),
        a.device_id.to_uppercase(),
        "opaque:_/+".to_owned(),
        "opaque-雪".to_owned(),
    ] {
        s.known(email, &id, false)?;
    }
    let b = s.accounts[1].clone();
    s.known(text(&b.fixture["email"])?, &b.device_id, true)?;
    require(
        s.list(&a.token)? == before,
        "Known-device matching reads mutated device state",
    )
}

fn devices_list_and_single_projection(s: &mut Suite) -> Result<(), DevicesError> {
    let a = s.accounts[0].clone();
    let b = s.accounts[1].clone();
    let alice = s.list(&a.token)?;
    let bob = s.list(&b.token)?;
    require(
        alice.len() == 1 && bob.len() == 1 && a.device_id == b.device_id,
        "Initial same-identifier devices were not isolated by account",
    )?;
    for (account, devices) in [(&a, &alice), (&b, &bob)] {
        let listed = devices
            .get(&account.device_id)
            .ok_or(DevicesError("Owned listed device missing"))?;
        matching_metadata(
            listed,
            &account.device_id,
            &account.device_name,
            account.device_type,
        )?;
        require(
            s.single(&account.token, &account.device_id)? == single_from_list(listed),
            "Single and list device metadata differed",
        )?;
    }
    require(
        alice[&a.device_id]["name"] != bob[&b.device_id]["name"],
        "Shared identifier exposed another account's metadata",
    )?;
    require(
        s.list(&a.token)? == alice && s.list(&b.token)? == bob,
        "Device projection reads changed stored metadata",
    )
}

fn devices_identifier_path_guards(s: &mut Suite) -> Result<(), DevicesError> {
    let a = s.accounts[0].clone();
    let before = s.list(&a.token)?;
    let normal = s.single(&a.token, &a.device_id)?;
    let encoded = format!("%44{}", &a.device_id[1..]);
    require(
        s.single(&a.token, &encoded)? == normal,
        "Device path percent decoding lost an owned identifier",
    )?;
    for id in [
        a.device_id.to_uppercase(),
        format!("Missing-{}", Uuid::new_v4()),
        Uuid::new_v4().to_string(),
    ] {
        s.request(
            Method::GET,
            &format!("/api/devices/identifier/{id}"),
            Some(&a.token),
            None,
            &[],
        )?
        .status(400)?;
    }
    for (index, id) in [
        "not_a_uuid",
        "invalid%5Fid",
        "invalid%2Fid",
        "invalid%3Aid",
        "%E9%9B%AA",
        "invalid%20id",
    ]
    .iter()
    .enumerate()
    {
        let response = s.request(
            Method::GET,
            &format!("/api/devices/identifier/{id}"),
            Some(&a.token),
            None,
            &[],
        )?;
        if response.status != 422 {
            eprintln!("Device path-guard fixture {}", index + 1);
        }
        response.status(422)?;
    }
    require(
        s.list(&a.token)? == before,
        "Rejected device paths changed stored metadata",
    )
}

fn devices_duplicate_login_preserves_metadata(s: &mut Suite) -> Result<(), DevicesError> {
    let a = s.accounts[0].clone();
    let b = s.accounts[1].clone();
    let before = s.list(&a.token)?;
    let result = s.token(
        &[
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("username", text(&a.fixture["email"])?),
            ("password", text(&a.fixture["masterPasswordHash"])?),
            ("deviceIdentifier", &a.device_id),
            ("deviceName", "replacement must be ignored"),
            ("deviceType", "99"),
            ("userId", &b.id),
            ("creationDate", "1900-01-01T00:00:00Z"),
            ("isTrusted", "true"),
            ("encryptedPublicKey", "ignored"),
            ("encryptedUserKey", "ignored"),
        ],
        200,
        TokenKind::Login,
    )?;
    s.accounts[0].refresh = text(&result["refresh_token"])?.to_owned();
    require(
        s.list(text(&result["access_token"])?)? == before && s.list(&a.token)? == before,
        "Repeated login changed original device metadata, creation, or ownership",
    )?;
    require(
        s.single(&a.token, &a.device_id)? == single_from_list(&before[&a.device_id]),
        "Repeated login changed single-device projection",
    )
}

fn devices_api_key_login_registers_device(s: &mut Suite) -> Result<(), DevicesError> {
    let a = s.accounts[0].clone();
    let b = s.accounts[1].clone();
    let before = s.list(&a.token)?;
    let id = format!("Api-{}", Uuid::new_v4());
    let name = "API device 雪\0opaque";
    let client_id = format!("user.{}", a.id);
    let secret = s.api_key.clone();
    let result = s.token(
        &[
            ("grant_type", "client_credentials"),
            ("client_id", &client_id),
            ("client_secret", &secret),
            ("scope", "api"),
            ("deviceIdentifier", &id),
            ("deviceName", name),
            ("deviceType", "iOS"),
            ("userId", &b.id),
            ("isTrusted", "true"),
            ("creationDate", "1900-01-01T00:00:00Z"),
        ],
        200,
        TokenKind::Login,
    )?;
    require(
        result.get("refresh_token").is_none(),
        "API-key login unexpectedly returned a refresh token",
    )?;
    let after = s.list(&a.token)?;
    require(
        after.len() == before.len() + 1
            && before
                .iter()
                .all(|(id, device)| after.get(id) == Some(device)),
        "API-key device registration changed existing devices",
    )?;
    let new = after
        .get(&id)
        .ok_or(DevicesError("API-key login did not register its device"))?;
    matching_metadata(new, &id, name, 14)?;
    require(
        !text(&new["creationDate"])?.starts_with("1900-"),
        "API-key device registration trusted caller-supplied creation metadata",
    )?;
    require(
        s.list(text(&result["access_token"])?)? == after
            && s.single(&a.token, &id)? == single_from_list(new),
        "API-key bearer or single-device projection did not match owner",
    )?;
    s.known(text(&a.fixture["email"])?, &id, true)?;
    s.known(text(&b.fixture["email"])?, &id, false)?;
    s.request(
        Method::GET,
        &format!("/api/devices/identifier/{id}"),
        Some(&b.token),
        None,
        &[],
    )?
    .status(400)?;
    Ok(())
}

fn devices_refresh_preserves_identity(s: &mut Suite) -> Result<(), DevicesError> {
    let a = s.accounts[0].clone();
    let before = s.list(&a.token)?;
    let decoy = format!("Refresh-{}", Uuid::new_v4());
    let result = s.token(
        &[
            ("grant_type", "refresh_token"),
            ("client_id", "cli"),
            ("refresh_token", &a.refresh),
            ("deviceIdentifier", &decoy),
            ("deviceName", "ignored on refresh"),
            ("deviceType", "99"),
        ],
        200,
        TokenKind::Refresh,
    )?;
    s.accounts[0].refresh = text(&result["refresh_token"])?.to_owned();
    require(
        s.list(text(&result["access_token"])?)? == before && s.list(&a.token)? == before,
        "Refresh changed device identity, original metadata, or device count",
    )?;
    s.known(text(&a.fixture["email"])?, &decoy, false)
}

fn devices_failed_login_and_auth_guards(s: &mut Suite) -> Result<(), DevicesError> {
    let a = s.accounts[0].clone();
    let before = s.list(&a.token)?;
    let failed = format!("Failed-{}", Uuid::new_v4());
    s.token(
        &[
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("username", text(&a.fixture["email"])?),
            ("password", "deliberately-invalid-device-password-hash"),
            ("deviceIdentifier", &failed),
            ("deviceName", "failed login"),
            ("deviceType", "8"),
        ],
        400,
        TokenKind::Login,
    )?;
    s.known(text(&a.fixture["email"])?, &failed, false)?;
    for bearer in [None, Some("invalid-device-discovery-bearer")] {
        for path in [
            DEVICES.to_owned(),
            format!("/api/devices/identifier/{}", a.device_id),
        ] {
            s.request(Method::GET, &path, bearer, None, &[])?
                .status(401)?;
        }
    }
    require(
        s.list(&a.token)? == before,
        "Failed authentication changed device metadata or count",
    )
}

fn receipt() -> Result<Option<fs::File>, DevicesError> {
    let Some(path) = std::env::var_os("BW_DEVICES_RECEIPT") else {
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
        .map_err(|_| DevicesError("Private device receipt creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| DevicesError("Private device receipt permissions failed"))?;
    }
    Ok(Some(file))
}

/// Exercise discovery with two accounts and six identity requests: four
/// successful logins, one rejected password login, and one token refresh.
/// Run this group separately from the personal suite against a fresh reference
/// process; no authentication or mutation is retried and rate limits stay intact.
pub fn run() -> Result<(), DevicesError> {
    let server = std::env::var("BW_E2E_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8000".into());
    let server = server.trim_end_matches('/').to_owned();
    let url = reqwest::Url::parse(&server)
        .map_err(|_| DevicesError("Invalid device test server configuration"))?;
    require(
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Invalid device test server configuration",
    )?;
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| DevicesError("Device HTTP client initialization failed"))?;
    let mut suite = Suite {
        server,
        client,
        accounts: Vec::new(),
        api_key: String::new(),
        requests: 0,
        identity_requests: 0,
        identity_login_attempts: 0,
        successful_logins: 0,
        refresh_requests: 0,
        passed: Vec::new(),
        receipt: receipt()?,
        finished: false,
    };
    suite.write_receipt("running")?;
    let shared_id = format!("Device-{}", Uuid::new_v4());
    for (name, device_type) in [
        ("First owner 雪\0metadata", i32::MIN),
        ("Second owner metadata", i32::MAX),
    ] {
        let email = format!("devices-{}@example.test", Uuid::new_v4());
        let password = format!("Nw!{}", Uuid::new_v4());
        let body = fixture::seed_account(&suite.server, &email, &password)
            .map_err(|_| DevicesError("Device fixture registration failed"))?;
        let tokens = suite.password_login(&body, &shared_id, name, &device_type.to_string())?;
        let token = text(&tokens["access_token"])?.to_owned();
        let profile = suite.json(Method::GET, "/api/accounts/profile", &token, None)?;
        let account = Account {
            token,
            refresh: text(&tokens["refresh_token"])?.to_owned(),
            id: text(&profile["id"])?.to_owned(),
            fixture: body,
            device_id: shared_id.clone(),
            device_name: name.to_owned(),
            device_type,
        };
        suite.seed_vault(&account)?;
        suite.accounts.push(account);
    }
    let a = suite.accounts[0].clone();
    let api_key = suite.json(
        Method::POST,
        "/api/accounts/api-key",
        &a.token,
        Some(&json!({"masterPasswordHash":a.fixture["masterPasswordHash"]})),
    )?;
    suite.api_key = text(&api_key["apiKey"])?.to_owned();
    for (name, case) in CASES {
        let alice = suite.accounts[0].token.clone();
        let bob = suite.accounts[1].token.clone();
        let before_alice = suite.snapshot(&alice)?;
        let before_bob = suite.snapshot(&bob)?;
        let foreign_devices = suite.list(&bob)?;
        case(&mut suite)?;
        require(
            suite.snapshot(&alice)? == before_alice && suite.snapshot(&bob)? == before_bob,
            "Device case changed account profile, keys, vault, settings, or revision",
        )?;
        require(
            suite.list(&bob)? == foreign_devices,
            "Device case changed a foreign owner's devices",
        )?;
        suite.passed.push(name);
        suite.write_receipt("running")?;
        println!("PASS {name}");
    }
    require(
        suite.identity_requests == 6
            && suite.identity_login_attempts == 5
            && suite.successful_logins == 4
            && suite.refresh_requests == 1,
        "Device identity request budget differed",
    )?;
    suite.write_receipt("passed")?;
    suite.finished = true;
    println!(
        "PASS devices: {} cases, {} HTTP requests, {} identity requests, {} successful logins, {} refresh",
        suite.passed.len(),
        suite.requests,
        suite.identity_requests,
        suite.successful_logins,
        suite.refresh_requests
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn single() -> Value {
        json!({"id":"opaque-ID-1","identifier":"opaque-ID-1","name":"opaque\0雪","type":i32::MIN,
            "creationDate":"2026-10-18T00:00:00.000000Z","isTrusted":false,"object":"device"})
    }
    #[test]
    fn projections_enforce_distinct_exact_shapes_and_reject_duplicate_ids() {
        let value = single();
        assert!(validate_single(&value).is_ok());
        let mut listed = value.clone();
        for key in [
            "devicePendingAuthRequest",
            "encryptedPublicKey",
            "encryptedUserKey",
        ] {
            listed[key] = Value::Null;
        }
        let wrapper = json!({"data":[listed],"object":"list","continuationToken":null});
        let result = list_projection(&wrapper).unwrap();
        assert_eq!(single_from_list(&result["opaque-ID-1"]), value);
        let mut extra = value;
        extra["untrusted"] = json!(true);
        assert!(validate_single(&extra).is_err());
        let mut duplicate = wrapper.clone();
        duplicate["data"]
            .as_array_mut()
            .unwrap()
            .push(wrapper["data"][0].clone());
        assert!(list_projection(&duplicate).is_err());
        let mut missing = wrapper;
        missing["data"][0]
            .as_object_mut()
            .unwrap()
            .remove("encryptedUserKey");
        assert!(list_projection(&missing).is_err());
        let mut missing_token = json!({"data":[],"object":"list","ignored":null});
        assert!(list_projection(&missing_token).is_err());
        missing_token.as_object_mut().unwrap().remove("ignored");
        missing_token["continuationToken"] = Value::Null;
        assert!(list_projection(&missing_token).is_ok());
    }
    #[test]
    fn header_fixtures_distinguish_padding_invalid_alphabet_trailing_bits_and_utf8() {
        let email = "header@example.test";
        let encoded = URL_SAFE_NO_PAD.encode(email);
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(format!("{encoded}====").trim_end_matches('='))
                .unwrap(),
            email.as_bytes()
        );
        for invalid in ["%", "A", "+w", "/w", "Zh", "Z g", "Zg==junk"] {
            assert!(URL_SAFE_NO_PAD.decode(invalid).is_err());
        }
        let invalid_utf8 = URL_SAFE_NO_PAD.decode("_w").unwrap();
        assert!(String::from_utf8(invalid_utf8).is_err());
    }
    #[test]
    fn diagnostics_discard_response_contents() {
        let error = Reply {
            status: 500,
            bytes: b"private-device-marker".to_vec(),
        }
        .status(200)
        .err()
        .unwrap();
        assert_eq!(error.to_string(), "Device HTTP status differed");
        assert!(!format!("{error:?}").contains("private-device-marker"));
        let error = Reply {
            status: 200,
            bytes: b"private-device-marker".to_vec(),
        }
        .json()
        .err()
        .unwrap();
        assert!(!format!("{error} {error:?}").contains("private-device-marker"));
    }
}
