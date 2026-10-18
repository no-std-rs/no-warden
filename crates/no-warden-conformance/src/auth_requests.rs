//! Portable creation and discovery of pending authentication requests.
//!
//! Contracts: Vaultwarden 58a980f850464f7d9cdc99a765df36f0a3308b91,
//! accounts.rs1650–1743/1863–1900, auth.rs610–633, models/auth_request.rs,
//! and models/device.rs291–379. Approval, response access-code authentication,
//! identity login, notifications, and scheduled purging are separate work.
//! Private response snapshots never enter diagnostics or receipts.

use crate::fixture;
use reqwest::{Method, blocking::Client};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    net::IpAddr,
    thread,
    time::Duration,
};
use uuid::Uuid;

type Case = fn(&mut Suite) -> Result<(), AuthRequestsError>;
const CASES: [(&str, Case); 8] = [
    (
        "auth_requests_public_creation_and_projection",
        auth_requests_public_creation_and_projection,
    ),
    (
        "auth_requests_required_opaque_and_positional_values",
        auth_requests_required_opaque_and_positional_values,
    ),
    (
        "auth_requests_device_verification_and_type_headers",
        auth_requests_device_verification_and_type_headers,
    ),
    (
        "auth_requests_schema_and_syntax_rejections",
        auth_requests_schema_and_syntax_rejections,
    ),
    (
        "auth_requests_uuid_and_authentication_guards",
        auth_requests_uuid_and_authentication_guards,
    ),
    (
        "auth_requests_pending_aliases_and_owner_isolation",
        auth_requests_pending_aliases_and_owner_isolation,
    ),
    (
        "auth_requests_repeated_creation_get_consistency",
        auth_requests_repeated_creation_get_consistency,
    ),
    (
        "auth_requests_latest_pending_device_metadata",
        auth_requests_latest_pending_device_metadata,
    ),
];
const COLLECTION: &str = "/api/auth-requests";
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// Static errors retain no identifiers, credentials, codes, keys, or response bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthRequestsError(&'static str);
impl fmt::Display for AuthRequestsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for AuthRequestsError {}
fn require(condition: bool, message: &'static str) -> Result<(), AuthRequestsError> {
    if condition {
        Ok(())
    } else {
        Err(AuthRequestsError(message))
    }
}
fn text(value: &Value) -> Result<&str, AuthRequestsError> {
    value.as_str().ok_or(AuthRequestsError(
        "Required authentication-request string missing",
    ))
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, AuthRequestsError> {
        if self.status != expected {
            eprintln!(
                "Auth-request HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Auth-request HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, AuthRequestsError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| AuthRequestsError("Auth-request response was not valid JSON"))
    }
}

// Declaration order also classifies positional fixtures. This owned classifier
// counts schema-valid public attempts, not authenticated logins or schema errors.
#[derive(Deserialize)]
struct Shape {
    #[serde(rename = "accessCode")]
    _access_code: String,
    #[serde(rename = "deviceIdentifier")]
    _device_identifier: String,
    #[serde(rename = "email")]
    _email: String,
    #[serde(rename = "publicKey")]
    _public_key: String,
}
#[derive(Clone)]
struct Account {
    token: String,
    id: String,
    fixture: Value,
}
#[derive(Clone)]
struct Device {
    owner: usize,
    id: String,
    kind: i32,
    label: &'static str,
}
struct Stored {
    owner: usize,
    device: String,
    wire: Value,
}
#[derive(PartialEq)]
struct Snapshot {
    profile: Value,
    sync: Value,
    revision: i64,
}
struct Suite {
    server: String,
    client: Client,
    origin: String,
    request_ip: Option<String>,
    accounts: Vec<Account>,
    devices: Vec<Device>,
    device_baselines: Vec<Value>,
    records: Vec<Stored>,
    requests: usize,
    identity_requests: usize,
    successful_logins: usize,
    decoded_creations: usize,
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
    fn write_receipt(&mut self, status: &'static str) -> Result<(), AuthRequestsError> {
        if let Some(file) = &mut self.receipt {
            let record = json!({"schemaVersion":1,"status":status,"cases":self.passed,
                "passedCases":self.passed.len(),"expectedCases":CASES.len(),"httpRequests":self.requests,
                "identityRequests":self.identity_requests,"successfulLogins":self.successful_logins,
                "decodedCreationAttempts":self.decoded_creations});
            file.seek(SeekFrom::Start(0))
                .map_err(|_| AuthRequestsError("Auth-request receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| AuthRequestsError("Auth-request receipt update failed"))?;
            file.write_all(record.to_string().as_bytes())
                .map_err(|_| AuthRequestsError("Auth-request receipt write failed"))?;
            file.sync_all()
                .map_err(|_| AuthRequestsError("Auth-request receipt persistence failed"))?;
        }
        Ok(())
    }
    fn read(&self, response: reqwest::blocking::Response) -> Result<Reply, AuthRequestsError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AuthRequestsError("Auth-request response read failed"))?;
        require(
            bytes.len() as u64 <= MAX_RESPONSE_BYTES,
            "Auth-request response exceeded capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn request(
        &mut self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&[u8]>,
        device_type: Option<&str>,
    ) -> Result<Reply, AuthRequestsError> {
        self.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.server));
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        if let Some(kind) = device_type {
            request = request.header("device-type", kind);
        }
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        let response = request
            .send()
            .map_err(|_| AuthRequestsError("Auth-request HTTP request failed"))?;
        self.read(response)
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Value, AuthRequestsError> {
        let body = body.map(Value::to_string);
        self.request(
            method,
            path,
            bearer,
            body.as_deref().map(str::as_bytes),
            None,
        )?
        .status(200)?
        .json()
    }
    fn login(&mut self, fixture: &Value, id: &str, kind: i32) -> Result<String, AuthRequestsError> {
        let kind = kind.to_string();
        let form = [
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("username", text(&fixture["email"])?),
            ("password", text(&fixture["masterPasswordHash"])?),
            ("deviceIdentifier", id),
            ("deviceName", "Auth-request comparison"),
            ("deviceType", kind.as_str()),
        ];
        self.requests += 1;
        self.identity_requests += 1;
        let response = self
            .client
            .post(format!("{}/identity/connect/token", self.server))
            .form(&form)
            .send()
            .map_err(|_| AuthRequestsError("Auth-request fixture login failed"))?;
        let response = self.read(response)?.status(200)?.json()?;
        let token = text(&response["access_token"])?.to_owned();
        self.successful_logins += 1;
        Ok(token)
    }
    fn snapshot(&mut self, bearer: &str) -> Result<Snapshot, AuthRequestsError> {
        let profile = self.json(Method::GET, "/api/accounts/profile", Some(bearer), None)?;
        let sync = self.json(Method::GET, "/api/sync", Some(bearer), None)?;
        let revision = self
            .json(
                Method::GET,
                "/api/accounts/revision-date",
                Some(bearer),
                None,
            )?
            .as_i64()
            .ok_or(AuthRequestsError(
                "Auth-request account revision was not an integer",
            ))?;
        Ok(Snapshot {
            profile,
            sync,
            revision,
        })
    }
    fn seed_vault(&mut self, account: &Account) -> Result<(), AuthRequestsError> {
        let encrypted = text(&account.fixture["key"])?;
        let folder = self.json(
            Method::POST,
            "/api/folders",
            Some(&account.token),
            Some(&json!({"name":encrypted})),
        )?;
        let cipher = self.json(
            Method::POST,
            "/api/ciphers",
            Some(&account.token),
            Some(&json!({"type":2,
            "name":encrypted,"notes":encrypted,"folderId":folder["id"],"encryptedFor":account.id,
            "secureNote":{"type":0,"futureOpaqueField":encrypted}})),
        )?;
        require(
            cipher["folderId"] == folder["id"],
            "Auth-request vault fixture lost folder association",
        )
    }
    fn body(&self, device: usize, code: &str, key: &str) -> Value {
        let device = &self.devices[device];
        json!({"accessCode":code,"deviceIdentifier":device.id,
            "email":self.accounts[device.owner].fixture["email"],"publicKey":key})
    }
    fn raw_create(
        &mut self,
        body: &[u8],
        header: Option<&str>,
        bearer: Option<&str>,
    ) -> Result<Reply, AuthRequestsError> {
        if serde_json::from_slice::<Shape>(body).is_ok() {
            self.decoded_creations += 1;
            require(
                self.decoded_creations <= 50,
                "Auth-request decoded creation budget exceeded",
            )?;
        }
        self.request(Method::POST, COLLECTION, bearer, Some(body), header)
    }
    fn create(
        &mut self,
        device: usize,
        body: &Value,
        header: Option<&str>,
        bearer: Option<&str>,
    ) -> Result<Value, AuthRequestsError> {
        let body_bytes = body.to_string();
        let shape: Shape = serde_json::from_str(&body_bytes).map_err(|_| {
            AuthRequestsError("Auth-request positive fixture did not match required schema")
        })?;
        let expected_device = self.devices[device].clone();
        require(
            header
                .and_then(|value| value.parse::<i32>().ok())
                .unwrap_or(14)
                == expected_device.kind,
            "Positive auth-request fixture did not match its registered device type",
        )?;
        // Keep different creation timestamps for deterministic latest-device assertions.
        thread::sleep(Duration::from_millis(10));
        let response = self
            .raw_create(body_bytes.as_bytes(), header, bearer)?
            .status(200)?
            .json()?;
        validate_projection(
            &response,
            &shape._public_key,
            expected_device.label,
            &self.origin,
            false,
        )?;
        let id = text(&response["id"])?;
        require(
            Uuid::parse_str(id).is_ok()
                && self.records.iter().all(|record| record.wire["id"] != id),
            "Auth-request creation did not assign a fresh UUID",
        )?;
        let ip = text(&response["requestIpAddress"])?;
        require(
            ip.parse::<IpAddr>().is_ok(),
            "Auth-request IP address was not an address",
        )?;
        if let Some(expected) = &self.request_ip {
            require(
                ip == expected,
                "Auth-request client address changed without a transport change",
            )?;
        } else {
            self.request_ip = Some(ip.to_owned());
        }
        let mut stored = response.clone();
        stored["requestApproved"] = Value::Null;
        let bearer = self.accounts[expected_device.owner].token.clone();
        require(
            self.json(
                Method::GET,
                &format!("{COLLECTION}/{id}"),
                Some(&bearer),
                None,
            )? == stored,
            "Stored auth-request projection differed from creation beyond the pending null flag",
        )?;
        self.records.push(Stored {
            owner: expected_device.owner,
            device: expected_device.id,
            wire: stored,
        });
        Ok(response)
    }
    fn expected_requests(&self, owner: usize) -> BTreeMap<String, Value> {
        self.records
            .iter()
            .filter(|record| record.owner == owner)
            .map(|record| {
                (
                    record.wire["id"].as_str().unwrap_or_default().to_owned(),
                    record.wire.clone(),
                )
            })
            .collect()
    }
    fn list(
        &mut self,
        owner: usize,
        pending: bool,
    ) -> Result<BTreeMap<String, Value>, AuthRequestsError> {
        let path = if pending {
            "/api/auth-requests/pending"
        } else {
            COLLECTION
        };
        let bearer = self.accounts[owner].token.clone();
        let value = self.json(Method::GET, path, Some(&bearer), None)?;
        let records = list_records(&value)?;
        require(
            records == self.expected_requests(owner),
            "Pending auth-request list changed records, projection, or ownership",
        )?;
        Ok(records)
    }
    fn check_devices(&mut self, owner: usize) -> Result<(), AuthRequestsError> {
        let bearer = self.accounts[owner].token.clone();
        let expected = expected_devices(&self.device_baselines[owner], owner, &self.records)?;
        require(
            self.json(Method::GET, "/api/devices", Some(&bearer), None)? == expected,
            "Device pending-auth metadata did not identify only the latest owned request",
        )
    }
}

fn validate_projection(
    value: &Value,
    key: &str,
    label: &str,
    origin: &str,
    stored: bool,
) -> Result<(), AuthRequestsError> {
    require(
        value.as_object().is_some_and(|object| object.len() == 11)
            && value["id"].is_string()
            && value["publicKey"] == key
            && value["requestDeviceType"] == label
            && value["requestIpAddress"].is_string()
            && value.get("key") == Some(&Value::Null)
            && value.get("masterPasswordHash") == Some(&Value::Null)
            && value["creationDate"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
            && value.get("responseDate") == Some(&Value::Null)
            && value.get("requestApproved")
                == Some(if stored {
                    &Value::Null
                } else {
                    &Value::Bool(false)
                })
            && value["origin"] == origin
            && value["object"] == "auth-request",
        "Auth-request response did not match the exact pending eleven-field projection",
    )
}
fn list_records(value: &Value) -> Result<BTreeMap<String, Value>, AuthRequestsError> {
    require(
        value.as_object().is_some_and(|object| object.len() == 3)
            && value["object"] == "list"
            && value.get("continuationToken") == Some(&Value::Null),
        "Auth-request list wrapper differed",
    )?;
    let records = value["data"]
        .as_array()
        .ok_or(AuthRequestsError("Auth-request list data missing"))?;
    let mut result = BTreeMap::new();
    for record in records {
        require(
            result
                .insert(text(&record["id"])?.to_owned(), record.clone())
                .is_none(),
            "Auth-request list contained duplicate IDs",
        )?;
    }
    Ok(result)
}
fn expected_devices(
    baseline: &Value,
    owner: usize,
    records: &[Stored],
) -> Result<Value, AuthRequestsError> {
    let mut result = baseline.clone();
    let devices = result["data"]
        .as_array_mut()
        .ok_or(AuthRequestsError("Device baseline data missing"))?;
    for device in devices {
        let id = text(&device["id"])?;
        let latest = records
            .iter()
            .rev()
            .find(|record| record.owner == owner && record.device == id);
        device["devicePendingAuthRequest"] = latest.map_or(
            Value::Null,
            |record| json!({"id":record.wire["id"],"creationDate":record.wire["creationDate"]}),
        );
    }
    Ok(result)
}

fn auth_requests_public_creation_and_projection(s: &mut Suite) -> Result<(), AuthRequestsError> {
    let mut body = s.body(0, "private-access-code", "opaque-public-key");
    body["id"] = json!(Uuid::new_v4().to_string());
    body["owner"] = json!(s.accounts[1].id);
    body["userId"] = json!(s.accounts[1].id);
    body["type"] = json!({"ignored":true});
    body["requestDeviceType"] = json!("forged");
    body["requestIpAddress"] = json!("198.51.100.19");
    body["requestApproved"] = json!(true);
    body["key"] = json!("ignored");
    body["masterPasswordHash"] = json!("ignored");
    body["responseDate"] = json!("1900-01-01T00:00:00Z");
    let response = s.create(0, &body, Some("8"), None)?;
    require(
        response["id"] != body["id"] && response["requestIpAddress"] != body["requestIpAddress"],
        "Auth-request creation trusted caller-owned response metadata",
    )?;
    s.create(
        0,
        &s.body(0, "private-other-code", "other-public-key"),
        Some("8"),
        Some("invalid-auth-request-bearer"),
    )?;
    Ok(())
}

fn auth_requests_required_opaque_and_positional_values(
    s: &mut Suite,
) -> Result<(), AuthRequestsError> {
    s.create(0, &s.body(0, "", ""), Some("8"), None)?;
    s.create(
        0,
        &s.body(0, "\0\t雪🔐", "  opaque\0key\r\n雪  "),
        Some("8"),
        None,
    )?;
    let positional = json!([
        "positional-code",
        s.devices[0].id,
        text(&s.accounts[0].fixture["email"])?.to_uppercase(),
        "positional-public-key"
    ]);
    s.create(0, &positional, Some("8"), None)?;
    Ok(())
}

fn auth_requests_device_verification_and_type_headers(
    s: &mut Suite,
) -> Result<(), AuthRequestsError> {
    // Device 2 was registered as type14. Missing, malformed and out-of-range
    // headers default to14, whereas syntactically valid unknown i32s do not.
    for header in [
        None,
        Some("iOS"),
        Some("2147483648"),
        Some("-2147483649"),
        Some(" 14"),
        Some(""),
        Some("+14"),
    ] {
        s.create(2, &s.body(2, "header-code", "header-key"), header, None)?;
    }
    for (device, header) in [(0, "+8"), (3, "25"), (4, "-7")] {
        s.create(
            device,
            &s.body(device, "typed-code", "typed-key"),
            Some(header),
            None,
        )?;
    }
    for (index, header) in [None, Some("iOS"), Some("14"), Some("25"), Some("-7")]
        .iter()
        .enumerate()
    {
        let response = s.raw_create(
            s.body(0, "mismatch-code", "mismatch-key")
                .to_string()
                .as_bytes(),
            *header,
            None,
        )?;
        if response.status != 400 {
            eprintln!("Auth-request device-header mismatch fixture {}", index + 1);
        }
        response.status(400)?;
    }
    let base = s.body(0, "verification-code", "verification-key");
    let mut invalid = Vec::new();
    for email in [
        format!(" {}", text(&s.accounts[0].fixture["email"])?),
        format!("{} ", text(&s.accounts[0].fixture["email"])?),
        "unknown-auth-request@example.test".to_owned(),
        String::new(),
    ] {
        let mut body = base.clone();
        body["email"] = json!(email);
        invalid.push(body);
    }
    for id in ["".to_owned(), format!("Unknown-{}", Uuid::new_v4())] {
        let mut body = base.clone();
        body["deviceIdentifier"] = json!(id);
        invalid.push(body);
    }
    for (index, body) in invalid.iter().enumerate() {
        let response = s.raw_create(body.to_string().as_bytes(), Some("8"), None)?;
        if response.status != 400 {
            eprintln!("Auth-request device-verification fixture {}", index + 1);
        }
        response.status(400)?;
    }
    let mut foreign = s.body(3, "foreign-code", "foreign-key");
    foreign["email"] = s.accounts[1].fixture["email"].clone();
    // Matching Alice's actual type prevents a type mismatch from masking an
    // incorrectly unscoped device lookup for Bob's email.
    s.raw_create(foreign.to_string().as_bytes(), Some("25"), None)?
        .status(400)?;
    Ok(())
}

fn auth_requests_schema_and_syntax_rejections(s: &mut Suite) -> Result<(), AuthRequestsError> {
    let base = s.body(0, "schema-code", "schema-key");
    let mut invalid = Vec::new();
    for field in ["accessCode", "deviceIdentifier", "email", "publicKey"] {
        let mut missing = base.clone();
        missing.as_object_mut().unwrap().remove(field);
        invalid.push(missing.to_string());
        for value in [Value::Null, json!(true), json!(7), json!([]), json!({})] {
            let mut body = base.clone();
            body[field] = value;
            invalid.push(body.to_string());
        }
    }
    invalid.extend(
        [
            "null",
            "true",
            "7",
            "\"string\"",
            "[]",
            "[null]",
            "[\"one\",\"two\",\"three\"]",
        ]
        .map(str::to_owned),
    );
    for field in [
        "accessCode",
        "deviceIdentifier",
        "email",
        "publicKey",
        "accessCo\\u0064e",
        "deviceIdentifi\\u0065r",
        "em\\u0061il",
        "public\\u004bey",
    ] {
        let mut body = base.to_string();
        body.pop();
        body.push_str(&format!(",\"{field}\":\"duplicate\"}}"));
        invalid.push(body);
    }
    for (index, body) in invalid.iter().enumerate() {
        let response = s.raw_create(body.as_bytes(), Some("8"), None)?;
        if response.status != 422 {
            eprintln!("Auth-request schema fixture {}", index + 1);
        }
        response.status(422)?;
    }
    let mut sequence = json!([
        "code",
        s.devices[0].id,
        s.accounts[0].fixture["email"],
        "key"
    ]);
    sequence.as_array_mut().unwrap().push(json!(0));
    for (index, body) in [
        String::new(),
        "{".into(),
        "{\"accessCode\":".into(),
        format!("{base} trailing"),
        format!("{base}{{}}"),
        sequence.to_string(),
    ]
    .iter()
    .enumerate()
    {
        let response = s.raw_create(body.as_bytes(), Some("8"), None)?;
        if response.status != 400 {
            eprintln!("Auth-request syntax fixture {}", index + 1);
        }
        response.status(400)?;
    }
    Ok(())
}

fn auth_requests_uuid_and_authentication_guards(s: &mut Suite) -> Result<(), AuthRequestsError> {
    let id = text(&s.records[0].wire["id"])?.to_owned();
    let alice = s.accounts[0].token.clone();
    let bob = s.accounts[1].token.clone();
    for bearer in [None, Some("invalid-auth-request-bearer")] {
        for path in [
            COLLECTION.to_owned(),
            "/api/auth-requests/pending".into(),
            format!("{COLLECTION}/{id}"),
            format!("{COLLECTION}/not-a-uuid"),
        ] {
            s.request(Method::GET, &path, bearer, None, None)?
                .status(401)?;
        }
    }
    s.request(
        Method::GET,
        &format!("{COLLECTION}/{id}"),
        Some(&bob),
        None,
        None,
    )?
    .status(400)?;
    let mut missing = vec![Uuid::new_v4().to_string(), id.replace('-', "")];
    let uppercase = id.to_uppercase();
    if uppercase != id {
        missing.push(uppercase);
    }
    for id in missing {
        s.request(
            Method::GET,
            &format!("{COLLECTION}/{id}"),
            Some(&alice),
            None,
            None,
        )?
        .status(400)?;
    }
    for (index, id) in ["not-a-uuid", "invalid%5Fid", "invalid%2Fid", "%E9%9B%AA"]
        .iter()
        .enumerate()
    {
        let response = s.request(
            Method::GET,
            &format!("{COLLECTION}/{id}"),
            Some(&alice),
            None,
            None,
        )?;
        if response.status != 422 {
            eprintln!("Auth-request UUID fixture {}", index + 1);
        }
        response.status(422)?;
    }
    Ok(())
}

fn auth_requests_pending_aliases_and_owner_isolation(
    s: &mut Suite,
) -> Result<(), AuthRequestsError> {
    s.create(
        1,
        &s.body(1, "foreign-owner-code", "foreign-owner-key"),
        Some("8"),
        None,
    )?;
    for owner in [0, 1] {
        let legacy = s.list(owner, false)?;
        require(
            s.list(owner, true)? == legacy,
            "Auth-request list aliases differed",
        )?;
        for record in legacy.values() {
            require(
                record["requestApproved"].is_null(),
                "Pending list projected an unapproved request as a false decision",
            )?;
        }
    }
    Ok(())
}

fn auth_requests_repeated_creation_get_consistency(s: &mut Suite) -> Result<(), AuthRequestsError> {
    let body = s.body(0, "repeated-private-code", "repeated-public-key");
    let before = s.records.len();
    for _ in 0..3 {
        s.create(0, &body, Some("8"), None)?;
    }
    require(
        s.records.len() == before + 3,
        "Repeated auth-request creation was deduplicated",
    )?;
    for owner in [0, 1] {
        s.list(owner, false)?;
        s.list(owner, true)?;
    }
    Ok(())
}

fn auth_requests_latest_pending_device_metadata(s: &mut Suite) -> Result<(), AuthRequestsError> {
    for key in ["latest-first", "latest-second"] {
        s.create(0, &s.body(0, "latest-private-code", key), Some("8"), None)?;
        s.check_devices(0)?;
        s.check_devices(1)?;
    }
    Ok(())
}

fn receipt() -> Result<Option<fs::File>, AuthRequestsError> {
    let Some(path) = std::env::var_os("BW_AUTH_REQUESTS_RECEIPT") else {
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
        .map_err(|_| AuthRequestsError("Private auth-request receipt creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| AuthRequestsError("Private auth-request receipt permissions failed"))?;
    }
    Ok(Some(file))
}

/// Use a fresh reference process for this selected group. Five password logins
/// register types8,14,25,-7 plus a foreign owner sharing the type8 identifier.
/// Schema-valid public creation attempts are bounded at50; rejected JSON does
/// not enter upstream's handler limiter. No mutation or authentication retries.
/// Shared fixture registration is excluded from the suite's HTTP request count.
pub fn run() -> Result<(), AuthRequestsError> {
    let server = std::env::var("BW_E2E_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8000".into());
    let server = server.trim_end_matches('/').to_owned();
    let url = reqwest::Url::parse(&server)
        .map_err(|_| AuthRequestsError("Invalid auth-request test server configuration"))?;
    require(
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Invalid auth-request test server configuration",
    )?;
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| AuthRequestsError("Auth-request HTTP client initialization failed"))?;
    let mut s = Suite {
        server,
        client,
        origin: String::new(),
        request_ip: None,
        accounts: Vec::new(),
        devices: Vec::new(),
        device_baselines: Vec::new(),
        records: Vec::new(),
        requests: 0,
        identity_requests: 0,
        successful_logins: 0,
        decoded_creations: 0,
        passed: Vec::new(),
        receipt: receipt()?,
        finished: false,
    };
    s.write_receipt("running")?;
    let config = s.json(Method::GET, "/api/config", None, None)?;
    s.origin = reqwest::Url::parse(text(&config["environment"]["vault"])?)
        .map_err(|_| AuthRequestsError("Configured auth-request origin was not a URL"))?
        .origin()
        .ascii_serialization();
    let shared = format!("Auth-Shared-{}", Uuid::new_v4());
    for owner in [0, 1] {
        let email = format!("auth-requests-{}@example.test", Uuid::new_v4());
        let password = format!("Nw!{}", Uuid::new_v4());
        let fixture = fixture::seed_account(&s.server, &email, &password)
            .map_err(|_| AuthRequestsError("Auth-request fixture registration failed"))?;
        let token = s.login(&fixture, &shared, 8)?;
        let profile = s.json(Method::GET, "/api/accounts/profile", Some(&token), None)?;
        let account = Account {
            token,
            id: text(&profile["id"])?.to_owned(),
            fixture,
        };
        s.seed_vault(&account)?;
        s.accounts.push(account);
        s.devices.push(Device {
            owner,
            id: shared.clone(),
            kind: 8,
            label: "Linux",
        });
    }
    for (kind, label) in [
        (14, "Unknown Browser"),
        (25, "Linux CLI"),
        (-7, "Unknown Browser"),
    ] {
        let id = if kind == -7 {
            format!("Auth_Opaque:雪/\0-{}", Uuid::new_v4())
        } else {
            format!("Auth-Other-{}", Uuid::new_v4())
        };
        s.login(&s.accounts[0].fixture.clone(), &id, kind)?;
        s.devices.push(Device {
            owner: 0,
            id,
            kind,
            label,
        });
    }
    for owner in [0, 1] {
        let bearer = s.accounts[owner].token.clone();
        let devices = s.json(Method::GET, "/api/devices", Some(&bearer), None)?;
        require(
            devices["data"].as_array().is_some_and(|records| {
                records
                    .iter()
                    .all(|record| record.get("devicePendingAuthRequest") == Some(&Value::Null))
            }),
            "Fresh device already had pending authentication metadata",
        )?;
        s.device_baselines.push(devices);
        require(
            s.list(owner, false)?.is_empty() && s.list(owner, true)?.is_empty(),
            "Fresh account already had authentication requests",
        )?;
    }
    for (name, case) in CASES {
        let alice = s.accounts[0].token.clone();
        let bob = s.accounts[1].token.clone();
        let before_alice = s.snapshot(&alice)?;
        let before_bob = s.snapshot(&bob)?;
        case(&mut s)?;
        require(
            s.snapshot(&alice)? == before_alice && s.snapshot(&bob)? == before_bob,
            "Auth-request operation changed profile, keys, vault, settings, or account revision",
        )?;
        for owner in [0, 1] {
            s.check_devices(owner)?;
            s.list(owner, false)?;
        }
        s.passed.push(name);
        s.write_receipt("running")?;
        println!("PASS {name}");
    }
    require(
        s.identity_requests == 5 && s.successful_logins == 5,
        "Auth-request login budget differed",
    )?;
    s.write_receipt("passed")?;
    s.finished = true;
    println!(
        "PASS auth-requests: {} cases, {} HTTP requests, {} successful logins, {} decoded creations",
        s.passed.len(),
        s.requests,
        s.successful_logins,
        s.decoded_creations
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn required_fields_positional_order_and_guard_error_categories() {
        let shape: Shape = serde_json::from_str("[\"code\",\"device\",\"email\",\"key\"]").unwrap();
        assert_eq!(
            (
                shape._access_code,
                shape._device_identifier,
                shape._email,
                shape._public_key
            ),
            ("code".into(), "device".into(), "email".into(), "key".into())
        );
        assert!(serde_json::from_str::<Shape>("[\"\",\"\",\"\",\"\"]").is_ok());
        for body in [
            "{}",
            "[]",
            "[\"a\",\"b\",\"c\"]",
            "[null,\"b\",\"c\",\"d\"]",
            "{\"accessCode\":\"a\",\"accessCo\\u0064e\":\"b\",\"deviceIdentifier\":\"d\",\"email\":\"e\",\"publicKey\":\"p\"}",
        ] {
            assert_eq!(
                serde_json::from_str::<Shape>(body)
                    .err()
                    .unwrap()
                    .classify(),
                serde_json::error::Category::Data
            );
        }
        assert_eq!(
            serde_json::from_str::<Shape>("[\"a\",\"b\",\"c\",\"d\",0]")
                .err()
                .unwrap()
                .classify(),
            serde_json::error::Category::Syntax
        );
        assert_eq!(
            serde_json::from_str::<Shape>("{").err().unwrap().classify(),
            serde_json::error::Category::Eof
        );
    }
    #[test]
    fn pending_metadata_selects_latest_request_for_exact_owner_and_device_only() {
        let baseline = json!({"data":[{"id":"shared","name":"unchanged","devicePendingAuthRequest":null},
            {"id":"other","devicePendingAuthRequest":null}]});
        let records = vec![
            Stored {
                owner: 0,
                device: "shared".into(),
                wire: json!({"id":"first","creationDate":"one","publicKey":"not-device-metadata"}),
            },
            Stored {
                owner: 1,
                device: "shared".into(),
                wire: json!({"id":"foreign","creationDate":"foreign"}),
            },
            Stored {
                owner: 0,
                device: "shared".into(),
                wire: json!({"id":"latest","creationDate":"two"}),
            },
        ];
        let expected = expected_devices(&baseline, 0, &records).unwrap();
        assert_eq!(
            expected["data"][0]["devicePendingAuthRequest"],
            json!({"id":"latest","creationDate":"two"})
        );
        assert_eq!(expected["data"][0]["name"], "unchanged");
        assert!(expected["data"][1]["devicePendingAuthRequest"].is_null());
        assert_eq!(
            expected_devices(&baseline, 1, &records).unwrap()["data"][0]["devicePendingAuthRequest"]
                ["id"],
            "foreign"
        );
    }
    #[test]
    fn response_diagnostics_discard_private_bodies() {
        let error = Reply {
            status: 500,
            bytes: b"private-auth-request-marker".to_vec(),
        }
        .status(200)
        .err()
        .unwrap();
        assert!(!format!("{error} {error:?}").contains("private-auth-request-marker"));
        let error = Reply {
            status: 200,
            bytes: b"private-auth-request-marker".to_vec(),
        }
        .json()
        .err()
        .unwrap();
        assert!(!format!("{error} {error:?}").contains("private-auth-request-marker"));
    }
}
