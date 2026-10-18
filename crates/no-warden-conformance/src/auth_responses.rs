//! Portable auth-request approval and public access-code polling.
//!
//! Pinned contracts: Vaultwarden 58a980f850464f7d9cdc99a765df36f0a3308b91,
//! accounts.rs1745–1861 and auth.rs610–633; Rocket 0.5.1 route query guards.
//! This selected group uses four logins and exactly44 guard-valid public
//! create/poll attempts on a fresh reference process with unchanged limits.
//! Direct peer-IP checks require an IPv4-loopback test server. Identity login,
//! notifications, trusted proxies, expiry, and scheduled purging are separate.
//! Private bodies, keys, codes, identifiers, and URLs never enter diagnostics.

use crate::fixture;
use reqwest::{Method, blocking::Client};
use serde::{Deserialize, Serialize};
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

type Case = fn(&mut Suite) -> Result<(), AuthResponsesError>;
const CASES: [(&str, Case); 8] = [
    (
        "auth_responses_approve_and_repeat_poll",
        auth_responses_approve_and_repeat_poll,
    ),
    (
        "auth_responses_reject_deletes_pending",
        auth_responses_reject_deletes_pending,
    ),
    (
        "auth_responses_verified_response_device_and_rejections",
        auth_responses_verified_response_device_and_rejections,
    ),
    (
        "auth_responses_opaque_optional_and_positional_values",
        auth_responses_opaque_optional_and_positional_values,
    ),
    (
        "auth_responses_schema_and_guard_precedence",
        auth_responses_schema_and_guard_precedence,
    ),
    (
        "auth_responses_code_query_guards",
        auth_responses_code_query_guards,
    ),
    (
        "auth_responses_type_bearer_and_ip_guards",
        auth_responses_type_bearer_and_ip_guards,
    ),
    (
        "auth_responses_pending_projection_transitions",
        auth_responses_pending_projection_transitions,
    ),
];
const COLLECTION: &str = "/api/auth-requests";
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const PUBLIC_BUDGET: usize = 44;

/// Static errors retain no credentials, keys, access codes, or response bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthResponsesError(&'static str);
impl fmt::Display for AuthResponsesError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for AuthResponsesError {}
fn require(condition: bool, message: &'static str) -> Result<(), AuthResponsesError> {
    if condition {
        Ok(())
    } else {
        Err(AuthResponsesError(message))
    }
}
fn text(value: &Value) -> Result<&str, AuthResponsesError> {
    value
        .as_str()
        .ok_or(AuthResponsesError("Required auth-response string missing"))
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, AuthResponsesError> {
        if self.status != expected {
            eprintln!(
                "Auth-response HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(
            self.status == expected,
            "Auth-response HTTP status differed",
        )?;
        Ok(self)
    }
    fn json(self) -> Result<Value, AuthResponsesError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| AuthResponsesError("Auth-response reply was not valid JSON"))
    }
}

// The pinned field declaration order determines sequence decoding, including
// the required third sequence slot despite its optional value in object form.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ApprovalShape {
    device_identifier: String,
    key: String,
    master_password_hash: Option<String>,
    request_approved: bool,
}
#[derive(Clone)]
struct Account {
    token: String,
    id: String,
    fixture: Value,
}
#[derive(Clone)]
struct Session {
    owner: usize,
    id: String,
    token: String,
    kind: i32,
    label: &'static str,
}
struct Stored {
    owner: usize,
    device: String,
    code: String,
    wire: Value,
    deleted: bool,
}
impl Stored {
    fn pending(&self) -> bool {
        !self.deleted && self.wire["requestApproved"].is_null()
    }
}
#[derive(PartialEq)]
struct Snapshot {
    profile: Value,
    sync: Value,
    revision: i64,
}
#[derive(Clone, Copy, Default)]
struct Headers<'a> {
    bearer: Option<&'a str>,
    kind: Option<&'a str>,
    device: Option<&'a str>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Receipt<'a> {
    schema_version: u8,
    status: &'static str,
    cases: &'a [&'static str],
    passed_cases: usize,
    expected_cases: usize,
    http_requests: usize,
    identity_requests: usize,
    successful_logins: usize,
    decoded_creation_attempts: usize,
    guard_valid_response_polls: usize,
    guard_rejected_response_polls: usize,
    guard_valid_public_attempts: usize,
}
struct Suite {
    server: String,
    client: Client,
    alternate_client: Client,
    origin: String,
    request_ip: Option<String>,
    accounts: Vec<Account>,
    sessions: Vec<Session>,
    device_baselines: Vec<Value>,
    records: Vec<Stored>,
    requests: usize,
    identity_requests: usize,
    successful_logins: usize,
    creations: usize,
    polls: usize,
    rejected_polls: usize,
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
    fn write_receipt(&mut self, status: &'static str) -> Result<(), AuthResponsesError> {
        if let Some(file) = &mut self.receipt {
            let record = Receipt {
                schema_version: 1,
                status,
                cases: &self.passed,
                passed_cases: self.passed.len(),
                expected_cases: CASES.len(),
                http_requests: self.requests,
                identity_requests: self.identity_requests,
                successful_logins: self.successful_logins,
                decoded_creation_attempts: self.creations,
                guard_valid_response_polls: self.polls,
                guard_rejected_response_polls: self.rejected_polls,
                guard_valid_public_attempts: self.creations + self.polls,
            };
            let bytes = serde_json::to_vec(&record)
                .map_err(|_| AuthResponsesError("Auth-response receipt encoding failed"))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| AuthResponsesError("Auth-response receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| AuthResponsesError("Auth-response receipt update failed"))?;
            file.write_all(&bytes)
                .map_err(|_| AuthResponsesError("Auth-response receipt write failed"))?;
            file.sync_all()
                .map_err(|_| AuthResponsesError("Auth-response receipt persistence failed"))?;
        }
        Ok(())
    }
    fn read(response: reqwest::blocking::Response) -> Result<Reply, AuthResponsesError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AuthResponsesError("Auth-response HTTP reply read failed"))?;
        require(
            bytes.len() as u64 <= MAX_RESPONSE_BYTES,
            "Auth-response reply exceeded capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn request(
        &mut self,
        method: Method,
        path: &str,
        headers: Headers<'_>,
        body: Option<&[u8]>,
        alternate: bool,
    ) -> Result<Reply, AuthResponsesError> {
        self.requests += 1;
        let client = if alternate {
            &self.alternate_client
        } else {
            &self.client
        };
        let mut request = client.request(method, format!("{}{path}", self.server));
        if let Some(bearer) = headers.bearer {
            request = request.bearer_auth(bearer);
        }
        if let Some(kind) = headers.kind {
            request = request.header("device-type", kind);
        }
        if let Some(device) = headers.device {
            request = request.header("x-device-identifier", device);
        }
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        Self::read(
            request
                .send()
                .map_err(|_| AuthResponsesError("Auth-response HTTP request failed"))?,
        )
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Value, AuthResponsesError> {
        let body = body.map(Value::to_string);
        self.request(
            method,
            path,
            Headers {
                bearer,
                ..Headers::default()
            },
            body.as_deref().map(str::as_bytes),
            false,
        )?
        .status(200)?
        .json()
    }
    fn login(
        &mut self,
        fixture: &Value,
        id: &str,
        kind: i32,
    ) -> Result<String, AuthResponsesError> {
        let kind = kind.to_string();
        let form = [
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("username", text(&fixture["email"])?),
            ("password", text(&fixture["masterPasswordHash"])?),
            ("deviceIdentifier", id),
            ("deviceName", "Auth-response comparison"),
            ("deviceType", kind.as_str()),
        ];
        self.requests += 1;
        self.identity_requests += 1;
        let response = self
            .client
            .post(format!("{}/identity/connect/token", self.server))
            .form(&form)
            .send()
            .map_err(|_| AuthResponsesError("Auth-response fixture login failed"))?;
        let response = Self::read(response)?.status(200)?.json()?;
        let token = text(&response["access_token"])?.to_owned();
        self.successful_logins += 1;
        Ok(token)
    }
    fn snapshot(&mut self, token: &str) -> Result<Snapshot, AuthResponsesError> {
        let profile = self.json(Method::GET, "/api/accounts/profile", Some(token), None)?;
        let sync = self.json(Method::GET, "/api/sync", Some(token), None)?;
        let revision = self
            .json(
                Method::GET,
                "/api/accounts/revision-date",
                Some(token),
                None,
            )?
            .as_i64()
            .ok_or(AuthResponsesError("Auth-response account revision missing"))?;
        Ok(Snapshot {
            profile,
            sync,
            revision,
        })
    }
    fn seed_vault(&mut self, account: &Account) -> Result<(), AuthResponsesError> {
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
            "Auth-response vault fixture lost its folder",
        )
    }
    fn budget(&self) -> Result<(), AuthResponsesError> {
        require(
            self.creations + self.polls <= PUBLIC_BUDGET,
            "Auth-response public request budget exceeded",
        )
    }
    fn create(&mut self, session: usize, code: &str) -> Result<usize, AuthResponsesError> {
        let device = self.sessions[session].clone();
        let body = json!({"accessCode":code,"deviceIdentifier":device.id,
            "email":self.accounts[device.owner].fixture["email"],"publicKey":"opaque-request-public-key"});
        self.creations += 1;
        self.budget()?;
        // Distinct timestamps avoid assuming an upstream order for equal dates.
        thread::sleep(Duration::from_millis(10));
        let kind = device.kind.to_string();
        let wire = self
            .request(
                Method::POST,
                COLLECTION,
                Headers {
                    kind: Some(&kind),
                    ..Headers::default()
                },
                Some(body.to_string().as_bytes()),
                false,
            )?
            .status(200)?
            .json()?;
        require(
            wire.as_object().is_some_and(|o| o.len() == 11)
                && wire["publicKey"] == body["publicKey"]
                && wire["requestDeviceType"] == device.label
                && wire["requestIpAddress"].is_string()
                && wire.get("key") == Some(&Value::Null)
                && wire.get("masterPasswordHash") == Some(&Value::Null)
                && wire["creationDate"].as_str().is_some_and(|s| !s.is_empty())
                && wire.get("responseDate") == Some(&Value::Null)
                && wire["requestApproved"] == false
                && wire["origin"] == self.origin
                && wire["object"] == "auth-request",
            "Creation did not return the exact eleven-field auth-request projection",
        )?;
        let id = text(&wire["id"])?;
        require(
            Uuid::parse_str(id).is_ok() && self.records.iter().all(|r| r.wire["id"] != id),
            "Creation did not assign a fresh auth-request UUID",
        )?;
        let ip = text(&wire["requestIpAddress"])?;
        require(
            ip.parse::<IpAddr>().is_ok(),
            "Auth-request peer address missing",
        )?;
        if let Some(expected) = &self.request_ip {
            require(
                ip == expected,
                "Auth-request peer address changed without a transport change",
            )?;
        } else {
            self.request_ip = Some(ip.to_owned());
        }
        let mut stored = wire;
        stored["requestApproved"] = Value::Null;
        let index = self.records.len();
        self.records.push(Stored {
            owner: device.owner,
            device: device.id,
            code: code.to_owned(),
            wire: stored,
            deleted: false,
        });
        self.check_record(index)?;
        Ok(index)
    }
    fn check_record(&mut self, index: usize) -> Result<(), AuthResponsesError> {
        let record = &self.records[index];
        let token = self.accounts[record.owner].token.clone();
        let path = format!("{COLLECTION}/{}", text(&record.wire["id"])?);
        let deleted = record.deleted;
        let expected = record.wire.clone();
        let reply = self.request(
            Method::GET,
            &path,
            Headers {
                bearer: Some(&token),
                ..Headers::default()
            },
            None,
            false,
        )?;
        if deleted {
            reply.status(400)?;
        } else {
            require(
                reply.status(200)?.json()? == expected,
                "Stored auth-request changed unexpectedly",
            )?;
        }
        Ok(())
    }
    fn approval(&self, actor: usize, key: &str, hash: Option<&str>, approved: bool) -> Value {
        json!({"deviceIdentifier":self.sessions[actor].id,"key":key,"masterPasswordHash":hash,"requestApproved":approved})
    }
    fn respond(
        &mut self,
        index: usize,
        actor: usize,
        body: &Value,
    ) -> Result<(), AuthResponsesError> {
        let shape: ApprovalShape = serde_json::from_value(body.clone())
            .map_err(|_| AuthResponsesError("Positive approval fixture schema invalid"))?;
        let session = self.sessions[actor].clone();
        require(
            shape.device_identifier == session.id
                && self.records[index].owner == session.owner
                && self.records[index].pending(),
            "Positive approval fixture authority invalid",
        )?;
        let before = self.records[index].wire.clone();
        let path = format!("{COLLECTION}/{}", text(&before["id"])?);
        thread::sleep(Duration::from_millis(10));
        let response = self.json(Method::PUT, &path, Some(&session.token), Some(body))?;
        let date = text(&response["responseDate"])?;
        require(
            !date.is_empty() && date > text(&before["creationDate"])?,
            "Accepted response did not set a fresh response date",
        )?;
        let mut expected = before;
        expected["responseDate"] = json!(date);
        if shape.request_approved {
            expected["requestApproved"] = json!(true);
            expected["key"] = json!(shape.key);
            expected["masterPasswordHash"] = json!(shape.master_password_hash);
            self.records[index].wire = expected.clone();
        } else {
            self.records[index].deleted = true;
        }
        require(
            response == expected,
            "Approval or rejection changed its exact eleven-field projection",
        )?;
        self.check_record(index)
    }
    fn rejected_approval(
        &mut self,
        index: usize,
        actor: usize,
        body: &Value,
    ) -> Result<(), AuthResponsesError> {
        let path = format!("{COLLECTION}/{}", text(&self.records[index].wire["id"])?);
        let token = self.sessions[actor].token.clone();
        self.request(
            Method::PUT,
            &path,
            Headers {
                bearer: Some(&token),
                ..Headers::default()
            },
            Some(body.to_string().as_bytes()),
            false,
        )?
        .status(400)?;
        self.check_record(index)
    }
    fn poll(
        &mut self,
        id: &str,
        query: Option<&str>,
        headers: Headers<'_>,
        expected: u16,
        alternate: bool,
    ) -> Result<Reply, AuthResponsesError> {
        if expected == 422 {
            self.rejected_polls += 1;
        } else {
            self.polls += 1;
            self.budget()?;
        }
        let suffix = query.map_or_else(String::new, |query| format!("?{query}"));
        self.request(
            Method::GET,
            &format!("{COLLECTION}/{id}/response{suffix}"),
            headers,
            None,
            alternate,
        )?
        .status(expected)
    }
    fn poll_record(
        &mut self,
        index: usize,
        headers: Headers<'_>,
    ) -> Result<(), AuthResponsesError> {
        let record = &self.records[index];
        let id = text(&record.wire["id"])?.to_owned();
        let query = code_query(&record.code)?;
        let expected = record.wire.clone();
        require(
            !record.deleted,
            "Positive poll fixture referenced a deleted request",
        )?;
        let reply = self.poll(&id, Some(&query), headers, 200, false)?.json()?;
        require(
            reply == expected,
            "Public polling changed the exact stored auth-request projection",
        )
    }
    fn deleted_poll(&mut self, index: usize, kind: &str) -> Result<(), AuthResponsesError> {
        let id = text(&self.records[index].wire["id"])?.to_owned();
        let query = code_query(&self.records[index].code)?;
        self.poll(
            &id,
            Some(&query),
            Headers {
                kind: Some(kind),
                ..Headers::default()
            },
            400,
            false,
        )?;
        Ok(())
    }
    fn check_pending(&mut self) -> Result<(), AuthResponsesError> {
        for owner in [0, 1] {
            let token = self.accounts[owner].token.clone();
            let expected: BTreeMap<_, _> = self
                .records
                .iter()
                .filter(|r| r.owner == owner && r.pending())
                .map(|r| {
                    (
                        r.wire["id"].as_str().unwrap_or_default().to_owned(),
                        r.wire.clone(),
                    )
                })
                .collect();
            for path in [COLLECTION, "/api/auth-requests/pending"] {
                let list = self.json(Method::GET, path, Some(&token), None)?;
                require(
                    list_records(&list)? == expected,
                    "Pending list changed approval state, projection, or ownership",
                )?;
            }
            let devices = self.json(Method::GET, "/api/devices", Some(&token), None)?;
            require(
                devices == expected_devices(&self.device_baselines[owner], owner, &self.records)?,
                "Latest pending-device metadata did not follow approval or rejection",
            )?;
        }
        Ok(())
    }
}

fn code_query(code: &str) -> Result<String, AuthResponsesError> {
    let mut url = reqwest::Url::parse("http://fixture.invalid/")
        .map_err(|_| AuthResponsesError("Query fixture construction failed"))?;
    url.query_pairs_mut().append_pair("code", code);
    Ok(url.query().unwrap_or_default().to_owned())
}
fn list_records(value: &Value) -> Result<BTreeMap<String, Value>, AuthResponsesError> {
    require(
        value.as_object().is_some_and(|o| o.len() == 3)
            && value["object"] == "list"
            && value.get("continuationToken") == Some(&Value::Null),
        "Pending list wrapper differed",
    )?;
    let mut result = BTreeMap::new();
    for row in value["data"]
        .as_array()
        .ok_or(AuthResponsesError("Pending list data missing"))?
    {
        require(
            result
                .insert(text(&row["id"])?.to_owned(), row.clone())
                .is_none(),
            "Pending list contained duplicate identifiers",
        )?;
    }
    Ok(result)
}
fn expected_devices(
    baseline: &Value,
    owner: usize,
    records: &[Stored],
) -> Result<Value, AuthResponsesError> {
    let mut expected = baseline.clone();
    for device in expected["data"]
        .as_array_mut()
        .ok_or(AuthResponsesError("Device baseline data missing"))?
    {
        let id = text(&device["id"])?;
        let latest = records
            .iter()
            .rev()
            .find(|r| r.owner == owner && r.device == id && r.pending());
        device["devicePendingAuthRequest"] = latest.map_or(
            Value::Null,
            |r| json!({"id":r.wire["id"],"creationDate":r.wire["creationDate"]}),
        );
    }
    Ok(expected)
}

fn auth_responses_approve_and_repeat_poll(s: &mut Suite) -> Result<(), AuthResponsesError> {
    let record = s.create(0, "repeat-poll-private-code")?;
    for _ in 0..2 {
        s.poll_record(
            record,
            Headers {
                kind: Some("8"),
                ..Headers::default()
            },
        )?;
    }
    s.respond(
        record,
        2,
        &s.approval(
            2,
            "opaque-encrypted-key",
            Some("opaque-password-hash"),
            true,
        ),
    )?;
    for _ in 0..2 {
        s.poll_record(
            record,
            Headers {
                kind: Some("8"),
                ..Headers::default()
            },
        )?;
    }
    Ok(())
}
fn auth_responses_reject_deletes_pending(s: &mut Suite) -> Result<(), AuthResponsesError> {
    let record = s.create(0, "reject-private-code")?;
    s.check_pending()?;
    s.respond(
        record,
        2,
        &s.approval(
            2,
            "ignored-rejection-key",
            Some("ignored-rejection-hash"),
            false,
        ),
    )?;
    s.check_pending()?;
    s.deleted_poll(record, "8")
}
fn auth_responses_verified_response_device_and_rejections(
    s: &mut Suite,
) -> Result<(), AuthResponsesError> {
    let record = s.create(0, "device-binding-private-code")?;
    // The requested device differs from the verified responding session's device.
    s.rejected_approval(record, 2, &s.approval(0, "key", None, true))?;
    let mut unknown = s.approval(2, "key", None, true);
    unknown["deviceIdentifier"] = json!(format!("missing-{}", Uuid::new_v4()));
    s.rejected_approval(record, 2, &unknown)?;
    // Bob shares Alice's requesting identifier, but cannot answer Alice's request.
    s.rejected_approval(record, 1, &s.approval(1, "key", None, true))?;
    let token = s.sessions[2].token.clone();
    s.request(
        Method::PUT,
        &format!("{COLLECTION}/{}", Uuid::new_v4()),
        Headers {
            bearer: Some(&token),
            ..Headers::default()
        },
        Some(s.approval(2, "key", None, true).to_string().as_bytes()),
        false,
    )?
    .status(400)?;
    s.respond(record, 2, &s.approval(2, "bound-response-key", None, true))?;
    for approved in [true, false] {
        s.rejected_approval(record, 2, &s.approval(2, "replacement-key", None, approved))?;
    }
    Ok(())
}
fn auth_responses_opaque_optional_and_positional_values(
    s: &mut Suite,
) -> Result<(), AuthResponsesError> {
    let record = s.create(0, "")?;
    let mut omitted = s.approval(2, "", None, true);
    omitted
        .as_object_mut()
        .ok_or(AuthResponsesError("Approval object fixture invalid"))?
        .remove("masterPasswordHash");
    omitted["id"] = json!(Uuid::new_v4().to_string());
    omitted["userId"] = json!(s.accounts[1].id);
    omitted["responseDate"] = json!("1900-01-01T00:00:00Z");
    omitted["requestDeviceType"] = json!("forged");
    s.respond(record, 2, &omitted)?;
    s.poll_record(
        record,
        Headers {
            kind: Some("8"),
            ..Headers::default()
        },
    )?;
    let record = s.create(0, "positional-private-code")?;
    s.respond(
        record,
        2,
        &json!([s.sessions[2].id, "  opaque\0雪🔐\r\n  ", "", true]),
    )?;
    s.poll_record(
        record,
        Headers {
            kind: Some("8"),
            ..Headers::default()
        },
    )?;
    let record = s.create(0, "opaque-hash-private-code")?;
    s.respond(
        record,
        2,
        &s.approval(2, "future-key\0雪", Some("  future-hash\0🔐\t  "), true),
    )?;
    s.poll_record(
        record,
        Headers {
            kind: Some("8"),
            ..Headers::default()
        },
    )
}
fn auth_responses_schema_and_guard_precedence(s: &mut Suite) -> Result<(), AuthResponsesError> {
    let record = s.create(0, "schema-private-code")?;
    let path = format!("{COLLECTION}/{}", text(&s.records[record].wire["id"])?);
    let token = s.sessions[2].token.clone();
    let base = s.approval(2, "key", None, true);
    let mut invalid = vec![
        json!(null),
        json!(false),
        json!("string"),
        json!({}),
        json!([]),
    ];
    for field in ["deviceIdentifier", "key", "requestApproved"] {
        let mut omitted = base.clone();
        omitted
            .as_object_mut()
            .ok_or(AuthResponsesError("Approval object fixture invalid"))?
            .remove(field);
        invalid.push(omitted);
        for value in [json!(null), json!(0), json!([]), json!({})] {
            let mut wrong = base.clone();
            wrong[field] = value;
            invalid.push(wrong);
        }
    }
    for value in [json!(false), json!(0), json!([]), json!({})] {
        let mut wrong = base.clone();
        wrong["masterPasswordHash"] = value;
        invalid.push(wrong);
    }
    invalid.push(json!([s.sessions[2].id, "key", null]));
    let mut raw: Vec<String> = invalid.iter().map(Value::to_string).collect();
    for field in [
        "deviceIdentifier",
        "key",
        "masterPasswordHash",
        "requestApproved",
    ] {
        let value = base[field].to_string();
        let prefix = format!("{{\"{field}\":{value},");
        raw.push(base.to_string().replacen('{', &prefix, 1));
    }
    raw.push(
        base.to_string()
            .replacen('{', "{\"k\\u0065y\":\"duplicate\",", 1),
    );
    for (index, body) in raw.iter().enumerate() {
        let reply = s.request(
            Method::PUT,
            &path,
            Headers {
                bearer: Some(&token),
                ..Headers::default()
            },
            Some(body.as_bytes()),
            false,
        )?;
        if reply.status != 422 {
            eprintln!(
                "Approval schema fixture {index}, method PUT, expected422, actual{}",
                reply.status
            );
        }
        reply.status(422)?;
    }
    for body in [
        "{".to_owned(),
        format!("{},", base),
        json!([s.sessions[2].id, "key", null, true, 0]).to_string(),
    ] {
        s.request(
            Method::PUT,
            &path,
            Headers {
                bearer: Some(&token),
                ..Headers::default()
            },
            Some(body.as_bytes()),
            false,
        )?
        .status(400)?;
    }
    let malformed = format!("{COLLECTION}/not-a-uuid");
    for bearer in [None, Some("invalid-approval-bearer")] {
        for target in [&path, &malformed] {
            s.request(
                Method::PUT,
                target,
                Headers {
                    bearer,
                    ..Headers::default()
                },
                Some(b"{"),
                false,
            )?
            .status(401)?;
        }
    }
    for body in [b"{".as_slice(), base.to_string().as_bytes()] {
        s.request(
            Method::PUT,
            &malformed,
            Headers {
                bearer: Some(&token),
                ..Headers::default()
            },
            Some(body),
            false,
        )?
        .status(422)?;
    }
    s.check_record(record)
}
fn auth_responses_code_query_guards(s: &mut Suite) -> Result<(), AuthResponsesError> {
    let record = s.create(0, "opaque+a b/雪\0&=")?;
    let id = text(&s.records[record].wire["id"])?.to_owned();
    let correct = code_query(&s.records[record].code)?;
    let encoded = correct
        .strip_prefix("code=")
        .ok_or(AuthResponsesError("Encoded query fixture invalid"))?;
    let headers = Headers {
        kind: Some("8"),
        ..Headers::default()
    };
    let positive = [
        format!("{correct}&unknown=ignored"),
        format!("{correct}&code=wrong"),
        format!("code.x={encoded}"),
        format!("[code]={encoded}"),
        format!(".code={encoded}"),
        format!("code[x]={encoded}"),
    ];
    for query in positive {
        let reply = s.poll(&id, Some(&query), headers, 200, false)?.json()?;
        require(
            reply == s.records[record].wire,
            "Accepted code query changed the auth-request projection",
        )?;
    }
    for query in [
        correct.replace("%2B", "+"),
        "code=wrong".into(),
        "code".into(),
        "code=".into(),
        format!("code=wrong&{correct}"),
    ] {
        s.poll(&id, Some(&query), headers, 400, false)?;
    }
    s.poll(
        &Uuid::new_v4().to_string(),
        Some(&correct),
        headers,
        400,
        false,
    )?;
    for query in [None, Some(""), Some("Code=wrong"), Some("unknown=ignored")] {
        s.poll(&id, query, headers, 422, false)?;
    }
    for query in [None, Some(correct.as_str())] {
        s.poll("not-a-uuid", query, headers, 422, false)?;
    }
    s.check_record(record)
}
fn auth_responses_type_bearer_and_ip_guards(s: &mut Suite) -> Result<(), AuthResponsesError> {
    let record = s.create(3, "fallback-type-private-code")?;
    for kind in [None, Some("iOS"), Some("2147483648")] {
        s.poll_record(
            record,
            Headers {
                kind,
                ..Headers::default()
            },
        )?;
    }
    let id = text(&s.records[record].wire["id"])?.to_owned();
    let query = code_query(&s.records[record].code)?;
    for kind in ["8", "-7"] {
        s.poll(
            &id,
            Some(&query),
            Headers {
                kind: Some(kind),
                ..Headers::default()
            },
            400,
            false,
        )?;
    }
    let original_id = text(&s.records[0].wire["id"])?.to_owned();
    let original_query = code_query(&s.records[0].code)?;
    s.poll(
        &original_id,
        Some(&original_query),
        Headers::default(),
        400,
        false,
    )?;
    let bob = s.accounts[1].token.clone();
    for bearer in ["invalid-public-poll-bearer", bob.as_str()] {
        s.poll_record(
            record,
            Headers {
                bearer: Some(bearer),
                kind: Some("14"),
                ..Headers::default()
            },
        )?;
    }
    s.poll(
        &id,
        Some(&query),
        Headers {
            kind: Some("14"),
            ..Headers::default()
        },
        400,
        true,
    )?;
    Ok(())
}
fn auth_responses_pending_projection_transitions(s: &mut Suite) -> Result<(), AuthResponsesError> {
    let older = s.create(0, "older-pending-private-code")?;
    let newer = s.create(0, "newer-pending-private-code")?;
    s.check_pending()?;
    s.respond(newer, 2, &s.approval(2, "newer-response-key", None, true))?;
    s.check_pending()?;
    for _ in 0..2 {
        s.poll_record(
            older,
            Headers {
                kind: Some("8"),
                ..Headers::default()
            },
        )?;
    }
    s.poll_record(
        newer,
        Headers {
            kind: Some("8"),
            ..Headers::default()
        },
    )?;
    s.respond(
        older,
        2,
        &s.approval(2, "ignored-rejected-key", None, false),
    )?;
    s.check_pending()?;
    s.deleted_poll(older, "8")
}

fn receipt() -> Result<Option<fs::File>, AuthResponsesError> {
    let Some(path) = std::env::var_os("BW_AUTH_RESPONSES_RECEIPT") else {
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
        .map_err(|_| AuthResponsesError("Private auth-response receipt creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| AuthResponsesError("Private auth-response receipt permissions failed"))?;
    }
    Ok(Some(file))
}
fn client(alternate: bool) -> Result<Client, AuthResponsesError> {
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30));
    if alternate {
        builder = builder.local_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)));
    }
    builder
        .build()
        .map_err(|_| AuthResponsesError("Auth-response HTTP client initialization failed"))
}

/// Run only once against a fresh reference process. Four successful password
/// logins register two owners and four sessions. Exactly11 public creates plus
/// 33 guard-valid public polls fit unchanged shared unauthenticated burst50.
/// Malformed query/path rejections never enter that handler limiter. Registration
/// requests made by the shared fixture helper are excluded from HTTP counters.
pub fn run() -> Result<(), AuthResponsesError> {
    let server = std::env::var("BW_E2E_SERVER")
        .unwrap_or_else(|_| "http://127.0.0.1:8000".into())
        .trim_end_matches('/')
        .to_owned();
    let url = reqwest::Url::parse(&server)
        .map_err(|_| AuthResponsesError("Invalid auth-response test server configuration"))?;
    require(
        matches!(url.scheme(), "http" | "https")
            && url.host_str() == Some("127.0.0.1")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Auth-response direct-peer suite requires an IPv4-loopback test server",
    )?;
    let mut s = Suite {
        server,
        client: client(false)?,
        alternate_client: client(true)?,
        origin: String::new(),
        request_ip: None,
        accounts: Vec::new(),
        sessions: Vec::new(),
        device_baselines: Vec::new(),
        records: Vec::new(),
        requests: 0,
        identity_requests: 0,
        successful_logins: 0,
        creations: 0,
        polls: 0,
        rejected_polls: 0,
        passed: Vec::new(),
        receipt: receipt()?,
        finished: false,
    };
    s.write_receipt("running")?;
    let config = s.json(Method::GET, "/api/config", None, None)?;
    s.origin = reqwest::Url::parse(text(&config["environment"]["vault"])?)
        .map_err(|_| AuthResponsesError("Configured auth-response origin invalid"))?
        .origin()
        .ascii_serialization();
    let shared = format!("Auth-Response-Shared-{}", Uuid::new_v4());
    for owner in [0, 1] {
        let email = format!("auth-response-{}@example.test", Uuid::new_v4());
        let password = format!("Nw!{}", Uuid::new_v4());
        let fixture = fixture::seed_account(&s.server, &email, &password)
            .map_err(|_| AuthResponsesError("Auth-response fixture registration failed"))?;
        let token = s.login(&fixture, &shared, 8)?;
        let profile = s.json(Method::GET, "/api/accounts/profile", Some(&token), None)?;
        let account = Account {
            token: token.clone(),
            id: text(&profile["id"])?.to_owned(),
            fixture,
        };
        s.seed_vault(&account)?;
        s.accounts.push(account);
        s.sessions.push(Session {
            owner,
            id: shared.clone(),
            token,
            kind: 8,
            label: "Linux",
        });
    }
    for (kind, label) in [(25, "Linux CLI"), (14, "Unknown Browser")] {
        let id = format!("Auth-Response-Other-{}", Uuid::new_v4());
        let token = s.login(&s.accounts[0].fixture.clone(), &id, kind)?;
        s.sessions.push(Session {
            owner: 0,
            id,
            token,
            kind,
            label,
        });
    }
    for owner in [0, 1] {
        let token = s.accounts[owner].token.clone();
        let devices = s.json(Method::GET, "/api/devices", Some(&token), None)?;
        s.device_baselines.push(devices);
    }
    s.check_pending()?;
    for (name, case) in CASES {
        let alice = s.accounts[0].token.clone();
        let bob = s.accounts[1].token.clone();
        let before_alice = s.snapshot(&alice)?;
        let before_bob = s.snapshot(&bob)?;
        case(&mut s)?;
        require(
            s.snapshot(&alice)? == before_alice && s.snapshot(&bob)? == before_bob,
            "Auth-response operation changed accounts, keys, sessions, vault, settings, or revision",
        )?;
        s.check_pending()?;
        s.passed.push(name);
        s.write_receipt("running")?;
        println!("PASS {name}");
    }
    require(
        s.identity_requests == 4
            && s.successful_logins == 4
            && s.creations == 11
            && s.polls == 33
            && s.creations + s.polls == PUBLIC_BUDGET,
        "Auth-response fixed request budget differed",
    )?;
    s.write_receipt("passed")?;
    s.finished = true;
    println!(
        "PASS auth-responses: {} cases, {} HTTP requests, {} successful logins, {} decoded creates, {} guard-valid polls, {} guard-rejected polls",
        s.passed.len(),
        s.requests,
        s.successful_logins,
        s.creations,
        s.polls,
        s.rejected_polls
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn approval_shape_preserves_optional_values_and_sequence_order() {
        let shape: ApprovalShape = serde_json::from_str("[\"device\",\"key\",\"\",true]").unwrap();
        assert!(
            shape.device_identifier == "device"
                && shape.key == "key"
                && shape.master_password_hash.as_deref() == Some("")
                && shape.request_approved
        );
        for body in [
            r#"{"deviceIdentifier":"d","key":"","requestApproved":true}"#,
            r#"{"deviceIdentifier":"d","key":"","masterPasswordHash":null,"requestApproved":true}"#,
        ] {
            assert!(
                serde_json::from_str::<ApprovalShape>(body)
                    .unwrap()
                    .master_password_hash
                    .is_none()
            );
        }
        for body in [
            r#"["d","k",true]"#,
            r#"["d","k",null]"#,
            r#"{"deviceIdentifier":"d","key":"k","k\u0065y":"duplicate","requestApproved":true}"#,
        ] {
            assert_eq!(
                serde_json::from_str::<ApprovalShape>(body)
                    .err()
                    .unwrap()
                    .classify(),
                serde_json::error::Category::Data
            );
        }
        assert_eq!(
            serde_json::from_str::<ApprovalShape>(r#"["d","k",null,true,0]"#)
                .err()
                .unwrap()
                .classify(),
            serde_json::error::Category::Syntax
        );
    }
    #[test]
    fn query_encoding_retains_plus_space_unicode_and_nul_distinctions() {
        let code = "opaque+a b/雪\0&=";
        let encoded = code_query(code).unwrap();
        assert!(encoded.contains("%2B") && encoded.contains('+') && encoded.contains("%00"));
        let url = reqwest::Url::parse(&format!("http://fixture.invalid/?{encoded}")).unwrap();
        assert_eq!(url.query_pairs().next().unwrap().1, code);
        let changed = reqwest::Url::parse(&format!(
            "http://fixture.invalid/?{}",
            encoded.replace("%2B", "+")
        ))
        .unwrap();
        assert_ne!(changed.query_pairs().next().unwrap().1, code);
    }
    #[test]
    fn approved_and_deleted_rows_stop_shadowing_latest_pending_metadata() {
        let baseline =
            json!({"data":[{"id":"shared","name":"unchanged","devicePendingAuthRequest":null}]});
        let row = |id: &str, owner, approved, deleted| Stored {
            owner,
            device: "shared".into(),
            code: "not-device-metadata".into(),
            wire: json!({"id":id,"creationDate":id,"requestApproved":approved}),
            deleted,
        };
        let records = vec![
            row("old", 0, Value::Null, false),
            row("foreign", 1, Value::Null, false),
            row("approved", 0, json!(true), false),
            row("deleted", 0, Value::Null, true),
        ];
        let expected = expected_devices(&baseline, 0, &records).unwrap();
        assert_eq!(
            expected["data"][0]["devicePendingAuthRequest"],
            json!({"id":"old","creationDate":"old"})
        );
        assert_eq!(expected["data"][0]["name"], "unchanged");
        assert_eq!(
            expected_devices(&baseline, 1, &records).unwrap()["data"][0]["devicePendingAuthRequest"]
                ["id"],
            "foreign"
        );
    }
    #[test]
    fn diagnostics_and_typed_receipts_exclude_private_response_contents() {
        let marker = "private-response-marker";
        let error = Reply {
            status: 500,
            bytes: marker.as_bytes().to_vec(),
        }
        .status(200)
        .err()
        .unwrap();
        assert!(!format!("{error} {error:?}").contains(marker));
        let error = Reply {
            status: 200,
            bytes: marker.as_bytes().to_vec(),
        }
        .json()
        .err()
        .unwrap();
        assert!(!format!("{error} {error:?}").contains(marker));
        let receipt = Receipt {
            schema_version: 1,
            status: "passed",
            cases: &[CASES[0].0],
            passed_cases: 1,
            expected_cases: 8,
            http_requests: 1,
            identity_requests: 4,
            successful_logins: 4,
            decoded_creation_attempts: 11,
            guard_valid_response_polls: 33,
            guard_rejected_response_polls: 6,
            guard_valid_public_attempts: 44,
        };
        let value = serde_json::to_value(receipt).unwrap();
        assert_eq!(value["guardValidPublicAttempts"], 44);
        assert!(!value.to_string().contains(marker));
    }
}
