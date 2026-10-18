//! Portable one-use authentication-request password grants.
//!
//! Source: Vaultwarden 58a980f850464f7d9cdc99a765df36f0a3308b91,
//! identity.rs370–498/1107–1178 and auth.rs1239–1389. The actual reference is
//! Vaultwarden1.37.4. Account verification, 2FA, notifications, trusted proxies,
//! expiry cleanup and client-side request-key decryption remain separate work.
//! Direct loopback peers keep each case within unchanged per-IP reference
//! limits. No forwarded-header spoofing, authentication retry, or clock override.

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
    time::{Duration, Instant},
};
use uuid::Uuid;

type Case = fn(&mut Suite) -> Result<(), AuthLoginError>;
const CASES: [(&str, Case); 8] = [
    (
        "auth_login_approved_request_grants_bound_password_authority",
        auth_login_approved_request_grants_bound_password_authority,
    ),
    (
        "auth_login_consumption_replay_and_public_poll",
        auth_login_consumption_replay_and_public_poll,
    ),
    (
        "auth_login_pending_foreign_and_rejected_requests",
        auth_login_pending_foreign_and_rejected_requests,
    ),
    (
        "auth_login_wrong_proofs_and_peer_ip",
        auth_login_wrong_proofs_and_peer_ip,
    ),
    (
        "auth_login_opaque_empty_values_and_new_device",
        auth_login_opaque_empty_values_and_new_device,
    ),
    (
        "auth_login_form_aliases_and_required_guards",
        auth_login_form_aliases_and_required_guards,
    ),
    (
        "auth_login_scope_and_no_password_fallback",
        auth_login_scope_and_no_password_fallback,
    ),
    (
        "auth_login_strict_five_minute_expiry",
        auth_login_strict_five_minute_expiry,
    ),
];
const AUTH_REQUESTS: &str = "/api/auth-requests";
const TOKEN: &str = "/identity/connect/token";
const MAX_REPLY_BYTES: u64 = 16 * 1024 * 1024;
const EXPIRY_WAIT: Duration = Duration::from_secs(301);
type Form = BTreeMap<String, String>;

/// Static diagnostics retain no passwords, access codes, token claims, or bodies.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthLoginError(&'static str);
impl fmt::Display for AuthLoginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for AuthLoginError {}
fn require(condition: bool, message: &'static str) -> Result<(), AuthLoginError> {
    if condition {
        Ok(())
    } else {
        Err(AuthLoginError(message))
    }
}
fn text(value: &Value) -> Result<&str, AuthLoginError> {
    value
        .as_str()
        .ok_or(AuthLoginError("Required auth-login string missing"))
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, AuthLoginError> {
        if self.status != expected {
            eprintln!(
                "Auth-login HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Auth-login HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, AuthLoginError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| AuthLoginError("Auth-login response was not valid JSON"))
    }
    fn token_result(self, expected: u16) -> Result<Value, AuthLoginError> {
        let reply = self.status(expected)?;
        // Rocket's form guard can return its HTML422 catcher. Its body is not
        // an identity JSON response; preserve the status check and discard it.
        if expected == 422 {
            Ok(Value::Null)
        } else {
            reply.json()
        }
    }
}
#[derive(Clone)]
struct Account {
    token: String,
    id: String,
    device: String,
    fixture: Value,
}
#[derive(Clone)]
struct Request {
    owner: usize,
    peer: u8,
    code: String,
    wire: Value,
    created: Instant,
    deleted: bool,
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
}
#[derive(Default)]
struct PeerCounts {
    identity: usize,
    public: usize,
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
    ordinary_password_logins: usize,
    auth_request_logins: usize,
    refresh_requests: usize,
    public_creations: usize,
    public_response_polls: usize,
    max_identity_requests_per_peer: usize,
    max_public_requests_per_peer: usize,
    expiry_wait_seconds: u64,
}
struct Suite {
    server: String,
    clients: BTreeMap<u8, Client>,
    peers: BTreeMap<u8, PeerCounts>,
    accounts: Vec<Account>,
    requests: usize,
    identity_requests: usize,
    ordinary_logins: usize,
    request_logins: usize,
    refresh_requests: usize,
    creations: usize,
    polls: usize,
    expiry: Option<Request>,
    expiry_waited: u64,
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
    fn write_receipt(&mut self, status: &'static str) -> Result<(), AuthLoginError> {
        if let Some(file) = &mut self.receipt {
            let receipt = Receipt {
                schema_version: 1,
                status,
                cases: &self.passed,
                passed_cases: self.passed.len(),
                expected_cases: CASES.len(),
                http_requests: self.requests,
                identity_requests: self.identity_requests,
                ordinary_password_logins: self.ordinary_logins,
                auth_request_logins: self.request_logins,
                refresh_requests: self.refresh_requests,
                public_creations: self.creations,
                public_response_polls: self.polls,
                max_identity_requests_per_peer: self
                    .peers
                    .values()
                    .map(|p| p.identity)
                    .max()
                    .unwrap_or(0),
                max_public_requests_per_peer: self
                    .peers
                    .values()
                    .map(|p| p.public)
                    .max()
                    .unwrap_or(0),
                expiry_wait_seconds: self.expiry_waited,
            };
            let bytes = serde_json::to_vec(&receipt)
                .map_err(|_| AuthLoginError("Auth-login receipt encoding failed"))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| AuthLoginError("Auth-login receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| AuthLoginError("Auth-login receipt update failed"))?;
            file.write_all(&bytes)
                .map_err(|_| AuthLoginError("Auth-login receipt write failed"))?;
            file.sync_all()
                .map_err(|_| AuthLoginError("Auth-login receipt persistence failed"))?;
        }
        Ok(())
    }
    fn read(response: reqwest::blocking::Response) -> Result<Reply, AuthLoginError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_REPLY_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AuthLoginError("Auth-login response read failed"))?;
        require(
            bytes.len() as u64 <= MAX_REPLY_BYTES,
            "Auth-login response exceeded capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn request(
        &mut self,
        peer: u8,
        method: Method,
        path: &str,
        headers: Headers<'_>,
        body: Option<&Value>,
    ) -> Result<Reply, AuthLoginError> {
        self.requests += 1;
        let client = self
            .clients
            .get(&peer)
            .ok_or(AuthLoginError("Auth-login peer fixture unavailable"))?;
        let mut request = client.request(method, format!("{}{path}", self.server));
        if let Some(token) = headers.bearer {
            request = request.bearer_auth(token);
        }
        if let Some(kind) = headers.kind {
            request = request.header("device-type", kind);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        Self::read(
            request
                .send()
                .map_err(|_| AuthLoginError("Auth-login HTTP request failed"))?,
        )
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Value, AuthLoginError> {
        self.request(
            1,
            method,
            path,
            Headers {
                bearer: token,
                ..Headers::default()
            },
            body,
        )?
        .status(200)?
        .json()
    }
    fn token(&mut self, peer: u8, form: &Form, expected: u16) -> Result<Value, AuthLoginError> {
        let count = &mut self.peers.entry(peer).or_default().identity;
        *count += 1;
        require(
            *count <= 10,
            "Auth-login per-peer identity request budget exceeded",
        )?;
        self.requests += 1;
        self.identity_requests += 1;
        let client = self
            .clients
            .get(&peer)
            .ok_or(AuthLoginError("Auth-login peer fixture unavailable"))?;
        Self::read(
            client
                .post(format!("{}{TOKEN}", self.server))
                .form(form)
                .send()
                .map_err(|_| AuthLoginError("Auth-login token request failed"))?,
        )?
        .token_result(expected)
    }
    fn public_attempt(&mut self, peer: u8) -> Result<(), AuthLoginError> {
        let count = &mut self.peers.entry(peer).or_default().public;
        *count += 1;
        require(
            *count <= 50,
            "Auth-login per-peer public request budget exceeded",
        )
    }
    fn snapshot(&mut self, owner: usize, token: Option<&str>) -> Result<Snapshot, AuthLoginError> {
        let original = self.accounts[owner].token.clone();
        let token = token.unwrap_or(&original);
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
            .ok_or(AuthLoginError("Auth-login account revision missing"))?;
        Ok(Snapshot {
            profile,
            sync,
            revision,
        })
    }
    fn devices(&mut self, owner: usize) -> Result<Value, AuthLoginError> {
        let token = self.accounts[owner].token.clone();
        self.json(Method::GET, "/api/devices", Some(&token), None)
    }
    fn seed_vault(&mut self, account: &Account) -> Result<(), AuthLoginError> {
        let key = text(&account.fixture["key"])?;
        let folder = self.json(
            Method::POST,
            "/api/folders",
            Some(&account.token),
            Some(&json!({"name":key})),
        )?;
        let cipher = self.json(Method::POST, "/api/ciphers", Some(&account.token), Some(&json!({"type":2,
            "name":key,"notes":key,"folderId":folder["id"],"encryptedFor":account.id,"secureNote":{"type":0}})))?;
        require(
            cipher["folderId"] == folder["id"],
            "Auth-login fixture lost vault data",
        )
    }
    fn create(&mut self, owner: usize, peer: u8, code: &str) -> Result<Request, AuthLoginError> {
        self.public_attempt(peer)?;
        self.creations += 1;
        let account = &self.accounts[owner];
        let body = json!({"accessCode":code,"deviceIdentifier":account.device,"email":account.fixture["email"],"publicKey":"opaque-auth-login-public-key"});
        let wire = self
            .request(
                peer,
                Method::POST,
                AUTH_REQUESTS,
                Headers {
                    kind: Some("8"),
                    ..Headers::default()
                },
                Some(&body),
            )?
            .status(200)?
            .json()?;
        let created = Instant::now();
        require(
            wire["requestApproved"] == false
                && wire["publicKey"] == body["publicKey"]
                && wire["requestDeviceType"] == "Linux"
                && wire["requestIpAddress"] == format!("127.0.0.{peer}")
                && Uuid::parse_str(text(&wire["id"])?).is_ok(),
            "Auth-login request creation fixture differed",
        )?;
        let mut wire = wire;
        wire["requestApproved"] = Value::Null;
        let request = Request {
            owner,
            peer,
            code: code.to_owned(),
            wire,
            created,
            deleted: false,
        };
        self.check_record(&request)?;
        Ok(request)
    }
    fn approve(&mut self, request: &mut Request, approved: bool) -> Result<(), AuthLoginError> {
        let account = self.accounts[request.owner].clone();
        let body = json!({"deviceIdentifier":account.device,"key":"approved-encrypted-key-is-not-login-proof",
            "masterPasswordHash":"approved-master-hash-is-not-login-proof","requestApproved":approved});
        let path = format!("{AUTH_REQUESTS}/{}", text(&request.wire["id"])?);
        let reply = self.json(Method::PUT, &path, Some(&account.token), Some(&body))?;
        let mut expected = request.wire.clone();
        expected["responseDate"] = reply["responseDate"].clone();
        require(
            expected["responseDate"].is_string(),
            "Approval fixture response date missing",
        )?;
        if approved {
            expected["requestApproved"] = json!(true);
            expected["key"] = body["key"].clone();
            expected["masterPasswordHash"] = body["masterPasswordHash"].clone();
            request.wire = expected.clone();
        } else {
            request.deleted = true;
        }
        require(
            reply == expected,
            "Auth-login approval fixture changed its exact projection",
        )?;
        self.check_record(request)
    }
    fn approved(&mut self, peer: u8, code: &str) -> Result<Request, AuthLoginError> {
        let mut request = self.create(0, peer, code)?;
        self.approve(&mut request, true)?;
        Ok(request)
    }
    fn check_record(&mut self, request: &Request) -> Result<(), AuthLoginError> {
        let token = self.accounts[request.owner].token.clone();
        let path = format!("{AUTH_REQUESTS}/{}", text(&request.wire["id"])?);
        let reply = self.request(
            1,
            Method::GET,
            &path,
            Headers {
                bearer: Some(&token),
                ..Headers::default()
            },
            None,
        )?;
        if request.deleted {
            reply.status(400)?;
        } else {
            require(
                reply.status(200)?.json()? == request.wire,
                "Login changed the public auth-request projection",
            )?;
        }
        Ok(())
    }
    fn poll(&mut self, request: &Request, expected: u16) -> Result<(), AuthLoginError> {
        self.public_attempt(request.peer)?;
        self.polls += 1;
        let query = form_query("code", &request.code)?;
        let path = format!(
            "{AUTH_REQUESTS}/{}/response?{query}",
            text(&request.wire["id"])?
        );
        let reply = self
            .request(
                request.peer,
                Method::GET,
                &path,
                Headers {
                    kind: Some("8"),
                    ..Headers::default()
                },
                None,
            )?
            .status(expected)?;
        if expected == 200 {
            require(
                reply.json()? == request.wire,
                "Public polling changed or consumed the approved request",
            )?;
        }
        Ok(())
    }
    fn grant_form(
        &self,
        request: &Request,
        device: &str,
        kind: &str,
    ) -> Result<Form, AuthLoginError> {
        let account = &self.accounts[request.owner];
        let mut form = password_form(&account.fixture, device, kind)?;
        form.insert("authRequest".into(), text(&request.wire["id"])?.into());
        form.insert("password".into(), request.code.clone());
        Ok(form)
    }
    fn rejected(
        &mut self,
        peer: u8,
        request: &Request,
        form: &Form,
        status: u16,
    ) -> Result<(), AuthLoginError> {
        let alice = self.devices(0)?;
        let bob = self.devices(1)?;
        self.token(peer, form, status)?;
        self.check_record(request)?;
        require(
            self.devices(0)? == alice && self.devices(1)? == bob,
            "Rejected auth-request grant changed registered devices",
        )
    }
    fn grant(&mut self, request: &Request, form: &Form) -> Result<Value, AuthLoginError> {
        let before = self.devices(request.owner)?;
        let tokens = self.token(request.peer, form, 200)?;
        self.request_logins += 1;
        self.check_tokens(&tokens, request.owner, form, Some(&before))?;
        self.check_record(request)?;
        Ok(tokens)
    }
    fn check_tokens(
        &mut self,
        tokens: &Value,
        owner: usize,
        form: &Form,
        before: Option<&Value>,
    ) -> Result<(), AuthLoginError> {
        let token = text(&tokens["access_token"])?;
        let refresh = text(&tokens["refresh_token"])?;
        require(
            !token.is_empty()
                && !refresh.is_empty()
                && tokens["token_type"] == "Bearer"
                && tokens["scope"] == "api offline_access"
                && tokens["expires_in"]
                    .as_i64()
                    .is_some_and(|s| (7195..=7200).contains(&s)),
            "Auth-request grant did not retain password access and refresh authority",
        )?;
        let claims = jwt_claims(token)?;
        let device = form_field(form, &["deviceIdentifier", "device_identifier"])
            .or_else(|| form.get("expectedDevice").map(String::as_str))
            .ok_or(AuthLoginError("Token device fixture missing"))?;
        let client_id = form_field(form, &["client_id", "clientid"]).unwrap_or("undefined");
        require(
            claims["sub"] == self.accounts[owner].id
                && claims["device"] == device
                && claims["client_id"] == client_id
                && claims["scope"] == json!(["api", "offline_access"])
                && claims["exp"]
                    .as_i64()
                    .zip(claims["nbf"].as_i64())
                    .is_some_and(|(exp, nbf)| exp - nbf == 7200),
            "Signed auth-request token claims lost owner, device, client, scope or lifetime",
        )?;
        require(
            self.snapshot(owner, Some(token))? == self.snapshot(owner, None)?,
            "Auth-request bearer had different profile, keys, settings or vault authority",
        )?;
        let devices = self.devices(owner)?;
        let row = device_row(&devices, device).ok_or(AuthLoginError(
            "Successful grant did not register its form device",
        ))?;
        let label = match row["type"].as_i64() {
            Some(8) => "Linux",
            Some(25) => "Linux CLI",
            Some(14) => "Unknown Browser",
            _ => return Err(AuthLoginError("Device-type fixture outside authored cases")),
        };
        require(
            claims["devicetype"] == label,
            "Signed token device type did not describe retained registry metadata",
        )?;
        if let Some(before) = before {
            require(
                tokens["Key"] == self.accounts[owner].fixture["key"]
                    && tokens["PrivateKey"]
                        == self.accounts[owner].fixture["keys"]["encryptedPrivateKey"],
                "Grant substituted approved request material for account keys",
            )?;
            if let Some(existing) = device_row(before, device) {
                require(
                    row == existing,
                    "Grant replaced an existing device's retained metadata",
                )?;
            } else {
                let kind = form_field(form, &["deviceType", "device_type"])
                    .unwrap_or_default()
                    .parse::<i32>()
                    .unwrap_or(14);
                let name = form_field(form, &["deviceName", "device_name"])
                    .ok_or(AuthLoginError("Token device-name fixture missing"))?;
                require(
                    row["identifier"] == device && row["name"] == name && row["type"] == kind,
                    "Grant reused requesting-device metadata instead of its fresh form device",
                )?;
            }
        }
        Ok(())
    }
    fn bound_device_proof(
        &mut self,
        tokens: &Value,
        peer: u8,
        device: &str,
    ) -> Result<(), AuthLoginError> {
        let mut extra = self.create(0, peer, "separate-device-binding-proof-code")?;
        let body =
            json!({"deviceIdentifier":device,"key":"bound-response-key","requestApproved":true});
        let path = format!("{AUTH_REQUESTS}/{}", text(&extra.wire["id"])?);
        let reply = self.json(
            Method::PUT,
            &path,
            Some(text(&tokens["access_token"])?),
            Some(&body),
        )?;
        let mut expected = extra.wire.clone();
        expected["key"] = body["key"].clone();
        expected["requestApproved"] = json!(true);
        expected["responseDate"] = reply["responseDate"].clone();
        require(
            reply == expected && reply["responseDate"].is_string(),
            "Auth-request bearer was not bound to its new form device",
        )?;
        extra.wire = expected;
        self.check_record(&extra)
    }
}

fn password_form(fixture: &Value, device: &str, kind: &str) -> Result<Form, AuthLoginError> {
    Ok([
        ("grant_type", "password"),
        ("client_id", "cli"),
        ("scope", "api offline_access"),
        ("username", text(&fixture["email"])?),
        ("password", text(&fixture["masterPasswordHash"])?),
        ("deviceIdentifier", device),
        ("deviceName", "Auth-login fresh device"),
        ("deviceType", kind),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_owned(), v.to_owned()))
    .collect())
}
fn form_field<'a>(form: &'a Form, names: &[&str]) -> Option<&'a str> {
    form.iter()
        .find(|(key, _)| names.iter().any(|name| key.eq_ignore_ascii_case(name)))
        .map(|(_, value)| value.as_str())
}
fn device_row<'a>(devices: &'a Value, identifier: &str) -> Option<&'a Value> {
    devices["data"]
        .as_array()?
        .iter()
        .find(|row| row["id"] == identifier)
}
fn form_query(key: &str, value: &str) -> Result<String, AuthLoginError> {
    let mut url = reqwest::Url::parse("http://fixture.invalid/")
        .map_err(|_| AuthLoginError("Auth-login query fixture invalid"))?;
    url.query_pairs_mut().append_pair(key, value);
    Ok(url.query().unwrap_or_default().to_owned())
}
fn jwt_claims(token: &str) -> Result<Value, AuthLoginError> {
    let payload = token
        .split('.')
        .nth(1)
        .ok_or(AuthLoginError("Issued token was not a JWT"))?;
    let bytes = URL_SAFE_NO_PAD
        .decode(payload)
        .map_err(|_| AuthLoginError("Issued JWT payload could not be decoded"))?;
    serde_json::from_slice(&bytes).map_err(|_| AuthLoginError("Issued JWT payload was not JSON"))
}

fn auth_login_approved_request_grants_bound_password_authority(
    s: &mut Suite,
) -> Result<(), AuthLoginError> {
    let request = s.approved(2, "authority-access-code")?;
    s.poll(&request, 200)?;
    let device = format!("Auth-Login-New-{}", Uuid::new_v4());
    let form = s.grant_form(&request, &device, "25")?;
    let tokens = s.grant(&request, &form)?;
    s.bound_device_proof(&tokens, 2, &device)?;
    s.poll(&request, 200)?;
    let mut refresh: Form = [
        ("grant_type".into(), "refresh_token".into()),
        (
            "refresh_token".into(),
            text(&tokens["refresh_token"])?.into(),
        ),
        ("client_id".into(), "changed-refresh-client".into()),
    ]
    .into_iter()
    .collect();
    s.refresh_requests += 1;
    let refreshed = s.token(2, &refresh, 200)?;
    refresh.insert("expectedDevice".into(), device.clone());
    s.check_tokens(&refreshed, 0, &refresh, None)?;
    refresh.remove("client_id");
    refresh.insert(
        "refresh_token".into(),
        text(&refreshed["refresh_token"])?.into(),
    );
    s.refresh_requests += 1;
    let refreshed = s.token(2, &refresh, 200)?;
    s.check_tokens(&refreshed, 0, &refresh, None)?;
    s.bound_device_proof(&refreshed, 2, &device)
}
fn auth_login_consumption_replay_and_public_poll(s: &mut Suite) -> Result<(), AuthLoginError> {
    let request = s.approved(3, "one-use-access-code")?;
    s.poll(&request, 200)?;
    let form = s.grant_form(&request, &format!("Auth-Replay-{}", Uuid::new_v4()), "25")?;
    s.grant(&request, &form)?;
    s.rejected(3, &request, &form, 400)?;
    let mut changed = form.clone();
    changed.insert(
        "deviceIdentifier".into(),
        format!("Replay-Fresh-{}", Uuid::new_v4()),
    );
    s.rejected(3, &request, &changed, 400)?;
    s.poll(&request, 200)
}
fn auth_login_pending_foreign_and_rejected_requests(s: &mut Suite) -> Result<(), AuthLoginError> {
    let mut pending = s.create(0, 4, "pending-access-code")?;
    let form = s.grant_form(&pending, &format!("Pending-New-{}", Uuid::new_v4()), "25")?;
    s.rejected(4, &pending, &form, 400)?;
    let mut foreign = form.clone();
    foreign.insert(
        "username".into(),
        text(&s.accounts[1].fixture["email"])?.into(),
    );
    s.rejected(4, &pending, &foreign, 400)?;
    let mut missing = form.clone();
    missing.insert("authRequest".into(), Uuid::new_v4().to_string());
    s.rejected(4, &pending, &missing, 400)?;
    let mut denied = s.create(0, 4, "denied-access-code")?;
    s.approve(&mut denied, false)?;
    let denied_form = s.grant_form(&denied, &format!("Denied-New-{}", Uuid::new_v4()), "25")?;
    s.rejected(4, &denied, &denied_form, 400)?;
    s.poll(&denied, 400)?;
    s.approve(&mut pending, true)?;
    s.grant(&pending, &form)?;
    s.poll(&pending, 200)
}
fn auth_login_wrong_proofs_and_peer_ip(s: &mut Suite) -> Result<(), AuthLoginError> {
    let request = s.approved(5, "correct-access-code\0雪+a b")?;
    let form = s.grant_form(&request, &format!("Proof-New-{}", Uuid::new_v4()), "25")?;
    for proof in [
        "wrong-access-code".to_owned(),
        text(&s.accounts[0].fixture["masterPasswordHash"])?.to_owned(),
        text(&request.wire["masterPasswordHash"])?.to_owned(),
    ] {
        let mut wrong = form.clone();
        wrong.insert("password".into(), proof);
        s.rejected(5, &request, &wrong, 400)?;
    }
    s.rejected(20, &request, &form, 400)?;
    s.grant(&request, &form)?;
    s.poll(&request, 200)
}
fn auth_login_opaque_empty_values_and_new_device(s: &mut Suite) -> Result<(), AuthLoginError> {
    let request = s.approved(6, "")?;
    s.poll(&request, 200)?;
    let mut form = s.grant_form(&request, "", "")?;
    form.insert("client_id".into(), String::new());
    form.insert("deviceName".into(), String::new());
    let tokens = s.grant(&request, &form)?;
    s.bound_device_proof(&tokens, 6, "")?;
    s.poll(&request, 200)
}
fn auth_login_form_aliases_and_required_guards(s: &mut Suite) -> Result<(), AuthLoginError> {
    let request = s.approved(7, "alias-access-code")?;
    let form = s.grant_form(&request, &format!("Aliases-New-{}", Uuid::new_v4()), "25")?;
    for (index, field) in [
        "client_id",
        "password",
        "scope",
        "username",
        "deviceIdentifier",
        "deviceName",
        "deviceType",
    ]
    .iter()
    .enumerate()
    {
        let mut missing = form.clone();
        missing.remove(*field);
        let before = s.devices(0)?;
        let reply = s.token(7, &missing, 400);
        if reply.is_err() {
            eprintln!("Auth-login required-field fixture index {index}, method POST");
        }
        reply?;
        require(
            s.devices(0)? == before,
            "Required-field rejection created a device",
        )?;
        s.check_record(&request)?;
    }
    let mut missing_grant = form.clone();
    missing_grant.remove("grant_type");
    s.rejected(7, &request, &missing_grant, 422)?;
    let mut alias = Form::new();
    for (key, value) in &form {
        let name = match key.as_str() {
            "grant_type" => "GRANTTYPE",
            "client_id" => "CLIENTID",
            "deviceIdentifier" => "DEVICE_IDENTIFIER",
            "deviceName" => "DEVICE_NAME",
            "deviceType" => "DEVICE_TYPE",
            "authRequest" => "aUtHrEqUeSt",
            "username" => "USERNAME",
            "password" => "PASSWORD",
            "scope" => "SCOPE",
            _ => key,
        };
        alias.insert(name.into(), value.clone());
    }
    alias.insert("futureUnknownField".into(), "ignored".into());
    s.grant(&request, &alias)?;
    s.poll(&request, 200)
}
fn auth_login_scope_and_no_password_fallback(s: &mut Suite) -> Result<(), AuthLoginError> {
    let request = s.approved(8, "scope-access-code")?;
    let mut form = s.grant_form(&request, &s.accounts[0].device, "25")?;
    form.insert(
        "deviceName".into(),
        "replacement metadata must be ignored".into(),
    );
    for scope in [
        "",
        "api",
        "offline_access api",
        "api offline_access ",
        "API offline_access",
        "api offline_access api",
    ] {
        let mut wrong = form.clone();
        wrong.insert("scope".into(), scope.into());
        s.rejected(8, &request, &wrong, 400)?;
    }
    for id in [
        String::new(),
        "malformed-not-a-uuid".into(),
        Uuid::new_v4().to_string(),
    ] {
        let mut wrong = form.clone();
        wrong.insert("authRequest".into(), id);
        wrong.insert(
            "password".into(),
            text(&s.accounts[0].fixture["masterPasswordHash"])?.into(),
        );
        s.rejected(8, &request, &wrong, 400)?;
    }
    // Rocket selects scalar fields by NameView root, not the entire name.
    // A valid ordinary password must not make these request selectors disappear.
    for (peer, name) in (30..=33).zip([
        "authRequest.x",
        "authRequest[x]",
        ".aUtHrEqUeSt",
        "[authRequest]",
    ]) {
        let mut wrong = form.clone();
        wrong.remove("authRequest");
        wrong.insert(name.into(), Uuid::new_v4().to_string());
        wrong.insert(
            "password".into(),
            text(&s.accounts[0].fixture["masterPasswordHash"])?.into(),
        );
        s.rejected(peer, &request, &wrong, 400)?;
    }
    s.grant(&request, &form)?;
    s.poll(&request, 200)
}
fn auth_login_strict_five_minute_expiry(s: &mut Suite) -> Result<(), AuthLoginError> {
    let request = s
        .expiry
        .clone()
        .ok_or(AuthLoginError("Auth-login expiry fixture missing"))?;
    while let Some(remaining) = EXPIRY_WAIT.checked_sub(request.created.elapsed()) {
        s.expiry_waited = request.created.elapsed().as_secs();
        s.write_receipt("waiting-expiry")?;
        thread::sleep(remaining.min(Duration::from_secs(15)));
    }
    s.expiry_waited = request.created.elapsed().as_secs();
    require(
        s.expiry_waited >= 301,
        "Real auth-request expiry wait was too short",
    )?;
    let form = s.grant_form(&request, &format!("Expired-New-{}", Uuid::new_v4()), "25")?;
    s.rejected(9, &request, &form, 400)?;
    s.poll(&request, 200)
}

fn receipt() -> Result<Option<fs::File>, AuthLoginError> {
    let Some(path) = std::env::var_os("BW_AUTH_LOGIN_RECEIPT") else {
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
        .map_err(|_| AuthLoginError("Private auth-login receipt creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| AuthLoginError("Private auth-login receipt permissions failed"))?;
    }
    Ok(Some(file))
}
fn peer_client(peer: u8) -> Result<Client, AuthLoginError> {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .local_address(IpAddr::V4(Ipv4Addr::new(127, 0, 0, peer)))
        .build()
        .map_err(|_| AuthLoginError("Auth-login peer client initialization failed"))
}

/// Run against a fresh selected reference process. Every identity request,
/// including rejected form guards and refresh, counts toward the conservative
/// ten-per-peer budget. Public create/poll requests stay below50 per peer.
/// A real301-second expiry fixture is prepared before the other cases; no clock
/// provider, SQL timestamp mutation, forwarded headers, or expiry shortcut is used.
/// Shared fixture registration requests are excluded from these HTTP counters.
pub fn run() -> Result<(), AuthLoginError> {
    let server = std::env::var("BW_E2E_SERVER")
        .unwrap_or_else(|_| "http://127.0.0.1:8000".into())
        .trim_end_matches('/')
        .to_owned();
    let url = reqwest::Url::parse(&server)
        .map_err(|_| AuthLoginError("Invalid auth-login test server configuration"))?;
    require(
        matches!(url.scheme(), "http" | "https")
            && url.host_str() == Some("127.0.0.1")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Auth-login direct-peer suite requires an IPv4-loopback test server",
    )?;
    let mut clients = BTreeMap::new();
    for peer in (1..=9).chain([20]).chain(30..=33) {
        clients.insert(peer, peer_client(peer)?);
    }
    let mut s = Suite {
        server,
        clients,
        peers: BTreeMap::new(),
        accounts: Vec::new(),
        requests: 0,
        identity_requests: 0,
        ordinary_logins: 0,
        request_logins: 0,
        refresh_requests: 0,
        creations: 0,
        polls: 0,
        expiry: None,
        expiry_waited: 0,
        passed: Vec::new(),
        receipt: receipt()?,
        finished: false,
    };
    s.write_receipt("running")?;
    for _ in [0, 1] {
        let email = format!("auth-login-{}@example.test", Uuid::new_v4());
        let password = format!("Nw!{}", Uuid::new_v4());
        let fixture = fixture::seed_account(&s.server, &email, &password)
            .map_err(|_| AuthLoginError("Auth-login fixture registration failed"))?;
        let device = format!("Auth-Login-Requester-{}", Uuid::new_v4());
        let tokens = s.token(1, &password_form(&fixture, &device, "8")?, 200)?;
        s.ordinary_logins += 1;
        let token = text(&tokens["access_token"])?.to_owned();
        let profile = s.json(Method::GET, "/api/accounts/profile", Some(&token), None)?;
        let account = Account {
            token,
            id: text(&profile["id"])?.into(),
            device,
            fixture,
        };
        s.seed_vault(&account)?;
        s.accounts.push(account);
    }
    s.expiry = Some(s.approved(9, "real-expiry-access-code")?);
    for (name, case) in CASES {
        let alice = s.snapshot(0, None)?;
        let bob = s.snapshot(1, None)?;
        let foreign_devices = s.devices(1)?;
        case(&mut s)?;
        require(
            s.snapshot(0, None)? == alice
                && s.snapshot(1, None)? == bob
                && s.devices(1)? == foreign_devices,
            "Auth-request login changed account keys, credentials, profile, vault, revision, or foreign devices",
        )?;
        s.passed.push(name);
        s.write_receipt("running")?;
        println!("PASS {name}");
    }
    require(
        s.ordinary_logins == 2
            && s.request_logins == 7
            && s.refresh_requests == 2
            && s.identity_requests == 43,
        "Auth-login fixed identity request budget differed",
    )?;
    s.write_receipt("passed")?;
    s.finished = true;
    println!(
        "PASS auth-login: {} cases, {} HTTP requests, {} identity requests, {} ordinary logins, {} request logins, {} refresh requests, {} public creates, {} public polls, max{} identity requests per peer, real expiry{} seconds",
        s.passed.len(),
        s.requests,
        s.identity_requests,
        s.ordinary_logins,
        s.request_logins,
        s.refresh_requests,
        s.creations,
        s.polls,
        s.peers.values().map(|p| p.identity).max().unwrap_or(0),
        s.expiry_waited
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aliases_preserve_presence_and_empty_values_without_underscore_auth_request_alias() {
        let form: Form = [
            ("AUTHREQUEST".into(), "".into()),
            ("DEVICE_IDENTIFIER".into(), "opaque\0雪".into()),
            ("CLIENTID".into(), "".into()),
        ]
        .into_iter()
        .collect();
        assert_eq!(form_field(&form, &["authrequest"]), Some(""));
        assert_eq!(
            form_field(&form, &["deviceIdentifier", "device_identifier"]),
            Some("opaque\0雪")
        );
        assert_eq!(form_field(&form, &["clientid", "client_id"]), Some(""));
        assert_eq!(form_field(&form, &["auth_request"]), None);
    }
    #[test]
    fn query_and_jwt_fixture_decoding_keeps_private_opaque_data_out_of_errors() {
        let value = "opaque+ space\0雪&=";
        let query = form_query("code", value).unwrap();
        let url = reqwest::Url::parse(&format!("http://fixture.invalid/?{query}")).unwrap();
        assert_eq!(url.query_pairs().next().unwrap().1, value);
        let payload =
            URL_SAFE_NO_PAD.encode(br#"{"device":"opaque","scope":["api","offline_access"]}"#);
        let claims = jwt_claims(&format!("header.{payload}.signature")).unwrap();
        assert_eq!(claims["device"], "opaque");
        for token in [
            "private-invalid-marker",
            "header.private-invalid-marker.signature",
        ] {
            let error = jwt_claims(token).err().unwrap();
            assert!(!format!("{error} {error:?}").contains("private-invalid-marker"));
        }
    }
    #[test]
    fn private_error_and_receipt_types_never_retain_server_bodies_or_peer_identifiers() {
        let marker = "private-auth-login-marker";
        let error = Reply {
            status: 500,
            bytes: marker.as_bytes().to_vec(),
        }
        .status(200)
        .err()
        .unwrap();
        assert!(!format!("{error} {error:?}").contains(marker));
        let guard = Reply {
            status: 422,
            bytes: format!("<html>{marker}</html>").into_bytes(),
        }
        .token_result(422)
        .unwrap();
        assert!(guard.is_null());
        let error = Reply {
            status: 400,
            bytes: marker.as_bytes().to_vec(),
        }
        .token_result(422)
        .err()
        .unwrap();
        assert!(!format!("{error} {error:?}").contains(marker));
        let error = Reply {
            status: 400,
            bytes: marker.as_bytes().to_vec(),
        }
        .token_result(400)
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
            identity_requests: 43,
            ordinary_password_logins: 2,
            auth_request_logins: 7,
            refresh_requests: 2,
            public_creations: 1,
            public_response_polls: 1,
            max_identity_requests_per_peer: 10,
            max_public_requests_per_peer: 5,
            expiry_wait_seconds: 301,
        };
        let value = serde_json::to_value(receipt).unwrap();
        assert_eq!(value["expiryWaitSeconds"], 301);
        assert!(!value.to_string().contains(marker));
    }
}
