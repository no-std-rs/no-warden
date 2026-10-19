//! Authenticated, read-only credential-list discovery and previous-stamp guards.
//!
//! Vaultwarden 58a980f850464f7d9cdc99a765df36f0a3308b91 core/mod.rs:38,198-207,
//! accounts.rs:634-687 and auth.rs:679-711; release1.37.4 has the same contract.
//! This GET returns an empty list, independently of passkey enrollment APIs.
//! HEAD/OPTIONS and isolated signed-access-JWT expiry remain separate coverage.
//! The real 121-second wait proves previous-stamp expiry using an unmodified JWT.
//! Receipts and diagnostics contain only authored names, statuses and counts.

use crate::fixture;
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

const PATH: &str = "/api/webauthn";
const MAX_REPLY: u64 = 16 * 1024 * 1024;
type Form = BTreeMap<String, String>;
type Case = fn(&mut Suite) -> Result<(), WebauthnCredentialsError>;
const CASES: [(&str, Case); 6] = [
    (
        "webauthn_credentials_authentication_guards",
        authentication_guards,
    ),
    (
        "webauthn_credentials_methods_paths_and_queries",
        methods_paths_and_queries,
    ),
    (
        "webauthn_credentials_exact_read_only_projection",
        exact_read_only_projection,
    ),
    (
        "webauthn_credentials_previous_stamp_and_refresh_authority",
        previous_stamp_and_refresh_authority,
    ),
    (
        "webauthn_credentials_device_recreation_and_owner_isolation",
        device_recreation_and_owner_isolation,
    ),
    (
        "webauthn_credentials_expiry_cleanup_once",
        expiry_cleanup_once,
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WebauthnCredentialsError(&'static str);
impl fmt::Display for WebauthnCredentialsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for WebauthnCredentialsError {}
fn require(value: bool, message: &'static str) -> Result<(), WebauthnCredentialsError> {
    if value {
        Ok(())
    } else {
        Err(WebauthnCredentialsError(message))
    }
}
fn text(value: &Value) -> Result<&str, WebauthnCredentialsError> {
    value.as_str().ok_or(WebauthnCredentialsError(
        "Required credential fixture string missing",
    ))
}
fn exact_list(value: &Value) -> Result<(), WebauthnCredentialsError> {
    require(
        *value == json!({"object":"list","data":[],"continuationToken":null}),
        "Credential list did not match the exact three-field response",
    )
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, WebauthnCredentialsError> {
        if self.status != expected {
            eprintln!(
                "Credential HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Credential HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, WebauthnCredentialsError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| WebauthnCredentialsError("Credential response was not JSON"))
    }
    fn list(self) -> Result<(), WebauthnCredentialsError> {
        exact_list(&self.status(200)?.json()?)
    }
    fn empty(self) -> Result<(), WebauthnCredentialsError> {
        require(
            self.bytes.is_empty(),
            "Credential fixture mutation response was not empty",
        )
    }
    fn rejected(self, expected: u16) -> Result<(), WebauthnCredentialsError> {
        let reply = self.status(expected)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&reply.bytes) {
            require(
                ["access_token", "refresh_token", "apiKey"]
                    .iter()
                    .all(|key| value.get(key).is_none()),
                "Rejected credential response supplied authority",
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
    successful_logins: usize,
    refreshes: usize,
    per_peer: [usize; 2],
}
impl Http {
    fn new() -> Result<Self, WebauthnCredentialsError> {
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
                .map_err(|_| {
                    WebauthnCredentialsError("Credential HTTP client initialization failed")
                })
        };
        Ok(Self {
            server,
            clients: [client(1)?, client(2)?],
            peer: 0,
            requests: 0,
            identities: 0,
            successful_logins: 0,
            refreshes: 0,
            per_peer: [0; 2],
        })
    }
    fn read(response: reqwest::blocking::Response) -> Result<Reply, WebauthnCredentialsError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_REPLY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| WebauthnCredentialsError("Credential response read failed"))?;
        require(
            bytes.len() as u64 <= MAX_REPLY,
            "Credential response exceeded capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn request(
        &mut self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Reply, WebauthnCredentialsError> {
        self.requests += 1;
        let mut request = self.clients[self.peer].request(method, format!("{}{path}", self.server));
        if let Some(token) = bearer {
            request = request.bearer_auth(token);
        }
        if let Some(value) = body {
            request = request.json(value);
        }
        Self::read(
            request
                .send()
                .map_err(|_| WebauthnCredentialsError("Credential HTTP request failed"))?,
        )
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        bearer: &str,
        body: Option<&Value>,
    ) -> Result<Value, WebauthnCredentialsError> {
        self.request(method, path, Some(bearer), body)?
            .status(200)?
            .json()
    }
    fn token(&mut self, form: &Form, expected: u16) -> Result<Value, WebauthnCredentialsError> {
        self.requests += 1;
        self.identities += 1;
        self.per_peer[self.peer] += 1;
        require(
            self.per_peer[self.peer] <= 6,
            "Credential identity peer budget exceeded",
        )?;
        if form
            .get("grant_type")
            .is_some_and(|value| value == "refresh_token")
        {
            self.refreshes += 1;
        }
        let reply = Self::read(
            self.clients[self.peer]
                .post(format!("{}/identity/connect/token", self.server))
                .form(form)
                .send()
                .map_err(|_| WebauthnCredentialsError("Credential identity request failed"))?,
        )?;
        if expected != 200 {
            reply.rejected(expected)?;
            return Ok(Value::Null);
        }
        let value = reply.status(200)?.json()?;
        self.successful_logins += 1;
        Ok(value)
    }
    fn login(
        &mut self,
        fixture: &Value,
        device: &str,
    ) -> Result<Session, WebauthnCredentialsError> {
        let tokens = self.token(
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
                ("deviceName".into(), "Credential fixture".into()),
                ("deviceType".into(), "8".into()),
            ]),
            200,
        )?;
        Ok(Session {
            access: text(&tokens["access_token"])?.into(),
            refresh: tokens["refresh_token"].as_str().map(str::to_owned),
        })
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
    current: Session,
}
#[derive(Clone, PartialEq)]
struct Snapshot {
    profile: Value,
    sync: Value,
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
    expiry_wait_seconds: u64,
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    shared_device: String,
    other_device: String,
    original: Option<Session>,
    api: Option<Session>,
    intermediate: Option<Session>,
    next: Value,
    changed_at: Option<Instant>,
    expiry_wait: u64,
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
    fn receipt(&mut self, status: &'static str) -> Result<(), WebauthnCredentialsError> {
        if let Some(file) = &mut self.receipt {
            let record = Receipt {
                schema_version: 1,
                status,
                cases: &self.passed,
                expected_cases: CASES.len(),
                passed_cases: self.passed.len(),
                http_requests: self.http.requests,
                identity_requests: self.http.identities,
                successful_logins: self.http.successful_logins,
                refresh_requests: self.http.refreshes,
                max_identity_requests_per_peer: *self.http.per_peer.iter().max().unwrap_or(&0),
                fixture_registrations: self.accounts.len(),
                expiry_wait_seconds: self.expiry_wait,
            };
            let bytes = serde_json::to_vec(&record)
                .map_err(|_| WebauthnCredentialsError("Credential receipt encoding failed"))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| WebauthnCredentialsError("Credential receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| WebauthnCredentialsError("Credential receipt update failed"))?;
            file.write_all(&bytes)
                .map_err(|_| WebauthnCredentialsError("Credential receipt write failed"))?;
            file.sync_all()
                .map_err(|_| WebauthnCredentialsError("Credential receipt persistence failed"))?;
        }
        Ok(())
    }
    fn snapshot(&mut self, owner: usize) -> Result<Snapshot, WebauthnCredentialsError> {
        let bearer = self.accounts[owner].current.access.clone();
        let profile = self
            .http
            .json(Method::GET, "/api/accounts/profile", &bearer, None)?;
        let sync = self.http.json(Method::GET, "/api/sync", &bearer, None)?;
        let revision = self
            .http
            .json(Method::GET, "/api/accounts/revision-date", &bearer, None)?
            .as_i64()
            .ok_or(WebauthnCredentialsError(
                "Credential revision was not numeric",
            ))?;
        require(
            sync["profile"] == profile,
            "Credential fixture profile and sync differed",
        )?;
        Ok(Snapshot {
            profile,
            sync,
            revision,
        })
    }
    fn snapshots(&mut self) -> Result<Vec<Snapshot>, WebauthnCredentialsError> {
        (0..2).map(|index| self.snapshot(index)).collect()
    }
    fn list(&mut self, bearer: &str, expected: u16) -> Result<(), WebauthnCredentialsError> {
        let reply = self.http.request(Method::GET, PATH, Some(bearer), None)?;
        if expected == 200 {
            reply.list()
        } else {
            reply.rejected(expected)
        }
    }
    fn public(&mut self, bearer: &str, expected: u16) -> Result<(), WebauthnCredentialsError> {
        let target = &self.accounts[1];
        let reply = self.http.request(
            Method::GET,
            &format!("/api/users/{}/public-key", target.id),
            Some(bearer),
            None,
        )?;
        if expected == 200 {
            require(
                reply.status(200)?.json()?
                    == json!({"userId":target.id,"publicKey":target.fixture["keys"]["publicKey"],"object":"userKey"}),
                "Credential follow-up public-key response differed",
            )
        } else {
            reply.rejected(expected)
        }
    }
    fn live(&self) -> Result<(), WebauthnCredentialsError> {
        require(
            self.changed_at
                .is_some_and(|clock| clock.elapsed() < Duration::from_secs(120)),
            "Credential live-window fixture ran too slowly",
        )
    }
}
fn authentication_guards(s: &mut Suite) -> Result<(), WebauthnCredentialsError> {
    let before = s.snapshots()?;
    for token in [
        None,
        Some("invalid-credential-bearer"),
        Some("eyJhbGciOiJub25lIn0.e30."),
    ] {
        s.http
            .request(Method::GET, PATH, token, None)?
            .rejected(401)?;
    }
    require(
        s.snapshots()? == before,
        "Rejected credential read changed account or vault",
    )
}
fn methods_paths_and_queries(s: &mut Suite) -> Result<(), WebauthnCredentialsError> {
    let before = s.snapshots()?;
    let bearer = s.accounts[0].current.access.clone();
    for path in [
        PATH,
        "/api/webauthn/",
        "/api/webauthn?ignored=true",
        "/api/webauthn/?opaque=%00%E9%9B%AA",
    ] {
        s.http
            .request(Method::GET, path, Some(&bearer), None)?
            .list()?;
    }
    for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
        s.http
            .request(method, PATH, Some(&bearer), None)?
            .rejected(404)?;
    }
    for path in ["/api/Webauthn", "/api/webauthn/extra"] {
        s.http
            .request(Method::GET, path, Some(&bearer), None)?
            .rejected(404)?;
    }
    require(
        s.snapshots()? == before,
        "Credential routing changed account or vault",
    )
}
fn exact_read_only_projection(s: &mut Suite) -> Result<(), WebauthnCredentialsError> {
    let before = s.snapshots()?;
    for owner in 0..2 {
        let token = s.accounts[owner].current.access.clone();
        for _ in 0..3 {
            s.list(&token, 200)?;
        }
        s.http
            .request(
                Method::GET,
                PATH,
                Some(&token),
                Some(&json!({"owner":"untrusted","credentials":["ignored"],"token":"untrusted"})),
            )?
            .list()?;
    }
    require(
        s.snapshots()? == before,
        "Credential list read mutated profile, revision or vault",
    )
}
fn previous_stamp_and_refresh_authority(s: &mut Suite) -> Result<(), WebauthnCredentialsError> {
    let before = s.snapshot(0)?;
    let foreign = s.snapshot(1)?;
    let old = s.accounts[0].current.clone();
    let body = json!({"masterPasswordHash":s.accounts[0].fixture["masterPasswordHash"],"newMasterPasswordHash":s.next["masterPasswordHash"],"key":s.next["key"]});
    s.http
        .request(
            Method::POST,
            "/api/accounts/password",
            Some(&old.access),
            Some(&body),
        )?
        .status(200)?
        .empty()?;
    s.changed_at = Some(Instant::now());
    s.original = Some(old.clone());
    for session in [
        old,
        s.api
            .clone()
            .ok_or(WebauthnCredentialsError("Credential API fixture missing"))?,
    ] {
        s.list(&session.access, 200)?;
        s.public(&session.access, 200)?;
        for path in ["/api/accounts/profile", "/api/sync"] {
            s.http
                .request(Method::GET, path, Some(&session.access), None)?
                .rejected(401)?;
        }
    }
    s.accounts[0].fixture = s.next.clone();
    s.http.peer = 1;
    let current = s.http.login(&s.accounts[0].fixture, &s.shared_device)?;
    s.intermediate = Some(current.clone());
    s.accounts[0].current = current;
    let after = s.snapshot(0)?;
    let mut expected = before;
    require(
        after.revision > expected.revision
            && after.profile["securityStamp"] != expected.profile["securityStamp"],
        "Credential password fixture did not renew stamp and revision",
    )?;
    expected.profile["key"] = s.next["key"].clone();
    expected.profile["securityStamp"] = after.profile["securityStamp"].clone();
    expected.sync["profile"] = expected.profile.clone();
    for key in ["masterKeyEncryptedUserKey", "masterKeyWrappedUserKey"] {
        expected.sync["userDecryption"]["masterPasswordUnlock"][key] = s.next["key"].clone();
    }
    expected.revision = after.revision;
    require(
        after == expected,
        "Credential password fixture altered unrelated vault data",
    )?;
    let refresh = s
        .original
        .as_ref()
        .and_then(|value| value.refresh.clone())
        .ok_or(WebauthnCredentialsError(
            "Credential refresh fixture missing",
        ))?;
    s.http.token(
        &Form::from([
            ("grant_type".into(), "refresh_token".into()),
            ("refresh_token".into(), refresh),
        ]),
        400,
    )?;
    require(
        s.snapshot(1)? == foreign,
        "Credential password fixture changed another owner",
    )?;
    s.live()
}
fn device_recreation_and_owner_isolation(s: &mut Suite) -> Result<(), WebauthnCredentialsError> {
    s.live()?;
    let foreign = s.snapshot(1)?;
    let current = s.accounts[0].current.access.clone();
    s.http
        .request(
            Method::POST,
            "/api/accounts/security-stamp",
            Some(&current),
            Some(&json!({"masterPasswordHash":s.accounts[0].fixture["masterPasswordHash"]})),
        )?
        .status(200)?
        .empty()?;
    let bob = s.accounts[1].current.access.clone();
    let devices = s.http.json(Method::GET, "/api/devices", &bob, None)?;
    require(
        devices["data"]
            .as_array()
            .is_some_and(|rows| rows.iter().any(|row| row["identifier"] == s.shared_device)),
        "Foreign shared device fixture missing",
    )?;
    let old = s.original.clone().ok_or(WebauthnCredentialsError(
        "Credential original session missing",
    ))?;
    s.list(&old.access, 401)?;
    s.accounts[0].current = s.http.login(&s.accounts[0].fixture, &s.other_device)?;
    s.list(&old.access, 401)?;
    s.accounts[0].current = s.http.login(&s.accounts[0].fixture, &s.shared_device)?;
    s.list(&old.access, 200)?;
    let api = s
        .api
        .clone()
        .ok_or(WebauthnCredentialsError("Credential API fixture missing"))?;
    s.list(&api.access, 200)?;
    s.public(&old.access, 200)?;
    let intermediate = s.intermediate.clone().ok_or(WebauthnCredentialsError(
        "Credential intermediate session missing",
    ))?;
    s.list(&intermediate.access, 401)?;
    s.list(&bob, 200)?;
    require(
        s.snapshot(1)? == foreign,
        "Credential device cleanup changed another owner",
    )?;
    s.live()
}
fn expiry_cleanup_once(s: &mut Suite) -> Result<(), WebauthnCredentialsError> {
    let clock = s
        .changed_at
        .ok_or(WebauthnCredentialsError("Credential expiry clock missing"))?;
    while clock.elapsed() < Duration::from_secs(121) {
        thread::sleep(
            Duration::from_secs(121)
                .saturating_sub(clock.elapsed())
                .min(Duration::from_secs(1)),
        );
    }
    s.expiry_wait = clock.elapsed().as_secs();
    let before = s.snapshot(0)?;
    let foreign = s.snapshot(1)?;
    let old = s.original.clone().ok_or(WebauthnCredentialsError(
        "Credential original session missing",
    ))?;
    s.list(&old.access, 401)?;
    let after = s.snapshot(0)?;
    require(
        after.revision > before.revision,
        "Expired credential exception did not advance owner revision",
    )?;
    let mut expected = before;
    expected.revision = after.revision;
    require(
        after == expected,
        "Credential expiry cleanup changed credentials or vault data",
    )?;
    s.list(&old.access, 401)?;
    let api = s
        .api
        .clone()
        .ok_or(WebauthnCredentialsError("Credential API fixture missing"))?;
    s.list(&api.access, 401)?;
    s.public(&old.access, 401)?;
    require(
        s.snapshot(0)? == after,
        "Repeated expired credential bearer repeated cleanup",
    )?;
    let alice = s.accounts[0].current.access.clone();
    let bob = s.accounts[1].current.access.clone();
    s.list(&alice, 200)?;
    s.list(&bob, 200)?;
    require(
        s.snapshot(1)? == foreign,
        "Credential expiry cleanup changed another owner",
    )?;
    let refresh = old.refresh.ok_or(WebauthnCredentialsError(
        "Credential refresh fixture missing",
    ))?;
    s.http.token(
        &Form::from([
            ("grant_type".into(), "refresh_token".into()),
            ("refresh_token".into(), refresh),
        ]),
        400,
    )?;
    require(
        s.http.identities == 8
            && s.http.successful_logins == 6
            && s.http.refreshes == 2
            && s.http.per_peer == [3, 5],
        "Credential identity counts changed",
    )
}
fn seed(http: &mut Http, device: &str) -> Result<Account, WebauthnCredentialsError> {
    let email = format!("webauthn-credentials-{}@example.test", Uuid::new_v4());
    let password = format!("Private-credential-fixture-{}", Uuid::new_v4());
    let fixture = fixture::seed_account(&http.server, &email, &password)
        .map_err(|_| WebauthnCredentialsError("Credential fixture registration failed"))?;
    let current = http.login(&fixture, device)?;
    let profile = http.json(Method::GET, "/api/accounts/profile", &current.access, None)?;
    Ok(Account {
        fixture,
        password,
        id: text(&profile["id"])?.into(),
        current,
    })
}
fn seed_vault(http: &mut Http, account: &Account) -> Result<(), WebauthnCredentialsError> {
    let name = fixture::encrypted_pbkdf2_value(
        &account.fixture,
        &account.password,
        b"Credential fixture note",
    )
    .map_err(|_| WebauthnCredentialsError("Credential encrypted fixture failed"))?;
    let notes = fixture::encrypted_pbkdf2_value(
        &account.fixture,
        &account.password,
        "Preserved note 雪\0".as_bytes(),
    )
    .map_err(|_| WebauthnCredentialsError("Credential encrypted fixture failed"))?;
    let folder = http.json(
        Method::POST,
        "/api/folders",
        &account.current.access,
        Some(&json!({"name":name})),
    )?;
    http.json(Method::POST,"/api/ciphers",&account.current.access,Some(&json!({"type":2,"name":name,"notes":notes,"folderId":folder["id"],"encryptedFor":account.id,"secureNote":{"type":0}})))?;
    Ok(())
}
fn private_receipt() -> Result<Option<fs::File>, WebauthnCredentialsError> {
    let Some(path) = std::env::var_os("BW_WEBAUTHN_CREDENTIALS_RECEIPT") else {
        return Ok(None);
    };
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| WebauthnCredentialsError("Credential private receipt creation failed"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| WebauthnCredentialsError("Credential receipt permissions failed"))?;
    Ok(Some(file))
}
/// Explicit opt-in: six cases, eight identity requests split3/5 across direct
/// peers, and one shared121-second real-time previous-stamp expiry fixture.
/// Registration helper requests are separate from the counted HTTP requests.
pub fn run() -> Result<(), WebauthnCredentialsError> {
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        shared_device: Uuid::new_v4().to_string(),
        other_device: Uuid::new_v4().to_string(),
        original: None,
        api: None,
        intermediate: None,
        next: Value::Null,
        changed_at: None,
        expiry_wait: 0,
        passed: Vec::new(),
        receipt: private_receipt()?,
        finished: false,
    };
    s.receipt("running")?;
    for _ in 0..2 {
        let account = seed(&mut s.http, &s.shared_device)?;
        seed_vault(&mut s.http, &account)?;
        s.accounts.push(account);
    }
    let account = &s.accounts[0];
    let secret = s.http.json(
        Method::POST,
        "/api/accounts/api-key",
        &account.current.access,
        Some(&json!({"masterPasswordHash":account.fixture["masterPasswordHash"]})),
    )?;
    let tokens = s.http.token(
        &Form::from([
            ("grant_type".into(), "client_credentials".into()),
            ("client_id".into(), format!("user.{}", account.id)),
            ("client_secret".into(), text(&secret["apiKey"])?.into()),
            ("scope".into(), "api".into()),
            ("deviceIdentifier".into(), s.shared_device.clone()),
            ("deviceName".into(), "Credential fixture".into()),
            ("deviceType".into(), "8".into()),
        ]),
        200,
    )?;
    require(
        tokens.get("refresh_token").is_none(),
        "Credential API fixture gained refresh authority",
    )?;
    s.api = Some(Session {
        access: text(&tokens["access_token"])?.into(),
        refresh: None,
    });
    s.next = fixture::rewrap_pbkdf2_password(
        &account.fixture,
        &account.password,
        &format!("Changed-private-credential-password-{}", Uuid::new_v4()),
    )
    .map_err(|_| WebauthnCredentialsError("Credential password rewrap failed"))?;
    for (name, case) in CASES {
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
        println!("PASS {name}");
    }
    s.receipt("passed")?;
    s.finished = true;
    println!("PASS webauthn-credentials HTTP cases: {}", s.passed.len());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn credential_projection_rejects_extra_missing_wrong_type_and_secret_fields_without_echo() {
        assert!(exact_list(&json!({"object":"list","data":[],"continuationToken":null})).is_ok());
        for value in [
            json!({"object":"list","data":[]}),
            json!({"object":"list","data":null,"continuationToken":null}),
            json!({"object":"list","data":[{}],"continuationToken":null}),
            json!({"object":"list","data":[],"continuationToken":null,"token":"private-sentinel"}),
        ] {
            let error = exact_list(&value).unwrap_err();
            assert!(!format!("{error:?} {error}").contains("private-sentinel"));
        }
    }
}
