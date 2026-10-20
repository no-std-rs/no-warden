//! Personal cipher GET, details and admin aliases, with disposable accounts.
//!
//! Pinned Vaultwarden ciphers.rs234-255 and release1.37.4 use the same readable
//! cipher authorization and projection. The admin alias adds no admin privilege.
//! UUID syntax is checked after Headers; accepted spellings are not normalized.
//! CoreSyncService's production details call is static evidence, not a claim
//! that the separate official CLI120 regression executes either read alias.
//! Organization sharing, complete errors/transport and notification delivery
//! remain separate contracts. Read-only snapshots permit capability issuance.

use crate::fixture;
use reqwest::{Method, blocking::Client};
use serde::Serialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};
use uuid::Uuid;

const MAX_REPLY: u64 = 32 * 1024 * 1024;
const SUFFIXES: [&str; 3] = ["", "/details", "/admin"];
type Form = BTreeMap<String, String>;
type Case = fn(&mut Suite) -> Result<(), CipherReadsError>;
const CASES: [(&str, Case); 6] = [
    (
        "cipher_reads_authentication_and_uuid_guard_order",
        authentication_and_uuid_guard_order,
    ),
    (
        "cipher_reads_missing_and_foreign_error_contract",
        missing_and_foreign_error_contract,
    ),
    (
        "cipher_reads_active_trash_archive_alias_equivalence",
        active_trash_archive_alias_equivalence,
    ),
    (
        "cipher_reads_get_bodies_queries_and_encoded_ids",
        get_bodies_queries_and_encoded_ids,
    ),
    (
        "cipher_reads_reserved_literals_and_method_guards",
        reserved_literals_and_method_guards,
    ),
    (
        "cipher_reads_readonly_isolation_and_revoked_authority",
        readonly_isolation_and_revoked_authority,
    ),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CipherReadsError(&'static str);
impl fmt::Display for CipherReadsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for CipherReadsError {}
fn require(value: bool, message: &'static str) -> Result<(), CipherReadsError> {
    if value {
        Ok(())
    } else {
        Err(CipherReadsError(message))
    }
}
fn text(value: &Value) -> Result<&str, CipherReadsError> {
    value.as_str().ok_or(CipherReadsError(
        "Required cipher-read fixture string missing",
    ))
}
fn array(value: &Value) -> Result<&[Value], CipherReadsError> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(CipherReadsError("Required cipher-read array missing"))
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, CipherReadsError> {
        if self.status != expected {
            eprintln!(
                "Cipher read HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Cipher read HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, CipherReadsError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| CipherReadsError("Cipher read response was not JSON"))
    }
    fn empty(self) -> Result<(), CipherReadsError> {
        require(
            self.bytes.is_empty(),
            "Cipher read fixture mutation body was not empty",
        )
    }
    fn rejected(self, status: u16) -> Result<(), CipherReadsError> {
        let response = self.status(status)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&response.bytes) {
            require(
                ["access_token", "refresh_token", "id", "name", "notes"]
                    .iter()
                    .all(|key| value.get(key).is_none()),
                "Rejected cipher read exposed authority or cipher contents",
            )?;
        }
        Ok(())
    }
    fn inaccessible(self, message: &'static str) -> Result<(), CipherReadsError> {
        let value = self.status(400)?.json()?;
        require(
            value["message"] == message,
            "Cipher read missing/foreign error message differed",
        )?;
        require(
            ["id", "name", "notes", "attachments"]
                .iter()
                .all(|key| value.get(key).is_none()),
            "Cipher read error exposed inaccessible payload",
        )
    }
}
struct Http {
    server: String,
    client: Client,
    requests: usize,
    identities: usize,
    logins: usize,
    downloads: usize,
}
impl Http {
    fn new() -> Result<Self, CipherReadsError> {
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
            .map_err(|_| CipherReadsError("Cipher read client initialization failed"))?;
        Ok(Self {
            server,
            client,
            requests: 0,
            identities: 0,
            logins: 0,
            downloads: 0,
        })
    }
    fn capture(response: reqwest::blocking::Response) -> Result<Reply, CipherReadsError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_REPLY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| CipherReadsError("Cipher read response capture failed"))?;
        require(
            bytes.len() as u64 <= MAX_REPLY,
            "Cipher read response exceeded private capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn send(
        &mut self,
        method: Method,
        url: &str,
        bearer: Option<&str>,
        body: Option<(&[u8], &str)>,
    ) -> Result<Reply, CipherReadsError> {
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
        Self::capture(
            request
                .send()
                .map_err(|_| CipherReadsError("Cipher read HTTP request failed"))?,
        )
    }
    fn raw(
        &mut self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Reply, CipherReadsError> {
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
    ) -> Result<Value, CipherReadsError> {
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
    fn login(&mut self, fixture: &Value, device: &str) -> Result<String, CipherReadsError> {
        self.requests += 1;
        self.identities += 1;
        require(
            self.identities <= 6,
            "Cipher read identity peer budget exceeded",
        )?;
        let form = Form::from([
            ("grant_type".into(), "password".into()),
            ("client_id".into(), "cli".into()),
            ("scope".into(), "api offline_access".into()),
            ("username".into(), text(&fixture["email"])?.into()),
            (
                "password".into(),
                text(&fixture["masterPasswordHash"])?.into(),
            ),
            ("deviceIdentifier".into(), device.into()),
            ("deviceName".into(), "Disposable cipher read fixture".into()),
            ("deviceType".into(), "8".into()),
        ]);
        let response = Self::capture(
            self.client
                .post(format!("{}/identity/connect/token", self.server))
                .form(&form)
                .send()
                .map_err(|_| CipherReadsError("Cipher read fixture identity request failed"))?,
        )?
        .status(200)?
        .json()?;
        self.logins += 1;
        Ok(text(&response["access_token"])?.into())
    }
    fn download(&mut self, url: &str, expected: &[u8]) -> Result<(), CipherReadsError> {
        let target = reqwest::Url::parse(url)
            .map_err(|_| CipherReadsError("Cipher read capability URL invalid"))?;
        let server = reqwest::Url::parse(&self.server)
            .map_err(|_| CipherReadsError("Cipher read fixture origin invalid"))?;
        require(
            target.origin() == server.origin() && target.path().starts_with("/attachments/"),
            "Cipher read capability escaped fixture origin",
        )?;
        self.downloads += 1;
        let response = self.send(Method::GET, url, None, None)?.status(200)?;
        require(
            response.bytes == expected,
            "Cipher read attachment bytes differed",
        )
    }
}
struct Account {
    fixture: Value,
    password: String,
    id: String,
    device: String,
    access: String,
    encrypted_name: String,
    encrypted_attachment_key: String,
}
struct Cipher {
    owner: usize,
    id: String,
    payload: Value,
    attachment: Option<(String, Vec<u8>)>,
}
#[derive(Clone, PartialEq)]
struct Snapshot {
    sync: Value,
    revision: Value,
    keys: Value,
    domains: Value,
    devices: Value,
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
    max_identity_requests_per_peer: usize,
    fixture_registrations: usize,
    attachment_download_checks: usize,
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    ciphers: Vec<Cipher>,
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
fn normalize_cipher(cipher: &mut Value) -> Result<(), CipherReadsError> {
    if let Some(attachments) = cipher["attachments"].as_array_mut() {
        for attachment in attachments {
            let mut url = reqwest::Url::parse(text(&attachment["url"])?)
                .map_err(|_| CipherReadsError("Cipher read snapshot capability URL invalid"))?;
            url.set_query(None);
            attachment["url"] = json!(url.to_string());
        }
    }
    Ok(())
}
impl Suite {
    fn receipt(&mut self, status: &'static str) -> Result<(), CipherReadsError> {
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
                max_identity_requests_per_peer: self.http.identities,
                fixture_registrations: self.accounts.len(),
                attachment_download_checks: self.http.downloads,
            };
            let bytes = serde_json::to_vec(&record)
                .map_err(|_| CipherReadsError("Cipher read receipt encoding failed"))?;
            file.seek(SeekFrom::Start(0))
                .map_err(|_| CipherReadsError("Cipher read receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| CipherReadsError("Cipher read receipt update failed"))?;
            file.write_all(&bytes)
                .map_err(|_| CipherReadsError("Cipher read receipt write failed"))?;
            file.sync_all()
                .map_err(|_| CipherReadsError("Cipher read receipt persistence failed"))?;
        }
        Ok(())
    }
    fn snapshot(&mut self, owner: usize) -> Result<Snapshot, CipherReadsError> {
        let token = self.accounts[owner].access.clone();
        let mut sync = self.http.json(Method::GET, "/api/sync", &token, None)?;
        for cipher in sync["ciphers"]
            .as_array_mut()
            .ok_or(CipherReadsError("Cipher read sync ciphers missing"))?
        {
            normalize_cipher(cipher)?;
        }
        Ok(Snapshot {
            sync,
            revision: self
                .http
                .json(Method::GET, "/api/accounts/revision-date", &token, None)?,
            keys: self
                .http
                .json(Method::GET, "/api/accounts/keys", &token, None)?,
            domains: self
                .http
                .json(Method::GET, "/api/settings/domains", &token, None)?,
            devices: self.http.json(Method::GET, "/api/devices", &token, None)?,
        })
    }
    fn snapshots(&mut self) -> Result<Vec<Snapshot>, CipherReadsError> {
        (0..2).map(|owner| self.snapshot(owner)).collect()
    }
    fn read(&mut self, index: usize, suffix: &str) -> Result<Value, CipherReadsError> {
        let cipher = &self.ciphers[index];
        let document = self.http.json(
            Method::GET,
            &format!("/api/ciphers/{}{suffix}", cipher.id),
            &self.accounts[cipher.owner].access,
            None,
        )?;
        self.check_document(index, document)
    }
    fn check_document(
        &mut self,
        index: usize,
        mut document: Value,
    ) -> Result<Value, CipherReadsError> {
        let cipher = &self.ciphers[index];
        require(
            document["id"] == cipher.id && document["object"] == "cipherDetails",
            "Cipher read identity/object projection differed",
        )?;
        for field in ["type", "name", "notes", "fields", "favorite", "reprompt"] {
            require(
                document[field] == cipher.payload[field],
                "Cipher read changed opaque fixture fields",
            )?;
        }
        require(
            document["login"]["futureOpaque"] == cipher.payload["login"]["futureOpaque"]
                && document["login"]["username"] == cipher.payload["login"]["username"]
                && document["login"]["password"] == cipher.payload["login"]["password"],
            "Cipher read changed opaque nested login payload",
        )?;
        require(
            text(&document["creationDate"]).is_ok() && text(&document["revisionDate"]).is_ok(),
            "Cipher read revision fields missing",
        )?;
        if let Some((id, bytes)) = &cipher.attachment {
            let attachments = array(&document["attachments"])?;
            require(
                attachments.len() == 1 && attachments[0]["id"] == *id,
                "Cipher read attachment projection differed",
            )?;
            self.http.download(text(&attachments[0]["url"])?, bytes)?;
        }
        normalize_cipher(&mut document)?;
        Ok(document)
    }
}
fn path(id: &str, suffix: &str) -> String {
    format!("/api/ciphers/{id}{suffix}")
}
fn authentication_and_uuid_guard_order(s: &mut Suite) -> Result<(), CipherReadsError> {
    let before = s.snapshots()?;
    let token = s.accounts[0].access.clone();
    for suffix in SUFFIXES {
        for id in [s.ciphers[0].id.as_str(), "not-a-uuid", "%2F", "%00"] {
            for bearer in [None, Some("invalid-cipher-read-bearer")] {
                s.http
                    .raw(Method::GET, &path(id, suffix), bearer, None)?
                    .rejected(401)?;
            }
        }
        for id in ["not-a-uuid", "%2F", "%00", "%E9%9B%AA"] {
            s.http
                .raw(Method::GET, &path(id, suffix), Some(&token), None)?
                .rejected(422)?;
        }
    }
    require(
        s.snapshots()? == before,
        "Cipher read authentication/UUID failures changed vault or revisions",
    )
}
fn missing_and_foreign_error_contract(s: &mut Suite) -> Result<(), CipherReadsError> {
    let before = s.snapshots()?;
    let token = s.accounts[0].access.clone();
    let own = &s.ciphers[0].id;
    let missing = Uuid::new_v4().to_string();
    let foreign = &s.ciphers[3].id;
    for suffix in SUFFIXES {
        for id in [
            &missing,
            &format!("%7B{own}%7D"),
            &own.replace('-', ""),
            &format!("urn:uuid:{own}"),
        ] {
            s.http
                .raw(Method::GET, &path(id, suffix), Some(&token), None)?
                .inaccessible("Cipher doesn't exist")?;
        }
        s.http
            .raw(Method::GET, &path(foreign, suffix), Some(&token), None)?
            .inaccessible("Cipher is not owned by user")?;
    }
    require(
        s.snapshots()? == before,
        "Missing/foreign cipher reads changed vault or revisions",
    )
}
fn active_trash_archive_alias_equivalence(s: &mut Suite) -> Result<(), CipherReadsError> {
    let before = s.snapshots()?;
    for index in 0..s.ciphers.len() {
        let ordinary = s.read(index, "")?;
        require(
            s.read(index, "/details")? == ordinary && s.read(index, "/admin")? == ordinary,
            "Cipher GET/details/admin responses differed",
        )?;
        if index == 1 {
            require(
                ordinary["deletedDate"].is_string(),
                "Cipher read trash fixture missing",
            )?;
        }
        if index == 2 {
            require(
                ordinary["archivedDate"].is_string(),
                "Cipher read archive fixture missing",
            )?;
        }
    }
    require(
        s.snapshots()? == before,
        "Cipher read aliases changed encrypted vault or account revision",
    )
}
fn get_bodies_queries_and_encoded_ids(s: &mut Suite) -> Result<(), CipherReadsError> {
    let before = s.snapshots()?;
    let token = s.accounts[0].access.clone();
    let id = s.ciphers[0].id.clone();
    let encoded = format!("%{:02X}{}", id.as_bytes()[0], &id[1..]);
    let doubled = id.replace('-', "%252D");
    let expected = s.read(0, "")?;
    for suffix in SUFFIXES {
        for query in [
            "?organizationId=invalid",
            "?id=foreign&admin=true&userId=another",
            "?ignored=first&ignored=second",
        ] {
            let document = s
                .http
                .raw(
                    Method::GET,
                    &format!("{}{query}", path(&id, suffix)),
                    Some(&token),
                    Some(b"{"),
                )?
                .status(200)?
                .json()?;
            require(
                s.check_document(0, document)? == expected,
                "GET query or ignored malformed body changed cipher response",
            )?;
        }
        for route in [path(&encoded, suffix), format!("{}/", path(&id, suffix))] {
            let document = s
                .http
                .raw(
                    Method::GET,
                    &route,
                    Some(&token),
                    Some(br#"{"owner":"ignored","name":"ignored"}"#),
                )?
                .status(200)?
                .json()?;
            require(
                s.check_document(0, document)? == expected,
                "Encoded/trailing cipher GET changed response",
            )?;
        }
        s.http
            .raw(Method::GET, &path(&doubled, suffix), Some(&token), None)?
            .rejected(422)?;
    }
    require(
        s.snapshots()? == before,
        "Cipher GET bodies/queries changed vault or revisions",
    )
}
fn reserved_literals_and_method_guards(s: &mut Suite) -> Result<(), CipherReadsError> {
    let before = s.snapshots()?;
    let token = s.accounts[0].access.clone();
    for literal in [
        "create",
        "import",
        "purge",
        "admin",
        "delete",
        "delete-admin",
        "restore",
        "restore-admin",
        "archive",
        "unarchive",
        "details",
    ] {
        let route = path(literal, "");
        s.http.raw(Method::GET, &route, None, None)?.rejected(401)?;
        s.http
            .raw(Method::GET, &route, Some(&token), None)?
            .rejected(422)?;
    }
    let own = &s.ciphers[0].id;
    for suffix in SUFFIXES {
        s.http
            .raw(Method::PATCH, &path(own, suffix), Some(&token), None)?
            .rejected(404)?;
    }
    for method in [Method::POST, Method::PUT, Method::DELETE] {
        s.http
            .raw(method, &path(own, "/details"), Some(&token), Some(b"{"))?
            .rejected(404)?;
    }
    require(
        s.snapshots()? == before,
        "Read-only reserved path/method probes changed vault or revisions",
    )
}
fn readonly_isolation_and_revoked_authority(s: &mut Suite) -> Result<(), CipherReadsError> {
    let foreign = s.snapshot(1)?;
    let old = s.accounts[0].access.clone();
    s.http
        .raw(
            Method::POST,
            "/api/accounts/security-stamp",
            Some(&old),
            Some(
                json!({"masterPasswordHash":s.accounts[0].fixture["masterPasswordHash"]})
                    .to_string()
                    .as_bytes(),
            ),
        )?
        .status(200)?
        .empty()?;
    s.accounts[0].access = s
        .http
        .login(&s.accounts[0].fixture, &s.accounts[0].device)?;
    let before = s.snapshots()?;
    for suffix in SUFFIXES {
        for id in [s.ciphers[0].id.as_str(), "not-a-uuid"] {
            s.http
                .raw(Method::GET, &path(id, suffix), Some(&old), None)?
                .rejected(401)?;
        }
        s.read(0, suffix)?;
    }
    require(
        s.snapshots()? == before,
        "Revoked-device cipher read changed vault or revisions",
    )?;
    let old = s.accounts[0].access.clone();
    let password = format!("Changed-cipher-read-fixture-{}", Uuid::new_v4());
    let next =
        fixture::rewrap_pbkdf2_password(&s.accounts[0].fixture, &s.accounts[0].password, &password)
            .map_err(|_| CipherReadsError("Cipher read credential fixture rewrap failed"))?;
    let body = json!({"masterPasswordHash":s.accounts[0].fixture["masterPasswordHash"],"newMasterPasswordHash":next["masterPasswordHash"],"key":next["key"]});
    s.http
        .raw(
            Method::POST,
            "/api/accounts/password",
            Some(&old),
            Some(body.to_string().as_bytes()),
        )?
        .status(200)?
        .empty()?;
    s.accounts[0].fixture = next;
    s.accounts[0].password = password;
    s.accounts[0].access = s
        .http
        .login(&s.accounts[0].fixture, &s.accounts[0].device)?;
    // Establish that this signed bearer still qualifies for an allowed exception,
    // while all three cipher read handler names remain outside that allowlist.
    s.http.json(
        Method::GET,
        &format!("/api/users/{}/public-key", s.accounts[0].id),
        &old,
        None,
    )?;
    let before = s.snapshots()?;
    for suffix in SUFFIXES {
        for id in [s.ciphers[0].id.as_str(), "not-a-uuid"] {
            s.http
                .raw(Method::GET, &path(id, suffix), Some(&old), None)?
                .rejected(401)?;
        }
        s.read(0, suffix)?;
    }
    require(
        s.snapshots()? == before && s.snapshot(1)? == foreign,
        "Previous-stamp cipher reads changed owned/foreign vault or revisions",
    )?;
    require(
        s.http.identities == 4 && s.http.logins == 4,
        "Cipher read identity counts differed",
    )?;
    // Finish the existing lifecycle fixture only after every read-only snapshot
    // assertion. Actual web-client comparison exposed a successful 204 that the
    // CLI accepted, while the pinned reference returns an empty 200.
    let token = s.accounts[0].access.clone();
    let id = s.ciphers[1].id.clone();
    s.http
        .raw(Method::DELETE, &path(&id, ""), Some(&token), None)?
        .status(200)?
        .empty()?;
    s.http
        .raw(Method::GET, &path(&id, ""), Some(&token), None)?
        .inaccessible("Cipher doesn't exist")
}
fn seed_account(http: &mut Http) -> Result<Account, CipherReadsError> {
    let email = format!("cipher-reads-{}@example.test", Uuid::new_v4());
    let password = format!("Private-cipher-read-fixture-{}", Uuid::new_v4());
    let fixture = fixture::seed_account(&http.server, &email, &password)
        .map_err(|_| CipherReadsError("Cipher read fixture registration failed"))?;
    let encrypted_name =
        fixture::encrypted_pbkdf2_value(&fixture, &password, b"Opaque cipher read fixture")
            .map_err(|_| CipherReadsError("Cipher read encrypted field fixture failed"))?;
    let encrypted_attachment_key =
        fixture::encrypted_pbkdf2_value(&fixture, &password, &[0x42; 64])
            .map_err(|_| CipherReadsError("Cipher read attachment key fixture failed"))?;
    let device = Uuid::new_v4().to_string();
    let access = http.login(&fixture, &device)?;
    let profile = http.json(Method::GET, "/api/accounts/profile", &access, None)?;
    Ok(Account {
        fixture,
        password,
        id: text(&profile["id"])?.into(),
        device,
        access,
        encrypted_name,
        encrypted_attachment_key,
    })
}
fn seed_cipher(
    http: &mut Http,
    account: &Account,
    owner: usize,
    index: usize,
) -> Result<Cipher, CipherReadsError> {
    let encrypted = &account.encrypted_name;
    let payload = json!({"encryptedFor":account.id,"type":1,"name":encrypted,"notes":encrypted,"favorite":true,"reprompt":1,
        "fields":[{"type":1,"name":encrypted,"value":encrypted,"linkedId":null,"futureOpaque":{"nul":"雪\0","url":"https://opaque.invalid/?token=preserve-this-query"}}],
        "login":{"username":encrypted,"password":encrypted,"uris":[{"uri":encrypted,"match":null}],"futureOpaque":{"array":[null,true,7,"雪\0"],"url":"https://opaque.invalid/?token=preserve-this-query"}}});
    let created = http.json(
        Method::POST,
        "/api/ciphers",
        &account.access,
        Some(&payload),
    )?;
    let id = text(&created["id"])?.to_owned();
    let bytes: Vec<u8> = (0..=255).chain([0, 13, 10, 255]).collect();
    let reserve = http.json(Method::POST, &format!("/api/ciphers/{id}/attachment/v2"), &account.access, Some(&json!({"fileName":encrypted,"key":account.encrypted_attachment_key,"fileSize":bytes.len()})))?;
    require(
        reserve["fileUploadType"] == 0,
        "Cipher read attachment fixture was not direct upload",
    )?;
    let attachment_id = text(&reserve["attachmentId"])?;
    let boundary = format!("cipher-read-{}", Uuid::new_v4());
    let mut multipart = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"data\"; filename=\"opaque.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n").into_bytes();
    multipart.extend_from_slice(&bytes);
    multipart.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    http.send(
        Method::POST,
        &format!(
            "{}/api/ciphers/{id}/attachment/{attachment_id}",
            http.server
        ),
        Some(&account.access),
        Some((
            &multipart,
            &format!("multipart/form-data; boundary={boundary}"),
        )),
    )?
    .status(200)?
    .empty()?;
    if owner == 0 && index > 0 {
        let action = if index == 1 { "delete" } else { "archive" };
        let response = http.raw(
            Method::PUT,
            &format!("/api/ciphers/{id}/{action}"),
            Some(&account.access),
            None,
        )?;
        if index == 1 {
            response.status(200)?.empty()?;
        } else {
            require(
                (200..300).contains(&response.status),
                "Cipher read lifecycle fixture preparation failed",
            )?;
        }
    }
    Ok(Cipher {
        owner,
        id,
        payload,
        attachment: Some((attachment_id.into(), bytes)),
    })
}
fn private_receipt() -> Result<Option<fs::File>, CipherReadsError> {
    let Some(path) = std::env::var_os("BW_CIPHER_READS_RECEIPT") else {
        return Ok(None);
    };
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|_| CipherReadsError("Cipher read private receipt creation failed"))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))
        .map_err(|_| CipherReadsError("Cipher read receipt permissions failed"))?;
    Ok(Some(file))
}
/// Six independent opt-in cases and four identity requests per direct peer.
/// Fixture helper registration requests are counted separately.
pub fn run() -> Result<(), CipherReadsError> {
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        ciphers: Vec::new(),
        passed: Vec::new(),
        receipt: private_receipt()?,
        finished: false,
    };
    s.receipt("running")?;
    for owner in 0..2 {
        let account = seed_account(&mut s.http)?;
        for index in 0..if owner == 0 { 3 } else { 1 } {
            s.ciphers
                .push(seed_cipher(&mut s.http, &account, owner, index)?);
        }
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
    println!("PASS cipher-reads HTTP cases: {}", s.passed.len());
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn capability_normalization_preserves_opaque_payload_queries_and_fields() {
        let mut document = json!({"login":{"futureOpaque":{"url":"https://opaque.invalid/?token=preserve"}},"attachments":[{"id":"attachment","url":"http://127.0.0.1/attachments/cipher/file?token=private","key":"opaque-key"}]});
        normalize_cipher(&mut document).unwrap();
        assert!(
            document["login"]["futureOpaque"]["url"] == "https://opaque.invalid/?token=preserve"
        );
        assert!(
            document["attachments"][0]["url"] == "http://127.0.0.1/attachments/cipher/file"
                && document["attachments"][0]["key"] == "opaque-key"
        );
    }
    #[test]
    fn cipher_read_diagnostics_discard_private_response_material() {
        let error = Reply {
            status: 200,
            bytes: b"private-cipher-token-key".to_vec(),
        }
        .json()
        .unwrap_err();
        assert!(!format!("{error:?} {error}").contains("private-cipher"));
        assert!(
            Reply {
                status: 401,
                bytes: br#"{"name":"private-cipher"}"#.to_vec()
            }
            .rejected(401)
            .is_err()
        );
    }
}
