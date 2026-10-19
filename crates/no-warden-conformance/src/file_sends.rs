//! Independently authored MIT/Apache-2.0 portable tests of file Send protocol facts.
//! Ciphertext is opaque to the server; fixtures authenticate file bytes before
//! decryption. Existing URL capabilities intentionally outlive later policy changes.
//! No upstream implementation is incorporated. Live expiry, large quota policy,
//! object storage and notification delivery are outside this bounded selection.
use crate::{
    fixture,
    text_sends::{
        TextSendsError as Error, future_date, http_client, receipt_file, require, server, text,
        write_receipt,
    },
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::{RngCore, rngs::OsRng};
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use std::{
    fs,
    io::Read,
    time::{Duration, Instant},
};
use uuid::Uuid;

pub const CASE_COUNT: usize = 6;
const MAX_REPLY: u64 = 16 * 1024 * 1024;
pub(crate) const FILE_NAME: &str = "Send fixture 雪.bin";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    (
        "file_sends_reservation_schema_and_owner_guards",
        reservation_guards,
    ),
    (
        "file_sends_upload_filename_length_and_identity_guards",
        upload_guards,
    ),
    (
        "file_sends_recipient_file_bytes_and_download_counts",
        recipient_bytes,
    ),
    (
        "file_sends_owner_edits_sync_and_foreign_isolation",
        owner_edits,
    ),
    (
        "file_sends_availability_limits_and_existing_urls",
        availability,
    ),
    (
        "file_sends_delete_revokes_bytes_and_preserves_foreign_vault",
        delete_and_isolate,
    ),
];
pub(crate) fn payload() -> Vec<u8> {
    (0..131_123).map(|i| ((i * 31) % 256) as u8).collect()
}
fn array(v: &Value) -> Result<&[Value], Error> {
    v.as_array()
        .map(Vec::as_slice)
        .ok_or(Error("File Send array missing"))
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, Error> {
        if self.status != expected {
            eprintln!(
                "File Send HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "File Send HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, Error> {
        serde_json::from_slice(&self.bytes).map_err(|_| Error("File Send response was not JSON"))
    }
    fn rejected(self, status: u16) -> Result<(), Error> {
        let reply = self.status(status)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&reply.bytes) {
            require(
                ["access_token", "refresh_token", "key", "file", "url"]
                    .iter()
                    .all(|k| value.get(k).is_none()),
                "Rejected file Send response exposed authority",
            )?;
        }
        Ok(())
    }
    fn empty(self) -> Result<(), Error> {
        require(
            self.status(200)?.bytes.is_empty(),
            "File Send success body was not empty",
        )
    }
}
struct Http {
    server: String,
    client: Client,
    requests: usize,
    logins: usize,
    grants: usize,
    uploads: usize,
    url_requests: usize,
    downloads: usize,
}
impl Http {
    fn new() -> Result<Self, Error> {
        Ok(Self {
            server: server(),
            client: http_client()?,
            requests: 0,
            logins: 0,
            grants: 0,
            uploads: 0,
            url_requests: 0,
            downloads: 0,
        })
    }
    fn capture(response: reqwest::blocking::Response) -> Result<Reply, Error> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_REPLY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("File Send private capture failed"))?;
        require(
            bytes.len() as u64 <= MAX_REPLY,
            "File Send capture exceeded limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn request(
        &mut self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Reply, Error> {
        self.requests += 1;
        if method == Method::POST && path.starts_with("/api/sends/access/file/") {
            self.url_requests += 1;
        }
        let mut r = self
            .client
            .request(method, format!("{}{path}", self.server));
        if let Some(t) = token {
            r = r.bearer_auth(t);
        }
        if let Some(b) = body {
            r = r.json(b);
        }
        Self::capture(
            r.send()
                .map_err(|_| Error("File Send HTTP request failed"))?,
        )
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        self.request(method, path, Some(token), body)?
            .status(200)?
            .json()
    }
    fn login(&mut self, fixture: &Value) -> Result<String, Error> {
        self.requests += 1;
        self.logins += 1;
        require(self.logins <= 2, "File Send login budget exceeded")?;
        let form = [
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("username", text(&fixture["email"])?),
            ("password", text(&fixture["masterPasswordHash"])?),
            ("deviceIdentifier", "file-sends-browser"),
            ("deviceName", "File Send fixture browser"),
            ("deviceType", "8"),
        ];
        let v = Self::capture(
            self.client
                .post(format!("{}/identity/connect/token", self.server))
                .form(&form)
                .send()
                .map_err(|_| Error("File Send fixture login failed"))?,
        )?
        .status(200)?
        .json()?;
        Ok(text(&v["access_token"])?.into())
    }
    fn grant(&mut self, access_id: &str) -> Result<Reply, Error> {
        self.requests += 1;
        self.grants += 1;
        require(self.grants <= 20, "File Send public grant budget exceeded")?;
        Self::capture(
            self.client
                .post(format!("{}/identity/connect/token", self.server))
                .form(&[
                    ("grant_type", "send_access"),
                    ("client_id", "send"),
                    ("scope", "api.send.access"),
                    ("send_id", access_id),
                ])
                .send()
                .map_err(|_| Error("File Send capability mint failed"))?,
        )
    }
    fn capability(&mut self, access_id: &str) -> Result<String, Error> {
        let v = self.grant(access_id)?.status(200)?.json()?;
        require(
            v.as_object().is_some_and(|o| o.len() == 4)
                && v["scope"] == "api.send.access"
                && v["token_type"] == "Bearer",
            "File Send capability projection differed",
        )?;
        Ok(text(&v["access_token"])?.into())
    }
    fn upload(
        &mut self,
        path: &str,
        token: Option<&str>,
        name: Option<&str>,
        bytes: &[u8],
        field: &str,
    ) -> Result<Reply, Error> {
        self.requests += 1;
        self.uploads += 1;
        let boundary = format!("no-warden-file-send-{}", Uuid::new_v4());
        let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{field}\"")
            .into_bytes();
        if let Some(name) = name {
            require(
                !name.contains(['\r', '\n', '"']),
                "Unsafe synthetic multipart filename",
            )?;
            body.extend_from_slice(format!("; filename=\"{name}\"").as_bytes());
        }
        body.extend_from_slice(b"\r\nContent-Type: application/octet-stream\r\n\r\n");
        body.extend_from_slice(bytes);
        body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
        let mut r = self
            .client
            .post(format!("{}{path}", self.server))
            .header(
                "Content-Type",
                format!("multipart/form-data; boundary={boundary}"),
            )
            .body(body);
        if let Some(token) = token {
            r = r.bearer_auth(token);
        }
        Self::capture(
            r.send()
                .map_err(|_| Error("File Send multipart request failed"))?,
        )
    }
    fn download(&mut self, url: &str) -> Result<Reply, Error> {
        let target =
            reqwest::Url::parse(url).map_err(|_| Error("File Send download URL invalid"))?;
        let origin =
            reqwest::Url::parse(&self.server).map_err(|_| Error("File Send server URL invalid"))?;
        require(
            target.origin() == origin.origin() && target.path().starts_with("/api/sends/"),
            "File Send capability crossed allowed origin or path",
        )?;
        self.requests += 1;
        self.downloads += 1;
        Self::capture(
            self.client
                .get(target)
                .send()
                .map_err(|_| Error("File Send byte download failed"))?,
        )
    }
}
struct FileFixture {
    seed: [u8; 16],
    user_key: [u8; 64],
    key: [u8; 64],
    plaintext: Vec<u8>,
    blob: Vec<u8>,
    body: Value,
}
impl FileFixture {
    fn new(account: &Value, password: &str, plaintext: Vec<u8>) -> Result<Self, Error> {
        let mut seed = [0; 16];
        OsRng
            .try_fill_bytes(&mut seed)
            .map_err(|_| Error("File Send seed generation failed"))?;
        let key = fixture::send_key(&seed);
        let user_key = fixture::pbkdf2_fixture_user_key(account, password)
            .map_err(|_| Error("File Send account key unwrap failed"))?;
        let blob = fixture::encrypt_file(&plaintext, &key)
            .map_err(|_| Error("File Send blob encryption failed"))?;
        let wrap = fixture::encrypted_pbkdf2_value(account, password, &seed)
            .map_err(|_| Error("File Send seed wrapping failed"))?;
        let enc = |v: &[u8]| {
            fixture::encrypt(v, &key).map_err(|_| Error("File Send field encryption failed"))
        };
        let body = json!({"type":1,"key":wrap,"name":enc(b"File Send private name")?,"notes":enc(b"Owner-only file notes\0")?,"file":{"fileName":enc(FILE_NAME.as_bytes())?},"fileLength":blob.len(),"password":null,"maxAccessCount":null,"expirationDate":null,"deletionDate":future_date(1)?,"disabled":false,"hideEmail":false,"emails":null});
        Ok(Self {
            seed,
            user_key,
            key,
            plaintext,
            blob,
            body,
        })
    }
    fn check_bytes(&self, bytes: &[u8]) -> Result<(), Error> {
        require(
            bytes == self.blob,
            "Stored file Send encrypted bytes changed",
        )?;
        require(
            fixture::decrypt_file(bytes, &self.key).is_ok_and(|p| p == self.plaintext),
            "File Send bytes failed authenticated decryption",
        )
    }
    fn check_filename(&self, value: &Value) -> Result<(), Error> {
        require(
            fixture::decrypt(text(&value["file"]["fileName"])?, &self.key)
                .is_ok_and(|p| p == FILE_NAME.as_bytes()),
            "File Send filename failed authenticated decryption",
        )
    }
}
struct Account {
    token: String,
    id: String,
    access_id: String,
    file_id: String,
    upload_path: String,
    file: FileFixture,
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    vault: Vec<Value>,
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
    fn receipt(&mut self, status: &str) -> Result<(), Error> {
        write_receipt(
            &mut self.receipt,
            &json!({"schemaVersion":1,"status":status,"cases":self.passed,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"httpRequests":self.http.requests,"passwordCredentialAttempts":self.http.logins,"sendAccessGrantRequests":self.http.grants,"multipartUploadRequests":self.http.uploads,"fileDownloadUrlRequests":self.http.url_requests,"fileByteGetRequests":self.http.downloads,"fixtureRegistrations":self.accounts.len()}),
        )
    }
    fn owner(&mut self, i: usize) -> Result<Value, Error> {
        let a = &self.accounts[i];
        self.http
            .json(Method::GET, &format!("/api/sends/{}", a.id), &a.token, None)
    }
    fn revision(&mut self, i: usize) -> Result<Value, Error> {
        let a = &self.accounts[i];
        self.http
            .json(Method::GET, "/api/accounts/revision-date", &a.token, None)
    }
    fn update(&mut self, i: usize, body: &Value) -> Result<Value, Error> {
        let a = &self.accounts[i];
        self.http.json(
            Method::PUT,
            &format!("/api/sends/{}", a.id),
            &a.token,
            Some(body),
        )
    }
    fn metadata(&mut self, cap: &str) -> Result<Value, Error> {
        self.http.json(Method::POST, "/api/sends/access", cap, None)
    }
    fn url(&mut self, i: usize, cap: &str) -> Result<String, Error> {
        let a = &self.accounts[i];
        let path = format!("/api/sends/access/file/{}", a.file_id);
        let v = self.http.json(Method::POST, &path, cap, None)?;
        require(
            v.as_object().is_some_and(|o| o.len() == 3)
                && v["object"] == "send-fileDownload"
                && v["id"] == a.file_id,
            "File Send download metadata projection differed",
        )?;
        let url = text(&v["url"])?;
        let parsed = reqwest::Url::parse(url).map_err(|_| Error("File Send URL shape invalid"))?;
        require(
            parsed.path() == format!("/api/sends/{}/{}", a.id, a.file_id),
            "File Send URL selected a different resource",
        )?;
        let token = parsed
            .query_pairs()
            .find(|(k, _)| k == "t")
            .map(|(_, v)| v.into_owned())
            .ok_or(Error("File Send URL omitted capability"))?;
        let fields = token.split('.').collect::<Vec<_>>();
        require(fields.len() == 3, "File Send URL token shape invalid")?;
        let claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(fields[1])
                .map_err(|_| Error("File Send URL claims encoding invalid"))?,
        )
        .map_err(|_| Error("File Send URL claims invalid"))?;
        let origin = reqwest::Url::parse(&self.http.server)
            .map_err(|_| Error("File Send origin invalid"))?
            .origin()
            .ascii_serialization();
        require(
            claims["sub"] == format!("{}/{}", a.id, a.file_id)
                && claims["iss"] == format!("{origin}|send")
                && claims["exp"]
                    .as_i64()
                    .zip(claims["nbf"].as_i64())
                    .is_some_and(|(e, n)| e - n == 120),
            "File Send URL capability purpose differed",
        )?;
        Ok(url.into())
    }
    fn vault(&mut self, i: usize) -> Result<Value, Error> {
        let token = self.accounts[i].token.clone();
        let mut sync = self.http.json(Method::GET, "/api/sync", &token, None)?;
        sync.as_object_mut()
            .ok_or(Error("File Send sync missing"))?
            .remove("sends");
        let keys = self
            .http
            .json(Method::GET, "/api/accounts/keys", &token, None)?;
        let devices = self.http.json(Method::GET, "/api/devices", &token, None)?;
        Ok(json!({"sync":sync,"keys":keys,"devices":devices}))
    }
}
fn owner_shape(v: &Value, length: usize) -> Result<(), Error> {
    let expected_size = length.to_string();
    const FIELDS: [&str; 18] = [
        "id",
        "accessId",
        "type",
        "name",
        "notes",
        "text",
        "file",
        "key",
        "maxAccessCount",
        "accessCount",
        "password",
        "authType",
        "disabled",
        "hideEmail",
        "revisionDate",
        "expirationDate",
        "deletionDate",
        "object",
    ];
    require(
        v.as_object()
            .is_some_and(|o| o.len() == FIELDS.len() && FIELDS.iter().all(|k| o.contains_key(*k)))
            && v["type"] == 1
            && v["object"] == "send"
            && v["text"].is_null()
            && v["file"].as_object().is_some_and(|o| {
                o.len() == 4
                    && ["id", "fileName", "size", "sizeName"]
                        .iter()
                        .all(|k| o.contains_key(*k))
            })
            && v["file"]["size"].as_str() == Some(expected_size.as_str())
            && v["file"]["sizeName"]
                .as_str()
                .is_some_and(|s| !s.is_empty()),
        "File Send owner or encrypted-size projection differed",
    )?;
    let id = text(&v["file"]["id"])?;
    require(
        id.len() == 64
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "File Send ID was not fresh hexadecimal material",
    )
}
fn reservation(s: &mut Suite, i: usize, body: &Value) -> Result<Value, Error> {
    let token = s.accounts[i].token.clone();
    let v = s
        .http
        .json(Method::POST, "/api/sends/file/v2", &token, Some(body))?;
    require(
        v.as_object().is_some_and(|o| o.len() == 4)
            && v["object"] == "send-fileUpload"
            && v["fileUploadType"] == 0,
        "File Send upload reservation projection differed",
    )?;
    Ok(v)
}
fn reservation_guards(s: &mut Suite) -> Result<(), Error> {
    let token = s.accounts[0].token.clone();
    let other = s.accounts[1].token.clone();
    let body = s.accounts[0].file.body.clone();
    let id = s.accounts[0].id.clone();
    let before = s.owner(0)?;
    let revision = s.revision(0)?;
    s.http
        .request(Method::POST, "/api/sends/file/v2", None, Some(&json!({})))?
        .rejected(401)?;
    s.http
        .request(
            Method::POST,
            "/api/sends/file/v2",
            Some("invalid"),
            Some(&body),
        )?
        .rejected(401)?;
    for (field, value, status) in [
        ("fileLength", Value::Null, 400),
        ("fileLength", json!(-1), 400),
        ("fileLength", json!(550_502_401_i64), 400),
        ("type", json!(0), 400),
        ("file", Value::Null, 400),
        ("deletionDate", json!("invalid"), 422),
    ] {
        let mut bad = body.clone();
        bad[field] = value;
        s.http
            .request(Method::POST, "/api/sends/file/v2", Some(&token), Some(&bad))?
            .rejected(status)?;
    }
    s.http
        .request(
            Method::POST,
            "/api/sends/file/v2",
            Some(&token),
            Some(&json!({})),
        )?
        .rejected(422)?;
    for method in [Method::GET, Method::DELETE] {
        s.http
            .request(method, &format!("/api/sends/{id}"), Some(&other), None)?
            .rejected(400)?;
    }
    s.http
        .request(Method::GET, "/api/sends/not-a-uuid", Some(&token), None)?
        .rejected(422)?;
    s.http
        .request(Method::PATCH, "/api/sends/file/v2", Some(&token), None)?
        .rejected(404)?;
    require(
        s.owner(0)? == before && s.revision(0)? == revision,
        "Rejected file Send reservation changed state",
    )
}
fn upload_guards(s: &mut Suite) -> Result<(), Error> {
    let token = s.accounts[0].token.clone();
    let other = s.accounts[1].token.clone();
    let path = s.accounts[0].upload_path.clone();
    let name = text(&s.accounts[0].file.body["file"]["fileName"])?.to_owned();
    let blob = s.accounts[0].file.blob.clone();
    let before = s.owner(0)?;
    let revision = s.revision(0)?;
    s.http
        .upload(&path, None, Some(&name), &blob, "data")?
        .rejected(401)?;
    s.http
        .upload(&path, Some(&other), Some(&name), &blob, "data")?
        .rejected(400)?;
    s.http
        .upload(
            &path,
            Some(&token),
            Some("wrong-encrypted-name"),
            &blob,
            "data",
        )?
        .rejected(400)?;
    s.http
        .upload(
            &path,
            Some(&token),
            Some(&name),
            &blob[..blob.len() - 1],
            "data",
        )?
        .rejected(400)?;
    let wrong = format!("/api/sends/{}/file/{}", s.accounts[0].id, "0".repeat(64));
    s.http
        .upload(&wrong, Some(&token), Some(&name), &blob, "data")?
        .rejected(400)?;
    s.http
        .upload(&path, Some(&token), Some(&name), &blob, "other")?
        .rejected(422)?;
    require(
        s.owner(0)? == before && s.revision(0)? == revision,
        "Rejected file Send upload changed reservation",
    )?;
    s.http
        .upload(&path, Some(&token), Some(&name), &blob, "data")?
        .empty()?;
    require(
        s.owner(0)? == before,
        "Successful byte upload changed immutable file metadata or Send revision",
    )?;
    require(
        s.revision(0)? != revision,
        "Successful file upload did not advance account revision",
    )?;
    let uploaded_revision = s.revision(0)?;
    let mut replacement = blob.clone();
    replacement[49] ^= 1;
    s.http
        .upload(&path, Some(&token), Some(&name), &replacement, "data")?
        .rejected(400)?;
    require(
        s.owner(0)? == before && s.revision(0)? == uploaded_revision,
        "Rejected duplicate upload changed file metadata or account revision",
    )
}
fn recipient_bytes(s: &mut Suite) -> Result<(), Error> {
    let id = s.accounts[0].access_id.clone();
    let owner = s.owner(0)?;
    let revision = s.revision(0)?;
    let cap = s.http.capability(&id)?;
    require(
        s.owner(0)? == owner && s.revision(0)? == revision,
        "Minting a file Send token changed owner state",
    )?;
    let metadata = s.metadata(&cap)?;
    const FIELDS: [&str; 8] = [
        "id",
        "type",
        "name",
        "text",
        "file",
        "expirationDate",
        "creatorIdentifier",
        "object",
    ];
    require(
        metadata
            .as_object()
            .is_some_and(|o| o.len() == FIELDS.len() && FIELDS.iter().all(|k| o.contains_key(*k)))
            && metadata["object"] == "send-access"
            && metadata["type"] == 1
            && metadata["file"] == owner["file"],
        "File Send recipient metadata projection differed",
    )?;
    s.accounts[0].file.check_filename(&metadata)?;
    require(
        s.owner(0)?["accessCount"] == owner["accessCount"],
        "File recipient metadata consumed a download",
    )?;
    // File metadata access leaves download counts unchanged but may bump owner revision.
    let file_id = s.accounts[0].file_id.clone();
    let path = format!("/api/sends/access/file/{file_id}");
    let token = s.accounts[0].token.clone();
    s.http
        .request(Method::POST, &path, None, None)?
        .rejected(401)?;
    s.http
        .request(Method::POST, &path, Some(&token), None)?
        .rejected(401)?;
    s.http
        .request(
            Method::POST,
            &format!("/api/sends/access/file/{}", s.accounts[1].file_id),
            Some(&cap),
            None,
        )?
        .rejected(404)?;
    let fresh = Instant::now();
    let url = s.url(0, &cap)?;
    let count = s.owner(0)?["accessCount"]
        .as_i64()
        .ok_or(Error("File Send access count missing"))?;
    require(
        count == 1,
        "File Send URL issuance did not increment exactly once",
    )?;
    for _ in 0..2 {
        let bytes = s.http.download(&url)?.status(200)?.bytes;
        s.accounts[0].file.check_bytes(&bytes)?;
    }
    require(
        s.owner(0)?["accessCount"] == count,
        "Repeated URL downloads consumed additional accesses",
    )?;
    let mut wrong = reqwest::Url::parse(&url).map_err(|_| Error("File Send URL parse failed"))?;
    wrong.set_query(Some("t=invalid"));
    s.http.download(wrong.as_str())?.rejected(404)?;
    wrong.set_query(Some("t="));
    s.http.download(wrong.as_str())?.rejected(404)?;
    wrong.set_query(None);
    s.http.download(wrong.as_str())?.rejected(422)?;
    let mut rooted = reqwest::Url::parse(&url).map_err(|_| Error("File Send URL parse failed"))?;
    let proof = rooted
        .query_pairs()
        .find(|(key, _)| key == "t")
        .map(|(_, value)| value.into_owned())
        .ok_or(Error("File Send URL omitted capability"))?;
    for root in ["t.x", "t[x]", ".t", "[t]"] {
        rooted.query_pairs_mut().clear().append_pair(root, &proof);
        let bytes = s.http.download(rooted.as_str())?.status(200)?.bytes;
        s.accounts[0].file.check_bytes(&bytes)?;
    }
    let mut foreign = reqwest::Url::parse(&url).map_err(|_| Error("File Send URL parse failed"))?;
    foreign.set_path(&format!(
        "/api/sends/{}/{}",
        s.accounts[1].id, s.accounts[1].file_id
    ));
    s.http.download(foreign.as_str())?.rejected(404)?;
    require(
        fresh.elapsed() < Duration::from_secs(30),
        "File Send repeated capability proof exceeded fresh window",
    )
}
fn owner_edits(s: &mut Suite) -> Result<(), Error> {
    let original = s.owner(0)?;
    let foreign = s.owner(1)?;
    let foreign_revision = s.revision(1)?;
    let mut body = s.accounts[0].file.body.clone();
    body["name"] = json!(
        fixture::encrypt(b"Edited file Send name", &s.accounts[0].file.key)
            .map_err(|_| Error("File Send edit encryption failed"))?
    );
    body["file"] = json!({"fileName":"ignored replacement","id":"ignored","size":1});
    body["hideEmail"] = json!(true);
    let changed = s.update(0, &body)?;
    require(
        changed["file"] == original["file"] && changed["key"] == original["key"],
        "Owner edit replaced immutable file metadata or wrapped seed",
    )?;
    require(
        fixture::decrypt(text(&changed["name"])?, &s.accounts[0].file.key)
            .is_ok_and(|p| p == b"Edited file Send name"),
        "Edited file Send name did not decrypt",
    )?;
    let token = s.accounts[0].token.clone();
    let listed = s.http.json(Method::GET, "/api/sends", &token, None)?;
    let sync = s.http.json(Method::GET, "/api/sync", &token, None)?;
    require(
        array(&listed["data"])?.contains(&changed) && array(&sync["sends"])?.contains(&changed),
        "Edited file Send omitted from owner list or sync",
    )?;
    require(
        s.owner(1)? == foreign && s.revision(1)? == foreign_revision,
        "File Send edit changed foreign state",
    )?;
    s.accounts[0].file.body["name"] = body["name"].clone();
    s.accounts[0].file.body["hideEmail"] = json!(true);
    Ok(())
}
fn availability(s: &mut Suite) -> Result<(), Error> {
    let access = s.accounts[0].access_id.clone();
    let cap = s.http.capability(&access)?;
    let fresh = Instant::now();
    let url = s.url(0, &cap)?;
    let bytes = s.http.download(&url)?.status(200)?.bytes;
    s.accounts[0].file.check_bytes(&bytes)?;
    let body = s.accounts[0].file.body.clone();
    let file_path = format!("/api/sends/access/file/{}", s.accounts[0].file_id);
    for (field, value) in [
        ("disabled", json!(true)),
        ("expirationDate", json!("2000-01-01T00:00:00Z")),
        ("deletionDate", json!("2000-01-01T00:00:00Z")),
    ] {
        let mut blocked = body.clone();
        blocked[field] = value;
        s.update(0, &blocked)?;
        s.http.grant(&access)?.rejected(404)?;
        s.http
            .request(Method::POST, "/api/sends/access", Some(&cap), None)?
            .rejected(404)?;
        s.http
            .request(Method::POST, &file_path, Some(&cap), None)?
            .rejected(404)?;
        let bytes = s.http.download(&url)?.status(200)?.bytes;
        s.accounts[0].file.check_bytes(&bytes)?;
    }
    require(
        fresh.elapsed() < Duration::from_secs(30),
        "File Send policy bypass URL proof exceeded fresh window",
    )?;
    s.update(0, &body)?;
    let count = s.owner(0)?["accessCount"]
        .as_i64()
        .ok_or(Error("File Send count missing"))?;
    let mut limited = body.clone();
    limited["maxAccessCount"] = json!(count + 1);
    s.update(0, &limited)?;
    let cap = s.http.capability(&access)?;
    let fresh = Instant::now();
    let limited_url = s.url(0, &cap)?;
    s.http
        .request(Method::POST, &file_path, Some(&cap), None)?
        .rejected(404)?;
    s.http.grant(&access)?.rejected(404)?;
    let metadata = s.metadata(&cap)?;
    require(
        metadata["type"] == 1,
        "Preissued file capability lost count-independent metadata access",
    )?;
    require(
        s.owner(0)?["accessCount"] == count + 1,
        "File download count exceeded maximum",
    )?;
    let bytes = s.http.download(&limited_url)?.status(200)?.bytes;
    s.accounts[0].file.check_bytes(&bytes)?;
    require(
        fresh.elapsed() < Duration::from_secs(30),
        "Limited file capability proof exceeded fresh window",
    )?;
    s.update(0, &body)?;
    Ok(())
}
fn delete_and_isolate(s: &mut Suite) -> Result<(), Error> {
    let a = s.accounts[0].access_id.clone();
    let b = s.accounts[1].access_id.clone();
    let acap = s.http.capability(&a)?;
    let bcap = s.http.capability(&b)?;
    let fresh = Instant::now();
    let aurl = s.url(0, &acap)?;
    let burl = s.url(1, &bcap)?;
    for (i, url) in [(0, &aurl), (1, &burl)] {
        let bytes = s.http.download(url)?.status(200)?.bytes;
        s.accounts[i].file.check_bytes(&bytes)?;
    }
    let foreign = s.owner(1)?;
    let foreign_revision = s.revision(1)?;
    let token = s.accounts[0].token.clone();
    let id = s.accounts[0].id.clone();
    s.http
        .request(
            Method::DELETE,
            &format!("/api/sends/{id}"),
            Some(&token),
            None,
        )?
        .empty()?;
    s.http.download(&aurl)?.rejected(404)?;
    s.http
        .request(Method::GET, &format!("/api/sends/{id}"), Some(&token), None)?
        .rejected(400)?;
    s.http
        .request(
            Method::POST,
            &format!("/api/sends/access/file/{}", s.accounts[0].file_id),
            Some(&acap),
            None,
        )?
        .rejected(404)?;
    s.http.grant(&a)?.rejected(404)?;
    let bytes = s.http.download(&burl)?.status(200)?.bytes;
    s.accounts[1].file.check_bytes(&bytes)?;
    require(
        fresh.elapsed() < Duration::from_secs(30),
        "Deleted file URL proof exceeded fresh window",
    )?;
    require(
        s.owner(1)? == foreign && s.revision(1)? == foreign_revision,
        "File Send deletion changed foreign resource",
    )?;
    for i in 0..2 {
        require(
            s.vault(i)? == s.vault[i],
            "File Send lifecycle changed account, vault, keys, settings or devices",
        )?;
    }
    Ok(())
}

pub fn run() -> Result<(), Error> {
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        vault: Vec::new(),
        passed: Vec::new(),
        receipt: receipt_file("BW_FILE_SENDS_RECEIPT")?,
        finished: false,
    };
    s.receipt("running")?;
    for i in 0..2 {
        let email = format!("file-sends-{}@example.test", Uuid::new_v4());
        let password = Uuid::new_v4().to_string();
        let account = fixture::seed_account(&s.http.server, &email, &password)
            .map_err(|_| Error("File Send account registration failed"))?;
        let token = s.http.login(&account)?;
        let profile = s
            .http
            .json(Method::GET, "/api/accounts/profile", &token, None)?;
        let encrypted = fixture::encrypted_pbkdf2_value(
            &account,
            &password,
            b"Retained personal vault through file Sends",
        )
        .map_err(|_| Error("File Send vault fixture encryption failed"))?;
        s.http.json(Method::POST,"/api/ciphers",&token,Some(&json!({"encryptedFor":profile["id"],"type":2,"name":encrypted,"notes":encrypted,"secureNote":{"type":0}})))?;
        let file = FileFixture::new(
            &account,
            &password,
            if i == 0 { payload() } else { Vec::new() },
        )?;
        // Account entry lets the shared reservation helper enforce authenticated ownership.
        s.accounts.push(Account {
            token,
            id: String::new(),
            access_id: String::new(),
            file_id: String::new(),
            upload_path: String::new(),
            file,
        });
        let mut body = s.accounts[i].file.body.clone();
        if i == 1 {
            body["fileLength"] = json!(s.accounts[i].file.blob.len().to_string());
        }
        let reserved = reservation(&mut s, i, &body)?;
        let v = &reserved["sendResponse"];
        owner_shape(v, s.accounts[i].file.blob.len())?;
        s.accounts[i].file.check_filename(v)?;
        require(
            v["key"] == s.accounts[i].file.body["key"]
                && v["name"] == s.accounts[i].file.body["name"]
                && v["notes"] == s.accounts[i].file.body["notes"],
            "File reservation changed opaque owner ciphertext",
        )?;
        require(
            fixture::decrypt(text(&v["key"])?, &s.accounts[i].file.user_key)
                .is_ok_and(|seed| seed == s.accounts[i].file.seed),
            "File Send wrapped seed failed account-key decryption",
        )?;
        let id = text(&v["id"])?.to_owned();
        let file_id = text(&v["file"]["id"])?.to_owned();
        let access_id = text(&v["accessId"])?.to_owned();
        let relative = format!("/sends/{id}/file/{file_id}");
        require(
            reserved["url"] == relative,
            "File Send upload URL selected a different reservation",
        )?;
        s.accounts[i].id = id;
        s.accounts[i].file_id = file_id;
        s.accounts[i].access_id = access_id;
        s.accounts[i].upload_path = format!("/api{relative}");
        if i == 1 {
            let a = &s.accounts[i];
            let path = a.upload_path.clone();
            let token = a.token.clone();
            let name = text(&a.file.body["file"]["fileName"])?.to_owned();
            let blob = a.file.blob.clone();
            s.http
                .upload(&path, Some(&token), Some(&name), &blob, "data")?
                .empty()?;
        }
    }
    require(
        s.accounts[0].file_id != s.accounts[1].file_id,
        "Independent file reservations reused identity",
    )?;
    for i in 0..2 {
        let v = s.vault(i)?;
        s.vault.push(v);
    }
    for (name, case) in CASES {
        println!("  {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.http.logins == 2 && s.http.grants <= 20,
        "File Send final budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS: 6 file Send HTTP cases, {} requests, {} public grants, 2 password logins",
        s.http.requests, s.http.grants
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::STANDARD;
    #[test]
    fn file_send_binary_authentication_handles_empty_and_arbitrary_bytes() {
        let key = fixture::send_key(&[0x42; 16]);
        for plaintext in [Vec::new(), payload()] {
            let blob = fixture::encrypt_file(&plaintext, &key).unwrap();
            assert!(blob[0] == 2 && blob.len() >= 65 && (blob.len() - 49).is_multiple_of(16));
            assert!(fixture::decrypt_file(&blob, &key).is_ok_and(|v| v == plaintext));
            let mut changed = blob.clone();
            changed[17] ^= 1;
            assert!(fixture::decrypt_file(&changed, &key).is_err());
            assert!(fixture::decrypt_file(&blob, &fixture::send_key(&[0x43; 16])).is_err());
            assert!(fixture::decrypt_file(&blob[..48], &key).is_err());
        }
    }
    #[test]
    fn file_send_derivation_uses_the_pinned_protocol_vector() {
        assert_eq!(
            STANDARD.encode(fixture::send_key(b"0123456789abcdef")),
            "Zn/CXNxzryjlrrwNzU//SAuf/idOwPeOJ92rOzSkYlN5yHiOa44FgZKCfzGJdcfC0CDGwje8H9RzFpnet6NlsA=="
        );
    }
}
