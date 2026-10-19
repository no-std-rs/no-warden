//! Opt-in portable text Send lifecycle. Pin/release: core/sends.rs, auth/send.rs,
//! models/send.rs; CLI b449ac1, bundled SDK c5e53d3 Send key/password derivation.
//! Tokens, seeds, proofs and payloads are deliberately absent from diagnostics.
//! File/email Sends, policies, notifications and live token expiry are separate.

use crate::fixture;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::{RngCore, rngs::OsRng};
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use sha2::Sha256;
use std::{
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;

const MAX_REPLY: u64 = 16 * 1024 * 1024;
pub(crate) const SEND_TEXT: &str = "Text Send round trip: 雪\nquotes \" and NUL\0 retained";
const SEND_NAME: &str = "Encrypted Send 雪";
const SEND_NOTES: &str = "Private owner notes\0with Unicode Ω";
const SEND_PASSWORD: &str = " synthetic Send password 雪 ";
type Case = fn(&mut Suite) -> Result<(), TextSendsError>;
const CASES: [(&str, Case); 6] = [
    (
        "text_sends_owner_guards_schema_and_foreign_isolation",
        owner_guards,
    ),
    (
        "text_sends_encrypted_owner_get_list_and_sync",
        owner_roundtrip,
    ),
    (
        "text_sends_recipient_capability_decryption_and_count",
        recipient_access,
    ),
    (
        "text_sends_password_replacement_removal_and_existing_capability",
        password_lifecycle,
    ),
    ("text_sends_disabled_dates_and_access_limits", availability),
    ("text_sends_edit_delete_and_preserved_vault", edit_delete),
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextSendsError(pub(crate) &'static str);
impl fmt::Display for TextSendsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for TextSendsError {}
pub(crate) fn require(ok: bool, message: &'static str) -> Result<(), TextSendsError> {
    if ok {
        Ok(())
    } else {
        Err(TextSendsError(message))
    }
}
pub(crate) fn text(value: &Value) -> Result<&str, TextSendsError> {
    value
        .as_str()
        .ok_or(TextSendsError("Required Send string missing"))
}
fn list(value: &Value) -> Result<&[Value], TextSendsError> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(TextSendsError("Required Send array missing"))
}
pub(crate) fn http_client() -> Result<Client, TextSendsError> {
    Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| TextSendsError("Send HTTP client initialization failed"))
}
pub(crate) fn server() -> String {
    std::env::var("BW_E2E_SERVER")
        .unwrap_or_else(|_| "http://127.0.0.1:8000".into())
        .trim_end_matches('/')
        .to_owned()
}
fn mac(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts every key length");
    for part in parts {
        h.update(part);
    }
    h.finalize().into_bytes().into()
}
fn send_key(seed: &[u8; 16]) -> [u8; 64] {
    let prk = mac(b"bitwarden-send", &[seed]);
    let first = mac(&prk, &[b"send", &[1]]);
    let second = mac(&prk, &[&first, b"send", &[2]]);
    let mut result = [0; 64];
    result[..32].copy_from_slice(&first);
    result[32..].copy_from_slice(&second);
    result
}
fn password_proof(password: &str, seed: &[u8; 16]) -> String {
    let mut result = [0; 32];
    pbkdf2_hmac::<Sha256>(password.as_bytes(), seed, 100_000, &mut result);
    STANDARD.encode(result)
}
// Gregorian conversion keeps date fixtures in Rust without another dependency.
fn timestamp(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let time = seconds.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    let year = year + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        time / 3600,
        time / 60 % 60,
        time % 60
    )
}
pub(crate) fn future_date(days: i64) -> Result<String, TextSendsError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| TextSendsError("Send fixture clock invalid"))?
        .as_secs();
    let now = i64::try_from(now).map_err(|_| TextSendsError("Send fixture clock overflow"))?;
    Ok(timestamp(now + days * 86_400))
}

struct SendFixture {
    seed: [u8; 16],
    key: [u8; 64],
    body: Value,
}
impl SendFixture {
    fn new(account: &Value, password: &str, protected: bool) -> Result<Self, TextSendsError> {
        let mut seed = [0; 16];
        OsRng
            .try_fill_bytes(&mut seed)
            .map_err(|_| TextSendsError("Send seed generation failed"))?;
        let key = send_key(&seed);
        let encrypt = |value: &[u8]| {
            fixture::encrypt(value, &key)
                .map_err(|_| TextSendsError("Send content encryption failed"))
        };
        let wrapped = fixture::encrypted_pbkdf2_value(account, password, &seed)
            .map_err(|_| TextSendsError("Send seed wrapping failed"))?;
        let body = json!({"type":0,"key":wrapped,"name":encrypt(SEND_NAME.as_bytes())?,
            "notes":encrypt(SEND_NOTES.as_bytes())?,"text":{"text":encrypt(SEND_TEXT.as_bytes())?,"hidden":true},
            "password":if protected { Some(password_proof(SEND_PASSWORD,&seed)) } else { None },
            "maxAccessCount":null,"expirationDate":null,"deletionDate":future_date(1)?,
            "disabled":false,"hideEmail":false,"emails":null});
        Ok(Self { seed, key, body })
    }
    fn decrypt(&self, value: &Value, expected_text: &str) -> Result<(), TextSendsError> {
        for (cipher, expected) in [
            (&value["name"], SEND_NAME),
            (&value["text"]["text"], expected_text),
        ] {
            require(
                fixture::decrypt(text(cipher)?, &self.key)
                    .is_ok_and(|bytes| bytes == expected.as_bytes()),
                "Send recipient content failed authenticated decryption",
            )?;
        }
        require(
            value["text"]["hidden"] == true,
            "Send hidden text flag differed",
        )
    }
}
struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, TextSendsError> {
        if self.status != expected {
            eprintln!(
                "Send HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Send HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, TextSendsError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| TextSendsError("Send response was not JSON"))
    }
    fn rejected(self, status: u16) -> Result<(), TextSendsError> {
        let reply = self.status(status)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&reply.bytes) {
            require(
                ["access_token", "refresh_token", "key", "Key", "text"]
                    .iter()
                    .all(|k| value.get(k).is_none()),
                "Rejected Send response exposed authority or content",
            )?;
        }
        Ok(())
    }
    fn grant_error(self, status: u16, error: &str, kind: &str) -> Result<(), TextSendsError> {
        require(
            self.status(status)?.json()?
                == json!({"kind":"expected_server","error":error,"send_access_error_type":kind}),
            "Send access proof error contract differed",
        )
    }
    fn empty(self) -> Result<(), TextSendsError> {
        require(
            self.status(200)?.bytes.is_empty(),
            "Send deletion response was not empty",
        )
    }
}
struct Http {
    server: String,
    client: Client,
    requests: usize,
    passwords: usize,
    grants: usize,
    accesses: usize,
}
impl Http {
    fn new() -> Result<Self, TextSendsError> {
        Ok(Self {
            server: server(),
            client: http_client()?,
            requests: 0,
            passwords: 0,
            grants: 0,
            accesses: 0,
        })
    }
    fn capture(response: reqwest::blocking::Response) -> Result<Reply, TextSendsError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_REPLY + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| TextSendsError("Send response capture failed"))?;
        require(
            bytes.len() as u64 <= MAX_REPLY,
            "Send response capture exceeded limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn request(
        &mut self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&Value>,
    ) -> Result<Reply, TextSendsError> {
        self.requests += 1;
        if method == Method::POST && path.starts_with("/api/sends/access") {
            self.accesses += 1;
        }
        let mut r = self
            .client
            .request(method, format!("{}{path}", self.server));
        if let Some(token) = token {
            r = r.bearer_auth(token);
        }
        if let Some(body) = body {
            r = r.json(body);
        }
        Self::capture(
            r.send()
                .map_err(|_| TextSendsError("Send HTTP request failed"))?,
        )
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, TextSendsError> {
        self.request(method, path, Some(token), body)?
            .status(200)?
            .json()
    }
    fn login(&mut self, account: &Value) -> Result<String, TextSendsError> {
        self.requests += 1;
        self.passwords += 1;
        require(self.passwords <= 2, "Send password login budget exceeded")?;
        let form = [
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("username", text(&account["email"])?),
            ("password", text(&account["masterPasswordHash"])?),
            ("deviceIdentifier", "text-sends-proof-device"),
            ("deviceName", "Text Sends proof"),
            ("deviceType", "8"),
        ];
        let v = Self::capture(
            self.client
                .post(format!("{}/identity/connect/token", self.server))
                .form(&form)
                .send()
                .map_err(|_| TextSendsError("Send fixture login failed"))?,
        )?
        .status(200)?
        .json()?;
        Ok(text(&v["access_token"])?.to_owned())
    }
    fn grant(
        &mut self,
        access_id: Option<&str>,
        proof: Option<&str>,
        client: bool,
    ) -> Result<Reply, TextSendsError> {
        let mut form = vec![("grant_type", "send_access"), ("scope", "api.send.access")];
        if client {
            form.push(("client_id", "send"));
        }
        if let Some(id) = access_id {
            form.push(("send_id", id));
        }
        if let Some(proof) = proof {
            form.push(("password_hash_b64", proof));
        }
        self.grant_form(&form)
    }
    fn grant_form(&mut self, form: &[(&str, &str)]) -> Result<Reply, TextSendsError> {
        self.requests += 1;
        self.grants += 1;
        require(self.grants <= 32, "Send public proof budget exceeded")?;
        Self::capture(
            self.client
                .post(format!("{}/identity/connect/token", self.server))
                .form(form)
                .send()
                .map_err(|_| TextSendsError("Send access grant failed"))?,
        )
    }
    fn capability(
        &mut self,
        access_id: &str,
        proof: Option<&str>,
    ) -> Result<String, TextSendsError> {
        let value = self
            .grant(Some(access_id), proof, true)?
            .status(200)?
            .json()?;
        require(
            value.as_object().is_some_and(|o| o.len() == 4)
                && value["token_type"] == "Bearer"
                && value["scope"] == "api.send.access"
                && value["expires_in"]
                    .as_i64()
                    .is_some_and(|s| (118..=120).contains(&s)),
            "Send access token response projection differed",
        )?;
        let token = text(&value["access_token"])?;
        let parts = token.split('.').collect::<Vec<_>>();
        require(parts.len() == 3, "Send access token claims missing")?;
        let claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(parts[1])
                .map_err(|_| TextSendsError("Send access claims encoding failed"))?,
        )
        .map_err(|_| TextSendsError("Send access claims decoding failed"))?;
        let origin = reqwest::Url::parse(&self.server)
            .map_err(|_| TextSendsError("Send server URL invalid"))?
            .origin()
            .ascii_serialization();
        let uuid = Uuid::from_slice(
            &URL_SAFE_NO_PAD
                .decode(access_id)
                .map_err(|_| TextSendsError("Send access ID encoding invalid"))?,
        )
        .map_err(|_| TextSendsError("Send access ID length invalid"))?;
        require(
            claims["iss"] == format!("{origin}|send")
                && claims["sub"] == uuid.to_string()
                && claims["exp"]
                    .as_i64()
                    .zip(claims["nbf"].as_i64())
                    .is_some_and(|(e, n)| e - n == 120),
            "Send access capability purpose or lifetime differed",
        )?;
        Ok(token.to_owned())
    }
}
struct Account {
    fixture: Value,
    password: String,
    token: String,
    send: SendFixture,
    id: String,
    access_id: String,
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    initial_vault: Vec<Value>,
    initial_foreign: Option<(Value, Value)>,
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
pub(crate) fn receipt_file(name: &str) -> Result<Option<fs::File>, TextSendsError> {
    std::env::var_os(name)
        .map(|path| {
            let mut o = fs::OpenOptions::new();
            o.read(true).write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            o.open(path)
                .map_err(|_| TextSendsError("Send receipt must be a new private file"))
        })
        .transpose()
}
pub(crate) fn write_receipt(
    file: &mut Option<fs::File>,
    value: &Value,
) -> Result<(), TextSendsError> {
    if let Some(f) = file {
        f.seek(SeekFrom::Start(0))
            .map_err(|_| TextSendsError("Send receipt seek failed"))?;
        f.set_len(0)
            .map_err(|_| TextSendsError("Send receipt truncate failed"))?;
        f.write_all(value.to_string().as_bytes())
            .map_err(|_| TextSendsError("Send receipt write failed"))?;
        f.sync_all()
            .map_err(|_| TextSendsError("Send receipt persistence failed"))?;
    }
    Ok(())
}
impl Suite {
    fn receipt(&mut self, status: &str) -> Result<(), TextSendsError> {
        write_receipt(
            &mut self.receipt,
            &json!({"schemaVersion":1,"status":status,"cases":self.passed,
            "expectedCases":6,"passedCases":self.passed.len(),"httpRequests":self.http.requests,
            "passwordCredentialAttempts":self.http.passwords,"sendAccessGrantRequests":self.http.grants,
            "recipientAccessRequests":self.http.accesses,"fixtureRegistrations":self.accounts.len()}),
        )
    }
    fn owner(&mut self, index: usize) -> Result<Value, TextSendsError> {
        let a = &self.accounts[index];
        self.http
            .json(Method::GET, &format!("/api/sends/{}", a.id), &a.token, None)
    }
    fn vault(&mut self, index: usize) -> Result<Value, TextSendsError> {
        let token = self.accounts[index].token.clone();
        let mut sync = self.http.json(Method::GET, "/api/sync", &token, None)?;
        sync.as_object_mut()
            .ok_or(TextSendsError("Send sync object missing"))?
            .remove("sends");
        let keys = self
            .http
            .json(Method::GET, "/api/accounts/keys", &token, None)?;
        let devices = self.http.json(Method::GET, "/api/devices", &token, None)?;
        Ok(json!({"sync":sync,"keys":keys,"devices":devices}))
    }
    fn revision(&mut self, index: usize) -> Result<Value, TextSendsError> {
        let token = self.accounts[index].token.clone();
        self.http
            .json(Method::GET, "/api/accounts/revision-date", &token, None)
    }
    fn update(&mut self, index: usize, body: &Value) -> Result<Value, TextSendsError> {
        let a = &self.accounts[index];
        self.http.json(
            Method::PUT,
            &format!("/api/sends/{}", a.id),
            &a.token,
            Some(body),
        )
    }
    fn access(&mut self, capability: &str) -> Result<Value, TextSendsError> {
        self.http
            .json(Method::POST, "/api/sends/access", capability, None)
    }
}
fn owner_shape(v: &Value) -> Result<(), TextSendsError> {
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
            .is_some_and(|o| o.len() == 18 && FIELDS.iter().all(|k| o.contains_key(*k)))
            && v["object"] == "send"
            && v["type"] == 0
            && v["file"].is_null(),
        "Owner Send projection differed",
    )
}
fn recipient_shape(v: &Value) -> Result<(), TextSendsError> {
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
        v.as_object()
            .is_some_and(|o| o.len() == 8 && FIELDS.iter().all(|k| o.contains_key(*k)))
            && v["object"] == "send-access"
            && v["type"] == 0
            && v["file"].is_null(),
        "Recipient Send projection exposed owner fields or differed",
    )
}

fn password_removed(value: &Value) -> bool {
    // Pinned SendAuthType / shipped client AuthType: Email=0, Password=1, None=2.
    value["password"].is_null() && value["authType"] == 2
}

fn owner_guards(s: &mut Suite) -> Result<(), TextSendsError> {
    let a = s.accounts[0].token.clone();
    let b = s.accounts[1].token.clone();
    let id = s.accounts[0].id.clone();
    let before = s.owner(0)?;
    let revision = s.revision(0)?;
    for path in [
        "/api/sends".to_owned(),
        format!("/api/sends/{id}"),
        "/api/sends/not-a-uuid".into(),
    ] {
        s.http
            .request(Method::GET, &path, None, None)?
            .rejected(401)?;
        s.http
            .request(Method::GET, &path, Some("invalid"), None)?
            .rejected(401)?;
    }
    for method in [Method::GET, Method::DELETE] {
        s.http
            .request(method, &format!("/api/sends/{id}"), Some(&b), None)?
            .rejected(400)?;
    }
    let body = s.accounts[0].send.body.clone();
    s.http
        .request(
            Method::PUT,
            &format!("/api/sends/{id}"),
            Some(&b),
            Some(&body),
        )?
        .rejected(400)?;
    s.http
        .request(
            Method::PUT,
            &format!("/api/sends/{id}/remove-password"),
            Some(&b),
            None,
        )?
        .rejected(400)?;
    s.http
        .request(Method::GET, "/api/sends/not-a-uuid", Some(&a), None)?
        .rejected(422)?;
    s.http
        .request(
            Method::GET,
            &format!("/api/sends/{}", Uuid::new_v4()),
            Some(&a),
            None,
        )?
        .rejected(400)?;
    for bad in [json!({}), json!({"type":"0"}), {
        let mut v = body.clone();
        v["deletionDate"] = json!("invalid");
        v
    }] {
        s.http
            .request(Method::POST, "/api/sends", Some(&a), Some(&bad))?
            .rejected(422)?;
    }
    for raw in [b"{".as_slice(), b"{\"type\":0,\"type\":0}".as_slice()] {
        s.http.requests += 1;
        Http::capture(
            s.http
                .client
                .post(format!("{}/api/sends", s.http.server))
                .bearer_auth(&a)
                .header("Content-Type", "application/json")
                .body(raw.to_vec())
                .send()
                .map_err(|_| TextSendsError("Send raw schema request failed"))?,
        )?
        .rejected(if raw == b"{" { 400 } else { 422 })?;
    }
    s.http
        .request(Method::POST, "/api/sends", None, Some(&json!({})))?
        .rejected(401)?;
    s.http
        .request(Method::PATCH, "/api/sends", Some(&a), None)?
        .rejected(404)?;
    s.http
        .request(
            Method::POST,
            &format!("/api/sends/{id}"),
            Some(&a),
            Some(&body),
        )?
        .rejected(404)?;
    require(
        s.owner(0)? == before && s.revision(0)? == revision,
        "Rejected owner Send operation mutated state",
    )
}
fn owner_roundtrip(s: &mut Suite) -> Result<(), TextSendsError> {
    for i in 0..2 {
        let revision = s.revision(i)?;
        let v = s.owner(i)?;
        owner_shape(&v)?;
        let a = &s.accounts[i];
        require(
            ["key", "name", "notes", "text"]
                .iter()
                .all(|k| v[*k] == a.send.body[*k]),
            "Stored Send ciphertext differed",
        )?;
        let user_key = fixture::pbkdf2_fixture_user_key(&a.fixture, &a.password)
            .map_err(|_| TextSendsError("Send account key unwrap failed"))?;
        require(
            fixture::decrypt(text(&v["key"])?, &user_key).is_ok_and(|seed| seed == a.send.seed),
            "Owner Send seed did not unwrap under account key",
        )?;
        require(
            fixture::decrypt(text(&v["notes"])?, &a.send.key)
                .is_ok_and(|p| p == SEND_NOTES.as_bytes()),
            "Owner Send notes did not decrypt",
        )?;
        a.send.decrypt(&v, SEND_TEXT)?;
        let token = a.token.clone();
        let id = a.id.clone();
        let listed = s.http.json(Method::GET, "/api/sends", &token, None)?;
        require(
            listed["object"] == "list"
                && listed["continuationToken"].is_null()
                && list(&listed["data"])?.iter().any(|x| x == &v),
            "Owner Send list omitted stored ciphertext",
        )?;
        let sync = s.http.json(Method::GET, "/api/sync", &token, None)?;
        require(
            list(&sync["sends"])?
                .iter()
                .any(|x| x["id"] == id && x == &v),
            "Sync omitted encrypted owner Send",
        )?;
        require(
            s.revision(i)? == revision,
            "Owner Send reads advanced account revision",
        )?;
    }
    let mut body = s.accounts[0].send.body.clone();
    body["text"]["ExtraField"] =
        json!({"NestedField":"opaque extension","response":"nested retained"});
    body["text"]["response"] = json!("strip this field");
    let projected = s.update(0, &body)?;
    require(
        projected["text"]["extraField"]
            == json!({"nestedField":"opaque extension","response":"nested retained"})
            && projected["text"].get("response").is_none()
            && projected["text"]["text"] == body["text"]["text"],
        "Send text extension normalization differed",
    )?;
    Ok(())
}
fn recipient_access(s: &mut Suite) -> Result<(), TextSendsError> {
    let id = s.accounts[0].access_id.clone();
    let proof = password_proof(SEND_PASSWORD, &s.accounts[0].send.seed);
    let revision = s.revision(0)?;
    let before = s.owner(0)?;
    s.http.grant(Some(&id), None, true)?.grant_error(
        400,
        "invalid_request",
        "password_hash_b64_required",
    )?;
    s.http
        .grant(Some(&id), Some("wrong-proof"), true)?
        .grant_error(404, "invalid_grant", "password_hash_b64_invalid")?;
    s.http
        .grant(Some("not-an-access-id"), None, true)?
        .grant_error(404, "invalid_grant", "send_id_invalid")?;
    s.http.grant(None, None, true)?.rejected(400)?;
    s.http.grant(Some(&id), None, false)?.rejected(400)?;
    // ConnectData gives these two fields no compact or uncased aliases.
    // A correct proof must not turn an unknown send-ID spelling into authority.
    for unknown in ["sendid", "SEND_ID"] {
        s.http
            .grant_form(&[
                ("grant_type", "send_access"),
                ("client_id", "send"),
                (unknown, &id),
                ("password_hash_b64", &proof),
            ])?
            .rejected(400)?;
    }
    s.http
        .grant_form(&[
            ("grant_type", "send_access"),
            ("client_id", "send"),
            ("send_id", &id),
            ("passwordhashb64", &proof),
        ])?
        .grant_error(400, "invalid_request", "password_hash_b64_required")?;
    let cap = s.http.capability(&id, Some(&proof))?;
    require(
        s.owner(0)? == before && s.revision(0)? == revision,
        "Minting or rejecting Send proof mutated owner state",
    )?;
    let user = s.accounts[0].token.clone();
    s.http
        .request(Method::GET, "/api/sends", Some(&cap), None)?
        .rejected(401)?;
    s.http
        .request(Method::POST, "/api/sends/access", Some("invalid"), None)?
        .rejected(401)?;
    s.http
        .request(Method::POST, "/api/sends/access", None, None)?
        .rejected(401)?;
    s.http
        .request(Method::POST, "/api/sends/access", Some(&user), None)?
        .rejected(401)?;
    for count in 1..=2 {
        let value = if count == 1 {
            s.access(&cap)?
        } else {
            s.http.json(
                Method::POST,
                "/api/sends/access?send_id=ignored",
                &cap,
                Some(&json!({"id":"ignored","password":"ignored"})),
            )?
        };
        recipient_shape(&value)?;
        s.accounts[0].send.decrypt(&value, SEND_TEXT)?;
        require(
            value["id"] == id && value["creatorIdentifier"] == s.accounts[0].fixture["email"],
            "Recipient Send selected wrong resource or creator",
        )?;
        require(
            s.owner(0)?["accessCount"] == count,
            "Text access count did not increment exactly once",
        )?;
    }
    require(
        s.revision(0)? != revision,
        "Text recipient access did not advance owner revision",
    )
}
fn password_lifecycle(s: &mut Suite) -> Result<(), TextSendsError> {
    let id = s.accounts[0].access_id.clone();
    let old = password_proof(SEND_PASSWORD, &s.accounts[0].send.seed);
    let cap = s.http.capability(&id, Some(&old))?;
    let new = password_proof("replacement password", &s.accounts[0].send.seed);
    let mut body = s.accounts[0].send.body.clone();
    body["password"] = json!(new);
    let updated = s.update(0, &body)?;
    require(
        updated["authType"] == 1 && updated["password"].is_string(),
        "Send password replacement projection differed",
    )?;
    s.http.grant(Some(&id), Some(&old), true)?.grant_error(
        404,
        "invalid_grant",
        "password_hash_b64_invalid",
    )?;
    let accessed = s.access(&cap)?;
    s.accounts[0].send.decrypt(&accessed, SEND_TEXT)?;
    body["password"] = Value::Null;
    s.update(0, &body)?;
    s.http.grant(Some(&id), None, true)?.grant_error(
        400,
        "invalid_request",
        "password_hash_b64_required",
    )?;
    let newcap = s.http.capability(&id, Some(&new))?;
    let accessed = s.access(&newcap)?;
    s.accounts[0].send.decrypt(&accessed, SEND_TEXT)?;
    let token = s.accounts[0].token.clone();
    let owner_id = s.accounts[0].id.clone();
    let removed = s.http.json(
        Method::PUT,
        &format!("/api/sends/{owner_id}/remove-password"),
        &token,
        None,
    )?;
    require(
        password_removed(&removed),
        "Send password removal projection differed",
    )?;
    let public = s.http.capability(&id, None)?;
    let accessed = s.access(&public)?;
    s.accounts[0].send.decrypt(&accessed, SEND_TEXT)?;
    s.accounts[0].send.body["password"] = Value::Null;
    Ok(())
}
fn availability(s: &mut Suite) -> Result<(), TextSendsError> {
    let id = s.accounts[0].access_id.clone();
    let issued_at = Instant::now();
    let cap = s.http.capability(&id, None)?;
    let body = s.accounts[0].send.body.clone();
    // Chrono's JSON DateTime parser accepts these forms, and the owner response
    // preserves leap seconds. These probes add no capability mints or logins.
    let owner_token = s.accounts[0].token.clone();
    for (input, canonical) in [
        ("2000-01-01 00:00:00+0000", "2000-01-01T00:00:00.000000Z"),
        ("2016-12-31T23:59:60Z", "2016-12-31T23:59:60.000000Z"),
    ] {
        let mut probe = body.clone();
        probe["deletionDate"] = json!(input);
        let saved = s
            .http
            .json(Method::POST, "/api/sends", &owner_token, Some(&probe))?;
        owner_shape(&saved)?;
        require(
            saved["deletionDate"] == canonical,
            "Send owner date did not retain the source canonical representation",
        )?;
        s.http
            .request(
                Method::DELETE,
                &format!("/api/sends/{}", text(&saved["id"])?),
                Some(&owner_token),
                None,
            )?
            .empty()?;
    }
    for (field, value) in [
        ("disabled", json!(true)),
        ("expirationDate", json!("2000-01-01T00:00:00Z")),
        ("deletionDate", json!("2000-01-01T00:00:00Z")),
    ] {
        let mut blocked = body.clone();
        blocked[field] = value;
        s.update(0, &blocked)?;
        s.http.grant(Some(&id), None, true)?.grant_error(
            404,
            "invalid_grant",
            "send_id_invalid",
        )?;
        s.http
            .request(Method::POST, "/api/sends/access", Some(&cap), None)?
            .rejected(404)?;
        require(
            s.owner(0)?["id"] == s.accounts[0].id,
            "Inaccessible Send disappeared from owner reads",
        )?;
    }
    let count = s.owner(0)?["accessCount"]
        .as_i64()
        .ok_or(TextSendsError("Send access count missing"))?;
    let mut limited = body.clone();
    limited["maxAccessCount"] = json!((count + 1).to_string());
    s.update(0, &limited)?;
    // Pre-mint two capabilities: minting does not reserve a remaining access.
    let first = s.http.capability(&id, None)?;
    let second = s.http.capability(&id, None)?;
    let accessed = s.access(&first)?;
    s.accounts[0].send.decrypt(&accessed, SEND_TEXT)?;
    s.http
        .request(Method::POST, "/api/sends/access", Some(&second), None)?
        .rejected(404)?;
    require(
        s.owner(0)?["accessCount"] == count + 1,
        "Send access limit was exceeded",
    )?;
    s.http
        .grant(Some(&id), None, true)?
        .grant_error(404, "invalid_grant", "send_id_invalid")?;
    let before = s.owner(0)?;
    let token = s.accounts[0].token.clone();
    let owner_id = s.accounts[0].id.clone();
    let mut invalid = body.clone();
    invalid["deletionDate"] = json!(future_date(32)?);
    s.http
        .request(
            Method::PUT,
            &format!("/api/sends/{owner_id}"),
            Some(&token),
            Some(&invalid),
        )?
        .rejected(400)?;
    require(
        s.owner(0)? == before,
        "Rejected future deletion date mutated Send",
    )?;
    require(
        issued_at.elapsed() < Duration::from_secs(60),
        "Send availability proof exceeded the capability non-expiry window",
    )?;
    s.update(0, &body)?;
    Ok(())
}
fn edit_delete(s: &mut Suite) -> Result<(), TextSendsError> {
    let (foreign, foreign_revision) = s
        .initial_foreign
        .clone()
        .ok_or(TextSendsError("Initial foreign Send snapshot missing"))?;
    let mut body = s.accounts[0].send.body.clone();
    body["text"]["text"] = json!(
        fixture::encrypt(
            b"Edited text \0 with Unicode \xe9\x9b\xaa",
            &s.accounts[0].send.key
        )
        .map_err(|_| TextSendsError("Edited Send encryption failed"))?
    );
    body["hideEmail"] = json!(true);
    let edited = s.update(0, &body)?;
    owner_shape(&edited)?;
    let id = s.accounts[0].access_id.clone();
    let issued_at = Instant::now();
    let cap = s.http.capability(&id, None)?;
    let value = s.access(&cap)?;
    s.accounts[0]
        .send
        .decrypt(&value, "Edited text \0 with Unicode 雪")?;
    require(
        value["creatorIdentifier"].is_null(),
        "Hidden creator email was exposed",
    )?;
    let a = s.accounts[0].token.clone();
    let owner_id = s.accounts[0].id.clone();
    s.http
        .request(
            Method::DELETE,
            &format!("/api/sends/{owner_id}"),
            Some(&a),
            None,
        )?
        .empty()?;
    s.http
        .request(
            Method::GET,
            &format!("/api/sends/{owner_id}"),
            Some(&a),
            None,
        )?
        .rejected(400)?;
    s.http
        .request(Method::POST, "/api/sends/access", Some(&cap), None)?
        .rejected(404)?;
    require(
        issued_at.elapsed() < Duration::from_secs(60),
        "Deleted Send proof exceeded the capability non-expiry window",
    )?;
    s.http
        .grant(Some(&id), None, true)?
        .grant_error(404, "invalid_grant", "send_id_invalid")?;
    let sync = s.http.json(Method::GET, "/api/sync", &a, None)?;
    require(
        !list(&sync["sends"])?.iter().any(|v| v["id"] == owner_id),
        "Deleted Send remained in sync",
    )?;
    require(
        s.owner(1)? == foreign && s.revision(1)? == foreign_revision,
        "Own Send lifecycle changed foreign Send state",
    )?;
    for i in 0..2 {
        require(
            s.vault(i)? == s.initial_vault[i],
            "Send lifecycle changed vault, account keys, settings or devices",
        )?;
    }
    Ok(())
}

pub fn run() -> Result<(), TextSendsError> {
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        initial_vault: Vec::new(),
        initial_foreign: None,
        passed: Vec::new(),
        receipt: receipt_file("BW_TEXT_SENDS_RECEIPT")?,
        finished: false,
    };
    s.receipt("running")?;
    for _ in 0..2 {
        let email = format!("text-sends-{}@example.test", Uuid::new_v4());
        let password = Uuid::new_v4().to_string();
        let account = fixture::seed_account(&s.http.server, &email, &password)
            .map_err(|_| TextSendsError("Send fixture registration failed"))?;
        let token = s.http.login(&account)?;
        let owner = s
            .http
            .json(Method::GET, "/api/accounts/profile", &token, None)?;
        let owner_id = text(&owner["id"])?;
        let encrypted = fixture::encrypted_pbkdf2_value(
            &account,
            &password,
            b"Personal vault retained through Send lifecycle",
        )
        .map_err(|_| TextSendsError("Retained vault fixture encryption failed"))?;
        s.http.json(Method::POST,"/api/ciphers",&token,Some(&json!({"encryptedFor":owner_id,"type":2,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"favorite":false})))?;
        let send = SendFixture::new(&account, &password, s.accounts.is_empty())?;
        let saved = s
            .http
            .json(Method::POST, "/api/sends", &token, Some(&send.body))?;
        owner_shape(&saved)?;
        let id = text(&saved["id"])?.to_owned();
        let access_id = text(&saved["accessId"])?.to_owned();
        s.accounts.push(Account {
            fixture: account,
            password,
            token,
            send,
            id,
            access_id,
        });
    }
    for i in 0..2 {
        let value = s.vault(i)?;
        s.initial_vault.push(value);
    }
    s.initial_foreign = Some((s.owner(1)?, s.revision(1)?));
    for (name, case) in CASES {
        println!("  {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.http.passwords == 2 && s.http.grants <= 32,
        "Send final request budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS: 6 text Send HTTP cases, {} requests, {} public grants, 2 password logins",
        s.http.requests, s.http.grants
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn removed_password_requires_the_source_no_auth_discriminant() {
        assert!(password_removed(&json!({"password":null,"authType":2})));
        for invalid in [
            json!({"password":null,"authType":0}),
            json!({"password":null,"authType":1}),
            json!({"password":"synthetic verifier","authType":2}),
        ] {
            assert!(!password_removed(&invalid));
        }
    }
    #[test]
    fn send_key_derivation_and_password_proof_match_independent_known_vectors() {
        // Synthetic fixed inputs only; expected values produced independently by RFC5869/PBKDF2.
        let seed = *b"0123456789abcdef";
        let derived = send_key(&seed);
        assert_eq!(
            STANDARD.encode(derived),
            "Zn/CXNxzryjlrrwNzU//SAuf/idOwPeOJ92rOzSkYlN5yHiOa44FgZKCfzGJdcfC0CDGwje8H9RzFpnet6NlsA=="
        );
        assert_eq!(
            password_proof("password", &seed),
            "p1GQp5LNWdbZyMOmOxHCdq1EmXK3iG4cLYGcKGBTNm8="
        );
        assert_ne!(&derived[..32], &derived[32..]);
        assert_ne!(
            password_proof("password", &seed),
            password_proof(" password", &seed)
        );
        assert_eq!(
            URL_SAFE_NO_PAD
                .decode(URL_SAFE_NO_PAD.encode(seed))
                .unwrap(),
            seed
        );
    }
    #[test]
    fn send_content_rejects_wrong_seed_and_tampered_mac_before_plaintext() {
        let key = send_key(&[0x42; 16]);
        let ciphertext = fixture::encrypt(b"synthetic Send plaintext", &key).unwrap();
        assert!(
            fixture::decrypt(&ciphertext, &key).is_ok_and(|p| p == b"synthetic Send plaintext")
        );
        assert!(fixture::decrypt(&ciphertext, &send_key(&[0x43; 16])).is_err());
        let mut parts = ciphertext[2..]
            .split('|')
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let mut tag = STANDARD.decode(&parts[2]).unwrap();
        tag[0] ^= 1;
        parts[2] = STANDARD.encode(tag);
        assert!(fixture::decrypt(&format!("2.{}", parts.join("|")), &key).is_err());
    }
    #[test]
    fn send_date_fixtures_cover_epoch_and_leap_calendar() {
        assert_eq!(timestamp(0), "1970-01-01T00:00:00Z");
        assert_eq!(timestamp(951_827_696), "2000-02-29T12:34:56Z");
        assert_eq!(timestamp(-1), "1969-12-31T23:59:59Z");
    }
}
