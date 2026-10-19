//! Independently authored MIT/Apache-2.0 user-key ID initialization contracts.
//! Opaque IDs are tested on disposable HTTP accounts; the official-client suite
//! separately exercises IDs derived by its unlocked SDK. No upstream code is used.
use crate::{
    fixture,
    text_sends::{
        TextSendsError as Error, http_client, receipt_file, require, server, text, write_receipt,
    },
};
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use std::{fs, io::Read};
use uuid::Uuid;

pub const CASE_COUNT: usize = 6;
pub(crate) const ENDPOINT: &str = "/api/accounts/key-management/user-key-id";
pub(crate) const NOTE: &str = "Retained user-key-ID note 雪\0with private bytes";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    ("user_key_id_authentication_and_schema_guards", guards),
    ("user_key_id_empty_string_initialization", empty),
    ("user_key_id_opaque_unicode_initialization", opaque),
    ("user_key_id_positional_initialization", positional),
    ("user_key_id_repeat_rejection_and_owner_isolation", repeated),
    (
        "user_key_id_sessions_keys_and_vault_preservation",
        preservation,
    ),
];

pub(crate) fn sync_key_id(sync: &Value) -> Result<&Value, Error> {
    let id = sync
        .get("userDecryption")
        .and_then(|v| v.get("userKeyId"))
        .ok_or(Error("Sync user-key-ID metadata was absent"))?;
    require(
        id.is_null() || id.is_string(),
        "Sync user-key-ID metadata had the wrong type",
    )?;
    Ok(id)
}
fn normalized_sync(mut sync: Value) -> Result<Value, Error> {
    sync_key_id(&sync)?;
    sync["userDecryption"]["userKeyId"] = Value::Null;
    Ok(sync)
}

pub(crate) struct Reply {
    pub(crate) status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    pub(crate) fn status(self, status: u16) -> Result<Self, Error> {
        if self.status != status {
            eprintln!(
                "User-key-ID HTTP status mismatch: expected {status}, actual {}",
                self.status
            );
        }
        require(self.status == status, "User-key-ID HTTP status differed")?;
        Ok(self)
    }
    pub(crate) fn json(self) -> Result<Value, Error> {
        serde_json::from_slice(&self.bytes).map_err(|_| Error("User-key-ID response was not JSON"))
    }
    fn empty(self) -> Result<(), Error> {
        require(
            self.status(200)?.bytes.is_empty(),
            "User-key-ID success body was not empty",
        )
    }
    fn rejected(self, status: u16) -> Result<(), Error> {
        let reply = self.status(status)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&reply.bytes) {
            require(
                ["access_token", "refresh_token", "key", "privateKey"]
                    .iter()
                    .all(|field| value.get(field).is_none()),
                "Rejected user-key-ID request exposed authority",
            )?;
        }
        Ok(())
    }
    fn already_set(self) -> Result<(), Error> {
        let value = self.status(422)?.json()?;
        require(
            value["message"] == "Unexpected data",
            "Repeated user-key-ID rejection message differed",
        )
    }
}
pub(crate) struct Http {
    pub(crate) server: String,
    client: Client,
    pub(crate) requests: usize,
    pub(crate) logins: usize,
    pub(crate) refreshes: usize,
}
impl Http {
    pub(crate) fn new() -> Result<Self, Error> {
        Ok(Self {
            server: server(),
            client: http_client()?,
            requests: 0,
            logins: 0,
            refreshes: 0,
        })
    }
    fn read(response: reqwest::blocking::Response) -> Result<Reply, Error> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("User-key-ID private capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "User-key-ID private capture exceeded limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn raw(
        &mut self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&str>,
    ) -> Result<Reply, Error> {
        self.raw_media(method, path, token, body, Some("application/json"))
    }
    fn raw_media(
        &mut self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&str>,
        content_type: Option<&str>,
    ) -> Result<Reply, Error> {
        self.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.server));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request.body(body.to_owned());
            if let Some(content_type) = content_type {
                request = request.header("Content-Type", content_type);
            }
        }
        Self::read(
            request
                .send()
                .map_err(|_| Error("User-key-ID HTTP request failed"))?,
        )
    }
    pub(crate) fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        self.raw(
            method,
            path,
            Some(token),
            body.map(Value::to_string).as_deref(),
        )?
        .status(200)?
        .json()
    }
    fn token(&mut self, form: &[(&str, &str)]) -> Result<Value, Error> {
        self.requests += 1;
        Self::read(
            self.client
                .post(format!("{}/identity/connect/token", self.server))
                .form(form)
                .send()
                .map_err(|_| Error("User-key-ID fixture identity failed"))?,
        )?
        .status(200)?
        .json()
    }
    fn login(&mut self, fixture: &Value) -> Result<(String, String), Error> {
        self.logins += 1;
        require(
            self.logins <= 3,
            "User-key-ID HTTP password budget exceeded",
        )?;
        let value = self.token(&[
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("username", text(&fixture["email"])?),
            ("password", text(&fixture["masterPasswordHash"])?),
            ("deviceIdentifier", "User-Key-ID-Fixture"),
            ("deviceName", "User key ID fixture"),
            ("deviceType", "8"),
        ])?;
        Ok((
            text(&value["access_token"])?.into(),
            text(&value["refresh_token"])?.into(),
        ))
    }
    pub(crate) fn sync(&mut self, token: &str) -> Result<Value, Error> {
        self.json(Method::GET, "/api/sync", token, None)
    }
    pub(crate) fn revision(&mut self, token: &str) -> Result<Value, Error> {
        self.json(Method::GET, "/api/accounts/revision-date", token, None)
    }
    pub(crate) fn snapshot(&mut self, token: &str) -> Result<Value, Error> {
        let sync = normalized_sync(self.sync(token)?)?;
        let keys = self.json(Method::GET, "/api/accounts/keys", token, None)?;
        let devices = self.json(Method::GET, "/api/devices", token, None)?;
        let ciphers = self.json(Method::GET, "/api/ciphers", token, None)?;
        Ok(json!({"sync":sync,"keys":keys,"devices":devices,"ciphers":ciphers}))
    }
}
pub(crate) struct Account {
    pub(crate) fixture: Value,
    pub(crate) password: String,
    pub(crate) token: String,
    refresh: String,
    pub(crate) cipher_id: String,
    pub(crate) user_key: [u8; 64],
}
pub(crate) fn seed(http: &mut Http) -> Result<Account, Error> {
    let email = format!("user-key-id-{}@example.test", Uuid::new_v4());
    let password = Uuid::new_v4().to_string();
    let fixture = fixture::seed_account(&http.server, &email, &password)
        .map_err(|_| Error("User-key-ID fixture registration failed"))?;
    let (token, refresh) = http.login(&fixture)?;
    let profile = http.json(Method::GET, "/api/accounts/profile", &token, None)?;
    let encrypted = fixture::encrypted_pbkdf2_value(&fixture, &password, NOTE.as_bytes())
        .map_err(|_| Error("User-key-ID note encryption failed"))?;
    let cipher=http.json(Method::POST,"/api/ciphers",&token,Some(&json!({"type":2,"encryptedFor":profile["id"],"name":encrypted,"notes":encrypted,"secureNote":{"type":0}})))?;
    let cipher_id = text(&cipher["id"])?.into();
    let user_key = fixture::pbkdf2_fixture_user_key(&fixture, &password)
        .map_err(|_| Error("User-key-ID fixture key unwrap failed"))?;
    require(
        sync_key_id(&http.sync(&token)?)?.is_null(),
        "Fresh account already had a user key ID",
    )?;
    Ok(Account {
        fixture,
        password,
        token,
        refresh,
        cipher_id,
        user_key,
    })
}
pub(crate) fn check_note(http: &mut Http, account: &Account) -> Result<(), Error> {
    let value = http.json(
        Method::GET,
        &format!("/api/ciphers/{}", account.cipher_id),
        &account.token,
        None,
    )?;
    require(
        fixture::decrypt(text(&value["notes"])?, &account.user_key)
            .is_ok_and(|p| p == NOTE.as_bytes()),
        "User-key-ID lifecycle changed authenticated note contents",
    )
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
    before: Vec<Value>,
    revisions: Vec<Value>,
    ids: Vec<String>,
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
            &json!({"schemaVersion":1,"status":status,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"cases":self.passed,"httpRequests":self.http.requests,"passwordCredentialAttempts":self.http.logins,"refreshRequests":self.http.refreshes,"fixtureRegistrations":self.accounts.len()}),
        )
    }
    fn unchanged(&mut self) -> Result<(), Error> {
        for i in 0..self.accounts.len() {
            let token = &self.accounts[i].token;
            require(
                self.http.snapshot(token)? == self.before[i],
                "User-key-ID write changed account keys, cipher bytes, devices or vault",
            )?;
        }
        Ok(())
    }
    fn initialize(&mut self, i: usize, body: Value) -> Result<(), Error> {
        let token = &self.accounts[i].token;
        self.http
            .raw_media(
                Method::POST,
                ENDPOINT,
                Some(token),
                Some(&body.to_string()),
                [None, Some("text/plain"), Some("application/problem+json")][i],
            )?
            .empty()?;
        require(
            self.http.sync(token)?["userDecryption"]["userKeyId"] == self.ids[i],
            "User-key-ID sync metadata differed",
        )?;
        require(
            self.http.revision(token)? != self.revisions[i],
            "User-key-ID initialization did not advance account revision",
        )?;
        for j in 0..self.accounts.len() {
            if j != i {
                require(
                    self.http.revision(&self.accounts[j].token)? == self.revisions[j],
                    "User-key-ID initialization changed another owner revision",
                )?;
            }
        }
        self.revisions[i] = self.http.revision(token)?;
        self.unchanged()
    }
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    let token = s.accounts[0].token.clone();
    for bearer in [None, Some("invalid-user-key-id-bearer")] {
        s.http
            .raw(Method::POST, ENDPOINT, bearer, Some("{"))?
            .rejected(401)?;
    }
    for (body, status) in [
        ("{", 400),
        ("{}", 422),
        ("[]", 422),
        (r#"{"userKeyId":null}"#, 422),
        (r#"{"userKeyId":1}"#, 422),
        (r#"{"userKeyId":true}"#, 422),
        (r#"{"userKeyId":[]}"#, 422),
        (r#"{"userKeyId":{}}"#, 422),
        (r#"{"UserKeyId":"ignored"}"#, 422),
        (r#"{"userKeyId":"one","userKeyId":"two"}"#, 422),
        (r#"["first","surplus"]"#, 400),
    ] {
        s.http
            .raw(Method::POST, ENDPOINT, Some(&token), Some(body))?
            .rejected(status)?;
    }
    // Rocket first decodes the entire body as UTF-8, including ignored fields.
    // A parser that skips unknown JSON values must not initialize this ID.
    s.http.requests += 1;
    Http::read(
        s.http
            .client
            .post(format!("{}{ENDPOINT}", s.http.server))
            .bearer_auth(&token)
            .header("Content-Type", "application/json")
            .body(b"{\"userKeyId\":\"would-initialize\",\"ignored\":\"\xff\"}".to_vec())
            .send()
            .map_err(|_| Error("User-key-ID raw UTF-8 probe failed"))?,
    )?
    .rejected(400)?;
    for method in [Method::GET, Method::PUT, Method::DELETE, Method::PATCH] {
        s.http
            .raw(method, ENDPOINT, Some(&token), Some("{"))?
            .rejected(404)?;
    }
    for i in 0..s.accounts.len() {
        require(
            s.http.sync(&s.accounts[i].token)?["userDecryption"]["userKeyId"].is_null()
                && s.http.revision(&s.accounts[i].token)? == s.revisions[i],
            "Rejected user-key-ID request changed state",
        )?;
    }
    s.unchanged()
}
fn empty(s: &mut Suite) -> Result<(), Error> {
    s.initialize(0, json!({"userKeyId":""}))
}
fn opaque(s: &mut Suite) -> Result<(), Error> {
    let body = json!({"userKeyId":s.ids[1],"owner":"foreign","id":"foreign","email":"foreign@example.test","key":"ignored","future":{"ignored":true}});
    s.initialize(1, body)
}
fn positional(s: &mut Suite) -> Result<(), Error> {
    s.initialize(2, json!([s.ids[2]]))
}
fn repeated(s: &mut Suite) -> Result<(), Error> {
    for i in 0..s.accounts.len() {
        let token = s.accounts[i].token.clone();
        for body in [
            json!({"userKeyId":s.ids[i]}),
            json!({"userKeyId":"replacement","owner":s.accounts[(i+1)%s.accounts.len()].fixture["email"]}),
            json!([""]),
        ] {
            s.http
                .raw(
                    Method::POST,
                    &format!("{ENDPOINT}?organizationId=ignored&userId=foreign"),
                    Some(&token),
                    Some(&body.to_string()),
                )?
                .already_set()?;
        }
        require(
            s.http.sync(&token)?["userDecryption"]["userKeyId"] == s.ids[i]
                && s.http.revision(&token)? == s.revisions[i],
            "Repeated user-key-ID request changed ID or revision",
        )?;
    }
    s.unchanged()
}
fn preservation(s: &mut Suite) -> Result<(), Error> {
    for i in 0..s.accounts.len() {
        let refresh = s.accounts[i].refresh.clone();
        s.http.refreshes += 1;
        let value = s.http.token(&[
            ("grant_type", "refresh_token"),
            ("refresh_token", &refresh),
            ("client_id", "cli"),
        ])?;
        let token = text(&value["access_token"])?;
        require(
            s.http.sync(token)?["userDecryption"]["userKeyId"] == s.ids[i],
            "User-key-ID write invalidated refresh authority or metadata",
        )?;
        check_note(&mut s.http, &s.accounts[i])?;
        require(
            s.http.revision(&s.accounts[i].token)? == s.revisions[i],
            "Read or refresh changed account revision",
        )?;
    }
    s.unchanged()
}
pub fn run() -> Result<(), Error> {
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        before: Vec::new(),
        revisions: Vec::new(),
        ids: vec![
            String::new(),
            format!("{}\0Ω", "opaque-雪".repeat(100)),
            "positional ID 雪\0".into(),
        ],
        passed: Vec::new(),
        receipt: receipt_file("BW_USER_KEY_ID_RECEIPT")?,
        finished: false,
    };
    s.receipt("running")?;
    for _ in 0..3 {
        let account = seed(&mut s.http)?;
        s.before.push(s.http.snapshot(&account.token)?);
        s.revisions.push(s.http.revision(&account.token)?);
        s.accounts.push(account);
    }
    for (name, case) in CASES {
        eprintln!("User-key-ID case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.passed.len() == CASE_COUNT && s.http.logins == 3 && s.http.refreshes == 3,
        "User-key-ID proof budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS user-key-ID: {} cases, {} HTTP requests, 3 password logins, 3 refreshes",
        CASE_COUNT, s.http.requests
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sync_metadata_requires_explicit_nullable_string_and_keeps_empty_initialized() {
        for value in [
            json!({}),
            json!({"userDecryption":{}}),
            json!({"userDecryption":{"userKeyId":1}}),
        ] {
            assert!(sync_key_id(&value).is_err());
        }
        for id in [Value::Null, json!(""), json!("opaque\0雪")] {
            let value = json!({"userDecryption":{"userKeyId":id}});
            assert!(sync_key_id(&value).is_ok_and(|actual| actual == &id));
        }
    }
    #[test]
    fn snapshot_normalization_changes_only_key_id_metadata() {
        let initial = json!({"userDecryption":{"userKeyId":null,"future":"retained"},"profile":{"key":"retained"},"ciphers":[{"id":"cipher","notes":"opaque","revisionDate":"same"}]});
        let mut migrated = initial.clone();
        migrated["userDecryption"]["userKeyId"] = json!("opaque\0雪");
        assert!(
            normalized_sync(initial.clone()).unwrap() == normalized_sync(migrated.clone()).unwrap()
        );
        migrated["ciphers"][0]["notes"] = json!("changed");
        assert!(normalized_sync(initial).unwrap() != normalized_sync(migrated).unwrap());
    }
}
