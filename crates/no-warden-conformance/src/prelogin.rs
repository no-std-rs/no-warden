//! Independently authored MIT/Apache-2.0 discovery contracts for the two public
//! identity prelogin aliases. The `/api` legacy extension is not upstream parity.
//! Unknown choices are compared within one server, never across private secrets.
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
pub(crate) const ROUTES: [&str; 2] = [
    "/identity/accounts/prelogin",
    "/identity/accounts/prelogin/password",
];
pub(crate) const NOTE: &str = "Prelogin KDF discovery preserves this note 雪\0";
type Case = fn(&mut Suite) -> Result<(), Error>;
const CASES: [(&str, Case); CASE_COUNT] = [
    ("prelogin_known_pbkdf2_projection", pbkdf2),
    ("prelogin_known_argon2_projection", argon2),
    ("prelogin_normalized_email_lookup", normalized),
    ("prelogin_unknown_stability_and_catalog", unknown),
    ("prelogin_schema_media_and_utf8_guards", guards),
    ("prelogin_public_semantics_and_state_preservation", public),
];
type Kdf = (i32, i32, Option<i32>, Option<i32>);
pub(crate) struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, Error> {
        if self.status != expected {
            eprintln!(
                "Prelogin HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Prelogin HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, Error> {
        serde_json::from_slice(&self.bytes).map_err(|_| Error("Prelogin response was not JSON"))
    }
    fn rejected(self, status: u16) -> Result<(), Error> {
        let reply = self.status(status)?;
        if let Ok(value) = serde_json::from_slice::<Value>(&reply.bytes) {
            require(
                ["access_token", "refresh_token", "key", "privateKey"]
                    .iter()
                    .all(|k| value.get(k).is_none()),
                "Rejected prelogin returned credential authority",
            )?;
        }
        Ok(())
    }
}
pub(crate) struct Http {
    pub(crate) server: String,
    client: Client,
    pub(crate) requests: usize,
    pub(crate) logins: usize,
    decoded: usize,
}
impl Http {
    pub(crate) fn new() -> Result<Self, Error> {
        Ok(Self {
            server: server(),
            client: http_client()?,
            requests: 0,
            logins: 0,
            decoded: 0,
        })
    }
    fn read(response: reqwest::blocking::Response) -> Result<Reply, Error> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(16 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| Error("Prelogin private capture failed"))?;
        require(
            bytes.len() <= 16 * 1024 * 1024,
            "Prelogin capture exceeded bound",
        )?;
        Ok(Reply { status, bytes })
    }
    fn request(
        &mut self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<&[u8]>,
        media: Option<&str>,
    ) -> Result<Reply, Error> {
        self.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.server));
        if let Some(bearer) = bearer {
            request = request.bearer_auth(bearer);
        }
        if let Some(body) = body {
            request = request.body(body.to_vec());
            if let Some(media) = media {
                request = request.header("Content-Type", media);
            }
        }
        Self::read(
            request
                .send()
                .map_err(|_| Error("Prelogin HTTP request failed"))?,
        )
    }
    pub(crate) fn json(
        &mut self,
        method: Method,
        path: &str,
        bearer: &str,
        body: Option<&Value>,
    ) -> Result<Value, Error> {
        self.request(
            method,
            path,
            Some(bearer),
            body.map(Value::to_string).as_deref().map(str::as_bytes),
            Some("application/json"),
        )?
        .status(200)?
        .json()
    }
    pub(crate) fn prelogin(
        &mut self,
        path: &str,
        email: &str,
        bearer: Option<&str>,
        media: Option<&str>,
    ) -> Result<Value, Error> {
        self.decoded += 1;
        require(
            self.decoded <= 32,
            "Prelogin decoded request budget exceeded",
        )?;
        let body = json!({"email":email,"ignored":{"email":"ignored@example.test"}}).to_string();
        let value = self
            .request(Method::POST, path, bearer, Some(body.as_bytes()), media)?
            .status(200)?
            .json()?;
        shape(&value)?;
        Ok(value)
    }
    fn login(&mut self, fixture: &Value) -> Result<String, Error> {
        self.requests += 1;
        self.logins += 1;
        require(
            self.logins <= 2,
            "Prelogin password attempt budget exceeded",
        )?;
        let value = Self::read(
            self.client
                .post(format!("{}/identity/connect/token", self.server))
                .form(&[
                    ("grant_type", "password"),
                    ("client_id", "cli"),
                    ("scope", "api offline_access"),
                    ("username", text(&fixture["email"])?),
                    ("password", text(&fixture["masterPasswordHash"])?),
                    ("deviceIdentifier", "Prelogin-Discovery-Fixture"),
                    ("deviceName", "Prelogin discovery fixture"),
                    ("deviceType", "8"),
                ])
                .send()
                .map_err(|_| Error("Prelogin fixture login failed"))?,
        )?
        .status(200)?
        .json()?;
        Ok(text(&value["access_token"])?.into())
    }
    fn snapshot(&mut self, token: &str) -> Result<Value, Error> {
        let sync = self.json(Method::GET, "/api/sync", token, None)?;
        let keys = self.json(Method::GET, "/api/accounts/keys", token, None)?;
        let devices = self.json(Method::GET, "/api/devices", token, None)?;
        let revision = self.json(Method::GET, "/api/accounts/revision-date", token, None)?;
        Ok(json!({"sync":sync,"keys":keys,"devices":devices,"revision":revision}))
    }
}
fn i32_field(value: &Value) -> Result<i32, Error> {
    value
        .as_i64()
        .and_then(|n| i32::try_from(n).ok())
        .ok_or(Error("Prelogin signed KDF field invalid"))
}
fn optional_i32(value: &Value) -> Result<Option<i32>, Error> {
    if value.is_null() {
        Ok(None)
    } else {
        i32_field(value).map(Some)
    }
}
fn shape(value: &Value) -> Result<Kdf, Error> {
    const FIELDS: [&str; 6] = [
        "kdf",
        "kdfIterations",
        "kdfMemory",
        "kdfParallelism",
        "kdfSettings",
        "salt",
    ];
    require(
        value
            .as_object()
            .is_some_and(|o| o.len() == 6 && FIELDS.iter().all(|k| o.contains_key(*k))),
        "Prelogin top-level projection differed",
    )?;
    let kdf = (
        i32_field(&value["kdf"])?,
        i32_field(&value["kdfIterations"])?,
        optional_i32(&value["kdfMemory"])?,
        optional_i32(&value["kdfParallelism"])?,
    );
    require(
        value["salt"].is_null()
            && value["kdfSettings"]
                == json!({"kdfType":kdf.0,"iterations":kdf.1,"memory":kdf.2,"parallelism":kdf.3}),
        "Prelogin legacy and modern settings differed or salt was not null",
    )?;
    Ok(kdf)
}
fn in_catalog(kdf: Kdf) -> bool {
    matches!(
        kdf,
        (0, 600000, None, None)
            | (0, 100000, None, None)
            | (0, 5000, None, None)
            | (1, 3, Some(64), Some(4))
            | (1, 6, Some(32), Some(4))
    )
}
pub(crate) fn expected(fixture: &Value, value: &Value) -> Result<(), Error> {
    let actual = shape(value)?;
    require(
        actual
            == (
                i32_field(&fixture["kdf"])?,
                i32_field(&fixture["kdfIterations"])?,
                optional_i32(&fixture["kdfMemory"])?,
                optional_i32(&fixture["kdfParallelism"])?,
            ),
        "Known prelogin KDF settings differed from registered settings",
    )
}
pub(crate) fn seed_fixture(server: &str, argon: bool) -> Result<(Value, String), Error> {
    let email = format!("prelogin-café-{}@example.test", Uuid::new_v4());
    let password = Uuid::new_v4().to_string();
    let value = if argon {
        fixture::registration_argon2(&email, &password, 3, 64, 4)
    } else {
        fixture::registration(&email, &password, 600_000)
    }
    .map_err(|_| Error("Prelogin account registration failed"))?;
    fixture::register_modern_fixture(server, &value)
        .map_err(|_| Error("Prelogin modern registration failed"))?;
    Ok((value, password))
}
struct Account {
    fixture: Value,
    token: String,
    user_key: [u8; 64],
    cipher_id: String,
    before: Value,
}
struct Suite {
    http: Http,
    accounts: Vec<Account>,
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
            &json!({"schemaVersion":1,"status":status,"expectedCases":CASE_COUNT,"passedCases":self.passed.len(),"cases":self.passed,"httpRequests":self.http.requests,"decodedPreloginRequests":self.http.decoded,"passwordCredentialAttempts":self.http.logins,"fixtureRegistrations":self.accounts.len(),"legacyApiExtensionCompared":false,"unknownCatalogSelectionComparedAcrossServers":false}),
        )
    }
}
fn known(s: &mut Suite, index: usize) -> Result<(), Error> {
    let fixture = &s.accounts[index].fixture;
    for route in ROUTES {
        let response = s.http.prelogin(
            route,
            text(&fixture["email"])?,
            None,
            Some("application/json"),
        )?;
        expected(fixture, &response)?;
    }
    Ok(())
}
fn pbkdf2(s: &mut Suite) -> Result<(), Error> {
    known(s, 0)
}
fn argon2(s: &mut Suite) -> Result<(), Error> {
    known(s, 1)
}
fn normalized(s: &mut Suite) -> Result<(), Error> {
    for account in &s.accounts {
        let email = format!(
            "\u{2003}\t{}\n\u{3000}",
            text(&account.fixture["email"])?.to_uppercase()
        );
        for route in ROUTES {
            let response = s
                .http
                .prelogin(route, &email, None, Some("application/json"))?;
            expected(&account.fixture, &response)?;
        }
    }
    Ok(())
}
fn unknown(s: &mut Suite) -> Result<(), Error> {
    for email in [
        format!("unknown-{}@example.test", Uuid::new_v4()),
        "opaque-Σ\0not-an-email".into(),
        String::new(),
    ] {
        let first = s
            .http
            .prelogin(ROUTES[0], &email, None, Some("application/json"))?;
        require(
            in_catalog(shape(&first)?),
            "Unknown prelogin KDF was outside the documented catalog",
        )?;
        let second = s
            .http
            .prelogin(ROUTES[1], &email, None, Some("application/json"))?;
        let normalized = format!("\u{2003}{}\t", email.to_lowercase());
        let third = s
            .http
            .prelogin(ROUTES[0], &normalized, None, Some("application/json"))?;
        require(
            first == second && first == third,
            "Unknown normalized prelogin settings were not stable within one server",
        )?;
    }
    Ok(())
}
fn guards(s: &mut Suite) -> Result<(), Error> {
    for route in ROUTES {
        for (body, status) in [
            ("{", 400),
            ("{}", 422),
            ("[]", 422),
            (r#"{"email":null}"#, 422),
            (r#"{"email":1}"#, 422),
            (r#"{"email":[]}"#, 422),
            (r#"{"Email":"ignored"}"#, 422),
            (r#"{"email":"one","email":"two"}"#, 422),
            (r#"["one","surplus"]"#, 400),
        ] {
            s.http
                .request(
                    Method::POST,
                    route,
                    None,
                    Some(body.as_bytes()),
                    Some("application/json"),
                )?
                .rejected(status)?;
        }
        s.http
            .request(
                Method::POST,
                route,
                None,
                Some(b"{\"email\":\"known@example.test\",\"ignored\":\"\xff\"}"),
                Some("application/json"),
            )?
            .rejected(400)?;
        for media in [None, Some("text/plain"), Some("application/problem+json")] {
            let response =
                s.http
                    .prelogin(route, text(&s.accounts[0].fixture["email"])?, None, media)?;
            expected(&s.accounts[0].fixture, &response)?;
        }
    }
    Ok(())
}
fn public(s: &mut Suite) -> Result<(), Error> {
    for route in ROUTES {
        for bearer in ["invalid-prelogin-bearer", s.accounts[1].token.as_str()] {
            let response = s.http.prelogin(
                &format!("{route}?email=foreign&organizationId=ignored"),
                text(&s.accounts[0].fixture["email"])?,
                Some(bearer),
                Some("application/json"),
            )?;
            expected(&s.accounts[0].fixture, &response)?;
        }
        for method in [Method::GET, Method::PUT, Method::DELETE, Method::PATCH] {
            s.http
                .request(method, route, None, None, None)?
                .rejected(404)?;
        }
    }
    for account in &s.accounts {
        require(
            s.http.snapshot(&account.token)? == account.before,
            "Public prelogin discovery changed protected account or vault state",
        )?;
        let value = s.http.json(
            Method::GET,
            &format!("/api/ciphers/{}", account.cipher_id),
            &account.token,
            None,
        )?;
        require(
            fixture::decrypt(text(&value["notes"])?, &account.user_key)
                .is_ok_and(|p| p == NOTE.as_bytes()),
            "Prelogin discovery changed authenticated vault contents",
        )?;
    }
    Ok(())
}
pub fn run() -> Result<(), Error> {
    let mut s = Suite {
        http: Http::new()?,
        accounts: Vec::new(),
        passed: Vec::new(),
        receipt: receipt_file("BW_PRELOGIN_RECEIPT")?,
        finished: false,
    };
    s.receipt("running")?;
    for argon in [false, true] {
        let (fixture, password) = seed_fixture(&s.http.server, argon)?;
        let token = s.http.login(&fixture)?;
        let profile = s
            .http
            .json(Method::GET, "/api/accounts/profile", &token, None)?;
        let encrypted = fixture::encrypted_fixture_value(&fixture, &password, NOTE.as_bytes())
            .map_err(|_| Error("Prelogin fixture field encryption failed"))?;
        let value=s.http.json(Method::POST,"/api/ciphers",&token,Some(&json!({"type":2,"encryptedFor":profile["id"],"name":encrypted,"notes":encrypted,"secureNote":{"type":0}})))?;
        let cipher_id = text(&value["id"])?.into();
        let user_key = fixture::fixture_user_key(&fixture, &password)
            .map_err(|_| Error("Prelogin fixture key unwrap failed"))?;
        let before = s.http.snapshot(&token)?;
        s.accounts.push(Account {
            fixture,
            token,
            user_key,
            cipher_id,
            before,
        });
    }
    for (name, case) in CASES {
        eprintln!("Prelogin case: {name}");
        case(&mut s)?;
        s.passed.push(name);
        s.receipt("running")?;
    }
    require(
        s.http.logins == 2 && s.http.decoded == 27 && s.passed.len() == CASE_COUNT,
        "Prelogin case or identity budget differed",
    )?;
    s.receipt("passed")?;
    s.finished = true;
    println!(
        "PASS prelogin: {} cases, {} HTTP requests, {} decoded prelogin requests, 2 password logins",
        CASE_COUNT, s.http.requests, s.http.decoded
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn valid() -> Value {
        json!({"kdf":1,"kdfIterations":3,"kdfMemory":64,"kdfParallelism":4,"kdfSettings":{"kdfType":1,"iterations":3,"memory":64,"parallelism":4},"salt":null})
    }
    #[test]
    fn prelogin_projection_validator_rejects_missing_extra_and_disagreeing_metadata() {
        let value = valid();
        assert!(shape(&value).is_ok());
        for field in ["salt", "kdf", "kdfSettings"] {
            let mut bad = value.clone();
            bad.as_object_mut().unwrap().remove(field);
            assert!(shape(&bad).is_err());
        }
        let mut bad = value.clone();
        bad["key"] = json!("unexpected");
        assert!(shape(&bad).is_err());
        let mut bad = value.clone();
        bad["kdfSettings"]["iterations"] = json!(4);
        assert!(shape(&bad).is_err());
        let mut bad = value;
        bad["salt"] = json!("");
        assert!(shape(&bad).is_err());
    }
    #[test]
    fn prelogin_unknown_catalog_does_not_accept_arbitrary_or_invalid_settings() {
        for tuple in [
            (0, 600000, None, None),
            (0, 100000, None, None),
            (0, 5000, None, None),
            (1, 3, Some(64), Some(4)),
            (1, 6, Some(32), Some(4)),
        ] {
            assert!(in_catalog(tuple));
        }
        for tuple in [
            (0, 700000, None, None),
            (1, 3, None, Some(4)),
            (-1, 3, None, None),
        ] {
            assert!(!in_catalog(tuple));
        }
    }
}
