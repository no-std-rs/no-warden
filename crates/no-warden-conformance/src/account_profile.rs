//! Portable contracts for personal profile updates and avatar-color updates.
//!
//! Assertions compare private in-memory snapshots without displaying their
//! contents. Diagnostics and receipts contain authored names and counts only.
//! Profile names and avatar colors are opaque strings with UTF-8 byte limits.

use crate::fixture;
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use std::{
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    thread,
    time::Duration,
};
use uuid::Uuid;

type Case = fn(&mut Suite) -> Result<(), AccountProfileError>;
const CASES: [(&str, Case); 8] = [
    (
        "account_profile_aliases_exact_names",
        account_profile_aliases_exact_names,
    ),
    (
        "account_profile_utf8_byte_boundaries",
        account_profile_utf8_byte_boundaries,
    ),
    (
        "account_avatar_values_and_clearing",
        account_avatar_values_and_clearing,
    ),
    (
        "account_profile_ignored_fields",
        account_profile_ignored_fields,
    ),
    (
        "account_profile_schema_rejections",
        account_profile_schema_rejections,
    ),
    (
        "account_avatar_schema_rejections",
        account_avatar_schema_rejections,
    ),
    (
        "account_profile_repeated_updates",
        account_profile_repeated_updates,
    ),
    (
        "account_profile_unauthenticated_rejections",
        account_profile_unauthenticated_rejections,
    ),
];
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// Static diagnostics never retain URLs, request bodies, or response contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountProfileError(&'static str);
impl fmt::Display for AccountProfileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for AccountProfileError {}

fn require(condition: bool, message: &'static str) -> Result<(), AccountProfileError> {
    if condition {
        Ok(())
    } else {
        Err(AccountProfileError(message))
    }
}
fn text(value: &Value) -> Result<&str, AccountProfileError> {
    value.as_str().ok_or(AccountProfileError(
        "Required profile response string missing",
    ))
}

struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, AccountProfileError> {
        if self.status != expected {
            eprintln!(
                "Profile HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(
            self.status == expected,
            "Profile HTTP response status differed",
        )?;
        Ok(self)
    }
    fn json(self) -> Result<Value, AccountProfileError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| AccountProfileError("Profile response was not valid JSON"))
    }
}

#[derive(Clone)]
struct Account {
    token: String,
    id: String,
    fixture: Value,
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
    accounts: Vec<Account>,
    requests: usize,
    logins: usize,
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
    fn write_receipt(&mut self, status: &'static str) -> Result<(), AccountProfileError> {
        if let Some(file) = &mut self.receipt {
            let record = json!({"schemaVersion":1,"status":status,"cases":self.passed,
                "passedCases":self.passed.len(),"expectedCases":CASES.len(),
                "httpRequests":self.requests,"identityLogins":self.logins});
            file.seek(SeekFrom::Start(0))
                .map_err(|_| AccountProfileError("Profile receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| AccountProfileError("Profile receipt update failed"))?;
            file.write_all(record.to_string().as_bytes())
                .map_err(|_| AccountProfileError("Profile receipt write failed"))?;
            file.sync_all()
                .map_err(|_| AccountProfileError("Profile receipt persistence failed"))?;
        }
        Ok(())
    }
    fn read(&self, response: reqwest::blocking::Response) -> Result<Reply, AccountProfileError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AccountProfileError("Profile response read failed"))?;
        require(
            bytes.len() as u64 <= MAX_RESPONSE_BYTES,
            "Profile response exceeded the capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn request(
        &mut self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Reply, AccountProfileError> {
        self.requests += 1;
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.server));
        if let Some(token) = token {
            request = request.bearer_auth(token);
        }
        if let Some(body) = body {
            request = request
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .body(body.to_vec());
        }
        let response = request
            .send()
            .map_err(|_| AccountProfileError("Profile HTTP request failed"))?;
        self.read(response)
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, AccountProfileError> {
        let body = body.map(Value::to_string);
        self.request(
            method,
            path,
            Some(token),
            body.as_deref().map(str::as_bytes),
        )?
        .status(200)?
        .json()
    }
    fn login(&mut self, body: &Value) -> Result<String, AccountProfileError> {
        let device = Uuid::new_v4().to_string();
        let form = [
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("deviceIdentifier", device.as_str()),
            ("deviceType", "8"),
            ("deviceName", "no-warden-profile-conformance"),
            ("username", text(&body["email"])?),
            ("password", text(&body["masterPasswordHash"])?),
        ];
        self.requests += 1;
        self.logins += 1;
        let response = self
            .client
            .post(format!("{}/identity/connect/token", self.server))
            .form(&form)
            .send()
            .map_err(|_| AccountProfileError("Profile fixture login failed"))?;
        let result = self.read(response)?.status(200)?.json()?;
        Ok(text(&result["access_token"])?.to_owned())
    }
    fn snapshot(&mut self, token: &str) -> Result<Snapshot, AccountProfileError> {
        let profile = self.json(Method::GET, "/api/accounts/profile", token, None)?;
        let sync = self.json(Method::GET, "/api/sync", token, None)?;
        let revision = self
            .json(Method::GET, "/api/accounts/revision-date", token, None)?
            .as_i64()
            .ok_or(AccountProfileError(
                "Profile account revision was not an integer",
            ))?;
        Ok(Snapshot {
            profile,
            sync,
            revision,
        })
    }
    fn seed_vault(&mut self, account: &Account) -> Result<(), AccountProfileError> {
        let encrypted = text(&account.fixture["key"])?;
        let folder = self.json(
            Method::POST,
            "/api/folders",
            &account.token,
            Some(&json!({"name":encrypted})),
        )?;
        let folder = text(&folder["id"])?;
        let cipher = self.json(
            Method::POST,
            "/api/ciphers",
            &account.token,
            Some(&json!({
                "type":2,"name":encrypted,"notes":encrypted,"folderId":folder,
                "encryptedFor":account.id,"secureNote":{"type":0,"futureOpaqueField":encrypted},
            })),
        )?;
        require(
            cipher["folderId"] == folder,
            "Profile vault fixture lost its folder association",
        )
    }
    fn mutate(
        &mut self,
        method: Method,
        path: &str,
        body: &Value,
        field: &str,
        value: Value,
    ) -> Result<(), AccountProfileError> {
        let token = self.accounts[0].token.clone();
        let mut expected = self.snapshot(&token)?;
        let revision = expected.revision;
        expected.profile[field] = value;
        expected.sync["profile"] = expected.profile.clone();
        thread::sleep(Duration::from_millis(10));
        let response = self.json(method, path, &token, Some(body))?;
        require(
            response == expected.profile,
            "Profile mutation response changed unrelated fields or opaque values",
        )?;
        let actual = self.snapshot(&token)?;
        require(
            actual.revision > revision,
            "Profile mutation did not advance account revision",
        )?;
        expected.revision = actual.revision;
        require(
            actual == expected,
            "Profile mutation changed unrelated account, key, or vault data",
        )
    }
    fn reject_bodies(
        &mut self,
        method: Method,
        path: &str,
        bodies: &[&str],
        expected: u16,
    ) -> Result<(), AccountProfileError> {
        let token = self.accounts[0].token.clone();
        for (index, body) in bodies.iter().enumerate() {
            let response =
                self.request(method.clone(), path, Some(&token), Some(body.as_bytes()))?;
            if response.status != expected {
                eprintln!(
                    "Profile JSON fixture {}, method {}",
                    index + 1,
                    method.as_str()
                );
            }
            response.status(expected)?;
        }
        Ok(())
    }
}

fn account_profile_aliases_exact_names(s: &mut Suite) -> Result<(), AccountProfileError> {
    let token = s.accounts[0].token.clone();
    let before = s.snapshot(&token)?;
    require(
        s.json(Method::GET, "/api/accounts/profile", &token, None)? == before.profile
            && s.json(Method::GET, "/api/sync", &token, None)? == before.sync,
        "Profile reads changed persisted values",
    )?;
    require(
        s.snapshot(&token)? == before,
        "Profile reads advanced account revision",
    )?;
    for method in [Method::PUT, Method::POST] {
        for name in ["", "  unchanged whitespace  ", "雪\\\"🔐", "\0\t\r\n\u{1}"] {
            s.mutate(
                method.clone(),
                "/api/accounts/profile",
                &json!({"name":name}),
                "name",
                json!(name),
            )?;
        }
    }
    Ok(())
}

fn account_profile_utf8_byte_boundaries(s: &mut Suite) -> Result<(), AccountProfileError> {
    let token = s.accounts[0].token.clone();
    for method in [Method::PUT, Method::POST] {
        for name in [
            "x".repeat(50),
            "é".repeat(25),
            format!("{}é", "🔐".repeat(12)),
        ] {
            s.mutate(
                method.clone(),
                "/api/accounts/profile",
                &json!({"name":name}),
                "name",
                json!(name),
            )?;
        }
        let before = s.snapshot(&token)?;
        for name in [
            "x".repeat(51),
            format!("{}a", "é".repeat(25)),
            format!("{}雪", "é".repeat(24)),
        ] {
            s.request(
                method.clone(),
                "/api/accounts/profile",
                Some(&token),
                Some(json!({"name":name}).to_string().as_bytes()),
            )?
            .status(400)?;
        }
        require(
            s.snapshot(&token)? == before,
            "Rejected UTF-8 name length changed profile or revision",
        )?;
    }
    Ok(())
}

fn account_avatar_values_and_clearing(s: &mut Suite) -> Result<(), AccountProfileError> {
    for color in ["#12AbcF", "nothex!", "雪abcd", "éabcde"] {
        s.mutate(
            Method::PUT,
            "/api/accounts/avatar",
            &json!({"avatarColor":color}),
            "avatarColor",
            json!(color),
        )?;
    }
    s.mutate(
        Method::PUT,
        "/api/accounts/avatar",
        &json!(["nothex!"]),
        "avatarColor",
        json!("nothex!"),
    )?;
    for body in [json!({}), json!({"avatarColor":null}), json!([null])] {
        s.mutate(
            Method::PUT,
            "/api/accounts/avatar",
            &json!({"avatarColor":"#abcdef"}),
            "avatarColor",
            json!("#abcdef"),
        )?;
        s.mutate(
            Method::PUT,
            "/api/accounts/avatar",
            &body,
            "avatarColor",
            Value::Null,
        )?;
    }
    let token = s.accounts[0].token.clone();
    let before = s.snapshot(&token)?;
    for color in ["", "123456", "12345678", "雪abc", "雪abcde", "雪abcdef"] {
        s.request(
            Method::PUT,
            "/api/accounts/avatar",
            Some(&token),
            Some(json!({"avatarColor":color}).to_string().as_bytes()),
        )?
        .status(400)?;
    }
    require(
        s.snapshot(&token)? == before,
        "Rejected avatar byte length changed profile or revision",
    )
}

fn account_profile_ignored_fields(s: &mut Suite) -> Result<(), AccountProfileError> {
    let foreign = s.accounts[1].clone();
    for method in [Method::PUT, Method::POST] {
        let name = "Only this name changes";
        let body = json!({"name":name,"id":foreign.id,"userId":foreign.id,
            "email":foreign.fixture["email"],"key":"ignored","privateKey":"ignored",
            "accountKeys":{"ignored":true},"avatarColor":{"ignored":true},
            "culture":"ignored","revisionDate":"1900-01-01T00:00:00Z","futureField":["ignored"]});
        s.mutate(method, "/api/accounts/profile", &body, "name", json!(name))?;
    }
    let body = json!({"avatarColor":"nothex!","name":{"ignored":true},"id":foreign.id,
        "email":foreign.fixture["email"],"key":"ignored","privateKey":"ignored","futureField":true});
    s.mutate(
        Method::PUT,
        "/api/accounts/avatar",
        &body,
        "avatarColor",
        json!("nothex!"),
    )?;
    // Unknown field spelling remains ignored, so the absent real field clears.
    s.mutate(
        Method::PUT,
        "/api/accounts/avatar",
        &json!({"AvatarColor":"ignored","name":7}),
        "avatarColor",
        Value::Null,
    )
}

fn account_profile_schema_rejections(s: &mut Suite) -> Result<(), AccountProfileError> {
    let token = s.accounts[0].token.clone();
    // A required one-field struct also accepts [name] in declaration order.
    s.mutate(
        Method::PUT,
        "/api/accounts/profile",
        &json!(["Positional profile"]),
        "name",
        json!("Positional profile"),
    )?;
    let before = s.snapshot(&token)?;
    let invalid = [
        "{}",
        "null",
        "true",
        "[]",
        "[null]",
        "[1]",
        "{\"name\":null}",
        "{\"name\":7}",
        "{\"name\":false}",
        "{\"name\":[]}",
        "{\"name\":{}}",
        "{\"Name\":\"wrongcase\"}",
        "{\"name\":\"a\",\"name\":\"b\"}",
        "{\"name\":\"a\",\"na\\u006de\":\"b\"}",
    ];
    let malformed = [
        "",
        "{",
        "{\"name\":",
        "{\"name\":\"valid\"} trailing",
        "{\"name\":\"valid\"}{}",
        "[\"valid\",0]",
    ];
    for method in [Method::PUT, Method::POST] {
        s.reject_bodies(method.clone(), "/api/accounts/profile", &invalid, 422)?;
        s.reject_bodies(method, "/api/accounts/profile", &malformed, 400)?;
    }
    require(
        s.snapshot(&token)? == before,
        "Rejected profile JSON changed state or revision",
    )
}

fn account_avatar_schema_rejections(s: &mut Suite) -> Result<(), AccountProfileError> {
    let token = s.accounts[0].token.clone();
    let before = s.snapshot(&token)?;
    let invalid = [
        "[]",
        "null",
        "true",
        "7",
        "{\"avatarColor\":1}",
        "{\"avatarColor\":false}",
        "{\"avatarColor\":[]}",
        "{\"avatarColor\":{}}",
        "[1]",
        "[false]",
        "{\"avatarColor\":null,\"avatarColor\":null}",
        "{\"avatarColor\":\"1234567\",\"avatar\\u0043olor\":null}",
    ];
    let malformed = [
        "",
        "{",
        "{\"avatarColor\":",
        "{\"avatarColor\":null} trailing",
        "{\"avatarColor\":null}{}",
        "[null,0]",
    ];
    s.reject_bodies(Method::PUT, "/api/accounts/avatar", &invalid, 422)?;
    s.reject_bodies(Method::PUT, "/api/accounts/avatar", &malformed, 400)?;
    require(
        s.snapshot(&token)? == before,
        "Rejected avatar JSON changed state or revision",
    )
}

fn account_profile_repeated_updates(s: &mut Suite) -> Result<(), AccountProfileError> {
    for method in [Method::PUT, Method::POST] {
        for _ in 0..2 {
            s.mutate(
                method.clone(),
                "/api/accounts/profile",
                &json!({"name":"Repeated exact name"}),
                "name",
                json!("Repeated exact name"),
            )?;
        }
    }
    for _ in 0..2 {
        s.mutate(
            Method::PUT,
            "/api/accounts/avatar",
            &json!({"avatarColor":"#abcdef"}),
            "avatarColor",
            json!("#abcdef"),
        )?;
    }
    Ok(())
}

fn account_profile_unauthenticated_rejections(s: &mut Suite) -> Result<(), AccountProfileError> {
    let token = s.accounts[0].token.clone();
    let before = s.snapshot(&token)?;
    for method in [Method::PUT, Method::POST] {
        s.request(
            method,
            "/api/accounts/profile",
            None,
            Some(b"{\"name\":\"unauthenticated\"}"),
        )?
        .status(401)?;
    }
    s.request(
        Method::PUT,
        "/api/accounts/avatar",
        None,
        Some(b"{\"avatarColor\":\"#abcdef\"}"),
    )?
    .status(401)?;
    require(
        s.snapshot(&token)? == before,
        "Unauthenticated profile requests changed state or revision",
    )
}

fn receipt() -> Result<Option<fs::File>, AccountProfileError> {
    let Some(path) = std::env::var_os("BW_PROFILE_RECEIPT") else {
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
        .map_err(|_| AccountProfileError("Private profile receipt creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| AccountProfileError("Private profile receipt permissions failed"))?;
    }
    Ok(Some(file))
}

/// Exercise both profile aliases and avatar updates with two disposable accounts.
///
/// Each account logs in once. Registration transport is delegated to the shared
/// fixture helper and excluded from the request count. No failed mutation is
/// retried; snapshots retain whole profiles, sync results, and account revisions.
pub fn run() -> Result<(), AccountProfileError> {
    let server = std::env::var("BW_E2E_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8000".into());
    let server = server.trim_end_matches('/').to_owned();
    let url = reqwest::Url::parse(&server)
        .map_err(|_| AccountProfileError("Invalid profile test server configuration"))?;
    require(
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Invalid profile test server configuration",
    )?;
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| AccountProfileError("Profile HTTP client initialization failed"))?;
    let mut suite = Suite {
        server,
        client,
        accounts: Vec::new(),
        requests: 0,
        logins: 0,
        passed: Vec::new(),
        receipt: receipt()?,
        finished: false,
    };
    suite.write_receipt("running")?;
    for _ in 0..2 {
        let email = format!("profile-{}@example.test", Uuid::new_v4());
        let password = format!("Nw!{}", Uuid::new_v4());
        let body = fixture::seed_account(&suite.server, &email, &password)
            .map_err(|_| AccountProfileError("Profile fixture registration failed"))?;
        let token = suite.login(&body)?;
        let profile = suite.json(Method::GET, "/api/accounts/profile", &token, None)?;
        let id = text(&profile["id"])?.to_owned();
        let account = Account {
            token,
            id,
            fixture: body,
        };
        suite.seed_vault(&account)?;
        suite.accounts.push(account);
    }
    for (name, case) in CASES {
        let foreign = suite.accounts[1].token.clone();
        let before = suite.snapshot(&foreign)?;
        case(&mut suite)?;
        require(
            suite.snapshot(&foreign)? == before,
            "Profile case changed another account, keys, vault, or revision",
        )?;
        suite.passed.push(name);
        suite.write_receipt("running")?;
        println!("PASS {name}");
    }
    suite.write_receipt("passed")?;
    suite.finished = true;
    println!(
        "PASS profile: {} cases, {} HTTP requests, {} logins",
        suite.passed.len(),
        suite.requests,
        suite.logins
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn diagnostics_discard_profile_response_contents() {
        let error = Reply {
            status: 500,
            bytes: b"private-profile-marker".to_vec(),
        }
        .status(200)
        .err()
        .unwrap();
        assert!(error.to_string() == "Profile HTTP response status differed");
        assert!(!format!("{error:?}").contains("private-profile-marker"));
        let error = Reply {
            status: 200,
            bytes: b"private-profile-marker".to_vec(),
        }
        .json()
        .err()
        .unwrap();
        assert!(!format!("{error} {error:?}").contains("private-profile-marker"));
    }

    #[test]
    fn fixture_boundaries_measure_utf8_bytes() {
        for name in [
            "x".repeat(50),
            "é".repeat(25),
            format!("{}é", "🔐".repeat(12)),
        ] {
            assert_eq!(name.len(), 50);
        }
        for name in [
            "x".repeat(51),
            format!("{}a", "é".repeat(25)),
            format!("{}雪", "é".repeat(24)),
        ] {
            assert_eq!(name.len(), 51);
        }
        for color in ["#12AbcF", "nothex!", "雪abcd", "éabcde"] {
            assert_eq!(color.len(), 7);
        }
        for color in ["", "123456", "12345678", "雪abc", "雪abcde", "雪abcdef"] {
            assert_ne!(color.len(), 7);
        }
    }

    #[test]
    fn positional_forms_preserve_optional_avatar_clearing_and_error_classes() {
        #[derive(serde::Deserialize)]
        struct Profile {
            name: String,
        }
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Avatar {
            avatar_color: Option<String>,
        }
        assert!(serde_json::from_str::<Profile>("[\"name\"]").unwrap().name == "name");
        for body in ["{}", "[null]"] {
            assert!(
                serde_json::from_str::<Avatar>(body)
                    .unwrap()
                    .avatar_color
                    .is_none()
            );
        }
        assert!(
            serde_json::from_str::<Avatar>("[\"nothex!\"]")
                .unwrap()
                .avatar_color
                .as_deref()
                == Some("nothex!")
        );
        assert_eq!(
            serde_json::from_str::<Profile>("[]")
                .err()
                .unwrap()
                .classify(),
            serde_json::error::Category::Data
        );
        assert_eq!(
            serde_json::from_str::<Avatar>("[]")
                .err()
                .unwrap()
                .classify(),
            serde_json::error::Category::Data
        );
        assert_eq!(
            serde_json::from_str::<Profile>("[\"name\",0]")
                .err()
                .unwrap()
                .classify(),
            serde_json::error::Category::Syntax
        );
        assert_eq!(
            serde_json::from_str::<Avatar>("[null,0]")
                .err()
                .unwrap()
                .classify(),
            serde_json::error::Category::Syntax
        );
    }
}
