//! Portable checks for legacy personal account-key initialization and public lookup.
//!
//! Secrets stay in process memory. Diagnostics and the optional private receipt
//! contain authored case names, request counts, and numeric statuses only. These
//! cases do not claim account-key rotation or modern key-management API parity.

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

type Case = fn(&mut Suite) -> Result<(), AccountKeysError>;
const CASES: [(&str, Case); 8] = [
    (
        "account_keys_existing_pair_projection",
        account_keys_existing_pair_projection,
    ),
    ("account_keys_keyless_reads", account_keys_keyless_reads),
    (
        "account_keys_schema_and_syntax_rejections",
        account_keys_schema_and_syntax_rejections,
    ),
    (
        "account_keys_initialize_generated_pair",
        account_keys_initialize_generated_pair,
    ),
    (
        "account_keys_empty_and_opaque_initialization",
        account_keys_empty_and_opaque_initialization,
    ),
    (
        "account_keys_cross_user_public_lookup",
        account_keys_cross_user_public_lookup,
    ),
    (
        "account_keys_path_and_auth_guards",
        account_keys_path_and_auth_guards,
    ),
    (
        "account_keys_reinitialization_is_nonmutating",
        account_keys_reinitialization_is_nonmutating,
    ),
];
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

/// Static, redacted diagnostics never retain request or response values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccountKeysError(&'static str);
impl fmt::Display for AccountKeysError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for AccountKeysError {}

fn require(condition: bool, message: &'static str) -> Result<(), AccountKeysError> {
    if condition {
        Ok(())
    } else {
        Err(AccountKeysError(message))
    }
}
fn text(value: &Value) -> Result<&str, AccountKeysError> {
    value
        .as_str()
        .ok_or(AccountKeysError("Required response string missing"))
}

struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16, message: &'static str) -> Result<Self, AccountKeysError> {
        if self.status != expected {
            eprintln!(
                "Account-key HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, message)?;
        Ok(self)
    }
    fn json(self) -> Result<Value, AccountKeysError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| AccountKeysError("Account-key response was not valid JSON"))
    }
}

#[derive(Clone)]
struct Account {
    token: String,
    id: String,
    fixture: Value,
    pair: Option<(String, String)>, // private, public; presence is separate from emptiness.
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
    fn write_receipt(&mut self, status: &'static str) -> Result<(), AccountKeysError> {
        if let Some(file) = &mut self.receipt {
            let record = json!({"schemaVersion":1,"status":status,"cases":self.passed,
                "passedCases":self.passed.len(),"expectedCases":CASES.len(),
                "httpRequests":self.requests,"identityLogins":self.logins});
            file.seek(SeekFrom::Start(0))
                .map_err(|_| AccountKeysError("Account-key receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| AccountKeysError("Account-key receipt update failed"))?;
            file.write_all(record.to_string().as_bytes())
                .map_err(|_| AccountKeysError("Account-key receipt write failed"))?;
            file.sync_all()
                .map_err(|_| AccountKeysError("Account-key receipt persistence failed"))?;
        }
        Ok(())
    }
    fn read(&self, response: reqwest::blocking::Response) -> Result<Reply, AccountKeysError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| AccountKeysError("Account-key response read failed"))?;
        require(
            bytes.len() as u64 <= MAX_RESPONSE_BYTES,
            "Account-key response exceeded the capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn request(
        &mut self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Reply, AccountKeysError> {
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
            .map_err(|_| AccountKeysError("Account-key HTTP request failed"))?;
        self.read(response)
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, AccountKeysError> {
        let encoded = body.map(Value::to_string);
        self.request(
            method,
            path,
            Some(token),
            encoded.as_deref().map(str::as_bytes),
        )?
        .status(200, "Account-key JSON request did not return 200")?
        .json()
    }
    fn login(&mut self, body: &Value) -> Result<String, AccountKeysError> {
        let device = Uuid::new_v4().to_string();
        let form = [
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("deviceIdentifier", device.as_str()),
            ("deviceType", "8"),
            ("deviceName", "no-warden-account-key-conformance"),
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
            .map_err(|_| AccountKeysError("Account-key fixture login failed"))?;
        let body = self
            .read(response)?
            .status(200, "Account-key fixture login rejected")?
            .json()?;
        Ok(text(&body["access_token"])?.to_owned())
    }
    fn snapshot(&mut self, token: &str) -> Result<Snapshot, AccountKeysError> {
        let profile = self.json(Method::GET, "/api/accounts/profile", token, None)?;
        let sync = self.json(Method::GET, "/api/sync", token, None)?;
        let revision = self
            .json(Method::GET, "/api/accounts/revision-date", token, None)?
            .as_i64()
            .ok_or(AccountKeysError(
                "Account-key account revision was not an integer",
            ))?;
        Ok(Snapshot {
            profile,
            sync,
            revision,
        })
    }
    fn snapshots(&mut self) -> Result<Vec<Snapshot>, AccountKeysError> {
        let tokens: Vec<_> = self
            .accounts
            .iter()
            .map(|account| account.token.clone())
            .collect();
        tokens.iter().map(|token| self.snapshot(token)).collect()
    }
    fn own_keys(&mut self, account: &Account) -> Result<Value, AccountKeysError> {
        self.json(Method::GET, "/api/accounts/keys", &account.token, None)
    }
    fn public_key(
        &mut self,
        reader: &Account,
        subject: &Account,
    ) -> Result<Value, AccountKeysError> {
        self.json(
            Method::GET,
            &format!("/api/users/{}/public-key", subject.id),
            &reader.token,
            None,
        )
    }
    fn seed_vault(&mut self, account: &Account) -> Result<(), AccountKeysError> {
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
            "Account-key vault fixture was not associated with its folder",
        )
    }
}

fn account_keys(private: &str, public: &str) -> Value {
    json!({"publicKeyEncryptionKeyPair":{"wrappedPrivateKey":private,"publicKey":public,
        "signedPublicKey":null,"object":"publicKeyEncryptionKeyPair"},
        "securityState":null,"signatureKeyPair":null,"object":"privateKeys"})
}
fn check_own_keys(value: &Value, account: &Account) -> Result<(), AccountKeysError> {
    let (private, public) = account
        .pair
        .as_ref()
        .ok_or(AccountKeysError("Account-key fixture has no expected pair"))?;
    let key = match account.fixture["key"].as_str() {
        Some("") | None => Value::Null,
        Some(key) => json!(key),
    };
    require(
        *value
            == json!({"key":key,"privateKey":private,"publicKey":public,
        "accountKeys":account_keys(private,public),"object":"keys"}),
        "Own account-key response projection differed",
    )
}
fn check_public_key(value: &Value, account: &Account) -> Result<(), AccountKeysError> {
    let (_, public) = account.pair.as_ref().ok_or(AccountKeysError(
        "Account-key fixture has no expected public key",
    ))?;
    require(
        *value == json!({"userId":account.id,"publicKey":public,"object":"userKey"}),
        "Public account-key response projection differed",
    )
}
fn check_initialization(
    before: Vec<Snapshot>,
    after: Vec<Snapshot>,
    changed: usize,
    account: &Account,
) -> Result<(), AccountKeysError> {
    let (private, public) = account
        .pair
        .as_ref()
        .ok_or(AccountKeysError("Initialized fixture has no expected pair"))?;
    require(
        before.len() == after.len(),
        "Account-key snapshot count differed",
    )?;
    for (index, (mut expected, actual)) in before.into_iter().zip(after).enumerate() {
        if index == changed {
            require(
                actual.revision > expected.revision,
                "Key initialization did not advance account revision",
            )?;
            expected.revision = actual.revision;
            expected.profile["privateKey"] = json!(private);
            expected.profile["accountKeys"] = account_keys(private, public);
            expected.sync["profile"] = expected.profile.clone();
        }
        require(
            actual == expected,
            "Account-key initialization changed unrelated profile or vault state",
        )?;
    }
    Ok(())
}

fn account_keys_existing_pair_projection(s: &mut Suite) -> Result<(), AccountKeysError> {
    let before = s.snapshots()?;
    let account = s.accounts[0].clone();
    check_own_keys(&s.own_keys(&account)?, &account)?;
    check_public_key(&s.public_key(&account, &account)?, &account)?;
    require(
        s.snapshots()? == before,
        "Account-key reads mutated a vault or revision",
    )
}

fn account_keys_keyless_reads(s: &mut Suite) -> Result<(), AccountKeysError> {
    let before = s.snapshots()?;
    let reader = s.accounts[0].clone();
    for index in [1, 2] {
        let account = s.accounts[index].clone();
        s.request(
            Method::GET,
            "/api/accounts/keys",
            Some(&account.token),
            None,
        )?
        .status(404, "Keyless account-key GET did not return 404")?;
        for token in [&account.token, &reader.token] {
            s.request(
                Method::GET,
                &format!("/api/users/{}/public-key", account.id),
                Some(token),
                None,
            )?
            .status(404, "Keyless public-key GET did not return 404")?;
        }
    }
    require(
        s.snapshots()? == before,
        "Missing-key reads mutated a vault or revision",
    )
}

fn account_keys_schema_and_syntax_rejections(s: &mut Suite) -> Result<(), AccountKeysError> {
    let before = s.snapshots()?;
    let invalid = [
        "{}",
        "null",
        "true",
        "[]",
        "[\"private\"]",
        "[null,\"public\"]",
        "[\"private\",null]",
        "{\"encryptedPrivateKey\":\"private\"}",
        "{\"publicKey\":\"public\"}",
        "{\"encryptedPrivateKey\":null,\"publicKey\":\"public\"}",
        "{\"encryptedPrivateKey\":1,\"publicKey\":\"public\"}",
        "{\"encryptedPrivateKey\":[],\"publicKey\":\"public\"}",
        "{\"encryptedPrivateKey\":\"private\",\"publicKey\":false}",
        "{\"encryptedPrivateKey\":\"private\",\"publicKey\":{}}",
        "{\"encryptedPrivateKey\":\"a\",\"encryptedPrivateKey\":\"b\",\"publicKey\":\"public\"}",
        "{\"encryptedPrivateKey\":\"private\",\"publicKey\":\"a\",\"publicKey\":\"b\"}",
        "{\"encryptedPrivateKey\":\"private\",\"publicKey\":\"a\",\"public\\u004bey\":\"b\"}",
        "{\"EncryptedPrivateKey\":\"private\",\"PublicKey\":\"public\"}",
    ];
    let malformed = [
        "",
        "{",
        "{\"encryptedPrivateKey\":",
        "{\"encryptedPrivateKey\":\"private\",\"publicKey\":\"public\"} trailing",
        "{\"encryptedPrivateKey\":\"private\",\"publicKey\":\"public\"}{}",
        "[\"private\",\"public\",0]",
    ];
    // Both keyed and keyless accounts must fail the JSON guard before the
    // handler's existing-pair policy; no rejected request may initialize keys.
    for account_index in [0, 1] {
        let token = s.accounts[account_index].token.clone();
        for (group, expected) in [(&invalid[..], 422), (&malformed[..], 400)] {
            for (index, body) in group.iter().enumerate() {
                let response = s.request(
                    Method::POST,
                    "/api/accounts/keys",
                    Some(&token),
                    Some(body.as_bytes()),
                )?;
                if response.status != expected {
                    eprintln!("Account-key JSON fixture {}, method POST", index + 1);
                }
                response.status(expected, "Account-key JSON rejection status differed")?;
            }
        }
    }
    require(
        s.snapshots()? == before,
        "Rejected account-key bodies mutated keys, vaults, or revisions",
    )
}

fn account_keys_initialize_generated_pair(s: &mut Suite) -> Result<(), AccountKeysError> {
    let before = s.snapshots()?;
    let mut account = s.accounts[1].clone();
    let private = text(&account.fixture["keys"]["encryptedPrivateKey"])?.to_owned();
    let public = text(&account.fixture["keys"]["publicKey"])?.to_owned();
    thread::sleep(Duration::from_millis(10));
    let result = s.json(
        Method::POST,
        "/api/accounts/keys",
        &account.token,
        Some(&json!({
            "encryptedPrivateKey":private,"publicKey":public,
            "privateKey":"ignored","key":"ignored","object":"ignored",
            "accountKeys":{"future":"ignored"},"futureOpaqueField":"ignored",
        })),
    )?;
    require(
        result == json!({"privateKey":private,"publicKey":public,"object":"keys"}),
        "Key initialization response did not have exactly three fields",
    )?;
    account.pair = Some((private, public));
    s.accounts[1] = account.clone();
    let after = s.snapshots()?;
    check_initialization(before, after, 1, &account)?;
    check_own_keys(&s.own_keys(&account)?, &account)
}

fn account_keys_empty_and_opaque_initialization(s: &mut Suite) -> Result<(), AccountKeysError> {
    let before = s.snapshots()?;
    let mut account = s.accounts[2].clone();
    let private = "";
    let public = "future-format.v999|opaque\\雪\"\n🔐";
    thread::sleep(Duration::from_millis(10));
    // KeysData's derived sequence order is encryptedPrivateKey, then publicKey.
    let result = s.json(
        Method::POST,
        "/api/accounts/keys",
        &account.token,
        Some(&json!([private, public])),
    )?;
    require(
        result == json!({"privateKey":private,"publicKey":public,"object":"keys"}),
        "Opaque key initialization changed field order, values, or projection",
    )?;
    account.pair = Some((private.into(), public.into()));
    s.accounts[2] = account.clone();
    let after = s.snapshots()?;
    check_initialization(before, after, 2, &account)?;
    check_own_keys(&s.own_keys(&account)?, &account)
}

fn account_keys_cross_user_public_lookup(s: &mut Suite) -> Result<(), AccountKeysError> {
    let before = s.snapshots()?;
    let accounts = s.accounts.clone();
    for reader in &accounts {
        for subject in &accounts {
            check_public_key(&s.public_key(reader, subject)?, subject)?;
        }
    }
    require(
        s.snapshots()? == before,
        "Cross-user public-key reads mutated accounts or vaults",
    )
}

fn account_keys_path_and_auth_guards(s: &mut Suite) -> Result<(), AccountKeysError> {
    let before = s.snapshots()?;
    let account = s.accounts[0].clone();
    let body = json!({"encryptedPrivateKey":"private","publicKey":"public"}).to_string();
    for (method, path, body) in [
        (Method::GET, "/api/accounts/keys".to_owned(), None),
        (
            Method::POST,
            "/api/accounts/keys".to_owned(),
            Some(body.as_bytes()),
        ),
        (
            Method::GET,
            format!("/api/users/{}/public-key", account.id),
            None,
        ),
    ] {
        s.request(method, &path, None, body)?.status(
            401,
            "Unauthenticated account-key request did not return 401",
        )?;
    }
    s.request(
        Method::GET,
        &format!("/api/users/{}/public-key", Uuid::new_v4()),
        Some(&account.token),
        None,
    )?
    .status(404, "Missing user public-key GET did not return 404")?;
    for (index, id) in [
        "not-a-uuid",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaz",
        "user_id",
    ]
    .into_iter()
    .enumerate()
    {
        let response = s.request(
            Method::GET,
            &format!("/api/users/{id}/public-key"),
            Some(&account.token),
            None,
        )?;
        if response.status != 422 {
            eprintln!("Account-key UUID fixture {}, method GET", index + 1);
        }
        response.status(422, "Malformed public-key user UUID did not return 422")?;
    }
    let upper = s
        .accounts
        .iter()
        .map(|account| account.id.to_ascii_uppercase())
        .zip(&s.accounts)
        .find(|(upper, account)| *upper != account.id)
        .map(|(upper, _)| upper)
        .ok_or(AccountKeysError(
            "No generated account can exercise UUID spelling",
        ))?;
    s.request(
        Method::GET,
        &format!("/api/users/{upper}/public-key"),
        Some(&account.token),
        None,
    )?
    .status(404, "Public-key lookup normalized a UUID spelling")?;
    require(
        s.snapshots()? == before,
        "Account-key guard rejections mutated accounts or vaults",
    )
}

fn account_keys_reinitialization_is_nonmutating(s: &mut Suite) -> Result<(), AccountKeysError> {
    let before = s.snapshots()?;
    let accounts = s.accounts.clone();
    for account in &accounts {
        for body in [
            json!({"encryptedPrivateKey":"replacement-private","publicKey":"replacement-public"}),
            json!(["replacement-private", "replacement-public"]),
        ] {
            s.request(
                Method::POST,
                "/api/accounts/keys",
                Some(&account.token),
                Some(body.to_string().as_bytes()),
            )?
            .status(400, "Existing account key pair could be replaced")?;
        }
        check_own_keys(&s.own_keys(account)?, account)?;
    }
    require(
        s.snapshots()? == before,
        "Rejected key replacement changed keys, vaults, or revisions",
    )
}

fn receipt() -> Result<Option<fs::File>, AccountKeysError> {
    let Some(path) = std::env::var_os("BW_ACCOUNT_KEYS_RECEIPT") else {
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
        .map_err(|_| AccountKeysError("Private account-key receipt creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| AccountKeysError("Private account-key receipt permissions failed"))?;
    }
    Ok(Some(file))
}

/// Exercise the three account-key routes using three disposable password accounts.
///
/// Registration transport requests are owned by the shared fixture helper and
/// excluded from the HTTP counter. Exactly three ordinary password logins are
/// performed, without retries. The optional receipt is a newly created 0600 file.
pub fn run() -> Result<(), AccountKeysError> {
    let server = std::env::var("BW_E2E_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8000".into());
    let server = server.trim_end_matches('/').to_owned();
    let url = reqwest::Url::parse(&server)
        .map_err(|_| AccountKeysError("Invalid account-key test server configuration"))?;
    require(
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Invalid account-key test server configuration",
    )?;
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| AccountKeysError("Account-key HTTP client initialization failed"))?;
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
    for index in 0..3 {
        let email = format!("account-keys-{}@example.test", Uuid::new_v4());
        let password = format!("Nw!{}", Uuid::new_v4());
        let body = if index == 0 {
            fixture::seed_account(&suite.server, &email, &password)
        } else {
            fixture::seed_account_without_keys(&suite.server, &email, &password)
        }
        .map_err(|_| AccountKeysError("Account-key fixture registration failed"))?;
        let token = suite.login(&body)?;
        let profile = suite.json(Method::GET, "/api/accounts/profile", &token, None)?;
        let id = text(&profile["id"])?.to_owned();
        let pair = if index == 0 {
            Some((
                text(&body["keys"]["encryptedPrivateKey"])?.to_owned(),
                text(&body["keys"]["publicKey"])?.to_owned(),
            ))
        } else {
            None
        };
        let account = Account {
            token,
            id,
            fixture: body,
            pair,
        };
        suite.seed_vault(&account)?;
        suite.accounts.push(account);
    }
    for (name, case) in CASES {
        case(&mut suite)?;
        suite.passed.push(name);
        suite.write_receipt("running")?;
        println!("PASS {name}");
    }
    suite.write_receipt("passed")?;
    suite.finished = true;
    println!(
        "PASS account keys: {} cases, {} HTTP requests, {} logins",
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
    fn account_key_errors_do_not_retain_response_material() {
        let error = Reply {
            status: 500,
            bytes: b"private-secret-marker".to_vec(),
        }
        .status(200, "Static account-key status error")
        .err()
        .unwrap();
        assert!(error.to_string() == "Static account-key status error");
        assert!(!format!("{error:?}").contains("private-secret-marker"));
        let error = Reply {
            status: 200,
            bytes: b"private-secret-marker".to_vec(),
        }
        .json()
        .err()
        .unwrap();
        assert!(!format!("{error} {error:?}").contains("private-secret-marker"));
    }

    #[test]
    fn key_pair_sequence_order_and_json_categories_match_the_upstream_guard() {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Keys {
            encrypted_private_key: String,
            public_key: String,
        }
        let keys: Keys = serde_json::from_str("[\"private\",\"public\"]").unwrap();
        assert!(keys.encrypted_private_key == "private" && keys.public_key == "public");
        for (body, expected) in [
            (
                "[\"private\",\"public\",0]",
                serde_json::error::Category::Syntax,
            ),
            ("[null,\"public\"]", serde_json::error::Category::Data),
        ] {
            assert_eq!(
                serde_json::from_str::<Keys>(body).err().unwrap().classify(),
                expected
            );
        }
    }
}
