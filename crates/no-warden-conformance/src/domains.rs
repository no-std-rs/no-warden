//! Portable personal equivalent-domain contracts, with private in-memory snapshots.
//!
//! Catalog facts are pinned to Vaultwarden 58a980f850464f7d9cdc99a765df36f0a3308b91,
//! `src/static/global_domains.json` (raw SHA-256
//! 3f2c8a39c8c1a8dd9a8c9f4c6b14201afd7113d4fea2b22a27e1847e95e7933a).
//! Diagnostics contain authored case names, statuses, counts, and public catalog
//! fingerprints only. They never display account, request, or response contents.

use crate::fixture;
use reqwest::{Method, blocking::Client};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeSet,
    fmt, fs,
    io::{Read, Seek, SeekFrom, Write},
    thread,
    time::Duration,
};
use uuid::Uuid;

type Case = fn(&mut Suite) -> Result<(), DomainsError>;
const CASES: [(&str, Case); 8] = [
    ("domains_catalog_and_defaults", domains_catalog_and_defaults),
    (
        "domains_aliases_preserve_opaque_groups",
        domains_aliases_preserve_opaque_groups,
    ),
    (
        "domains_excluded_ids_and_filtering",
        domains_excluded_ids_and_filtering,
    ),
    ("domains_sync_query_guard", domains_sync_query_guard),
    (
        "domains_omitted_null_and_positional_resets",
        domains_omitted_null_and_positional_resets,
    ),
    (
        "domains_schema_and_syntax_rejections",
        domains_schema_and_syntax_rejections,
    ),
    (
        "domains_repeated_updates_advance_revision",
        domains_repeated_updates_advance_revision,
    ),
    (
        "domains_authentication_and_owner_isolation",
        domains_authentication_and_owner_isolation,
    ),
];
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;
const CATALOG_COUNT: usize = 91;
const CATALOG_FINGERPRINT: &str =
    "7ca6dc6994f8aa69537211ba1f7a1fa454471dd9451f7d3037170a44405f4372";
const SETTINGS: &str = "/api/settings/domains";

/// Static diagnostics do not retain URLs, credentials, or response contents.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DomainsError(&'static str);
impl fmt::Display for DomainsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for DomainsError {}

fn require(condition: bool, message: &'static str) -> Result<(), DomainsError> {
    if condition {
        Ok(())
    } else {
        Err(DomainsError(message))
    }
}
fn text(value: &Value) -> Result<&str, DomainsError> {
    value
        .as_str()
        .ok_or(DomainsError("Required domain fixture string missing"))
}

struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16) -> Result<Self, DomainsError> {
        if self.status != expected {
            eprintln!(
                "Domain HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, "Domain HTTP status differed")?;
        Ok(self)
    }
    fn json(self) -> Result<Value, DomainsError> {
        serde_json::from_slice(&self.bytes)
            .map_err(|_| DomainsError("Domain response was not valid JSON"))
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
    settings: Value,
    profile: Value,
    sync: Value,
    revision: i64,
}
struct Suite {
    server: String,
    client: Client,
    accounts: Vec<Account>,
    catalog: Vec<Value>,
    catalog_hash: Option<String>,
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
    fn write_receipt(&mut self, status: &'static str) -> Result<(), DomainsError> {
        if let Some(file) = &mut self.receipt {
            let record = json!({"schemaVersion":1,"status":status,"cases":self.passed,
                "passedCases":self.passed.len(),"expectedCases":CASES.len(),
                "httpRequests":self.requests,"identityLogins":self.logins,
                "publicCatalogGroups":self.catalog.len(),"publicCatalogHash":self.catalog_hash});
            file.seek(SeekFrom::Start(0))
                .map_err(|_| DomainsError("Domain receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| DomainsError("Domain receipt update failed"))?;
            file.write_all(record.to_string().as_bytes())
                .map_err(|_| DomainsError("Domain receipt write failed"))?;
            file.sync_all()
                .map_err(|_| DomainsError("Domain receipt persistence failed"))?;
        }
        Ok(())
    }
    fn read(&self, response: reqwest::blocking::Response) -> Result<Reply, DomainsError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| DomainsError("Domain response read failed"))?;
        require(
            bytes.len() as u64 <= MAX_RESPONSE_BYTES,
            "Domain response exceeded the capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn request(
        &mut self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Reply, DomainsError> {
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
            .map_err(|_| DomainsError("Domain HTTP request failed"))?;
        self.read(response)
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, DomainsError> {
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
    fn login(&mut self, body: &Value) -> Result<String, DomainsError> {
        let device = Uuid::new_v4().to_string();
        let form = [
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("deviceIdentifier", device.as_str()),
            ("deviceType", "8"),
            ("deviceName", "no-warden-domains-conformance"),
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
            .map_err(|_| DomainsError("Domain fixture login failed"))?;
        let result = self.read(response)?.status(200)?.json()?;
        Ok(text(&result["access_token"])?.to_owned())
    }
    fn snapshot(&mut self, token: &str) -> Result<Snapshot, DomainsError> {
        let settings = self.json(Method::GET, SETTINGS, token, None)?;
        let profile = self.json(Method::GET, "/api/accounts/profile", token, None)?;
        let sync = self.json(Method::GET, "/api/sync", token, None)?;
        let revision = self
            .json(Method::GET, "/api/accounts/revision-date", token, None)?
            .as_i64()
            .ok_or(DomainsError("Domain account revision was not an integer"))?;
        Ok(Snapshot {
            settings,
            profile,
            sync,
            revision,
        })
    }
    fn seed_vault(&mut self, account: &Account) -> Result<(), DomainsError> {
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
            Some(
                &json!({"type":2,"name":encrypted,"notes":encrypted,"folderId":folder,
                "encryptedFor":account.id,"secureNote":{"type":0,"futureOpaqueField":encrypted}}),
            ),
        )?;
        require(
            cipher["folderId"] == folder,
            "Domain vault fixture lost its folder association",
        )
    }
    fn expected_domains(&self, groups: &Value, excluded: &[i32], filtered: bool) -> Value {
        let globals: Vec<_> = self
            .catalog
            .iter()
            .filter_map(|record| {
                let mut record = record.clone();
                let is_excluded = record["type"]
                    .as_i64()
                    .is_some_and(|id| excluded.iter().any(|other| i64::from(*other) == id));
                record["excluded"] = json!(is_excluded);
                (!filtered || !is_excluded).then_some(record)
            })
            .collect();
        json!({"equivalentDomains":groups,"globalEquivalentDomains":globals,"object":"domains"})
    }
    fn mutate(
        &mut self,
        method: Method,
        body: &Value,
        groups: Value,
        excluded: &[i32],
    ) -> Result<(), DomainsError> {
        let token = self.accounts[0].token.clone();
        let mut expected = self.snapshot(&token)?;
        let revision = expected.revision;
        expected.settings = self.expected_domains(&groups, excluded, false);
        expected.sync["domains"] = self.expected_domains(&groups, excluded, true);
        thread::sleep(Duration::from_millis(10));
        require(
            self.json(method, SETTINGS, &token, Some(body))? == json!({}),
            "Domain update response was not exactly an empty object",
        )?;
        let actual = self.snapshot(&token)?;
        require(
            actual.revision > revision,
            "Domain update did not advance account revision",
        )?;
        expected.revision = actual.revision;
        require(
            actual == expected,
            "Domain update changed unrelated profile, key, vault, or opaque values",
        )
    }
    fn reject_bodies(
        &mut self,
        method: Method,
        bodies: &[&str],
        expected: u16,
    ) -> Result<(), DomainsError> {
        let token = self.accounts[0].token.clone();
        for (index, body) in bodies.iter().enumerate() {
            let reply = self.request(
                method.clone(),
                SETTINGS,
                Some(&token),
                Some(body.as_bytes()),
            )?;
            if reply.status != expected {
                eprintln!(
                    "Domain JSON fixture {}, method {}",
                    index + 1,
                    method.as_str()
                );
            }
            reply.status(expected)?;
        }
        Ok(())
    }
}

/// Hash the ordered public facts, independent of JSON object-key order/whitespace.
/// Each record is i32 LE type, u64 LE domain count, then for each ordered domain
/// u64 LE UTF-8 byte length followed by its bytes. Flags are checked separately.
fn catalog_fingerprint(catalog: &[Value]) -> Result<String, DomainsError> {
    let mut hasher = Sha256::new();
    for record in catalog {
        let id = record["type"]
            .as_i64()
            .and_then(|id| i32::try_from(id).ok())
            .ok_or(DomainsError(
                "Public domain catalog has an invalid identifier",
            ))?;
        let domains = record["domains"]
            .as_array()
            .ok_or(DomainsError("Public domain catalog has an invalid group"))?;
        hasher.update(id.to_le_bytes());
        hasher.update((domains.len() as u64).to_le_bytes());
        for domain in domains {
            let domain = text(domain)?;
            hasher.update((domain.len() as u64).to_le_bytes());
            hasher.update(domain.as_bytes());
        }
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn domains_catalog_and_defaults(s: &mut Suite) -> Result<(), DomainsError> {
    let token = s.accounts[0].token.clone();
    let before = s.snapshot(&token)?;
    require(
        before
            .settings
            .as_object()
            .is_some_and(|object| object.len() == 3)
            && before.settings["object"] == "domains"
            && before.settings["equivalentDomains"] == json!([]),
        "Default domain response shape or custom groups differed",
    )?;
    let catalog = before.settings["globalEquivalentDomains"]
        .as_array()
        .ok_or(DomainsError("Default public domain catalog missing"))?
        .clone();
    let mut ids = BTreeSet::new();
    for record in &catalog {
        require(
            record.as_object().is_some_and(|object| object.len() == 3)
                && record["excluded"] == false
                && record["domains"]
                    .as_array()
                    .is_some_and(|domains| domains.iter().all(Value::is_string)),
            "Default public domain record shape or excluded flag differed",
        )?;
        require(
            ids.insert(record["type"].as_i64()),
            "Default public domain catalog contains duplicate identifiers",
        )?;
    }
    let fingerprint = catalog_fingerprint(&catalog)?;
    if catalog.len() != CATALOG_COUNT || fingerprint != CATALOG_FINGERPRINT {
        eprintln!(
            "Public domain catalog: {} groups, SHA256 {fingerprint}",
            catalog.len()
        );
    }
    s.catalog_hash = Some(fingerprint.clone());
    s.catalog = catalog;
    require(
        s.catalog.len() == CATALOG_COUNT && fingerprint == CATALOG_FINGERPRINT,
        "Entire public domain catalog differed from the pinned facts",
    )?;
    require(
        s.catalog.iter().any(|record| {
            record["type"] == 0
                && record["domains"] == json!(["youtube.com", "google.com", "gmail.com"])
        }) && s.catalog.iter().any(|record| {
            record["type"] == 1 && record["domains"] == json!(["apple.com", "icloud.com"])
        }),
        "Authored public domain catalog examples differed",
    )?;
    require(
        before.sync["domains"] == before.settings,
        "Default sync domains differed from default settings",
    )?;
    require(
        s.snapshot(&token)? == before,
        "Domain reads changed account, vault, or revision",
    )
}

fn domains_aliases_preserve_opaque_groups(s: &mut Suite) -> Result<(), DomainsError> {
    let groups = json!([
        [],
        [""],
        ["ExAmPlE.test", "ExAmPlE.test", "example.test"],
        [
            "雪.example",
            "https://not-a-domain.test/path?x=1",
            " leading and trailing "
        ],
        ["quoted\\\"value", "\0\t\r\n", "🔐", "<opaque>"]
    ]);
    let foreign = s.accounts[1].clone();
    for method in [Method::PUT, Method::POST] {
        s.mutate(
            method,
            &json!({"equivalentDomains":groups,"excludedGlobalEquivalentDomains":[],
                "id":foreign.id,"userId":foreign.id,"email":foreign.fixture["email"],
                "key":"ignored","profile":{"name":"ignored"},"futureField":[1,2]}),
            groups.clone(),
            &[],
        )?;
    }
    Ok(())
}

fn domains_excluded_ids_and_filtering(s: &mut Suite) -> Result<(), DomainsError> {
    let groups = json!([["custom.example", "other.example"], []]);
    let excluded = [0, -1, 0, 1, i32::MAX, i32::MIN];
    for method in [Method::PUT, Method::POST] {
        s.mutate(
            method,
            &json!({"equivalentDomains":groups,"excludedGlobalEquivalentDomains":excluded}),
            groups.clone(),
            &excluded,
        )?;
    }
    Ok(())
}

fn domains_sync_query_guard(s: &mut Suite) -> Result<(), DomainsError> {
    let token = s.accounts[0].token.clone();
    let before = s.snapshot(&token)?;
    // Rocket 0.5.1 FromFormField<bool> aliases are ASCII-case-insensitive;
    // lenient scalar parsing keeps the first field with the matching root name.
    let queries = [
        ("?excludeDomains=false", false),
        ("?excludeDomains=FALSE", false),
        ("?excludeDomains=off", false),
        ("?excludeDomains=No", false),
        ("?excludeDomains=true", true),
        ("?excludeDomains=TrUe", true),
        ("?excludeDomains=on", true),
        ("?excludeDomains=YES", true),
        ("?excludeDomains=", true),
        ("?excludeDomains", true),
        ("?ExcludeDomains=true", false),
        ("?excludedomains=true", false),
        ("?futureUnknown=true", false),
        ("?exclude%44omains=%74rue", true),
        ("?excludeDomains=false&excludeDomains=true", false),
        ("?excludeDomains=true&excludeDomains=false", true),
        ("?excludeDomains=false&excludeDomains=invalid", false),
        ("?excludeDomains.foo=true", true),
        ("?excludeDomains%5Bfoo%5D=true", true),
        // Rocket NameView strips a leading dot or the first bracket pair;
        // an unmatched opening bracket strips only that opening character.
        ("?.excludeDomains=true", true),
        ("?%5BexcludeDomains%5D=true", true),
        ("?%5BexcludeDomains=true", true),
        ("?%5BexcludeDomains%5Djunk=true", true),
        ("?.excludeDomains%5Bfoo%5D=true", true),
        ("?..excludeDomains=true", false),
        ("?%5BexcludeDomains.foo%5D=true", false),
        ("?%5BexcludeDomains.foo=true", false),
        ("?%5BexcludeDomains%5Bfoo%5D=true", false),
        ("?%3DexcludeDomains=true", false),
        ("?%5BexcludeDomains%5D=false&excludeDomains=true", false),
    ];
    for (index, (query, excluded)) in queries.iter().enumerate() {
        let mut expected = before.sync.clone();
        if *excluded {
            expected["domains"] = Value::Null;
        }
        let reply = s.request(
            Method::GET,
            &format!("/api/sync{query}"),
            Some(&token),
            None,
        )?;
        if reply.status != 200 {
            eprintln!("Domain sync query fixture {}", index + 1);
        }
        let actual = reply.status(200)?.json()?;
        if actual != expected {
            eprintln!("Domain sync query fixture {}", index + 1);
        }
        require(
            actual == expected,
            "Domain sync query changed unrelated values or domain inclusion",
        )?;
    }
    for (index, query) in [
        "?excludeDomains=0",
        "?excludeDomains=1",
        "?excludeDomains=null",
        "?excludeDomains=%20true",
        "?excludeDomains=invalid&excludeDomains=true",
        "?%5BexcludeDomains%5D=invalid",
        "?.excludeDomains=invalid",
        "?%5BexcludeDomains=invalid&excludeDomains=true",
    ]
    .iter()
    .enumerate()
    {
        let reply = s.request(
            Method::GET,
            &format!("/api/sync{query}"),
            Some(&token),
            None,
        )?;
        if reply.status != 422 {
            eprintln!("Domain invalid sync query fixture {}", index + 1);
        }
        reply.status(422)?;
    }
    require(
        s.snapshot(&token)? == before,
        "Sync domain query reads changed account or revision",
    )
}

fn domains_omitted_null_and_positional_resets(s: &mut Suite) -> Result<(), DomainsError> {
    for method in [Method::PUT, Method::POST] {
        for body in [
            json!({}),
            json!({"equivalentDomains":null,"excludedGlobalEquivalentDomains":null}),
            json!([null, null]),
            json!([[], []]),
            json!({"EquivalentDomains":[["ignored"]],"ExcludedGlobalEquivalentDomains":[0]}),
        ] {
            s.mutate(
                method.clone(),
                &json!([[0], [["before-reset"]]]),
                json!([["before-reset"]]),
                &[0],
            )?;
            s.mutate(method.clone(), &body, json!([]), &[])?;
        }
        let groups = json!([["only-groups", "duplicate"], ["duplicate"]]);
        s.mutate(
            method.clone(),
            &json!({"equivalentDomains":groups}),
            groups.clone(),
            &[],
        )?;
        s.mutate(
            method.clone(),
            &json!({"excludedGlobalEquivalentDomains":[1]}),
            json!([]),
            &[1],
        )?;
        s.mutate(method.clone(), &json!([[0], groups]), groups.clone(), &[0])?;
    }
    Ok(())
}

fn domains_schema_and_syntax_rejections(s: &mut Suite) -> Result<(), DomainsError> {
    let token = s.accounts[0].token.clone();
    let before = s.snapshot(&token)?;
    let invalid = [
        "null",
        "true",
        "7",
        "\"text\"",
        "[]",
        "[null]",
        "[[0]]",
        "{\"equivalentDomains\":0}",
        "{\"equivalentDomains\":false}",
        "{\"equivalentDomains\":{}}",
        "{\"equivalentDomains\":[\"group\"]}",
        "{\"equivalentDomains\":[[null]]}",
        "{\"equivalentDomains\":[[1]]}",
        "{\"equivalentDomains\":[[{}]]}",
        "{\"equivalentDomains\":[null]}",
        "{\"excludedGlobalEquivalentDomains\":{}}",
        "{\"excludedGlobalEquivalentDomains\":false}",
        "{\"excludedGlobalEquivalentDomains\":[\"0\"]}",
        "{\"excludedGlobalEquivalentDomains\":[null]}",
        "{\"excludedGlobalEquivalentDomains\":[0.5]}",
        "{\"excludedGlobalEquivalentDomains\":[2147483648]}",
        "{\"excludedGlobalEquivalentDomains\":[-2147483649]}",
        "{\"equivalentDomains\":[],\"equivalentDomains\":[]}",
        "{\"equivalentDomains\":null,\"equivalentDoma\\u0069ns\":null}",
        "{\"excludedGlobalEquivalentDomains\":[],\"excludedGlobalEquivalentDomains\":null}",
        "[[],[1]]",
        "[\"wrong\",[]]",
    ];
    let malformed = [
        "",
        "{",
        "{\"equivalentDomains\":",
        "{} trailing",
        "{}{}",
        "[null,null,0]",
        "{\"equivalentDomains\":[[\"unterminated]]}",
    ];
    for method in [Method::PUT, Method::POST] {
        s.reject_bodies(method.clone(), &invalid, 422)?;
        s.reject_bodies(method, &malformed, 400)?;
    }
    require(
        s.snapshot(&token)? == before,
        "Rejected domain JSON changed account, vault, settings, or revision",
    )
}

fn domains_repeated_updates_advance_revision(s: &mut Suite) -> Result<(), DomainsError> {
    let groups = json!([["repeat.example", "repeat.example"]]);
    for method in [Method::PUT, Method::POST] {
        for _ in 0..2 {
            s.mutate(
                method.clone(),
                &json!({"equivalentDomains":groups,"excludedGlobalEquivalentDomains":[0,0]}),
                groups.clone(),
                &[0, 0],
            )?;
        }
    }
    Ok(())
}

fn domains_authentication_and_owner_isolation(s: &mut Suite) -> Result<(), DomainsError> {
    let token = s.accounts[0].token.clone();
    let before = s.snapshot(&token)?;
    s.request(Method::GET, SETTINGS, None, None)?.status(401)?;
    for method in [Method::PUT, Method::POST] {
        s.request(method, SETTINGS, None, Some(b"{}"))?
            .status(401)?;
    }
    // Rocket runs Headers request guards before the sync query guard.
    for bearer in [None, Some("invalid-bearer-for-domain-conformance")] {
        s.request(
            Method::GET,
            "/api/sync?excludeDomains=invalid",
            bearer,
            None,
        )?
        .status(401)?;
    }
    require(
        s.snapshot(&token)? == before,
        "Unauthenticated domain requests changed account or revision",
    )?;
    let other = s.accounts[1].clone();
    s.mutate(
        Method::POST,
        &json!({"userId":other.id,"id":other.id,"email":other.fixture["email"],
            "equivalentDomains":[["only-authenticated-owner"]],"excludedGlobalEquivalentDomains":[1]}),
        json!([["only-authenticated-owner"]]),
        &[1],
    )
}

fn receipt() -> Result<Option<fs::File>, DomainsError> {
    let Some(path) = std::env::var_os("BW_DOMAINS_RECEIPT") else {
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
        .map_err(|_| DomainsError("Private domain receipt creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| DomainsError("Private domain receipt permissions failed"))?;
    }
    Ok(Some(file))
}

/// Compare domain settings and sync inclusion using two disposable accounts.
///
/// Each account logs in once. Shared fixture registration is excluded from the
/// HTTP request count. No authentication or mutation is retried. Full snapshots
/// preserve both users' profiles, key material, vaults, and account revisions.
pub fn run() -> Result<(), DomainsError> {
    let server = std::env::var("BW_E2E_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8000".into());
    let server = server.trim_end_matches('/').to_owned();
    let url = reqwest::Url::parse(&server)
        .map_err(|_| DomainsError("Invalid domain test server configuration"))?;
    require(
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Invalid domain test server configuration",
    )?;
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| DomainsError("Domain HTTP client initialization failed"))?;
    let mut suite = Suite {
        server,
        client,
        accounts: Vec::new(),
        catalog: Vec::new(),
        catalog_hash: None,
        requests: 0,
        logins: 0,
        passed: Vec::new(),
        receipt: receipt()?,
        finished: false,
    };
    suite.write_receipt("running")?;
    for _ in 0..2 {
        let email = format!("domains-{}@example.test", Uuid::new_v4());
        let password = format!("Nw!{}", Uuid::new_v4());
        let body = fixture::seed_account(&suite.server, &email, &password)
            .map_err(|_| DomainsError("Domain fixture registration failed"))?;
        let token = suite.login(&body)?;
        let profile = suite.json(Method::GET, "/api/accounts/profile", &token, None)?;
        let account = Account {
            token,
            id: text(&profile["id"])?.to_owned(),
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
            "Domain case changed another account, settings, keys, vault, or revision",
        )?;
        suite.passed.push(name);
        suite.write_receipt("running")?;
        println!("PASS {name}");
    }
    suite.write_receipt("passed")?;
    suite.finished = true;
    println!(
        "PASS domains: {} cases, {} HTTP requests, {} logins",
        suite.passed.len(),
        suite.requests,
        suite.logins
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Request {
        excluded_global_equivalent_domains: Option<Vec<i32>>,
        equivalent_domains: Option<Vec<Vec<String>>>,
    }

    #[test]
    fn positional_order_optional_fields_and_json_error_classes() {
        let value = serde_json::from_str::<Request>("[[0,-1],[[\"opaque\"],[]]]").unwrap();
        assert_eq!(value.excluded_global_equivalent_domains, Some(vec![0, -1]));
        assert_eq!(
            value.equivalent_domains,
            Some(vec![vec!["opaque".to_owned()], vec![]])
        );
        for body in ["{}", "[null,null]"] {
            let value = serde_json::from_str::<Request>(body).unwrap();
            assert!(value.excluded_global_equivalent_domains.is_none());
            assert!(value.equivalent_domains.is_none());
        }
        for body in [
            "[]",
            "[null]",
            "[[0]]",
            "{\"excludedGlobalEquivalentDomains\":[2147483648]}",
            "{\"equivalentDomains\":null,\"equivalentDomains\":null}",
        ] {
            assert_eq!(
                serde_json::from_str::<Request>(body)
                    .err()
                    .unwrap()
                    .classify(),
                serde_json::error::Category::Data
            );
        }
        for body in ["[null,null,0]", "{} trailing", "{}{}"] {
            assert_eq!(
                serde_json::from_str::<Request>(body)
                    .err()
                    .unwrap()
                    .classify(),
                serde_json::error::Category::Syntax
            );
        }
    }

    #[test]
    fn catalog_hash_binds_identifiers_group_order_and_domain_bytes() {
        let original = vec![
            json!({"type":0,"domains":["a","b"],"excluded":false}),
            json!({"type":1,"domains":["c"],"excluded":false}),
        ];
        let hash = catalog_fingerprint(&original).unwrap();
        for changed in [
            vec![original[1].clone(), original[0].clone()],
            vec![json!({"type":2,"domains":["a","b"]}), original[1].clone()],
            vec![json!({"type":0,"domains":["b","a"]}), original[1].clone()],
            vec![json!({"type":0,"domains":["ab"]}), original[1].clone()],
            vec![original[0].clone()],
        ] {
            assert_ne!(catalog_fingerprint(&changed).unwrap(), hash);
        }
    }

    #[test]
    fn diagnostics_discard_response_contents() {
        let error = Reply {
            status: 500,
            bytes: b"private-domains-marker".to_vec(),
        }
        .status(200)
        .err()
        .unwrap();
        assert_eq!(error.to_string(), "Domain HTTP status differed");
        assert!(!format!("{error:?}").contains("private-domains-marker"));
        let error = Reply {
            status: 200,
            bytes: b"private-domains-marker".to_vec(),
        }
        .json()
        .err()
        .unwrap();
        assert!(!format!("{error} {error:?}").contains("private-domains-marker"));
    }
}
