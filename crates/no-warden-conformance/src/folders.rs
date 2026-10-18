//! Portable HTTP checks for the seven registered Vaultwarden folder routes.
//!
//! These checks intentionally do not claim notification, shared-client bulk-route,
//! global error-envelope, or transport-limit parity. Only authored case names,
//! counts, and static errors leave the process; fixtures and responses stay private.

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

const ENCRYPTED: &str = "2.AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAA==|AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
const CASES: [(&str, Case); 8] = [
    (
        "folder_crud_projection_and_sync",
        folder_crud_projection_and_sync,
    ),
    (
        "folder_opaque_names_and_large_value",
        folder_opaque_names_and_large_value,
    ),
    (
        "folder_ignored_body_ids_and_sequences",
        folder_ignored_body_ids_and_sequences,
    ),
    (
        "folder_schema_and_syntax_rejections",
        folder_schema_and_syntax_rejections,
    ),
    (
        "folder_missing_and_foreign_isolation",
        folder_missing_and_foreign_isolation,
    ),
    (
        "folder_uuid_path_guard_and_spelling",
        folder_uuid_path_guard_and_spelling,
    ),
    (
        "folder_delete_preserves_cipher_revisions",
        folder_delete_preserves_cipher_revisions,
    ),
    (
        "folder_unauthenticated_rejections",
        folder_unauthenticated_rejections,
    ),
];
type Case = fn(&mut Suite) -> Result<(), FolderError>;

/// A static diagnostic that never retains HTTP errors, fixture values, or paths.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FolderError(&'static str);

impl fmt::Display for FolderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.0)
    }
}
impl std::error::Error for FolderError {}

fn require(condition: bool, message: &'static str) -> Result<(), FolderError> {
    if condition {
        Ok(())
    } else {
        Err(FolderError(message))
    }
}
fn text(value: &Value) -> Result<&str, FolderError> {
    value
        .as_str()
        .ok_or(FolderError("Required response string missing"))
}
fn array(value: &Value) -> Result<&[Value], FolderError> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or(FolderError("Required response array missing"))
}

struct Reply {
    status: u16,
    bytes: Vec<u8>,
}
impl Reply {
    fn status(self, expected: u16, message: &'static str) -> Result<Self, FolderError> {
        if self.status != expected {
            eprintln!(
                "HTTP status mismatch: expected {expected}, actual {}",
                self.status
            );
        }
        require(self.status == expected, message)?;
        Ok(self)
    }
    fn json(self) -> Result<Value, FolderError> {
        serde_json::from_slice(&self.bytes).map_err(|_| FolderError("Response was not valid JSON"))
    }
}

struct Suite {
    server: String,
    client: Client,
    alice: String,
    bob: String,
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
    fn write_receipt(&mut self, status: &'static str) -> Result<(), FolderError> {
        if let Some(file) = &mut self.receipt {
            let record = json!({
                "schemaVersion": 1, "status": status,
                "passedCases": self.passed.len(), "expectedCases": CASES.len(),
                "cases": self.passed, "httpRequests": self.requests,
                "identityLogins": self.logins,
            });
            file.seek(SeekFrom::Start(0))
                .map_err(|_| FolderError("Receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| FolderError("Receipt update failed"))?;
            file.write_all(record.to_string().as_bytes())
                .map_err(|_| FolderError("Receipt write failed"))?;
            file.sync_all()
                .map_err(|_| FolderError("Receipt persistence failed"))?;
        }
        Ok(())
    }

    fn request(
        &mut self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
    ) -> Result<Reply, FolderError> {
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
            .map_err(|_| FolderError("HTTP request failed"))?;
        self.read_response(response)
    }
    fn read_response(&self, response: reqwest::blocking::Response) -> Result<Reply, FolderError> {
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        response
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| FolderError("Response read failed"))?;
        require(
            bytes.len() as u64 <= MAX_RESPONSE_BYTES,
            "Response exceeded the capture limit",
        )?;
        Ok(Reply { status, bytes })
    }
    fn json(
        &mut self,
        method: Method,
        path: &str,
        token: &str,
        body: Option<&Value>,
    ) -> Result<Value, FolderError> {
        let encoded = body.map(Value::to_string);
        self.request(
            method,
            path,
            Some(token),
            encoded.as_deref().map(str::as_bytes),
        )?
        .status(200, "Expected a successful JSON response")?
        .json()
    }
    fn login(&mut self, registration: &Value) -> Result<String, FolderError> {
        let device = Uuid::new_v4().to_string();
        let form = [
            ("grant_type", "password"),
            ("client_id", "cli"),
            ("scope", "api offline_access"),
            ("deviceType", "8"),
            ("deviceIdentifier", device.as_str()),
            ("deviceName", "no-warden-folder-conformance"),
            ("username", text(&registration["email"])?),
            ("password", text(&registration["masterPasswordHash"])?),
        ];
        self.requests += 1;
        self.logins += 1;
        let response = self
            .client
            .post(format!("{}/identity/connect/token", self.server))
            .form(&form)
            .send()
            .map_err(|_| FolderError("Password login request failed"))?;
        let response = self
            .read_response(response)?
            .status(200, "Password login rejected")?
            .json()?;
        Ok(text(&response["access_token"])?.to_owned())
    }
    fn folder(&mut self, token: &str, name: &str) -> Result<Value, FolderError> {
        let value = self.json(
            Method::POST,
            "/api/folders",
            token,
            Some(&json!({"name":name})),
        )?;
        folder_shape(&value, name)?;
        Ok(value)
    }
    fn folders(&mut self, token: &str) -> Result<Value, FolderError> {
        let result = self.json(Method::GET, "/api/folders", token, None)?;
        require(
            result["object"] == "list" && result.get("continuationToken") == Some(&Value::Null),
            "Folder list wrapper differed",
        )?;
        array(&result["data"])?;
        Ok(result["data"].clone())
    }
    fn sync(&mut self, token: &str) -> Result<Value, FolderError> {
        self.json(Method::GET, "/api/sync", token, None)
    }
    fn revision(&mut self, token: &str) -> Result<i64, FolderError> {
        self.json(Method::GET, "/api/accounts/revision-date", token, None)?
            .as_i64()
            .ok_or(FolderError("Account revision was not an integer"))
    }
    fn snapshot(&mut self, token: &str) -> Result<Value, FolderError> {
        let sync = self.sync(token)?;
        Ok(
            json!({"folders":sync["folders"],"ciphers":sync["ciphers"],"revision":self.revision(token)?}),
        )
    }
}

fn folder_shape(value: &Value, name: &str) -> Result<(), FolderError> {
    let object = value
        .as_object()
        .ok_or(FolderError("Folder response was not an object"))?;
    require(
        object.len() == 4
            && ["id", "name", "object", "revisionDate"]
                .iter()
                .all(|key| object.contains_key(*key)),
        "Folder response did not contain exactly four fields",
    )?;
    require(
        value["object"] == "folder" && value["name"] == name,
        "Folder response name or object differed",
    )?;
    require(
        Uuid::parse_str(text(&value["id"])?).is_ok() && !text(&value["revisionDate"])?.is_empty(),
        "Folder server metadata was invalid",
    )
}

fn folder_crud_projection_and_sync(s: &mut Suite) -> Result<(), FolderError> {
    let token = s.alice.clone();
    let foreign = s.bob.clone();
    let foreign_before = s.snapshot(&foreign)?;
    let ignored = Uuid::new_v4().to_string();
    let name = "opaque\\name\"\n雪 🔐";
    let before = s.revision(&token)?;
    thread::sleep(Duration::from_millis(10));
    let created = s.json(
        Method::POST,
        "/api/folders",
        &token,
        Some(&json!({
            "name":name,"id":ignored,"userId":"untrusted-owner","owner":"untrusted-owner",
            "object":"untrusted-object","revisionDate":"1900-01-01T00:00:00Z",
            "creationDate":"1900-01-01T00:00:00Z","deletedDate":"1900-01-01T00:00:00Z",
            "futureEncryptedField":ENCRYPTED,
        })),
    )?;
    folder_shape(&created, name)?;
    let id = text(&created["id"])?.to_owned();
    require(
        id != ignored && s.revision(&token)? > before,
        "Folder creation did not assign fresh metadata",
    )?;
    let path = format!("/api/folders/{id}");
    require(
        s.json(Method::GET, &path, &token, None)? == created,
        "Folder GET differed from creation",
    )?;
    for method in [Method::PUT, Method::POST] {
        let name = if method == Method::PUT {
            "renamed\\雪\"\n🔐"
        } else {
            "legacy\\é\t🦀"
        };
        let old_revision = s.revision(&token)?;
        thread::sleep(Duration::from_millis(10));
        let updated = s.json(
            method,
            &path,
            &token,
            Some(&json!({"name":name,"id":ignored,"futureEncryptedField":ENCRYPTED})),
        )?;
        folder_shape(&updated, name)?;
        require(
            updated["id"] == id && s.revision(&token)? > old_revision,
            "Folder update did not preserve ID or advance account revision",
        )?;
        let folders = s.folders(&token)?;
        let sync = s.sync(&token)?;
        require(
            array(&folders)?.iter().find(|folder| folder["id"] == id) == Some(&updated)
                && array(&sync["folders"])?
                    .iter()
                    .find(|folder| folder["id"] == id)
                    == Some(&updated),
            "Folder list or sync differed from update",
        )?;
    }
    require(
        s.snapshot(&foreign)? == foreign_before,
        "Folder CRUD mutated another vault",
    )
}

fn folder_opaque_names_and_large_value(s: &mut Suite) -> Result<(), FolderError> {
    let token = s.alice.clone();
    let names = [
        String::new(),
        "future-envelope.opaque|雪\\\"\n🔐".to_owned(),
        "x".repeat(1024 * 1024 + 1),
    ];
    for name in names {
        let folder = s.folder(&token, &name)?;
        let path = format!("/api/folders/{}", text(&folder["id"])?);
        for method in [Method::PUT, Method::POST] {
            let updated = s.json(method, &path, &token, Some(&json!({"name":name})))?;
            folder_shape(&updated, &name)?;
            require(
                updated["id"] == folder["id"],
                "Opaque-name update changed folder ID",
            )?;
        }
        require(
            s.json(Method::GET, &path, &token, None)?["name"] == name,
            "Opaque folder name was not preserved",
        )?;
    }
    Ok(())
}

fn folder_ignored_body_ids_and_sequences(s: &mut Suite) -> Result<(), FolderError> {
    let token = s.alice.clone();
    let ignored = Uuid::new_v4().to_string();
    for body in [
        json!({"name":ENCRYPTED}),
        json!({"name":ENCRYPTED,"id":null}),
        json!({"name":ENCRYPTED,"id":""}),
        json!({"name":ENCRYPTED,"id":"not-a-uuid"}),
        json!({"name":ENCRYPTED,"id":ignored}),
        json!([ENCRYPTED]),
        json!([ENCRYPTED, null]),
    ] {
        let created = s.json(Method::POST, "/api/folders", &token, Some(&body))?;
        folder_shape(&created, ENCRYPTED)?;
        let id = text(&created["id"])?.to_owned();
        require(id != ignored, "Folder creation trusted a body ID")?;
        for method in [Method::PUT, Method::POST] {
            let updated = s.json(method, &format!("/api/folders/{id}"), &token, Some(&body))?;
            folder_shape(&updated, ENCRYPTED)?;
            require(updated["id"] == id, "Folder update trusted a body ID")?;
        }
    }
    Ok(())
}

fn folder_schema_and_syntax_rejections(s: &mut Suite) -> Result<(), FolderError> {
    let token = s.alice.clone();
    let folder = s.folder(&token, ENCRYPTED)?;
    let path = format!("/api/folders/{}", text(&folder["id"])?);
    let before = s.snapshot(&token)?;
    let invalid = [
        "{}",
        "null",
        "true",
        "[]",
        "[1]",
        "{\"name\":null}",
        "{\"name\":1}",
        "{\"name\":false}",
        "{\"name\":[]}",
        "{\"name\":{}}",
        "{\"name\":\"a\",\"id\":1}",
        "{\"name\":\"a\",\"id\":false}",
        "{\"name\":\"a\",\"id\":[]}",
        "{\"name\":\"a\",\"id\":{}}",
        "{\"name\":\"a\",\"name\":\"b\"}",
        "{\"name\":\"a\",\"na\\u006de\":\"b\"}",
        "{\"name\":\"a\",\"id\":null,\"id\":\"\"}",
        "[\"a\",false]",
    ];
    for (index, body) in invalid.iter().enumerate() {
        for (method, path) in [
            (Method::POST, "/api/folders"),
            (Method::PUT, path.as_str()),
            (Method::POST, path.as_str()),
        ] {
            let response = s.request(method.clone(), path, Some(&token), Some(body.as_bytes()))?;
            if response.status != 422 {
                eprintln!("Schema fixture {}, method {}", index + 1, method.as_str());
            }
            response.status(422, "Folder schema rejection did not return 422")?;
        }
    }
    for body in [
        "",
        "{",
        "{\"name\":\"a\"",
        "{\"name\":\"a\"} trailing",
        "{\"name\":\"a\"}{}",
        // Serde's surplus sequence element is a syntax error, confirmed as
        // HTTP 400 against the official Vaultwarden 1.37.4 runtime.
        "[\"a\",null,0]",
    ] {
        for (method, path) in [
            (Method::POST, "/api/folders"),
            (Method::PUT, path.as_str()),
            (Method::POST, path.as_str()),
        ] {
            s.request(method, path, Some(&token), Some(body.as_bytes()))?
                .status(400, "Malformed folder JSON did not return 400")?;
        }
    }
    require(
        s.snapshot(&token)? == before,
        "Rejected folder bodies changed vault state",
    )
}

fn folder_missing_and_foreign_isolation(s: &mut Suite) -> Result<(), FolderError> {
    let token = s.alice.clone();
    let foreign_token = s.bob.clone();
    let foreign = s.folder(&foreign_token, ENCRYPTED)?;
    let alice_before = s.snapshot(&token)?;
    let bob_before = s.snapshot(&foreign_token)?;
    for id in [Uuid::new_v4().to_string(), text(&foreign["id"])?.to_owned()] {
        reject_folder_operations(s, &token, &id, 400)?;
    }
    require(
        s.snapshot(&token)? == alice_before && s.snapshot(&foreign_token)? == bob_before,
        "Missing or foreign folder requests mutated a vault",
    )
}

fn reject_folder_operations(
    s: &mut Suite,
    token: &str,
    id: &str,
    expected: u16,
) -> Result<(), FolderError> {
    let path = format!("/api/folders/{id}");
    let delete_path = format!("{path}/delete");
    let body = json!({"name":ENCRYPTED}).to_string();
    for (index, (method, path, body)) in [
        (Method::GET, path.as_str(), None),
        (Method::PUT, path.as_str(), Some(body.as_bytes())),
        (Method::POST, path.as_str(), Some(body.as_bytes())),
        (Method::DELETE, path.as_str(), None),
        (Method::POST, delete_path.as_str(), None),
    ]
    .into_iter()
    .enumerate()
    {
        let response = s.request(method.clone(), path, Some(token), body)?;
        if response.status != expected {
            eprintln!(
                "Folder rejection operation {}, method {}",
                index + 1,
                method.as_str()
            );
        }
        response.status(
            expected,
            "Folder ownership or path rejection status differed",
        )?;
    }
    Ok(())
}

fn folder_uuid_path_guard_and_spelling(s: &mut Suite) -> Result<(), FolderError> {
    let token = s.alice.clone();
    let before = s.snapshot(&token)?;
    for id in [
        "not-a-uuid",
        "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaz",
        "folder_id",
    ] {
        // Rocket 0.5.1 forwards failed FromParam guards with status 422:
        // core/codegen/src/attribute/route/mod.rs:130-143. The official
        // Vaultwarden 1.37.4 runtime confirms this for malformed folder UUIDs.
        reject_folder_operations(s, &token, id, 422)?;
    }
    // Choose an existing fixture with hexadecimal letters; an uppercased UUID
    // remains syntactically valid but must not resolve to its lowercase record.
    let folders = s.folders(&token)?;
    let id = array(&folders)?
        .iter()
        .filter_map(|value| value["id"].as_str())
        .find(|id| id.to_ascii_uppercase() != *id)
        .ok_or(FolderError(
            "No generated folder can exercise UUID spelling",
        ))?;
    reject_folder_operations(s, &token, &id.to_ascii_uppercase(), 400)?;
    require(
        s.snapshot(&token)? == before,
        "Rejected UUID spellings changed vault state",
    )
}

fn fixture_cipher(
    s: &mut Suite,
    token: &str,
    folder: &str,
    owner: &str,
) -> Result<String, FolderError> {
    let cipher = s.json(
        Method::POST,
        "/api/ciphers",
        token,
        Some(&json!({
            "type":2,"name":ENCRYPTED,"notes":ENCRYPTED,"folderId":folder,"favorite":false,
            "encryptedFor":owner,
            "secureNote":{"type":0,"futureEncryptedField":ENCRYPTED},
        })),
    )?;
    Ok(text(&cipher["id"])?.to_owned())
}

fn folder_delete_preserves_cipher_revisions(s: &mut Suite) -> Result<(), FolderError> {
    let token = s.alice.clone();
    let owner = text(&s.sync(&token)?["profile"]["id"])?.to_owned();
    let foreign_token = s.bob.clone();
    let foreign_before = s.snapshot(&foreign_token)?;
    for alias in [false, true] {
        let folder = s.folder(&token, ENCRYPTED)?;
        let id = text(&folder["id"])?.to_owned();
        let active = fixture_cipher(s, &token, &id, &owner)?;
        let trashed = fixture_cipher(s, &token, &id, &owner)?;
        let archived = fixture_cipher(s, &token, &id, &owner)?;
        for (cipher, action) in [(&trashed, "delete"), (&archived, "archive")] {
            let response = s.request(
                Method::PUT,
                &format!("/api/ciphers/{cipher}/{action}"),
                Some(&token),
                None,
            )?;
            require(
                (200..300).contains(&response.status),
                "Cipher lifecycle fixture preparation failed",
            )?;
        }
        let before = s.sync(&token)?;
        let revision = s.revision(&token)?;
        thread::sleep(Duration::from_millis(10));
        let (method, path) = if alias {
            (Method::POST, format!("/api/folders/{id}/delete"))
        } else {
            (Method::DELETE, format!("/api/folders/{id}"))
        };
        let deleted = s
            .request(method, &path, Some(&token), None)?
            .status(200, "Folder deletion did not return 200")?;
        require(
            deleted.bytes.is_empty(),
            "Folder deletion did not return an empty body",
        )?;
        let after = s.sync(&token)?;
        require(
            s.revision(&token)? > revision,
            "Folder deletion did not advance account revision",
        )?;
        require(
            !array(&after["folders"])?
                .iter()
                .any(|value| value["id"] == id),
            "Deleted folder remained in sync",
        )?;
        require(
            !array(&s.folders(&token)?)?
                .iter()
                .any(|value| value["id"] == id),
            "Deleted folder remained in list",
        )?;
        require(
            array(&before["ciphers"])?.len() == array(&after["ciphers"])?.len(),
            "Folder deletion changed cipher count",
        )?;
        for original in array(&before["ciphers"])? {
            let mut expected = original.clone();
            if original["folderId"] == id {
                expected["folderId"] = Value::Null;
            }
            let actual = array(&after["ciphers"])?
                .iter()
                .find(|value| value["id"] == original["id"]);
            require(
                actual == Some(&expected),
                "Folder deletion changed cipher data or revision beyond folderId",
            )?;
        }
        for cipher in [&active, &trashed, &archived] {
            require(
                array(&after["ciphers"])?
                    .iter()
                    .any(|value| value["id"] == *cipher && value["folderId"].is_null()),
                "Folder deletion lost a lifecycle fixture",
            )?;
        }
        reject_folder_operations(s, &token, &id, 400)?;
    }
    require(
        s.snapshot(&foreign_token)? == foreign_before,
        "Folder deletion changed another vault",
    )
}

fn folder_unauthenticated_rejections(s: &mut Suite) -> Result<(), FolderError> {
    let id = Uuid::new_v4().to_string();
    let path = format!("/api/folders/{id}");
    let delete_path = format!("{path}/delete");
    let body = json!({"name":ENCRYPTED}).to_string();
    for (method, path, body) in [
        (Method::GET, "/api/folders", None),
        (Method::GET, path.as_str(), None),
        (Method::POST, "/api/folders", Some(body.as_bytes())),
        (Method::PUT, path.as_str(), Some(body.as_bytes())),
        (Method::POST, path.as_str(), Some(body.as_bytes())),
        (Method::DELETE, path.as_str(), None),
        (Method::POST, delete_path.as_str(), None),
    ] {
        s.request(method, path, None, body)?
            .status(401, "Unauthenticated folder request did not return 401")?;
    }
    Ok(())
}

fn receipt() -> Result<Option<fs::File>, FolderError> {
    let Some(path) = std::env::var_os("BW_FOLDER_RECEIPT") else {
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
        .map_err(|_| FolderError("Private receipt creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| FolderError("Private receipt permissions failed"))?;
    }
    Ok(Some(file))
}

/// Exercise the folder contracts against a disposable configured server.
///
/// Creates exactly two random accounts and performs one password login for each.
/// The optional receipt is a newly created private file containing case names,
/// statuses, and counts only. Registration requests are owned by the shared
/// fixture helper and are not included in the HTTP request counter.
pub fn run() -> Result<(), FolderError> {
    let server = std::env::var("BW_E2E_SERVER").unwrap_or_else(|_| "http://127.0.0.1:8000".into());
    let server = server.trim_end_matches('/').to_owned();
    let url = reqwest::Url::parse(&server)
        .map_err(|_| FolderError("Invalid test server configuration"))?;
    require(
        matches!(url.scheme(), "http" | "https")
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "Invalid test server configuration",
    )?;
    let client = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|_| FolderError("HTTP client initialization failed"))?;
    let mut suite = Suite {
        server,
        client,
        alice: String::new(),
        bob: String::new(),
        requests: 0,
        logins: 0,
        passed: Vec::new(),
        receipt: receipt()?,
        finished: false,
    };
    suite.write_receipt("running")?;
    for first in [true, false] {
        let email = format!("folders-{}@example.test", Uuid::new_v4());
        let password = format!("Nw!{}", Uuid::new_v4());
        let registration = fixture::seed_account(&suite.server, &email, &password)
            .map_err(|_| FolderError("Disposable account registration failed"))?;
        let token = suite.login(&registration)?;
        if first {
            suite.alice = token;
        } else {
            suite.bob = token;
        }
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
        "PASS folders: {} cases, {} HTTP requests, {} logins",
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
    fn projection_rejects_additional_server_fields() {
        let mut value = json!({"id":Uuid::new_v4().to_string(),"name":"opaque","revisionDate":"date","object":"folder"});
        assert!(folder_shape(&value, "opaque").is_ok());
        value["owner"] = json!("untrusted");
        assert!(folder_shape(&value, "opaque").is_err());
    }

    #[test]
    fn diagnostics_discard_response_contents() {
        let reply = Reply {
            status: 500,
            bytes: b"secret-response-token".to_vec(),
        };
        let error = reply.status(200, "Static HTTP failure").err().unwrap();
        assert_eq!(error.to_string(), "Static HTTP failure");
        assert!(!format!("{error:?}").contains("secret-response-token"));
    }

    #[test]
    fn surplus_sequence_element_is_json_syntax_error() {
        #[derive(serde::Deserialize)]
        struct OwnedFolder {
            name: String,
            #[serde(default)]
            id: Option<String>,
        }
        let valid: OwnedFolder = serde_json::from_str("[\"opaque\",null]").unwrap();
        assert!(valid.name == "opaque" && valid.id.is_none());
        let error = serde_json::from_str::<OwnedFolder>("[\"opaque\",null,0]")
            .err()
            .unwrap();
        assert_eq!(error.classify(), serde_json::error::Category::Syntax);
    }
}
