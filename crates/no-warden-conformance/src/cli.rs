//! Real official-client checks. Diagnostics contain stages and counts, never vault data.
use crate::{capture, fixture, transport::TlsProxy};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use rand::{RngCore, rngs::OsRng};
use reqwest::blocking::Client;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fmt, fs,
    io::Write,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;

#[derive(Debug)]
pub struct Failure(String);
impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Failure {}
fn fail(message: &'static str) -> Failure {
    Failure(message.into())
}
fn check(condition: bool, message: &'static str) -> Result<(), Failure> {
    if condition {
        Ok(())
    } else {
        Err(fail(message))
    }
}
fn text(value: &Value) -> Result<&str, Failure> {
    value
        .as_str()
        .ok_or_else(|| fail("Required response string missing"))
}
fn array(value: &Value) -> Result<&[Value], Failure> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| fail("Required response array missing"))
}
fn encode(value: &Value) -> String {
    STANDARD.encode(value.to_string())
}
fn stage(message: &'static str) {
    println!("  {message}");
}

fn private_directory(prefix: &str) -> Result<TempDir, Failure> {
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| fail("Private test directory creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| fail("Private directory permissions failed"))?;
    }
    Ok(directory)
}
fn private_file(path: &Path, bytes: &[u8]) -> Result<(), Failure> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| fail("Private fixture file creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| fail("Private file permissions failed"))?;
    }
    file.write_all(bytes)
        .map_err(|_| fail("Private fixture file write failed"))
}

struct Runner {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    commands: usize,
    email: String,
    appdata: TempDir,
    output: TempDir,
    receipt: Option<fs::File>,
    passed: bool,
}
impl Drop for Runner {
    fn drop(&mut self) {
        if !self.passed {
            let _ = self.write_receipt("failed");
        }
    }
}
impl Runner {
    fn write_receipt(&mut self, status: &'static str) -> Result<(), Failure> {
        if let Some(file) = &mut self.receipt {
            use std::io::{Seek, SeekFrom};
            file.seek(SeekFrom::Start(0))
                .map_err(|_| fail("Conformance receipt seek failed"))?;
            file.set_len(0)
                .map_err(|_| fail("Conformance receipt update failed"))?;
            let record = json!({"status":status,"commands":self.commands,"expectedCommands":118,"cliVersion":"2026.10.0"});
            file.write_all(record.to_string().as_bytes())
                .map_err(|_| fail("Conformance receipt write failed"))?;
            file.sync_all()
                .map_err(|_| fail("Conformance receipt persistence failed"))?;
        }
        Ok(())
    }
    fn command(&mut self, args: &[&str]) -> Result<String, Failure> {
        self.command_options(args, false, None)
    }
    fn rejected(&mut self, args: &[&str], overrides: Option<(&str, &str)>) -> Result<(), Failure> {
        self.command_options(args, true, overrides).map(|_| ())
    }
    fn command_options(
        &mut self,
        args: &[&str],
        rejected: bool,
        overrides: Option<(&str, &str)>,
    ) -> Result<String, Failure> {
        self.commands += 1;
        let mut environment = self.environment.clone();
        if let Some((key, value)) = overrides {
            environment.insert(key.into(), value.into());
        }
        let args = args
            .iter()
            .copied()
            .chain(["--nointeraction"])
            .map(OsString::from)
            .collect::<Vec<_>>();
        let result = capture::run(&self.binary, &args, &environment, Duration::from_secs(90))
            .map_err(|_| {
                Failure(format!(
                    "CLI command {} could not complete within capture limits",
                    self.commands
                ))
            })?;
        if result.status.code().is_none() || result.status.success() == rejected {
            return Err(Failure(format!(
                "CLI command {} had unexpected status {:?}; stdout bytes {}, stderr bytes {}",
                self.commands,
                result.status.code(),
                result.stdout.len(),
                result.stderr_bytes
            )));
        }
        if rejected {
            return Ok(String::new());
        }
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| fail("CLI returned invalid UTF-8"))
    }
    fn json(&mut self, args: &[&str]) -> Result<Value, Failure> {
        serde_json::from_str(&self.command(args)?).map_err(|_| fail("CLI returned invalid JSON"))
    }
    fn login(&mut self) -> Result<(), Failure> {
        let email = self.email.clone();
        let session =
            self.command(&["login", &email, "--passwordenv", "BW_E2E_PASSWORD", "--raw"])?;
        check(session.len() > 20, "CLI did not return an unlock session")?;
        self.environment.insert("BW_SESSION".into(), session.into());
        Ok(())
    }
    fn unlock(&mut self) -> Result<(), Failure> {
        let session = self.command(&["unlock", "--passwordenv", "BW_E2E_PASSWORD", "--raw"])?;
        check(session.len() > 20, "CLI did not return an unlock session")?;
        self.environment.insert("BW_SESSION".into(), session.into());
        Ok(())
    }
    fn clear_session(&mut self) {
        self.environment.remove(&OsString::from("BW_SESSION"));
    }
    fn clear_cache(&mut self) -> Result<(), Failure> {
        self.clear_session();
        fs::remove_dir_all(self.appdata.path()).map_err(|_| fail("Client cache cleanup failed"))?;
        fs::create_dir(self.appdata.path()).map_err(|_| fail("Client cache recreation failed"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(self.appdata.path(), fs::Permissions::from_mode(0o700))
                .map_err(|_| fail("Client cache permissions failed"))?;
        }
        Ok(())
    }
    fn count(&self, expected: usize) -> Result<(), Failure> {
        check(self.commands == expected, "CLI command milestone changed")
    }
}

fn api(
    client: &Client,
    server: &str,
    path: &str,
    method: reqwest::Method,
    token: Option<&str>,
    body: Option<&Value>,
    form: Option<&BTreeMap<&str, String>>,
) -> Result<Value, Failure> {
    let mut request = client.request(method, format!("{server}{path}"));
    if let Some(token) = token {
        request = request.bearer_auth(token);
    }
    if let Some(body) = body {
        request = request.json(body);
    }
    if let Some(form) = form {
        request = request.form(form);
    }
    let response = request
        .send()
        .map_err(|_| fail("Fixture HTTP request failed"))?;
    check(
        response.status().as_u16() == 200,
        "Fixture HTTP request returned an unexpected status",
    )?;
    response
        .json()
        .map_err(|_| fail("Fixture HTTP response was invalid JSON"))
}

struct Imports {
    folders: Value,
    items: Value,
    normalized_csv_folder: String,
    csv_parent: String,
    csv_notes: [String; 2],
}
impl Imports {
    fn create() -> Self {
        let folders = json!([
            {"id":uuid::Uuid::new_v4().to_string(),"name":"JSON import \"quoted\" \\ café 🔐"},
            {"id":uuid::Uuid::new_v4().to_string(),"name":"JSON import/第二 folder"},
        ]);
        let items = json!([
            {"id":uuid::Uuid::new_v4().to_string(),"type":1,"name":"Imported JSON login \"quoted\"","folderId":folders[0]["id"],"organizationId":null,"favorite":true,"reprompt":0,"notes":"Imported café 🔐\nsecond line","fields":[{"name":"Imported custom field","value":"preserved field value","type":0}],"login":{"username":"json-user","password":"json-import-password","uris":[{"uri":"https://example.test/import","match":null}]}},
            {"id":uuid::Uuid::new_v4().to_string(),"type":2,"name":"Imported JSON secure note","folderId":folders[1]["id"],"organizationId":null,"favorite":false,"reprompt":0,"notes":"Private note \"quoted\" \\ 雪","secureNote":{"type":0}},
            {"id":uuid::Uuid::new_v4().to_string(),"type":3,"name":"Imported JSON card","folderId":folders[0]["id"],"organizationId":null,"favorite":false,"reprompt":0,"notes":null,"card":{"cardholderName":"Test Cardholder","brand":"Visa","number":"4111111111111111","expMonth":"12","expYear":"2035","code":"123"}},
            {"id":uuid::Uuid::new_v4().to_string(),"type":4,"name":"Imported JSON identity","folderId":null,"organizationId":null,"favorite":false,"reprompt":0,"notes":null,"identity":{"firstName":"Test","lastName":"Identity","email":"identity@example.test","city":"Montréal"}},
        ]);
        let normalized_csv_folder = "CSV import \"quoted\", \\ café 🔑".replace('\\', "/");
        let csv_parent = normalized_csv_folder.rsplit_once('/').unwrap().0.to_owned();
        Self {
            folders,
            items,
            normalized_csv_folder,
            csv_parent,
            csv_notes: [
                "CSV note \"quoted\"\nsecond line".into(),
                "CSV secure note café 🔐".into(),
            ],
        }
    }
    fn write(&self, directory: &Path) -> Result<(PathBuf, PathBuf), Failure> {
        let json_path = directory.join("import.json");
        private_file(
            &json_path,
            json!({"encrypted":false,"folders":self.folders,"items":self.items})
                .to_string()
                .as_bytes(),
        )?;
        let csv_path = directory.join("import.csv");
        let rows = [
            vec![
                "folder",
                "favorite",
                "type",
                "name",
                "notes",
                "fields",
                "reprompt",
                "login_uri",
                "login_username",
                "login_password",
                "login_totp",
            ],
            vec![
                "CSV import \"quoted\", \\ café 🔑",
                "1",
                "login",
                "Imported CSV login",
                &self.csv_notes[0],
                "CSV field: preserved CSV value",
                "0",
                "https://example.test/csv",
                "csv-user",
                "csv-import-password",
                "",
            ],
            vec![
                "CSV import \"quoted\", \\ café 🔑",
                "0",
                "note",
                "Imported CSV secure note",
                &self.csv_notes[1],
                "",
                "0",
                "",
                "",
                "",
                "",
            ],
        ];
        let csv = rows
            .iter()
            .map(|row| {
                row.iter()
                    .map(|cell| format!("\"{}\"", cell.replace('"', "\"\"")))
                    .collect::<Vec<_>>()
                    .join(",")
            })
            .collect::<Vec<_>>()
            .join("\r\n");
        private_file(&csv_path, csv.as_bytes())?;
        Ok((json_path, csv_path))
    }
    fn verify(&self, items: &Value, folders: &Value) -> Result<BTreeMap<String, Value>, Failure> {
        let items = array(items)?;
        let folders = array(folders)?
            .iter()
            .filter(|folder| folder["id"].as_str().is_some_and(|id| !id.is_empty()))
            .collect::<Vec<_>>();
        check(
            items.len() == 6 && folders.len() == 4,
            "Imported item or folder count changed",
        )?;
        let folder_ids = folders
            .iter()
            .map(|folder| Ok((text(&folder["name"])?, text(&folder["id"])?)))
            .collect::<Result<BTreeMap<_, _>, Failure>>()?;
        for name in [
            text(&self.folders[0]["name"])?,
            text(&self.folders[1]["name"])?,
            &self.normalized_csv_folder,
            &self.csv_parent,
        ] {
            check(
                folder_ids.contains_key(name),
                "Escaped imported folder did not decrypt",
            )?;
        }
        let by_name = items
            .iter()
            .map(|item| Ok((text(&item["name"])?.to_owned(), item.clone())))
            .collect::<Result<BTreeMap<_, _>, Failure>>()?;
        for expected in array(&self.items)? {
            let actual = by_name
                .get(text(&expected["name"])?)
                .ok_or_else(|| fail("Imported item missing"))?;
            check(
                actual["type"] == expected["type"] && actual["id"] != expected["id"],
                "Imported type or fresh identifier changed",
            )?;
            let expected_folder = array(&self.folders)?
                .iter()
                .find(|f| f["id"] == expected["folderId"]);
            let expected_folder_id = expected_folder
                .and_then(|f| f["name"].as_str())
                .and_then(|name| folder_ids.get(name))
                .copied();
            check(
                actual["folderId"].as_str() == expected_folder_id
                    && actual["organizationId"].is_null(),
                "Imported folder or organization association changed",
            )?;
        }
        for (index, pointer) in [
            (0, "/login/password"),
            (0, "/notes"),
            (0, "/fields/0/value"),
            (1, "/notes"),
            (2, "/card/number"),
            (3, "/identity/city"),
        ] {
            let expected = &self.items[index];
            check(
                by_name[text(&expected["name"])?].pointer(pointer) == expected.pointer(pointer),
                "Imported encrypted JSON field did not decrypt",
            )?;
        }
        let csv_login = by_name
            .get("Imported CSV login")
            .ok_or_else(|| fail("CSV login missing"))?;
        let csv_note = by_name
            .get("Imported CSV secure note")
            .ok_or_else(|| fail("CSV note missing"))?;
        check(
            csv_login["type"] == 1 && csv_note["type"] == 2,
            "CSV item types changed",
        )?;
        check(
            csv_login["login"]["password"] == "csv-import-password"
                && csv_login["notes"] == self.csv_notes[0]
                && csv_login["fields"][0]["value"] == "preserved CSV value"
                && csv_note["notes"] == self.csv_notes[1],
            "Imported encrypted CSV field did not decrypt",
        )?;
        let folder = folder_ids.get(self.normalized_csv_folder.as_str()).copied();
        check(
            csv_login["folderId"].as_str() == folder && csv_note["folderId"].as_str() == folder,
            "CSV folder association changed",
        )?;
        Ok(by_name)
    }
}

pub fn run() -> Result<(), Failure> {
    check(
        std::env::args_os().len() == 1,
        "Conformance runner uses BW_E2E_SERVER/BW_BIN environment configuration",
    )?;
    let server = std::env::var("BW_E2E_SERVER")
        .unwrap_or_else(|_| "http://127.0.0.1:8000".into())
        .trim_end_matches('/')
        .to_owned();
    let email = std::env::var("BW_E2E_EMAIL")
        .unwrap_or_else(|_| format!("no-warden-{}@example.test", uuid::Uuid::new_v4()));
    let mut random_password = [0_u8; 32];
    OsRng.fill_bytes(&mut random_password);
    let password = std::env::var("BW_E2E_PASSWORD")
        .unwrap_or_else(|_| URL_SAFE_NO_PAD.encode(random_password));
    let appdata = private_directory("no-warden-bw-rust-")?;
    let output = private_directory("no-warden-cli-rust-")?;
    let tls_directory = private_directory("no-warden-tls-rust-")?;
    let local_bw = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/node_modules/.bin/bw");
    let binary = std::env::var_os("BW_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| {
            if local_bw.exists() {
                local_bw
            } else {
                "bw".into()
            }
        });
    let mut environment = std::env::vars_os().collect::<BTreeMap<_, _>>();
    for key in ["BW_SESSION", "BW_CLIENTID", "BW_CLIENTSECRET"] {
        environment.remove(&OsString::from(key));
    }
    environment.insert(
        "BITWARDENCLI_APPDATA_DIR".into(),
        appdata.path().as_os_str().to_owned(),
    );
    environment.insert("BW_E2E_PASSWORD".into(), password.clone().into());
    environment.insert("BW_NOINTERACTION".into(), "true".into());
    let proxy = if server.starts_with("http:") {
        Some(
            TlsProxy::start(&server, tls_directory.path())
                .map_err(|_| fail("Loopback TLS proxy startup failed"))?,
        )
    } else {
        None
    };
    let client_server = proxy
        .as_ref()
        .map_or(server.as_str(), TlsProxy::url)
        .to_owned();
    if let Some(proxy) = &proxy {
        environment.insert(
            "NODE_EXTRA_CA_CERTS".into(),
            proxy.certificate().as_os_str().to_owned(),
        );
    }
    let client = Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|_| fail("HTTP client initialization failed"))?;
    let mut runner = Runner {
        binary,
        environment,
        commands: 0,
        email: email.clone(),
        appdata,
        output,
        receipt: match std::env::var_os("BW_E2E_RECEIPT") {
            Some(path) => {
                let mut options = fs::OpenOptions::new();
                options.read(true).write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let file = options
                    .open(path)
                    .map_err(|_| fail("Conformance receipt must be a new writable file"))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    file.set_permissions(fs::Permissions::from_mode(0o600))
                        .map_err(|_| fail("Conformance receipt permissions failed"))?;
                }
                Some(file)
            }
            None => None,
        },
        passed: false,
    };
    runner.write_receipt("running")?;
    let version = runner.command(&["--version"])?;
    check(
        version == "2026.10.0",
        "Official CLI version differs from locked conformance version",
    )?;
    println!("Bitwarden CLI {version}: Rust conformance runner");
    fixture::seed_account(&server, &email, &password)
        .map_err(|_| fail("Disposable account registration failed"))?;
    runner.command(&["config", "server", &client_server])?;
    lifecycle(&mut runner, &client_server, &password)?;
    runner.count(37)?;
    let imports = Imports::create();
    let imported = import_checks(&mut runner, &client_server, &imports)?;
    runner.count(51)?;
    let archive_item = imported
        .get(text(&imports.items[0]["name"])?)
        .ok_or_else(|| fail("Archive fixture missing"))?
        .clone();
    archive_checks(&mut runner, &client_server, &imports, &archive_item)?;
    runner.count(66)?;
    api_key_checks(
        &mut runner,
        &client,
        &server,
        &client_server,
        &email,
        &password,
        &imports,
        &archive_item,
    )?;
    runner.count(90)?;
    attachment_checks(&mut runner, &client_server, &archive_item)?;
    runner.count(118)?;
    runner.write_receipt("passed")?;
    runner.passed = true;
    println!(
        "PASS: 118 real CLI commands; Rust runner verified personal vault, import, archive, API-key authentication and binary attachments."
    );
    Ok(())
}

fn lifecycle(r: &mut Runner, client_server: &str, password: &str) -> Result<(), Failure> {
    stage("Reject incorrect password, then authenticate and decrypt the user key");
    let email = r.email.clone();
    let wrong_password = format!("{password}-incorrect");
    r.rejected(
        &["login", &email, "--passwordenv", "BW_E2E_PASSWORD", "--raw"],
        Some(("BW_E2E_PASSWORD", &wrong_password)),
    )?;
    r.login()?;
    check(
        r.json(&["status"])?["status"] == "unlocked",
        "Password login did not unlock",
    )?;
    r.command(&["sync"])?;
    check(
        array(&r.json(&["list", "items"])?)?.is_empty(),
        "Disposable vault was not empty",
    )?;
    stage("Create, read, and rename an encrypted folder");
    let folder = r.json(&[
        "create",
        "folder",
        &encode(&json!({"name":"Compatibility folder"})),
    ])?;
    let folder_id = text(&folder["id"])?;
    check(
        folder["name"] == "Compatibility folder"
            && r.json(&["get", "folder", folder_id])?["name"] == folder["name"],
        "Encrypted folder did not decrypt",
    )?;
    let mut renamed = folder.clone();
    renamed["name"] = json!("Renamed folder");
    check(
        r.json(&["edit", "folder", folder_id, &encode(&renamed)])?["name"] == "Renamed folder",
        "Encrypted folder rename failed",
    )?;
    stage("Create and decrypt a login item with URI, notes, custom field, and folder");
    let item = r.json(&["create","item",&encode(&json!({"type":1,"name":"Compatibility login","notes":"Encrypted note: café 🔐","favorite":true,"folderId":folder_id,"reprompt":0,"login":{"username":"test-user","password":"test-item-password","totp":"JBSWY3DPEHPK3PXP","uris":[{"uri":"https://example.test/login","match":null}]},"fields":[{"name":"Test field","value":"Private field value","type":0}]}))])?;
    let id = text(&item["id"])?;
    check(
        item["name"] == "Compatibility login",
        "Created item name did not decrypt",
    )?;
    let fetched = r.json(&["get", "item", id])?;
    check(
        fetched["login"]["password"] == "test-item-password"
            && fetched["notes"] == "Encrypted note: café 🔐"
            && fetched["fields"][0]["value"] == "Private field value"
            && fetched["folderId"] == folder_id,
        "Created item fields did not decrypt",
    )?;
    check(
        array(&r.json(&["list", "items", "--search", "Compatibility login"])?)?.len() == 1,
        "Item search failed",
    )?;
    stage("Edit encrypted fields, sync, lock, and unlock");
    let mut edited = fetched;
    edited["name"] = json!("Edited compatibility login");
    edited["notes"] = json!("Updated encrypted note");
    edited["login"]["password"] = json!("changed-item-password");
    check(
        r.json(&["edit", "item", id, &encode(&edited)])?["login"]["password"]
            == "changed-item-password",
        "Edited password did not decrypt",
    )?;
    r.command(&["sync"])?;
    r.command(&["lock"])?;
    r.clear_session();
    check(
        r.json(&["status"])?["status"] == "locked",
        "CLI did not lock",
    )?;
    r.unlock()?;
    check(
        r.json(&["get", "item", id])?["login"]["password"] == "changed-item-password",
        "Unlocked password did not decrypt",
    )?;
    stage("Logout/login and verify server persistence with a fresh client cache");
    r.command(&["logout"])?;
    r.clear_cache()?;
    r.command(&["config", "server", client_server])?;
    r.login()?;
    let persisted = r.json(&["get", "item", id])?;
    check(
        persisted["name"] == "Edited compatibility login"
            && persisted["login"]["password"] == "changed-item-password",
        "Fresh-cache vault did not decrypt",
    )?;
    check(
        r.json(&["get", "folder", folder_id])?["name"] == "Renamed folder",
        "Fresh-cache folder did not decrypt",
    )?;
    stage("Trash, restore, permanently delete the cipher, and delete its folder");
    r.command(&["delete", "item", id])?;
    check(
        array(&r.json(&["list", "items"])?)?.is_empty(),
        "Trashed item remained active",
    )?;
    check(
        array(&r.json(&["list", "items", "--trash"])?)?.len() == 1,
        "Trashed item missing",
    )?;
    r.command(&["restore", "item", id])?;
    check(
        r.json(&["get", "item", id])?["login"]["password"] == "changed-item-password",
        "Restored password did not decrypt",
    )?;
    r.command(&["delete", "item", id])?;
    r.command(&["delete", "item", id, "--permanent"])?;
    r.command(&["delete", "folder", folder_id])?;
    r.command(&["sync"])?;
    check(
        array(&r.json(&["list", "items"])?)?.is_empty(),
        "Deleted item remained active",
    )?;
    check(
        array(&r.json(&["list", "items", "--trash"])?)?.is_empty(),
        "Permanently deleted item remained in trash",
    )?;
    check(
        array(&r.json(&["list", "folders"])?)?
            .iter()
            .all(|f| f["id"].as_str().is_none_or(str::is_empty)),
        "Deleted folder remained",
    )?;
    r.command(&["logout"])?;
    Ok(())
}

fn import_checks(
    r: &mut Runner,
    client_server: &str,
    imports: &Imports,
) -> Result<BTreeMap<String, Value>, Failure> {
    stage("Import JSON and CSV vaults with escaped folders and multiple encrypted item types");
    r.login()?;
    let (json_path, csv_path) = imports.write(r.output.path())?;
    r.command(&[
        "import",
        "bitwardenjson",
        json_path
            .to_str()
            .ok_or_else(|| fail("Invalid fixture path"))?,
    ])?;
    r.command(&[
        "import",
        "bitwardencsv",
        csv_path
            .to_str()
            .ok_or_else(|| fail("Invalid fixture path"))?,
    ])?;
    r.command(&["sync"])?;
    let imported = imports.verify(&r.json(&["list", "items"])?, &r.json(&["list", "folders"])?)?;
    stage(
        "Discard the client cache, log in again, and decrypt every imported item and folder link",
    );
    r.command(&["logout"])?;
    r.clear_cache()?;
    r.command(&["config", "server", client_server])?;
    r.login()?;
    let fresh = imports.verify(&r.json(&["list", "items"])?, &r.json(&["list", "folders"])?)?;
    for name in [text(&imports.items[0]["name"])?, "Imported CSV login"] {
        let fetched = r.json(&["get", "item", text(&imported[name]["id"])?])?;
        check(
            fetched["login"]["password"] == fresh[name]["login"]["password"],
            "Fresh-cache imported password did not decrypt",
        )?;
    }
    r.command(&["logout"])?;
    Ok(imported)
}

fn archive_checks(
    r: &mut Runner,
    client_server: &str,
    imports: &Imports,
    item: &Value,
) -> Result<(), Failure> {
    stage("Archive an encrypted item, discard the cache, and restore it from the archive");
    r.login()?;
    let id = text(&item["id"])?;
    r.command(&["archive", "item", id])?;
    r.command(&["sync"])?;
    let archived = r.json(&["list", "items", "--archived"])?;
    check(
        array(&archived)?.len() == 1
            && archived[0]["id"] == id
            && archived[0]["login"]["password"] == imports.items[0]["login"]["password"],
        "Archived item did not decrypt",
    )?;
    check(
        array(&r.json(&["list", "items"])?)?.len() == 5,
        "Archived item remained in active list",
    )?;
    r.command(&["logout"])?;
    r.clear_cache()?;
    r.command(&["config", "server", client_server])?;
    r.login()?;
    let archived = r.json(&["list", "items", "--archived"])?;
    check(
        array(&archived)?.len() == 1
            && archived[0]["id"] == id
            && archived[0]["login"]["password"] == imports.items[0]["login"]["password"],
        "Fresh-cache archive did not decrypt",
    )?;
    let fresh = r.json(&["get", "item", id])?;
    check(
        fresh["archivedDate"].is_string() && fresh["notes"] == imports.items[0]["notes"],
        "Fresh-cache archive fields changed",
    )?;
    r.command(&["restore", "item", id])?;
    r.command(&["sync"])?;
    check(
        array(&r.json(&["list", "items", "--archived"])?)?.is_empty(),
        "Restored item remained archived",
    )?;
    let restored = r.json(&["get", "item", id])?;
    check(
        restored["archivedDate"].is_null()
            && restored["login"]["password"] == imports.items[0]["login"]["password"]
            && restored["folderId"] == item["folderId"],
        "Unarchived content changed",
    )?;
    r.command(&["logout"])?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn api_key_checks(
    r: &mut Runner,
    client: &Client,
    server: &str,
    client_server: &str,
    email: &str,
    password: &str,
    imports: &Imports,
    item: &Value,
) -> Result<(), Failure> {
    stage("Authenticate with a personal API key, then unlock and decrypt with the master password");
    r.clear_session();
    let hash = fixture::master_password_hash(email, password, 600_000);
    let form = BTreeMap::from([
        ("grant_type", "password".into()),
        ("username", email.into()),
        ("password", hash.clone()),
        ("scope", "api offline_access".into()),
        ("client_id", "cli".into()),
        ("deviceType", "8".into()),
        ("deviceIdentifier", uuid::Uuid::new_v4().to_string()),
        ("deviceName", "CLI API-key fixture".into()),
    ]);
    let bearer = api(
        client,
        server,
        "/identity/connect/token",
        reqwest::Method::POST,
        None,
        None,
        Some(&form),
    )?;
    let token = text(&bearer["access_token"])?;
    let profile = api(
        client,
        server,
        "/api/accounts/profile",
        reqwest::Method::GET,
        Some(token),
        None,
        None,
    )?;
    let key = api(
        client,
        server,
        "/api/accounts/api-key",
        reqwest::Method::POST,
        Some(token),
        Some(&json!({"masterPasswordHash":hash})),
        None,
    )?;
    let secret = text(&key["apiKey"])?;
    check(
        secret.len() == 30 && secret.bytes().all(|b| b.is_ascii_alphanumeric()),
        "API key response had invalid shape",
    )?;
    r.environment.insert(
        "BW_CLIENTID".into(),
        format!("user.{}", text(&profile["id"])?).into(),
    );
    r.environment
        .insert("BW_CLIENTSECRET".into(), secret.into());
    r.rejected(
        &["login", "--apikey"],
        Some(("BW_CLIENTSECRET", &format!("{secret}-incorrect"))),
    )?;
    r.command(&["login", "--apikey"])?;
    check(
        r.json(&["status"])?["status"] == "locked",
        "API-key login was not locked",
    )?;
    r.unlock()?;
    check(
        r.json(&["status"])?["status"] == "unlocked",
        "API-key password unlock failed",
    )?;
    r.command(&["sync"])?;
    let id = text(&item["id"])?;
    check(
        r.json(&["get", "item", id])?["login"]["password"] == imports.items[0]["login"]["password"],
        "API-key vault did not decrypt",
    )?;
    r.command(&["logout"])?;
    r.clear_cache()?;
    r.command(&["config", "server", client_server])?;
    r.command(&["login", "--apikey"])?;
    check(
        r.json(&["status"])?["status"] == "locked",
        "Fresh-cache API login was not locked",
    )?;
    r.unlock()?;
    r.command(&["sync"])?;
    imports.verify(&r.json(&["list", "items"])?, &r.json(&["list", "folders"])?)?;
    check(
        r.json(&["get", "item", id])?["notes"] == imports.items[0]["notes"],
        "Fresh-cache API vault did not decrypt",
    )?;
    r.command(&["logout"])?;
    r.clear_session();
    stage(
        "Rotate the personal API key, reject the old secret, and decrypt after login with the new key",
    );
    let rotated = api(
        client,
        server,
        "/api/accounts/rotate-api-key",
        reqwest::Method::POST,
        Some(token),
        Some(&json!({"masterPasswordHash":hash})),
        None,
    )?;
    check(
        rotated["apiKey"].is_string() && rotated["apiKey"] != key["apiKey"],
        "API key did not rotate",
    )?;
    r.rejected(&["login", "--apikey"], None)?;
    r.environment
        .insert("BW_CLIENTSECRET".into(), text(&rotated["apiKey"])?.into());
    r.command(&["login", "--apikey"])?;
    check(
        r.json(&["status"])?["status"] == "locked",
        "Rotated API login was not locked",
    )?;
    r.unlock()?;
    r.command(&["sync"])?;
    check(
        r.json(&["get", "item", id])?["login"]["password"] == imports.items[0]["login"]["password"],
        "Rotated API vault did not decrypt",
    )?;
    r.command(&["logout"])?;
    Ok(())
}

struct AttachmentFixture {
    name: &'static str,
    bytes: Vec<u8>,
    id: String,
}
fn attachment_checks(r: &mut Runner, client_server: &str, item: &Value) -> Result<(), Failure> {
    stage("Upload and download empty, arbitrary-byte, and multi-megabyte encrypted attachments");
    r.clear_session();
    r.login()?;
    let id = text(&item["id"])?;
    let mut large = vec![0_u8; 2 * 1024 * 1024 + 37];
    OsRng.fill_bytes(&mut large);
    let mut fixtures = [
        AttachmentFixture {
            name: "Empty attachment.bin",
            bytes: vec![],
            id: String::new(),
        },
        AttachmentFixture {
            name: "Attachment \"quoted\" café 🔐.bin",
            bytes: (0..=255).collect(),
            id: String::new(),
        },
        AttachmentFixture {
            name: "Large attachment.bin",
            bytes: large,
            id: String::new(),
        },
    ];
    let mut attached = Value::Null;
    for fixture in &mut fixtures {
        let path = r.output.path().join(fixture.name);
        private_file(&path, &fixture.bytes)?;
        attached = r.json(&[
            "create",
            "attachment",
            "--file",
            path.to_str()
                .ok_or_else(|| fail("Invalid attachment path"))?,
            "--itemid",
            id,
        ])?;
        let metadata = array(&attached["attachments"])?
            .iter()
            .find(|a| a["fileName"] == fixture.name)
            .ok_or_else(|| fail("Uploaded filename did not decrypt"))?;
        fixture.id = text(&metadata["id"])?.to_owned();
    }
    for fixture in &fixtures {
        download_attachment(r, id, fixture, "initial")?;
    }
    attached["notes"] = json!("Attachment lifecycle edit");
    r.json(&["edit", "item", id, &encode(&attached)])?;
    r.command(&["sync"])?;
    check(
        array(&r.json(&["get", "item", id])?["attachments"])?.len() == 3,
        "Item edit lost attachments",
    )?;
    r.command(&["delete", "item", id])?;
    let trash = r.json(&["list", "items", "--trash"])?;
    let trashed = array(&trash)?
        .iter()
        .find(|a| a["id"] == id)
        .ok_or_else(|| fail("Trashed attachment item missing"))?;
    check(
        array(&trashed["attachments"])?.len() == 3,
        "Trash lost attachment metadata",
    )?;
    r.command(&["restore", "item", id])?;
    r.command(&["logout"])?;
    r.clear_cache()?;
    r.command(&["config", "server", client_server])?;
    r.login()?;
    r.command(&["sync"])?;
    let fresh = r.json(&["get", "item", id])?;
    check(
        array(&fresh["attachments"])?.len() == 3,
        "Fresh-cache attachment metadata missing",
    )?;
    for fixture in &fixtures {
        check(
            array(&fresh["attachments"])?
                .iter()
                .any(|a| a["id"] == fixture.id && a["fileName"] == fixture.name),
            "Fresh-cache filename did not decrypt",
        )?;
        download_attachment(r, id, fixture, "fresh")?;
    }
    for fixture in &fixtures {
        r.command(&["delete", "attachment", &fixture.id, "--itemid", id])?;
    }
    r.command(&["sync"])?;
    let deleted = r.json(&["get", "item", id])?;
    check(
        deleted["attachments"].is_null() || array(&deleted["attachments"])?.is_empty(),
        "Deleted attachment remained",
    )?;
    let destination = r.output.path().join("deleted.bin");
    r.rejected(
        &[
            "get",
            "attachment",
            &fixtures[0].id,
            "--itemid",
            id,
            "--output",
            destination
                .to_str()
                .ok_or_else(|| fail("Invalid attachment path"))?,
        ],
        None,
    )?;
    r.command(&["logout"])?;
    Ok(())
}
fn download_attachment(
    r: &mut Runner,
    item: &str,
    fixture: &AttachmentFixture,
    prefix: &str,
) -> Result<(), Failure> {
    let path = r.output.path().join(format!("{prefix}-{}.bin", fixture.id));
    r.command(&[
        "get",
        "attachment",
        &fixture.id,
        "--itemid",
        item,
        "--output",
        path.to_str()
            .ok_or_else(|| fail("Invalid attachment path"))?,
    ])?;
    check(
        fs::read(path).map_err(|_| fail("Attachment download file missing"))? == fixture.bytes,
        "Downloaded attachment bytes changed",
    )
}
