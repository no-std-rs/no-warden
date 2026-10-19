//! Independently authored MIT/Apache-2.0 official-client file Send lifecycle.
//! Twenty commands remain separate from baseline120. Private sender/recipient stores
//! prevent password-cache false positives; received files are compared byte for byte.
use crate::{
    capture, file_sends, fixture,
    text_sends::{TextSendsError, future_date, receipt_file, require, server, text, write_receipt},
    transport::TlsProxy,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant},
};
use tempfile::TempDir;
use uuid::Uuid;

const PASSWORD: &str = "Synthetic recipient password 雪";
pub const COMMAND_COUNT: usize = 20;

#[derive(Clone, Copy)]
enum Rejection {
    InvalidPassword,
    NotFound,
}
impl Rejection {
    fn message(self) -> &'static str {
        match self {
            Self::InvalidPassword => "Invalid password",
            Self::NotFound => "Not found.",
        }
    }
}

// BW_RESPONSE exposes the published CLI Response on stdout even on failure.
// BaseProgram.processResponse24-38 / Response.error30-35 omit undefined fields.
// Keep captured messages private and reject malformed or unrelated failures.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RejectedResponse {
    success: bool,
    message: String,
}
fn validate_rejection(
    exit_code: Option<i32>,
    output: &[u8],
    expected: Rejection,
) -> Result<(), TextSendsError> {
    require(
        exit_code == Some(1),
        "File Send CLI rejection exit status differed",
    )?;
    let response: RejectedResponse = serde_json::from_slice(output)
        .map_err(|_| TextSendsError("File Send CLI rejection response was malformed"))?;
    require(
        !response.success && response.message == expected.message(),
        "File Send CLI rejection category differed",
    )
}
fn private_dir(prefix: &str) -> Result<TempDir, TextSendsError> {
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| TextSendsError("File Send CLI private directory creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| TextSendsError("File Send CLI private directory permissions failed"))?;
    }
    Ok(directory)
}
struct Cli {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    commands: usize,
    receipt: Option<fs::File>,
    finished: bool,
}
impl Drop for Cli {
    fn drop(&mut self) {
        if !self.finished {
            let _ = self.receipt("failed");
        }
    }
}
impl Cli {
    fn receipt(&mut self, status: &str) -> Result<(), TextSendsError> {
        write_receipt(
            &mut self.receipt,
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,
            "expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","passwordCredentialAttempts":1,
            "fixtureRegistrations":1,"separateFromBaseline120":true}),
        )
    }
    fn command(
        &mut self,
        args: &[&str],
        store: &Path,
        session: Option<&str>,
        rejected: Option<Rejection>,
    ) -> Result<String, TextSendsError> {
        self.commands += 1;
        require(
            self.commands <= COMMAND_COUNT,
            "File Send CLI command budget exceeded",
        )?;
        let mut env = self.environment.clone();
        env.insert(
            "BITWARDENCLI_APPDATA_DIR".into(),
            store.as_os_str().to_owned(),
        );
        if let Some(session) = session {
            env.insert("BW_SESSION".into(), session.into());
        } else {
            env.remove(&OsString::from("BW_SESSION"));
        }
        if rejected.is_some() {
            // Public CLI JSON mode writes failures to bounded private stdout.
            // Quiet/cleanexit must not hide their category or change exit 1.
            env.insert("BW_RESPONSE".into(), "true".into());
            env.remove(&OsString::from("BW_QUIET"));
            env.remove(&OsString::from("BW_CLEANEXIT"));
        }
        let args = args
            .iter()
            .copied()
            .chain(["--nointeraction"])
            .map(OsString::from)
            .collect::<Vec<_>>();
        let result = capture::run(&self.binary, &args, &env, Duration::from_secs(90))
            .map_err(|_| TextSendsError("File Send CLI private capture failed"))?;
        if let Some(expected) = rejected {
            validate_rejection(result.status.code(), &result.stdout, expected)?;
            self.receipt("running")?;
            return Ok(String::new());
        }
        require(
            result.status.success(),
            "File Send CLI command exit status differed",
        )?;
        self.receipt("running")?;
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| TextSendsError("File Send CLI output was not UTF-8"))
    }
    fn json(
        &mut self,
        args: &[&str],
        store: &Path,
        session: Option<&str>,
    ) -> Result<Value, TextSendsError> {
        serde_json::from_str(&self.command(args, store, session, None)?)
            .map_err(|_| TextSendsError("File Send CLI output was not JSON"))
    }
}
fn encoded(value: &Value) -> String {
    STANDARD.encode(value.to_string())
}
fn metadata(value: &Value) -> Result<(), TextSendsError> {
    let length = file_sends::payload().len();
    let encrypted_length = 49 + (length / 16 + 1) * 16;
    let expected_size = encrypted_length.to_string();
    require(
        value["type"] == 1
            && value["file"]["fileName"] == file_sends::FILE_NAME
            && value["file"]["size"].as_str() == Some(expected_size.as_str()),
        "Official file Send metadata did not decrypt or used plaintext size",
    )
}
fn private_file(path: &Path, bytes: &[u8]) -> Result<(), TextSendsError> {
    use std::io::Write;
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|_| TextSendsError("Private file Send input creation failed"))?;
    file.write_all(bytes)
        .map_err(|_| TextSendsError("Private file Send input write failed"))
}
fn check_received(path: &Path) -> Result<(), TextSendsError> {
    let bytes = fs::read(path).map_err(|_| TextSendsError("Received file Send output missing"))?;
    require(
        bytes == file_sends::payload(),
        "Official file Send received bytes differed",
    )
}

pub fn run() -> Result<(), TextSendsError> {
    let server = server();
    let sender = private_dir("no-warden-file-send-sender-")?;
    let recipient = private_dir("no-warden-file-send-recipient-")?;
    let public_recipient = private_dir("no-warden-file-send-public-")?;
    let files = private_dir("no-warden-file-send-files-")?;
    let tls = private_dir("no-warden-file-send-tls-")?;
    let proxy = if server.starts_with("http:") {
        Some(
            TlsProxy::start(&server, tls.path())
                .map_err(|_| TextSendsError("File Send CLI TLS setup failed"))?,
        )
    } else {
        None
    };
    let client_server = proxy.as_ref().map_or(server.as_str(), TlsProxy::url);
    let local = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/node_modules/.bin/bw");
    let binary = std::env::var_os("BW_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| if local.exists() { local } else { "bw".into() });
    let password = Uuid::new_v4().to_string();
    let email = format!("file-sends-cli-{}@example.test", Uuid::new_v4());
    let mut environment = std::env::vars_os().collect::<BTreeMap<_, _>>();
    for key in ["BW_SESSION", "BW_CLIENTID", "BW_CLIENTSECRET"] {
        environment.remove(&OsString::from(key));
    }
    environment.insert("BW_NOINTERACTION".into(), "true".into());
    environment.insert("BW_SEND_ACCOUNT_PASSWORD".into(), password.clone().into());
    environment.insert("BW_SEND_RECIPIENT_PASSWORD".into(), PASSWORD.into());
    environment.insert(
        "BW_SEND_WRONG_PASSWORD".into(),
        "wrong synthetic recipient password".into(),
    );
    if let Some(proxy) = &proxy {
        environment.insert(
            "NODE_EXTRA_CA_CERTS".into(),
            proxy.certificate().as_os_str().to_owned(),
        );
    }
    let mut c = Cli {
        binary,
        environment,
        commands: 0,
        receipt: receipt_file("BW_FILE_SENDS_CLI_RECEIPT")?,
        finished: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], sender.path(), None, None)? == "2026.10.0",
        "File Send CLI version differed",
    )?;
    fixture::seed_account(&server, &email, &password)
        .map_err(|_| TextSendsError("File Send CLI registration failed"))?;
    c.command(
        &["config", "server", client_server],
        sender.path(),
        None,
        None,
    )?;
    let session = c.command(
        &[
            "login",
            &email,
            "--passwordenv",
            "BW_SEND_ACCOUNT_PASSWORD",
            "--raw",
        ],
        sender.path(),
        None,
        None,
    )?;
    require(session.len() > 20, "File Send CLI login session missing")?;
    let input = files.path().join(file_sends::FILE_NAME);
    private_file(&input, &file_sends::payload())?;
    let input_name = input
        .to_str()
        .ok_or(TextSendsError("File Send input path encoding failed"))?;
    let request = json!({"type":1,"name":"Official file Send 雪","notes":"Private file notes\0",
        "file":{"fileName":input_name},"password":PASSWORD,"deletionDate":future_date(1)?,
        "expirationDate":null,"disabled":false,"hideEmail":false,"maxAccessCount":null});
    let created = c.json(
        &["send", "--fullObject", "create", &encoded(&request)],
        sender.path(),
        Some(&session),
    )?;
    metadata(&created)?;
    let id = text(&created["id"])?.to_owned();
    let access_url = text(&created["accessUrl"])?.to_owned();
    let parsed = reqwest::Url::parse(&access_url)
        .map_err(|_| TextSendsError("Official file Send URL invalid"))?;
    let configured = reqwest::Url::parse(client_server)
        .map_err(|_| TextSendsError("Configured file Send URL invalid"))?;
    require(
        parsed.origin() == configured.origin() && parsed.fragment().is_some(),
        "File Send URL crossed configured origin",
    )?;
    c.command(&["sync"], sender.path(), Some(&session), None)?;
    let got = c.json(&["send", "get", &id], sender.path(), Some(&session))?;
    metadata(&got)?;
    require(
        got["key"] == created["key"]
            && got["notes"] == created["notes"]
            && got["file"] == created["file"],
        "File Send sync changed decrypted seed, metadata or notes",
    )?;
    let listed = c.json(&["send", "list"], sender.path(), Some(&session))?;
    require(
        listed
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v["id"] == id && v["file"] == got["file"])),
        "File Send missing from synced CLI list",
    )?;
    c.command(
        &["config", "server", client_server],
        recipient.path(),
        None,
        None,
    )?;
    c.command(
        &[
            "receive",
            &access_url,
            "--passwordenv",
            "BW_SEND_WRONG_PASSWORD",
        ],
        recipient.path(),
        None,
        Some(Rejection::InvalidPassword),
    )?;
    let first_output = files.path().join("first-received.bin");
    let first_path = first_output
        .to_str()
        .ok_or(TextSendsError("File Send output path encoding failed"))?;
    c.command(
        &[
            "receive",
            &access_url,
            "--passwordenv",
            "BW_SEND_RECIPIENT_PASSWORD",
            "--output",
            first_path,
        ],
        recipient.path(),
        None,
        None,
    )?;
    check_received(&first_output)?;
    let mut edited = got.clone();
    edited["name"] = json!("Edited official file Send Ω");
    edited["notes"] = json!("Edited private file notes\0");
    edited["password"] = json!(PASSWORD);
    let changed = c.json(
        &["send", "edit", &encoded(&edited)],
        sender.path(),
        Some(&session),
    )?;
    metadata(&changed)?;
    require(
        changed["file"] == got["file"],
        "Official file Send edit replaced immutable file metadata",
    )?;
    c.command(&["sync"], sender.path(), Some(&session), None)?;
    let after_edit = c.json(&["send", "get", &id], sender.path(), Some(&session))?;
    require(
        after_edit["name"] == edited["name"]
            && after_edit["notes"] == edited["notes"]
            && after_edit["file"] == got["file"],
        "Edited file Send did not survive real sync",
    )?;
    let removed = c.json(
        &["send", "remove-password", &id],
        sender.path(),
        Some(&session),
    )?;
    require(
        removed["passwordSet"] == false,
        "File Send password removal was not reflected",
    )?;
    c.command(
        &["config", "server", client_server],
        public_recipient.path(),
        None,
        None,
    )?;
    let second_output = files.path().join("second-received.bin");
    let second_path = second_output
        .to_str()
        .ok_or(TextSendsError("File Send output path encoding failed"))?;
    let fresh = Instant::now();
    c.command(
        &["send", "receive", &access_url, "--output", second_path],
        public_recipient.path(),
        None,
        None,
    )?;
    check_received(&second_output)?;
    c.command(
        &["send", "delete", &id],
        sender.path(),
        Some(&session),
        None,
    )?;
    c.command(&["sync"], sender.path(), Some(&session), None)?;
    let after = c.json(&["send", "list"], sender.path(), Some(&session))?;
    require(
        after
            .as_array()
            .is_some_and(|a| !a.iter().any(|v| v["id"] == id)),
        "Deleted file Send remained in CLI sync cache",
    )?;
    c.command(
        &["receive", &access_url],
        public_recipient.path(),
        None,
        Some(Rejection::NotFound),
    )?;
    require(
        fresh.elapsed() < Duration::from_secs(60),
        "Deleted file Send proof exceeded capability non-expiry window",
    )?;
    require(
        c.commands == COMMAND_COUNT,
        "File Send CLI command count differed",
    )?;
    c.receipt("passed")?;
    c.finished = true;
    println!("PASS: 20 official CLI file Send commands (separate from baseline120)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn file_cli_rejections_require_exact_categories_and_reject_download_failures() {
        assert!(
            validate_rejection(
                Some(1),
                br#"{"success":false,"message":"Invalid password"}"#,
                Rejection::InvalidPassword
            )
            .is_ok()
        );
        assert!(
            validate_rejection(
                Some(1),
                br#"{"success":false,"message":"Not found."}"#,
                Rejection::NotFound
            )
            .is_ok()
        );
        for bytes in [br#"{"success":false,"message":"A 404 error occurred while downloading the attachment."}"#.as_slice(),br#"{"success":false,"message":"Server error: 500"}"#,b"<html>500</html>",br#"{"success":false,"message":"Not found.","data":{"key":"private marker"}}"#] {
            assert!(validate_rejection(Some(1), bytes, Rejection::NotFound).is_err());
        }
    }
    #[test]
    fn file_cli_byte_comparison_detects_truncated_or_modified_output() {
        let root = private_dir("no-warden-file-send-byte-test-").unwrap();
        let file = root.path().join("received.bin");
        private_file(&file, &file_sends::payload()).unwrap();
        assert!(check_received(&file).is_ok());
        fs::write(&file, b"truncated").unwrap();
        assert!(check_received(&file).is_err());
    }
}
