//! Explicit official-client text Send lifecycle, separate from the 120-command baseline.
//! Sender and recipients use separate private stores. Recipient password failures run
//! before any successful token is cached; a fresh recipient proves password removal.
use crate::{
    capture, fixture,
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

const CONTENT: &str = "Official CLI Send: 雪\nNUL\0 and \"quotes\" retained";
const EDITED: &str = "Edited official CLI Send: Ω\0 exact content";
const PASSWORD: &str = "Synthetic recipient password 雪";
const COMMANDS: usize = 20;

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
        "Send CLI rejection exit status differed",
    )?;
    let response: RejectedResponse = serde_json::from_slice(output)
        .map_err(|_| TextSendsError("Send CLI rejection response was malformed"))?;
    require(
        !response.success && response.message == expected.message(),
        "Send CLI rejection category differed",
    )
}
fn private_dir(prefix: &str) -> Result<TempDir, TextSendsError> {
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| TextSendsError("Send CLI private directory creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| TextSendsError("Send CLI private directory permissions failed"))?;
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
            "expectedCommands":COMMANDS,"cliVersion":"2026.10.0","passwordCredentialAttempts":1,
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
            self.commands <= COMMANDS,
            "Send CLI command budget exceeded",
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
            .map_err(|_| TextSendsError("Send CLI private capture failed"))?;
        if let Some(expected) = rejected {
            validate_rejection(result.status.code(), &result.stdout, expected)?;
            self.receipt("running")?;
            return Ok(String::new());
        }
        require(
            result.status.success(),
            "Send CLI command exit status differed",
        )?;
        self.receipt("running")?;
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| TextSendsError("Send CLI output was not UTF-8"))
    }
    fn json(
        &mut self,
        args: &[&str],
        store: &Path,
        session: Option<&str>,
    ) -> Result<Value, TextSendsError> {
        serde_json::from_str(&self.command(args, store, session, None)?)
            .map_err(|_| TextSendsError("Send CLI output was not JSON"))
    }
}
fn encoded(value: &Value) -> String {
    STANDARD.encode(value.to_string())
}
fn content(value: &Value, expected: &str) -> Result<(), TextSendsError> {
    require(
        value["text"]["text"] == expected && value["text"]["hidden"] == true,
        "Official CLI Send plaintext or hidden flag differed",
    )
}
pub fn run() -> Result<(), TextSendsError> {
    let server = server();
    let sender = private_dir("no-warden-send-sender-")?;
    let recipient = private_dir("no-warden-send-recipient-")?;
    let fresh_recipient = private_dir("no-warden-send-public-recipient-")?;
    let tls = private_dir("no-warden-send-tls-")?;
    let proxy = if server.starts_with("http:") {
        Some(
            TlsProxy::start(&server, tls.path())
                .map_err(|_| TextSendsError("Send CLI loopback TLS setup failed"))?,
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
    let email = format!("text-sends-cli-{}@example.test", Uuid::new_v4());
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
        receipt: receipt_file("BW_TEXT_SENDS_CLI_RECEIPT")?,
        finished: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], sender.path(), None, None)? == "2026.10.0",
        "Send CLI version differed from pinned official client",
    )?;
    fixture::seed_account(&server, &email, &password)
        .map_err(|_| TextSendsError("Send CLI account fixture registration failed"))?;
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
    require(session.len() > 20, "Send CLI login session missing")?;
    let request = json!({"type":0,"name":"Official Send 雪","notes":"Owner-only notes\0retained",
        "text":{"text":CONTENT,"hidden":true},"password":PASSWORD,"deletionDate":future_date(1)?,
        "expirationDate":null,"disabled":false,"hideEmail":false,"maxAccessCount":null});
    let created = c.json(
        &["send", "--fullObject", "create", &encoded(&request)],
        sender.path(),
        Some(&session),
    )?;
    content(&created, CONTENT)?;
    let id = text(&created["id"])?.to_owned();
    let access_url = text(&created["accessUrl"])?.to_owned();
    // Only send the URL/seed to the client configured for this exact proxy origin.
    let parsed = reqwest::Url::parse(&access_url)
        .map_err(|_| TextSendsError("Official Send URL invalid"))?;
    let configured = reqwest::Url::parse(client_server)
        .map_err(|_| TextSendsError("Configured Send URL invalid"))?;
    require(
        parsed.origin() == configured.origin() && parsed.fragment().is_some(),
        "Official Send URL crossed configured origin",
    )?;
    c.command(&["sync"], sender.path(), Some(&session), None)?;
    let got = c.json(&["send", "get", &id], sender.path(), Some(&session))?;
    content(&got, CONTENT)?;
    require(
        got["key"] == created["key"] && got["notes"] == created["notes"],
        "Send seed or owner notes changed after real sync",
    )?;
    let listed = c.json(&["send", "list"], sender.path(), Some(&session))?;
    require(
        listed.as_array().is_some_and(|a| {
            a.iter()
                .any(|v| v["id"] == id && v["text"]["text"] == CONTENT)
        }),
        "Official Send list omitted synced decrypted content",
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
    require(
        c.command(
            &[
                "receive",
                &access_url,
                "--passwordenv",
                "BW_SEND_RECIPIENT_PASSWORD",
            ],
            recipient.path(),
            None,
            None,
        )? == CONTENT,
        "Anonymous CLI Send receive did not decrypt exact content",
    )?;
    let mut edited = got.clone();
    edited["text"]["text"] = json!(EDITED);
    edited["password"] = json!(PASSWORD);
    let changed = c.json(
        &["send", "edit", &encoded(&edited)],
        sender.path(),
        Some(&session),
    )?;
    content(&changed, EDITED)?;
    c.command(&["sync"], sender.path(), Some(&session), None)?;
    require(
        c.command(
            &["send", "get", &id, "--text"],
            sender.path(),
            Some(&session),
            None,
        )? == EDITED,
        "Official CLI edited Send did not survive sync",
    )?;
    let removed = c.json(
        &["send", "remove-password", &id],
        sender.path(),
        Some(&session),
    )?;
    require(
        removed["passwordSet"] == false,
        "Official CLI Send password removal was not reflected",
    )?;
    c.command(
        &["config", "server", client_server],
        fresh_recipient.path(),
        None,
        None,
    )?;
    // Include token minting and the initial read: starting after the command
    // could hide most of the capability's lifetime inside its 90-second timeout.
    let fresh_access = Instant::now();
    let public = c.json(
        &["send", "receive", &access_url, "--obj"],
        fresh_recipient.path(),
        None,
    )?;
    content(&public, EDITED)?;
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
        "Deleted Send remained in official CLI sync cache",
    )?;
    c.command(
        &["receive", &access_url],
        fresh_recipient.path(),
        None,
        Some(Rejection::NotFound),
    )?;
    require(
        fresh_access.elapsed() < Duration::from_secs(60),
        "Deleted Send capability check exceeded non-expiry proof window",
    )?;
    require(c.commands == COMMANDS, "Send CLI command total differed")?;
    c.receipt("passed")?;
    c.finished = true;
    println!("PASS: 20 official CLI text Send commands (separate from baseline120)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn negative_send_cli_checks_require_distinct_source_categories() {
        let password = br#"{"success":false,"message":"Invalid password"}"#;
        let missing = br#"{"success":false,"message":"Not found."}"#;
        assert!(validate_rejection(Some(1), password, Rejection::InvalidPassword).is_ok());
        assert!(validate_rejection(Some(1), missing, Rejection::NotFound).is_ok());
        assert!(validate_rejection(Some(1), password, Rejection::NotFound).is_err());
        assert!(validate_rejection(Some(1), missing, Rejection::InvalidPassword).is_err());
    }
    #[test]
    fn negative_send_cli_checks_reject_server_errors_and_malformed_output() {
        for output in [
            br#"{"success":false,"message":"Server error: 500 Internal Server Error"}"#.as_slice(),
            br#"{"success":false,"message":"Too many requests"}"#,
            br#"{"success":false,"message":"Unexpected response"}"#,
            br#"{"success":true,"message":"Invalid password"}"#,
            br#"{"success":false,"message":"Invalid password","data":{"key":"private marker"}}"#,
            br#"{"success":false,"success":false,"message":"Invalid password"}"#,
            br#"{"success":false,"message":null}"#,
            br#"{"success":false}"#,
            b"Invalid password",
            b"<html>500 Internal Server Error</html>",
            b"{",
            b"\xff",
            b"",
        ] {
            for expected in [Rejection::InvalidPassword, Rejection::NotFound] {
                let error = validate_rejection(Some(1), output, expected).unwrap_err();
                assert!(!format!("{error:?} {error}").contains("private marker"));
            }
        }
    }
    #[test]
    fn negative_send_cli_checks_require_the_published_failure_exit_code() {
        let output = br#"{"success":false,"message":"Invalid password"}"#;
        for code in [None, Some(0), Some(2), Some(127)] {
            assert!(validate_rejection(code, output, Rejection::InvalidPassword).is_err());
        }
    }
    #[test]
    fn cli_send_json_encoding_preserves_unicode_nul_and_private_fields_without_diagnostics() {
        let v = json!({"text":{"text":CONTENT},"password":PASSWORD,"key":"synthetic seed"});
        let decoded: Value =
            serde_json::from_slice(&STANDARD.decode(encoded(&v)).unwrap()).unwrap();
        assert!(decoded == v);
        let error = TextSendsError("Send CLI rejected private capture");
        assert!(!format!("{error:?}").contains(PASSWORD));
    }
}
