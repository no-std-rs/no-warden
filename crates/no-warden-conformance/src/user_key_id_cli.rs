//! Independently authored official CLI login/unlock user-key-ID backfill proof.
//! Before/after sync metadata is observed without claiming an HTTP route trace.
//! Synthetic HTTP-only opaque IDs are never fed into the real SDK.
use crate::{
    capture,
    text_sends::{TextSendsError as Error, receipt_file, require, text, write_receipt},
    transport::TlsProxy,
    user_key_id::{self, Http},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;

pub const COMMAND_COUNT: usize = 15;
struct Cli {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    commands: usize,
    logins: usize,
    direct_http_requests: Option<usize>,
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
    fn receipt(&mut self, status: &str) -> Result<(), Error> {
        write_receipt(
            &mut self.receipt,
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":1,"directHttpRequests":self.direct_http_requests,"fixtureRegistrations":1,"separateFromBaseline120":true,"clientInternalRequestsCounted":false}),
        )
    }
    fn command(
        &mut self,
        args: &[&str],
        store: &Path,
        session: Option<&str>,
    ) -> Result<String, Error> {
        self.commands += 1;
        require(
            self.commands <= COMMAND_COUNT,
            "User-key-ID CLI command budget exceeded",
        )?;
        if args.first() == Some(&"login") {
            self.logins += 1;
        }
        let mut environment = self.environment.clone();
        environment.insert(
            "BITWARDENCLI_APPDATA_DIR".into(),
            store.as_os_str().to_owned(),
        );
        if let Some(session) = session {
            environment.insert("BW_SESSION".into(), session.into());
        } else {
            environment.remove(&OsString::from("BW_SESSION"));
        }
        let args = args
            .iter()
            .copied()
            .chain(["--nointeraction"])
            .map(OsString::from)
            .collect::<Vec<_>>();
        let result = capture::run(&self.binary, &args, &environment, Duration::from_secs(90))
            .map_err(|_| Error("User-key-ID CLI private capture failed"))?;
        if !result.status.success() {
            eprintln!(
                "User-key-ID CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "User-key-ID CLI command failed")?;
        self.receipt("running")?;
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| Error("User-key-ID CLI output was not UTF-8"))
    }
    fn note(&mut self, id: &str, store: &Path, session: &str) -> Result<(), Error> {
        let value: Value =
            serde_json::from_str(&self.command(&["get", "item", id], store, Some(session))?)
                .map_err(|_| Error("User-key-ID CLI item output was not JSON"))?;
        require(
            value["notes"] == user_key_id::NOTE
                && value["name"] == user_key_id::NOTE
                && value["secureNote"]["type"] == 0,
            "CLI user-key-ID migration failed retained note decryption",
        )
    }
}
fn private_directory(prefix: &str) -> Result<TempDir, Error> {
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| Error("User-key-ID CLI private directory creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("User-key-ID CLI directory permissions failed"))?;
    }
    Ok(directory)
}
fn sync_id(http: &mut Http, token: &str) -> Result<String, Error> {
    let sync = http.sync(token)?;
    let id = text(user_key_id::sync_key_id(&sync)?)?;
    require(
        !id.is_empty(),
        "Official CLI did not initialize a user key ID",
    )?;
    Ok(id.into())
}
pub fn run() -> Result<(), Error> {
    let sender = private_directory("no-warden-key-id-cli-")?;
    let fresh = private_directory("no-warden-key-id-cli-fresh-")?;
    let tls = private_directory("no-warden-key-id-cli-tls-")?;
    let mut http = Http::new()?;
    let account = user_key_id::seed(&mut http)?;
    let before = http.snapshot(&account.token)?;
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("User-key-ID CLI TLS setup failed"))?,
        )
    } else {
        None
    };
    let configured = proxy
        .as_ref()
        .map_or(http.server.as_str(), TlsProxy::url)
        .to_owned();
    let local = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/node_modules/.bin/bw");
    let binary = std::env::var_os("BW_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| if local.exists() { local } else { "bw".into() });
    let mut environment = std::env::vars_os().collect::<BTreeMap<_, _>>();
    for key in [
        "BW_SESSION",
        "BW_CLIENTID",
        "BW_CLIENTSECRET",
        "BW_RESPONSE",
        "BW_QUIET",
        "BW_CLEANEXIT",
    ] {
        environment.remove(&OsString::from(key));
    }
    environment.insert("BW_NOINTERACTION".into(), "true".into());
    environment.insert(
        "BW_USER_KEY_ID_PASSWORD".into(),
        account.password.clone().into(),
    );
    if let Some(proxy) = &proxy {
        environment.insert(
            "NODE_EXTRA_CA_CERTS".into(),
            proxy.certificate().as_os_str().to_owned(),
        );
    }
    let mut cli = Cli {
        binary,
        environment,
        commands: 0,
        logins: 0,
        direct_http_requests: None,
        receipt: receipt_file("BW_USER_KEY_ID_CLI_RECEIPT")?,
        finished: false,
    };
    cli.receipt("running")?;
    require(
        cli.command(&["--version"], sender.path(), None)? == "2026.10.0",
        "User-key-ID official CLI version differed",
    )?;
    cli.command(&["config", "server", &configured], sender.path(), None)?;
    let email = text(&account.fixture["email"])?;
    let login = [
        "login",
        email,
        "--passwordenv",
        "BW_USER_KEY_ID_PASSWORD",
        "--raw",
    ];
    let session = cli.command(&login, sender.path(), None)?;
    require(
        session.len() > 20,
        "User-key-ID CLI unlocked session missing",
    )?;
    // An explicit client sync makes the observation independent of scheduler delay.
    cli.command(&["sync"], sender.path(), Some(&session))?;
    let id = sync_id(&mut http, &account.token)?;
    cli.note(&account.cipher_id, sender.path(), &session)?;
    cli.command(&["lock"], sender.path(), Some(&session))?;
    let session = cli.command(
        &[
            "unlock",
            "--passwordenv",
            "BW_USER_KEY_ID_PASSWORD",
            "--raw",
        ],
        sender.path(),
        None,
    )?;
    require(session.len() > 20, "User-key-ID CLI unlock session missing")?;
    cli.command(&["sync"], sender.path(), Some(&session))?;
    cli.note(&account.cipher_id, sender.path(), &session)?;
    require(
        sync_id(&mut http, &account.token)? == id,
        "CLI unlock changed the initialized user key ID",
    )?;
    cli.command(&["logout"], sender.path(), Some(&session))?;
    cli.command(&["config", "server", &configured], fresh.path(), None)?;
    let session = cli.command(&login, fresh.path(), None)?;
    require(
        session.len() > 20,
        "Fresh-cache user-key-ID CLI login failed",
    )?;
    cli.command(&["sync"], fresh.path(), Some(&session))?;
    cli.note(&account.cipher_id, fresh.path(), &session)?;
    require(
        sync_id(&mut http, &account.token)? == id,
        "Fresh-cache CLI login changed the initialized user key ID",
    )?;
    // Device registrations legitimately differ after fresh client logins. Compare
    // every other protected snapshot field and exact encrypted vault bytes.
    let mut after = http.snapshot(&account.token)?;
    after
        .as_object_mut()
        .ok_or(Error("User-key-ID snapshot malformed"))?
        .remove("devices");
    let mut before = before;
    before
        .as_object_mut()
        .ok_or(Error("User-key-ID initial snapshot malformed"))?
        .remove("devices");
    require(
        after == before,
        "Real CLI key-ID migration changed keys, cipher bytes or account state",
    )?;
    user_key_id::check_note(&mut http, &account)?;
    cli.command(&["logout"], fresh.path(), Some(&session))?;
    require(
        cli.commands == COMMAND_COUNT && cli.logins == 2 && http.logins == 1,
        "User-key-ID CLI proof budget differed",
    )?;
    cli.direct_http_requests = Some(http.requests);
    cli.receipt("passed")?;
    cli.finished = true;
    println!(
        "PASS user-key-ID CLI migration: {} commands, 2 CLI logins, 1 direct fixture login",
        COMMAND_COUNT
    );
    Ok(())
}
