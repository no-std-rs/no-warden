//! Independently authored official-client PBKDF2 and Argon2id discovery proof.
//! Actual fresh caches login, encrypt, sync, unlock and decrypt disposable notes.
//! Internal endpoint traces and unknown-email selection parity are not claimed.
use crate::{
    capture,
    prelogin::{self, Http},
    text_sends::{TextSendsError as Error, receipt_file, require, text, write_receipt},
    transport::TlsProxy,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;

pub const COMMAND_COUNT: usize = 26;
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
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":0,"directHttpRequests":self.direct_http_requests,"fixtureRegistrations":2,"separateFromBaseline120":true,"clientInternalRequestsCounted":false,"knownKdfs":[0,1]}),
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
            "Prelogin CLI command budget exceeded",
        )?;
        if args.first() == Some(&"login") {
            self.logins += 1;
        }
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
        let args = args
            .iter()
            .copied()
            .chain(["--nointeraction"])
            .map(OsString::from)
            .collect::<Vec<_>>();
        let result = capture::run(&self.binary, &args, &env, Duration::from_secs(90))
            .map_err(|_| Error("Prelogin CLI private capture failed"))?;
        if !result.status.success() {
            eprintln!(
                "Prelogin CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "Prelogin CLI command failed")?;
        self.receipt("running")?;
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| Error("Prelogin CLI output was not UTF-8"))
    }
    fn json(&mut self, args: &[&str], store: &Path, session: &str) -> Result<Value, Error> {
        serde_json::from_str(&self.command(args, store, Some(session))?)
            .map_err(|_| Error("Prelogin CLI output was not JSON"))
    }
    fn note(&mut self, id: &str, store: &Path, session: &str) -> Result<(), Error> {
        let value = self.json(&["get", "item", id], store, session)?;
        require(
            value["name"] == "Real prelogin discovery note"
                && value["notes"] == prelogin::NOTE
                && value["secureNote"]["type"] == 0,
            "Actual CLI could not decrypt the prelogin discovery note",
        )
    }
}
fn private_directory(prefix: &str) -> Result<TempDir, Error> {
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| Error("Prelogin CLI private directory creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("Prelogin CLI directory permissions failed"))?;
    }
    Ok(directory)
}
pub fn run() -> Result<(), Error> {
    let pbkdf_cache = private_directory("no-warden-prelogin-pbkdf-")?;
    let argon_cache = private_directory("no-warden-prelogin-argon-")?;
    let fresh_cache = private_directory("no-warden-prelogin-argon-fresh-")?;
    let tls = private_directory("no-warden-prelogin-tls-")?;
    let mut http = Http::new()?;
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Prelogin CLI TLS setup failed"))?,
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
        "BW_RAW",
    ] {
        environment.remove(&OsString::from(key));
    }
    environment.insert("BW_NOINTERACTION".into(), "true".into());
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
        logins: 0,
        direct_http_requests: None,
        receipt: receipt_file("BW_PRELOGIN_CLI_RECEIPT")?,
        finished: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], pbkdf_cache.path(), None)? == "2026.10.0",
        "Prelogin official CLI version differed",
    )?;
    let mut argon_account = None;
    for (argon, cache) in [(false, pbkdf_cache.path()), (true, argon_cache.path())] {
        let (fixture, password) = prelogin::seed_fixture(&http.server, argon)?;
        let email = text(&fixture["email"])?;
        let discovery =
            http.prelogin(prelogin::ROUTES[1], email, None, Some("application/json"))?;
        prelogin::expected(&fixture, &discovery)?;
        c.environment
            .insert("BW_PRELOGIN_PASSWORD".into(), password.clone().into());
        c.command(&["config", "server", &configured], cache, None)?;
        let session = c.command(
            &[
                "login",
                email,
                "--passwordenv",
                "BW_PRELOGIN_PASSWORD",
                "--raw",
            ],
            cache,
            None,
        )?;
        require(session.len() > 20, "Prelogin CLI login did not unlock")?;
        let body = json!({"type":2,"name":"Real prelogin discovery note","notes":prelogin::NOTE,"secureNote":{"type":0},"favorite":false});
        let encoded = STANDARD.encode(body.to_string());
        let created = c.json(&["create", "item", &encoded], cache, &session)?;
        let id = text(&created["id"])?.to_owned();
        c.command(&["sync"], cache, Some(&session))?;
        c.note(&id, cache, &session)?;
        c.command(&["lock"], cache, Some(&session))?;
        let session = c.command(
            &["unlock", "--passwordenv", "BW_PRELOGIN_PASSWORD", "--raw"],
            cache,
            None,
        )?;
        require(
            session.len() > 20,
            "Prelogin CLI unlock did not return a session",
        )?;
        c.command(&["sync"], cache, Some(&session))?;
        c.note(&id, cache, &session)?;
        c.command(&["logout"], cache, Some(&session))?;
        if argon {
            argon_account = Some((fixture, password, id));
        }
    }
    let (fixture, password, id) =
        argon_account.ok_or(Error("Argon2 CLI account was not prepared"))?;
    c.environment
        .insert("BW_PRELOGIN_PASSWORD".into(), password.into());
    c.command(&["config", "server", &configured], fresh_cache.path(), None)?;
    let session = c.command(
        &[
            "login",
            text(&fixture["email"])?,
            "--passwordenv",
            "BW_PRELOGIN_PASSWORD",
            "--raw",
        ],
        fresh_cache.path(),
        None,
    )?;
    require(session.len() > 20, "Fresh Argon2 CLI login did not unlock")?;
    c.command(&["sync"], fresh_cache.path(), Some(&session))?;
    c.note(&id, fresh_cache.path(), &session)?;
    c.command(&["logout"], fresh_cache.path(), Some(&session))?;
    require(
        c.commands == COMMAND_COUNT && c.logins == 3 && http.logins == 0,
        "Prelogin CLI command or credential budget differed",
    )?;
    c.direct_http_requests = Some(http.requests);
    c.receipt("passed")?;
    c.finished = true;
    println!(
        "PASS prelogin CLI: {} commands, 3 CLI logins, 2 direct prelogin requests",
        COMMAND_COUNT
    );
    Ok(())
}
