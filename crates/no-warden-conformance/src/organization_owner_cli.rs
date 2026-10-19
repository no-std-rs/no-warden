//! Independently authored owner organization CLI sync/decryption proof.
//! Organization and collection list commands read client caches; no per-route
//! HTTP trace is claimed. The fresh cache must independently unwrap the org key.
use crate::{
    capture,
    organization_owner::{self, Http, Organization},
    text_sends::{TextSendsError as Error, receipt_file, require, text, write_receipt},
    transport::TlsProxy,
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

pub const COMMAND_COUNT: usize = 19;
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
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":1,"directHttpRequests":self.direct_http_requests,"fixtureRegistrations":1,"separateFromBaseline120":true,"clientInternalRequestsCounted":false,"cacheListCallsAreNotHttpTraces":true}),
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
            "Organization CLI command budget exceeded",
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
            .map_err(|_| Error("Organization CLI private capture failed"))?;
        if !result.status.success() {
            eprintln!(
                "Organization CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "Organization CLI command failed")?;
        self.receipt("running")?;
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| Error("Organization CLI output was not UTF-8"))
    }
    fn json(&mut self, args: &[&str], store: &Path, session: &str) -> Result<Value, Error> {
        serde_json::from_str(&self.command(args, store, Some(session))?)
            .map_err(|_| Error("Organization CLI JSON output invalid"))
    }
    fn organizations(&mut self, id: &str, store: &Path, session: &str) -> Result<(), Error> {
        let value = self.json(&["list", "organizations"], store, session)?;
        require(
            value.as_array().is_some_and(|a| {
                a.iter().any(|v| {
                    v["id"] == id
                        && v["name"] == organization_owner::ORG_NAME
                        && v["type"] == 0
                        && v["status"] == 2
                        && v["enabled"] == true
                })
            }),
            "Official CLI omitted confirmed owner organization",
        )
    }
    fn collections(
        &mut self,
        organization: &Organization,
        store: &Path,
        session: &str,
    ) -> Result<(), Error> {
        let value = self.json(
            &["list", "collections", "--organizationid", &organization.id],
            store,
            session,
        )?;
        require(
            value.as_array().is_some_and(|a| {
                a.iter().any(|v| {
                    v["id"] == organization.collection_id
                        && v["organizationId"] == organization.id
                        && v["name"] == organization_owner::COLLECTION_NAME
                })
            }),
            "Official CLI did not decrypt initial organization collection name",
        )
    }
    fn note(&mut self, id: &str, store: &Path, session: &str) -> Result<(), Error> {
        let value = self.json(&["get", "item", id], store, session)?;
        require(
            value["notes"] == organization_owner::NOTE
                && value["name"] == organization_owner::NOTE
                && value["secureNote"]["type"] == 0,
            "Organization CLI flow changed decrypted personal note",
        )
    }
}
fn private_dir(prefix: &str) -> Result<TempDir, Error> {
    let directory = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| Error("Organization CLI private directory creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("Organization CLI directory permissions failed"))?;
    }
    Ok(directory)
}
fn normalize_cli(mut value: Value) -> Result<Value, Error> {
    require(
        value.get("devices").is_some(),
        "Organization CLI device snapshot missing",
    )?;
    value
        .as_object_mut()
        .ok_or(Error("Organization CLI snapshot malformed"))?
        .remove("devices");
    crate::user_key_id::sync_key_id(&value["sync"])?;
    value["sync"]["userDecryption"]["userKeyId"] = Value::Null;
    Ok(value)
}
pub fn run() -> Result<(), Error> {
    let cache = private_dir("no-warden-organization-cli-")?;
    let fresh = private_dir("no-warden-organization-cli-fresh-")?;
    let tls = private_dir("no-warden-organization-cli-tls-")?;
    let mut http = Http::new()?;
    let account = organization_owner::seed(&mut http)?;
    let before = normalize_cli(http.personal(&account.token)?)?;
    let mut organization = Organization::encrypted(&account)?;
    let created = http.json(
        reqwest::Method::POST,
        "/api/organizations",
        &account.token,
        Some(&organization.body),
    )?;
    organization_owner::organization_shape(&created, &organization.body, false)?;
    organization.id = text(&created["id"])?.into();
    organization_owner::inspect_collection(&mut http, &account, &mut organization)?;
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Organization CLI TLS setup failed"))?,
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
    environment.insert(
        "BW_ORGANIZATION_PASSWORD".into(),
        account.password.clone().into(),
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
        logins: 0,
        direct_http_requests: None,
        receipt: receipt_file("BW_ORGANIZATION_OWNER_CLI_RECEIPT")?,
        finished: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], cache.path(), None)? == "2026.10.0",
        "Organization official CLI version differed",
    )?;
    c.command(&["config", "server", &configured], cache.path(), None)?;
    let login = [
        "login",
        text(&account.fixture["email"])?,
        "--passwordenv",
        "BW_ORGANIZATION_PASSWORD",
        "--raw",
    ];
    let session = c.command(&login, cache.path(), None)?;
    require(session.len() > 20, "Organization CLI login did not unlock")?;
    c.command(&["sync"], cache.path(), Some(&session))?;
    c.organizations(&organization.id, cache.path(), &session)?;
    c.collections(&organization, cache.path(), &session)?;
    c.note(&account.cipher_id, cache.path(), &session)?;
    c.command(&["lock"], cache.path(), Some(&session))?;
    let session = c.command(
        &[
            "unlock",
            "--passwordenv",
            "BW_ORGANIZATION_PASSWORD",
            "--raw",
        ],
        cache.path(),
        None,
    )?;
    require(
        session.len() > 20,
        "Organization CLI unlock did not return a session",
    )?;
    c.command(&["sync"], cache.path(), Some(&session))?;
    c.collections(&organization, cache.path(), &session)?;
    c.command(&["logout"], cache.path(), Some(&session))?;
    c.command(&["config", "server", &configured], fresh.path(), None)?;
    let session = c.command(&login, fresh.path(), None)?;
    require(
        session.len() > 20,
        "Fresh-cache organization CLI login failed",
    )?;
    c.command(&["sync"], fresh.path(), Some(&session))?;
    c.organizations(&organization.id, fresh.path(), &session)?;
    c.collections(&organization, fresh.path(), &session)?;
    c.note(&account.cipher_id, fresh.path(), &session)?;
    c.command(&["logout"], fresh.path(), Some(&session))?;
    require(
        normalize_cli(http.personal(&account.token)?)? == before,
        "Organization CLI flow changed personal keys, ciphertext or settings",
    )?;
    require(
        c.commands == COMMAND_COUNT && c.logins == 2 && http.logins == 1,
        "Organization CLI command or identity budget differed",
    )?;
    c.direct_http_requests = Some(http.requests);
    c.receipt("passed")?;
    c.finished = true;
    println!(
        "PASS organization-owner CLI: {} commands, 2 CLI logins, 1 direct setup login",
        COMMAND_COUNT
    );
    Ok(())
}
