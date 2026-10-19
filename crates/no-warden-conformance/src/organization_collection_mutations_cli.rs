//! Independently authored official CLI collection rename/delete proof.
//! Calls are established by pinned source; this runner captures no HTTP trace.
use crate::{
    capture, fixture,
    organization_collection_mutations::NAME,
    organization_collections::{self, collection_shape},
    organization_owner::{self, Http, Organization},
    text_sends::{TextSendsError as Error, receipt_file, require, text, write_receipt},
    transport::TlsProxy,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;

pub const COMMAND_COUNT: usize = 20;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = 15;
struct Cli {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    commands: usize,
    logins: usize,
    direct_requests: Option<usize>,
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
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":1,"directHttpRequests":self.direct_requests,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,"fixtureRegistrations":1,"fixtureRegistrationHttpRequests":2,"separateFromBaseline120":true,"clientInternalRequestsCounted":false,"capturedRouteTrace":false}),
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
            "Collection CLI command budget exceeded",
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
            .map_err(|_| Error("Collection CLI private capture failed"))?;
        if !result.status.success() {
            eprintln!(
                "Collection CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "Collection CLI command failed")?;
        self.receipt("running")?;
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| Error("Collection CLI output was not UTF-8"))
    }
    fn json(&mut self, args: &[&str], store: &Path, session: &str) -> Result<Value, Error> {
        serde_json::from_str(&self.command(args, store, Some(session))?)
            .map_err(|_| Error("Collection CLI JSON output invalid"))
    }
    fn list(
        &mut self,
        org: &Organization,
        id: &str,
        name: &str,
        store: &Path,
        session: &str,
        cached: bool,
    ) -> Result<(), Error> {
        let kind = if cached {
            "collections"
        } else {
            "org-collections"
        };
        let value = self.json(&["list", kind, "--organizationid", &org.id], store, session)?;
        require(
            value.as_array().is_some_and(|a| {
                a.iter()
                    .any(|v| v["id"] == id && v["organizationId"] == org.id && v["name"] == name)
            }),
            "Official CLI did not decrypt listed collection name",
        )
    }
    fn get(
        &mut self,
        org: &Organization,
        id: &str,
        store: &Path,
        session: &str,
    ) -> Result<(), Error> {
        let value = self.json(
            &["get", "org-collection", id, "--organizationid", &org.id],
            store,
            session,
        )?;
        require(
            value["id"] == id
                && value["organizationId"] == org.id
                && value["name"] == NAME
                && value["externalId"] == "renamed-cli-external 雪\0"
                && value["groups"] == json!([])
                && value["users"] == json!([]),
            "Official CLI did not decrypt collection access details",
        )
    }
    fn absent(
        &mut self,
        org: &Organization,
        store: &Path,
        session: &str,
        cached: bool,
    ) -> Result<(), Error> {
        let kind = if cached {
            "collections"
        } else {
            "org-collections"
        };
        let value = self.json(&["list", kind, "--organizationid", &org.id], store, session)?;
        require(
            value.as_array().is_some_and(Vec::is_empty),
            "Official CLI retained a deleted collection",
        )
    }
    fn note(&mut self, id: &str, store: &Path, session: &str) -> Result<(), Error> {
        let value = self.json(&["get", "item", id], store, session)?;
        require(
            value["notes"] == organization_owner::NOTE
                && value["name"] == organization_owner::NOTE
                && value["secureNote"]["type"] == 0,
            "Collection CLI flow changed personal note decryption",
        )
    }
}
fn private_dir(prefix: &str) -> Result<TempDir, Error> {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| Error("Collection CLI private directory creation failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("Collection CLI private permissions failed"))?;
    }
    Ok(dir)
}
fn normalize_cli(mut value: Value) -> Result<Value, Error> {
    require(
        value.get("devices").is_some(),
        "Collection CLI device snapshot missing",
    )?;
    value
        .as_object_mut()
        .ok_or(Error("Collection CLI snapshot malformed"))?
        .remove("devices");
    crate::user_key_id::sync_key_id(&value["sync"])?;
    value["sync"]["userDecryption"]["userKeyId"] = Value::Null;
    Ok(value)
}
pub fn run() -> Result<(), Error> {
    let cache = private_dir("no-warden-collection-mutation-cli-")?;
    let fresh = private_dir("no-warden-collection-mutation-cli-fresh-")?;
    let tls = private_dir("no-warden-collection-mutation-cli-tls-")?;
    let mut http = Http::new()?;
    let account = organization_owner::seed(&mut http)?;
    let organization = organization_collections::create_organization(&mut http, &account)?;
    let before = normalize_cli(http.personal(&account.token)?)?;
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Collection mutation CLI TLS setup failed"))?,
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
        "BW_COLLECTION_PASSWORD".into(),
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
        direct_requests: None,
        receipt: receipt_file("BW_ORGANIZATION_COLLECTION_MUTATIONS_CLI_RECEIPT")?,
        finished: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], cache.path(), None)? == "2026.10.0",
        "Collection mutation CLI version differed",
    )?;
    c.command(&["config", "server", &configured], cache.path(), None)?;
    let login = [
        "login",
        text(&account.fixture["email"])?,
        "--passwordenv",
        "BW_COLLECTION_PASSWORD",
        "--raw",
    ];
    let session = c.command(&login, cache.path(), None)?;
    require(
        session.len() > 20,
        "Collection mutation CLI login did not unlock",
    )?;
    c.command(&["sync"], cache.path(), Some(&session))?;
    let encoded=STANDARD.encode(json!({"organizationId":organization.id,"name":NAME,"externalId":"renamed-cli-external 雪\0"}).to_string());
    // The real edit constructor encrypts the name and emits [] for omitted groups/users.
    let updated = c.json(
        &[
            "edit",
            "org-collection",
            &organization.collection_id,
            &encoded,
            "--organizationid",
            &organization.id,
        ],
        cache.path(),
        &session,
    )?;
    require(
        updated["id"] == organization.collection_id
            && updated["name"] == NAME
            && updated["groups"] == json!([])
            && updated["users"] == json!([]),
        "CLI collection update response differed",
    )?;
    let detail = http.json(
        reqwest::Method::GET,
        &organization_collections::details_path(&organization.id, &organization.collection_id),
        &account.token,
        None,
    )?;
    collection_shape(
        &detail,
        &organization.id,
        &detail["name"],
        &json!("renamed-cli-external 雪\0"),
        2,
    )?;
    require(
        fixture::decrypt(text(&detail["name"])?, &organization.key)
            .is_ok_and(|p| p == NAME.as_bytes()),
        "CLI renamed ciphertext failed independent authenticated decryption",
    )?;
    c.get(
        &organization,
        &organization.collection_id,
        cache.path(),
        &session,
    )?;
    c.list(
        &organization,
        &organization.collection_id,
        NAME,
        cache.path(),
        &session,
        false,
    )?;
    c.command(&["sync"], cache.path(), Some(&session))?;
    c.list(
        &organization,
        &organization.collection_id,
        NAME,
        cache.path(),
        &session,
        true,
    )?;
    c.command(&["logout"], cache.path(), Some(&session))?;
    c.command(&["config", "server", &configured], fresh.path(), None)?;
    let session = c.command(&login, fresh.path(), None)?;
    require(
        session.len() > 20,
        "Fresh collection mutation CLI login did not unlock",
    )?;
    c.command(&["sync"], fresh.path(), Some(&session))?;
    c.get(
        &organization,
        &organization.collection_id,
        fresh.path(),
        &session,
    )?;
    c.command(
        &[
            "delete",
            "org-collection",
            &organization.collection_id,
            "--organizationid",
            &organization.id,
        ],
        fresh.path(),
        Some(&session),
    )?;
    c.absent(&organization, fresh.path(), &session, false)?;
    c.command(&["sync"], fresh.path(), Some(&session))?;
    c.absent(&organization, fresh.path(), &session, true)?;
    c.note(&account.cipher_id, fresh.path(), &session)?;
    c.command(&["logout"], fresh.path(), Some(&session))?;
    let remaining = http.json(
        reqwest::Method::GET,
        &organization_collections::path(&organization.id),
        &account.token,
        None,
    )?;
    require(
        remaining["data"] == json!([]),
        "CLI deleted collection remained in direct server list",
    )?;
    require(
        normalize_cli(http.personal(&account.token)?)? == before,
        "Collection CLI mutations changed personal keys, ciphertext or settings",
    )?;
    require(
        c.commands == COMMAND_COUNT
            && c.logins == 2
            && http.logins == 1
            && http.requests == DIRECT_HTTP_REQUEST_COUNT,
        "Collection mutation CLI command or login budget differed",
    )?;
    c.direct_requests = Some(http.requests);
    c.receipt("passed")?;
    c.finished = true;
    println!(
        "PASS organization-collection-mutations CLI: {COMMAND_COUNT} commands, 2 CLI logins, 1 direct setup login"
    );
    Ok(())
}
