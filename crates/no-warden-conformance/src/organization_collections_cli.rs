//! Independently authored official CLI collection create/list/get proof.
//! Calls are established by pinned source; this runner captures no HTTP trace.
use crate::{
    capture, fixture,
    organization_collections::{self, NAME, collection_shape},
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
use uuid::Uuid;

pub const COMMAND_COUNT: usize = 19;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = 14;
pub(crate) const WEB_COMMAND_COUNT: usize = COMMAND_COUNT + 2;
pub(crate) const WEB_DIRECT_HTTP_REQUEST_COUNT: usize = DIRECT_HTTP_REQUEST_COUNT + 11;
#[derive(Clone, Copy)]
enum Observation {
    Standard,
    WebReads,
}
impl Observation {
    fn commands(self) -> usize {
        if matches!(self, Self::WebReads) {
            WEB_COMMAND_COUNT
        } else {
            COMMAND_COUNT
        }
    }
    fn requests(self) -> usize {
        if matches!(self, Self::WebReads) {
            WEB_DIRECT_HTTP_REQUEST_COUNT
        } else {
            DIRECT_HTTP_REQUEST_COUNT
        }
    }
    fn receipt_environment(self) -> &'static str {
        if matches!(self, Self::WebReads) {
            "BW_WEB_ORGANIZATION_READS_CLI_RECEIPT"
        } else {
            "BW_ORGANIZATION_COLLECTIONS_CLI_RECEIPT"
        }
    }
    fn observe(
        self,
        http: &mut Http,
        account: &organization_owner::Account,
        org: &Organization,
        shared: Option<&Value>,
        created: Option<&str>,
    ) -> Result<(), Error> {
        if matches!(self, Self::WebReads) {
            crate::organization_web_reads::observe_owner(
                http,
                account,
                org,
                shared.ok_or(Error("Web CLI shared fixture missing"))?,
                created,
            )?;
        }
        Ok(())
    }
}
struct Cli {
    observation: Observation,
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
        let mut value = json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":self.observation.commands(),"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":1,"directHttpRequests":self.direct_requests,"expectedDirectHttpRequests":self.observation.requests(),"fixtureRegistrations":1,"fixtureRegistrationHttpRequests":2,"separateFromBaseline120":true,"clientInternalRequestsCounted":false,"capturedRouteTrace":false});
        if matches!(self.observation, Observation::WebReads) {
            value["cliWebOrganizationReadCallerClaimed"] = json!(false);
            value["browserTraceClaimed"] = json!(false);
            value["directOrganizationReadRequests"] = json!(9);
            value["actualSharedItemFreshCacheDecryption"] = json!(status == "passed");
            value["fullParityClaimed"] = json!(false);
        }
        write_receipt(&mut self.receipt, &value)
    }
    fn command(
        &mut self,
        args: &[&str],
        store: &Path,
        session: Option<&str>,
    ) -> Result<String, Error> {
        self.commands += 1;
        require(
            self.commands <= self.observation.commands(),
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
                && value["externalId"] == "cli-external 雪\0"
                && value["groups"] == json!([])
                && value["users"] == json!([]),
            "Official CLI did not decrypt collection access details",
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
    run_mode(Observation::Standard)
}
pub(crate) fn run_web_reads() -> Result<(), Error> {
    run_mode(Observation::WebReads)
}
fn run_mode(observation: Observation) -> Result<(), Error> {
    let cache = private_dir("no-warden-collection-cli-")?;
    let fresh = private_dir("no-warden-collection-cli-fresh-")?;
    let tls = private_dir("no-warden-collection-cli-tls-")?;
    let mut http = Http::new()?;
    let account = organization_owner::seed(&mut http)?;
    let organization = organization_collections::create_organization(&mut http, &account)?;
    let shared = if matches!(observation, Observation::WebReads) {
        Some(crate::organization_web_reads::share_fixture(
            &mut http,
            &account,
            &organization,
        )?)
    } else {
        None
    };
    observation.observe(&mut http, &account, &organization, shared.as_ref(), None)?;
    let before = normalize_cli(http.personal(&account.token)?)?;
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Collection CLI TLS setup failed"))?,
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
        observation,
        binary,
        environment,
        commands: 0,
        logins: 0,
        direct_requests: None,
        receipt: receipt_file(observation.receipt_environment())?,
        finished: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], cache.path(), None)? == "2026.10.0",
        "Collection CLI version differed",
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
    require(session.len() > 20, "Collection CLI login did not unlock")?;
    c.command(&["sync"], cache.path(), Some(&session))?;
    c.list(
        &organization,
        &organization.collection_id,
        organization_owner::COLLECTION_NAME,
        cache.path(),
        &session,
        false,
    )?;
    // Omitted groups/users exercise the real CLI constructor's empty groups and
    // own-membership selection. The owner already has accessAll, so no link is stored.
    let encoded = STANDARD.encode(
        json!({"organizationId":organization.id,"name":NAME,"externalId":"cli-external 雪\0"})
            .to_string(),
    );
    let created = c.json(
        &[
            "create",
            "org-collection",
            &encoded,
            "--organizationid",
            &organization.id,
        ],
        cache.path(),
        &session,
    )?;
    let id = text(&created["id"])?.to_owned();
    require(
        Uuid::parse_str(&id).is_ok()
            && created["name"] == NAME
            && created["groups"] == json!([])
            && created["users"] == json!([]),
        "CLI collection creation response differed",
    )?;
    c.get(&organization, &id, cache.path(), &session)?;
    observation.observe(
        &mut http,
        &account,
        &organization,
        shared.as_ref(),
        Some(&id),
    )?;
    c.list(&organization, &id, NAME, cache.path(), &session, false)?;
    c.command(&["sync"], cache.path(), Some(&session))?;
    c.list(&organization, &id, NAME, cache.path(), &session, true)?;
    c.note(&account.cipher_id, cache.path(), &session)?;
    if let Some(shared) = &shared {
        let value = c.json(
            &["get", "item", text(&shared["id"])?],
            cache.path(),
            &session,
        )?;
        check_shared_cli(&value, shared, &organization)?;
    }
    c.command(&["logout"], cache.path(), Some(&session))?;
    c.command(&["config", "server", &configured], fresh.path(), None)?;
    let session = c.command(&login, fresh.path(), None)?;
    require(
        session.len() > 20,
        "Fresh collection CLI login did not unlock",
    )?;
    c.command(&["sync"], fresh.path(), Some(&session))?;
    c.list(&organization, &id, NAME, fresh.path(), &session, false)?;
    c.get(&organization, &id, fresh.path(), &session)?;
    c.note(&account.cipher_id, fresh.path(), &session)?;
    if let Some(shared) = &shared {
        let value = c.json(
            &["get", "item", text(&shared["id"])?],
            fresh.path(),
            &session,
        )?;
        check_shared_cli(&value, shared, &organization)?;
    }
    c.command(&["logout"], fresh.path(), Some(&session))?;
    observation.observe(
        &mut http,
        &account,
        &organization,
        shared.as_ref(),
        Some(&id),
    )?;
    let detail = http.json(
        reqwest::Method::GET,
        &organization_collections::details_path(&organization.id, &id),
        &account.token,
        None,
    )?;
    collection_shape(
        &detail,
        &organization.id,
        &detail["name"],
        &json!("cli-external 雪\0"),
        2,
    )?;
    require(
        fixture::decrypt(text(&detail["name"])?, &organization.key)
            .is_ok_and(|p| p == NAME.as_bytes()),
        "CLI collection ciphertext failed independent authenticated decryption",
    )?;
    require(
        normalize_cli(http.personal(&account.token)?)? == before,
        "Collection CLI changed personal keys, ciphertext or settings",
    )?;
    require(
        c.commands == observation.commands()
            && c.logins == 2
            && http.logins == 1
            && http.requests == observation.requests(),
        "Collection CLI command or login budget differed",
    )?;
    c.direct_requests = Some(http.requests);
    c.receipt("passed")?;
    c.finished = true;
    let label = if matches!(observation, Observation::WebReads) {
        "web-organization-reads"
    } else {
        "organization-collections"
    };
    let count = observation.commands();
    println!("PASS {label} CLI: {count} commands, 2 CLI logins, 1 direct setup login");
    Ok(())
}

fn check_shared_cli(value: &Value, shared: &Value, org: &Organization) -> Result<(), Error> {
    require(
        value["id"] == shared["id"]
            && value["organizationId"] == org.id
            && value["collectionIds"] == json!([org.collection_id])
            && value["name"] == crate::organization_web_reads::NOTE
            && value["notes"] == crate::organization_web_reads::NOTE,
        "Official CLI shared-item decryption differed",
    )
}
