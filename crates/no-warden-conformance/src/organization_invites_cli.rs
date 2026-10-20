//! Independently authored actual CLI accepted-invitee personal-vault proof.
//! Calls are established by pinned source; this runner captures no HTTP trace.
use crate::{
    capture, fixture, organization_collections, organization_invites,
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

pub const COMMAND_COUNT: usize = 24;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = 16;
const NOTE: &str = "Registered invited personal note 雪\0";
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
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":1,"directHttpRequests":self.direct_requests,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"successfulConfirmationClaimed":false,"cliInvitationCommandClaimed":false,"separateFromBaseline120":true,"clientInternalRequestsCounted":false,"capturedRouteTrace":false}),
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
    fn members(
        &mut self,
        organization: &Organization,
        expected: &Value,
        store: &Path,
        session: &str,
    ) -> Result<(), Error> {
        let value = self.json(
            &["list", "org-members", "--organizationid", &organization.id],
            store,
            session,
        )?;
        require(
            value.as_array().is_some_and(|rows| {
                rows.len() == 2
                    && rows.contains(expected)
                    && rows
                        .iter()
                        .any(|v| v["status"] == 2 && v["type"] == 0 && v["object"] == "org-member")
            }),
            "Official CLI did not discover accepted invitee",
        )
    }
    fn status(
        &mut self,
        user: &str,
        email: &str,
        store: &Path,
        session: &str,
    ) -> Result<(), Error> {
        let value = self.json(&["status"], store, session)?;
        require(
            value["userId"] == user && value["userEmail"] == email && value["status"] == "unlocked",
            "Registered placeholder CLI identity changed",
        )
    }
    fn note(&mut self, id: &str, contents: &str, store: &Path, session: &str) -> Result<(), Error> {
        let value = self.json(&["get", "item", id], store, session)?;
        require(
            value["notes"] == contents
                && value["name"] == contents
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
    let owner_cache = private_dir("no-warden-invite-owner-cli-")?;
    let recipient_cache = private_dir("no-warden-invitee-cli-")?;
    let fresh = private_dir("no-warden-invitee-fresh-cli-")?;
    let tls = private_dir("no-warden-invite-cli-tls-")?;
    let mut http = Http::new()?;
    let owner = organization_owner::seed(&mut http)?;
    let organization = organization_collections::create_organization(&mut http, &owner)?;
    let before = normalize_cli(http.personal(&owner.token)?)?;
    let password = Uuid::new_v4().to_string();
    let account = fixture::registration(
        &format!("cli-placeholder-{}@example.test", Uuid::new_v4()),
        &password,
        600000,
    )
    .map_err(|_| Error("CLI invited-account crypto fixture failed"))?;
    let email = text(&account["email"])?;
    organization_invites::invite_owner(
        &mut http,
        &organization.id,
        &owner.token,
        &organization_invites::ordinary_body(email),
    )?;
    let invited = http.json(
        reqwest::Method::GET,
        &organization_invites::member_path(&organization.id),
        &owner.token,
        None,
    )?;
    let pending = organization_invites::member(&invited, email)?.clone();
    organization_invites::basic_member(&pending, email, 0, 2, &Value::Null, false)?;
    fixture::register_modern_fixture(&http.server, &account)
        .map_err(|_| Error("CLI invited-account modern completion failed"))?;
    let accepted = http.json(
        reqwest::Method::GET,
        &organization_invites::member_path(&organization.id),
        &owner.token,
        None,
    )?;
    let row = organization_invites::member(&accepted, email)?;
    let mut expected = pending;
    expected["status"] = json!(1);
    expected["name"] = account["name"].clone();
    expected["hasMasterPassword"] = json!(true);
    require(
        *row == expected,
        "CLI placeholder completion changed UUID or non-registration authority",
    )?;
    let user_id = text(&row["userId"])?.to_owned();
    let cli_member = json!({"object":"org-member","id":row["id"],"email":email,"name":account["name"],"status":1,"type":2,"twoFactorEnabled":false});
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Invited CLI TLS setup failed"))?,
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
        "BW_INVITE_OWNER_PASSWORD".into(),
        owner.password.clone().into(),
    );
    environment.insert("BW_INVITEE_PASSWORD".into(), password.into());
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
        receipt: receipt_file("BW_ORGANIZATION_INVITES_CLI_RECEIPT")?,
        finished: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], owner_cache.path(), None)? == "2026.10.0",
        "Invited CLI version differed",
    )?;
    c.command(&["config", "server", &configured], owner_cache.path(), None)?;
    let session = c.command(
        &[
            "login",
            text(&owner.fixture["email"])?,
            "--passwordenv",
            "BW_INVITE_OWNER_PASSWORD",
            "--raw",
        ],
        owner_cache.path(),
        None,
    )?;
    require(session.len() > 20, "Owner CLI login did not unlock")?;
    c.command(&["sync"], owner_cache.path(), Some(&session))?;
    c.members(&organization, &cli_member, owner_cache.path(), &session)?;
    c.list(
        &organization,
        &organization.collection_id,
        organization_owner::COLLECTION_NAME,
        owner_cache.path(),
        &session,
        false,
    )?;
    c.note(
        &owner.cipher_id,
        organization_owner::NOTE,
        owner_cache.path(),
        &session,
    )?;
    c.command(&["logout"], owner_cache.path(), Some(&session))?;
    c.command(
        &["config", "server", &configured],
        recipient_cache.path(),
        None,
    )?;
    let login = [
        "login",
        email,
        "--passwordenv",
        "BW_INVITEE_PASSWORD",
        "--raw",
    ];
    let session = c.command(&login, recipient_cache.path(), None)?;
    require(session.len() > 20, "Invited CLI login did not unlock")?;
    c.status(&user_id, email, recipient_cache.path(), &session)?;
    let encoded = STANDARD.encode(
        json!({"type":2,"name":NOTE,"notes":NOTE,"secureNote":{"type":0},"favorite":false})
            .to_string(),
    );
    let created = c.json(
        &["create", "item", &encoded],
        recipient_cache.path(),
        &session,
    )?;
    let id = text(&created["id"])?.to_owned();
    require(
        Uuid::parse_str(&id).is_ok(),
        "Invited CLI did not create a personal item",
    )?;
    c.command(&["sync"], recipient_cache.path(), Some(&session))?;
    c.note(&id, NOTE, recipient_cache.path(), &session)?;
    c.command(&["lock"], recipient_cache.path(), Some(&session))?;
    let session = c.command(
        &["unlock", "--passwordenv", "BW_INVITEE_PASSWORD", "--raw"],
        recipient_cache.path(),
        None,
    )?;
    require(
        session.len() > 20,
        "Invited CLI unlock did not return session",
    )?;
    c.note(&id, NOTE, recipient_cache.path(), &session)?;
    c.command(&["logout"], recipient_cache.path(), Some(&session))?;
    c.command(&["config", "server", &configured], fresh.path(), None)?;
    let session = c.command(&login, fresh.path(), None)?;
    require(session.len() > 20, "Fresh invited CLI login failed")?;
    c.status(&user_id, email, fresh.path(), &session)?;
    c.command(&["sync"], fresh.path(), Some(&session))?;
    c.note(&id, NOTE, fresh.path(), &session)?;
    c.command(&["logout"], fresh.path(), Some(&session))?;
    require(
        normalize_cli(http.personal(&owner.token)?)? == before,
        "Invited CLI lifecycle changed owner vault, keys or settings",
    )?;
    require(
        c.commands == COMMAND_COUNT
            && c.logins == 3
            && http.logins == 1
            && http.requests == DIRECT_HTTP_REQUEST_COUNT,
        "Invited CLI command or authentication budget differed",
    )?;
    c.direct_requests = Some(http.requests);
    c.receipt("passed")?;
    c.finished = true;
    println!(
        "PASS organization-invites CLI: {COMMAND_COUNT} commands, 3 CLI logins, 1 direct setup login"
    );
    Ok(())
}
