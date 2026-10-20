//! Independently authored actual CLI recipient decryption after direct HTTP bulk confirmation.
//! Calls are established by pinned source; this runner captures no HTTP trace.
use crate::{
    capture, fixture, organization_bulk_confirmations as bulk, organization_collections,
    organization_confirmations as confirmation, organization_invites,
    organization_owner::{self, Http, Organization},
    text_sends::{TextSendsError as Error, receipt_file, require, text, write_receipt},
    transport::TlsProxy,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;

pub const COMMAND_COUNT: usize = 21;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = 33;
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
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":2,"directHttpRequests":self.direct_requests,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"successfulConfirmationClaimed":true,"cliBulkCallerClaimed":false,"bulkSetupViaDirectHttp":true,"cliInvitationCommandClaimed":false,"separateFromBaseline120":true,"clientInternalRequestsCounted":false,"capturedRouteTrace":false}),
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
                a.iter().filter(|v| v["organizationId"] == org.id).count() == 1
                    && a.iter().any(|v| {
                        v["id"] == id && v["organizationId"] == org.id && v["name"] == name
                    })
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
    let owner_cache = private_dir("no-warden-confirm-owner-cli-")?;
    let recipient_cache = private_dir("no-warden-confirm-recipient-cli-")?;
    let fresh = private_dir("no-warden-confirm-fresh-cli-")?;
    let tls = private_dir("no-warden-confirm-cli-tls-")?;
    let mut http = Http::new()?;
    let owner = organization_owner::seed(&mut http)?;
    let recipient = organization_owner::seed(&mut http)?;
    let org = organization_collections::create_organization(&mut http, &owner)?;
    let hidden = confirmation::hidden_collection(&mut http, &owner, &org)?;
    organization_invites::invite_owner(
        &mut http,
        &org.id,
        &owner.token,
        &confirmation::invitation(
            text(&recipient.fixture["email"])?,
            2,
            Some(&org.collection_id),
        ),
    )?;
    let row = confirmation::member_row(
        &mut http,
        &org.id,
        &owner.token,
        text(&recipient.fixture["email"])?,
    )?;
    require(
        row["status"] == 1 && row["userId"] == recipient.user_id,
        "CLI confirmation fixture was not accepted recipient",
    )?;
    let personal = [
        normalize_cli(http.personal(&owner.token)?)?,
        normalize_cli(http.personal(&recipient.token)?)?,
    ];
    let profile = http.json(
        reqwest::Method::GET,
        "/api/accounts/profile",
        &recipient.token,
        None,
    )?;
    require(
        confirmation::org_in(&profile, "organizations", &org.id)?.is_none()
            && confirmation::org_in(&profile, "organizationsNew", &org.id)?
                .is_some_and(|o| o["key"] == ""),
        "CLI recipient already had confirmed organization key",
    )?;
    let wrapped = fixture::organization_key_for_account(&recipient.fixture, &org.key)
        .map_err(|_| Error("Bulk CLI setup RSA wrapping failed"))?;
    http.requests += 1;
    let value = crate::text_sends::http_client()?
        .post(format!("{}{}", http.server, bulk::path(&org.id)))
        .bearer_auth(&owner.token)
        .json(&json!({"keys":[{"id":row["id"],"key":wrapped}]}))
        .send()
        .map_err(|_| Error("Bulk CLI setup HTTP failed"))?;
    require(
        value.status().as_u16() == 200,
        "Bulk CLI setup status differed",
    )?;
    let mut bytes = Vec::new();
    std::io::Read::take(value, 16 * 1024 * 1024 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error("Bulk CLI setup private response capture failed"))?;
    require(
        bytes.len() <= 16 * 1024 * 1024,
        "Bulk CLI setup response exceeded bound",
    )?;
    let value: Value =
        serde_json::from_slice(&bytes).map_err(|_| Error("Bulk CLI setup response malformed"))?;
    bulk::result(&value, &[(text(&row["id"])?, "")])?;
    let after = confirmation::member_row(
        &mut http,
        &org.id,
        &owner.token,
        text(&recipient.fixture["email"])?,
    )?;
    confirmation::member_after(&row, &after, 2)?;
    let profile = http.json(
        reqwest::Method::GET,
        "/api/accounts/profile",
        &recipient.token,
        None,
    )?;
    require(
        confirmation::org_in(&profile, "organizations", &org.id)?
            .is_some_and(|o| o["key"].as_str().is_some_and(|k| k.starts_with("4."))),
        "Bulk setup did not deliver confirmed RSA-OAEP organization key",
    )?;
    let collections = http.json(
        reqwest::Method::GET,
        "/api/collections",
        &recipient.token,
        None,
    )?;
    confirmation::selective(&collections, &org, text(&hidden["id"])?, false)?;
    let sync = http.json(reqwest::Method::GET, "/api/sync", &recipient.token, None)?;
    confirmation::selective(&sync, &org, text(&hidden["id"])?, true)?;
    let cli_member = json!({"object":"org-member","id":row["id"],"email":recipient.fixture["email"],"name":recipient.fixture["name"],"status":2,"type":2,"twoFactorEnabled":false});
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Confirmation CLI TLS setup failed"))?,
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
        "BW_CONFIRM_OWNER_PASSWORD".into(),
        owner.password.clone().into(),
    );
    environment.insert(
        "BW_CONFIRM_RECIPIENT_PASSWORD".into(),
        recipient.password.clone().into(),
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
        receipt: receipt_file("BW_ORGANIZATION_BULK_CONFIRMATION_CLI_RECEIPT")?,
        finished: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], owner_cache.path(), None)? == "2026.10.0",
        "Confirmation CLI version differed",
    )?;
    c.command(&["config", "server", &configured], owner_cache.path(), None)?;
    let session = c.command(
        &[
            "login",
            text(&owner.fixture["email"])?,
            "--passwordenv",
            "BW_CONFIRM_OWNER_PASSWORD",
            "--raw",
        ],
        owner_cache.path(),
        None,
    )?;
    require(session.len() > 20, "Confirmation owner CLI login failed")?;
    c.command(&["sync"], owner_cache.path(), Some(&session))?;
    c.members(&org, &cli_member, owner_cache.path(), &session)?;
    c.command(&["logout"], owner_cache.path(), Some(&session))?;
    c.command(
        &["config", "server", &configured],
        recipient_cache.path(),
        None,
    )?;
    let login = [
        "login",
        text(&recipient.fixture["email"])?,
        "--passwordenv",
        "BW_CONFIRM_RECIPIENT_PASSWORD",
        "--raw",
    ];
    let session = c.command(&login, recipient_cache.path(), None)?;
    require(
        session.len() > 20,
        "Confirmation recipient CLI login failed",
    )?;
    c.command(&["sync"], recipient_cache.path(), Some(&session))?;
    c.list(
        &org,
        &org.collection_id,
        organization_owner::COLLECTION_NAME,
        recipient_cache.path(),
        &session,
        true,
    )?;
    c.list(
        &org,
        &org.collection_id,
        organization_owner::COLLECTION_NAME,
        recipient_cache.path(),
        &session,
        false,
    )?;
    c.command(&["lock"], recipient_cache.path(), Some(&session))?;
    let session = c.command(
        &[
            "unlock",
            "--passwordenv",
            "BW_CONFIRM_RECIPIENT_PASSWORD",
            "--raw",
        ],
        recipient_cache.path(),
        None,
    )?;
    require(session.len() > 20, "Confirmed recipient unlock failed")?;
    c.list(
        &org,
        &org.collection_id,
        organization_owner::COLLECTION_NAME,
        recipient_cache.path(),
        &session,
        true,
    )?;
    c.command(&["logout"], recipient_cache.path(), Some(&session))?;
    c.command(&["config", "server", &configured], fresh.path(), None)?;
    let session = c.command(&login, fresh.path(), None)?;
    require(session.len() > 20, "Fresh confirmed recipient login failed")?;
    c.command(&["sync"], fresh.path(), Some(&session))?;
    c.list(
        &org,
        &org.collection_id,
        organization_owner::COLLECTION_NAME,
        fresh.path(),
        &session,
        true,
    )?;
    c.list(
        &org,
        &org.collection_id,
        organization_owner::COLLECTION_NAME,
        fresh.path(),
        &session,
        false,
    )?;
    c.command(&["logout"], fresh.path(), Some(&session))?;
    for (i, account) in [&owner, &recipient].into_iter().enumerate() {
        require(
            normalize_cli(http.personal(&account.token)?)? == personal[i],
            "Confirmation CLI changed personal ciphertext, credentials or settings",
        )?;
    }
    require(
        c.commands == COMMAND_COUNT
            && c.logins == 3
            && http.logins == 2
            && http.requests == DIRECT_HTTP_REQUEST_COUNT,
        "Confirmation CLI request or command budget differed",
    )?;
    c.direct_requests = Some(http.requests);
    c.receipt("passed")?;
    c.finished = true;
    println!(
        "PASS organization-bulk-confirmation CLI: {COMMAND_COUNT} commands, 3 CLI logins, 2 direct setup logins"
    );
    Ok(())
}
