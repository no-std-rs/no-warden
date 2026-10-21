//! Actual CLI ordinary edits with independent fresh Owner/recipient caches.
//! The safe TLS adapter captures no requests; separate native research traces
//! are not promoted into this final paired runner's evidence.
use crate::{
    capture, organization_cipher_bulk_sharing as bulk, organization_cipher_update as update,
    organization_collections::create_organization,
    organization_owner::{self, Account, Http},
    text_sends::{TextSendsError as Error, receipt_file, require, text, write_receipt},
    transport::TlsProxy,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use reqwest::Method;
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    time::Duration,
};
use tempfile::TempDir;
pub const COMMAND_COUNT: usize = 32;
pub const DIRECT_HTTP_REQUEST_COUNT: usize = 16;
struct Cli {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    commands: usize,
    logins: usize,
    direct: Option<usize>,
    receipt: Option<fs::File>,
    finished: bool,
    owner_edit: bool,
    recipient_edit: bool,
    owner_fresh: bool,
    recipient_fresh: bool,
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
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directHttpRequests":self.direct,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,"directPasswordLoginRequests":2,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"actualOwnerEditCommandExecuted":self.owner_edit,"actualRecipientEditCommandExecuted":self.recipient_edit,"ownerFreshCacheDecryptionCompleted":self.owner_fresh,"recipientFreshCacheDecryptionCompleted":self.recipient_fresh,"personalEditControlAsserted":self.owner_fresh,"recipientPersonalControlPreserved":self.recipient_fresh,"capturedRouteTrace":false,"clientInternalRequestsCounted":false,"browserTraceClaimed":false,"configuredGroups":false,"configuredPolicies":false,"smtpEnabled":false,"attachments":false,"otherItemTypes":false,"fullParityClaimed":false,"separateFromBaseline120":true}),
        )
    }
    fn command(
        &mut self,
        args: &[&str],
        cache: &Path,
        session: Option<&str>,
    ) -> Result<String, Error> {
        self.commands += 1;
        require(
            self.commands <= COMMAND_COUNT,
            "Shared edit CLI command budget exceeded",
        )?;
        if args.first() == Some(&"login") {
            self.logins += 1;
        }
        let mut env = self.environment.clone();
        env.insert(
            "BITWARDENCLI_APPDATA_DIR".into(),
            cache.as_os_str().to_owned(),
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
        let result = capture::run(&self.binary, &args, &env, Duration::from_secs(180))
            .map_err(|_| Error("Shared edit CLI private capture failed"))?;
        if !result.status.success() {
            eprintln!(
                "Shared edit CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "Shared edit CLI command failed")?;
        self.receipt("running")?;
        String::from_utf8(result.stdout)
            .map(|v| v.trim().to_owned())
            .map_err(|_| Error("Shared edit CLI output was not UTF8"))
    }
    fn json(&mut self, args: &[&str], cache: &Path, session: &str) -> Result<Value, Error> {
        serde_json::from_str(&self.command(args, cache, Some(session))?)
            .map_err(|_| Error("Shared edit CLI JSON malformed"))
    }
}
fn private_dir() -> Result<TempDir, Error> {
    let dir = tempfile::Builder::new()
        .prefix("no-warden-shared-edit-cli-")
        .tempdir()
        .map_err(|_| Error("Shared edit CLI private directory failed"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("Shared edit CLI directory permissions failed"))?;
    }
    Ok(dir)
}
fn login(
    c: &mut Cli,
    a: &Account,
    cache: &Path,
    server: &str,
    passwordenv: &str,
) -> Result<String, Error> {
    c.command(&["config", "server", server], cache, None)?;
    let session = c.command(
        &[
            "login",
            text(&a.fixture["email"])?,
            "--passwordenv",
            passwordenv,
            "--raw",
        ],
        cache,
        None,
    )?;
    require(session.len() > 20, "Shared edit CLI login failed to unlock")?;
    c.command(&["sync"], cache, Some(&session))?;
    Ok(session)
}
fn check(
    v: &Value,
    id: &str,
    org: Option<&str>,
    collection: Option<&str>,
    plaintext: &str,
) -> Result<(), Error> {
    require(
        v["id"] == id
            && v["name"] == plaintext
            && v["notes"] == plaintext
            && v["type"] == 2
            && v["secureNote"]["type"] == 0,
        "Shared edit CLI plaintext or identity differed",
    )?;
    require(
        match org {
            Some(org) => {
                v["organizationId"] == org
                    && v["collectionIds"].as_array().is_some_and(|a| {
                        a.iter()
                            .any(|id| Some(id.as_str().unwrap_or("")) == collection)
                    })
            }
            None => v["organizationId"].is_null(),
        },
        "Shared edit CLI canonical ownership differed",
    )
}
fn read(
    c: &mut Cli,
    cache: &Path,
    session: &str,
    id: &str,
    org: Option<&str>,
    collection: Option<&str>,
    plaintext: &str,
) -> Result<Value, Error> {
    let v = c.json(&["get", "item", id], cache, session)?;
    check(&v, id, org, collection, plaintext)?;
    Ok(v)
}
fn edit(
    c: &mut Cli,
    cache: &Path,
    session: &str,
    id: &str,
    mut value: Value,
    plaintext: &str,
) -> Result<Value, Error> {
    value["name"] = json!(plaintext);
    value["notes"] = json!(plaintext);
    c.json(
        &["edit", "item", id, &STANDARD.encode(value.to_string())],
        cache,
        session,
    )
}
pub fn run() -> Result<(), Error> {
    let mut http = Http::new()?;
    let owner = organization_owner::seed(&mut http)?;
    let recipient = organization_owner::seed(&mut http)?;
    let org = create_organization(&mut http, &owner)?;
    let member = bulk::invite(
        &mut http,
        &owner,
        &recipient,
        &org,
        2,
        json!([{"id":org.collection_id,"readOnly":false,"hidePasswords":false,"manage":false}]),
        true,
    )?;
    let confirmed = http.json(
        Method::GET,
        &format!(
            "/api/organizations/{}/users/{member}?includeCollections=true",
            org.id
        ),
        &owner.token,
        None,
    )?;
    require(
        confirmed["status"] == 2
            && confirmed["type"] == 2
            && confirmed["collections"].as_array().is_some_and(|rows| {
                rows.iter().any(|v| {
                    v["id"] == org.collection_id
                        && v["readOnly"] == false
                        && v["hidePasswords"] == false
                        && v["manage"] == false
                })
            }),
        "Shared edit CLI recipient admission fixture differed",
    )?;
    let shared = update::seed_shared(&mut http, &owner, &org, None)?;
    let id = text(&shared["id"])?.to_owned();
    let private = private_dir()?;
    let tls = private_dir()?;
    let proxy = TlsProxy::start(&http.server, tls.path())
        .map_err(|_| Error("Shared edit CLI TLS adapter failed"))?;
    let mut environment = std::env::vars_os().collect::<BTreeMap<_, _>>();
    for name in [
        "BW_SESSION",
        "BW_CLIENTID",
        "BW_CLIENTSECRET",
        "BW_E2E_EMAIL",
        "BW_E2E_PASSWORD",
        "DEBUG",
        "DEBUG_FILE",
        "NODE_DEBUG",
        "NODE_DEBUG_NATIVE",
        "PWDEBUG",
    ] {
        environment.remove(&OsString::from(name));
    }
    environment.insert(
        "NODE_EXTRA_CA_CERTS".into(),
        proxy.certificate().as_os_str().to_owned(),
    );
    environment.insert("BW_NOINTERACTION".into(), "true".into());
    environment.insert(
        "BW_SHARED_EDIT_OWNER_PASSWORD".into(),
        owner.password.clone().into(),
    );
    environment.insert(
        "BW_SHARED_EDIT_RECIPIENT_PASSWORD".into(),
        recipient.password.clone().into(),
    );
    let mut c = Cli {
        binary: std::env::var_os("BW_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| "bw".into()),
        environment,
        commands: 0,
        logins: 0,
        direct: None,
        receipt: receipt_file("BW_ORGANIZATION_CIPHER_UPDATE_CLI_RECEIPT")?,
        finished: false,
        owner_edit: false,
        recipient_edit: false,
        owner_fresh: false,
        recipient_fresh: false,
    };
    let owner_cache = private.path().join("owner");
    let recipient_cache = private.path().join("recipient");
    let owner_fresh_cache = private.path().join("owner-fresh");
    let recipient_fresh_cache = private.path().join("recipient-fresh");
    require(
        c.command(&["--version"], &owner_cache, None)? == "2026.10.0",
        "Shared edit CLI version differed",
    )?;
    let owner_session = login(
        &mut c,
        &owner,
        &owner_cache,
        proxy.url(),
        "BW_SHARED_EDIT_OWNER_PASSWORD",
    )?;
    let recipient_session = login(
        &mut c,
        &recipient,
        &recipient_cache,
        proxy.url(),
        "BW_SHARED_EDIT_RECIPIENT_PASSWORD",
    )?;
    let personal_plain = format!("{}personal", update::NOTE);
    let owner_plain = format!("{}owner", update::NOTE);
    let recipient_plain = format!("{}recipient", update::NOTE);
    let personal = read(
        &mut c,
        &owner_cache,
        &owner_session,
        &owner.cipher_id,
        None,
        None,
        organization_owner::NOTE,
    )?;
    let edited = edit(
        &mut c,
        &owner_cache,
        &owner_session,
        &owner.cipher_id,
        personal,
        &personal_plain,
    )?;
    check(&edited, &owner.cipher_id, None, None, &personal_plain)?;
    let original = read(
        &mut c,
        &owner_cache,
        &owner_session,
        &id,
        Some(&org.id),
        Some(&org.collection_id),
        update::NOTE,
    )?;
    let edited = edit(
        &mut c,
        &owner_cache,
        &owner_session,
        &id,
        original,
        &owner_plain,
    )?;
    check(
        &edited,
        &id,
        Some(&org.id),
        Some(&org.collection_id),
        &owner_plain,
    )?;
    c.owner_edit = true;
    c.command(&["sync"], &owner_cache, Some(&owner_session))?;
    read(
        &mut c,
        &owner_cache,
        &owner_session,
        &id,
        Some(&org.id),
        Some(&org.collection_id),
        &owner_plain,
    )?;
    c.command(&["sync"], &recipient_cache, Some(&recipient_session))?;
    let current = read(
        &mut c,
        &recipient_cache,
        &recipient_session,
        &id,
        Some(&org.id),
        Some(&org.collection_id),
        &owner_plain,
    )?;
    let edited = edit(
        &mut c,
        &recipient_cache,
        &recipient_session,
        &id,
        current,
        &recipient_plain,
    )?;
    check(
        &edited,
        &id,
        Some(&org.id),
        Some(&org.collection_id),
        &recipient_plain,
    )?;
    c.recipient_edit = true;
    c.command(&["sync"], &recipient_cache, Some(&recipient_session))?;
    read(
        &mut c,
        &recipient_cache,
        &recipient_session,
        &id,
        Some(&org.id),
        Some(&org.collection_id),
        &recipient_plain,
    )?;
    let owner_fresh = login(
        &mut c,
        &owner,
        &owner_fresh_cache,
        proxy.url(),
        "BW_SHARED_EDIT_OWNER_PASSWORD",
    )?;
    read(
        &mut c,
        &owner_fresh_cache,
        &owner_fresh,
        &id,
        Some(&org.id),
        Some(&org.collection_id),
        &recipient_plain,
    )?;
    read(
        &mut c,
        &owner_fresh_cache,
        &owner_fresh,
        &owner.cipher_id,
        None,
        None,
        &personal_plain,
    )?;
    c.owner_fresh = true;
    let recipient_fresh = login(
        &mut c,
        &recipient,
        &recipient_fresh_cache,
        proxy.url(),
        "BW_SHARED_EDIT_RECIPIENT_PASSWORD",
    )?;
    read(
        &mut c,
        &recipient_fresh_cache,
        &recipient_fresh,
        &id,
        Some(&org.id),
        Some(&org.collection_id),
        &recipient_plain,
    )?;
    read(
        &mut c,
        &recipient_fresh_cache,
        &recipient_fresh,
        &recipient.cipher_id,
        None,
        None,
        organization_owner::NOTE,
    )?;
    c.recipient_fresh = true;
    for a in [&owner, &recipient] {
        let projected = http.json(Method::GET, &format!("/api/ciphers/{id}"), &a.token, None)?;
        require(
            projected["id"] == id
                && projected["organizationId"] == org.id
                && projected["collectionIds"] == json!([org.collection_id]),
            "Shared edit CLI HTTP control lost canonical associations",
        )?;
    }
    for (cache, session) in [
        (&owner_cache, &owner_session),
        (&recipient_cache, &recipient_session),
        (&owner_fresh_cache, &owner_fresh),
        (&recipient_fresh_cache, &recipient_fresh),
    ] {
        c.command(&["logout"], cache, Some(session))?;
    }
    c.direct = Some(http.requests);
    if c.commands != COMMAND_COUNT || http.requests != DIRECT_HTTP_REQUEST_COUNT {
        eprintln!(
            "Shared edit CLI counts: commands {}, direct HTTP {}",
            c.commands, http.requests
        );
    }
    require(
        c.commands == COMMAND_COUNT && http.requests == DIRECT_HTTP_REQUEST_COUNT && c.logins == 4,
        "Shared edit CLI final count differed",
    )?;
    c.receipt("passed")?;
    c.finished = true;
    Ok(())
}
