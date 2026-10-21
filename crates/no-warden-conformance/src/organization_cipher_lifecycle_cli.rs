//! Actual official CLI Trash/restore commands on a shared secure note.
//! Source-attributed single lifecycle and selected unarchive callers; no captured HTTP trace or browser claim.
//! Independently authored MIT OR Apache-2.0.
use crate::{
    capture, fixture,
    organization_collections::create_organization,
    organization_confirmations, organization_invites,
    organization_owner::{self, Account, Http, Organization},
    text_sends::{
        TextSendsError as Error, http_client, receipt_file, require, text, write_receipt,
    },
    transport::TlsProxy,
};
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

pub const COMMAND_COUNT: usize = 63;
// Measured native63-command flow; excludes four registration requests.
pub const DIRECT_HTTP_REQUEST_COUNT: usize = 101;
struct Cli {
    binary: PathBuf,
    environment: BTreeMap<OsString, OsString>,
    commands: usize,
    logins: usize,
    direct: Option<usize>,
    receipt: Option<fs::File>,
    finished: bool,
    owner_observation_completed: bool,
    recipient_observation_completed: bool,
    owner_fresh_completed: bool,
    recipient_fresh_completed: bool,
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
            &json!({"schemaVersion":1,"status":status,"commands":self.commands,"expectedCommands":COMMAND_COUNT,"cliVersion":"2026.10.0","cliPasswordLoginCommands":self.logins,"directPasswordLoginRequests":2,"directHttpRequests":self.direct,"expectedDirectHttpRequests":DIRECT_HTTP_REQUEST_COUNT,"fixtureRegistrations":2,"fixtureRegistrationHttpRequests":4,"observerOnly":false,"actualTrashCliCommandExecuted":self.owner_observation_completed&&self.recipient_observation_completed,"actualTrashRestoreCliCommandExecuted":self.owner_observation_completed&&self.recipient_observation_completed,"actualArchivedActiveRestoreCliCommandExecuted":self.owner_observation_completed&&self.recipient_observation_completed,"deletedArchivedRestorePriorityAsserted":self.owner_observation_completed&&self.recipient_observation_completed,"sourceAttributedSingleLifecycleAndSelectedUnarchiveCallers":true,"ownerLifecycleDecryptionCompleted":self.owner_observation_completed,"writableRecipientLifecycleDecryptionCompleted":self.recipient_observation_completed,"ownerFreshCacheDecryptionCompleted":self.owner_fresh_completed,"recipientFreshCacheDecryptionCompleted":self.recipient_fresh_completed,"privateFoldersAndFavoriteObserved":self.finished,"commonOpaquePayloadKeyAndPrivateArchivePreservationAsserted":self.finished,"currentReadersLifecycleRevisionAndActorOnlyUnarchiveAsserted":self.finished,"readonlyManageCliClaimed":false,"permanentDeleteCliClaimed":false,"capturedRouteTrace":false,"clientInternalRequestsCounted":false,"browserTraceClaimed":false,"attachmentBearingTested":false,"fullParityClaimed":false,"configuredPolicies":false,"groupsConfigured":false,"smtpEnabled":false,"separateFromBaseline120":true}),
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
            COMMAND_COUNT == 0 || self.commands <= COMMAND_COUNT,
            "Lifecycle CLI command budget exceeded",
        )?;
        if args.first() == Some(&"login") {
            self.logins += 1;
        }
        self.receipt("running")?;
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
        let result = capture::run(&self.binary, &args, &env, Duration::from_secs(120))
            .map_err(|_| Error("Lifecycle CLI private capture failed"))?;
        if !result.status.success() {
            eprintln!(
                "Lifecycle CLI command {} failed with status {:?}",
                self.commands,
                result.status.code()
            );
        }
        require(result.status.success(), "Lifecycle CLI command failed")?;
        String::from_utf8(result.stdout)
            .map(|s| s.trim().to_owned())
            .map_err(|_| Error("Lifecycle CLI output was not UTF8"))
    }
    fn json(&mut self, args: &[&str], cache: &Path, session: &str) -> Result<Value, Error> {
        serde_json::from_str(&self.command(args, cache, Some(session))?)
            .map_err(|_| Error("Lifecycle CLI JSON output malformed"))
    }
    fn login(
        &mut self,
        account: &Account,
        cache: &Path,
        server: &str,
        password_env: &str,
    ) -> Result<String, Error> {
        self.command(&["config", "server", server], cache, None)?;
        let session = self.command(
            &[
                "login",
                text(&account.fixture["email"])?,
                "--passwordenv",
                password_env,
                "--raw",
            ],
            cache,
            None,
        )?;
        require(
            session.len() > 20,
            "Lifecycle CLI login did not return session",
        )?;
        self.command(&["sync"], cache, Some(&session))?;
        Ok(session)
    }
}
fn check_note(value: &Value, id: &str, org: Option<&Organization>) -> Result<(), Error> {
    require(
        value["id"] == id
            && value["name"] == organization_owner::NOTE
            && value["notes"] == organization_owner::NOTE
            && value["type"] == 2
            && value["secureNote"]["type"] == 0,
        "Lifecycle CLI did not decrypt expected secure note",
    )?;
    match org {
        Some(org) => require(
            value["organizationId"] == org.id
                && value["collectionIds"] == json!([org.collection_id]),
            "Lifecycle CLI lost target org/collection identity",
        ),
        None => require(
            value["organizationId"].is_null(),
            "Lifecycle CLI personal control acquired org ownership",
        ),
    }
}
fn private_dir(prefix: &str) -> Result<TempDir, Error> {
    let dir = tempfile::Builder::new()
        .prefix(prefix)
        .tempdir()
        .map_err(|_| Error("Lifecycle CLI private directory unavailable"))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700))
            .map_err(|_| Error("Lifecycle CLI private directory permissions failed"))?;
    }
    Ok(dir)
}
fn confirm(
    http: &mut Http,
    owner: &Account,
    recipient: &Account,
    org: &Organization,
) -> Result<(), Error> {
    organization_invites::invite_owner(
        http,
        &org.id,
        &owner.token,
        &json!({"emails":[recipient.fixture["email"]],"type":2,"groups":[],"collections":[{"id":org.collection_id,"readOnly":false,"hidePasswords":false,"manage":false}]}),
    )?;
    let row = organization_confirmations::member_row(
        http,
        &org.id,
        &owner.token,
        text(&recipient.fixture["email"])?,
    )?;
    require(
        row["status"] == 1 && row["type"] == 2,
        "Lifecycle CLI invitee fixture was not accepted User",
    )?;
    let wrapped = fixture::organization_key_for_account(&recipient.fixture, &org.key)
        .map_err(|_| Error("Lifecycle CLI RSA fixture failed"))?;
    http.requests += 1;
    let response = http_client()?
        .post(format!(
            "{}/api/organizations/{}/users/{}/confirm",
            http.server,
            org.id,
            text(&row["id"])?
        ))
        .bearer_auth(&owner.token)
        .json(&json!({"key":wrapped}))
        .send()
        .map_err(|_| Error("Lifecycle CLI confirmation request failed"))?;
    require(
        response.status().as_u16() == 200,
        "Lifecycle CLI confirmation rejected",
    )?;
    let after = organization_confirmations::member_row(
        http,
        &org.id,
        &owner.token,
        text(&recipient.fixture["email"])?,
    )?;
    organization_confirmations::member_after(&row, &after, 2)
}
fn personal(http: &mut Http, account: &Account) -> Result<Value, Error> {
    http.json(
        Method::GET,
        &format!("/api/ciphers/{}", account.cipher_id),
        &account.token,
        None,
    )
}
fn totp(value: &Value) -> Result<bool, Error> {
    value["organizationUseTotp"]
        .as_bool()
        .ok_or(Error("Sharing personal TOTP projection missing"))
}
fn check_private(
    value: &Value,
    id: &str,
    org: &Organization,
    favorite: bool,
    folder: Option<&str>,
) -> Result<(), Error> {
    check_note(value, id, Some(org))?;
    require(
        value["favorite"] == favorite && value["folderId"].as_str() == folder,
        "Lifecycle decrypted private annotations differed",
    )
}
fn revision(http: &mut Http, accounts: [&Account; 2]) -> Result<[Value; 2], Error> {
    Ok([
        http.json(
            Method::GET,
            "/api/accounts/revision-date",
            &accounts[0].token,
            None,
        )?,
        http.json(
            Method::GET,
            "/api/accounts/revision-date",
            &accounts[1].token,
            None,
        )?,
    ])
}
const FOLDER_NAME: &str = "Private lifecycle folder";
pub fn run() -> Result<(), Error> {
    let owner_cache = private_dir("no-warden-lifecycle-owner-cli-")?;
    let recipient_cache = private_dir("no-warden-lifecycle-recipient-cli-")?;
    let owner_fresh = private_dir("no-warden-lifecycle-owner-fresh-")?;
    let recipient_fresh = private_dir("no-warden-lifecycle-recipient-fresh-")?;
    let tls = private_dir("no-warden-lifecycle-cli-tls-")?;
    let mut http = Http::new()?;
    let owner = organization_owner::seed(&mut http)?;
    let recipient = organization_owner::seed(&mut http)?;
    let before = [
        totp(&personal(&mut http, &owner)?)?,
        totp(&personal(&mut http, &recipient)?)?,
    ];
    let org = create_organization(&mut http, &owner)?;
    confirm(&mut http, &owner, &recipient, &org)?;
    let owner_control = personal(&mut http, &owner)?;
    let recipient_control = personal(&mut http, &recipient)?;
    let after = [totp(&owner_control)?, totp(&recipient_control)?];
    require(
        before == [true; 2] && after == [true; 2],
        "Lifecycle personal TOTP changed",
    )?;
    let keys = [
        http.json(Method::GET, "/api/accounts/keys", &owner.token, None)?,
        http.json(Method::GET, "/api/accounts/keys", &recipient.token, None)?,
    ];
    let mut folders = Vec::new();
    for a in [&owner, &recipient] {
        let name =
            fixture::encrypted_fixture_value(&a.fixture, &a.password, FOLDER_NAME.as_bytes())
                .map_err(|_| Error("Lifecycle folder encryption failed"))?;
        let v = http.json(
            Method::POST,
            "/api/folders",
            &a.token,
            Some(&json!({"name":name})),
        )?;
        folders.push(text(&v["id"])?.to_owned());
    }
    let cipher_key = [67u8; 64];
    let wrapped = fixture::encrypt(&cipher_key, &org.key)
        .map_err(|_| Error("Lifecycle wrapped key fixture failed"))?;
    let encrypted = fixture::encrypt(organization_owner::NOTE.as_bytes(), &cipher_key)
        .map_err(|_| Error("Lifecycle org encryption failed"))?;
    http.json(Method::PUT,&format!("/api/ciphers/{}/share",owner.cipher_id),&owner.token,Some(&json!({"collectionIds":[org.collection_id],"cipher":{"type":2,"encryptedFor":owner.user_id,"organizationId":org.id,"name":encrypted,"notes":encrypted,"secureNote":{"type":0},"key":wrapped,"favorite":true,"folderId":folders[0]}})))?;
    let owner_before = personal(&mut http, &owner)?;
    http.json(
        Method::PUT,
        &format!("/api/ciphers/{}/partial", owner.cipher_id),
        &recipient.token,
        Some(&json!({"favorite":false,"folderId":folders[1]})),
    )?;
    let recipient_before = http.json(
        Method::GET,
        &format!("/api/ciphers/{}", owner.cipher_id),
        &recipient.token,
        None,
    )?;
    require(
        owner_before["edit"] == true && recipient_before["edit"] == true,
        "Lifecycle recipient was not writable",
    )?;
    let proxy = if http.server.starts_with("http:") {
        Some(
            TlsProxy::start(&http.server, tls.path())
                .map_err(|_| Error("Lifecycle TLS setup failed"))?,
        )
    } else {
        None
    };
    let server = proxy
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
        "DEBUG",
        "DEBUG_FILE",
        "PWDEBUG",
        "NODE_DEBUG",
        "NODE_DEBUG_NATIVE",
    ] {
        environment.remove(&OsString::from(key));
    }
    environment.insert("BW_NOINTERACTION".into(), "true".into());
    environment.insert(
        "BW_LIFECYCLE_OWNER_PASSWORD".into(),
        owner.password.clone().into(),
    );
    environment.insert(
        "BW_LIFECYCLE_RECIPIENT_PASSWORD".into(),
        recipient.password.clone().into(),
    );
    if let Some(p) = &proxy {
        environment.insert(
            "NODE_EXTRA_CA_CERTS".into(),
            p.certificate().as_os_str().to_owned(),
        );
    }
    let mut c = Cli {
        binary,
        environment,
        commands: 0,
        logins: 0,
        direct: None,
        receipt: receipt_file("BW_ORGANIZATION_CIPHER_LIFECYCLE_CLI_RECEIPT")?,
        finished: false,
        owner_observation_completed: false,
        recipient_observation_completed: false,
        owner_fresh_completed: false,
        recipient_fresh_completed: false,
    };
    c.receipt("running")?;
    require(
        c.command(&["--version"], owner_cache.path(), None)? == "2026.10.0",
        "Lifecycle CLI version differed",
    )?;
    let os = c.login(
        &owner,
        owner_cache.path(),
        &server,
        "BW_LIFECYCLE_OWNER_PASSWORD",
    )?;
    let rs = c.login(
        &recipient,
        recipient_cache.path(),
        &server,
        "BW_LIFECYCLE_RECIPIENT_PASSWORD",
    )?;

    let check = |v: &Value, actor: usize, deleted: bool, archived: bool| -> Result<(), Error> {
        check_private(v, &owner.cipher_id, &org, actor == 0, Some(&folders[actor]))?;
        require(
            if deleted {
                v["deletedDate"].is_string()
            } else {
                v["deletedDate"].is_null()
            },
            "Lifecycle CLI Trash state differed",
        )?;
        require(
            if archived {
                v["archivedDate"].is_string()
            } else {
                v["archivedDate"].is_null()
            },
            "Lifecycle CLI archive state differed",
        )
    };
    let accounts = [&owner, &recipient];
    let mut baseline = [owner_before, recipient_before];
    require(
        baseline.iter().all(|v| v["key"].is_string()),
        "Lifecycle CLI wrapped cipher key absent",
    )?;
    for (actor, cache, session) in [
        (0, owner_cache.path(), &os),
        (1, recipient_cache.path(), &rs),
    ] {
        let v = c.json(&["get", "item", &owner.cipher_id], cache, session)?;
        check(&v, actor, false, false)?;
        // Archive is legitimate CLI setup. Restore first chooses Trash restoration,
        // then selected unarchive only once the source is active but still archived.
        for (command, deleted, archived, lifecycle) in [
            ("archive", false, true, false),
            ("delete", true, true, true),
            ("restore", false, true, true),
            ("restore", false, false, false),
            ("delete", true, false, true),
            ("restore", false, false, true),
        ] {
            let before = revision(&mut http, accounts)?;
            c.command(&[command, "item", &owner.cipher_id], cache, Some(session))?;
            let after = revision(&mut http, accounts)?;
            for viewer in 0..2 {
                require(
                    (before[viewer] != after[viewer]) == (lifecycle || viewer == actor),
                    "Lifecycle CLI revision scope differed",
                )?;
                let doc = http.json(
                    Method::GET,
                    &format!("/api/ciphers/{}", owner.cipher_id),
                    &accounts[viewer].token,
                    None,
                )?;
                require(
                    if deleted {
                        doc["deletedDate"].is_string()
                    } else {
                        doc["deletedDate"].is_null()
                    },
                    "Lifecycle CLI direct viewer deletion state differed",
                )?;
                let mut wanted = baseline[viewer].clone();
                if lifecycle {
                    wanted["deletedDate"] = doc["deletedDate"].clone();
                    wanted["revisionDate"] = doc["revisionDate"].clone();
                    require(
                        doc["revisionDate"] != baseline[viewer]["revisionDate"],
                        "Lifecycle CLI source revision did not advance",
                    )?;
                } else if viewer == actor {
                    wanted["archivedDate"] = doc["archivedDate"].clone();
                }
                require(
                    wanted == doc,
                    "Lifecycle CLI lost opaque/key/private/archive/common state",
                )?;
                baseline[viewer] = doc;
            }
            c.command(&["sync"], cache, Some(session))?;
            let v = c.json(&["get", "item", &owner.cipher_id], cache, session)?;
            check(&v, actor, deleted, archived)?;
            if deleted {
                // Pinned ListCommand applies Trash AND Archive filters together.
                let args: &[&str] = if archived {
                    &["list", "items", "--trash", "--archived"]
                } else {
                    &["list", "items", "--trash"]
                };
                let rows = c.json(args, cache, session)?;
                let row = rows
                    .as_array()
                    .and_then(|a| a.iter().find(|v| v["id"] == owner.cipher_id))
                    .ok_or(Error("Lifecycle CLI item absent from Trash list"))?;
                check(row, actor, true, archived)?;
            }
        }
        if actor == 0 {
            c.owner_observation_completed = true;
        } else {
            c.recipient_observation_completed = true;
        }
    }
    let ofs = c.login(
        &owner,
        owner_fresh.path(),
        &server,
        "BW_LIFECYCLE_OWNER_PASSWORD",
    )?;
    let v = c.json(&["get", "item", &owner.cipher_id], owner_fresh.path(), &ofs)?;
    check(&v, 0, false, false)?;
    c.owner_fresh_completed = true;
    let rfs = c.login(
        &recipient,
        recipient_fresh.path(),
        &server,
        "BW_LIFECYCLE_RECIPIENT_PASSWORD",
    )?;
    let v = c.json(
        &["get", "item", &owner.cipher_id],
        recipient_fresh.path(),
        &rfs,
    )?;
    check(&v, 1, false, false)?;
    c.recipient_fresh_completed = true;
    for (actor, cache, session) in [
        (0, owner_fresh.path(), &ofs),
        (1, recipient_fresh.path(), &rfs),
    ] {
        let v = c.json(&["list", "folders"], cache, session)?;
        require(
            v.as_array().is_some_and(|a| {
                a.iter()
                    .any(|v| v["id"] == folders[actor] && v["name"] == FOLDER_NAME)
                    && a.iter().all(|v| v["id"] != folders[1 - actor])
            }),
            "Lifecycle CLI folder privacy/decryption differed",
        )?;
        require(
            http.json(
                Method::GET,
                &format!("/api/ciphers/{}", owner.cipher_id),
                &accounts[actor].token,
                None,
            )? == baseline[actor],
            "Lifecycle fresh cache changed source",
        )?;
        require(
            http.json(
                Method::GET,
                "/api/accounts/keys",
                &accounts[actor].token,
                None,
            )? == keys[actor],
            "Lifecycle CLI changed account keys",
        )?;
    }
    require(
        personal(&mut http, &recipient)? == recipient_control,
        "Lifecycle CLI changed personal control",
    )?;
    for (cache, session) in [
        (owner_cache.path(), &os),
        (recipient_cache.path(), &rs),
        (owner_fresh.path(), &ofs),
        (recipient_fresh.path(), &rfs),
    ] {
        c.command(&["logout"], cache, Some(session))?;
    }
    c.direct = Some(http.requests);
    if c.commands != COMMAND_COUNT || http.requests != DIRECT_HTTP_REQUEST_COUNT {
        eprintln!(
            "Lifecycle measured commands {}, direct requests {}",
            c.commands, http.requests
        );
    }
    require(
        c.commands == COMMAND_COUNT
            && http.requests == DIRECT_HTTP_REQUEST_COUNT
            && c.logins == 4
            && http.logins == 2,
        "Lifecycle fixture budget differed",
    )?;
    c.finished = true;
    c.receipt("passed")?;
    println!("PASS organization-cipher-lifecycle CLI: {COMMAND_COUNT} commands");
    Ok(())
}
